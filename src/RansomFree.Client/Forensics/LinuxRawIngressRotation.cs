using System.Security.Cryptography;
using System.Text.Json;
using RansomFree.Contracts;

namespace RansomFree.Client.Forensics;

// A single live source keeps its epoch, ordering and native leases during raw
// segment rotation. Each old segment is immutable and verified on recovery.
// Rotation never recycles records or infers a new native source capability.
internal sealed partial class LinuxRawIngressReserve
{
    private bool rotating,rotationFaulted;
    private int sequenceBase;
    private readonly List<LinuxRawIngressReserve> segments=[];
    private InputSeal? logSeal;
    private string? rotationQuotaDirectory;
    private long rotationQuotaBytes;
    private bool RotatingRoot=>rotating&&sequenceBase==0;
    internal string Format=>RotatingRoot?"raw-ingress-v4-rotating":"raw-ingress-v3";
    private bool RotationCanAppend=>!readOnly&&!disposed&&!ioFaulted&&!rotationFaulted&&logSeal==null&&
        (segments.Count==0?inputSeal==null:segments[^1].CanAppend);
    private sealed record Rotation(int Version,int Ordinal,int SequenceBase,string StableId,long Bytes,string PreviousSealSha256);
    private Entry[] AllEntries()=>entries.Concat(segments.SelectMany(x=>x.entries)).ToArray();
    private string RotationPath(int ordinal)=>Path.Combine(Path.GetDirectoryName(FullPath)!,"rotation-"+ordinal.ToString("D6")+".json");
    private string SegmentDirectory(int ordinal)=>Path.Combine(Path.GetDirectoryName(FullPath)!,"part-"+ordinal.ToString("D6"));
    private string LogSealPath=>FullPath+".log-sealed.json";
    private static byte[] BoundedPrivateRead(string path)
    {
        EvidenceDurability.NoLinks(path);
        if(OperatingSystem.IsLinux()&&(File.GetUnixFileMode(path)&(UnixFileMode.GroupRead|UnixFileMode.GroupWrite|UnixFileMode.GroupExecute|UnixFileMode.OtherRead|UnixFileMode.OtherWrite|UnixFileMode.OtherExecute))!=0)
            throw new IOException("Raw rotation receipt is not private");
        using var file=new FileStream(path,FileMode.Open,FileAccess.Read,FileShare.Read);
        if(file.Length is <2 or >4096)throw new InvalidDataException("Raw rotation receipt exceeds bound");
        var bytes=new byte[(int)file.Length];file.ReadExactly(bytes);return bytes;
    }
    private string SegmentSealSha256()=>Convert.ToHexString(SHA256.HashData(BoundedPrivateRead(FullPath+".sealed.json")));
    private void InitializeRotation()
    {
        if(!RotatingRoot)return;
        var directory=Path.GetDirectoryName(FullPath)!;
        EvidenceDurability.NoLinks(directory);
        // Writable instances can only be brand-new preparations. Retained
        // inputs are opened read-only and never resume a native source.
        for(int ordinal=1;File.Exists(RotationPath(ordinal));ordinal++)
        {
            if(!readOnly||ordinal>16384)throw new InvalidDataException("Unexpected retained raw rotation at new source admission");
            var previous=segments.Count==0?this:segments[^1];
            if(previous.inputSeal==null||previous.entries.Count!=slots)
                throw new InvalidDataException("Rotation predecessor is not a sealed full segment");
            var bytes=BoundedPrivateRead(RotationPath(ordinal));
            var receipt=JsonSerializer.Deserialize<Rotation>(bytes)??throw new InvalidDataException("Missing raw rotation receipt");
            var expectedBase=checked(ordinal*slots);
            if(receipt.Version!=1||receipt.Ordinal!=ordinal||receipt.SequenceBase!=expectedBase||receipt.PreviousSealSha256!=previous.SegmentSealSha256()||
                !JsonSerializer.SerializeToUtf8Bytes(receipt).AsSpan().SequenceEqual(bytes))
                throw new InvalidDataException("Raw rotation chain changed");
            EvidenceDurability.NoLinks(SegmentDirectory(ordinal));
            var child=new LinuxRawIngressReserve(SegmentDirectory(ordinal),sensor,collector,epoch,slots,true,null,true,null,true,expectedBase);
            if(!child.rotating||child.sequenceBase!=expectedBase||child.BankIdentity.StableId!=receipt.StableId||child.BankIdentity.Size!=receipt.Bytes)
            {child.Dispose();throw new InvalidDataException("Raw rotation segment identity changed");}
            segments.Add(child);
        }
        var named=System.IO.Directory.EnumerateFiles(directory,"rotation-*.json").Count();
        var children=System.IO.Directory.EnumerateDirectories(directory,"part-*").Count();
        if(named!=segments.Count||children!=segments.Count)
            throw new InvalidDataException("Uncommitted or missing raw rotation retained; recovery unresolved");
        if(File.Exists(LogSealPath))
        {
            var bytes=BoundedPrivateRead(LogSealPath);var value=JsonSerializer.Deserialize<InputSeal>(bytes)??throw new InvalidDataException("Missing raw log seal");
            if(value.SealedUtc==default||value!=DescribeLogSeal(value.SealedUtc)||!JsonSerializer.SerializeToUtf8Bytes(value).AsSpan().SequenceEqual(bytes)||
                (segments.Count==0?inputSeal:segments[^1].inputSeal)==null)
                throw new InvalidDataException("Raw log changed after terminal seal");
            logSeal=value;
        }
    }
    internal Admission Commit(ReadOnlyMemory<byte> raw,LinuxSourceWorkBarrier.View view,DateTimeOffset receivedUtc)
        =>RotatingRoot?CommitRotating(raw,view,receivedUtc):CommitSegment(raw,view,receivedUtc);
    private Admission CommitRotating(ReadOnlyMemory<byte> raw,LinuxSourceWorkBarrier.View view,DateTimeOffset receivedUtc)
    {
        lock(gate)
        {
            if(!RotationCanAppend)throw new InvalidOperationException("Historical, faulted or sealed raw log cannot append");
            var current=segments.Count==0?this:segments[^1];
            if(current.entries.Count==slots)
            {
                LinuxRawIngressReserve? child=null;
                try
                {
                    if(rotationQuotaDirectory==null)throw new InvalidOperationException("Rotation storage quota owner missing");
                    var ordinal=segments.Count+1;var directory=SegmentDirectory(ordinal);
                    // Reserve disk before sealing the current segment. The
                    // predecessor emergency slot survives allocation failure.
                    using var prepared=PrepareRotation(directory);
                    child=new LinuxRawIngressReserve(prepared.Directory,sensor,collector,epoch,slots,!PhysicalAllocationEstablished,null,false,prepared,true,checked(ordinal*slots));
                    current.SealSegmentInput(DateTimeOffset.UtcNow);
                    var receipt=new Rotation(1,ordinal,child.sequenceBase,child.BankIdentity.StableId!,child.BankIdentity.Size!.Value,current.SegmentSealSha256());
                    EvidenceDurability.SaveNew(RotationPath(ordinal),JsonSerializer.SerializeToUtf8Bytes(receipt));
                    if(!BoundedPrivateRead(RotationPath(ordinal)).AsSpan().SequenceEqual(JsonSerializer.SerializeToUtf8Bytes(receipt)))
                        throw new IOException("Raw rotation receipt readback differs");
                    segments.Add(child);current=child;child=null;
                }
                catch
                {
                    child?.Dispose();rotationFaulted=true;throw; // preserve every bank, including stranded preparations
                }
            }
            return current.CommitSegment(raw,view,receivedUtc);
        }
    }
    private Preparation PrepareRotation(string directory)
    {
        // The preparation capacity walk includes all retained segments and
        // orphaned preparations. It does not depend on the SQL index succeeding.
        RequirePreparationCapacity(Path.GetDirectoryName(FullPath)!,rotationQuotaDirectory!,
            4096+(long)(slots+1)*(128+131072),rotationQuotaBytes);
        return Prepare(directory,sensor,collector,slots,layoutReplayForTest:!PhysicalAllocationEstablished);
    }
    private InputSeal DescribeLogSeal(DateTimeOffset utc)
    {
        var all=AllEntries();
        return new(2,sensor,collector,epoch,BankIdentity.StableId,BankIdentity.Size,checked(slots*(segments.Count+1)),all.Length,
            all.LastOrDefault()?.DeliveryId,Convert.ToHexString(SHA256.HashData(JsonSerializer.SerializeToUtf8Bytes(all))),
            Convert.ToHexString(SHA256.HashData(JsonSerializer.SerializeToUtf8Bytes(FirstBoundary))),utc);
    }
    internal InputSeal SealInput(DateTimeOffset utc)
    {
        if(!RotatingRoot)return SealSegmentInput(utc);
        lock(gate)
        {
            if(logSeal!=null)return logSeal;
            if(readOnly||utc==default)throw new InvalidOperationException("Actual writable raw log terminal seal required");
            (segments.Count==0?this:segments[^1]).SealSegmentInput(utc);
            if(File.Exists(LogSealPath))
            {
                var bytes=BoundedPrivateRead(LogSealPath);var existing=JsonSerializer.Deserialize<InputSeal>(bytes);
                if(existing==null||existing!=DescribeLogSeal(existing.SealedUtc)||!JsonSerializer.SerializeToUtf8Bytes(existing).AsSpan().SequenceEqual(bytes))
                    throw new InvalidDataException("Raw log terminal seal differs");
                EvidenceDurability.DirectoryCommitted(Path.GetDirectoryName(FullPath)!);return logSeal=existing;
            }
            var value=DescribeLogSeal(utc);EvidenceDurability.SaveNew(LogSealPath,JsonSerializer.SerializeToUtf8Bytes(value));
            return logSeal=value;
        }
    }
}
