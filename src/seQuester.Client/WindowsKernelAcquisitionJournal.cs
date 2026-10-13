using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text.Json;
using RansomFree.Client.Forensics;
using RansomFree.Contracts;

namespace RansomFree.Client;

// The required marker precedes raw Prepare; a crash cannot turn an advertised
// but missing companion into legacy evidence. Companion commit precedes ACK.
internal sealed class WindowsKernelAcquisitionJournal(string directory)
{
    private sealed record Requirement(int Version,string? Provider,ulong Epoch,ulong Instance,ulong Sequence,string RawSha256);
    private sealed record Retirement(string SourceProvider,ulong SourceEpoch,ulong Instance,ulong Sequence,string RawSha256,string CurrentProvider,ulong CurrentEpoch,DateTimeOffset ObservedUtc);
    private readonly string root=Path.GetFullPath(directory);
    private string PathFor(string id,string suffix)
    {
        if(!Guid.TryParseExact(id,"N",out _))throw new InvalidDataException("Invalid acquisition event ID");
        return Path.Combine(root,id+suffix);
    }
    private static string Hash(byte[] bytes)=>Convert.ToHexString(SHA256.HashData(bytes));
    private static Requirement Read(string file)
    {
        if(new FileInfo(file).Length>1024)throw new InvalidDataException("Acquisition requirement exceeds bound");
        return JsonSerializer.Deserialize<Requirement>(File.ReadAllBytes(file))??throw new InvalidDataException("Empty acquisition requirement");
    }
    private static void Validate(Requirement requirement,byte[] raw)
    {
        if(!WindowsKernelDecoder.ValidRecordLength(raw.Length)||requirement.Version is not (0 or 1)||requirement.Instance==0||requirement.Sequence==0||
            requirement.Instance!=WindowsKernelDecoder.U64(raw,8)||requirement.Sequence!=WindowsKernelDecoder.U64(raw,16)||requirement.RawSha256!=Hash(raw))throw new InvalidDataException("Acquisition requirement does not match immutable raw record");
        if(requirement.Version==1)_=WindowsAcquisitionOutcomeProtocol.Request(requirement.Provider??"",requirement.Epoch,requirement.Instance,requirement.Sequence);
        else if(requirement.Provider!=null||requirement.Epoch!=0)throw new InvalidDataException("Legacy requirement has fabricated native provider evidence");
    }
    private static void Commit(string target,byte[] bytes)
    {
        if(File.Exists(target)){if(!File.ReadAllBytes(target).AsSpan().SequenceEqual(bytes))throw new IOException("Immutable acquisition evidence collision");return;}
        var temporary=target+"."+Guid.NewGuid().ToString("N")+".tmp";
        using(var file=new FileStream(temporary,FileMode.CreateNew,FileAccess.Write,FileShare.None,4096,FileOptions.WriteThrough)){file.Write(bytes);file.Flush(true);}
        if(OperatingSystem.IsWindows())
        {if(!MoveFileEx(temporary,target,8))throw new IOException("Acquisition evidence commit failed: "+Marshal.GetLastPInvokeError());}
        else File.Move(temporary,target,false);
        if(!File.ReadAllBytes(target).AsSpan().SequenceEqual(bytes))throw new IOException("Acquisition evidence readback differs");
    }
    internal void Require(string id,byte[] raw,string? provider,ulong epoch,bool supported)
    {
        var requirement=new Requirement(supported?1:0,supported?provider:null,supported?epoch:0,WindowsKernelDecoder.U64(raw,8),WindowsKernelDecoder.U64(raw,16),Hash(raw));
        Validate(requirement,raw);Commit(PathFor(id,".acq-required"),JsonSerializer.SerializeToUtf8Bytes(requirement));
    }
    internal void Capture(string id,byte[] raw,Func<byte[],int,byte[]> exchange)
    {
        var requirement=Read(PathFor(id,".acq-required"));Validate(requirement,raw);
        if(requirement.Version==0)return;
        var reply=PathFor(id,".acq1");
        if(File.Exists(reply)){ValidateOutcome(requirement,File.ReadAllBytes(reply));return;}
        var bytes=exchange(WindowsAcquisitionOutcomeProtocol.Request(requirement.Provider!,requirement.Epoch,requirement.Instance,requirement.Sequence),128);
        ValidateOutcome(requirement,bytes);Commit(reply,bytes);
    }
    private static WindowsAcquisitionOutcome ValidateOutcome(Requirement r,byte[] bytes)=>WindowsAcquisitionOutcomeProtocol.Decode(bytes,r.Provider!,r.Epoch,r.Instance,r.Sequence);
    private static WindowsAcquisitionObservation RetiredEvidence(Requirement r,string file)
    {
        if(new FileInfo(file).Length>2048)throw new InvalidDataException("Acquisition retirement evidence exceeds bound");
        var retired=JsonSerializer.Deserialize<Retirement>(File.ReadAllBytes(file))??throw new InvalidDataException("Empty acquisition retirement evidence");
        if(r.Version!=1||retired.SourceProvider!=r.Provider||retired.SourceEpoch!=r.Epoch||retired.Instance!=r.Instance||retired.Sequence!=r.Sequence||retired.RawSha256!=r.RawSha256)throw new InvalidDataException("Acquisition retirement source differs");
        var evidence=new WindowsAcquisitionObservation{Version=2,QueryAttempted=null,Status=EvidenceStatus.Unavailable("provider-retired-before-companion-commit"),Provider=r.Provider,Epoch=r.Epoch,Instance=r.Instance,Sequence=r.Sequence,OperationRecordSha256=r.RawSha256,
            RecoveryProvider=retired.CurrentProvider,RecoveryEpoch=retired.CurrentEpoch,RecoveryObservedUtc=retired.ObservedUtc};
        if(!evidence.IsValid(new(){Instance=r.Instance.ToString("X16"),Sequence=checked((long)r.Sequence)}))throw new InvalidDataException("Invalid acquisition retirement evidence");
        return evidence;
    }
    // Called only with the locally connected native provider's validated UUID
    // and epoch. A reconnect with the same identity is never a retirement.
    internal void RecoverRetired(string currentProvider,ulong currentEpoch,Action<string> schedule,Action<string> health)
    {
        _=WindowsAcquisitionOutcomeProtocol.Request(currentProvider,currentEpoch,currentEpoch,1);
        foreach(var marker in Directory.EnumerateFiles(root,"*.acq-required"))
        {
            try
            {
                var rawPath=Path.ChangeExtension(marker,".record");if(!File.Exists(rawPath))continue;
                var raw=File.ReadAllBytes(rawPath);var r=Read(marker);Validate(r,raw);
                if(r.Version!=1||r.Provider==currentProvider&&r.Epoch==currentEpoch||File.Exists(Path.ChangeExtension(marker,".acq1")))continue;
                var retirement=Path.ChangeExtension(marker,".acq-unavailable");
                if(!File.Exists(retirement))Commit(retirement,JsonSerializer.SerializeToUtf8Bytes(new Retirement(r.Provider!,r.Epoch,r.Instance,r.Sequence,r.RawSha256,currentProvider,currentEpoch,DateTimeOffset.UtcNow)));
                _=RetiredEvidence(r,retirement);schedule(rawPath);
                health("Windows acquisition companion unavailable after native provider retirement; original raw event retained for delivery: "+Path.GetFileName(rawPath));
            }
            catch(Exception ex)when(ex is IOException or InvalidDataException or UnauthorizedAccessException or JsonException or OverflowException)
            {health("Windows acquisition retired-provider recovery held record "+Path.GetFileName(marker)+": "+ex.GetType().Name);}
        }
    }
    internal static bool Ready(string rawPath)
    {
        var marker=Path.ChangeExtension(rawPath,".acq-required");if(!File.Exists(marker))return true; // historical raw record
        var r=Read(marker);Validate(r,File.ReadAllBytes(rawPath));
        if(r.Version==0)return true;
        var companion=Path.ChangeExtension(rawPath,".acq1");var retirement=Path.ChangeExtension(rawPath,".acq-unavailable");
        if(File.Exists(retirement)){if(File.Exists(companion))throw new InvalidDataException("Acquisition companion and retirement evidence conflict");_=RetiredEvidence(r,retirement);return true;}
        if(!File.Exists(companion))return false;
        if(new FileInfo(companion).Length!=128)throw new InvalidDataException("Acquisition companion length differs");
        ValidateOutcome(r,File.ReadAllBytes(companion));return true;
    }
    internal AgentEvent Attach(AgentEvent observed,byte[] raw)
    {
        var kernel=observed.Attribution?.WindowsKernel??throw new InvalidDataException("Kernel observation required");
        WindowsAcquisitionObservation evidence;
        var marker=PathFor(observed.EventId,".acq-required");
        if(!File.Exists(marker))evidence=new(){Status=EvidenceStatus.Unavailable("pre-companion-record")};
        else
        {
            var r=Read(marker);Validate(r,raw);
            var retirement=PathFor(observed.EventId,".acq-unavailable");
            if(File.Exists(retirement)&&File.Exists(PathFor(observed.EventId,".acq1")))throw new InvalidDataException("Acquisition companion and retirement evidence conflict");
            evidence=r.Version==0?new():File.Exists(retirement)?RetiredEvidence(r,retirement):WindowsAcquisitionOutcomeProtocol.Evidence(ValidateOutcome(r,File.ReadAllBytes(PathFor(observed.EventId,".acq1"))),r.RawSha256);
        }
        if(!evidence.IsValid(kernel))throw new InvalidDataException("Acquisition projection differs from operation key");
        return observed with{Attribution=observed.Attribution! with{WindowsKernel=kernel with{AcquisitionObservation=evidence}}};
    }
    [DllImport("kernel32.dll",CharSet=CharSet.Unicode,SetLastError=true)]
    [return:MarshalAs(UnmanagedType.Bool)]private static extern bool MoveFileEx(string source,string destination,uint flags);
}
