using System.Buffers.Binary;
using System.ComponentModel;
using System.Diagnostics;
using System.Globalization;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text.Json;
using Microsoft.Win32.SafeHandles;
using RansomFree.Contracts;

namespace RansomFree.Client.Forensics;

// Versioned extension of the v2 intent-before-frame pattern. Keeps exact bytes
// BEFORE schema decoding, including malformed/residual frames. The v2 bank is
// untouched. An ingress receipt grants no typed-event or native-I/O authority.
// No actor/target file is hashed: all hashes here protect this transport record.
internal sealed partial class LinuxRawIngressReserve:IDisposable
{
    internal sealed record Entry(int Version,string Sensor,string Collector,string ProviderEpoch,
        string DeliveryId,int Sequence,DateTimeOffset ReceivedUtc,string MonotonicTicks,
        LinuxSourceWorkBarrier.View View,int RawLength,string RawSha256);
    internal sealed record Boundary(int Version,string BoundaryId,string Reason,DateTimeOffset RecordedUtc,
        string Sensor,string Collector,string ProviderEpoch,LinuxSourceWorkBarrier.View View,
        int LastDurableSequence,string? LastDurableDeliveryId,long? InputLength,string? Error,bool OpenEnded=true);
    internal sealed record Admission(bool Committed,Entry? Entry,Boundary? Boundary);
    internal sealed record BoundaryReceipt(bool NewlyCommitted,Boundary Boundary);
    internal sealed record InputSeal(int Version,string Sensor,string Collector,string ProviderEpoch,string? StableId,
        long? Bytes,int Capacity,int Entries,string? LastDeliveryId,string ReceiptsSha256,string BoundarySha256,DateTimeOffset SealedUtc);
    private const int HeaderBytes=4096,IntentBytes=128,SlotBytes=131072,PrefixBytes=48,MetadataLimit=4096;
    private const int MaximumBody=8+MetadataLimit+65536;
    private readonly FileStream stream;
    private readonly string sensor,collector,epoch;
    private readonly int slots;
    private readonly object gate=new();
    private readonly List<Entry> entries=[];
    private readonly Action<string,int>? checkpoint;
    private readonly bool readOnly;
    private Boundary? boundary;
    private bool disposed,ioFaulted;
    private InputSeal? inputSeal;
    internal bool CanAppend=>RotatingRoot?RotationCanAppend:!readOnly&&inputSeal==null&&!disposed&&!ioFaulted;
    internal InputSeal? SealedInput {get{lock(gate)return RotatingRoot?logSeal:inputSeal;}}
    internal bool Reopened {get;}
    internal bool PhysicalAllocationEstablished {get;}
    internal FileIdentityEvidence BankIdentity {get;}
    internal string CollectorInstance=>collector;
    internal string SensorId=>sensor;
    internal string ProviderEpoch=>epoch;
    internal string FullPath=>Path.GetFullPath(stream.Name);
    internal Entry[] Entries {get{lock(gate)return AllEntries();}}
    internal Boundary? FirstBoundary {get{lock(gate)return boundary??segments.Select(x=>x.FirstBoundary).FirstOrDefault(x=>x!=null);}}
    [DllImport("libc",SetLastError=true,EntryPoint="fallocate")]
    private static extern int Allocate(SafeFileHandle file,int mode,long offset,long length);
    // Own the newly created, zero-filled file before the loader starts its
    // activation deadline. No provider epoch or source authority exists yet.
    // The same held descriptor is transferred exactly once after native ready.
    internal sealed class Preparation:IDisposable
    {
        private FileStream? owned;
        internal string Directory {get;}
        internal string Sensor {get;}
        internal string Collector {get;}
        internal int Slots {get;}
        internal bool PhysicalAllocationEstablished {get;}
        internal FileIdentityEvidence Identity {get;}
        internal DateTimeOffset StartedUtc {get;}
        internal DateTimeOffset CompletedUtc {get;}
        internal long StartedMonotonic {get;}
        internal long CompletedMonotonic {get;}
        internal Preparation(string directory,string sensor,string collector,int slots,bool layoutReplayForTest,string? quotaDirectory,long quotaBytes)
        {
            if(!Guid.TryParseExact(sensor,"N",out _)||!Guid.TryParseExact(collector,"N",out _)||slots is <5 or >4096)
                throw new ArgumentException("Exact preparation owner and bounded capacity required");
            if(!OperatingSystem.IsLinux()&&!layoutReplayForTest)throw new PlatformNotSupportedException("Physical Linux preparation required");
            Directory=Path.GetFullPath(directory);Sensor=sensor;Collector=collector;Slots=slots;
            StartedUtc=DateTimeOffset.UtcNow;StartedMonotonic=Stopwatch.GetTimestamp();
            EvidenceStore.EnsurePrivate(Directory);
            long size=HeaderBytes+(long)(slots+1)*(IntentBytes+SlotBytes);
            if(quotaDirectory!=null)RequirePreparationCapacity(Directory,quotaDirectory,size,quotaBytes);
            var path=Path.Combine(Directory,"raw-ingress-v3.bin");EvidenceDurability.NoLinks(path);
            var options=new FileStreamOptions{Mode=FileMode.CreateNew,Access=FileAccess.ReadWrite,Share=FileShare.None};
            if(!OperatingSystem.IsWindows())options.UnixCreateMode=UnixFileMode.UserRead|UnixFileMode.UserWrite;
            owned=new FileStream(path,options);
            try
            {
                PhysicalAllocationEstablished=OperatingSystem.IsLinux();
                if(PhysicalAllocationEstablished)
                {if(Allocate(owned.SafeFileHandle,0,0,size)!=0)throw new Win32Exception(Marshal.GetLastPInvokeError());}
                else owned.SetLength(size); // Explicit layout replay only.
                owned.Flush(true);EvidenceDurability.DirectoryCommitted(Directory);
                Identity=NativeFileIdentity.Read(owned);
                if(Identity.Size!=size)throw new IOException("Prepared bank allocation length changed");
                CompletedUtc=DateTimeOffset.UtcNow;CompletedMonotonic=Stopwatch.GetTimestamp();
            }
            catch{owned.Dispose();owned=null;throw;}
        }
        internal FileStream Take(string directory,string sensor,string collector,int slots)
        {
            if(Path.GetFullPath(directory)!=Directory||sensor!=Sensor||collector!=Collector||slots!=Slots)
                throw new InvalidDataException("Prepared bank owner or capacity changed");
            var stream=owned??throw new InvalidOperationException("Prepared bank already transferred or closed");
            var current=NativeFileIdentity.Read(stream);
            if(!NativeFileIdentity.Same(Identity,current)||Identity.ResolvedPath==null||current.ResolvedPath!=Identity.ResolvedPath)
                throw new IOException("Prepared bank changed before native binding");
            owned=null;return stream;
        }
        public void Dispose(){owned?.Dispose();owned=null;}
    }
    // The existing journal quota covers bound banks. Include retained unbound
    // preparations too, so early policy expiry cannot allocate one new bank
    // on every automatic restart without consuming that same storage budget.
    // Production calls this while holding the existing journal/runtime owner.
    private static void RequirePreparationCapacity(string directory,string quotaDirectory,long requested,long quotaBytes)
    {
        var root=Path.GetFullPath(quotaDirectory);
        if(Path.GetDirectoryName(Path.GetDirectoryName(Path.GetFullPath(directory)))!=root||quotaBytes<=0)
            throw new ArgumentException("Exact source parent and positive preparation quota required");
        EvidenceDurability.NoLinks(root);
        long retained=0;
        foreach(var source in System.IO.Directory.EnumerateDirectories(root))
        {
            var raw=Path.Combine(source,"raw");EvidenceDurability.NoLinks(raw);
            if(!System.IO.Directory.Exists(raw))continue;
            var banks=System.IO.Directory.EnumerateFiles(raw,"raw-ingress-v3.bin",SearchOption.AllDirectories).Take(16385).ToArray();
            if(banks.Length>16384)throw new IOException("RAW_BANK_INVENTORY_BOUND_EXCEEDED");
            foreach(var bank in banks){EvidenceDurability.NoLinks(Path.GetDirectoryName(bank)!);EvidenceDurability.NoLinks(bank);retained=checked(retained+new FileInfo(bank).Length);}
        }
        if(checked(retained+requested)>quotaBytes)
            throw new IOException("RAW_BANK_QUOTA_EXHAUSTED: retained bound and unbound storage preserved; loader not started");
    }
    internal static Preparation Prepare(string directory,string sensor,string collector,int slots,bool layoutReplayForTest=false,
        string? quotaDirectory=null,long quotaBytes=512L*1024*1024)
        =>new(directory,sensor,collector,slots,layoutReplayForTest,quotaDirectory,quotaBytes);
    internal LinuxRawIngressReserve(Preparation preparation,string epoch,bool layoutReplayForTest=false,bool rotating=false,string? quotaDirectory=null,long quotaBytes=512L*1024*1024)
        :this(preparation.Directory,preparation.Sensor,preparation.Collector,epoch,preparation.Slots,layoutReplayForTest,null,false,preparation,rotating)
        {this.rotationQuotaDirectory=quotaDirectory;this.rotationQuotaBytes=quotaBytes;}
    internal LinuxRawIngressReserve(string directory,string sensor,string collector,string epoch,int slots,
        bool layoutReplayForTest=false,Action<string,int>? checkpoint=null)
        :this(directory,sensor,collector,epoch,slots,layoutReplayForTest,checkpoint,false){}
    // Historical inventory/recovery has no writable bank, physical allocation
    // claim or native capability. The same parser verifies the exact format.
    internal static LinuxRawIngressReserve OpenReadOnly(string directory,string sensor,string collector,string epoch,int slots)
        =>new(directory,sensor,collector,epoch,slots,true,null,true);
    private LinuxRawIngressReserve(string directory,string sensor,string collector,string epoch,int slots,
        bool layoutReplayForTest,Action<string,int>? checkpoint,bool readOnly,Preparation? preparation=null,bool rotating=false,int sequenceBase=0)
    {
        if(!Guid.TryParseExact(sensor,"N",out _)||!Guid.TryParseExact(collector,"N",out _)||!Counter(epoch)||epoch=="0"||slots is <5 or >4096)
            throw new ArgumentException("Exact sensor, collector, nonzero epoch and bounded capacity required");
        if(!OperatingSystem.IsLinux()&&!layoutReplayForTest)throw new PlatformNotSupportedException("Physical Linux admission required; layout replay must be explicit");
        this.sensor=sensor;this.collector=collector;this.epoch=epoch;this.sequenceBase=sequenceBase;this.rotating=rotating;this.slots=slots;this.checkpoint=checkpoint;this.readOnly=readOnly;
        if(!readOnly)EvidenceStore.EnsurePrivate(directory);var path=Path.Combine(directory,"raw-ingress-v3.bin");EvidenceDurability.NoLinks(path);
        Reopened=preparation==null&&File.Exists(path);var options=new FileStreamOptions{Mode=readOnly||Reopened?FileMode.Open:FileMode.CreateNew,Access=readOnly?FileAccess.Read:FileAccess.ReadWrite,Share=readOnly?FileShare.Read:FileShare.None};
        if(!OperatingSystem.IsWindows()&&!Reopened&&!readOnly)options.UnixCreateMode=UnixFileMode.UserRead|UnixFileMode.UserWrite;
        stream=preparation?.Take(directory,sensor,collector,slots)??new FileStream(path,options);
        try
        {
            long size=HeaderBytes+(long)(slots+1)*(IntentBytes+SlotBytes);
            PhysicalAllocationEstablished=!readOnly&&OperatingSystem.IsLinux();
            if(!Reopened)
            {
                if(preparation==null)
                {
                    if(PhysicalAllocationEstablished){if(Allocate(stream.SafeFileHandle,0,0,size)!=0)throw new Win32Exception(Marshal.GetLastPInvokeError());}
                    else stream.SetLength(size);
                }
                stream.Write(Header());stream.Flush(true);EvidenceDurability.DirectoryCommitted(directory);
            }
            if(stream.Length!=size)throw new InvalidDataException("Ingress bank length changed; evidence retained");
            var header=new byte[HeaderBytes];stream.Position=0;stream.ReadExactly(header);
            if(readOnly&&header.AsSpan(0,8).SequenceEqual("SQRAW004"u8))
            {
                if(BinaryPrimitives.ReadInt32LittleEndian(header.AsSpan(68))!=sequenceBase)throw new InvalidDataException("Raw segment sequence base differs from its exact chain position");
                this.rotating=true;
            }
            if(header[64]>1||!header.AsSpan().SequenceEqual(Header(readOnly?header[64]!=0:null)))throw new InvalidDataException("Ingress bank owner, epoch, format or platform changed");
            if(PhysicalAllocationEstablished&&preparation==null)
            {if(Allocate(stream.SafeFileHandle,0,0,size)!=0)throw new Win32Exception(Marshal.GetLastPInvokeError());stream.Flush(true);}
            BankIdentity=NativeFileIdentity.Read(stream);
            // New held preparation has no prior entries. Reopened files still
            // take the complete corruption/gap/seal validation path below.
            if(preparation!=null){InitializeRotation();return;}
            bool gap=false;var ids=new HashSet<string>(StringComparer.Ordinal);
            for(int i=0;i<slots;i++)
            {
                var bytes=ReadSlot(i);
                if(bytes==null){gap=true;continue;}
                if(gap)throw new InvalidDataException("Interrupted ingress slot range; coverage unknown");
                var (entry,_)=Decode(bytes,i);
                if(!ids.Add(entry.DeliveryId))throw new InvalidDataException("Duplicate ingress delivery identity");entries.Add(entry);
            }
            if(ReadSlot(slots) is {} emergency)
            {
                boundary=JsonSerializer.Deserialize<Boundary>(emergency)??throw new InvalidDataException("Missing ingress boundary");
                Validate(boundary);
                if(!JsonSerializer.SerializeToUtf8Bytes(boundary).AsSpan().SequenceEqual(emergency))throw new InvalidDataException("Ingress boundary serialization changed");
            }
            inputSeal=ReadSeal();
            InitializeRotation();
        }
        catch{foreach(var segment in segments)segment.Dispose();stream.Dispose();throw;}
    }
    private static bool Counter(string value)=>ulong.TryParse(value,NumberStyles.None,CultureInfo.InvariantCulture,out var number)&&number.ToString(CultureInfo.InvariantCulture)==value;
    private byte[] Header(bool? storedPhysicalMarker=null)
    {
        var bytes=new byte[HeaderBytes];(rotating?"SQRAW004"u8:"SQRAW003"u8).CopyTo(bytes);BinaryPrimitives.WriteInt32LittleEndian(bytes.AsSpan(8),slots);
        BinaryPrimitives.WriteInt32LittleEndian(bytes.AsSpan(12),SlotBytes);BinaryPrimitives.WriteInt32LittleEndian(bytes.AsSpan(16),IntentBytes);
        new Guid(sensor).TryWriteBytes(bytes.AsSpan(24,16));new Guid(collector).TryWriteBytes(bytes.AsSpan(40,16));
        BinaryPrimitives.WriteUInt64LittleEndian(bytes.AsSpan(56),ulong.Parse(epoch,CultureInfo.InvariantCulture));bytes[64]=(storedPhysicalMarker??PhysicalAllocationEstablished)?(byte)1:(byte)0;
        if(rotating){bytes[65]=1;BinaryPrimitives.WriteInt32LittleEndian(bytes.AsSpan(68),sequenceBase);}
        "raw-before-decode-v3;json-default-v1"u8.CopyTo(bytes.AsSpan(72));SHA256.HashData(bytes.AsSpan(0,128)).CopyTo(bytes.AsSpan(128));return bytes;
    }
    private static void ValidateView(LinuxSourceWorkBarrier.View value)
    {
        if(value==null)throw new InvalidDataException("Missing ingress source-state view");
        if(value.Generation<1||value.State is not ("Active" or "Faulted" or "StopRequested" or "Closing")||value.Reason?.Length>128||
            value.State=="Active"&&(value.FirstInterruption!=null||value.ChangedUtc!=null||value.Reason!=null)||
            value.State!="Active"&&(value.ChangedUtc==null||value.ChangedUtc==default(DateTimeOffset)||string.IsNullOrWhiteSpace(value.Reason)||value.FirstInterruption==null))
            throw new InvalidDataException("Invalid ingress source-state view");
        if(value.FirstInterruption is {} first&&(first.Generation<2||first.Generation>value.Generation||first.State is not ("Faulted" or "StopRequested" or "Closing")||string.IsNullOrWhiteSpace(first.Reason)||first.Reason.Length>128||first.RecordedUtc==default))
            throw new InvalidDataException("Invalid first interruption evidence");
    }
    private (Entry Entry,byte[] Raw) Decode(byte[] bytes,int index)
    {
        if(bytes.Length<8)throw new InvalidDataException("Truncated ingress envelope");
        int metadata=BinaryPrimitives.ReadInt32LittleEndian(bytes),length=BinaryPrimitives.ReadInt32LittleEndian(bytes.AsSpan(4));
        if(metadata is <2 or >MetadataLimit||length is <0 or >65536||bytes.Length!=8+metadata+length)throw new InvalidDataException("Invalid bounded ingress envelope");
        var e=JsonSerializer.Deserialize<Entry>(bytes.AsSpan(8,metadata))??throw new InvalidDataException("Missing ingress metadata");
        ValidateView(e.View);var raw=bytes.AsSpan(8+metadata,length);
        if(e.Version!=(rotating?4:3)||e.Sensor!=sensor||e.Collector!=collector||e.ProviderEpoch!=epoch||e.Sequence!=sequenceBase+index+1||!Guid.TryParseExact(e.DeliveryId,"N",out _)||e.ReceivedUtc==default||!Counter(e.MonotonicTicks)||e.RawLength!=length||e.RawSha256!=Convert.ToHexString(SHA256.HashData(raw))||!JsonSerializer.SerializeToUtf8Bytes(e).AsSpan().SequenceEqual(bytes.AsSpan(8,metadata)))
            throw new InvalidDataException("Ingress envelope contradicts owner, raw bytes or canonical metadata");
        return(e,raw.ToArray());
    }
    private void Validate(Boundary value)
    {
        ValidateView(value.View);
        if(value.Version!=(rotating?4:3)||!Guid.TryParseExact(value.BoundaryId,"N",out _)||string.IsNullOrWhiteSpace(value.Reason)||value.Reason.Length>128||value.RecordedUtc==default||
            value.Sensor!=sensor||value.Collector!=collector||value.ProviderEpoch!=epoch||!value.OpenEnded||value.InputLength<0||value.Error?.Length>128||
            value.LastDurableSequence<sequenceBase||value.LastDurableSequence>sequenceBase+entries.Count||value.LastDurableDeliveryId!=(value.LastDurableSequence==sequenceBase?null:entries[value.LastDurableSequence-sequenceBase-1].DeliveryId))
            throw new InvalidDataException("Ingress boundary contradicts its durable prefix");
    }
    private Admission CommitSegment(ReadOnlyMemory<byte> raw,LinuxSourceWorkBarrier.View view,DateTimeOffset receivedUtc)
    {
        if(raw.Length>65536||receivedUtc==default)throw new InvalidDataException("Bounded frame and actual receipt time required");ValidateView(view);
        lock(gate)
        {
            RequireWritable();
            if(entries.Count==slots)
                return new(false,null,RecordBoundary("RAW_BACKLOG_EXHAUSTED",view,raw.Length,null).Boundary);
            var entry=new Entry(rotating?4:3,sensor,collector,epoch,Guid.NewGuid().ToString("N"),sequenceBase+entries.Count+1,receivedUtc,
                Stopwatch.GetTimestamp().ToString(CultureInfo.InvariantCulture),view,raw.Length,Convert.ToHexString(SHA256.HashData(raw.Span)));
            var metadata=JsonSerializer.SerializeToUtf8Bytes(entry);
            if(metadata.Length>MetadataLimit)throw new InvalidDataException("Ingress metadata exceeds bound");
            var bytes=new byte[8+metadata.Length+raw.Length];BinaryPrimitives.WriteInt32LittleEndian(bytes,metadata.Length);BinaryPrimitives.WriteInt32LittleEndian(bytes.AsSpan(4),raw.Length);
            metadata.CopyTo(bytes,8);raw.Span.CopyTo(bytes.AsSpan(8+metadata.Length));WriteSlot(entries.Count,bytes);entries.Add(entry);return new(true,entry,boundary);
        }
    }
    internal BoundaryReceipt RecordBoundary(string reason,LinuxSourceWorkBarrier.View view,long? inputLength,string? error)
    {
        lock(gate)
        {
            // Select the active segment under the rotation lock. An index
            // failure must not write its emergency receipt to the predecessor
            // after the pump has sealed and advanced that segment.
            if(RotatingRoot&&segments.Count>0)return segments[^1].RecordBoundary(reason,view,inputLength,error);
            RequireWritable();
            if(boundary!=null)return new(false,boundary); // Never claim the new reason was written.
            var value=new Boundary(rotating?4:3,Guid.NewGuid().ToString("N"),reason,DateTimeOffset.UtcNow,sensor,collector,epoch,view,sequenceBase+entries.Count,entries.LastOrDefault()?.DeliveryId,inputLength,error);
            Validate(value);var bytes=JsonSerializer.SerializeToUtf8Bytes(value);if(bytes.Length>MetadataLimit)throw new InvalidDataException("Ingress boundary exceeds fixed bound");
            WriteSlot(slots,bytes);boundary=value;return new(true,value);
        }
    }
    internal byte[] ReadRaw(Entry entry)
    {
        if(RotatingRoot&&entry.Sequence>slots){lock(gate)return segments.Single(x=>entry.Sequence>x.sequenceBase&&entry.Sequence<=x.sequenceBase+x.slots).ReadRaw(entry);}
        lock(gate)
        {
            ObjectDisposedException.ThrowIf(disposed,this);
            if(entry.Sequence<=sequenceBase||entry.Sequence>sequenceBase+entries.Count||entries[entry.Sequence-sequenceBase-1]!=entry)throw new InvalidDataException("Entry does not belong to this committed ingress bank");
            try{return Decode(ReadSlot(entry.Sequence-sequenceBase-1)??throw new InvalidDataException("Committed raw slot missing"),entry.Sequence-sequenceBase-1).Raw;}
            catch{ioFaulted=true;throw;}
        }
    }
    // A separate immutable receipt preserves v3 bank compatibility. It seals
    // every physical receipt, including raw-only diagnostics and the first
    // emergency boundary. Opening a sealed bank never restores write authority.
    private InputSeal DescribeSeal(DateTimeOffset utc)=>new(1,sensor,collector,epoch,BankIdentity.StableId,BankIdentity.Size,slots,
        entries.Count,entries.LastOrDefault()?.DeliveryId,Convert.ToHexString(SHA256.HashData(JsonSerializer.SerializeToUtf8Bytes(entries))),
        Convert.ToHexString(SHA256.HashData(JsonSerializer.SerializeToUtf8Bytes(boundary))),utc);
    private InputSeal? ReadSeal()
    {
        var path=FullPath+".sealed.json";EvidenceDurability.NoLinks(path);
        if(!File.Exists(path))return null;
        using var file=new FileStream(path,FileMode.Open,FileAccess.Read,FileShare.Read);
        if(file.Length is <2 or >4096)throw new InvalidDataException("Raw input seal outside its bound");
        var bytes=new byte[(int)file.Length];file.ReadExactly(bytes);
        var value=JsonSerializer.Deserialize<InputSeal>(bytes)??throw new InvalidDataException("Missing raw input seal");
        if(value.SealedUtc==default||value!=DescribeSeal(value.SealedUtc)||!JsonSerializer.SerializeToUtf8Bytes(value).AsSpan().SequenceEqual(bytes))
            throw new InvalidDataException("Raw input changed after sealing; evidence retained");
        return value;
    }
    private InputSeal SealSegmentInput(DateTimeOffset utc)
    {
        lock(gate)
        {
            ObjectDisposedException.ThrowIf(disposed,this);
            if(inputSeal!=null)return inputSeal;
            // Retry an interrupted receipt write without manufacturing a new
            // seal timestamp. Directory durability is re-established too.
            if(ReadSeal() is {} existing){EvidenceDurability.DirectoryCommitted(Path.GetDirectoryName(FullPath)!);return inputSeal=existing;}
            RequireWritable();if(utc==default)throw new ArgumentException("Actual input seal time required");
            var value=DescribeSeal(utc);EvidenceDurability.SaveNew(FullPath+".sealed.json",JsonSerializer.SerializeToUtf8Bytes(value));
            return inputSeal=ReadSeal()??throw new IOException("Input seal not readable after commit");
        }
    }
    private void RequireWritable()
    {
        ObjectDisposedException.ThrowIf(disposed,this);
        // A SaveNew directory-sync failure can leave the seal already named.
        // Such a receipt must still revoke writes before a retry adopts it.
        if(!readOnly&&inputSeal==null)inputSeal=ReadSeal();
        if(readOnly||inputSeal!=null)throw new InvalidOperationException("Historical or sealed ingress cannot append or grant native authority");
        if(ioFaulted)throw new IOException("RAW_INGRESS_IO_UNKNOWN: bank retained; no further writes authorized");
    }
    private long Offset(int index)=>HeaderBytes+(long)(slots+1)*IntentBytes+(long)index*SlotBytes;
    private byte[]? ReadIntent(int index)
    {
        var bytes=new byte[IntentBytes];stream.Position=HeaderBytes+(long)index*IntentBytes;stream.ReadExactly(bytes);
        if(bytes.AsSpan().IndexOfAnyExcept((byte)0)<0)return null;
        if(!bytes.AsSpan(0,8).SequenceEqual("SQINT003"u8)||BinaryPrimitives.ReadInt32LittleEndian(bytes.AsSpan(8))!=index||BinaryPrimitives.ReadInt32LittleEndian(bytes.AsSpan(12)) is <2 or >MaximumBody||
            !SHA256.HashData(bytes.AsSpan(0,48)).AsSpan().SequenceEqual(bytes.AsSpan(48,32))||bytes.AsSpan(80).IndexOfAnyExcept((byte)0)>=0)
            throw new InvalidDataException("Ingress intent corrupt or interrupted");
        return bytes;
    }
    private byte[]? ReadSlot(int index)
    {
        var intent=ReadIntent(index);var bytes=new byte[SlotBytes];stream.Position=Offset(index);stream.ReadExactly(bytes);
        if(bytes.AsSpan().IndexOfAnyExcept((byte)0)<0)
        {if(intent!=null)throw new InvalidDataException("RAW_INGRESS_INTERRUPTED_UNKNOWN: intent without frame");return null;}
        int length=BinaryPrimitives.ReadInt32LittleEndian(bytes.AsSpan(8));
        if(intent==null||!bytes.AsSpan(0,8).SequenceEqual("SQREC003"u8)||length is <2 or >MaximumBody||BinaryPrimitives.ReadInt32LittleEndian(bytes.AsSpan(12))!=index||BinaryPrimitives.ReadInt32LittleEndian(intent.AsSpan(12))!=length||
            !bytes.AsSpan(16,32).SequenceEqual(intent.AsSpan(16,32))||!SHA256.HashData(bytes.AsSpan(PrefixBytes,length)).AsSpan().SequenceEqual(intent.AsSpan(16,32))||bytes.AsSpan(PrefixBytes+length).IndexOfAnyExcept((byte)0)>=0)
            throw new InvalidDataException("Ingress frame or prior intent mismatch");
        return bytes.AsSpan(PrefixBytes,length).ToArray();
    }
    private void WriteSlot(int index,byte[] body)
    {
        try
        {
            if(body.Length is <2 or >MaximumBody||ReadSlot(index)!=null)throw new InvalidOperationException("Ingress never overwrites an existing slot");
            var intent=new byte[IntentBytes];"SQINT003"u8.CopyTo(intent);BinaryPrimitives.WriteInt32LittleEndian(intent.AsSpan(8),index);BinaryPrimitives.WriteInt32LittleEndian(intent.AsSpan(12),body.Length);
            SHA256.HashData(body).CopyTo(intent.AsSpan(16));SHA256.HashData(intent.AsSpan(0,48)).CopyTo(intent.AsSpan(48));
            stream.Position=HeaderBytes+(long)index*IntentBytes;stream.Write(intent);stream.Flush(true);
            if(!ReadIntent(index)!.AsSpan().SequenceEqual(intent))throw new IOException("Ingress intent readback differs");checkpoint?.Invoke("ingress-intent-committed",index);
            var bytes=new byte[SlotBytes];"SQREC003"u8.CopyTo(bytes);BinaryPrimitives.WriteInt32LittleEndian(bytes.AsSpan(8),body.Length);BinaryPrimitives.WriteInt32LittleEndian(bytes.AsSpan(12),index);
            intent.AsSpan(16,32).CopyTo(bytes.AsSpan(16));body.CopyTo(bytes,PrefixBytes);stream.Position=Offset(index);stream.Write(bytes);stream.Flush(true);
            if(!ReadSlot(index)!.AsSpan().SequenceEqual(body))throw new IOException("Ingress frame readback differs");checkpoint?.Invoke("ingress-frame-committed",index);
        }
        catch{ioFaulted=true;throw;}
    }
    public void Dispose(){lock(gate){if(disposed)return;disposed=true;foreach(var segment in segments)segment.Dispose();stream.Dispose();}}
}
