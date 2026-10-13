using System.Buffers.Binary;
using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text.Json;
using Microsoft.Win32.SafeHandles;
using RansomFree.Contracts;

namespace RansomFree.Client.Forensics;

// Append-only raw admission storage companion for LinuxForensicJournal.
// It is independent of SQLite/WAL allocation and native acquisition permits.
// Slots are never recycled here. Exhaustion is an explicit open unknown range,
// not permission to continue advertising complete observation coverage.
internal sealed class LinuxRawIntakeReserve:IDisposable
{
    internal sealed record RawRecord(int Version,string Sensor,string RawBase64,AgentEvent Observation,ForensicPolicy Policy)
    {
        // Runtime recovery facts, never appended to the immutable v2 envelope.
        internal string FrameIntegrity {get;init;}="verified-current-owner";
        internal string PreviousCallerAcknowledgment {get;init;}="not-a-recovered-record";
    }
    internal sealed record UnknownRange(int Version,string Reason,string? LastDurableEventId,string FirstUncommittedEventId,
        string ProviderEpoch,string Cookie,DateTimeOffset RecordedUtc,bool OpenEnded=true);
    internal sealed record CommitResult(bool Committed,bool Duplicate,RawRecord? Record,UnknownRange? Overflow);
    private const int HeaderBytes=4096,SlotBytes=131072,PrefixBytes=48,IntentBytes=256;
    // Binary envelope: four Int32 lengths/version + independently bounded raw,
    // canonical observation and policy. No Base64/JSON escaping expansion.
    internal const int MaximumEnvelopeBytes=16+65536+24576+4096;
    private readonly FileStream stream;
    private readonly string sensor;
    private readonly int slots;
    private readonly object gate=new();
    private readonly List<RawRecord> records=[];
    private readonly Dictionary<string,string> bodyHashes=new(StringComparer.Ordinal);
    private UnknownRange? overflow;
    private bool disposed,faulted;
    private readonly Action<string,int>? checkpoint;
    internal UnknownRange? Overflow {get{lock(gate)return overflow;}}
    internal bool Reopened {get;}
    // Recovered bytes never prove a previous caller received a successful
    // fsync/commit acknowledgment. The source must retain its lifecycle gap.
    internal bool PreviousCommitAcknowledgmentsUnknown=>Reopened;
    internal bool PhysicalAllocationEstablished {get;}
    internal string FullPath=>Path.GetFullPath(stream.Name);
    internal FileIdentityEvidence BankIdentity {get;}
    internal IReadOnlyList<RawRecord> Records {get{lock(gate)return records.ToArray();}}
    [DllImport("libc",SetLastError=true,EntryPoint="fallocate")]
    private static extern int Allocate(SafeFileHandle file,int mode,long offset,long length);

    internal LinuxRawIntakeReserve(string directory,string sensor,int slots,Action<string,int>? checkpoint=null)
    {
        if(!Guid.TryParseExact(sensor,"N",out _)||slots is <5 or >4096)throw new ArgumentException("Invalid raw intake reservation");
        this.sensor=sensor;this.slots=slots;this.checkpoint=checkpoint;EvidenceStore.EnsurePrivate(directory);
        // Version 1 evidence remains untouched; its torn-zero ambiguity cannot
        // be repaired by interpreting the same bytes as this new format.
        var path=Path.Combine(directory,"raw-reserve-v2.bin");EvidenceDurability.NoLinks(path);
        var exists=File.Exists(path);
        Reopened=exists;
        var options=new FileStreamOptions{Mode=exists?FileMode.Open:FileMode.CreateNew,Access=FileAccess.ReadWrite,Share=FileShare.None};
        if(!OperatingSystem.IsWindows()&&!exists)options.UnixCreateMode=UnixFileMode.UserRead|UnixFileMode.UserWrite;
        stream=new FileStream(path,options);
        try
        {
            var length=HeaderBytes+(long)(slots+1)*(SlotBytes+IntentBytes);
            if(!exists)
            {
                if(OperatingSystem.IsLinux())
                {
                    // No sparse-file fallback: a successful Linux admission
                    // requires actual allocation of this exact writable range.
                    if(Allocate(stream.SafeFileHandle,0,0,length)!=0)throw new Win32Exception(Marshal.GetLastPInvokeError());
                }
                else stream.SetLength(length); // Layout replay only, not Linux physical admission.
                var header=Header(sensor,slots,OperatingSystem.IsLinux());
                stream.Position=0;stream.Write(header);stream.Flush(true);EvidenceDurability.DirectoryCommitted(directory);
            }
            if(stream.Length!=length)throw new InvalidDataException("Raw reserve allocation/layout incomplete; retained");
            var actual=new byte[HeaderBytes];stream.Position=0;stream.ReadExactly(actual);
            PhysicalAllocationEstablished=OperatingSystem.IsLinux();
            if(!actual.AsSpan().SequenceEqual(Header(sensor,slots,PhysicalAllocationEstablished)))throw new InvalidDataException("Raw reserve sensor, capacity or platform changed; retained");
            // Re-establish allocation on Linux reopen; do not assume surviving
            // length proves reserved blocks (e.g. a sparse/copied backup).
            if(OperatingSystem.IsLinux()&&Allocate(stream.SafeFileHandle,0,0,length)!=0)throw new Win32Exception(Marshal.GetLastPInvokeError());
            if(OperatingSystem.IsLinux())stream.Flush(true);
            BankIdentity=NativeFileIdentity.Read(stream);
            var gap=false;
            for(int i=0;i<slots;i++)
            {
                var bytes=ReadSlot(i);
                if(bytes==null){gap=true;continue;}
                if(gap)throw new InvalidDataException("Raw reserve has an interrupted slot range; coverage unknown");
                var record=DecodeRecord(bytes);Validate(record);
                VerifyIntent(i,bytes,record.Observation);
                if(records.Any(x=>x.Observation.EventId==record.Observation.EventId))throw new InvalidDataException("Duplicate raw reserve identity");
                records.Add(record with{FrameIntegrity="verified-recovered",PreviousCallerAcknowledgment="unknown-before-this-open"});bodyHashes.Add(record.Observation.EventId,Convert.ToHexString(SHA256.HashData(bytes)));
            }
            var emergency=ReadSlot(slots);
            if(emergency!=null)
            {
                overflow=JsonSerializer.Deserialize<UnknownRange>(emergency)??throw new InvalidDataException("Invalid emergency slot");
                if(overflow.Version!=1||overflow.Reason!="RAW_BACKLOG_EXHAUSTED"||!overflow.OpenEnded||!Guid.TryParseExact(overflow.FirstUncommittedEventId,"N",out _)||overflow.LastDurableEventId!=records.LastOrDefault()?.Observation.EventId)throw new InvalidDataException("Invalid raw overflow range; retained");
                var intent=ReadIntent(slots)!;
                if(new Guid(intent.AsSpan(48,16)).ToString("N")!=overflow.FirstUncommittedEventId||BinaryPrimitives.ReadUInt64LittleEndian(intent.AsSpan(64)).ToString(System.Globalization.CultureInfo.InvariantCulture)!=overflow.ProviderEpoch||BinaryPrimitives.ReadUInt64LittleEndian(intent.AsSpan(72)).ToString(System.Globalization.CultureInfo.InvariantCulture)!=overflow.Cookie)throw new InvalidDataException("Emergency intent identity differs from overflow boundary");
            }
        }
        catch{stream.Dispose();throw;}
    }
    private static byte[] Header(string sensor,int count,bool allocated)
    {
        var header=new byte[HeaderBytes];"SQRAW002"u8.CopyTo(header);BinaryPrimitives.WriteInt32LittleEndian(header.AsSpan(8),count);
        BinaryPrimitives.WriteInt32LittleEndian(header.AsSpan(12),SlotBytes);new Guid(sensor).TryWriteBytes(header.AsSpan(16,16));header[32]=allocated?(byte)1:(byte)0;
        BinaryPrimitives.WriteInt32LittleEndian(header.AsSpan(36),IntentBytes);BinaryPrimitives.WriteInt32LittleEndian(header.AsSpan(40),MaximumEnvelopeBytes);
        "sq-raw-binary-v2;json-default-v1"u8.CopyTo(header.AsSpan(48));
        SHA256.HashData(header.AsSpan(0,128)).CopyTo(header.AsSpan(128,32));return header;
    }
    private void Validate(RawRecord record)
    {
        if(record.Version!=2||record.Sensor!=sensor||record.Policy==null||!record.Policy.IsValid()||record.Observation?.Attribution?.LinuxKernel is not {} k||record.Observation.Forensics!=null||record.Observation.Trust!=null)throw new InvalidDataException("Invalid raw reserve record");
        var raw=Convert.FromBase64String(record.RawBase64);
        var decoded=LinuxKernelDecoder.Decode(raw,sensor,k.CollectorInstance,k.CollectorSequence,record.Observation.ObservedUtc);
        if(!EventSpool.Encode(decoded).AsSpan().SequenceEqual(EventSpool.Encode(record.Observation)))throw new InvalidDataException("Raw reserve typed event contradicts native bytes");
    }
    internal bool Commit(ReadOnlyMemory<byte> raw,AgentEvent observation,ForensicPolicy policy)
        =>CommitRecord(raw,observation,policy).Committed;
    internal CommitResult CommitRecord(ReadOnlyMemory<byte> raw,AgentEvent observation,ForensicPolicy policy)
    {
        var record=new RawRecord(2,sensor,Convert.ToBase64String(raw.Span),observation,policy);Validate(record);
        var bytes=EncodeRecord(record);
        lock(gate)
        {
            ObjectDisposedException.ThrowIf(disposed,this);
            if(faulted)throw new IOException("RAW_RESERVE_IO_FAILED_UNVERIFIED: admission stopped; reserve retained");
            var prior=records.FirstOrDefault(x=>x.Observation.EventId==observation.EventId);
            if(prior!=null){if(bodyHashes[prior.Observation.EventId]!=Convert.ToHexString(SHA256.HashData(bytes)))throw new InvalidDataException("Raw reserve event conflict");return new(true,true,prior,overflow);}
            if(overflow!=null)return new(false,false,null,overflow);
            if(records.Count==slots)
            {
                var k=observation.Attribution!.LinuxKernel!;
                var missing=new UnknownRange(1,"RAW_BACKLOG_EXHAUSTED",records[^1].Observation.EventId,observation.EventId,k.ProviderEpoch,k.Cookie,DateTimeOffset.UtcNow);
                WriteSlot(slots,JsonSerializer.SerializeToUtf8Bytes(missing),observation);overflow=missing;return new(false,false,null,overflow);
            }
            WriteSlot(records.Count,bytes,observation);records.Add(record);bodyHashes.Add(observation.EventId,Convert.ToHexString(SHA256.HashData(bytes)));return new(true,false,record,null);
        }
    }
    private byte[] EncodeRecord(RawRecord record)
    {
        var raw=Convert.FromBase64String(record.RawBase64);var observation=EventSpool.Encode(record.Observation);var policy=LinuxRawPolicyCodec.Encode(record.Policy);
        if(raw.Length>65536||observation.Length>24576||policy.Length>4096)throw new InvalidDataException("Unsupported raw, observation or policy bound; source must record unknown protocol coverage");
        var bytes=new byte[16+raw.Length+observation.Length+policy.Length];
        BinaryPrimitives.WriteInt32LittleEndian(bytes,2);BinaryPrimitives.WriteInt32LittleEndian(bytes.AsSpan(4),raw.Length);BinaryPrimitives.WriteInt32LittleEndian(bytes.AsSpan(8),observation.Length);BinaryPrimitives.WriteInt32LittleEndian(bytes.AsSpan(12),policy.Length);
        raw.CopyTo(bytes,16);observation.CopyTo(bytes,16+raw.Length);policy.CopyTo(bytes,16+raw.Length+observation.Length);return bytes;
    }
    private RawRecord DecodeRecord(byte[] bytes)
    {
        if(bytes.Length is <16 or >MaximumEnvelopeBytes||BinaryPrimitives.ReadInt32LittleEndian(bytes)!=2)throw new InvalidDataException("Unsupported binary raw envelope");
        var raw=BinaryPrimitives.ReadInt32LittleEndian(bytes.AsSpan(4));var observation=BinaryPrimitives.ReadInt32LittleEndian(bytes.AsSpan(8));var policy=BinaryPrimitives.ReadInt32LittleEndian(bytes.AsSpan(12));
        if(raw is <2 or >65536||observation is <2 or >24576||policy is <2 or >4096||bytes.Length!=16+raw+observation+policy)throw new InvalidDataException("Raw envelope lengths invalid");
        var e=JsonSerializer.Deserialize<AgentEvent>(bytes.AsSpan(16+raw,observation))??throw new InvalidDataException("Empty raw observation");
        var p=LinuxRawPolicyCodec.Decode(bytes.AsMemory(16+raw+observation,policy));
        var record=new RawRecord(2,sensor,Convert.ToBase64String(bytes.AsSpan(16,raw)),e,p);
        if(!EncodeRecord(record).AsSpan().SequenceEqual(bytes))throw new InvalidDataException("Stored raw envelope serialization changed; explicit migration required");return record;
    }
    private long DataOffset(int index)=>HeaderBytes+(long)(slots+1)*IntentBytes+(long)index*SlotBytes;
    private byte[]? ReadIntent(int index)
    {
        stream.Position=HeaderBytes+(long)index*IntentBytes;var intent=new byte[IntentBytes];stream.ReadExactly(intent);
        if(intent.AsSpan().IndexOfAnyExcept((byte)0)<0)return null;
        if(!intent.AsSpan(0,8).SequenceEqual("SQINT002"u8)||BinaryPrimitives.ReadInt32LittleEndian(intent.AsSpan(8))!=index||BinaryPrimitives.ReadInt32LittleEndian(intent.AsSpan(12)) is <2 or >SlotBytes-PrefixBytes||!SHA256.HashData(intent.AsSpan(0,136)).AsSpan().SequenceEqual(intent.AsSpan(136,32))||intent.AsSpan(168).IndexOfAnyExcept((byte)0)>=0)throw new InvalidDataException("RAW_RESERVE_INTENT_UNVERIFIED: corrupt or interrupted intent; coverage unknown");
        return intent;
    }
    private static byte[] Intent(int index,byte[] bytes,AgentEvent e)
    {
        var k=e.Attribution!.LinuxKernel!;
        if(!k.IsValid()||!Guid.TryParseExact(e.EventId,"N",out _))throw new InvalidDataException("Invalid fixed-width raw intent identity");
        var intent=new byte[IntentBytes];"SQINT002"u8.CopyTo(intent);
        BinaryPrimitives.WriteInt32LittleEndian(intent.AsSpan(8),index);BinaryPrimitives.WriteInt32LittleEndian(intent.AsSpan(12),bytes.Length);SHA256.HashData(bytes).CopyTo(intent.AsSpan(16));new Guid(e.EventId).TryWriteBytes(intent.AsSpan(48,16));
        BinaryPrimitives.WriteUInt64LittleEndian(intent.AsSpan(64),ulong.Parse(k.ProviderEpoch,System.Globalization.CultureInfo.InvariantCulture));BinaryPrimitives.WriteUInt64LittleEndian(intent.AsSpan(72),ulong.Parse(k.Cookie,System.Globalization.CultureInfo.InvariantCulture));
        Convert.FromHexString(k.NativeObservationSha256).CopyTo(intent.AsSpan(80));new Guid(k.CollectorInstance).TryWriteBytes(intent.AsSpan(112,16));BinaryPrimitives.WriteInt64LittleEndian(intent.AsSpan(128),k.CollectorSequence);
        SHA256.HashData(intent.AsSpan(0,136)).CopyTo(intent.AsSpan(136));return intent;
    }
    private void VerifyIntent(int index,byte[] bytes,AgentEvent e)
    {if(!ReadIntent(index)!.AsSpan().SequenceEqual(Intent(index,bytes,e)))throw new InvalidDataException("Raw frame contradicts its prior intent identity");}
    private byte[]? ReadSlot(int index)
    {
        var intent=ReadIntent(index);stream.Position=DataOffset(index);var slot=new byte[SlotBytes];stream.ReadExactly(slot);
        if(slot.AsSpan().IndexOfAnyExcept((byte)0)<0)
        {if(intent!=null)throw new InvalidDataException("RAW_RESERVE_INTERRUPTED_UNKNOWN: durable intent with missing frame at slot "+index);return null;}
        var length=BinaryPrimitives.ReadInt32LittleEndian(slot.AsSpan(8));
        if(intent==null||!slot.AsSpan(0,8).SequenceEqual("SQREC002"u8)||length is <2 or >SlotBytes-PrefixBytes||BinaryPrimitives.ReadInt32LittleEndian(slot.AsSpan(12))!=index||BinaryPrimitives.ReadInt32LittleEndian(intent.AsSpan(12))!=length)throw new InvalidDataException("Raw reserve interrupted/corrupt slot; coverage unknown");
        var body=slot.AsSpan(PrefixBytes,length);
        if(!SHA256.HashData(body).AsSpan().SequenceEqual(slot.AsSpan(16,32))||!slot.AsSpan(16,32).SequenceEqual(intent.AsSpan(16,32))||slot.AsSpan(PrefixBytes+length).IndexOfAnyExcept((byte)0)>=0)throw new InvalidDataException("Raw reserve checksum/padding failure; coverage unknown");
        return body.ToArray();
    }
    private void WriteSlot(int index,byte[] bytes,AgentEvent e)
    {
      try
      {
        if(bytes.Length>SlotBytes-PrefixBytes)throw new InvalidDataException("Raw reserve slot too large");
        if(ReadSlot(index)!=null)throw new InvalidOperationException("Raw reserve never overwrites committed evidence");
        var intent=Intent(index,bytes,e);stream.Position=HeaderBytes+(long)index*IntentBytes;stream.Write(intent);checkpoint?.Invoke("intent-written",index);
        stream.Flush(true);checkpoint?.Invoke("intent-flushed",index);
        if(!ReadIntent(index)!.AsSpan().SequenceEqual(intent))throw new IOException("Raw reserve intent readback differs");
        checkpoint?.Invoke("intent-readback",index);
        checkpoint?.Invoke("intent-committed",index);
        var slot=new byte[SlotBytes];"SQREC002"u8.CopyTo(slot);BinaryPrimitives.WriteInt32LittleEndian(slot.AsSpan(8),bytes.Length);BinaryPrimitives.WriteInt32LittleEndian(slot.AsSpan(12),index);
        SHA256.HashData(bytes).CopyTo(slot.AsSpan(16,32));bytes.CopyTo(slot,PrefixBytes);
        stream.Position=DataOffset(index);stream.Write(slot);checkpoint?.Invoke("frame-written",index);
        stream.Flush(true);checkpoint?.Invoke("frame-flushed",index);
        if(!ReadSlot(index)!.AsSpan().SequenceEqual(bytes))throw new IOException("Raw reserve durable readback differs");
        checkpoint?.Invoke("frame-readback",index);
        checkpoint?.Invoke("frame-committed",index);
      }
      catch{faulted=true;throw;}
    }
    public void Dispose(){lock(gate){if(disposed)return;disposed=true;stream.Dispose();}}
}
