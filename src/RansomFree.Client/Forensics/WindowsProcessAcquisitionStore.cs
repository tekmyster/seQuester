using System.Buffers.Binary;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using RansomFree.Contracts;

namespace RansomFree.Client.Forensics;

internal sealed partial class WindowsStagedActorStore
{
    // No fabricated file operation, source event ID, or accessing-thread token.
    // The later real operation supplies those, independently of this byte cache.
    private sealed record ProcessRecord(int Version,string Sensor,WindowsReadyActor Ready,string State,string Reason,
        string? SnapshotId,string? Sha256,FileIdentityEvidence? SnapshotFile,string? Metadata,DateTimeOffset RecordedUtc,
        string? SourceIdentityReply=null,EvidenceStatus? SourceIdentityFailure=null,WindowsCreationRecord? Creation=null);
    private string ProcessPath(WindowsReadyActor key)=>ProcessPath(key.Provider,key.OperationInstance.ToString("X16"),key.Generation.ToString("X16"),key.Candidate.ToString("X16"),key.Pid,key.Created);
    private string ProcessPath(string provider,string instance,string generation,string candidate,int pid,long created)
        =>Path.Combine(root,Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(sensor+":"+provider+":"+instance+":"+generation+":"+candidate+":"+pid+":"+created)))+".process.json");
    private static ActorAcquisitionEvidence TransferFields(WindowsReadyActor key)=>new(){Provider=key.Provider,ProviderStatus="0x"+key.ProviderStatus.ToString("X8"),ProviderScope=key.ProviderStatus==0?"os-uuid":"local-only",
        EventInstance=key.OperationInstance.ToString("X16"),ProcessGeneration=key.Generation.ToString("X16"),CandidateId=key.Candidate.ToString("X16"),ProcessId=key.Pid,ProcessCreatedFileTime=key.Created};
    private static void WriteFrame(FileStream stream,uint kind,byte[] bytes)
    {
        if(bytes.Length>32768)throw new InvalidDataException("Process acquisition frame exceeds bound");
        var header=new byte[16];Encoding.ASCII.GetBytes("SQACQ001").CopyTo(header,0);BinaryPrimitives.WriteUInt32LittleEndian(header.AsSpan(8),kind);BinaryPrimitives.WriteInt32LittleEndian(header.AsSpan(12),bytes.Length);
        using var digest=IncrementalHash.CreateHash(HashAlgorithmName.SHA256);digest.AppendData(header);digest.AppendData(bytes);
        stream.Write(header);stream.Write(bytes);stream.Write(digest.GetHashAndReset());stream.Flush(true);
    }
    private static byte[] ReadFrame(FileStream stream,uint kind)
    {
        var header=new byte[16];stream.ReadExactly(header);var length=BinaryPrimitives.ReadInt32LittleEndian(header.AsSpan(12));
        if(!header.AsSpan(0,8).SequenceEqual("SQACQ001"u8)||BinaryPrimitives.ReadUInt32LittleEndian(header.AsSpan(8))!=kind||length is <0 or >32768)throw new InvalidDataException("Invalid process acquisition frame");
        var payload=new byte[length];var expected=new byte[32];stream.ReadExactly(payload);stream.ReadExactly(expected);
        using var digest=IncrementalHash.CreateHash(HashAlgorithmName.SHA256);digest.AppendData(header);digest.AppendData(payload);
        if(!CryptographicOperations.FixedTimeEquals(expected,digest.GetHashAndReset()))throw new InvalidDataException("Process acquisition frame checksum differs");return payload;
    }
    private ProcessRecord ReadCommittedProcess(string path)
    {
        using var wal=Open(path+".wal",FileMode.Open,FileAccess.Read);
        if(wal.Length>65664)throw new InvalidDataException("Oversized process acquisition journal");
        var prepared=ReadFrame(wal,1);var committed=ReadFrame(wal,2);
        if(committed.Length!=32||!CryptographicOperations.FixedTimeEquals(committed,SHA256.HashData(prepared))||wal.Position!=wal.Length)throw new InvalidDataException("Incomplete or contradictory process acquisition commit");
        var record=JsonSerializer.Deserialize<ProcessRecord>(prepared)??throw new InvalidDataException("Missing process acquisition record");
        ValidateProcessRecord(record);return record;
    }
    private ProcessRecord ReadProcess(string path)
    {
        using var file=Open(path,FileMode.Open,FileAccess.Read);if(file.Length>32768)throw new InvalidDataException("Oversized process acquisition index");
        var record=JsonSerializer.Deserialize<ProcessRecord>(file)??throw new InvalidDataException("Empty process acquisition index");
        ValidateProcessRecord(record);
        if(record.State=="captured"&&JsonSerializer.Serialize(ReadCommittedProcess(path))!=JsonSerializer.Serialize(record))throw new InvalidDataException("Process acquisition index differs from committed journal");
        return record;
    }
    private void ValidateProcessRecord(ProcessRecord record)
    {
        if(record.Version!=1||record.Sensor!=sensor||record.Ready==null||record.RecordedUtc==default||record.State is not ("captured" or "unavailable" or "failed")||record.Reason is not {Length:>0 and <=256})throw new InvalidDataException("Invalid process acquisition record");
        ValidateReady(record.Ready);
        if(record.State!="captured"&&(record.SnapshotId!=null||record.Sha256!=null||record.SnapshotFile!=null||record.Metadata!=null||record.SourceIdentityReply!=null||record.SourceIdentityFailure!=null||record.Creation!=null))throw new InvalidDataException("Failed process acquisition claims snapshot bytes");
        if(record.SourceIdentityFailure is {} failure&&(record.SourceIdentityReply!=null||failure.State!="unavailable"||failure.Reason!="source-volume-query-unavailable"||failure.NativeCode is not {Length:10}||!failure.NativeCode.StartsWith("0x",StringComparison.Ordinal)||!failure.NativeCode[2..].All(Uri.IsHexDigit)))throw new InvalidDataException("Invalid source identity query failure");
    }
    private void VerifyProcessBytes(ProcessRecord record)
    {
        if(record.Version!=1||record.Sensor!=sensor||record.State!="captured"||record.SnapshotId==null||record.Sha256?.Length!=64||record.SnapshotFile==null||record.Metadata==null)throw new InvalidDataException("Incomplete process acquisition proof");
        var raw=ProcessMetadata(record.Metadata);var parsed=WindowsStagedActorProtocol.Metadata(raw,TransferFields(record.Ready));
        WindowsStagedActorProtocol.SourceIdentity(parsed.Acquisition,parsed.Source,record.SourceIdentityReply==null?null:ProcessMetadata(record.SourceIdentityReply),record.SourceIdentityFailure,false);
        if(record.Ready.ByteLength!=WindowsStagedActorProtocol.U32(raw,8)||record.SnapshotFile.Size!=record.Ready.ByteLength||parsed.Acquisition.SourceFileIndex!=record.Ready.FileIndex.ToString("X16")||parsed.Acquisition.OriginalRequestedAccess!=record.Ready.OriginalAccess||parsed.Acquisition.MappedRequestedAccess!=record.Ready.MappedAccess||parsed.Acquisition.AccessQualificationVersion!=record.Ready.QualificationVersion||parsed.Acquisition.CreateStatus!="0x"+record.Ready.CreateStatus.ToString("X8"))throw new InvalidDataException("Ready feed and copied source evidence differ");
        using var file=Open(ArtifactPath(record.SnapshotId),FileMode.Open,FileAccess.Read);var identity=NativeFileIdentity.Read(file);
        if(!NativeFileIdentity.Same(identity,record.SnapshotFile)||file.Length!=record.Ready.ByteLength||Convert.ToHexString(SHA256.HashData(file))!=record.Sha256||!NativeFileIdentity.Same(identity,NativeFileIdentity.Read(file)))throw new InvalidDataException("Committed process snapshot failed recovery verification");
    }
    private static byte[] ProcessMetadata(string metadata)
    {try{return Convert.FromBase64String(metadata);}catch(FormatException ex){throw new InvalidDataException("Invalid process acquisition metadata encoding",ex);}}
    private static void ValidateReady(WindowsReadyActor key)
    {
        if(key.Provider is not {Length:32}||!key.Provider.All(Uri.IsHexDigit)||key.ProviderStatus is not (0 or 0x40020056)||key.OperationInstance==0||key.ReadySequence==0||key.Generation==0||key.Candidate==0||key.Pid<=0||key.Created is <=0 or >2650467743999999999||key.Deadline==0||key.ByteLength is 0 or >8388608||key.State is 0 or >5||key.QualificationVersion!=2||unchecked((int)key.CreateStatus)<0)throw new InvalidDataException("Invalid proactive acquisition key");
    }
    private Record? LinkProcessAcquisition(AgentEvent e,ActorAcquisitionEvidence a)
    {
        var path=ProcessPath(a.Provider,a.EventInstance,a.ProcessGeneration!,a.CandidateId!,a.ProcessId!.Value,a.ProcessCreatedFileTime!.Value);
        if(!File.Exists(path))return null;var process=ReadProcess(path);
        var key=process.Ready;
        if(ProcessPath(key)!=path||a.ProviderStatus!="0x"+key.ProviderStatus.ToString("X8"))throw new InvalidDataException("Proactive acquisition full key differs");
        if(process.State!="captured")return null;
        VerifyProcessBytes(process);var (acquisition,source)=WindowsStagedActorProtocol.Metadata(ProcessMetadata(process.Metadata!),a);
        (acquisition,source)=WindowsStagedActorProtocol.SourceIdentity(acquisition,source,process.SourceIdentityReply==null?null:ProcessMetadata(process.SourceIdentityReply),process.SourceIdentityFailure,false);
        acquisition=acquisition with{SnapshotId=process.SnapshotId,SnapshotSha256=process.Sha256,SnapshotFile=process.SnapshotFile,PersistedUtc=process.RecordedUtc,Status=EvidenceStatus.Captured("proactive-snapshot-prepare-commit-and-hash-verified")};
        var record=new Record(1,sensor,acquisition,source,process.Creation);using(var verified=Lease(record,e)){}return record;
    }
    internal string CaptureReady(WindowsReadyActor key,Func<byte[],int,byte[]> send,Action<string> health)
    {
        var state=CaptureReadyCore(key,send,health);
        if(state=="captured")
        {
            // Retry I/O never holds the acquisition mutex. The committed index
            // remains recoverable if this process exits before intent creation.
            var record=ReadProcess(ProcessPath(key));VerifyProcessBytes(record);
            IndexSyscallProcess(record);
            var intent=QueueProcessAcknowledgement(record,health);
            AttemptProcessAcknowledgement(intent,key.Provider,key.OperationInstance,send,health,DateTimeOffset.UtcNow);
        }
        return state;
    }
    private string CaptureReadyCore(WindowsReadyActor key,Func<byte[],int,byte[]> send,Action<string> health)
    {
        ValidateReady(key);
        lock(gate)
        {
            var path=ProcessPath(key);ProcessRecord record;
            if(File.Exists(path))
            {
                record=ReadProcess(path);if(record.Ready with{State=key.State}!=key)throw new InvalidDataException("Proactive acquisition identity collision");
                if(record.State=="captured")VerifyProcessBytes(record);return record.State;
            }
            try
            {
                if(File.Exists(path+".wal"))
                {
                    record=ReadCommittedProcess(path);if(record.Ready with{State=key.State}!=key)throw new InvalidDataException("Recovered acquisition identity collision");VerifyProcessBytes(record);
                }
                else if(key.State!=1)
                    record=new(1,sensor,key,"unavailable","ready-candidate-state-"+key.State,null,null,null,null,DateTimeOffset.UtcNow);
                else
                {
                    var metadata=send(key.Request(13),WindowsStagedActorProtocol.HeaderBytes);var fields=TransferFields(key);
                    var parsed=WindowsStagedActorProtocol.Metadata(metadata,fields);var length=WindowsStagedActorProtocol.U32(metadata,8);if(length!=key.ByteLength)throw new InvalidDataException("Ready candidate size changed");
                    var sourceIdentity=WindowsStagedActorProtocol.QuerySourceIdentity(key.Request(26),send);
                    WindowsStagedActorProtocol.SourceIdentity(parsed.Acquisition,parsed.Source,sourceIdentity.Reply,sourceIdentity.Failure,false);
                    var creation=WindowsProcessCreationProtocol.Query(key.Request(27),fields,send);
                    CheckQuota(length+65536);var id=Guid.NewGuid().ToString("N");var artifact=ArtifactPath(id);string hash;FileIdentityEvidence identity;
                    using(var file=Open(artifact,FileMode.CreateNew,FileAccess.ReadWrite))
                    {
                        using var digest=IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
                        for(uint offset=0;offset<length;)
                        {
                            var count=Math.Min(65536u,length-offset);var bytes=send(key.Request(10,offset,count),checked((int)(144+count)));
                            WindowsStagedActorProtocol.CheckReply(bytes,fields,length,offset,count,metadata);file.Write(bytes,144,(int)count);digest.AppendData(bytes,144,(int)count);offset+=count;
                        }
                        file.Flush(true);hash=Convert.ToHexString(digest.GetHashAndReset());
                    }
                    using(var file=Open(artifact,FileMode.Open,FileAccess.Read)){identity=NativeFileIdentity.Read(file);if(Convert.ToHexString(SHA256.HashData(file))!=hash||!NativeFileIdentity.Same(identity,NativeFileIdentity.Read(file)))throw new IOException("Proactive snapshot verification failed");}
                    record=new(1,sensor,key,"captured","exact-process-generation-ready-feed",id,hash,identity,Convert.ToBase64String(metadata),DateTimeOffset.UtcNow,sourceIdentity.Reply==null?null:Convert.ToBase64String(sourceIdentity.Reply),sourceIdentity.Failure,creation);
                    VerifyProcessBytes(record);var prepared=JsonSerializer.SerializeToUtf8Bytes(record);
                    CheckQuota(prepared.Length+128);
                    using(var wal=Open(path+".wal",FileMode.CreateNew,FileAccess.ReadWrite)){WriteFrame(wal,1,prepared);WriteFrame(wal,2,SHA256.HashData(prepared));}
                    if(JsonSerializer.Serialize(ReadCommittedProcess(path))!=JsonSerializer.Serialize(record))throw new InvalidDataException("Process commit readback differs");
                }
                SaveImmutable(path,JsonSerializer.SerializeToUtf8Bytes(record));
            }
            catch(Exception ex)when(ex is IOException or InvalidDataException or UnauthorizedAccessException or COMException or System.ComponentModel.Win32Exception or ArgumentException or OverflowException or JsonException)
            {
                // Partial artifacts and WAL remain private and count against quota.
                // No candidate ACK or successful snapshot claim on any failure.
                record=new(1,sensor,key,"failed","proactive-acquisition-"+ex.GetType().Name,null,null,null,null,DateTimeOffset.UtcNow);
                SaveImmutable(path,JsonSerializer.SerializeToUtf8Bytes(record));health("Proactive actor acquisition failed; no bytes acknowledged: "+record.Reason);return record.State;
            }
            return record.State;
        }
    }
    private sealed record ReadyCursor(int Version,string Provider,ulong Instance,ulong Sequence);
    private int consecutiveReadyDeferrals;
    internal void DrainReady(string provider,ulong instance,Func<byte[],int,byte[]> send,Action<string> health)
    {
        // Raw operations have priority, with one discovery opportunity after
        // nine consecutive deferrals. This is bounded invocation fairness, not
        // a hard time bound on synchronous native or filesystem calls.
        var operations=send(WindowsStagedActorProtocol.Message(3),48);
        if(WindowsStagedActorProtocol.U32(operations,0)!=4||WindowsStagedActorProtocol.U64(operations,8)!=instance)throw new InvalidDataException("Proactive provider operation epoch changed");
        if(WindowsStagedActorProtocol.U32(operations,40)!=0&&++consecutiveReadyDeferrals<10)return;
        consecutiveReadyDeferrals=0;
        var cursorPath=Path.Combine(root,provider+"."+instance.ToString("X16")+".ready-cursor.json");
        ReadyCursor cursor;
        using(var file=File.Exists(cursorPath)?Open(cursorPath,FileMode.Open,FileAccess.Read):null)
        {
            if(file!=null&&file.Length>1024)throw new InvalidDataException("Oversized proactive cursor");
            cursor=file==null?new(1,provider,instance,0):JsonSerializer.Deserialize<ReadyCursor>(file)??throw new InvalidDataException("Empty proactive cursor");
        }
        if(cursor.Version!=1||cursor.Provider!=provider||cursor.Instance!=instance)throw new InvalidDataException("Proactive cursor epoch differs");
        var page=WindowsReadyActorProtocol.Decode(send(WindowsReadyActorProtocol.Request(provider,cursor.Sequence),WindowsReadyActorProtocol.PageBytes),provider,instance,cursor.Sequence);
        if(page.CursorResetRequired)
        {
            var gap=JsonSerializer.SerializeToUtf8Bytes(new{Version=1,Provider=provider,Instance=instance,After=cursor.Sequence,page.OldestRetained,page.HighestPublished,Reason="READY_PUBLICATION_HISTORY_LOST"});
            lock(gate)SaveImmutable(Path.Combine(root,provider+"."+instance.ToString("X16")+"."+cursor.Sequence.ToString("X16")+"."+page.HighestPublished.ToString("X16")+".ready-gap.json"),gap);
            health("Proactive actor ready-feed gap: after="+cursor.Sequence+", oldest="+page.OldestRetained);
        }
        // Native byte retention is bounded. Preserve retrievable bytes before
        // spending durable I/O on older, already unavailable discoveries. This
        // changes acquisition scheduling only: every row is still materialized
        // and the sequential cursor advances only after the entire page commits.
        foreach(var ready in page.Actors.OrderByDescending(r=>r.State==1)
            .ThenByDescending(r=>r.State==1?r.ReadySequence:0))CaptureReady(ready,send,health);
        if(page.SequenceExhausted)health("Proactive actor ready sequence exhausted; no new acquisitions can be assumed");
        if(page.NextSequence==cursor.Sequence)return;
        var bytes=JsonSerializer.SerializeToUtf8Bytes(cursor with{Sequence=page.NextSequence});
        // Mutable operational cursor. Acquisition and gap evidence stay immutable.
        lock(gate)
        {
            CheckQuota(bytes.Length);var temporary=cursorPath+"."+Guid.NewGuid().ToString("N")+".tmp";
            using(var file=Open(temporary,FileMode.CreateNew,FileAccess.Write)){file.Write(bytes);file.Flush(true);}
            if(OperatingSystem.IsWindows()){if(!MoveFileEx(ExtendedWindowsPath(temporary),ExtendedWindowsPath(cursorPath),9))throw new IOException("Ready cursor commit failed: "+Marshal.GetLastPInvokeError());}
            else File.Move(temporary,cursorPath,true);
            if(!File.ReadAllBytes(cursorPath).AsSpan().SequenceEqual(bytes))throw new IOException("Ready cursor readback differs");
        }
    }
}
