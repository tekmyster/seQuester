using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Text;
using RansomFree.Contracts;
namespace RansomFree.Client.Forensics;

// Separate companion protocol; the deployed 3,800-byte v4 operation layout is unchanged.
internal static class WindowsStagedActorProtocol
{
    internal const int HeaderBytes=144,MaximumBytes=8*1024*1024;
    internal static uint U32(byte[] b,int o)=>BinaryPrimitives.ReadUInt32LittleEndian(b.AsSpan(o));
    internal static ulong U64(byte[] b,int o)=>BinaryPrimitives.ReadUInt64LittleEndian(b.AsSpan(o));
    internal static void Put(byte[] b,int o,ulong n)=>BinaryPrimitives.WriteUInt64LittleEndian(b.AsSpan(o),n);
    internal static void Put32(byte[] b,int o,uint n)=>BinaryPrimitives.WriteUInt32LittleEndian(b.AsSpan(o),n);
    internal static byte[] Message(uint command,int size=8){var b=new byte[size];Put32(b,0,4);Put32(b,4,command);return b;}
    internal static byte[] CompanionRequest(AgentEvent e,string provider)
    {
        var k=e.Attribution?.WindowsKernel??throw new InvalidDataException("Operation-time identity required");
        var b=Message(18,40);Put(b,8,Convert.ToUInt64(k.Instance,16));Put(b,16,checked((ulong)k.Sequence));Convert.FromHexString(provider).CopyTo(b,24);return b;
    }
    internal static ActorAcquisitionEvidence Companion(byte[] b,AgentEvent e,string provider)
    {
        var k=e.Attribution?.WindowsKernel??throw new InvalidDataException("Operation-time identity required");
        if(b.Length!=88||U32(b,0) is not (1 or 2)||U32(b,4)!=88||Convert.ToHexString(b.AsSpan(16,16))!=provider||U64(b,72)!=Convert.ToUInt64(k.Instance,16)||U64(b,80)!=(ulong)k.Sequence)throw new InvalidDataException("Companion does not match operation");
        var flags=U32(b,8);var status=U32(b,12);var providerStatus=U32(b,64);
        if(providerStatus is not (0 or 0x40020056))throw new InvalidDataException("Provider UUID was not established");
        if(flags>2||flags==2&&(U32(b,0)!=2||status!=0xC0000225)||flags==1&&status!=0||flags!=0&&(U64(b,32)==0||U64(b,40)==0||U64(b,48)!=(ulong?)k.ProcessId||U64(b,56)!=(ulong?)k.ProcessCreatedFileTime)||
            flags==0&&(status==0||U64(b,32)!=0||U64(b,40)!=0||U64(b,48)!=0||U64(b,56)!=0))throw new InvalidDataException("Invalid operation binding");
        return new(){SourceEventId=e.EventId,Provider=provider,ProviderStatus="0x"+providerStatus.ToString("X8"),ProviderScope=providerStatus==0?"os-uuid":"local-only",EventInstance=k.Instance,EventSequence=k.Sequence,
            BindingKind=flags switch{1=>"bytes-pinned",2=>"process-generation-only",_=>"unavailable"},ProcessGeneration=flags!=0?U64(b,32).ToString("X16"):null,CandidateId=flags!=0?U64(b,40).ToString("X16"):null,ProcessId=flags!=0?k.ProcessId:null,ProcessCreatedFileTime=flags!=0?k.ProcessCreatedFileTime:null,
            Status=flags!=0?EvidenceStatus.Unavailable("operation-bound-bytes-not-persisted"):new("unavailable","operation-binding-unavailable-reason-"+U32(b,68),"0x"+status.ToString("X8"))};
    }
    internal static byte[] CandidateRequest(ActorAcquisitionEvidence a,uint operation,uint offset=0,uint count=0)
    {
        if(a.ProcessGeneration==null||a.CandidateId==null||a.ProcessId is not >0||a.ProcessCreatedFileTime is not >0)throw new InvalidDataException("Exact candidate key required");
        var b=Message(19,72);Convert.FromHexString(a.Provider).CopyTo(b,8);Put(b,24,Convert.ToUInt64(a.ProcessGeneration,16));Put(b,32,Convert.ToUInt64(a.CandidateId,16));Put(b,40,(ulong)a.ProcessId.Value);Put(b,48,(ulong)a.ProcessCreatedFileTime.Value);
        Put32(b,56,offset);Put32(b,60,count);Put32(b,64,operation);Put32(b,68,1);return b;
    }
    internal static byte[] OperationRequest(ActorAcquisitionEvidence a,uint operation,uint offset=0,uint count=0)
    {
        if(a.BindingKind!="bytes-pinned"||a.EventSequence<=0||operation is not (10 or 13 or 26 or 27))throw new InvalidDataException("Pinned operation required");
        var b=new byte[88];CandidateRequest(a,operation,offset,count).CopyTo(b,0);Put32(b,4,22);Put32(b,68,3);
        Put(b,72,Convert.ToUInt64(a.EventInstance,16));Put(b,80,checked((ulong)a.EventSequence));return b;
    }
    internal static byte[] DurableAcknowledgement(ActorAcquisitionEvidence a)
    {
        if(a.Status.State!="captured"||a.RecoveryStatus!=null||a.SnapshotFile?.Size is not >0||a.SnapshotSha256?.Length!=64||!Guid.TryParseExact(a.SnapshotId,"N",out var receipt))throw new InvalidDataException("Verified durable snapshot required for ACK");
        var b=new byte[160];CandidateRequest(a,11).CopyTo(b,0);Put32(b,4,21);Put32(b,68,2);
        Put32(b,72,checked((uint)a.SnapshotFile.Size.Value));Put32(b,76,1);Convert.FromHexString(a.SnapshotSha256).CopyTo(b,80);
        receipt.ToByteArray().CopyTo(b,112);SHA256.HashData(Encoding.UTF8.GetBytes(NativeFileIdentity.CacheKey(a.SnapshotFile))).CopyTo(b,128);return b;
    }
    internal static void CheckReply(byte[] b,ActorAcquisitionEvidence a,uint length,uint offset,uint count,byte[]? metadata=null)
    {
        if(b.Length!=HeaderBytes+count||U32(b,0)!=3||U32(b,4)!=HeaderBytes||U32(b,8)!=length||length is 0 or >MaximumBytes||U32(b,12)!=offset||U32(b,16)!=count||
            (U32(b,20)&13)!=13||(U32(b,20)&~15u)!=0||U32(b,24)!=0||U64(b,32)!=Convert.ToUInt64(a.CandidateId,16)||U64(b,40)!=(ulong)a.ProcessId!||U64(b,48)!=(ulong)a.ProcessCreatedFileTime!||
            Convert.ToHexString(b.AsSpan(120,16))!=a.Provider||U64(b,136)!=Convert.ToUInt64(a.ProcessGeneration,16)||U32(b,108)!=2||unchecked((int)U32(b,112))<0)throw new InvalidDataException("Candidate byte reply does not match full identity");
        // Exit flag may change during reads. Source identity, copy interval and access evidence must not.
        if(metadata!=null&&(!b.AsSpan(28,116).SequenceEqual(metadata.AsSpan(28,116))||U32(b,8)!=U32(metadata,8)))throw new InvalidDataException("Candidate metadata changed between chunks");
    }
    internal static (ActorAcquisitionEvidence Acquisition,FileIdentityEvidence Source) Metadata(byte[] b,ActorAcquisitionEvidence a)
    {
        if(b.Length!=HeaderBytes)throw new InvalidDataException("Invalid candidate metadata length");
        CheckReply(b,a,U32(b,8),0,0);
        DateTimeOffset? Time(int o)=>U64(b,o)==0?null:DateTimeOffset.FromFileTime(checked((long)U64(b,o)));
        var source=new FileIdentityEvidence{Size=U32(b,8),CreatedUtc=Time(64),ModifiedUtc=Time(72),ChangedUtc=Time(80),Status=new("partial","source-metadata-captured; volume-identity-unavailable")};
        return(a with{SourceFileIndex=U64(b,56).ToString("X16"),OriginalRequestedAccess=U32(b,104),MappedRequestedAccess=U32(b,28),AccessQualificationVersion=U32(b,108),CreateStatus="0x"+U32(b,112).ToString("X8"),CopyStartedUtc=Time(88),CopyEndedUtc=Time(96)},source);
    }
    internal static (byte[]? Reply,EvidenceStatus? Failure) QuerySourceIdentity(byte[] request,Func<byte[],int,byte[]> send)
    {
        try{return(send(request,224),null);}
        catch(Exception ex)when(ex is System.Runtime.InteropServices.COMException or ArgumentException)
        {return(null,new("unavailable","source-volume-query-unavailable","0x"+ex.HResult.ToString("X8")));}
    }
    internal static (ActorAcquisitionEvidence Acquisition,FileIdentityEvidence Source) SourceIdentity(ActorAcquisitionEvidence a,FileIdentityEvidence source,byte[]? b,EvidenceStatus? failure,bool pinned)
    {
        if(b==null)return(a with{SourceIdentityStatus=failure??a.SourceIdentityStatus},source);
        if(failure!=null||b.Length!=224||U32(b,0)!=1||U32(b,4)!=224||U32(b,12)>1||U32(b,204)!=0||
            Convert.ToHexString(b.AsSpan(16,16))!=a.Provider||U64(b,32)!=Convert.ToUInt64(a.ProcessGeneration,16)||U64(b,40)!=Convert.ToUInt64(a.CandidateId,16)||
            U64(b,48)!=(ulong)a.ProcessId!||U64(b,56)!=(ulong)a.ProcessCreatedFileTime!||U64(b,64).ToString("X16")!=a.SourceFileIndex||
            U64(b,208)!=(pinned?Convert.ToUInt64(a.EventInstance,16):0)||U64(b,216)!=(pinned?checked((ulong)a.EventSequence):0))throw new InvalidDataException("Source volume reply differs from exact acquisition key");
        var status=U32(b,8);var length=U32(b,200);
        if(U32(b,12)==0)
        {
            if(unchecked((int)status)>=0||length!=0||b.AsSpan(72,128).ContainsAnyExcept((byte)0))throw new InvalidDataException("Failed source volume query claims identity");
            return(a with{SourceIdentityStatus=new("unavailable","source-volume-query-failed","0x"+status.ToString("X8"))},source);
        }
        if(status!=0||length is 0 or >126||length%2!=0||b.AsSpan(72+(int)length,128-(int)length).ContainsAnyExcept((byte)0))throw new InvalidDataException("Invalid source volume identity encoding");
        var volume=Encoding.Unicode.GetString(b,72,(int)length);
        if(!volume.StartsWith(@"\??\Volume",StringComparison.Ordinal)||volume.Length!=48||!Guid.TryParseExact(volume.AsSpan(10),"B",out var guid))throw new InvalidDataException("Source volume is not a mount-manager GUID");
        if(a.SourceFileIndex=="0000000000000000")return(a with{SourceIdentityStatus=new("unavailable","source-file-index-zero","0x00000000")},source);
        var captured=new EvidenceStatus("captured","ntfs-volume-guid-and-file-index-at-source-copy","0x00000000");
        return(a with{SourceIdentityStatus=captured},source with{StableId="windows-volume-guid:"+guid.ToString("N").ToUpperInvariant()+":file-index:"+a.SourceFileIndex,Status=captured});
    }
}
