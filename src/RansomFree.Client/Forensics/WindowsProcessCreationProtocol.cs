using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using RansomFree.Contracts;
namespace RansomFree.Client.Forensics;

internal sealed record WindowsCreationRecord(string? Raw,string? Sha256,EvidenceStatus? Failure);
internal static class WindowsProcessCreationProtocol
{
    internal const int ReplyBytes=5304;
    private static readonly UnicodeEncoding Utf16=new(false,false,true);
    private static uint U32(byte[] b,int offset)=>WindowsStagedActorProtocol.U32(b,offset);
    private static ulong U64(byte[] b,int offset)=>WindowsStagedActorProtocol.U64(b,offset);
    private static bool Failure(Exception ex)=>ex is COMException or IOException or InvalidDataException or ArgumentException or FormatException or OverflowException;
    internal static WindowsCreationRecord Query(byte[] request,ActorAcquisitionEvidence key,Func<byte[],int,byte[]> send)
    {
        try
        {
            var raw=send(request,ReplyBytes);
            var pinned=WindowsStagedActorProtocol.U32(request,4)==22;
            if(raw.Length!=ReplyBytes||U64(raw,64)!=(pinned?Convert.ToUInt64(key.EventInstance,16):0)||U64(raw,72)!=(pinned?(ulong)key.EventSequence:0))throw new InvalidDataException("Process creation reply does not match querying operation");
            var record=new WindowsCreationRecord(Convert.ToBase64String(raw),Convert.ToHexString(SHA256.HashData(raw)),null);
            Decode(record,key,new(),"");return record;
        }
        catch(Exception ex)when(Failure(ex)){return new(null,null,new("unavailable","process-creation-companion-query-failed","0x"+ex.HResult.ToString("X8")));}
    }
    internal static ProcessInstanceEvidence Apply(WindowsCreationRecord? record,ActorAcquisitionEvidence key,ProcessInstanceEvidence process,string sensor)
    {
        // Callers supply ActorLease.Unavailable + ApplyKernel: PID/start, image
        // path and operation-time tokens only. This companion owns parent and
        // command fields; it never overwrites an independently enriched lease.
        if(record==null)return process; // Legacy manifests retain their original schema.
        try{return Decode(record,key,process,sensor);}
        catch(Exception ex)when(Failure(ex))
        {
            return process with{Creation=new(){Status=new("failed","process-creation-durable-proof-invalid","0x"+ex.HResult.ToString("X8"))},CommandLine=null,CommandLineStatus=EvidenceStatus.Unavailable("process-creation-durable-proof-invalid"),
                ParentPid=null,ParentStartKey=null,ParentStartedUtc=null,ParentInstanceId=null,ParentExecutablePath=null,ParentStatus=EvidenceStatus.Unavailable("process-creation-durable-proof-invalid")};
        }
    }
    private static ProcessInstanceEvidence Decode(WindowsCreationRecord record,ActorAcquisitionEvidence key,ProcessInstanceEvidence process,string sensor)
    {
        if(record.Raw==null)
        {
            if(record.Sha256!=null||record.Failure is not {State:"unavailable",Reason:"process-creation-companion-query-failed"})throw new InvalidDataException("Invalid process creation failure");
            return process with{Creation=new(){Status=record.Failure},CommandLineStatus=record.Failure,ParentStatus=record.Failure};
        }
        if(record.Raw.Length>7072||record.Failure!=null)throw new InvalidDataException("Invalid process creation proof envelope");
        var b=Convert.FromBase64String(record.Raw);
        if(b.Length!=ReplyBytes||record.Sha256!=Convert.ToHexString(SHA256.HashData(b))||U32(b,0)!=1||U32(b,4)!=ReplyBytes||U32(b,12)!=0||
            Convert.ToHexString(b.AsSpan(16,16))!=key.Provider||U64(b,32)!=Convert.ToUInt64(key.ProcessGeneration,16)||U64(b,40)!=Convert.ToUInt64(key.CandidateId,16)||
            U64(b,48)!=(ulong)key.ProcessId!||U64(b,56)!=(ulong)key.ProcessCreatedFileTime!||U32(b,80)!=1||U32(b,84)!=5224||
            (U64(b,64)==0?U64(b,72)!=0:U64(b,64)!=Convert.ToUInt64(key.EventInstance,16)||U64(b,72)==0))throw new InvalidDataException("Process creation proof differs from full process key");
        if(U32(b,8)!=0)
        {
            if(U32(b,8)!=0xC000009A||U32(b,88)!=U32(b,8)||U32(b,92) is not (2 or 3)||b.AsSpan(96).ContainsAnyExcept((byte)0))throw new InvalidDataException("Failed creation capture claims metadata");
            var missing=new EvidenceStatus("unavailable",U32(b,92)==2?"process-creation-metadata-capacity-refused":"process-creation-metadata-allocation-failed","0xC000009A");
            return process with{Creation=new(){Status=missing},ParentStatus=missing,CommandLineStatus=missing};
        }
        var flags=U32(b,92);var parent=U64(b,96);var creator=U64(b,104);var tid=U64(b,112);var creatorTime=U64(b,120);var parentTime=U64(b,128);
        if(U32(b,88)!=0||flags>7||U64(b,136) is 0 or >2650467743999999999||creatorTime>2650467743999999999||parentTime>2650467743999999999||
            ((flags&2)==0&&(creatorTime!=0||U32(b,152)!=0))||((flags&2)!=0&&(unchecked((int)U32(b,152))>=0?creatorTime==0:creatorTime!=0))||
            ((flags&4)!=0?(flags&2)==0||parent!=creator||parentTime==0||parentTime!=creatorTime:parentTime!=0))throw new InvalidDataException("Contradictory creator/parent context");
        (string? Text,EvidenceStatus Status) Text(int stateOffset,int originalOffset,int storedOffset,int dataOffset,int capacity,string name)
        {
            var state=U32(b,stateOffset);var original=U32(b,originalOffset);var stored=U32(b,storedOffset);
            if(state>3||original>65535||stored>capacity||stored%2!=0||stored>original||b.AsSpan(dataOffset+(int)stored,capacity-(int)stored).ContainsAnyExcept((byte)0)||
                (state==0&&(original!=0||stored!=0))||(state==1&&(original!=stored||original%2!=0))||(state==2&&(original<=stored||original%2!=0||stored<capacity-2))||(state==3&&stored!=0))throw new InvalidDataException("Invalid creation string bounds/status");
            if(state is 0 or 3)return(null,EvidenceStatus.Unavailable("creation-"+name+(state==0?"-absent":"-invalid-source")));
            try{return(Utf16.GetString(b,dataOffset,(int)stored),new(state==1?"captured":"partial","creation-"+name+(state==1?"-notification":"-truncated")));}
            catch(DecoderFallbackException){return(null,EvidenceStatus.Unavailable("creation-"+name+"-invalid-utf16; raw-retained"));}
        }
        var command=Text(160,164,168,184,4096,"command-line");var image=Text(172,176,180,4280,1024,"image-name");
        var parentPid=parent is >0 and <=int.MaxValue?(int?)parent:null;
        var start=parentTime>0&&parentPid!=null?(long?)parentTime:null;
        var parentStatus=start!=null?EvidenceStatus.Captured("creation-reported-parent-equals-referenced-creator; parent-image-unavailable"):EvidenceStatus.Unavailable(parent!=creator?"creation-designated-parent-instance-unavailable":"creation-creator-instance-unavailable");
        return process with{CommandLine=command.Text,CommandLineStatus=command.Status,ParentPid=parentPid,ParentStartKey=start?.ToString(System.Globalization.CultureInfo.InvariantCulture),
            ParentStartedUtc=start is {} stamp?DateTimeOffset.FromFileTime(stamp):null,ParentInstanceId=start!=null&&sensor.Length>0?ActorLease.Correlate(sensor,parentPid!.Value,start.Value.ToString(System.Globalization.CultureInfo.InvariantCulture)):null,ParentExecutablePath=null,ParentStatus=parentStatus,
            Creation=new(){RawSha256=record.Sha256,CapturedUtc=DateTimeOffset.FromFileTime((long)U64(b,136)),Monotonic=U64(b,144),CreatorPid=creator,CreatorTid=tid,CreatorCreatedFileTime=creatorTime==0?null:(long)creatorTime,
                CreatorStatus=creatorTime!=0?new("captured","creation-callback-owning-thread-referenced-process","0x"+U32(b,152).ToString("X8")):new("unavailable",(flags&2)==0?"creation-creator-context-mismatch; lookup-not-attempted":"creation-creator-lookup-failed",(flags&2)==0?null:"0x"+U32(b,152).ToString("X8")),
                ReportedParentPid=parent,ParentCreatedFileTime=start,ImageName=image.Text,FileOpenNameAvailable=(flags&1)!=0,ImageOriginalBytes=U32(b,176),ImageStoredBytes=U32(b,180),
                ImageStatus=(flags&1)==0&&image.Text!=null?new("partial","creation-image-notification-name-nonexact"):image.Status,CommandOriginalBytes=U32(b,164),CommandStoredBytes=U32(b,168),
                NotificationCreationStatus="0x"+U32(b,156).ToString("X8"),Status=EvidenceStatus.Captured("creation-notification; not-final-create-verdict")}};
    }
}
