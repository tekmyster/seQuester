using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using RansomFree.Contracts;

namespace RansomFree.Client;

// Native loader schemas 5/6; service activation and retained-lease acquisition are
// separate consumers. Decode never reopens a PID/path or upgrades provenance.
public static class LinuxKernelDecoder
{
    public static AgentEvent Decode(ReadOnlyMemory<byte> bytes,string sensor,string collector,long sequence,DateTimeOffset receivedUtc)
    {
        // Two 4095-byte paths can each expand sixfold in JSON in addition to
        // their base64 representation. The normalized event stores bytes once.
        if(bytes.Length is <2 or >65536||!Guid.TryParseExact(sensor,"N",out _)||!Guid.TryParseExact(collector,"N",out _)||sequence<=0||receivedUtc==default)throw new InvalidDataException("Invalid Linux observation context");
        using var json=JsonDocument.Parse(bytes);var r=json.RootElement;
        if(r.ValueKind!=JsonValueKind.Object||r.EnumerateObject().Select(x=>x.Name).Distinct(StringComparer.Ordinal).Count()!=r.EnumerateObject().Count())throw new InvalidDataException("Duplicate or invalid Linux observation fields");
        string S(string name)=>r.GetProperty(name).GetString()??throw new InvalidDataException("Null native string: "+name);
        string U(string name)=>r.GetProperty(name).GetUInt64().ToString(CultureInfo.InvariantCulture);
        uint? Nullable(string name)=>r.GetProperty(name).ValueKind==JsonValueKind.Null?null:r.GetProperty(name).GetUInt32();
        int I(string name)=>r.GetProperty(name).GetInt32();long L(string name)=>r.GetProperty(name).GetInt64();
        var schema=I("schemaVersion");
        if(schema is 7 or 8)return DecodeAtomic(bytes,sensor,collector,sequence,receivedUtc);
        if(schema is not (5 or 6))throw new InvalidDataException("Unsupported Linux native schema");
        LinuxKernelTargetIdentity? targetIdentity=null;
        if(schema==6)
        {
            var inode=U("targetInode");var device=r.GetProperty("targetDevice").GetUInt32();var ordinal=r.GetProperty("targetOrdinal").GetUInt32();
            if(inode!=r.GetProperty("targetInode").GetRawText()||device.ToString(CultureInfo.InvariantCulture)!=r.GetProperty("targetDevice").GetRawText()||ordinal.ToString(CultureInfo.InvariantCulture)!=r.GetProperty("targetOrdinal").GetRawText())throw new InvalidDataException("Noncanonical target identity");
            targetIdentity=new(){Inode=inode,Device=device,Ordinal=ordinal};
        }
        else if(new[]{"targetInode","targetDevice","targetOrdinal"}.Any(name=>r.TryGetProperty(name,out _)))throw new InvalidDataException("Legacy observation cannot assert schema-6 target identity");
        LinuxKernelPathEvidence Path(string name)
        {
            var path=new LinuxKernelPathEvidence{NativeResult=I(name+"PathResult"),State=S(name+"PathStatus"),BytesBase64=r.GetProperty(name+"PathBytesBase64").GetString(),RenderedAtNs=r.GetProperty(name+"PathRenderedAtNs").ValueKind==JsonValueKind.Null?null:U(name+"PathRenderedAtNs"),Semantics=S("pathSemantics"),NamespaceStatus=S("mountNamespaceIdentityStatus"),OriginalSyscallPathStatus=S("originalSyscallPathStatus"),DeletedTextStatus=S("deletedPathTextStatus")};
            if(!path.IsValid()||r.GetProperty(name+"Path").GetString()!=path.Text)throw new InvalidDataException("Native path bytes/text/status contradict each other");return path;
        }
        if(r.GetProperty("mountNamespaceIdentity").ValueKind!=JsonValueKind.Null)throw new InvalidDataException("Unsupported native namespace identity");
        var pid=r.GetProperty("pid").GetUInt32();if(pid>int.MaxValue)throw new InvalidDataException("Native PID outside supported range");var tid=r.GetProperty("tid").GetUInt32();
        var k=new LinuxKernelEvidence{Version=schema==5?1:2,NativeSchemaVersion=schema,TargetIdentity=targetIdentity,CollectorInstance=collector,CollectorSequence=sequence,NativeObservationSha256=Convert.ToHexString(SHA256.HashData(bytes.Span)),
            ProviderEpoch=U("providerEpoch"),Cookie=U("cookie"),ProcessId=pid==0?null:(int)pid,ThreadId=tid==0?null:tid,TaskStartNs=U("taskStartNs"),ProcessStartNs=U("processStartNs"),SelfExecId=U("selfExecId"),
            AssociationBefore=U("before"),AssociationAfter=U("after"),AssociationErrorBefore=I("errorBefore"),AssociationErrorAfter=I("errorAfter"),AssociationError=I("associationError"),
            ActorInode=U("actorInode"),ActorDevice=r.GetProperty("actorDevice").GetUInt32(),ActorSize=U("actorSize"),CaptureStartNs=U("captureStartNs"),CaptureEndNs=U("captureEndNs"),
            Reservation=L("reservation"),Lease=L("lease"),FinalizeError=L("finalizeError"),DiagnosticResult=L("negativeResult"),DiagnosticMode=r.GetProperty("testMode").GetUInt32(),CredentialFields=r.GetProperty("credentialFields").GetUInt32(),CredentialError=I("credentialError"),
            Uid=Nullable("uid"),EffectiveUid=Nullable("euid"),FileSystemUid=Nullable("fsuid"),Gid=Nullable("gid"),EffectiveGid=Nullable("egid"),FileSystemGid=Nullable("fsgid"),CredentialNamespace=S("credentialNamespace"),CredentialEncoding=S("credentialIdEncoding"),
            PriorResult=I("priorResult"),PriorResultMeaning=S("priorResultMeaning"),OperationOutcome=S("targetOperationOutcome"),CaptureIssue=S("captureIssue"),RecordForm=S("recordForm"),ActorPath=Path("actor"),TargetPath=Path("target"),WhitelistEligible=r.GetProperty("whitelistEligible").GetBoolean()};
        if(!k.IsValid())throw new InvalidDataException("Invalid Linux kernel observation");
        var id=Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes($"{sensor}:{collector}:{sequence}:{k.ProviderEpoch}:{k.Cookie}")).AsSpan(0,16)).ToLowerInvariant();
        var e=new AgentEvent(id,receivedUtc,"File open observed before final result",k.TargetPath.Display,k.SubjectDisplay,k.ActorPath.State=="captured"?k.ActorPath.Display:null,k.ProcessId,"Linux kernel"){
            Attribution=new(){Provider="Linux kernel",Level="Partial attribution",Basis="Kernel pre-open evidence. Final I/O result and pathname namespace are unavailable. Inspect raw path bytes, credential namespace and actor association status.",
                EvidenceId=collector+":"+sequence.ToString(CultureInfo.InvariantCulture),Outcome="Unknown",UserId=k.Uid,EffectiveUserId=k.EffectiveUid,FileSystemUserId=k.FileSystemUid,GroupId=k.Gid,EffectiveGroupId=k.EffectiveGid,
                ProcessStartTicks=k.ProcessStartKey,TargetStableId=targetIdentity?.StableId,EventTimeCredentials=k.CredentialFields!=0,CompleteRecordSet=false,LinuxKernel=k}};
        if(!e.Attribution.IsValid()||!LinuxKernelEvidence.Matches(e))throw new InvalidDataException("Linux event mapping contradicts evidence");return e;
    }
    private static AgentEvent DecodeAtomic(ReadOnlyMemory<byte> raw,string sensor,string collector,long sequence,DateTimeOffset receivedUtc)
    {
        var f=LinuxAtomicObservationFrame.DecodeEnvelope(raw);var key=f.ObservedKey;
        string D(ulong v)=>v.ToString(CultureInfo.InvariantCulture);
        var p=new LinuxPermissionObservation{Schema=f.Schema,Stage=f.Stage,OperationNonce=D(key.OperationNonce),ObservedLease=D(key.LeaseId),EntryNs=D(f.EntryNs),ObservedNs=D(f.ObservedNs),
            AccessMask=f.AccessMask,PermissionResult=f.PermissionResult,IdentityFields=f.IdentityFields,IdentityError=f.IdentityError,ActorMetadataError=f.ActorMetadataError};
        var k=new LinuxKernelEvidence{Version=f.Io==null?3:4,NativeSchemaVersion=f.Io==null?7:8,PermissionObservation=f.Io==null?p:null,IoObservation=f.Io,OperationOutcome=f.Io?.Outcome??"not-observed",CollectorInstance=collector,CollectorSequence=sequence,
            NativeObservationSha256=Convert.ToHexString(SHA256.HashData(raw.Span)),ProviderEpoch=D(key.ProviderEpoch),Cookie=D(key.Cookie),ProcessId=(int)key.ProcessId,ThreadId=(uint)key.ThreadId,
            ProcessStartNs=D(key.ProcessStartNs),TaskStartNs=D(key.TaskStartNs),SelfExecId=D(key.SelfExecId),AssociationBefore=D(key.AssociationGeneration),AssociationAfter=D(key.AssociationGeneration),
            AssociationError=f.AssociationError,AssociationErrorBefore=f.AssociationError,AssociationErrorAfter=f.AssociationError,ActorDevice=(uint)key.ActorDevice,ActorInode=D(key.ActorInode),ActorSize=D(f.ActorSize),
            TargetIdentity=new(){Device=(uint)key.TargetDevice,Inode=D(key.TargetInode),Ordinal=f.TargetOrdinal},CaptureStartNs=D(f.EntryNs),CaptureEndNs=D(f.ObservedNs),
            Reservation=f.Reservation,Lease=f.CanAuthorizeCopy?(long)key.LeaseId:0,FinalizeError=f.FinalizeError,
            CredentialFields=f.CredentialFields,CredentialError=f.CredentialError,Uid=f.Uid,EffectiveUid=f.EffectiveUid,FileSystemUid=f.FileSystemUid,Gid=f.Gid,EffectiveGid=f.EffectiveGid,FileSystemGid=f.FileSystemGid,
            Hook=f.Hook switch{1=>"fentry-fexit/inode_permission",2=>"fentry-fexit/security_file_permission",3=>"fentry-fexit/vfs_write",4=>"fentry-fexit/do_iter_readv_writev",_=>throw new InvalidDataException("Unknown atomic hook")},PriorResultMeaning="NO_PRECEDING_LSM_RESULT",RecordForm="full",CaptureIssue="NONE",
            ActorPath=new(){NativeResult=-61},TargetPath=new(){NativeResult=-61}};
        if(!k.IsValid())throw new InvalidDataException("Invalid permission observation evidence");
        var id=LinuxAtomicObservationFrame.DeliveryIdentity(sensor,collector,sequence,raw.Span);
        var e=new AgentEvent(id,receivedUtc,k.OperationDescription,k.TargetPath.Display,k.SubjectDisplay,null,k.ProcessId,"Linux kernel"){
            Attribution=new(){Provider="Linux kernel",Level="Partial attribution",Basis=f.Io==null?"Kernel permission-hook evidence; permission return is not final syscall outcome. Paths and uncollected metadata are unavailable.":"Kernel VFS entry/return evidence; inspect I/O stage, availability and pending completion. Paths and uncollected metadata are unavailable.",
                EvidenceId=collector+":"+sequence.ToString(CultureInfo.InvariantCulture),Outcome="Unknown",UserId=k.Uid,EffectiveUserId=k.EffectiveUid,FileSystemUserId=k.FileSystemUid,GroupId=k.Gid,EffectiveGroupId=k.EffectiveGid,
                ProcessStartTicks=k.ProcessStartKey,TargetStableId=k.TargetIdentity.StableId,EventTimeCredentials=k.CredentialFields!=0,CompleteRecordSet=false,LinuxKernel=k}};
        if(!e.Attribution.IsValid()||!LinuxKernelEvidence.Matches(e))throw new InvalidDataException("Permission observation mapping contradicts evidence");return e;
    }
}
