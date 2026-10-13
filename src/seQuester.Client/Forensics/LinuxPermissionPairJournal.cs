using System.Text.Json;
using RansomFree.Contracts;

namespace RansomFree.Client.Forensics;

internal sealed partial class LinuxForensicJournal
{
    // Reconstruct from the existing immutable raw/canonical ledger, not a second
    // capability store. Missing or mismatched records never authorize native I/O.
    internal sealed record PermissionPair(string Status,string? EntryEventId,string? ResultEventId,int? PermissionResult,string Reason);
    internal PermissionPair ReadPermissionPair(string session,LinuxKernelEvidence evidence)
    {
        if(!evidence.IsValid()||evidence.Version!=3||evidence.PermissionObservation is not {Schema:1} p)
            return new("unavailable",null,null,null,"PERMISSION_OBSERVATION_UNPAIRABLE");
        lock(gate)
        {
            using var c=Open();var prefix=evidence.Cookie+":"+p.OperationNonce+":";
            AgentEvent? ReadStage(int stage)
            {
                using var q=Command(c,null,"SELECT decoded FROM canonical_events WHERE session_id=$session AND provider_epoch=$epoch AND positive_cookie=$cookie",
                    ("$session",session),("$epoch",evidence.ProviderEpoch),("$cookie",prefix+stage));
                var bytes=q.ExecuteScalar() as byte[];if(bytes==null)return null;
                var value=JsonSerializer.Deserialize<AgentEvent>(bytes)??throw new InvalidDataException("Permission canonical record unavailable");
                if(!LinuxKernelEvidence.Matches(value))throw new InvalidDataException("Permission canonical record invalid");return value;
            }
            var entry=ReadStage(1);var result=ReadStage(2);
            if(entry==null||result==null)return new("unavailable",entry?.EventId,result?.EventId,null,entry==null?"PERMISSION_ENTRY_NOT_DURABLE":"PERMISSION_RESULT_NOT_DURABLE");
            var a=entry.Attribution!.LinuxKernel!;var b=result.Attribution!.LinuxKernel!;
            // Only stage, return, and observation time may differ. The captured
            // process/actor/target/security identity must remain byte-equivalent.
            if(!LinuxKernelEvidence.SamePermissionOperation(a,b))return new("unavailable",entry.EventId,result.EventId,null,"PERMISSION_PAIR_IDENTITY_MISMATCH");
            return new("paired",entry.EventId,result.EventId,b.PermissionObservation!.PermissionResult,"EXACT_DURABLE_PERMISSION_PAIR");
        }
    }
    internal ForensicEvidence LinkPermissionReturnActor(AgentEvent observation,ForensicEvidence forensic)
    {
        if(observation.Attribution?.LinuxKernel is not {PermissionObservation:{Schema:1,Stage:2}} kernel)return forensic;
        var session=ReadNativePin(observation.EventId)?.Intent.SessionId;
        var pair=session==null?new PermissionPair("unavailable",null,observation.EventId,null,"PERMISSION_SOURCE_SESSION_UNAVAILABLE"):ReadPermissionPair(session,kernel);
        var link=new LinuxPermissionPairEvidence{ReturnEventId=observation.EventId,EntryEventId=pair.EntryEventId,Reason=pair.Reason};
        if(pair.Status=="paired")
        {
            var entry=Read(pair.EntryEventId!);link=link with{Status="paired",EntryKernel=entry.Observation.Attribution!.LinuxKernel};
            if(entry.Completion!=null)
            {
                var completed=JsonSerializer.Deserialize<AgentEvent>(entry.Completion)!;using var actor=RestoreActor(pair.EntryEventId!);
                var captured=completed.Forensics!.ActorExecutable;
                if(actor.Image!=null&&actor.LinuxAcquisition is {Status.State:"captured",SnapshotSha256:not null} acquisition&&captured.Sha256==acquisition.SnapshotSha256&&captured.HashStatus.State=="captured"&&acquisition.Matches(link.EntryKernel!))
                    link=link with{ActorCompletionEventId=completed.EventId,ActorSha256=captured.Sha256,ActorEvidenceId=completed.Forensics.Preservation.Status.State=="captured"?completed.Forensics.Preservation.EvidenceId:null,ActorStatus=EvidenceStatus.Captured("EXACT_PERMISSION_ENTRY_VERIFIED_PRIVATE_ACTOR")};
            }
        }
        if(!link.Matches(kernel,forensic.EventId,forensic.RelatedEventId))throw new InvalidDataException("Permission return actor linkage contradicts immutable observations");
        return forensic with{LinuxPermissionPair=link};
    }
}
