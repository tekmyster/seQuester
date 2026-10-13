using System.Text.Json;
using RansomFree.Contracts;

namespace RansomFree.Client.Forensics;

internal sealed partial class LinuxForensicJournal
{
    internal sealed record IoPair(string Status,string? EntryEventId,string? ResultEventId,string? ReturnValue,string Reason);
    internal bool IoEntryCompletionAvailable(string id)
    {
        var observation=Read(id).Observation;
        if(observation.Attribution?.LinuxKernel is not {} kernel)return true;
        if(kernel.IoObservation?.Stage!=2&&kernel.PermissionObservation?.Stage!=2)return true;
        var session=ReadNativePin(id)?.Intent.SessionId;
        if(session==null)return true; // Retain the explicit unavailable source outcome.
        if(kernel.IoObservation is {Schema:3,Stage:2}){var pair=ReadIoPair(session,kernel);return pair.Status!="paired"||Read(pair.EntryEventId!).Completion!=null;}
        if(kernel.PermissionObservation is {Schema:1,Stage:2}){var pair=ReadPermissionPair(session,kernel);return pair.Status!="paired"||Read(pair.EntryEventId!).Completion!=null;}
        return true;
    }
    internal IoPair ReadIoPair(string session,LinuxKernelEvidence evidence)
    {
        if(!evidence.IsValid()||evidence.Version!=4||evidence.IoObservation is not {Schema:3} io)
            return new("unavailable",null,null,null,"IO_OBSERVATION_UNPAIRABLE");
        lock(gate)
        {
            using var c=Open();var prefix=evidence.Cookie+":"+io.OperationNonce+":";
            AgentEvent? ReadStage(int stage)
            {
                using var q=Command(c,null,"SELECT decoded FROM canonical_events WHERE session_id=$session AND provider_epoch=$epoch AND positive_cookie=$cookie",
                    ("$session",session),("$epoch",evidence.ProviderEpoch),("$cookie",prefix+stage));
                var bytes=q.ExecuteScalar() as byte[];if(bytes==null)return null;
                var value=JsonSerializer.Deserialize<AgentEvent>(bytes)??throw new InvalidDataException("I/O canonical record missing");
                if(!LinuxKernelEvidence.Matches(value))throw new InvalidDataException("I/O canonical record invalid");return value;
            }
            var entry=ReadStage(1);var result=ReadStage(2);
            if(entry==null||result==null)return new("unavailable",entry?.EventId,result?.EventId,null,entry==null?"IO_ENTRY_NOT_DURABLE":"IO_RETURN_NOT_DURABLE");
            var a=entry.Attribution!.LinuxKernel!;var b=result.Attribution!.LinuxKernel!;
            // Check every task, birth, executable generation, credential, lease,
            // target, requested length, flags and entry-offset field. A later
            // completion read error is retained separately, not invented away.
            if(!LinuxKernelEvidence.SameIoOperation(a,b))return new("unavailable",entry.EventId,result.EventId,null,"IO_PAIR_IDENTITY_MISMATCH");
            return new("paired",entry.EventId,result.EventId,b.IoObservation!.ReturnValue,"EXACT_DURABLE_IO_PAIR");
        }
    }
    internal ForensicEvidence LinkIoReturnActor(AgentEvent observation,ForensicEvidence forensic)
    {
        if(observation.Attribution?.LinuxKernel is not {IoObservation:{Schema:3,Stage:2}} kernel)return forensic;
        var session=ReadNativePin(observation.EventId)?.Intent.SessionId;
        var pair=session==null?new IoPair("unavailable",null,observation.EventId,null,"IO_SOURCE_SESSION_UNAVAILABLE"):ReadIoPair(session,kernel);
        var link=new LinuxIoPairEvidence{ReturnEventId=observation.EventId,EntryEventId=pair.EntryEventId,Reason=pair.Reason};
        if(pair.Status=="paired")
        {
            var entry=Read(pair.EntryEventId!);
            link=link with{Status="paired",EntryKernel=entry.Observation.Attribution!.LinuxKernel};
            if(entry.Completion!=null)
            {
                var completed=JsonSerializer.Deserialize<AgentEvent>(entry.Completion)!;
                using var actor=RestoreActor(pair.EntryEventId!);
                var captured=completed.Forensics!.ActorExecutable;
                if(actor.Image!=null&&actor.LinuxAcquisition is {Status.State:"captured",SnapshotSha256:not null} acquisition&&
                    captured.Sha256==acquisition.SnapshotSha256&&captured.HashStatus.State=="captured"&&acquisition.Matches(link.EntryKernel!))
                    link=link with{ActorCompletionEventId=completed.EventId,ActorSha256=captured.Sha256,ActorEvidenceId=completed.Forensics.Preservation.Status.State=="captured"?completed.Forensics.Preservation.EvidenceId:null,
                        ActorStatus=EvidenceStatus.Captured("EXACT_IO_ENTRY_VERIFIED_PRIVATE_ACTOR")};
            }
        }
        if(!link.Matches(kernel,forensic.EventId,forensic.RelatedEventId))throw new InvalidDataException("I/O return actor linkage contradicts immutable observations");
        return forensic with{LinuxIoPair=link};
    }
    internal ActorLease? RestoreIoTrustEntry(AgentEvent value)
    {
        if(value.Attribution?.LinuxKernel is not {} kernel)return null;
        if(kernel.IoObservation?.Stage!=2&&kernel.PermissionObservation?.Stage!=2)return null;
        var session=ReadNativePin(value.EventId)?.Intent.SessionId;if(session==null)return null;
        string? entryId;
        if(kernel.IoObservation is {Stage:2}&&value.Forensics?.LinuxIoPair is {Status:"paired",ActorStatus.State:"captured"} io)
        {var pair=ReadIoPair(session,kernel);if(pair.Status!="paired"||pair.EntryEventId!=io.EntryEventId)return null;entryId=pair.EntryEventId;}
        else if(kernel.PermissionObservation is {Stage:2}&&value.Forensics?.LinuxPermissionPair is {Status:"paired",ActorStatus.State:"captured"} permission)
        {var pair=ReadPermissionPair(session,kernel);if(pair.Status!="paired"||pair.EntryEventId!=permission.EntryEventId)return null;entryId=pair.EntryEventId;}
        else return null;
        var work=Read(entryId!);if(work.Original==null||work.Completion==null)return null;
        var entry=LinuxKernelTrustBinding.PolicyInput(JsonSerializer.Deserialize<AgentEvent>(work.Original)!);
        if(LinuxNativeHashBinding.ActorHash(value,entry)==null)return null;
        var actor=RestoreActor(entry.EventId);
        try
        {
            if(actor.AcquiredLinuxNativeHash(entry)==null){actor.Dispose();return null;}
            actor.LinuxTrustEntry=entry;return actor;
        }
        catch{actor.Dispose();throw;}
    }
}
