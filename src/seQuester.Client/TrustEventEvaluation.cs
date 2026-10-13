using RansomFree.Contracts;
namespace RansomFree.Client;
public static class TrustEventEvaluation
{
    internal static EventTrust? EvaluateLinuxKernel(TrustPolicyCache cache,string endpoint,string? group,AgentEvent input,
        RansomFree.Client.Forensics.ActorLease actor,Func<LinuxKernelSourceMatchEvidence?> sampleSource,DateTimeOffset now)
        =>EvaluateLinuxKernel(cache.Evaluate,endpoint,group,input,actor,sampleSource,now);
    internal static EventTrust? EvaluateLinuxKernel(Func<TrustContext,DateTimeOffset,TrustRuntimeDecision> evaluate,string endpoint,string? group,AgentEvent input,
        RansomFree.Client.Forensics.ActorLease actor,Func<LinuxKernelSourceMatchEvidence?> sampleSource,DateTimeOffset now)
    {
        if(input.Forensics?.SensorId!=endpoint)return null;
        if(input.Attribution?.LinuxKernel?.NativeSchemaVersion is 7 or 8)
        {
            var entry=actor.LinuxTrustEntry;
            var hash=actor.AcquiredLinuxNativeHash(entry??input);if(hash==null||entry!=null&&LinuxNativeHashBinding.ActorHash(input,entry)!=hash)return null;
            var nativeIdentity=LinuxNativeHashBinding.ActorFor(endpoint,input,hash);
            var nativeContext=TrustIdentityContext.Bind(new("server",group,endpoint,"linux",input.Path,EventTrust.PolicyActions(input),input.ObservedUtc,nativeIdentity){ProcessBasis=LinuxNativeHashBinding.Basis},input);
            var nativeDecision=evaluate(nativeContext,now);var nativeSource=sampleSource();if(nativeSource==null)return null;
            var nativeBinding=LinuxNativeHashBinding.Create(input,nativeSource,entry);
            var nativeResult=new EventTrust(4,"linux",group,nativeIdentity,nativeDecision){EvaluatedUtc=now,ProcessBasis=LinuxNativeHashBinding.Basis,LinuxNativeHashBinding=nativeBinding};
            if(!nativeResult.IsValid())throw new InvalidDataException("Invalid Linux native hash decision");return nativeResult;
        }
        var acquired=actor.AcquiredLinuxMatchEvidence(input);
        if(acquired.Evidence is not {} facts)return null;
        var identity=LinuxKernelTrustBinding.ActorFor(endpoint,facts);
        var context=new TrustContext("server",group,endpoint,"linux",input.Path,["open"],input.ObservedUtc,identity){ProcessBasis=LinuxKernelTrustBinding.Basis};
        // Freeze the policy result before sampling. A refresh after this call
        // cannot replace its exact revision/digest or decision.
        var decision=evaluate(context,now);
        var source=sampleSource();if(source==null)return null;
        var binding=LinuxKernelTrustBinding.Create(input,source);
        var result=new EventTrust(3,"linux",group,identity,decision){EvaluatedUtc=now,ProcessBasis=LinuxKernelTrustBinding.Basis,LinuxKernelBinding=binding};
        if(!result.IsValid())throw new InvalidDataException("Invalid Linux kernel trust decision");
        return result;
    }
    public static EventTrust Evaluate(TrustPolicyCache cache,string endpoint,string? group,string os,AgentEvent value,TrustActor actor,DateTimeOffset now,string? processBasis=null,DateTimeOffset? processCreatedUtc=null,DateTimeOffset? imageCheckedUtc=null)
    {
        var provisional=new EventTrust(2,os,group,actor,new(null,null,"pending",new(1,"normal",false,true,"normal",[],"Awaiting policy."))){EvaluatedUtc=now,ProcessBasis=processBasis??(actor.Executable!=null&&actor.Sha256==null?"audit-executable-path-v1":null),ProcessCreatedUtc=processCreatedUtc,ImageCheckedUtc=imageCheckedUtc};
        if(!provisional.IsValid())provisional=provisional with{Actor=new(),ProcessBasis=null,ProcessCreatedUtc=null,ImageCheckedUtc=null};
        var evidence=provisional with{Result=cache.Evaluate(provisional.Context(endpoint,value),now)};
        if(!evidence.IsValid())throw new InvalidDataException("Invalid trust decision; event must remain unsuppressed.");
        return evidence;
    }
    public static TrustActor LinuxActor(string endpoint,AgentEvent value)
    {
        // Do not promote later procfs enrichment into event-time account/hash evidence.
        var a=value.Attribution;
        if(value.Source!="Linux Audit"||a is not {Provider:"Linux Audit",EventTimeCredentials:true,CompleteRecordSet:true,UserId:not null}||a.UserId==uint.MaxValue)return new();
        var uid=a.FileSystemUserId??a.UserId.Value;
        if(uid==uint.MaxValue)return new();
        var executable=value.Process is {Length:>1} path&&path.StartsWith('/')&&!path.Contains(" [truncated]")?path:null;
        return new(Authority:endpoint,AccountId:uid.ToString(System.Globalization.CultureInfo.InvariantCulture),Executable:executable,Verified:true,AccountKind:"uid");
    }
}
