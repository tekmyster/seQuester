using System.Globalization;
using System.Security.Cryptography;
using System.Text.Json;

namespace RansomFree.Contracts;

// Historical samples, not continuous availability through journal fsync.
public sealed record LinuxKernelSourceHealthEvidence(long Generation,ulong LostAtReady,ulong LostAtSample,
    DateTimeOffset StartedUtc,DateTimeOffset ReturnedUtc,DateTimeOffset ChildCheckedUtc,DateTimeOffset SealedUtc,
    long ActiveBeforeTicks,long SampleStartedTicks,long SampleReturnedTicks,long ChildCheckedTicks,long SealedTicks,long MonotonicFrequency)
{
    public string Semantics {get;init;}="ZERO_LOSS_AT_SAMPLE_WITH_ACTIVE_GENERATION_BRACKET";
    public bool ChildExitNotObservedAtCheck {get;init;}=true;
    public bool IsValid(long generation)=>Generation==generation&&generation>0&&LostAtReady==0&&LostAtSample==0&&
        Semantics=="ZERO_LOSS_AT_SAMPLE_WITH_ACTIVE_GENERATION_BRACKET"&&ChildExitNotObservedAtCheck&&
        StartedUtc!=default&&ReturnedUtc!=default&&ChildCheckedUtc!=default&&SealedUtc!=default&&
        ActiveBeforeTicks>0&&ActiveBeforeTicks<=SampleStartedTicks&&SampleStartedTicks<=SampleReturnedTicks&&
        SampleReturnedTicks<=ChildCheckedTicks&&ChildCheckedTicks<=SealedTicks&&MonotonicFrequency>0;
}

public sealed record LinuxKernelSourceMatchEvidence(string SourceSessionId,string ProviderEpoch,string CollectorInstance,
    string ReadyBase64,string ReadySha256,string ActivatedBase64,string ActivatedSha256,string TargetSetSha256,LinuxKernelSourceHealthEvidence Health)
{
    // Shared strict parsing uses the actual native ABI; no IDs are opened and
    // no source is recreated from these historical bytes on the server.
    public bool Matches(AgentEvent value,LinuxKernelActorMatchEvidence actor)
    {
        if(Health?.IsValid(actor.SourceGeneration)!=true||SourceSessionId!=actor.SourceSessionId||ProviderEpoch!=actor.ProviderEpoch||
            CollectorInstance!=actor.CollectorInstance||value.Attribution?.LinuxKernel?.TargetIdentity is not {} target||
            value.Forensics is not {} f||Health.MonotonicFrequency!=f.MonotonicFrequency||Health.ActiveBeforeTicks<f.MonotonicTicks)
            return false;
        try
        {
            static byte[] Exact(string text,string hash)
            {
                if(text is not {Length:>0 and <=5464}||hash is not {Length:64})throw new InvalidDataException("Bounded source frame required");
                var bytes=Convert.FromBase64String(text);
                if(Convert.ToBase64String(bytes)!=text||!Convert.ToHexString(SHA256.HashData(bytes)).Equals(hash,StringComparison.OrdinalIgnoreCase))
                    throw new InvalidDataException("Source frame digest mismatch");
                return bytes;
            }
            var ready=LinuxControlledLoaderProtocol.ParseReady(Exact(ReadyBase64,ReadySha256));
            if(ready.ControlVersion!=2||ready.Epoch.ToString(CultureInfo.InvariantCulture)!=ProviderEpoch||ready.Lost!=Health.LostAtReady||
                ready.Targets?.Digest!=TargetSetSha256||!ready.Targets.Contains(target.Ordinal,target.Device,ulong.Parse(target.Inode,CultureInfo.InvariantCulture)))return false;
            var activated=LinuxControlledLoaderProtocol.ParseActivated(Exact(ActivatedBase64,ActivatedSha256),ready,SourceSessionId);
            return activated.Lost==0;
        }
        catch(Exception ex)when(ex is InvalidDataException or FormatException or OverflowException or ArgumentException){return false;}
    }
}

// Consistency evidence for a future v3 trust decision, not a safe verdict or a
// cryptographic attestation of an authenticated sensor. Creation on the sensor
// additionally requires its held private descriptor and live owned source.
public sealed record LinuxKernelTrustBinding(string SensorId,LinuxKernelActorMatchEvidence Actor,LinuxKernelSourceMatchEvidence Source,string PolicyInputSha256)
{
    public int Version {get;init;}=1;
    public const string Basis="linux-bpf-lsm-module-backing-copy-v1";
    public bool Matches(AgentEvent? value)
    {
        if(Version!=1||value?.Forensics?.SensorId!=SensorId||!Guid.TryParseExact(SensorId,"N",out _)||Actor==null||Source==null)return false;
        var actual=LinuxKernelActorMatchEvidence.Inspect(value);
        return actual.Evidence==Actor&&Source.Matches(value,Actor)&&PolicyInputSha256==InputDigest(value);
    }
    public static LinuxKernelTrustBinding Create(AgentEvent value,LinuxKernelSourceMatchEvidence source)
    {
        var facts=LinuxKernelActorMatchEvidence.Inspect(value);
        if(facts.Evidence==null)throw new InvalidDataException(facts.Reason);
        var binding=new LinuxKernelTrustBinding(value.Forensics!.SensorId,facts.Evidence,source,InputDigest(value));
        if(!binding.Matches(value))throw new InvalidDataException("Linux actor/source matching evidence is inconsistent");
        return binding;
    }
    // Resulting trust/detection is not an input to the decision. All original
    // observation, acquisition and timeline fields remain in this projection.
    public static AgentEvent PolicyInput(AgentEvent value)=>value with{Trust=null,Forensics=value.Forensics is {} f?
        f with{Detection=new("alert","alert",[],["POLICY_INPUT_EXCLUDES_DETECTION"])}:null};
    public static string InputDigest(AgentEvent value)=>Convert.ToHexString(SHA256.HashData(JsonSerializer.SerializeToUtf8Bytes(PolicyInput(value))));
    public TrustActor TrustActor()=>ActorFor(SensorId,Actor);
    public static TrustActor ActorFor(string sensor,LinuxKernelActorMatchEvidence actor)=>new(Authority:sensor,
        AccountId:actor.FileSystemUid.ToString(CultureInfo.InvariantCulture),Executable:actor.Executable,Sha256:actor.Sha256,Verified:true,AccountKind:"uid");
}
