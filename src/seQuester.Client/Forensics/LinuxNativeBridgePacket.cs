using System.Security.Cryptography;
using System.Text.Json;
using RansomFree.Contracts;

namespace RansomFree.Client.Forensics;

// Local immutable transport, not a new event schema or policy decision. Original
// and completion bytes are retained exactly; only actor artifacts are carried.
internal sealed record LinuxNativeBridgePacket(int Version,string SensorId,string SourceEventId,string OriginalBase64,
    string CompletionBase64,string? ActorBase64,string? ManifestBase64)
{
    internal const int MaximumBytes=6*1024*1024;
    internal sealed record Verified(AgentEvent Original,AgentEvent Completion,byte[] OriginalBytes,byte[] CompletionBytes,byte[]? Actor,byte[]? Manifest);
    private static byte[] Decode(string value,int bound)
    {
        if(value==null||value.Length==0||value.Length>((bound+2)/3)*4)throw new InvalidDataException("Native bridge field exceeds bound");
        byte[] bytes;try{bytes=Convert.FromBase64String(value);}catch(FormatException e){throw new InvalidDataException("Invalid native bridge encoding",e);}
        if(bytes.Length>bound||Convert.ToBase64String(bytes)!=value)throw new InvalidDataException("Noncanonical native bridge encoding");return bytes;
    }
    internal static string Hash(byte[] bytes)=>Convert.ToHexString(SHA256.HashData(bytes));
    internal Verified Validate(string sensor)
    {
        if(Version!=1||!EvidenceTransferLimits.Id(sensor)||SensorId!=sensor||!EvidenceTransferLimits.Id(SourceEventId))throw new InvalidDataException("Native bridge identity invalid");
        var ob=Decode(OriginalBase64,65536);var cb=Decode(CompletionBase64,65536);
        var original=JsonSerializer.Deserialize<AgentEvent>(ob)??throw new InvalidDataException("Missing bridge original");
        var completion=JsonSerializer.Deserialize<AgentEvent>(cb)??throw new InvalidDataException("Missing bridge completion");
        if(!EventSpool.Encode(original).AsSpan().SequenceEqual(ob)||!EventSpool.Encode(completion).AsSpan().SequenceEqual(cb))throw new InvalidDataException("Bridge event serialization differs");
        var first=original.Forensics;var last=completion.Forensics;
        if(first==null||last==null||original.Attribution?.LinuxKernel==null||completion.Attribution?.LinuxKernel==null||
            first.SensorId!=sensor||last.SensorId!=sensor||first.RelatedEventId!=null||last.RelatedEventId!=SourceEventId||original.EventId!=SourceEventId||
            completion.EventId==SourceEventId||completion.Trust!=null||first.Process.InstanceId!=last.Process.InstanceId||
            original.ProcessId!=completion.ProcessId||original.Process!=completion.Process||original.User!=completion.User||original.Path!=completion.Path||
            JsonSerializer.Serialize(original.Attribution)!=JsonSerializer.Serialize(completion.Attribution))
            throw new InvalidDataException("Native bridge event/process/target linkage differs");
        if(original.Trust is {Version:3} trust&&trust.LinuxKernelBinding?.Matches(original)!=true||
            JsonSerializer.Serialize(first.Process)!=JsonSerializer.Serialize(last.Process)||
            JsonSerializer.Serialize(first.ActorExecutable.LinuxAcquisition)!=JsonSerializer.Serialize(last.ActorExecutable.LinuxAcquisition)||
            JsonSerializer.Serialize(first.ActorExecutable.LinuxNativeWork)!=JsonSerializer.Serialize(last.ActorExecutable.LinuxNativeWork))
            throw new InvalidDataException("Native bridge original/completion evidence or trust binding differs");
        var p=last.Preservation;
        if(p.Status.State!="captured")
        {
            if(ActorBase64!=null||ManifestBase64!=null)throw new InvalidDataException("Unpreserved event must not carry an actor or target copy");
            return new(original,completion,ob,cb,null,null);
        }
        if(ActorBase64==null||ManifestBase64==null||!EvidenceTransferLimits.Id(p.EvidenceId)||p.HashMatched!=true||p.Size is null or <0 or >4*1024*1024||
            p.SourceEventId!=SourceEventId||p.ProcessInstanceId!=last.Process.InstanceId||p.Sha256!=last.ActorExecutable.Sha256||
            p.ArtifactRelativePath!="evidence/actors/"+p.EvidenceId+".bin"||p.ManifestRelativePath!="evidence/actors/"+p.EvidenceId+".json")
            throw new InvalidDataException("Native actor preservation missing or inconsistent");
        var actor=Decode(ActorBase64,4*1024*1024);var manifest=Decode(ManifestBase64,EvidenceTransferLimits.ManifestBytes);
        if(actor.LongLength!=p.Size||Hash(actor)!=p.Sha256||Hash(manifest)!=p.ManifestSha256)throw new InvalidDataException("Native bridge actor/manifest hash mismatch");
        using var doc=JsonDocument.Parse(manifest);var m=doc.RootElement;
        if(m.GetProperty("SchemaVersion").GetInt32()!=1||m.GetProperty("ExpectedSha256").GetString()!=p.Sha256||
            JsonSerializer.Serialize(m.GetProperty("Process").Deserialize<ProcessInstanceEvidence>())!=JsonSerializer.Serialize(last.Process)||
            JsonSerializer.Serialize(m.GetProperty("Preservation").Deserialize<PreservationEvidence>())!=JsonSerializer.Serialize(p with{ManifestSha256=null})||
            JsonSerializer.Serialize(m.GetProperty("LinuxActorAcquisition").Deserialize<LinuxActorAcquisitionEvidence>())!=JsonSerializer.Serialize(last.ActorExecutable.LinuxAcquisition)||
            JsonSerializer.Serialize(m.GetProperty("LinuxNativeWork").Deserialize<LinuxNativeWorkEvidence>())!=JsonSerializer.Serialize(last.ActorExecutable.LinuxNativeWork))
            throw new InvalidDataException("Native bridge forensic manifest linkage differs");
        return new(original,completion,ob,cb,actor,manifest);
    }
    internal byte[] Encode(string sensor)
    {
        _=Validate(sensor);var bytes=JsonSerializer.SerializeToUtf8Bytes(this);
        if(bytes.Length>MaximumBytes)throw new InvalidDataException("Native bridge packet exceeds bound");return bytes;
    }
    internal static LinuxNativeBridgePacket Parse(byte[] bytes,string sensor)
    {
        if(bytes.Length is <1 or >MaximumBytes)throw new InvalidDataException("Native bridge packet exceeds bound");
        var packet=JsonSerializer.Deserialize<LinuxNativeBridgePacket>(bytes)??throw new InvalidDataException("Missing native bridge packet");
        if(!packet.Encode(sensor).AsSpan().SequenceEqual(bytes))throw new InvalidDataException("Unknown, duplicate or noncanonical bridge fields");return packet;
    }
    internal static LinuxNativeBridgePacket Create(string sensor,byte[] original,byte[] completion,byte[]? actor=null,byte[]? manifest=null)
    {
        var id=JsonSerializer.Deserialize<AgentEvent>(original)?.EventId??throw new InvalidDataException("Missing original");
        var packet=new LinuxNativeBridgePacket(1,sensor,id,Convert.ToBase64String(original),Convert.ToBase64String(completion),
            actor==null?null:Convert.ToBase64String(actor),manifest==null?null:Convert.ToBase64String(manifest));
        _=packet.Validate(sensor);return packet;
    }
}
