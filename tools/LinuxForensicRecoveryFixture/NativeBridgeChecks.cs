using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using RansomFree.Client;
using RansomFree.Client.Forensics;
using RansomFree.Contracts;

internal static class NativeBridgeChecks
{
    internal static void Run(string proofRoot,string root)
    {
        if(Directory.Exists(root))throw new ArgumentException("Fresh bridge test root required");Directory.CreateDirectory(root);
        var checks=new List<string>();void Check(bool yes,string label){if(!yes)throw new Exception(label);checks.Add(label);}
        void Reject(Action action,string label){try{action();}catch(Exception e)when(e is InvalidDataException or IOException or ArgumentException or InvalidOperationException or JsonException){Check(true,label);return;}throw new Exception("Accepted: "+label);}
        using var accepted=JsonDocument.Parse(File.ReadAllBytes(Path.Combine(proofRoot,"RUNTIME-ACCEPTANCE.json")));
        Check(accepted.RootElement.GetProperty("Passed").GetBoolean()&&accepted.RootElement.GetProperty("ArchiveSha256").GetString()=="a230b0a26c0067a18872ad71ea41dcba4e9d6ab310133cec232c132be5dc4cd2","exact independently accepted R37 native source required");
        foreach(var item in accepted.RootElement.GetProperty("Files").EnumerateArray())
        {
            var path=Path.GetFullPath(Path.Combine(proofRoot,item.GetProperty("Path").GetString()!));
            if(!path.StartsWith(Path.GetFullPath(proofRoot)+Path.DirectorySeparatorChar,StringComparison.OrdinalIgnoreCase)||
                !Convert.ToHexString(SHA256.HashData(File.ReadAllBytes(path))).Equals(item.GetProperty("Sha256").GetString(),StringComparison.OrdinalIgnoreCase))throw new InvalidDataException("Native proof bytes differ");
        }
        using var doc=JsonDocument.Parse(File.ReadAllBytes(Path.Combine(proofRoot,"evidence/events.json")));
        var originals=doc.RootElement.GetProperty("Originals").Deserialize<AgentEvent[]>()!;var completions=doc.RootElement.GetProperty("Completions").Deserialize<AgentEvent[]>()!;
        Check(originals.Length==5&&completions.Length==5,"five real native event pairs required");var sensor=originals[0].Forensics!.SensorId;
        LinuxNativeBridgePacket? preserved=null;var count=0;
        foreach(var original in originals)
        {
            var completion=completions.Single(e=>e.Forensics!.RelatedEventId==original.EventId);var p=completion.Forensics!.Preservation;byte[]? actor=null,manifest=null;
            if(p.Status.State=="captured")
            {actor=File.ReadAllBytes(Path.Combine(proofRoot,"evidence/evidence/actors",p.EvidenceId+".bin"));manifest=File.ReadAllBytes(Path.Combine(proofRoot,"evidence/evidence/actors",p.EvidenceId+".json"));}
            var packet=LinuxNativeBridgePacket.Create(sensor,EventSpool.Encode(original),EventSpool.Encode(completion),actor,manifest);var bytes=packet.Encode(sensor);
            File.WriteAllBytes(Path.Combine(root,"packet-"+count+".json"),bytes);
            if(actor!=null)preserved??=packet;
            Check(LinuxNativeBridgePacket.Parse(bytes,sensor)==packet,"native event packet round trip: "+count);
            var directory=Path.Combine(root,"pair-"+count++);var spool=new EventSpool(directory,sensor);var importer=new LinuxNativeBridgeImport(directory,sensor,spool);
            var receipt=importer.ImportVerifiedBytes(bytes,original.EventId);Check(spool.Count==2&&receipt.PacketSha256==LinuxNativeBridgePacket.Hash(bytes),"both exact events durably imported");
            var values=spool.Peek().Events;Check(EventSpool.Encode(values[0]).AsSpan().SequenceEqual(EventSpool.Encode(original))&&EventSpool.Encode(values[1]).AsSpan().SequenceEqual(EventSpool.Encode(completion)),"user/process/PID/hash/trust/timeline bytes unchanged");
            Check(importer.ImportVerifiedBytes(bytes,original.EventId)==receipt&&spool.Count==2,"exact receipt replay does not enqueue duplicate events");
            Check(Directory.Exists(Path.Combine(directory,"evidence/actors"))==(actor!=null),"log-only originals import no actor preservation artifacts");
            if(actor!=null)
            {
                Check(File.ReadAllBytes(Path.Combine(directory,"evidence/actors",p.EvidenceId+".bin")).AsSpan().SequenceEqual(actor)&&
                    File.ReadAllBytes(Path.Combine(directory,"evidence/actors",p.EvidenceId+".json")).AsSpan().SequenceEqual(manifest),"actor and forensic manifest copied byte-for-byte");
                Check(File.Exists(Path.Combine(directory,"evidence/uploads",p.EvidenceId+".pending.json")),"existing central upload queue registered");
            }
        }
        var sample=preserved??throw new Exception("Native preserved actor required");var encoded=sample.Encode(sensor);
        Reject(()=>sample.Encode(Guid.NewGuid().ToString("N")),"cross-sensor import refused");
        Reject(()=>LinuxNativeBridgePacket.Parse(Encoding.UTF8.GetBytes(Encoding.UTF8.GetString(encoded)[..^1]+",\"Extra\":1}"),sensor),"unknown bridge fields refused");
        Reject(()=>(sample with{Version=2}).Encode(sensor),"unknown bridge version refused");
        Reject(()=>(sample with{ActorBase64=Convert.ToBase64String(new byte[]{1})}).Encode(sensor),"changed actor bytes refused");
        Reject(()=>(sample with{ManifestBase64=Convert.ToBase64String(new byte[]{1})}).Encode(sensor),"changed forensic manifest refused");
        Reject(()=>(sample with{ActorBase64=null,ManifestBase64=null}).Encode(sensor),"preserved event cannot silently omit actor evidence");
        var core=sample.Validate(sensor);var wrong=core.Completion with{ProcessId=core.Completion.ProcessId+1};
        Reject(()=>(sample with{CompletionBase64=Convert.ToBase64String(JsonSerializer.SerializeToUtf8Bytes(wrong))}).Encode(sensor),"contradictory actor PID refused");
        foreach(var cut in new[]{"bridge-actor-imported","bridge-manifest-imported","bridge-original-imported","bridge-completion-imported","bridge-upload-registered","bridge-receipt-committed"})
        {
            var dir=Path.Combine(root,cut);var spool=new EventSpool(dir,sensor);var importer=new LinuxNativeBridgeImport(dir,sensor,spool);
            Reject(()=>importer.ImportVerifiedBytes(encoded,sample.SourceEventId,p=>{if(p==cut)throw new IOException("Injected import interruption");}),"interruption propagated: "+cut);
            var recovered=new LinuxNativeBridgeImport(dir,sensor,new EventSpool(dir,sensor)).ImportVerifiedBytes(encoded,sample.SourceEventId);
            Check(spool.Count==2&&recovered.PacketSha256==LinuxNativeBridgePacket.Hash(encoded),"fresh importer recovers exact durable bytes: "+cut);
        }
        var conflict=Path.Combine(root,"conflict");var conflictSpool=new EventSpool(conflict,sensor);var conflicting=new LinuxNativeBridgeImport(conflict,sensor,conflictSpool);
        var artifact=Path.Combine(conflict,"evidence/actors",core.Completion.Forensics!.Preservation.EvidenceId+".bin");Directory.CreateDirectory(Path.GetDirectoryName(artifact)!);File.WriteAllBytes(artifact,[42]);
        Reject(()=>conflicting.ImportVerifiedBytes(encoded,sample.SourceEventId),"existing actor bytes never overwritten");
        Check(File.ReadAllBytes(artifact).SequenceEqual(new byte[]{42})&&conflictSpool.Count==0&&!File.Exists(Path.Combine(conflict,"native-bridge-receipts",sample.SourceEventId+".json")),"conflict retains evidence without receipt or fabricated import");
        File.WriteAllText(Path.Combine(root,"RESULTS.json"),JsonSerializer.Serialize(new{Passed=true,Checks=checks.Count,Details=checks,Scope="Exact qualified native events through immutable packet validation and durable local import/replay; no installed bridge owner or native activation"}));
        Console.WriteLine(JsonSerializer.Serialize(new{Passed=true,Checks=checks.Count}));
    }
}
