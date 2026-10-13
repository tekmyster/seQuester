using System.Net;
using System.Security.Cryptography;
using System.Text.Json;
using System.Text.Json.Nodes;
using RansomFree.Client;
using RansomFree.Client.Forensics;
using RansomFree.Contracts;
using RansomFree.Server;

static class AcquisitionUploadChecks
{
    public static async Task Run(IReadOnlyList<AgentEvent> completions,IReadOnlyList<AgentEvent> events,string root,string sensor,string admin,Store store,ManagementClient client,HttpClient http,Action<bool,string> check)
    {
        var directory=Path.Combine(root,"acquisition-contract-replay");var queue=new EvidenceUploadQueue(directory);
        foreach(var completion in completions)queue.Register(events.Single(e=>e.EventId==completion.Forensics!.RelatedEventId),completion);
        var sent=0;for(var i=0;i<6&&sent<completions.Count;i++)sent+=await queue.Pump(client);
        check(sent==38,"all 38 archived native actor copies and manifests reach server through actual upload client");
        check(await new EvidenceUploadQueue(directory).Pump(client)==0,"upload restart retains confirmed receipts without retransmission");
        foreach(var e in completions)
        {
            var f=e.Forensics!;var p=f.Preservation;var receipt=store.EvidenceReceipt(sensor,p.EvidenceId!);
            check(receipt is {State:"received"}&&receipt.Sha256==p.Sha256&&receipt.ManifestSha256==p.ManifestSha256&&receipt.Size==p.Size,"central receipt verifies exact artifact and manifest: "+e.EventId);
            foreach(var kind in new[]{"artifact","manifest"})
            {
                using var request=new HttpRequestMessage(HttpMethod.Get,$"/api/v1/admin/actor-evidence/{sensor}/{p.EvidenceId}/{kind}");request.Headers.Authorization=new("Bearer",admin);
                using var response=await http.SendAsync(request);response.EnsureSuccessStatusCode();var bytes=await response.Content.ReadAsByteArrayAsync();
                check(response.Content.Headers.ContentType?.MediaType=="application/octet-stream"&&response.Content.Headers.ContentDisposition?.DispositionType=="attachment"&&Convert.ToHexString(SHA256.HashData(bytes))==(kind=="artifact"?p.Sha256:p.ManifestSha256),"authorized "+kind+" download matches preserved hash: "+e.EventId);
                if(kind=="manifest")using(var document=JsonDocument.Parse(bytes))check(JsonSerializer.Serialize(document.RootElement.GetProperty("LinuxActorAcquisition").Deserialize<LinuxActorAcquisitionEvidence>())==JsonSerializer.Serialize(f.ActorExecutable.LinuxAcquisition),"server manifest retains full Linux acquisition evidence: "+e.EventId);
            }
            check(File.Exists(Path.Combine(directory,p.ArtifactRelativePath!.Replace('/',Path.DirectorySeparatorChar))),"confirmed central receipt retains local forensic copy: "+e.EventId);
            var transfer=store.Events(0,500).Single(x=>x.Event.EventId==receipt!.ReceiptId).Event;
            check(transfer.Source=="Evidence transfer"&&transfer.Forensics!.IsValid()&&LinuxKernelEvidence.Matches(transfer)&&JsonSerializer.Serialize(transfer.Forensics.ActorExecutable.LinuxAcquisition)==JsonSerializer.Serialize(f.ActorExecutable.LinuxAcquisition),"central possession event retains original native attribution and acquisition: "+e.EventId);
        }
        var source=completions[0];var sourceManifest=File.ReadAllBytes(Path.Combine(directory,source.Forensics!.Preservation.ManifestRelativePath!.Replace('/',Path.DirectorySeparatorChar)));
        var mutations=new (string Name,Action<JsonObject> Change)[]{
            ("missing acquisition",n=>n.Remove("LinuxActorAcquisition")),
            ("different native event",n=>n["LinuxActorAcquisition"]!["NativeStatus"]!["Cookie"]="0"),
            ("different snapshot hash",n=>n["LinuxActorAcquisition"]!["SnapshotSha256"]=new string('0',64)),
            ("different source inode",n=>n["ActorFile"]!["StableId"]="linux-kernel-device:0:inode:0"),
            ("different accessing credentials",n=>n["Process"]!["EventSubject"]!["FileSystemUid"]=9999),
            ("unavailable acquisition status",n=>n["LinuxActorAcquisition"]!["Status"]=null)};
        foreach(var (name,change) in mutations)
        {
            var node=JsonNode.Parse(sourceManifest)!.AsObject();var evidenceId=Guid.NewGuid().ToString("N");node["Preservation"]!["EvidenceId"]=evidenceId;change(node);
            var manifest=JsonSerializer.SerializeToUtf8Bytes(node);var id=Guid.NewGuid().ToString("N");
            var f=source.Forensics!;var altered=source with{EventId=id,Forensics=f with{EventId=id,Preservation=f.Preservation with{EvidenceId=evidenceId,ManifestSha256=Convert.ToHexString(SHA256.HashData(manifest))}}};
            await client.SendEventsAsync(new([altered]));
            try{await client.StartEvidenceUpload(new(id,Convert.ToBase64String(manifest)));throw new Exception("Altered acquisition manifest accepted: "+name);}catch(HttpRequestException ex)when(ex.StatusCode==HttpStatusCode.UnprocessableEntity){check(store.EvidenceReceipt(sensor,evidenceId)==null,"server rejects "+name+" even with matching manifest digest");}
        }
    }
}
