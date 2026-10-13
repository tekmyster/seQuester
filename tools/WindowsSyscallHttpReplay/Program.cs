using System.Diagnostics;
using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Microsoft.Data.Sqlite;
using RansomFree.Client;
using RansomFree.Client.Forensics;
using RansomFree.Contracts;
using RansomFree.Server;

// Replays retained, actual native sensor publications. It never starts an actor,
// driver or production server. Input evidence, sensor IDs and event IDs stay exact.
if(args.Length!=3||!OperatingSystem.IsWindows())throw new ArgumentException("Pass isolated server executable, extracted live-run directory, and new private output directory.");
var executable=Path.GetFullPath(args[0]);var input=Path.GetFullPath(args[1]);var output=Path.GetFullPath(args[2]);
var boundary=Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),"Codex","sequester-windows-syscall-observer-20261011-r1")+Path.DirectorySeparatorChar;
if(!File.Exists(executable)||!input.StartsWith(boundary,StringComparison.OrdinalIgnoreCase)||!output.StartsWith(boundary,StringComparison.OrdinalIgnoreCase)||Path.Exists(output))throw new InvalidOperationException("Only retained input and a new owned output directory are allowed.");
void NoLinks(string path){for(string? p=path;p!=null;p=Path.GetDirectoryName(p))if(Path.Exists(p)&&(File.GetAttributes(p)&FileAttributes.ReparsePoint)!=0)throw new IOException("Linked input/output rejected");}
NoLinks(input);NoLinks(output);Directory.CreateDirectory(output);
var checks=new List<string>();void Check(bool ok,string reason){if(!ok)throw new InvalidDataException(reason);checks.Add(reason);Console.WriteLine("PASS: "+reason);}
var databases=Directory.GetFiles(Path.Combine(input,"sensor"),"events-*.db");Check(databases.Length==1,"exactly one retained event spool");
var sourceDigests=new Dictionary<string,string>(StringComparer.Ordinal);
void RecordSource(string path){NoLinks(path);sourceDigests.TryAdd(path,Convert.ToHexString(SHA256.HashData(File.ReadAllBytes(path))));}
RecordSource(databases[0]);if(File.Exists(databases[0]+"-wal"))RecordSource(databases[0]+"-wal");
var rows=new List<AgentEvent>();var raw=new Dictionary<string,byte[]>(StringComparer.Ordinal);
using(var db=new SqliteConnection(new SqliteConnectionStringBuilder{DataSource=databases[0],Mode=SqliteOpenMode.ReadOnly,Pooling=false}.ToString())){
    db.Open();using var command=db.CreateCommand();command.CommandText="SELECT payload FROM queue ORDER BY sequence";using var reader=command.ExecuteReader();
    while(reader.Read()){var bytes=(byte[])reader[0];var value=JsonSerializer.Deserialize<AgentEvent>(bytes)??throw new InvalidDataException("Empty retained event");Check(bytes.AsSpan().SequenceEqual(JsonSerializer.SerializeToUtf8Bytes(value)),"retained publication round-trips byte exactly: "+value.EventId);rows.Add(value);raw.Add(value.EventId,bytes);}
}
var originals=rows.Where(e=>e.Source=="Windows syscall").OrderBy(e=>e.Attribution!.WindowsSyscall!.Native.Sequence).ToArray();
Check(originals.Length is >0 and <=9&&rows.Count==originals.Length*2,"retained spool has complete original/completion pairs");
var sensor=originals[0].Forensics!.SensorId;Check(Guid.TryParseExact(sensor,"N",out _)&&rows.All(e=>e.Forensics?.SensorId==sensor),"original sensor identity is unchanged");
foreach(var original in originals){Check(WindowsSyscallObservation.Matches(original)&&original.Forensics!.IsValid(),"actual native observation and forensic linkage validate: "+original.EventId);Check(original.Forensics!.ActorExecutable.Acquisition is {Version:2,Status.State:"captured"},"actual process snapshot was acquired: "+original.EventId);}
var serverRoot=Path.Combine(output,"server");var store=new Store(serverRoot);var credential=Store.Secret();var admin=Store.Secret();
// Seed a NEW isolated endpoint with its original ID. No old credential is read
// or changed; this fixture setup avoids rewriting real forensic sensor identity.
using(var db=new SqliteConnection(new SqliteConnectionStringBuilder{DataSource=Path.Combine(serverRoot,"management.db"),Pooling=false}.ToString())){
    db.Open();using var cmd=db.CreateCommand();cmd.CommandText="INSERT INTO endpoints(id,credential_hash,machine,version,health,last_seen) VALUES($id,$hash,'retained-native-http-replay','private-fixture','Enrolled',$now)";
    cmd.Parameters.AddWithValue("$id",sensor);cmd.Parameters.AddWithValue("$hash",Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(credential))));cmd.Parameters.AddWithValue("$now",DateTimeOffset.UtcNow.ToUnixTimeSeconds());Check(cmd.ExecuteNonQuery()==1,"new isolated endpoint seeded with original sensor ID");
}
Check(store.Authenticate(credential)==sensor,"fresh isolated sensor credential authenticates");
var local=Path.Combine(output,"sensor");Directory.CreateDirectory(Path.Combine(local,"evidence","actors"));var queue=new EvidenceUploadQueue(local);
foreach(var original in originals){
    var completion=rows.Single(e=>e.Source=="Forensic enrichment"&&e.Forensics?.RelatedEventId==original.EventId);var p=completion.Forensics!.Preservation;
    Check(p is {Status.State:"captured",HashMatched:true}&&p.ArtifactRelativePath!=null&&p.ManifestRelativePath!=null,"preservation has a verified artifact and manifest: "+original.EventId);
    foreach(var relative in new[]{p.ArtifactRelativePath!,p.ManifestRelativePath!}){
        var source=Path.GetFullPath(Path.Combine(input,"sensor",relative));var target=Path.GetFullPath(Path.Combine(local,relative));
        if(!source.StartsWith(Path.Combine(input,"sensor")+Path.DirectorySeparatorChar,StringComparison.OrdinalIgnoreCase)||!target.StartsWith(local+Path.DirectorySeparatorChar,StringComparison.OrdinalIgnoreCase))throw new IOException("Evidence path escapes");
        NoLinks(source);NoLinks(target);Directory.CreateDirectory(Path.GetDirectoryName(target)!);if(!File.Exists(target))File.Copy(source,target,false);
        RecordSource(source);
        Check(SHA256.HashData(File.ReadAllBytes(source)).AsSpan().SequenceEqual(SHA256.HashData(File.ReadAllBytes(target))),"retained artifact/manifest copied without alteration: "+relative);
    }
    Check(Convert.ToHexString(SHA256.HashData(File.ReadAllBytes(Path.Combine(local,p.ArtifactRelativePath!))))==p.Sha256,"actor bytes match event hash: "+original.EventId);
    queue.Register(original,completion);
}
var listener=new TcpListener(IPAddress.Loopback,0);listener.Start();var port=((IPEndPoint)listener.LocalEndpoint).Port;listener.Stop();
var dll=executable.EndsWith(".dll",StringComparison.OrdinalIgnoreCase);var start=new ProcessStartInfo(dll?@"C:\Program Files\dotnet\dotnet.exe":executable){UseShellExecute=false,CreateNoWindow=true,WindowStyle=ProcessWindowStyle.Hidden,RedirectStandardOutput=true,RedirectStandardError=true};if(dll)start.ArgumentList.Add(executable);
foreach(var key in start.Environment.Keys.Where(k=>k.StartsWith("RF_")||k.StartsWith("ASPNETCORE_")||k.StartsWith("Forensics__")).ToArray())start.Environment.Remove(key);
start.Environment["RF_DATA_DIR"]=serverRoot;start.Environment["RF_ADMIN_KEY"]=admin;start.Environment["RF_ALLOW_LOOPBACK_HTTP"]="true";start.Environment["ASPNETCORE_URLS"]=$"http://127.0.0.1:{port}";start.Environment["ASPNETCORE_ENVIRONMENT"]="Development";start.Environment["DOTNET_ENVIRONMENT"]="Development";start.Environment["Database__Provider"]="Sqlite";start.Environment["Logging__LogLevel__Default"]="Warning";
using var process=Process.Start(start)!;var stdout=process.StandardOutput.ReadToEndAsync();var stderr=process.StandardError.ReadToEndAsync();
using var http=new HttpClient{BaseAddress=new Uri($"http://127.0.0.1:{port}"),Timeout=TimeSpan.FromSeconds(45)};
try{
    var ready=false;for(var n=0;n<300;n++){if(process.HasExited)throw new IOException("Owned server exited before readiness");try{ready=(await http.GetAsync("/health/live")).IsSuccessStatusCode;if(ready)break;}catch(HttpRequestException){}await Task.Delay(100);}Check(ready,"isolated packaged HTTP server is ready");
    using(var denied=await http.PostAsync("/api/v1/agent/evidence/start",new StringContent("{}",Encoding.UTF8,"application/json")))Check(denied.StatusCode==HttpStatusCode.Unauthorized,"anonymous evidence request rejected");
    var baseline=originals[0];var syscall=baseline.Attribution!.WindowsSyscall!;
    foreach(var changed in new[]{baseline with{ProcessId=baseline.ProcessId!.Value+1},baseline with{Attribution=baseline.Attribution with{WindowsSyscall=syscall with{Native=syscall.Native with{RawRecordSha256=new string('0',64)}}}}}){
        using var request=new HttpRequestMessage(HttpMethod.Post,"/api/v1/agent/events"){Content=JsonContent.Create(new EventBatch([changed]))};request.Headers.Authorization=new AuthenticationHeaderValue("Bearer",credential);
        using var rejected=await http.SendAsync(request);Check(rejected.StatusCode==HttpStatusCode.BadRequest,"server rejects contradictory native process/digest linkage");
    }
    using var client=new ManagementClient(new HttpClient{BaseAddress=http.BaseAddress,Timeout=TimeSpan.FromSeconds(45)},credential);
    var transferred=0;for(var attempt=0;attempt<10&&transferred<originals.Length;attempt++)transferred+=await queue.Pump(client);
    Check(transferred==originals.Length,"all retained actor artifacts received through authenticated HTTP");
    foreach(var e in rows){var saved=store.EvidenceSource(sensor,e.EventId);Check(saved!=null&&raw[e.EventId].AsSpan().SequenceEqual(JsonSerializer.SerializeToUtf8Bytes(saved)),"server event matches exact original sensor publication: "+e.EventId);}
    foreach(var original in originals){
        var completion=rows.Single(e=>e.Forensics?.RelatedEventId==original.EventId&&e.Source=="Forensic enrichment");var p=completion.Forensics!.Preservation;
        using var request=new HttpRequestMessage(HttpMethod.Get,$"/api/v1/admin/actor-evidence/{sensor}/{p.EvidenceId}/artifact");request.Headers.Authorization=new AuthenticationHeaderValue("Bearer",admin);
        using var response=await http.SendAsync(request);var bytes=await response.Content.ReadAsByteArrayAsync();Check(response.IsSuccessStatusCode&&response.Content.Headers.ContentDisposition?.DispositionType=="attachment"&&Convert.ToHexString(SHA256.HashData(bytes))==p.Sha256,"fresh authorized server download matches actor SHA-256: "+p.EvidenceId);
    }
    Check(await new EvidenceUploadQueue(local).Pump(client)==0,"restart honors verified receipts without repeating transfers");
    foreach(var source in sourceDigests)Check(Convert.ToHexString(SHA256.HashData(File.ReadAllBytes(source.Key)))==source.Value,"retained source bytes unchanged after replay: "+Path.GetRelativePath(input,source.Key));
    File.WriteAllText(Path.Combine(output,"acceptance.json"),JsonSerializer.Serialize(new{Passed=true,Checks=checks,NativePairs=originals.Length,HttpReplayQualified=true,LiveHttpDeliveryQualified=false,ProductionDeployed=false,OriginalSensorId=sensor,OriginalInput=input,SourceSha256=sourceDigests.ToDictionary(x=>Path.GetRelativePath(input,x.Key),x=>x.Value),Scope="authenticated HTTP replay of unchanged retained native events and actor artifacts"},new JsonSerializerOptions{WriteIndented=true}));
}catch(Exception ex){File.WriteAllText(Path.Combine(output,"failure.json"),JsonSerializer.Serialize(new{Passed=false,Error=ex.ToString(),Checks=checks}));throw;}
finally{
    // Only the owned loopback server is stopped; no endpoint actor or driver is involved.
    if(!process.HasExited)process.Kill(true);await process.WaitForExitAsync();File.WriteAllText(Path.Combine(output,"server.stdout.txt"),await stdout);File.WriteAllText(Path.Combine(output,"server.stderr.txt"),await stderr);
}
