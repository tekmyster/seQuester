using System.Diagnostics;
using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using RansomFree.Server;
if(args.Length!=2)throw new ArgumentException("dotnet executable and isolated published server DLL required");
var root=Path.Combine("D:\\Codex\\RansomFree\\W-SQ02","server-"+Guid.NewGuid().ToString("N"));Directory.CreateDirectory(root);
var results=new List<string>();void Check(bool value,string label){if(!value)throw new Exception(label);results.Add("PASS: "+label);Console.WriteLine(results[^1]);File.WriteAllLines(Path.Combine(root,"results.txt"),results);}
int Port(){using var listener=new TcpListener(IPAddress.Loopback,0);listener.Start();return ((IPEndPoint)listener.LocalEndpoint).Port;}
var httpPort=Port();var tlsPort=Port();while(tlsPort==httpPort)tlsPort=Port();
using var rsa=RSA.Create(2048);var certRequest=new CertificateRequest("CN=localhost",rsa,HashAlgorithmName.SHA256,RSASignaturePadding.Pkcs1);var names=new SubjectAlternativeNameBuilder();names.AddIpAddress(IPAddress.Loopback);certRequest.CertificateExtensions.Add(names.Build());using var certificate=certRequest.CreateSelfSigned(DateTimeOffset.UtcNow.AddMinutes(-1),DateTimeOffset.UtcNow.AddMinutes(20));
var certPath=Path.Combine(root,"fixture.pfx");var certPassword=Store.Secret();File.WriteAllBytes(certPath,certificate.Export(X509ContentType.Pfx,certPassword));
var data=Path.Combine(root,"data");var store=new Store(data);store.InitializeDecoyServiceStorage();var definition=new DecoyServiceChange("N05 HTTPS fixture","Synthetic records only",false,0,"unused"){RequestId=Guid.NewGuid().ToString("N"),Location="Loopback",Note="Immutable context"};var service=store.CreateDecoyService(definition,"fixture");var active=store.ChangeDecoyService(service.Service.Id,definition with{ExpectedRevision=1,Enabled=true},"fixture");
using var handler=new HttpClientHandler{ServerCertificateCustomValidationCallback=(_,cert,_,_)=>cert!=null&&cert.GetCertHashString(HashAlgorithmName.SHA256)==certificate.GetCertHashString(HashAlgorithmName.SHA256)};
using var https=new HttpClient(handler){BaseAddress=new Uri($"https://127.0.0.1:{tlsPort}"),Timeout=TimeSpan.FromSeconds(5)};
using var http=new HttpClient(){BaseAddress=new Uri($"http://127.0.0.1:{httpPort}"),Timeout=TimeSpan.FromSeconds(5)};
Process? server=null;var adminKey=Store.Secret();
async Task Start(){var start=new ProcessStartInfo(Path.GetFullPath(args[0])){UseShellExecute=false,CreateNoWindow=true,WindowStyle=ProcessWindowStyle.Hidden,RedirectStandardOutput=true,RedirectStandardError=true};start.ArgumentList.Add(Path.GetFullPath(args[1]));start.Environment["RF_DATA_DIR"]=data;start.Environment["RF_ADMIN_KEY"]=adminKey;start.Environment["ASPNETCORE_ENVIRONMENT"]="Development";start.Environment["RF_ALLOW_LOOPBACK_HTTP"]="false";start.Environment["ASPNETCORE_URLS"]=$"http://127.0.0.1:{httpPort};https://127.0.0.1:{tlsPort}";start.Environment["Kestrel__Certificates__Default__Path"]=certPath;start.Environment["Kestrel__Certificates__Default__Password"]=certPassword;start.Environment["Logging__LogLevel__Default"]="Warning";server=Process.Start(start)!;server.OutputDataReceived+=(_,e)=>{if(e.Data!=null)File.AppendAllText(Path.Combine(root,"server.log"),e.Data+Environment.NewLine);};server.ErrorDataReceived+=(_,e)=>{if(e.Data!=null)File.AppendAllText(Path.Combine(root,"server-error.log"),e.Data+Environment.NewLine);};server.BeginOutputReadLine();server.BeginErrorReadLine();for(var i=0;i<100;i++){if(server.HasExited)throw new Exception("Isolated server exited");try{using var response=await https.GetAsync("/health/live");if(response.IsSuccessStatusCode)return;}catch(HttpRequestException){}await Task.Delay(100);}throw new TimeoutException("Isolated server readiness");}
void Stop(){if(server==null)return;if(!server.HasExited){server.Kill();server.WaitForExit(10000);}server.Dispose();server=null;}
try{
 await Start();
 using(var untrusted=new HttpClient()){var denied=false;try{await untrusted.GetAsync(new Uri(https.BaseAddress!,service.ActivationPath));}catch(HttpRequestException){denied=true;}Check(denied&&store.LatestServiceSequence()==0,"default HTTPS client rejects fixture certificate without creating evidence");}
 using(var response=await http.GetAsync(service.ActivationPath))Check(response.StatusCode==HttpStatusCode.BadRequest&&store.LatestServiceSequence()==0,"plaintext service activation is rejected without evidence");
 using(var response=await https.GetAsync(service.ActivationPath+"bad"))Check(response.StatusCode==HttpStatusCode.NotFound&&store.LatestServiceSequence()==0,"invalid activation secret cannot create service evidence");
 foreach(var method in new[]{HttpMethod.Post,HttpMethod.Head}){using var request=new HttpRequestMessage(method,service.ActivationPath);using var response=await https.SendAsync(request);Check(response.StatusCode==HttpStatusCode.MethodNotAllowed&&store.LatestServiceSequence()==0,"unsupported "+method+" cannot record a service hit");}
 using(var response=await https.GetAsync("/api/v1/console/decoy-services"))Check(response.StatusCode==HttpStatusCode.Unauthorized,"anonymous HTTPS client cannot read management inventory");
 using(var response=await https.GetAsync(service.ActivationPath))Check(response.IsSuccessStatusCode&&response.Headers.CacheControl?.NoStore==true&&store.LatestServiceSequence()==1,"HTTPS service response follows durable evidence commit and prohibits caching");
 var evidence=store.ServiceEvents(0).Single();Check(evidence.Event.ServiceContext is {Location:"Loopback",Note:"Immutable context",SourceAddress:"127.0.0.1"}&&store.DecoyServiceHits(service.Service.Id).Count==1,"HTTPS hit contains saved service context and observed loopback address");
 Stop();await Start();Check(new Store(data).ServiceEvents(0).Single().Event.EventId==evidence.Event.EventId,"server process restart preserves exact service evidence identity");
 var disabled=store.ChangeDecoyService(service.Service.Id,definition with{ExpectedRevision=active.Revision},"fixture");
 using(var response=await https.GetAsync(service.ActivationPath))Check(response.StatusCode==HttpStatusCode.NotFound&&store.LatestServiceSequence()==1,"disabled HTTPS resource preserves evidence and emits no successful response");
 Console.WriteLine(root);Console.WriteLine("Isolated loopback server only; test-client certificate pin does not alter system trust.");
}finally{Stop();}
