using System.Diagnostics;
using System.IO.Compression;
using System.Net;
using System.Net.Http.Json;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Json;
using System.Xml.Linq;
using Microsoft.AspNetCore.Antiforgery;
using RansomFree.Callbacks;
using RansomFree.Server;

if(args.Length!=2)throw new ArgumentException("Usage: dotnet-executable receiver-dll; run from workspace root.");
var resultsBase=Environment.GetEnvironmentVariable("RF_QA_RESULTS")??(Directory.Exists("D:\\")?"D:\\Codex\\RansomFree\\test-results":Path.GetFullPath("test-results"));
var root=Path.GetFullPath(Path.Combine(resultsBase,"canaries",Guid.NewGuid().ToString("N")));
Directory.CreateDirectory(root);
var results=new List<string>();var failures=0;
void Check(bool ok,string label){var line=(ok?"PASS ":"FAIL ")+label;results.Add(line);Console.WriteLine(line);if(!ok)failures++;}
int Port(){var l=new TcpListener(IPAddress.Loopback,0);l.Start();var p=((IPEndPoint)l.LocalEndpoint).Port;l.Stop();return p;}
var webPort=Port();var dnsPort=Port();var smtpPort=Port();var managementPort=Port();
var callbackRoot=Path.Combine(root,"callbacks");
var config=new Dictionary<string,string?>{{"Callbacks:Enabled","true"},{"Callbacks:Origin","https://receiver.invalid/"},{"Callbacks:DnsZone","tokens.invalid"},{"Callbacks:MailDomain","mail.invalid"},{"RF_CALLBACK_DATA",callbackRoot}};
var builder=WebApplication.CreateBuilder(new WebApplicationOptions{EnvironmentName="Development",Args=[]});
builder.Configuration.Sources.Clear();builder.Configuration.AddInMemoryCollection(config);
builder.Logging.ClearProviders();builder.WebHost.UseUrls($"http://127.0.0.1:{managementPort}");
builder.Services.AddAntiforgery(o=>o.HeaderName="X-QA-CSRF");builder.Services.AddAuthorization();
builder.Services.AddSingleton<CallbackConfiguration>();builder.Services.AddSingleton(new Store(Path.Combine(root,"management")));
var statusType=typeof(Store).Assembly.GetType("RansomFree.Server.CallbackDeliveryStatus")!;
builder.Services.AddSingleton(statusType,Activator.CreateInstance(statusType)!);
var app=builder.Build();
// Test-only synthetic administrator, isolated loopback host; does not test production authentication.
app.Use(async(c,next)=>{c.User=new ClaimsPrincipal(new ClaimsIdentity([new Claim(ClaimTypes.NameIdentifier,"canary-qa"),new Claim(ClaimTypes.Role,"Administrator")],"QA"));await next(c);});
app.UseAuthorization();app.MapGet("/qa/csrf",(HttpContext c,IAntiforgery csrf)=>csrf.GetAndStoreTokens(c).RequestToken!);app.MapCallbacks();
Process? receiver=null;var output=new System.Collections.Concurrent.ConcurrentQueue<string>();
using var handler=new HttpClientHandler{AllowAutoRedirect=false};
using var management=new HttpClient(handler){BaseAddress=new Uri($"http://127.0.0.1:{managementPort}"),Timeout=TimeSpan.FromSeconds(15)};
using var http=new HttpClient(new HttpClientHandler{AllowAutoRedirect=false}){BaseAddress=new Uri($"http://127.0.0.1:{webPort}"),Timeout=TimeSpan.FromSeconds(15)};
using var rsa=RSA.Create(2048);var certificateRequest=new CertificateRequest("CN=localhost",rsa,HashAlgorithmName.SHA256,RSASignaturePadding.Pkcs1);
using var certificate=certificateRequest.CreateSelfSigned(DateTimeOffset.UtcNow.AddMinutes(-5),DateTimeOffset.UtcNow.AddHours(1));
var certPath=Path.Combine(root,"smtp-lab.pfx");File.WriteAllBytes(certPath,certificate.Export(X509ContentType.Pfx));
var tokens=new Dictionary<string,CallbackToken>();
async Task<HttpResponseMessage> Manage(string path,object? body=null){return await management.PostAsync("/api/v1/console/callbacks/"+path,body==null?null:JsonContent.Create(body));}
async Task<HttpResponseMessage> Request(string method,string path,string? auth=null,string? body=null,string? header=null,string? value=null)
{using var request=new HttpRequestMessage(new HttpMethod(method),path);if(auth!=null)request.Headers.TryAddWithoutValidation("Authorization",auth);if(body!=null)request.Content=new StringContent(body,Encoding.UTF8,"application/json");if(header!=null)request.Headers.TryAddWithoutValidation(header,value);return await http.SendAsync(request);}
byte[] Query(string host){using var m=new MemoryStream();m.Write([0x12,0x34,1,0,0,1,0,0,0,0,0,0]);foreach(var label in host.Split('.')){m.WriteByte((byte)label.Length);m.Write(Encoding.ASCII.GetBytes(label));}m.Write([0,0,1,0,1]);return m.ToArray();}
async Task<byte[]> Dns(string host,bool tcp=false)
{using var timeout=new CancellationTokenSource(TimeSpan.FromSeconds(4));var query=Query(host);if(!tcp){using var udp=new UdpClient();await udp.SendAsync(query,new IPEndPoint(IPAddress.Loopback,dnsPort),timeout.Token);return (await udp.ReceiveAsync(timeout.Token)).Buffer;}using var client=new TcpClient();await client.ConnectAsync(IPAddress.Loopback,dnsPort,timeout.Token);var stream=client.GetStream();await stream.WriteAsync(new byte[]{(byte)(query.Length>>8),(byte)query.Length},timeout.Token);await stream.WriteAsync(query,timeout.Token);var length=new byte[2];await stream.ReadExactlyAsync(length,timeout.Token);var response=new byte[(length[0]<<8)|length[1]];await stream.ReadExactlyAsync(response,timeout.Token);return response;}
try
{
    await app.StartAsync();management.DefaultRequestHeaders.Add("X-QA-CSRF",await management.GetStringAsync("/qa/csrf"));
    var store=app.Services.GetRequiredService<CallbackConfiguration>().Storage!;
    foreach(var mechanism in CallbackManagement.Catalog.Where(m=>m.State.StartsWith("Implemented")))
    {
        var type=mechanism.Id;var destination=type is "fast-redirect" or "slow-redirect" or "js-clone" or "css-clone"?"https://approved.invalid/":null;
        using var created=await Manage("tokens",new CreateCallbackBody("QA-"+type,type,destination));
        Check(created.IsSuccessStatusCode,type+": management create");if(!created.IsSuccessStatusCode)continue;
        var token=(await created.Content.ReadFromJsonAsync<CallbackToken>())!;tokens.Add(type,token);
        using var download=await Manage("tokens/"+token.Id+"/download");var bytes=await download.Content.ReadAsByteArrayAsync();
        Check(download.IsSuccessStatusCode&&bytes.Length>0,type+": artifact download");
        File.WriteAllBytes(Path.Combine(root,type+".artifact"),bytes);
        var text=Encoding.UTF8.GetString(bytes);bool valid;
        if(type is "docx" or "xlsx" or "windows-folder")
        {
            using var zip=new ZipArchive(new MemoryStream(bytes));
            Check(zip.Entries.All(e=>!e.FullName.StartsWith('/')&&!e.FullName.Split('/').Contains("..")),type+": safe archive paths");
            if(type=="windows-folder"){using var reader=new StreamReader(zip.GetEntry("CanaryFolder/desktop.ini")!.Open(),Encoding.Unicode);valid=reader.ReadToEnd().Contains(token.Id+".tokens.invalid");}
            else {
                var relationshipParts=type=="docx"?zip.Entries.Where(e=>e.FullName=="word/_rels/document.xml.rels"):
                    zip.Entries.Where(e=>e.FullName.StartsWith("xl/drawings/_rels/",StringComparison.Ordinal)&&e.FullName.EndsWith(".rels",StringComparison.Ordinal));
                valid=relationshipParts.Any(entry=>{using var stream=entry.Open();return XDocument.Load(stream).Descendants().Any(e=>(string?)e.Attribute("TargetMode")=="External"&&((string?)e.Attribute("Target"))?.Contains(token.Id)==true);});
                foreach(var entry in zip.Entries.Where(e=>e.FullName.EndsWith(".xml"))){using var content=entry.Open();XDocument.Load(content);}
            }
        }
        else if(type=="qr")valid=bytes.Take(8).SequenceEqual(new byte[]{137,80,78,71,13,10,26,10});
        else if(type=="mysql"){var hex=System.Text.RegularExpressions.Regex.Match(text,@"0x([0-9A-F]+)").Groups[1].Value;valid=Encoding.UTF8.GetString(Convert.FromHexString(hex)).Contains(token.Id+".tokens.invalid");}
        else {valid=text.Contains(token.Id);if(type is "mcp" or "kubeconfig")using(JsonDocument.Parse(bytes)){}if(type=="svg")XDocument.Parse(text);if(type=="pdf")valid&=text.StartsWith("%PDF-")&&text.Contains("/AA << /O")&&text.Contains("/S /URI");}
        Check(valid,type+": artifact structure/token binding (not reader activation)");
        Check(new CallbackStorage(callbackRoot).Get(token.Id)==token,type+": registry persists after reopen");
    }
    Check(tokens.Count==19,"all 19 implemented mechanisms exercised");
    using(var invalid=await Manage("tokens",new CreateCallbackBody("bad","not-a-type")))Check(invalid.StatusCode==HttpStatusCode.BadRequest,"unknown mechanism rejected");
    using(var invalid=await Manage("tokens",new CreateCallbackBody("bad","fast-redirect","http://approved.invalid/")))Check(invalid.StatusCode==HttpStatusCode.BadRequest,"insecure redirect destination rejected");
    using(var invalid=await Manage("tokens",new CreateCallbackBody("../escape","docx")))Check(invalid.StatusCode==HttpStatusCode.BadRequest,"unsafe document filename rejected");
    management.DefaultRequestHeaders.Remove("X-QA-CSRF");using(var invalid=await Manage("tokens",new CreateCallbackBody("csrf","dns")))Check(invalid.StatusCode==HttpStatusCode.BadRequest,"CSRF required for creation");management.DefaultRequestHeaders.Add("X-QA-CSRF",await management.GetStringAsync("/qa/csrf"));
    var start=new ProcessStartInfo(Path.GetFullPath(args[0])){UseShellExecute=false,CreateNoWindow=true,WindowStyle=ProcessWindowStyle.Hidden,RedirectStandardOutput=true,RedirectStandardError=true};start.ArgumentList.Add(Path.GetFullPath(args[1]));
    // Remove inherited product configuration: the child must never connect to live infrastructure.
    foreach(var key in start.Environment.Keys.Where(k=>k.StartsWith("RF_",StringComparison.OrdinalIgnoreCase)||new[]{"Database","Callbacks","Smtp","Dns","Kestrel","ASPNETCORE","DOTNET"}.Any(p=>k.StartsWith(p+"__",StringComparison.OrdinalIgnoreCase)||k.StartsWith(p+"_",StringComparison.OrdinalIgnoreCase))).ToArray())start.Environment.Remove(key);
    start.WorkingDirectory=root;
    foreach(var pair in new Dictionary<string,string>{{"ASPNETCORE_ENVIRONMENT","Development"},{"ASPNETCORE_URLS",http.BaseAddress!.ToString()},{"RF_ALLOW_LOOPBACK_HTTP","true"},{"RF_CALLBACK_DATA",callbackRoot},{"Database__Provider","Sqlite"},{"Dns__Enabled","true"},{"Dns__BindAddress","127.0.0.1"},{"Dns__Port",dnsPort.ToString()},{"Dns__Zone","tokens.invalid"},{"Smtp__Enabled","true"},{"Smtp__BindAddress","127.0.0.1"},{"Smtp__Port",smtpPort.ToString()},{"Smtp__Domain","mail.invalid"},{"Smtp__CertificatePath",certPath}})start.Environment[pair.Key]=pair.Value;
    start.Environment["Logging__LogLevel__EmailTripwire"]="Debug";
    receiver=Process.Start(start)!;receiver.OutputDataReceived+=(_,e)=>{if(e.Data!=null)output.Enqueue(e.Data);};receiver.ErrorDataReceived+=(_,e)=>{if(e.Data!=null)output.Enqueue(e.Data);};receiver.BeginOutputReadLine();receiver.BeginErrorReadLine();
    var ready=false;for(var n=0;n<100;n++){if(receiver.HasExited)throw new Exception("Receiver exited: "+string.Join('\n',output));try{using var response=await http.GetAsync("/health/live");if(response.IsSuccessStatusCode){ready=true;break;}}catch(HttpRequestException){}await Task.Delay(100);}Check(ready,"receiver starts with loopback HTTP/DNS/SMTP");if(!ready)throw new Exception("Receiver startup timeout");
    foreach(var type in new[]{"docx","xlsx","pdf","svg","web-image","web-bug","qr","js-clone","css-clone"})
    {
        var id=tokens[type].Id;
        if(type=="css-clone"){using var approved=await Request("GET","/t/"+id+"/pixel.png",header:"Referer",value:"https://approved.invalid/page");Check(!store.Hits(0,500).Any(h=>h.TokenId==id),"css-clone: approved referrer suppressed");}
        using var response=await http.GetAsync("/t/"+id+"/pixel.png");Check(response.IsSuccessStatusCode&&response.Content.Headers.ContentType?.MediaType=="image/png",type+": loopback image callback");
    }
    foreach(var type in new[]{"fast-redirect","slow-redirect"}){var watch=Stopwatch.StartNew();using var response=await http.GetAsync("/t/"+tokens[type].Id+"/open");Check(response.StatusCode==HttpStatusCode.Redirect&&response.Headers.Location?.AbsoluteUri=="https://approved.invalid/",type+": redirect returned, destination not followed");if(type=="slow-redirect")Check(watch.Elapsed>=TimeSpan.FromSeconds(1.9),"slow-redirect: two-second delay");}
    foreach(var type in new[]{"dns","windows-folder","mysql","log4shell"}){var host=tokens[type].Id+".tokens.invalid";Check(((await Dns(host))[3]&15)==3,type+": UDP DNS callback/NXDOMAIN");Check(((await Dns(host,true))[3]&15)==3,type+": TCP DNS callback/NXDOMAIN");}
    Check(((await Dns("outside.invalid"))[3]&15)==5,"DNS refuses unrelated zone");
    var mcp="/t/"+tokens["mcp"].Id+"/mcp";
    using(var response=await Request("POST",mcp,body:"{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"initialize\",\"params\":{}}")){var body=await response.Content.ReadAsStringAsync();Check(response.IsSuccessStatusCode&&body.Contains("protocolVersion"),"mcp: initialize response");}
    using(var response=await Request("POST",mcp,body:"{\"jsonrpc\":\"2.0\",\"id\":2,\"method\":\"tools/list\"}"))Check((await response.Content.ReadAsStringAsync()).Contains("\"tools\":[]"),"mcp: empty tools");
    using(var response=await Request("POST",mcp,body:"{}",header:"Origin",value:"https://untrusted.invalid"))Check(response.StatusCode==HttpStatusCode.Forbidden,"mcp: browser origin rejected");
    using(var response=await Request("POST",mcp,body:"{"))Check(response.StatusCode==HttpStatusCode.BadRequest,"mcp: malformed JSON rejected");
    var kube="/kubernetes/"+tokens["kubeconfig"].Id+"/api";
    using(var response=await Request("GET",kube))Check(response.StatusCode==HttpStatusCode.Unauthorized,"kubeconfig: missing credential rejected");
    using(var response=await Request("GET",kube,"Bearer rf_canary_"+tokens["kubeconfig"].Id))Check(response.StatusCode==HttpStatusCode.Forbidden,"kubeconfig: decoy credential recorded but access denied");
    var dav="/dav/"+tokens["network-folder"].Id+"/";var basic="Basic "+Convert.ToBase64String(Encoding.UTF8.GetBytes("archive:rf_canary_"+tokens["network-folder"].Id));
    using(var response=await Request("GET",dav+"inventory.txt"))Check(response.StatusCode==HttpStatusCode.Unauthorized,"network-folder: authentication required");
    using(var response=await Request("PROPFIND",dav,basic,header:"Depth",value:"1")){var xml=XDocument.Parse(await response.Content.ReadAsStringAsync());Check((int)response.StatusCode==207&&xml.Descendants(XName.Get("response","DAV:")).Count()==2,"network-folder: depth-one listing");}
    using(var response=await Request("GET",dav+"inventory.txt",basic))Check(response.IsSuccessStatusCode&&(await response.Content.ReadAsStringAsync()).Contains("Operations archive"),"network-folder: synthetic read");
    using(var response=await Request("PUT",dav+"inventory.txt",basic,"do not persist"))Check(response.StatusCode==HttpStatusCode.MethodNotAllowed,"network-folder: write rejected");
    using(var response=await Request("PROPFIND",dav,basic,header:"Depth",value:"infinity"))Check(response.StatusCode==HttpStatusCode.Forbidden,"network-folder: infinite depth rejected");
    // SMTP uses exact ephemeral-certificate pinning; no trust-store or TLS policy changes.
    using(var client=new TcpClient())
    {
        using var timeout=new CancellationTokenSource(TimeSpan.FromSeconds(15));await client.ConnectAsync(IPAddress.Loopback,smtpPort,timeout.Token);Stream stream=client.GetStream();
        async Task<string> Line(){var bytes=new List<byte>();var one=new byte[1];while(await stream.ReadAsync(one,timeout.Token)>0){bytes.Add(one[0]);if(one[0]==10)return Encoding.ASCII.GetString(bytes.ToArray()).TrimEnd();}throw new IOException("SMTP closed");}
        async Task<string> Reply(){string line;do{line=await Line();}while(line.Length>3&&line[3]=='-');return line;}
        async Task<string> Command(string command){await stream.WriteAsync(Encoding.ASCII.GetBytes(command+"\r\n"),timeout.Token);return await Reply();}
        Check((await Reply()).StartsWith("220"),"email: SMTP greeting");await Command("EHLO localhost");Check((await Command("MAIL FROM:<synthetic@example.invalid>")).StartsWith("530"),"email: plaintext mail prohibited");Check((await Command("STARTTLS")).StartsWith("220"),"email: STARTTLS offered");
        using var tls=new SslStream(stream,false,(_,remote,_,_)=>remote!=null&&remote.GetRawCertData().SequenceEqual(certificate.RawData));await tls.AuthenticateAsClientAsync(new SslClientAuthenticationOptions{TargetHost="localhost"},timeout.Token);stream=tls;
        await Command("EHLO localhost");await Command("MAIL FROM:<synthetic@example.invalid>");Check((await Command("RCPT TO:<unknown@outside.invalid>")).StartsWith("550"),"email: relay rejected");
        Check((await Command("RCPT TO:<"+tokens["email"].Id+"@mail.invalid>")).StartsWith("250"),"email: known recipient accepted");Check((await Command("DATA")).StartsWith("354"),"email: DATA ready");Check((await Command("Subject: QA\r\n\r\nPRIVATE_QA_BODY_MUST_NOT_PERSIST\r\n.")).StartsWith("250"),"email: TLS receipt recorded");await Command("QUIT");
    }
    foreach(var (type,token) in tokens)
    {
        var hits=new CallbackStorage(callbackRoot).Hits(0,500).Where(h=>h.TokenId==token.Id).ToArray();Check(hits.Length==1,type+": callback persisted after reopen");
        if(hits.Length==1){Check(store.Record(token.Id,hits[0].Transport,hits[0].SourceAddress,"duplicate probe")&&store.Hits(0,500).Count(h=>h.TokenId==token.Id)==1,type+": duplicate callback coalesced");}
        using var revoked=await Manage("tokens/"+token.Id+"/revoke");Check(revoked.StatusCode==HttpStatusCode.NoContent,type+": revoke route");
        using var denied=await Manage("tokens/"+token.Id+"/download");Check(denied.StatusCode==HttpStatusCode.NotFound,type+": revoked artifact unavailable");
        Check(!store.Record(token.Id,"HTTPS","127.0.0.2","revoked probe"),type+": revoked token cannot record");
        using(var pixel=await http.GetAsync("/t/"+token.Id+"/pixel.png"))Check(store.Hits(0,500).Count(h=>h.TokenId==token.Id)==1,type+": revoked HTTP callback adds no evidence");
        Check(new CallbackStorage(callbackRoot).Get(token.Id)?.Revoked==true,type+": revocation persists");
    }
    Check(!store.Hits(0,500).Any(h=>h.Detail.Contains("PRIVATE_QA_BODY")||h.Detail.Contains("rf_canary_")),"callback evidence excludes body/decoy credentials");
    using(var response=await http.GetAsync("/api/v1/console/callbacks/tokens"))Check(response.StatusCode==HttpStatusCode.NotFound,"receiver does not expose management routes");
}
catch(Exception ex){Check(false,"harness exception: "+ex);}
finally
{
    if(receiver!=null){if(!receiver.HasExited){receiver.Kill();await receiver.WaitForExitAsync();}receiver.Dispose();}
    await app.StopAsync();await app.DisposeAsync();
    results.Add("LIMITATIONS: local SQLite and synthetic administrator only; no production auth, SQL Server, Wazuh, external DNS delegation, public TLS, native Office/Acrobat/Explorer/MySQL/Log4j clients, QR decoding/scanning, browser activation, packaged tray or visual UI acceptance.");
    results.Add("Failures: "+failures);File.WriteAllLines(Path.Combine(root,"results.txt"),results);File.WriteAllLines(Path.Combine(root,"receiver.log"),output);Console.WriteLine("RESULTS "+root);Environment.ExitCode=failures==0?0:1;
}
