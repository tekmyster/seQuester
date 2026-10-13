using System.Diagnostics;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Text.Json;
using System.Net.Security;
using System.Security.Authentication;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.IO.Compression;
using System.Xml.Linq;

namespace RansomFree;

internal static class FeatureTests
{
    public static async Task RunAsync(string root,List<string> report)
    {
        void Check(bool value,string name) { if(!value)throw new Exception("FAIL: "+name);report.Add("PASS: "+name); }
        foreach(var name in new[]{"../escape","CON","COM1","bad:name","trailing.",""})
        {
            var rejected=false;try {CanaryTemplates.FileName(new(name,"txt"));}catch(ArgumentException){rejected=true;}
            Check(rejected,"reject unsafe name "+name);
        }
        Check(CanaryTemplates.FileName(new("Annual Report","csv"))=="Annual Report.csv","custom filename and chosen extension");
        Check(CanaryTemplates.FileName(new("Annual Report.CSV","csv"))=="Annual Report.CSV","avoid duplicate extension");
        foreach(var type in CanaryTemplates.Types) Check(CanaryTemplates.Render(new("Test",type)).Length>0,"render "+type);
        const string callback="https://callback.example.test/t/opaque-id?a=1&b=2";
        var callbackHtml=Encoding.UTF8.GetString(CanaryTemplates.Render(new("R&D archive","html",callback)));
        Check(callbackHtml.Contains("a=1&amp;b=2") && callbackHtml.Contains("R&amp;D archive") && callbackHtml.Contains("no-referrer"),"HTML callback and title safely encoded");
        using(var svgStream=new MemoryStream(CanaryTemplates.Render(new("R&D archive","svg",callback))))
        {
            XNamespace svgNs="http://www.w3.org/2000/svg";
            var svg=XDocument.Load(svgStream);
            Check(svg.Root!.Element(svgNs+"image")!.Attribute("href")!.Value==callback,"SVG callback survives XML escaping");
        }
        foreach(var url in new[]{"http://example.test/t","javascript:alert(1)","file:///C:/x","https://user:pass@example.test/t","https://example.test/t#fragment","https://example.test/white space","https://example.test/\\t"})
        {
            var rejected=false;try{CanaryTemplates.Render(new("Test","html",url));}catch(ArgumentException){rejected=true;}
            Check(rejected,"reject unsafe callback URL "+url);
        }
        foreach(var type in new[]{"docx","xlsx"})
        {
            var rendered=CanaryTemplates.Render(new("Test",type,callback));
            ImportedCanaries.Validate(rendered,type);
            using var bytes=new MemoryStream(rendered);
            using var package=new ZipArchive(bytes,ZipArchiveMode.Read);
            XNamespace relationships="http://schemas.openxmlformats.org/package/2006/relationships";
            var targets=new List<string>();
            foreach(var entry in package.Entries.Where(e=>e.FullName.EndsWith(".rels",StringComparison.Ordinal)))
            {
                using var stream=entry.Open();var document=XDocument.Load(stream);
                targets.AddRange(document.Descendants(relationships+"Relationship").Where(e=>(string?)e.Attribute("TargetMode")=="External").Select(e=>(string)e.Attribute("Target")!));
            }
            Check(targets.Count==1&&targets[0]==callback,"generated "+type+" preserves exact external callback without XML corruption");
        }
        var callbackPdf=CanaryTemplates.Render(new("Test","pdf",callback));
        ImportedCanaries.Validate(callbackPdf,"pdf");
        Check(Encoding.ASCII.GetString(callbackPdf).Contains("/URI ("+callback+")",StringComparison.Ordinal),"generated PDF preserves exact callback URI");
        foreach(var type in new[]{"txt","csv","rtf","json","xml","md"})
        {
            var rejected=false;try{CanaryTemplates.Render(new("Test",type,callback));}catch(ArgumentException){rejected=true;}
            Check(rejected,"reject unsupported generated callback for "+type);
        }
        foreach(var type in new[]{"docx","xlsx","pdf"})
        {
            var source=Path.Combine(root,"import-source."+type);
            var originalBytes=CanaryTemplates.Render(new("Test",type));File.WriteAllBytes(source,originalBytes);
            Check(CanaryTemplates.Render(new("Renamed",type,SourcePath:source)).SequenceEqual(originalBytes),"import preserves every byte of "+type);
        }
        foreach(var type in new[]{"docx","xlsx","pdf"})
        {
            var rejected=false;try{ImportedCanaries.Validate("not a document"u8.ToArray(),type);}catch(InvalidDataException){rejected=true;}
            Check(rejected,"reject invalid imported "+type);
        }
        foreach(var spec in new[]{new CanarySpec("Test","xlsx",SourcePath:Path.Combine(root,"import-source.docx")),new CanarySpec("Test","docx",callback,Path.Combine(root,"import-source.docx"))})
        {
            var rejected=false;try{CanaryTemplates.Render(spec);}catch(ArgumentException){rejected=true;}
            Check(rejected,"reject import type mismatch or callback rewrite");
        }
        var oversized=Path.Combine(root,"oversized.pdf");
        using(var large=new FileStream(oversized,FileMode.CreateNew)) large.SetLength(ImportedCanaries.MaxBytes+1L);
        var oversizedRejected=false;try{ImportedCanaries.Read(oversized,"pdf");}catch(InvalidDataException){oversizedRejected=true;}
        Check(oversizedRejected,"reject oversized import before allocating payload");
        foreach(var maliciousXml in new[]{"<!DOCTYPE x [<!ENTITY remote SYSTEM 'https://example.test/must-not-fetch'>]><x>&remote;</x>","<broken>"})
        {
            using var maliciousPackage=new MemoryStream();
            using(var zip=new ZipArchive(maliciousPackage,ZipArchiveMode.Create,true))
            {
                using(var writer=new StreamWriter(zip.CreateEntry("[Content_Types].xml").Open()))writer.Write(maliciousXml);
                using(var writer=new StreamWriter(zip.CreateEntry("word/document.xml").Open()))writer.Write("<document/>");
            }
            var rejected=false;try{ImportedCanaries.Validate(maliciousPackage.ToArray(),"docx");}catch(System.Xml.XmlException){rejected=true;}
            Check(rejected,"reject DTD or malformed XML without external resolution");
        }
        using(var badMonitor=new CanaryMonitor(Path.Combine(root,"preflight-config")))
        {
            var dest=Path.Combine(root,"preflight-canaries");Directory.CreateDirectory(dest);
            var rejected=false;try{badMonitor.Deploy(dest,[new("first","txt"),new("second","docx",SourcePath:Path.Combine(root,"missing.docx"))]);}catch(FileNotFoundException){rejected=true;}
            Check(rejected && Directory.GetFiles(dest).Length==0 && badMonitor.Settings.OriginalAuditPolicy==null,"batch preflight rejects missing import before writing or changing audit policy");
        }
        var importedConfig=Path.Combine(root,"import-config");
        using(var importMonitor=new CanaryMonitor(importedConfig))
        {
            var dest=Path.Combine(root,"imported-canaries");Directory.CreateDirectory(dest);
            importMonitor.Deploy(dest,[new("Imported","docx",SourcePath:Path.Combine(root,"import-source.docx")),new("Web callback","html",callback),new("Image callback","svg",callback)]);
            Check(File.ReadAllBytes(Path.Combine(dest,"Imported.docx")).SequenceEqual(File.ReadAllBytes(Path.Combine(root,"import-source.docx"))),"deployed import remains byte-identical");
            Check(importMonitor.Settings.Canaries.Count==3 && importMonitor.Settings.Canaries.All(c=>c.Tripwire.Contains("unverified")),"deployment records unverified callback status without claiming activation");
            var baseline=CanaryMonitor.Hash(Path.Combine(dest,"Web callback.html"));
            var rejected=false;try{importMonitor.Deploy(dest,[new("Web callback","html",callback)]);}catch(IOException){rejected=true;}
            Check(rejected && CanaryMonitor.Hash(Path.Combine(dest,"Web callback.html"))==baseline,"callback deployment refuses overwrite");
        }
        using(var reloaded=new CanaryMonitor(importedConfig)) Check(reloaded.Settings.Canaries.Count==3 && reloaded.Settings.Canaries[0].Tripwire=="Imported; callback unverified","callback metadata persists across restart");
        foreach(var type in new[]{"docx","xlsx"})
        {
            using var stream=new MemoryStream(CanaryTemplates.Render(new("Test",type)));
            using var package=new ZipArchive(stream,ZipArchiveMode.Read);
            var main=type=="docx" ? "word/document.xml":"xl/workbook.xml";
            Check(package.GetEntry("[Content_Types].xml")!=null && package.GetEntry(main)!=null,"real "+type+" package embedded");
            foreach(var entry in package.Entries.Where(e=>e.Name.EndsWith(".xml") || e.Name.EndsWith(".rels")))
            {
                using var xml=entry.Open();XDocument.Load(xml);
            }
        }
        var pdfBytes=CanaryTemplates.Render(new("Test","pdf"));
        Check(Encoding.ASCII.GetString(pdfBytes,0,5)=="%PDF-" && Encoding.ASCII.GetString(pdfBytes).Contains("%%EOF"),"real PDF payload embedded");
        using(var json=JsonDocument.Parse(CanaryTemplates.Render(new("R&D register","json")))) Check(json.RootElement.GetProperty("title").GetString()=="R&D register","JSON template escapes user text");
        using(var xml=new MemoryStream(CanaryTemplates.Render(new("R&D register","xml")))) Check(XDocument.Load(xml).Root!.Element("Title")!.Value=="R&D register","XML template escapes user text");
        var identity=new ProcessIdentity(123,"C:\\Apps\\approved.exe",1234,"ABC");
        var alert=new Alert(DateTime.Now,"Content read (copy possible)","C:\\Decoys\\α.txt","approved.exe","DOMAIN\\user","Test") {Identity=identity};
        var rule=new AllowRule(identity.Executable,"ABC");
        Check(rule.Matches(alert),"allowlist exact path and hash");
        Check(!rule.Matches(alert with {Identity=identity with {Hash="DEF"}}),"allowlist rejects changed binary");
        Check(!rule.Matches(alert with {Identity=null}),"allowlist does not suppress unattributed events");
        Check(!(rule with {ExpiresUtc=DateTime.UtcNow.AddSeconds(-1)}).Matches(alert),"allowlist expiry");
        var password=PasswordHash.Create("test-only-long-password");
        Check(PasswordHash.Verify("test-only-long-password",password) && !PasswordHash.Verify("wrong-password",password),"password verifier accepts correct password only");
        using var udp=new UdpClient(new IPEndPoint(IPAddress.Loopback,0));
        var udpPort=((IPEndPoint)udp.Client.LocalEndPoint!).Port;
        var options=new SyslogOptions {Enabled=true,Host="127.0.0.1",Port=udpPort,Transport="UDP"};
        await SyslogClient.SendAsync(alert,options);
        using var timeout=new CancellationTokenSource(TimeSpan.FromSeconds(10));
        var packet=await udp.ReceiveAsync(timeout.Token);
        var message=Encoding.UTF8.GetString(packet.Buffer);
        Check(message.StartsWith("<132>") && message.Contains("RansomFree: "),"UDP syslog header received");
        using(var json=JsonDocument.Parse(message[message.IndexOf('{')..])) Check(json.RootElement.GetProperty("User").GetString()=="DOMAIN\\user","syslog JSON preserves user attribution");
        var listener=new TcpListener(IPAddress.Loopback,0); listener.Start();
        try
        {
            var tcpOptions=options with {Port=((IPEndPoint)listener.LocalEndpoint).Port,Transport="TCP"};
            var sent=SyslogClient.SendAsync(alert,tcpOptions);
            using(var accepted=await listener.AcceptTcpClientAsync(timeout.Token))
            using(var reader=new StreamReader(accepted.GetStream()))
            {
                var line=await reader.ReadLineAsync(timeout.Token); Check(line?.Contains("RansomFree: ")==true,"Wazuh newline TCP frame received");
            }
            await sent;
            sent=SyslogClient.SendAsync(alert,tcpOptions with {OctetCounting=true,Format="RFC5424"});
            using(var accepted=await listener.AcceptTcpClientAsync(timeout.Token))
            {
                using var bytes=new MemoryStream(); await accepted.GetStream().CopyToAsync(bytes,timeout.Token);
                var all=bytes.ToArray(); var split=Array.IndexOf(all,(byte)' ');
                var length=int.Parse(Encoding.ASCII.GetString(all,0,split));
                Check(length==all.Length-split-1 && Encoding.UTF8.GetString(all,split+1,length).StartsWith("<132>1 "),"RFC5424 octet-counted TCP byte length");
            }
            await sent;
        }
        finally {listener.Stop();}
        var tlsListener=new TcpListener(IPAddress.Loopback,0);tlsListener.Start();
        try
        {
            using var key=RSA.Create(2048);
            var request=new CertificateRequest("CN=localhost",key,HashAlgorithmName.SHA256,RSASignaturePadding.Pkcs1);
            using var generated=request.CreateSelfSigned(DateTimeOffset.UtcNow.AddMinutes(-1),DateTimeOffset.UtcNow.AddHours(1));
            using var certificate=X509CertificateLoader.LoadPkcs12(generated.Export(X509ContentType.Pfx),null,X509KeyStorageFlags.DefaultKeySet);
            var receiver=Task.Run(async()=>
            {
                using var accepted=await tlsListener.AcceptTcpClientAsync(timeout.Token);
                using var stream=new SslStream(accepted.GetStream());
                try {await stream.AuthenticateAsServerAsync(new SslServerAuthenticationOptions {ServerCertificate=certificate},timeout.Token);} catch(AuthenticationException) {} catch(IOException) {}
            });
            var rejected=false;
            try {await SyslogClient.SendAsync(alert,options with {Host="localhost",Port=((IPEndPoint)tlsListener.LocalEndpoint).Port,Transport="TLS"});}
            catch(AuthenticationException) {rejected=true;}
            await receiver;
            Check(rejected,"TLS rejects untrusted server certificate");
        }
        finally {tlsListener.Stop();}
        var outboxDir=Path.Combine(root,"outbox");
        using(var outbox=new SyslogOutbox(outboxDir))
        {
            outbox.Enqueue(alert,options);
            await udp.ReceiveAsync(timeout.Token);
            var until=DateTime.UtcNow.AddSeconds(3);while(outbox.Count!=0 && DateTime.UtcNow<until)await Task.Delay(25);
            Check(outbox.Count==0,"outbox drains after successful send");
        }
        var closedPort=new TcpListener(IPAddress.Loopback,0);closedPort.Start();var unusedPort=((IPEndPoint)closedPort.LocalEndpoint).Port;closedPort.Stop();
        var pendingDir=Path.Combine(root,"pending-outbox");
        using(var pending=new SyslogOutbox(pendingDir))
        {
            pending.Enqueue(alert,options with {Port=unusedPort,Transport="TCP"});
            await Task.Delay(200);
            Check(pending.Count==1 && File.Exists(Path.Combine(pendingDir,"syslog-outbox.json")),"unreachable receiver retains persisted event");
        }
        using(var restarted=new SyslogOutbox(pendingDir)) Check(restarted.Count==1,"outbox survives restart");
        using(var paused=new SyslogOutbox(Path.Combine(root,"paused-outbox"),false))
        {
            paused.Enqueue(alert,options);await Task.Delay(100);
            Check(paused.Count==1 && udp.Available==0,"disabled forwarding preserves queue without sending");
            paused.SetEnabled(true);await udp.ReceiveAsync(timeout.Token);
        }
        using var child=Process.Start(new ProcessStartInfo(Environment.ProcessPath!) {UseShellExecute=false,CreateNoWindow=true,ArgumentList={"--hold-test"}})!;
        try
        {
            var observed=ProcessControls.Capture(child.Id,Environment.ProcessPath!,DateTime.UtcNow.AddSeconds(1));
            Check(observed!=null,"capture live process identity");
            var rejected=false;try {ProcessControls.End(observed! with {CreatedUtcFileTime=observed!.CreatedUtcFileTime-1});}catch(InvalidOperationException){rejected=true;}
            Check(rejected && !child.HasExited,"refuse changed process identity before termination");
            ProcessControls.End(observed!); child.WaitForExit(5000);
            Check(child.HasExited,"terminate verified disposable helper process");
        }
        finally {if(!child.HasExited)child.Kill();}
    }
}
