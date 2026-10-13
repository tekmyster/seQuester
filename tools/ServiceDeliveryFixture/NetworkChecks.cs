using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Authentication;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.Extensions.Configuration;
using RansomFree.Server;

internal static class NetworkChecks
{
    public static async Task Run(string root,Action<bool,string> check)
    {
        var dir=Path.Combine(root,"network");Directory.CreateDirectory(dir);
        var config=new ConfigurationBuilder().AddInMemoryCollection(new Dictionary<string,string?>{["RF_DATA_DIR"]=dir}).Build();
        var protector=new EphemeralDataProtectionProvider();var files=new ProtectedNotificationFiles(config,protector);var store=new Store(dir);store.InitializeDecoyServiceStorage();
        var definition=new DecoyServiceChange("Network fixture","Synthetic",false,0,"unused"){RequestId=Guid.NewGuid().ToString("N")};
        var service=store.CreateDecoyService(definition,"fixture");store.ChangeDecoyService(service.Service.Id,definition with{ExpectedRevision=1,Enabled=true},"fixture");
        var configuration=new ServerSyslogConfiguration(files,config);var callbacks=new CallbackConfiguration(config);var status=new ServiceSyslogStatus();
        using var timeout=new CancellationTokenSource(TimeSpan.FromSeconds(20));var ct=timeout.Token;
        using var listener=new TcpListener(IPAddress.Loopback,0);listener.Start();var port=((IPEndPoint)listener.LocalEndpoint).Port;
        using var rsa=RSA.Create(2048);var request=new CertificateRequest("CN=localhost",rsa,HashAlgorithmName.SHA256,RSASignaturePadding.Pkcs1);
        var names=new SubjectAlternativeNameBuilder();names.AddIpAddress(IPAddress.Loopback);request.CertificateExtensions.Add(names.Build());
        using var certificate=request.CreateSelfSigned(DateTimeOffset.UtcNow.AddMinutes(-1),DateTimeOffset.UtcNow.AddMinutes(10));
        var body=new SaveServerSyslogBody(0,new(){Enabled=true,Host="127.0.0.1",Port=port,Transport="TLS"},false,false,"unused"){ServiceHits=true};configuration.Save(body,store,callbacks);
        store.TouchDecoyService(service.Service.Id,service.ActivationPath.Split('/')[^1],"127.0.0.1","GET");
        var tlsServer=Task.Run(async()=>{using var client=await listener.AcceptTcpClientAsync(ct);await using var tls=new SslStream(client.GetStream());try{await tls.AuthenticateAsServerAsync(new SslServerAuthenticationOptions{ServerCertificate=certificate},ct);var buffer=new byte[1];return await tls.ReadAsync(buffer,ct);}catch(Exception ex) when(ex is AuthenticationException or IOException){return 0;}},ct);
        var pump=new ServiceSyslogPump(store,configuration,files,status,new ServiceSyslogTransport());var rejected=false;
        try{await pump.Step(ct);}catch(Exception ex) when(ex is AuthenticationException or IOException){rejected=true;}
        check(rejected&&await tlsServer==0&&(files.Read<ServerEventSyslogProgress>("service-syslog-progress.protected")?.Sequence??0)==0,"real TLS relay rejects an untrusted certificate, transmits no event, and retains checkpoint");
        // Explicit fixture destination repair; no production settings or trust-store mutation.
        configuration.Save(body with{ExpectedRevision=1,Destination=body.Destination with{Transport="TCP",OctetCounting=true,Format="RFC5424"}},store,callbacks);
        var receive=Task.Run(async()=>{using var client=await listener.AcceptTcpClientAsync(ct);using var reader=new StreamReader(client.GetStream(),Encoding.UTF8);return await reader.ReadToEndAsync(ct);},ct);
        var reopened=new ProtectedNotificationFiles(config,protector);pump=new(new Store(dir),new ServerSyslogConfiguration(reopened,config),reopened,status,new ServiceSyslogTransport());await pump.Step(ct);
        var wire=await receive;var split=wire.IndexOf(' ');var payload=wire[(split+1)..];
        check(int.TryParse(wire[..split],out var length)&&length==Encoding.UTF8.GetByteCount(payload)&&payload.Contains(store.ServiceEvents(0).Single().Event.EventId)&&payload.Contains("\"CanaryType\":\"N05\""),"real TCP recovery emits the durable N05 identity with valid octet-counted framing");
        check(status.LastSentSequence==1&&reopened.Read<ServerEventSyslogProgress>("service-syslog-progress.protected")!.Sequence==1&&store.ServiceEvents(0).Count==1,"real relay restart advances only after transport send and keeps source evidence");
        listener.Stop();
        using var smtp=new TcpListener(IPAddress.Loopback,0);smtp.Start();var smtpPort=((IPEndPoint)smtp.LocalEndpoint).Port;
        var smtpServer=Task.Run(async()=>{using var client=await smtp.AcceptTcpClientAsync(ct);using var reader=new StreamReader(client.GetStream());await using var writer=new StreamWriter(client.GetStream()){AutoFlush=true,NewLine="\r\n"};await writer.WriteLineAsync("220 localhost fixture");var line=await reader.ReadLineAsync(ct);await writer.WriteLineAsync("250 localhost");var next=await reader.ReadLineAsync(ct);return next;},ct);
        var denied=false;try{await new CallbackEmailSender().Send(new(){Enabled=true,Host="127.0.0.1",Port=smtpPort,From="fixture@example.invalid",Recipients=["target@example.invalid"]},"target@example.invalid","fixture","synthetic",ct);}catch(System.Net.Mail.SmtpException){denied=true;}
        var command=await smtpServer;check(denied&&(command==null||command=="QUIT"),"real SMTP sender refuses a relay without STARTTLS before sending message content");
        Console.WriteLine("PENDING: trusted TLS collector and external Wazuh persistence/mailbox acceptance; no system trust or live service changes.");
    }
}
