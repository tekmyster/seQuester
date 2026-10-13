using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Json;
using RansomFree;

if(args is ["--owned-runtime-check"])
{
    if(!OperatingSystem.IsWindows()||Environment.MachineName!="CPTNYC_DC01")throw new InvalidDataException("Owned management-server runtime check required.");
    Console.WriteLine(JsonSerializer.Serialize(new{Host=Environment.MachineName,RuntimeAvailable=true,Runtime=Environment.Version.ToString(),NetworkTest=false}));return;
}

if(args is ["--controlled-wazuh",var eventId,var observed])
{
    if(!OperatingSystem.IsWindows()||Environment.MachineName!="CPTNYC_DC01"||!Guid.TryParseExact(eventId,"N",out _)||
        !DateTimeOffset.TryParseExact(observed,"O",System.Globalization.CultureInfo.InvariantCulture,System.Globalization.DateTimeStyles.RoundtripKind,out var at)||
        at<DateTimeOffset.UtcNow.AddMinutes(-5)||at>DateTimeOffset.UtcNow.AddMinutes(1))throw new InvalidDataException("Owned production-server transport test required.");
    var controlled=new Alert(at.UtcDateTime,"Controlled Wazuh TLS route test","","","","Integration health")
        {EventId=eventId,EndpointId="server-route-qa",NotificationSuppressed=true,Note="Controlled transport test; no file-operation attribution asserted."};
    var destination=new SyslogOptions{Enabled=true,Host="10.81.100.10",Port=6514,Transport="TLS",Format="RFC5424",OctetCounting=true,RequirePersistenceReceipt=true,
        ServerCertificateSha256="175CAF3374B73996CE833EFEA6BE77B4B4EE8833AC67255F164063E01CA531FE"};
    await SyslogClient.SendAsync(controlled,destination);
    Console.WriteLine(JsonSerializer.Serialize(new{Host=Environment.MachineName,StorageReceiptVerified=true,EventId=eventId,PayloadSha256=Convert.ToHexString(SHA256.HashData(JsonSerializer.SerializeToUtf8Bytes(controlled))),ActualServerSyslogTransport=true}));return;
}

var checks=0;void Check(bool ok,string text){if(!ok)throw new InvalidDataException(text);checks++;Console.WriteLine("PASS: "+text);}
using var key=RSA.Create(2048);var request=new CertificateRequest("CN=localhost",key,HashAlgorithmName.SHA256,RSASignaturePadding.Pkcs1);
using var generated=request.CreateSelfSigned(DateTimeOffset.UtcNow.AddMinutes(-1),DateTimeOffset.UtcNow.AddHours(1));
// Windows Schannel needs an imported private key. This is an owned test key,
// never installed into a trusted certificate store; disposal removes its key.
var password=Convert.ToHexString(RandomNumberGenerator.GetBytes(32));
using var certificate=X509CertificateLoader.LoadPkcs12(generated.Export(X509ContentType.Pfx,password),password,X509KeyStorageFlags.DefaultKeySet);
var pin=Convert.ToHexString(SHA256.HashData(certificate.RawData));
var alert=new Alert(DateTime.UtcNow,"Content read",@"C:\QA\bait.txt",@"C:\QA\reader.exe","QA\alex","Windows minifilter"){EventId=Guid.NewGuid().ToString("N"),EndpointId=Guid.NewGuid().ToString("N"),ProcessId=4242};
var hash=Convert.ToHexString(SHA256.HashData(JsonSerializer.SerializeToUtf8Bytes(alert)));
async Task Attempt(string mode,bool tls,bool expectedSuccess,string? overridePin=null)
{
    using var listener=new TcpListener(IPAddress.Loopback,0);listener.Start();var port=((IPEndPoint)listener.LocalEndpoint).Port;
    using var timeout=new CancellationTokenSource(TimeSpan.FromSeconds(8));
    var server=Task.Run(async()=>
    {
        try
        {
            using var client=await listener.AcceptTcpClientAsync(timeout.Token);Stream stream=client.GetStream();
            using var secure=tls?new SslStream(stream,false):null;
            if(secure!=null){await secure.AuthenticateAsServerAsync(new SslServerAuthenticationOptions{ServerCertificate=certificate},timeout.Token);stream=secure;}
            var length=new StringBuilder();var one=new byte[1];
            while(true){if(await stream.ReadAsync(one,timeout.Token)!=1)throw new IOException("Missing frame");if(one[0]==32)break;length.Append((char)one[0]);if(length.Length>6)throw new IOException("Oversize length");}
            var bytes=new byte[int.Parse(length.ToString())];await stream.ReadExactlyAsync(bytes,timeout.Token);
            var payload=bytes.AsSpan().IndexOf((byte)'{');Check(payload>=0&&Convert.ToHexString(SHA256.HashData(bytes.AsSpan(payload)))==hash,"wire payload hash matches the exact serialized event: "+mode);
            var receipt=mode switch
            {
                "wrong-id"=>JsonSerializer.Serialize(new{version=1,event_id=Guid.NewGuid().ToString("N"),payload_sha256=hash,persisted=true}),
                "wrong-hash"=>JsonSerializer.Serialize(new{version=1,event_id=alert.EventId,payload_sha256=new string('B',64),persisted=true}),
                "not-persisted"=>JsonSerializer.Serialize(new{version=1,event_id=alert.EventId,payload_sha256=hash,persisted=false}),
                "malformed"=>"{}",
                "wrong-type"=>"{\"version\":1,\"event_id\":42,\"payload_sha256\":false,\"persisted\":true}",
                "closed"=>null,
                _=>JsonSerializer.Serialize(new{version=1,event_id=alert.EventId,payload_sha256=hash,persisted=true})
            };
            if(receipt!=null)await stream.WriteAsync(Encoding.UTF8.GetBytes(receipt+"\n"),timeout.Token);
        }
        catch(Exception e)when(overridePin!=null&&e is IOException or System.Security.Authentication.AuthenticationException){}
    });
    var options=new SyslogOptions{Enabled=true,Host="127.0.0.1",Port=port,Transport=tls?"TLS":"TCP",Format="RFC5424",OctetCounting=true,RequirePersistenceReceipt=true,ServerCertificateSha256=tls?overridePin??pin:null};
    var success=false;
    try{success=(await SyslogClient.SendAsync(alert,options,timeout.Token)).Contains("confirmed event storage",StringComparison.Ordinal);}
    catch(Exception e)when(e is IOException or JsonException or InvalidOperationException or System.Security.Authentication.AuthenticationException){}
    await server;Check(success==expectedSuccess,"storage result is accurate for "+mode+(tls?" over pinned TLS":" over TCP"));
}
await Attempt("valid",true,true);await Attempt("valid",false,true);
foreach(var mode in new[]{"wrong-id","wrong-hash","not-persisted","malformed","wrong-type","closed"})await Attempt(mode,false,false);
await Attempt("wrong-certificate",true,false,new string('C',64));
try{new SyslogOptions{Host="127.0.0.1",Transport="UDP",RequirePersistenceReceipt=true}.Validate();throw new InvalidDataException("UDP receipt accepted");}catch(ArgumentException){Check(true,"UDP cannot claim collector persistence");}
Console.WriteLine($"PASS: {checks} syslog transport checks; isolated loopback only, no live Wazuh delivery");
