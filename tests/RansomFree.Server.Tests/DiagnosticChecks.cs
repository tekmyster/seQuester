using System.Diagnostics;
using System.Net;
using System.Net.Http.Json;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Authentication;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using RansomFree.Client;

internal static class DiagnosticChecks
{
    private sealed class Handler(Func<HttpRequestMessage,CancellationToken,Task<HttpResponseMessage>> send) : HttpMessageHandler
    {protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request,CancellationToken ct)=>send(request,ct);}
    public static async Task Run(string dotnet,string? agent,string root,Action<bool,string> check)
    {
        var sentWithoutCredential=false;
        using(var client=new ManagementClient(new HttpClient(new Handler((r,ct)=>{sentWithoutCredential=r.Method==HttpMethod.Get && r.RequestUri!.AbsolutePath=="/health/live" && r.Headers.Authorization==null;return Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK){Content=JsonContent.Create(new {status="alive",apiVersion=1})});})){BaseAddress=new Uri("https://synthetic.invalid/")},new string('a',64)))
            check((await client.DiagnoseAsync()).Reachable && sentWithoutCredential,"diagnostic success contract uses read-only health request without endpoint credential (mock transport)");
        foreach(var item in new[]{(HttpStatusCode.Redirect,"Redirect"),(HttpStatusCode.ServiceUnavailable,"HttpError"),(HttpStatusCode.OK,"UnexpectedResponse")})
        {
            using var client=new ManagementClient(new HttpClient(new Handler((r,ct)=>Task.FromResult(new HttpResponseMessage(item.Item1){Content=new StringContent("not a management response")}))){BaseAddress=new Uri("https://synthetic.invalid/")});
            var result=await client.DiagnoseAsync();check(!result.Reachable && result.Code==item.Item2,"diagnostic classifies "+item.Item2+" without claiming reachability (mock transport)");
        }
        foreach(var item in new[]{(HttpRequestError.NameResolutionError,"DnsError"),(HttpRequestError.ConnectionError,"ConnectionError"),(HttpRequestError.SecureConnectionError,"TlsError")})
        {
            using var client=new ManagementClient(new HttpClient(new Handler((r,ct)=>throw new HttpRequestException(item.Item1,"sensitive test detail"))){BaseAddress=new Uri("https://synthetic.invalid/")});
            var result=await client.DiagnoseAsync();check(result.Code==item.Item2 && !result.Message.Contains("sensitive"),"diagnostic safely classifies "+item.Item2+" (mock transport)");
        }
        using(var client=new ManagementClient(new HttpClient(new Handler((r,ct)=>throw new OperationCanceledException())){BaseAddress=new Uri("https://synthetic.invalid/")}))
        {
            check((await client.DiagnoseAsync()).Code=="Timeout","diagnostic timeout does not assert a blocked firewall (mock transport)");
            using var cancelled=new CancellationTokenSource();cancelled.Cancel();var propagated=false;try{await client.DiagnoseAsync(cancelled.Token);}catch(OperationCanceledException){propagated=true;}check(propagated,"diagnostic respects caller cancellation");
        }
        using var rsa=RSA.Create(2048);var request=new CertificateRequest("CN=localhost",rsa,HashAlgorithmName.SHA256,RSASignaturePadding.Pkcs1);
        var san=new SubjectAlternativeNameBuilder();san.AddIpAddress(IPAddress.Loopback);request.CertificateExtensions.Add(san.Build());
        using var certificate=request.CreateSelfSigned(DateTimeOffset.UtcNow.AddMinutes(-1),DateTimeOffset.UtcNow.AddHours(1));
        async Task UntrustedTls(Func<string,Task> run)
        {
            using var listener=new TcpListener(IPAddress.Loopback,0);listener.Start();var origin="https://127.0.0.1:"+((IPEndPoint)listener.LocalEndpoint).Port;
            using var timeout=new CancellationTokenSource(TimeSpan.FromSeconds(25));
            var serve=Task.Run(async()=>{using var socket=await listener.AcceptTcpClientAsync(timeout.Token);using var stream=new SslStream(socket.GetStream());try{await stream.AuthenticateAsServerAsync(new SslServerAuthenticationOptions {ServerCertificate=certificate},timeout.Token);}catch(AuthenticationException){}catch(IOException){}});
            try{await run(origin);await serve;}finally{timeout.Cancel();listener.Stop();}
        }
        await UntrustedTls(async origin=>{using var client=new ManagementClient(origin);check((await client.DiagnoseAsync()).Code=="TlsError","real loopback TLS rejects an untrusted certificate without trust-store changes");});
        if(agent!=null)await UntrustedTls(async origin=>
        {
            var data=Path.Combine(root,"diagnostic-must-not-create");var start=new ProcessStartInfo(Path.GetFullPath(dotnet)){UseShellExecute=false,CreateNoWindow=true,WindowStyle=ProcessWindowStyle.Hidden,RedirectStandardOutput=true,RedirectStandardError=true};
            foreach(var arg in new[]{Path.GetFullPath(agent),"--diagnose","--server",origin,"--console","--data",data})start.ArgumentList.Add(arg);
            using var process=Process.Start(start)!;var output=process.StandardOutput.ReadToEndAsync();var error=process.StandardError.ReadToEndAsync();
            try{await process.WaitForExitAsync().WaitAsync(TimeSpan.FromSeconds(25));check(process.ExitCode==2 && (await output).Contains("TlsError") && !Directory.Exists(data),"packaged diagnostic reports TLS failure and creates no agent state");await error;}
            finally{if(!process.HasExited){process.Kill();process.WaitForExit(5000);}}
        });
    }
}
