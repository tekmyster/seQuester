using System.Diagnostics;
using System.Net;
using System.Net.Http.Json;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text.Json;
using RansomFree.Client;
using RansomFree.Contracts;
using RansomFree.Server;

internal static class NativePolicyHttpChecks
{
    internal static async Task Run(string serverDll,string root)
    {
        if(Directory.Exists(root))throw new ArgumentException("Fresh isolated root required");Directory.CreateDirectory(root);
        var checks=new List<string>();void Check(bool ok,string label){if(!ok)throw new Exception(label);checks.Add(label);}
        var data=Path.Combine(root,"server");var store=new Store(data);var enrollment=store.Enroll(new(store.CreateCode().Code,"Signed-policy isolated fixture","fixture"))!;
        var other=store.Enroll(new(store.CreateCode().Code,"Different sensor","fixture"))!;
        var listener=new TcpListener(IPAddress.Loopback,0);listener.Start();var port=((IPEndPoint)listener.LocalEndpoint).Port;listener.Stop();var admin=Store.Secret();const string origin="https://qualification.invalid/";
        ProcessStartInfo Start(params string[] args)
        {
            var info=new ProcessStartInfo(@"C:\Program Files\dotnet\dotnet.exe"){UseShellExecute=false,CreateNoWindow=true,WindowStyle=ProcessWindowStyle.Hidden,RedirectStandardOutput=true,RedirectStandardError=true};info.ArgumentList.Add(Path.GetFullPath(serverDll));foreach(var arg in args)info.ArgumentList.Add(arg);
            foreach(var key in info.Environment.Keys.Where(k=>k.StartsWith("RF_")||k.StartsWith("ASPNETCORE_")||k.StartsWith("NativePolicy__")).ToArray())info.Environment.Remove(key);
            info.Environment["RF_DATA_DIR"]=data;info.Environment["RF_ADMIN_KEY"]=admin;info.Environment["RF_ALLOW_LOOPBACK_HTTP"]="true";info.Environment["ASPNETCORE_ENVIRONMENT"]="Development";info.Environment["ASPNETCORE_URLS"]=$"http://127.0.0.1:{port}";info.Environment["Database__Provider"]="Sqlite";info.Environment["NativePolicy__ServerOrigin"]=origin;return info;
        }
        using var process=Process.Start(Start())!;var stdout=process.StandardOutput.ReadToEndAsync();var stderr=process.StandardError.ReadToEndAsync();using var http=new HttpClient{BaseAddress=new Uri($"http://127.0.0.1:{port}"),Timeout=TimeSpan.FromSeconds(30)};
        async Task<HttpResponseMessage> Post(string? credential,string challenge)
        {using var request=new HttpRequestMessage(HttpMethod.Post,"/api/v1/agent/native-policy"){Content=JsonContent.Create(new NativePolicyChallenge(challenge))};if(credential!=null)request.Headers.Authorization=new("Bearer",credential);return await http.SendAsync(request);}
        async Task<HttpResponseMessage> Key(string credential)
        {using var request=new HttpRequestMessage(HttpMethod.Get,"/api/v1/admin/native-policy/key");request.Headers.Authorization=new("Bearer",credential);return await http.SendAsync(request);}
        try
        {
            bool ready=false;for(int i=0;i<150;i++){if(process.HasExited)throw new Exception(await stderr);try{ready=(await http.GetAsync("/health/live")).IsSuccessStatusCode;if(ready)break;}catch(HttpRequestException){}await Task.Delay(100);}Check(ready,"actual isolated server starts without native signing key");
            var challenge=Convert.ToHexString(RandomNumberGenerator.GetBytes(32));
            using(var response=await Post(null,challenge))Check(response.StatusCode==HttpStatusCode.Unauthorized,"unsigned policy route still requires enrolled sensor authentication");
            using(var response=await Post(enrollment.Credential,challenge))Check(response.StatusCode==HttpStatusCode.ServiceUnavailable,"missing signing key refuses envelope without automatic generation");
            Check(!File.Exists(Path.Combine(data,"native-policy-signing-key.protected")),"request handling leaves missing key absent");
            async Task<int> Initialize(string label)
            {
                using var child=Process.Start(Start("--initialize-native-policy-signing"))!;var output=child.StandardOutput.ReadToEndAsync();var error=child.StandardError.ReadToEndAsync();await child.WaitForExitAsync();
                File.WriteAllText(Path.Combine(root,label+".stdout.txt"),await output);File.WriteAllText(Path.Combine(root,label+".stderr.txt"),await error);return child.ExitCode;
            }
            Check(await Initialize("initialize")==0,"explicit isolated local maintenance generates protected signing key");
            var keyPath=Path.Combine(data,"native-policy-signing-key.protected");var keyHash=Convert.ToHexString(SHA256.HashData(File.ReadAllBytes(keyPath)));
            Check(await Initialize("reinitialize")!=0&&Convert.ToHexString(SHA256.HashData(File.ReadAllBytes(keyPath)))==keyHash,"second initialization refuses replacement and preserves exact encrypted key");
            using(var response=await Key(enrollment.Credential))Check(response.StatusCode==HttpStatusCode.Unauthorized,"enrollment credential cannot use administrator pin export");
            NativePolicyVerificationKey pin;using(var response=await Key(admin)){response.EnsureSuccessStatusCode();pin=(await response.Content.ReadFromJsonAsync<NativePolicyVerificationKey>())!;}
            var der=Convert.FromBase64String(pin.SubjectPublicKeyInfoBase64);Check(pin.Version==1&&pin.Server==origin&&pin.KeyId==SignedNativePolicy.PublicKeyId(der),"administrator exports public key and origin only");
            using(var response=await Post(enrollment.Credential,"bad"))Check(response.StatusCode==HttpStatusCode.BadRequest,"malformed challenge refused");
            SignedNativePolicy envelope;using(var response=await Post(enrollment.Credential,challenge)){response.EnsureSuccessStatusCode();envelope=(await response.Content.ReadFromJsonAsync<SignedNativePolicy>())!;}
            var verified=envelope.Verify(der,origin,enrollment.EndpointId,challenge,DateTimeOffset.UtcNow);
            Check(verified.Trust.GroupId==verified.Monitoring.GroupId&&verified.Trust.EndpointId==enrollment.EndpointId&&verified.Trust.Digest==store.ReadTrustPolicy().Digest(),"actual signed response binds exact same-snapshot trust and monitoring assignment");
            Check(verified.ExpiresUtc-verified.IssuedUtc==TimeSpan.FromMinutes(2),"server issues bounded two-minute policy envelope");
            using(var relay=new ManagementClient(new HttpClient{BaseAddress=http.BaseAddress},enrollment.Credential))
            {
                var relayed=await relay.RelayNativePolicyAsync(challenge);
                Check(relayed.Verify(der,origin,enrollment.EndpointId,challenge,DateTimeOffset.UtcNow).SensorId==enrollment.EndpointId,"ordinary management client relays exact server-signed policy for independent root verification");
            }
            using(var response=await Post(other.Credential,challenge))
            {
                response.EnsureSuccessStatusCode();var different=(await response.Content.ReadFromJsonAsync<SignedNativePolicy>())!;
                bool rejected=false;try{different.Verify(der,origin,enrollment.EndpointId,challenge,DateTimeOffset.UtcNow);}catch(InvalidDataException){rejected=true;}
                Check(rejected&&different.Verify(der,origin,other.EndpointId,challenge,DateTimeOffset.UtcNow).SensorId==other.EndpointId,"server uses authenticated sensor identity and pin verifier rejects cross-sensor relay");
            }
            File.WriteAllText(Path.Combine(root,"envelope.json"),JsonSerializer.Serialize(envelope));File.WriteAllText(Path.Combine(root,"public-pin.json"),JsonSerializer.Serialize(pin));
            File.Move(keyPath,keyPath+".retained");
            using(var response=await Post(enrollment.Credential,challenge))Check(response.StatusCode==HttpStatusCode.ServiceUnavailable&&!File.Exists(keyPath),"lost key remains an explicit outage and is not silently regenerated");
            File.WriteAllText(Path.Combine(root,"RESULTS.json"),JsonSerializer.Serialize(new{Passed=true,Checks=checks.Count,Details=checks,Scope="Real isolated server signing, explicit local key initialization, authentication and pinned verification; no production key or installed native service"}));Console.WriteLine(JsonSerializer.Serialize(new{Passed=true,Checks=checks.Count,Root=root}));
        }
        finally{if(!process.HasExited)process.Kill(entireProcessTree:true);await process.WaitForExitAsync();File.WriteAllText(Path.Combine(root,"server.stdout.txt"),await stdout);File.WriteAllText(Path.Combine(root,"server.stderr.txt"),await stderr);}
    }
}
