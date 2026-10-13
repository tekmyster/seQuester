using Microsoft.Data.Sqlite;
using Microsoft.AspNetCore.Http;
using RansomFree.Server;
using System.Diagnostics;
using System.Security.Cryptography;
using System.Text.Json;

var expectBlocked=args is ["--expect-blocked"];
if(args.Length!=0&&!expectBlocked)throw new ArgumentException("Use --expect-blocked only for the unpatched baseline");
var root=Path.Combine(@"D:\Codex\RansomFree\boundary-20261006","native-policy-renewal-"+Guid.NewGuid().ToString("N"));Directory.CreateDirectory(root);
var store=new Store(root);store.InitializeTrustStorage();
var enrolled=store.Enroll(new(store.CreateCode().Code,"native-renewal-fixture","fixture"))!;
using var writer=new SqliteConnection(new SqliteConnectionStringBuilder{DataSource=Path.Combine(root,"management.db"),Pooling=false}.ToString());writer.Open();
var checks=new List<string>();void Check(bool value,string name){if(!value)throw new Exception(name);checks.Add(name);}
var before=Stopwatch.GetTimestamp();bool blocked;RansomFree.Contracts.NativePolicySnapshot snapshot;
using(var transaction=writer.BeginTransaction(deferred:false))
{
 var read=Task.Run(()=>store.NativePolicySnapshot("https://qualification.invalid/",enrolled.EndpointId,new string('A',64),DateTimeOffset.UtcNow));
 try
 {
  blocked=await Task.WhenAny(read,Task.Delay(TimeSpan.FromSeconds(2)))!=read;
  Check(blocked==expectBlocked,expectBlocked?"unpatched native policy requires writer lock during a held real SQLite write transaction":"native policy snapshot completes during a held real SQLite write transaction");
 }
 finally{transaction.Rollback();}
 snapshot=await read.WaitAsync(TimeSpan.FromSeconds(15));
}
Check(snapshot.SensorId==enrolled.EndpointId&&snapshot.Challenge==new string('A',64),"consistent authenticated sensor/challenge snapshot retained");
Check(snapshot.ExpiresUtc>snapshot.IssuedUtc&&snapshot.Trust.ExpiresUtc==snapshot.ExpiresUtc,"signed policy lifetime remains bounded and consistent");
if(!expectBlocked)
{
 var request=new DefaultHttpContext();request.Request.Method="POST";request.Request.Path="/api/v1/agent/native-policy";
 Check(!SqliteWriteAdmission.IsApiWrite(request.Request),"exact read-only native policy POST does not enter HTTP writer queue");
 using var key=RSA.Create(3072);var signed=RansomFree.Contracts.SignedNativePolicy.Sign(snapshot,key);
 var verified=signed.Verify(key.ExportSubjectPublicKeyInfo(),snapshot.Server,enrolled.EndpointId,snapshot.Challenge,DateTimeOffset.UtcNow);
 Check(verified.SensorId==enrolled.EndpointId,"fresh policy still requires valid RSA-PSS signature and exact nonce/origin");
 Check(store.Authenticate(enrolled.Credential)==enrolled.EndpointId&&store.Authenticate(new string('F',64))==null,"read-only route exception preserves enrollment authentication");
 foreach(var path in new[]{"/api/v1/agent/native-policy/","/api/v1/agent/native-policy/extra","/api/v1/agent/native-policy-old"})
 {request.Request.Path=path;Check(SqliteWriteAdmission.IsApiWrite(request.Request),"neighbor route remains admitted as writer: "+path);}
 request.Request.Path="/api/v1/agent/native-policy";
 foreach(var method in new[]{"PUT","PATCH","DELETE"}){request.Request.Method=method;Check(SqliteWriteAdmission.IsApiWrite(request.Request),"native policy exemption applies only to POST: "+method);}
}
var result=new{Passed=true,Baseline=expectBlocked,BlockedWhileWriterHeld=blocked,ElapsedSeconds=Stopwatch.GetElapsedTime(before).TotalSeconds,Checks=checks.Count,Details=checks,Root=root,ServerAssemblyVersion=typeof(Store).Assembly.GetName().Version!.ToString(),Scope="Real isolated SQLite WAL writer contention and policy signature/authentication; production latency is a separate gate"};
File.WriteAllText(Path.Combine(root,"RESULTS.json"),JsonSerializer.Serialize(result));Console.WriteLine(JsonSerializer.Serialize(result));
