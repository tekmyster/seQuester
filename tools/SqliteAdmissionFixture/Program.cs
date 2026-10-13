using Microsoft.AspNetCore.Http;
using RansomFree.Contracts;
using RansomFree.Server;
using System.Net;
using System.Text.Json;

var root=Path.Combine(@"D:\Codex\RansomFree\boundary-20261006","sqlite-admission-"+Guid.NewGuid().ToString("N"));
Directory.CreateDirectory(root);var checks=new List<string>();
void Check(bool passed,string name){if(!passed)throw new Exception(name);checks.Add(name);Console.WriteLine("PASS: "+name);}
DefaultHttpContext Context(string method="POST",string path="/api/v1/agent/events")
{var c=new DefaultHttpContext();c.Request.Method=method;c.Request.Path=path;c.Response.Body=new MemoryStream();return c;}
using var gate=new SqliteWriteAdmission(true,128);
var entered=new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
var release=new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
var first=gate.Execute(Context(),async()=>{entered.SetResult();await release.Task;});await entered.Task;
var store=new Store(root);var enrollment=store.Enroll(new(store.CreateCode().Code,"admission-qa","fixture"))!;var endpoint=enrollment.EndpointId;
var capability=Context("POST","/api/v1/agent/capabilities");
async Task Dispatch(DefaultHttpContext c,Func<Task> action)
{if(SqliteWriteAdmission.IsApiWrite(c.Request))await gate.Execute(c,action);else await action();}
var capabilityRan=false;
await Dispatch(capability,()=>
{
 Check(store.Authenticate(enrollment.Credential)==endpoint,"capability authentication remains valid while HTTP writer permit is held");
 Check(store.Authenticate("invalid-owned-fixture-credential")==null,"capability bypass does not bypass credential verification");
 capabilityRan=true;return Task.CompletedTask;
}).WaitAsync(TimeSpan.FromSeconds(5));
Check(capabilityRan&&!first.IsCompleted,"capability POST completes before held writer is released");
var ordered=new List<int>();var active=0;var maximumActive=0;
var queued=Enumerable.Range(0,64).Select(i=>gate.Execute(Context(),async()=>
{
 var n=Interlocked.Increment(ref active);maximumActive=Math.Max(maximumActive,n);
 try
 {
  ordered.Add(i);await Task.Yield();
  var e=new AgentEvent(Guid.NewGuid().ToString("N"),DateTimeOffset.UtcNow,"read",@"C:\QA\canary.txt","qa-user",@"C:\QA\actor.exe",1234,"owned admission fixture");
  if(store.Ingest(endpoint,new([e]),IPAddress.Parse("192.0.2.10"))!=new BatchReceipt(1,0))throw new Exception("Event not committed");
  if(!store.Heartbeat(endpoint,new("qa","admitted"),IPAddress.Parse("192.0.2.10")))throw new Exception("Heartbeat not committed");
 }
 finally{Interlocked.Decrement(ref active);}
})).ToArray();
Check(ordered.Count==0,"queued writers do not enter while writer is active");
release.SetResult();await first;await Task.WhenAll(queued);
Check(maximumActive==1&&ordered.SequenceEqual(Enumerable.Range(0,64)),"64 competing writers are admitted singly in arrival order");
Check(store.Events(0,100).Count==64&&store.HistoryContacts([endpoint])[endpoint].Ip=="192.0.2.10","all 64 evidence batches and actual connection identity persist");
try{await gate.Execute(Context(),()=>throw new IOException("owned failure"));throw new Exception("Failure swallowed");}catch(IOException){}
Check(await gate.Execute(Context(),()=>Task.CompletedTask),"exception releases writer permit and remains visible");
using(var small=new SqliteWriteAdmission(true,1))
{
 var hold=new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
 var a=small.Execute(Context(),()=>hold.Task);
 using var cancel=new CancellationTokenSource();var c=Context();c.RequestAborted=cancel.Token;
 var b=small.Execute(c,()=>throw new Exception("Cancelled writer entered"));
 var refused=Context();var ran=false;
 Check(!await small.Execute(refused,()=>{ran=true;return Task.CompletedTask;})&&!ran&&refused.Response.StatusCode==503&&refused.Response.Headers.RetryAfter=="1","full bounded queue returns retryable 503 without running action");
 cancel.Cancel();try{await b;throw new Exception("Cancellation swallowed");}catch(OperationCanceledException){}
 hold.SetResult();await a;
 Check(await small.Execute(Context(),()=>Task.CompletedTask),"cancelled queued request frees capacity without leaking permit");
}
using(var disabled=new SqliteWriteAdmission(false,0))
{
 var hold=new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);var a=disabled.Execute(Context(),()=>hold.Task);
 Check(await disabled.Execute(Context(),()=>Task.CompletedTask),"SQL Server bypass permits concurrent requests");hold.SetResult();await a;
}
foreach(var method in new[]{"GET","HEAD","OPTIONS"})Check(!SqliteWriteAdmission.IsApiWrite(Context(method).Request),method+" observation bypasses writer admission");
Check(!SqliteWriteAdmission.IsApiWrite(Context("POST","/api/v10/agent/events").Request)&&!SqliteWriteAdmission.IsApiWrite(Context("POST","/other").Request),"only exact versioned API segment is selected");
Check(new[]{"POST","PUT","PATCH","DELETE"}.All(method=>SqliteWriteAdmission.IsApiWrite(Context(method).Request)),"all versioned API mutation methods use admission");
Check(!SqliteWriteAdmission.IsApiWrite(Context("POST","/API/V1/AGENT/CAPABILITIES").Request),"case-insensitive exact capability route bypasses admission");
Check(new[]{"/api/v1/agent/capabilities/extra","/api/v1/agent/capabilities-old","/api/v1/agent/capabilities/","/api/v1/agent/policy","/api/v1/agent/evidence/status"}.All(path=>SqliteWriteAdmission.IsApiWrite(Context("POST",path).Request)),"capability exception does not exempt neighboring or mutation routes");
Check(new[]{"PUT","PATCH","DELETE"}.All(method=>SqliteWriteAdmission.IsApiWrite(Context(method,"/api/v1/agent/capabilities").Request)),"capability path exception applies only to POST");
File.WriteAllText(Path.Combine(root,"RESULTS.json"),JsonSerializer.Serialize(new{Passed=true,Checks=checks,Root=root,Scope="Isolated actual SQLite persistence and bounded asynchronous admission; deployed contention reduction remains a live gate"},new JsonSerializerOptions{WriteIndented=true}));
Console.WriteLine($"PASS: {checks.Count} admission checks; {root}");
