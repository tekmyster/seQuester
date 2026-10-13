using System.Text.Json;
using RansomFree.Client;

var checks=0;
void Check(bool value,string name){if(!value)throw new Exception(name);checks++;}
var started=new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
var returned=new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
var closes=0;var released=0;
using var stop=new CancellationTokenSource();
var once=new AsyncDisposeOnce(async()=>{
    Interlocked.Increment(ref closes);stop.Cancel();started.SetResult();
    await returned.Task;
    Interlocked.Increment(ref released);stop.Dispose();
});
var first=once.DisposeAsync();await started.Task;
var concurrent=Enumerable.Range(0,32).Select(_=>Task.Run(async()=>await once.DisposeAsync())).ToArray();
Check(!first.IsCompleted && released==0,"first caller waits for actual native return");
Check(ReferenceEquals(first,once.DisposeAsync()),"second caller receives identical pending drain");
returned.SetResult();await Task.WhenAll(concurrent.Append(first));
Check(closes==1 && released==1,"concurrent shutdown closes cancellation and resources exactly once");
await once.DisposeAsync();Check(closes==1,"repeated completed disposal succeeds without touching disposed CTS");

var failure=new IOException("original native drain failure");
var failureCalls=0;
var failing=new AsyncDisposeOnce(()=>{failureCalls++;throw failure;});
var failed=failing.DisposeAsync();
foreach(var call in new[]{failed,failing.DisposeAsync(),failing.DisposeAsync()}){
    try{await call;throw new Exception("failure lost");}
    catch(IOException error){Check(ReferenceEquals(error,failure),"all callers retain original drain failure");}
}
Check(failureCalls==1,"failed shutdown is not restarted");

AsyncDisposeOnce? recursive=null;Task? reentered=null;
recursive=new AsyncDisposeOnce(()=>{reentered=recursive!.DisposeAsync();return Task.CompletedTask;});
var reentrant=recursive.DisposeAsync();await reentrant;
Check(ReferenceEquals(reentrant,reentered),"synchronous cancellation reentry observes published drain task");
Console.WriteLine(JsonSerializer.Serialize(new{Passed=true,Checks=checks,ConcurrentCallers=32,NativeDriverLoaded=false,Scope="Actual async shutdown component: joined pending native drain, repeated/concurrent/reentrant disposal and original exception preservation."}));
