using System.Text.Json;
using System.Threading.Channels;
using RansomFree.Client;
using RansomFree.Client.Forensics;
using RansomFree.Contracts;

static class SharedCapacityChecks
{
    internal static async Task Run(string root,string sensor,byte[] raw)
    {
        if(Directory.Exists(root))throw new ArgumentException("Fresh shared-capacity fixture required");Directory.CreateDirectory(root);int checks=0;
        void Check(bool ok,string label){if(!ok)throw new Exception(label);checks++;Console.WriteLine("PASS: "+label);}
        using var s=new NativePinChecks.Scope(Path.Combine(root,"source"),sensor,raw);var claim=s.Claim(s.Issue());s.Journal.AbortNativePinBeforeStart(claim);
        var spool=new EventSpool(Path.Combine(root,"spool"),sensor);var errors=new List<string>();var policy=new ForensicPolicy(PreserveActorOnAlert:false);
        var wake=Channel.CreateBounded<byte>(new BoundedChannelOptions(1){FullMode=BoundedChannelFullMode.Wait});int returned=0,completed=0;
        using var blocked=new ManualResetEventSlim();using var release=new ManualResetEventSlim();var ownedReturned=new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        await using(var pipeline=new ForensicPipeline(sensor,root,errors.Add))
        {
            pipeline.CapacityReturned+=()=>{Interlocked.Increment(ref returned);wake.Writer.TryWrite(1);};
            AgentEvent Event()=>new(Guid.NewGuid().ToString("N"),DateTimeOffset.UtcNow,"read","/owned/fixture/canary","fixture-user","/owned/fixture/actor",321,"Owned shared-capacity fixture");
            var failed=Event();
            try{pipeline.Submit(failed,policy,_=>throw new IOException("Owned original persistence failure"),_=>{},ActorLease.Unavailable(failed,"owned-fixture"));throw new Exception("Failed original persistence ignored");}
            catch(IOException){Check(returned==1&&wake.Reader.TryRead(out _),"failed unrelated submission returns and signals shared capacity");}
            for(int i=0;i<32;i++)
            {
                var item=Event();pipeline.Submit(item,policy,_=>{},_=>
                {
                    if(Interlocked.Increment(ref completed)==1){blocked.Set();if(!release.Wait(TimeSpan.FromSeconds(30)))throw new TimeoutException("Owned worker release missing");}
                },ActorLease.Unavailable(item,"owned-fixture"));
            }
            try
            {
                Check(blocked.Wait(TimeSpan.FromSeconds(10)),"one unrelated completion is actually paused with all32 permits held");
                Check(!pipeline.TrySubmitPrepared(s.Journal,claim.Intent.EventId,spool)&&spool.Count==0,"full shared capacity leaves durable source work pending");
                Check(!wake.Reader.TryRead(out _),"no invented permit wake while unrelated completion is blocked");
            }
            finally{release.Set();}
            using var timeout=new CancellationTokenSource(TimeSpan.FromSeconds(15));
            await wake.Reader.ReadAsync(timeout.Token);
            Check(pipeline.TrySubmitPrepared(s.Journal,claim.Intent.EventId,spool,returned:()=>ownedReturned.TrySetResult()),"unrelated returned permit wakes and admits waiting source work");
            await ownedReturned.Task.WaitAsync(timeout.Token);
            Check(s.Journal.Read(claim.Intent.EventId).Done&&spool.Count==2,"actual prepared callback follows durable original/completion delivery");
            Check(completed==32&&returned==34&&errors.Count==0,"all32 unrelated jobs plus prepared/failed submissions return exactly one permit each");
            while(wake.Reader.TryRead(out _)){}
            Check(wake.Writer.TryWrite(1)&&!wake.Writer.TryWrite(1)&&await wake.Reader.ReadAsync(timeout.Token)==1,"bounded wake retains coalesced signal across the empty-scan/sleep boundary");
        }
        var result=new{Passed=true,Checks=checks,Scope="Real shared32 pipeline permit pressure, unrelated producer/failed-submit wakes and deferred source delivery; no native source activation"};File.WriteAllText(Path.Combine(root,"RESULTS.json"),JsonSerializer.Serialize(result));Console.WriteLine(JsonSerializer.Serialize(result));
    }
}
