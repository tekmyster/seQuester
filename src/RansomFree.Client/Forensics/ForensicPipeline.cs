using System.Threading.Channels;
using RansomFree.Contracts;
namespace RansomFree.Client.Forensics;

// A durable source owns the observation and actor lease until admission succeeds.
// This exception transfers no ownership and must not manufacture a failure event.
public sealed class ForensicQueueCapacityException:IOException
{
    public ForensicQueueCapacityException():base("Forensic worker capacity temporarily full; durable Windows observation and retained actor await retry."){}
}

// The original observation is persisted before work is queued. Completion is an immutable linked event.
// A crash leaves a visible pending observation, never an invented successful enrichment.
public sealed class ForensicPipeline:IAsyncDisposable
{
    private sealed record Work(AgentEvent Original,ActorLease Actor,ForensicPolicy Policy,Action<AgentEvent> Emit,Action? Prepared=null,Action? Returned=null);
    private readonly Channel<Work> queue=Channel.CreateBounded<Work>(new BoundedChannelOptions(32){SingleReader=true,FullMode=BoundedChannelFullMode.Wait});
    private readonly SemaphoreSlim capacity=new(32,32);
    private readonly ForensicCollector collector;
    private readonly EvidenceUploadQueue uploads;
    private readonly string sensor;
    private readonly Action<string> error;
    private readonly Task worker;
    internal event Action? CapacityReturned;
    private readonly HashSet<string> prepared=new(StringComparer.Ordinal);
    public ForensicPipeline(string sensor,string directory,Action<string> error)
    {this.sensor=sensor;this.error=error;collector=new(sensor,directory);uploads=new(directory);worker=Task.Run(Run);}
    public ForensicEvidence LinkResponse(ForensicEvidence source,string eventId,DateTimeOffset time)=>collector.LinkResponse(source,eventId,time);
    // The journal already owns raw/acquisition evidence before admission here.
    // Four Linux jobs share the existing 32 worker permits without blocking a
    // native source. False means keep the durable job for a later retry.
    internal bool TrySubmitPrepared(LinuxForensicJournal journal,string id,EventSpool spool,Action<string>? checkpoint=null,Action? returned=null,
        Func<AgentEvent,ActorLease,EventTrust?>? prepareTrust=null)
    {
        lock(prepared)
        {
            if(prepared.Contains(id)||prepared.Count>=4||!capacity.Wait(0))return false;
            prepared.Add(id);
        }
        ActorLease? placeholder=null;
        try
        {
            var work=journal.Read(id);
            placeholder=ActorLease.Unavailable(work.Observation,"prepared-work-placeholder");
            void RunPrepared()
            {
                try{DeliverPrepared(journal,id,spool,checkpoint,prepareTrust);}
                finally{lock(prepared)prepared.Remove(id);}
            }
            if(!queue.Writer.TryWrite(new(work.Observation,placeholder,work.Policy,_=>{},RunPrepared,returned)))throw new IOException("Forensic worker stopped; prepared work retained.");
            return true;
        }
        catch{placeholder?.Dispose();lock(prepared)prepared.Remove(id);ReleaseCapacity();throw;}
    }
    private void DeliverPrepared(LinuxForensicJournal journal,string id,EventSpool spool,Action<string>? checkpoint,Func<AgentEvent,ActorLease,EventTrust?>? prepareTrust)
    {
        if(journal.Read(id).Done)return;
        journal.RecoverVerifiedPrivateReceiptForDelivery(id);
        var originalBytes=journal.PrepareOriginal(id,work=>
        {
            using var actor=journal.RestoreActor(id);
            var provisional=work.Observation with{Forensics=journal.LinkPermissionReturnActor(work.Observation,journal.LinkIoReturnActor(work.Observation,collector.Begin(work.Observation,actor)))};
            if(prepareTrust==null)return provisional;
            using var entryActor=journal.RestoreIoTrustEntry(provisional);
            var result=LinuxPreparedTrustDecision.Apply(provisional,entryActor??actor,prepareTrust);
            if(result.Reason.StartsWith("LINUX_TRUST_PREPARATION_FAILED",StringComparison.Ordinal))error(result.Reason);
            return result.Event;
        },beforeCommit:()=>checkpoint?.Invoke("original-precommit"));
        checkpoint?.Invoke("original-prepared");spool.EnqueueExact(originalBytes);checkpoint?.Invoke("original-spooled");
        var completionBytes=journal.PrepareCompletion(id,work=>
        {
            var original=System.Text.Json.JsonSerializer.Deserialize<AgentEvent>(originalBytes)!;
            using var actor=journal.RestoreActor(id);
            var enriched=journal.LinkPermissionReturnActor(work.Observation,journal.LinkIoReturnActor(work.Observation,collector.Complete(original,actor,original.Forensics!,work.Policy)));
            var operation=enriched.Collection.State switch{"failed" or "unavailable"=>"Actor forensic evidence collection failed","partial"=>"Actor forensic evidence partially collected",_=>"Actor forensic evidence collected"};
            return original with{EventId=work.CompletionId,ObservedUtc=DateTimeOffset.UtcNow,Operation=operation,Source="Forensic enrichment",Trust=null,Forensics=collector.LinkCompletion(enriched,work.CompletionId)};
        });
        checkpoint?.Invoke("completion-prepared");spool.EnqueueExact(completionBytes);checkpoint?.Invoke("completion-spooled");
        var originalEvent=System.Text.Json.JsonSerializer.Deserialize<AgentEvent>(originalBytes)!;
        var completionEvent=System.Text.Json.JsonSerializer.Deserialize<AgentEvent>(completionBytes)!;
        uploads.Register(originalEvent,completionEvent);checkpoint?.Invoke("upload-registered");
        journal.MarkUploadedOrNotApplicable(id);checkpoint?.Invoke("work-finished");
    }
    public void Submit(AgentEvent value,ForensicPolicy policy,Action<AgentEvent> persistOriginal,Action<AgentEvent> persistCompletion,ActorLease? earlyActor=null,bool deferAtCapacity=false)
    {
        if(!capacity.Wait(0))
        {
            if(deferAtCapacity)throw new ForensicQueueCapacityException();
            using var overflow=earlyActor??ActorLease.Unavailable(value,"enrichment-queue-capacity-exceeded");var unavailable=collector.Begin(value,overflow);
            persistOriginal(value with{Forensics=unavailable with{Collection=new("unavailable","enrichment-queue-capacity-exceeded"),ActorExecutable=unavailable.ActorExecutable with{HashStatus=EvidenceStatus.Unavailable("enrichment-queue-capacity-exceeded")},Preservation=new(){SourceEventId=value.EventId,ProcessInstanceId=unavailable.Process.InstanceId,OriginalPath=value.Process,Status=new("failed","enrichment-queue-capacity-exceeded")},Detection=unavailable.Detection with{ReasonCodes=[..unavailable.Detection.ReasonCodes,"ENRICHMENT_QUEUE_CAPACITY_EXCEEDED"]}}});return;
        }
        ActorLease? actor=null;
        try
        {
            actor=earlyActor??ActorLease.Capture(value,sensor);var pending=collector.Begin(value,actor);
            var original=value with{Forensics=pending};persistOriginal(original);
            if(!queue.Writer.TryWrite(new(original,actor,policy,persistCompletion)))throw new IOException("Forensic worker stopped.");
        }
        catch{actor?.Dispose();ReleaseCapacity();throw;}
    }
    // Durable native intake already owns the raw event. Build its complete
    // publication on the intake dispatcher, outside the driver receive path,
    // using this pipeline's collector, cache and evidence store.
    public PreparedForensicPublication CollectForPublication(AgentEvent value,ActorLease actor,ForensicPolicy policy)
    {
        if(!capacity.Wait(0))throw new ForensicQueueCapacityException();
        try{
            var original=value with{Forensics=collector.Complete(value,actor,collector.Begin(value,actor),policy)};
            var id=Guid.NewGuid().ToString("N");
            var operation=original.Forensics.Collection.State switch{"failed" or "unavailable"=>"Actor forensic evidence collection failed","partial"=>"Actor forensic evidence partially collected",_=>"Actor forensic evidence collected"};
            var completion=original with{EventId=id,ObservedUtc=DateTimeOffset.UtcNow,Operation=operation,Source="Forensic enrichment",Trust=null,Forensics=collector.LinkCompletion(original.Forensics,id)};
            return new(original,completion);
        }
        finally{ReleaseCapacity();}
    }
    public void RegisterPublication(PreparedForensicPublication publication)=>uploads.Register(publication.Original,publication.Completion);
    private async Task Run()
    {
        await foreach(var item in queue.Reader.ReadAllAsync())
        {
            using(item.Actor)
            try
            {
                if(item.Prepared!=null){item.Prepared();continue;}
                ForensicEvidence enriched;
                try{enriched=collector.Complete(item.Original,item.Actor,item.Original.Forensics!,item.Policy);}
                catch(Exception ex)
                {
                    error("Forensic enrichment failed; recording a linked failure: "+ex.GetType().Name);
                    var pending=item.Original.Forensics!;
                    enriched=pending with{EnrichedUtc=DateTimeOffset.UtcNow,Collection=new("failed","actor-enrichment-worker-failed",ex.GetType().Name),ActorExecutable=pending.ActorExecutable with{HashStatus=EvidenceStatus.Unavailable("actor-enrichment-worker-failed")},Preservation=new(){SourceEventId=item.Original.EventId,ProcessInstanceId=pending.Process.InstanceId,OriginalPath=item.Original.Process,Status=new("failed","actor-enrichment-worker-failed")},Detection=pending.Detection with{ReasonCodes=[..pending.Detection.ReasonCodes,"ACTOR_ENRICHMENT_FAILED"]}};
                }
                var id=Guid.NewGuid().ToString("N");
                var operation=enriched.Collection.State switch{"failed" or "unavailable"=>"Actor forensic evidence collection failed","partial"=>"Actor forensic evidence partially collected",_=>"Actor forensic evidence collected"};
                var completed=item.Original with{EventId=id,ObservedUtc=DateTimeOffset.UtcNow,Operation=operation,Source="Forensic enrichment",Trust=null,Forensics=collector.LinkCompletion(enriched,id)};
                try{uploads.Register(item.Original,completed);}catch(Exception ex){error("Actor upload queue failed; local preservation retained: "+ex.GetType().Name);}
                item.Emit(completed);
            }
            catch(Exception ex){error("Forensic completion failed; original pending evidence retained: "+ex.GetType().Name);}
            finally
            {
                ReleaseCapacity();
                // Wake an owned dispatcher only after the shared permit is
                // really reusable. This callback conveys no successful result;
                // the dispatcher must inspect its durable work row.
                try{item.Returned?.Invoke();}
                catch(Exception ex){error("Forensic worker return notification failed: "+ex.GetType().Name);}
            }
        }
    }
    private void ReleaseCapacity()
    {
        capacity.Release();
        // Includes failed submissions: a waiting source must be woken even
        // when the unrelated producer returns its permit without queuing work.
        foreach(var callback in CapacityReturned?.GetInvocationList()??[])
            try{((Action)callback)();}catch(Exception ex){error("Forensic capacity notification failed: "+ex.GetType().Name);}
    }
    public async ValueTask DisposeAsync(){queue.Writer.TryComplete();await worker;capacity.Dispose();}
}
