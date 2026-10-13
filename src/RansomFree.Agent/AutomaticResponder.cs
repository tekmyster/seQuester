using System.Text.Json;
using System.Threading.Channels;
using Microsoft.Extensions.Logging;
using RansomFree;
using RansomFree.Contracts;

internal sealed class AutomaticResponder:IAsyncDisposable
{
    private readonly Channel<Alert> queue=Channel.CreateBounded<Alert>(new BoundedChannelOptions(32){SingleReader=true,FullMode=BoundedChannelFullMode.Wait});
    private readonly CancellationTokenSource stop=new();
    private readonly Task worker;
    private readonly Func<AutomaticResponsePolicy> policy;
    private readonly ILogger log;
    private long lastQueueWarning;
    public AutomaticResponder(string directory,Func<AutomaticResponsePolicy> getPolicy,AgentConsoleState state,Action<Alert> publish,ILogger logger,Func<Alert,bool> trustAllowsResponse)
    {
        policy=getPolicy;log=logger;worker=Task.Run(async()=>
        {
            ResponseJournal journal;
            try{journal=new ResponseJournal(directory,"automatic-response-journal.json");}
            catch(Exception ex){logger.LogError("Automatic response journal unavailable ({Type}); automatic actions disabled.",ex.GetType().Name);return;}
            var attempts=new Queue<DateTimeOffset>();var processes=new Dictionary<(int,long),DateTimeOffset>();var warning=DateTimeOffset.MinValue;
            try
            {
                await foreach(var alert in queue.Reader.ReadAllAsync(stop.Token))
                {
                    try
                    {
                        var options=policy();var now=DateTimeOffset.UtcNow;
                        if(!options.Enabled || alert.Trust?.Result.Decision.SuppressResponse==true || alert.Identity==null || now-alert.Time.ToUniversalTime()>TimeSpan.FromSeconds(30) || alert.Time.ToUniversalTime()>DateTime.UtcNow.AddSeconds(5))continue;
                        var approval=Path.Combine(directory,"response-permissions.json");
                        var permitted=false;
                        if(File.Exists(approval) && new FileInfo(approval).Length<=4096){using var configuration=JsonDocument.Parse(File.ReadAllText(approval));permitted=configuration.RootElement.TryGetProperty("AllowAutomaticProcessStop",out var value)&&value.ValueKind==JsonValueKind.True;}
                        if(!permitted){if(now-warning>TimeSpan.FromMinutes(1)){publish(new(DateTime.Now,"Automatic response is not approved locally",alert.Path,"","","Agent response"));warning=now;}continue;}
                        var operation=alert.Operation;
                        if(!(options.OnRead&&operation.Contains("Content read (copy possible)",StringComparison.Ordinal) || options.OnWrite&&operation.Contains("Content written",StringComparison.Ordinal) || options.OnDelete&&operation.Contains("Delete access used",StringComparison.Ordinal) || options.OnPermissionChange&&operation.Contains("Permissions changed",StringComparison.Ordinal)))continue;
                        while(attempts.TryPeek(out var time)&&time<now.AddMinutes(-1))attempts.Dequeue();
                        foreach(var key in processes.Where(x=>x.Value<now.AddMinutes(-5)).Select(x=>x.Key).ToArray())processes.Remove(key);
                        var identity=(alert.Identity.Pid,alert.Identity.CreatedUtcFileTime);if(processes.ContainsKey(identity))continue;
                        if(attempts.Count>=options.MaxStopsPerMinute){if(now-warning>TimeSpan.FromMinutes(1)){publish(new(DateTime.Now,"Automatic response rate limit reached",alert.Path,"","","Agent response"));warning=now;}continue;}
                        stop.Token.ThrowIfCancellationRequested();if(policy()!=options||!trustAllowsResponse(alert))continue;attempts.Enqueue(now);processes[identity]=now;
                        var command=new ResponseCommand(Guid.NewGuid().ToString("N"),alert.EventId,"end-process","Automatic policy","Matched configured local audit operation",now,now.AddMinutes(1));
                        var result=journal.Execute(command,state,"AllowAutomaticProcessStop");
                        publish(new Alert(DateTime.Now,"Automatic response "+result.Outcome+": "+result.Message,alert.Path,alert.Process,alert.User,"Agent response"){ProcessId=alert.ProcessId,Executable=alert.Executable,Attribution=alert.Attribution?.WindowsSyscall!=null?alert.Attribution:null,Forensics=alert.Forensics is {} forensic?forensic with{Response=new("end-process",result.Outcome,alert.EventId)}:null});journal.Acknowledge(result.Id);
                    }
                    catch(OperationCanceledException) when(stop.IsCancellationRequested){break;}
                    catch(Exception ex){logger.LogError("Automatic response failed ({Type}); journal preserved and action is not blindly retried.",ex.GetType().Name);}
                }
            }
            catch(OperationCanceledException) when(stop.IsCancellationRequested){}
        });
    }
    public void Enqueue(Alert alert)
    {
        if(policy().Enabled && alert.Trust?.Result.Decision.SuppressResponse!=true && alert.Source=="Windows audit 4663" && alert.Identity!=null && !alert.Allowlisted && !queue.Writer.TryWrite(alert))
        {
            var now=DateTime.UtcNow.Ticks;var prior=Interlocked.Read(ref lastQueueWarning);
            if(now-prior>TimeSpan.TicksPerMinute && Interlocked.CompareExchange(ref lastQueueWarning,now,prior)==prior)log.LogWarning("Automatic response queue is full or unavailable; activity remains recorded but some response attempts were skipped.");
        }
    }
    public async ValueTask DisposeAsync(){queue.Writer.TryComplete();stop.Cancel();await worker;stop.Dispose();}
}
