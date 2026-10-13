using RansomFree;

namespace RansomFree.LinuxAgent;

// Independent forwarding queue. Management always receives the original event too.
internal sealed class UnixSyslogOutbox:IDisposable
{
    private sealed record Pending(string Id,Alert Alert,SyslogOptions Destination);
    private readonly PrivateState state;
    private readonly object gate=new();
    private List<Pending> queue;
    private readonly CancellationTokenSource stop=new();
    private readonly Task worker;
    private volatile bool enabled;
    public string LastStatus {get;private set;}="Idle";
    public int Count {get{lock(gate)return queue.Count;}}
    public UnixSyslogOutbox(PrivateState state,bool enabled)
    {
        this.state=state;this.enabled=enabled;
        queue=state.Read<List<Pending>>("unix-syslog.json",16*1024*1024)??[];
        if(queue.Count>1000||queue.Select(x=>x.Id).Distinct().Count()!=queue.Count)throw new InvalidDataException("Invalid syslog inventory; preserved.");
        foreach(var item in queue)item.Destination.Validate();
        worker=Task.Run(Work);
    }
    public void Enqueue(Alert alert,SyslogOptions options)
    {
        var observed=new RansomFree.Contracts.AgentEvent(alert.EventId,alert.Time.ToUniversalTime(),alert.Operation,alert.Path,alert.User,alert.Process,alert.ProcessId,alert.Source){Attribution=alert.Attribution,Trust=alert.Trust,Forensics=alert.Forensics};
        if(alert.Trust?.IsLogOnlyFor(observed)==true)return;
        if(!options.Enabled)return;options.Validate();
        lock(gate)
        {
            if(queue.Count>=1000)throw new IOException("Syslog queue full; management delivery remains independent.");
            var next=new List<Pending>(queue){new(alert.EventId,alert,options)};
            state.Save("unix-syslog.json",next);queue=next;
        }
    }
    public void SetEnabled(bool value){enabled=value;}
    private async Task Work()
    {
        while(!stop.IsCancellationRequested)
        {
            var delay=TimeSpan.FromSeconds(1);
            try
            {
                Pending? pending;lock(gate)pending=enabled?queue.FirstOrDefault():null;
                if(pending!=null)
                {
                    LastStatus=await SyslogClient.SendAsync(pending.Alert,pending.Destination,stop.Token);
                    lock(gate)
                    {
                        var next=queue.Where(x=>x.Id!=pending.Id).ToList();
                        state.Save("unix-syslog.json",next);queue=next;
                    }
                }
            }
            catch(OperationCanceledException) when(stop.IsCancellationRequested){break;}
            catch(Exception ex){LastStatus="Retry pending: "+ex.GetType().Name;delay=TimeSpan.FromSeconds(30);}
            try{await Task.Delay(delay,stop.Token);}catch(OperationCanceledException) when(stop.IsCancellationRequested){break;}
        }
    }
    public void Dispose(){stop.Cancel();worker.GetAwaiter().GetResult();stop.Dispose();}
}
