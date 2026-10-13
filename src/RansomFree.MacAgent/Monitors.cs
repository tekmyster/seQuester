using RansomFree.LinuxAgent.EndpointSecurity;

namespace RansomFree.LinuxAgent;

internal sealed record Observation(string Path,string Operation,string Source,int? Pid=null,int PidFd=-1,string? Executable=null,string? User=null,uint[]? AuditToken=null)
{public DateTime ObservedUtc{get;init;}=DateTime.UtcNow;public string? EventId {get;init;} public RansomFree.Contracts.EventAttribution? Attribution {get;init;}}

// FSEvents detects changes only. Native selection stays unavailable until SDK verification.
internal sealed class LinuxMonitors:IDisposable
{
    private readonly Dictionary<string,FileSystemWatcher> watchers=new(StringComparer.Ordinal);
    private HashSet<string> paths=new(StringComparer.Ordinal);
    private readonly Action<Observation> publish;
    private readonly string mode;
    private readonly EndpointSecuritySensor sensor;
    private volatile bool disposed, fallbackFailed;
    public string Mode => ((mode=="fsevents"&&!disposed ? new SensorStatus(SensorState.FallbackOnly) : sensor.Status)
        with { FallbackRunning = !disposed && !fallbackFailed && watchers.Count > 0 }).Display;
    public LinuxMonitors(string mode,Action<Observation> publish)
    {
        if(mode is not ("fsevents" or "endpoint-security"))throw new ArgumentException("Unknown macOS monitor mode.",nameof(mode));
        this.mode=mode;this.publish=publish;
        sensor=new(new UnavailableNativeProvider(),new FileEvidenceStore(Path.Combine(Platform.DataPath,"endpoint-security-evidence")),mapped=>
        {
            if(Volatile.Read(ref paths).Contains(mapped.Path))
                publish(new(mapped.Path,mapped.Operation,"macOS Endpoint Security",mapped.Pid,-1,mapped.Executable)
                {EventId=mapped.EventId,ObservedUtc=mapped.Time.UtcDateTime,Attribution=mapped.Attribution});
        });
        if(mode=="endpoint-security")sensor.Start();
    }
    public void RequireRequestedCoverage()
    {
        if(mode=="endpoint-security"&&!sensor.Status.RequestedCoverageAvailable)
            throw new InvalidOperationException(sensor.Status.Summary+" Policy remains pending; FSEvents detection continues.");
    }
    public void Update(IEnumerable<Canary> canaries)
    {
        ObjectDisposedException.ThrowIf(disposed,this);
        var items=canaries.Where(x=>x.Active).Select(x=>x.Path).Order(StringComparer.Ordinal).ToArray();
        Volatile.Write(ref paths,items.ToHashSet(StringComparer.Ordinal));
        foreach(var folder in items.Select(x=>Path.GetDirectoryName(x)!).Distinct())
        {
            if(watchers.ContainsKey(folder))continue;
            var watcher=new FileSystemWatcher(Paths.NoLinks(folder)){IncludeSubdirectories=false,NotifyFilter=NotifyFilters.FileName|NotifyFilters.LastWrite|NotifyFilters.Size|NotifyFilters.Security,InternalBufferSize=65536};
            watcher.Created+=(_,e)=>Notice(e.FullPath,"Canary path created/replaced");
            watcher.Deleted+=(_,e)=>Notice(e.FullPath,"Canary deleted");
            watcher.Changed+=(_,e)=>Notice(e.FullPath,"Canary content/metadata changed");
            watcher.Renamed+=(_,e)=>{Notice(e.OldFullPath,"Canary moved/renamed");Notice(e.FullPath,"Canary path moved/replaced");};
            watcher.Error+=(_,_)=>{fallbackFailed=true;SafePublish(new(folder,"File change evidence lost; restart monitoring and inspect diagnostics.","macOS monitor health"));};
            try{watcher.EnableRaisingEvents=true;watchers.Add(folder,watcher);}catch{watcher.Dispose();fallbackFailed=true;throw;}
        }
    }
    private void SafePublish(Observation item){try{publish(item);}catch{fallbackFailed=true;}}
    private void Notice(string path,string operation){if(!disposed&&Volatile.Read(ref paths).Contains(path))SafePublish(new(path,operation,"macOS FSEvents"));}
    public void Dispose(){if(disposed)return;disposed=true;foreach(var watcher in watchers.Values)watcher.Dispose();sensor.Dispose();}
}
