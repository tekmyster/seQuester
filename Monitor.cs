using System.Diagnostics.Eventing.Reader;
using System.Security.Cryptography;
using System.Text.Json;

namespace RansomFree;

internal record Canary(string Path, string Hash)
{
    public string? ManagedId {get;init;}
    public string? ManagedSignature {get;init;}
    public string Tripwire { get; init; }="Local monitoring only";
}
internal sealed class Settings
{
    public List<Canary> Canaries { get; set; } = [];
    public uint? OriginalAuditPolicy { get; set; }
    public uint? OriginalHandlePolicy { get; set; }
    public uint? OriginalDetailedSharePolicy {get;set;}
    public bool MonitorSmbShares {get;set;}
    public SyslogOptions Syslog { get; set; }=new();
    public List<AllowRule> Allowlist { get; set; }=[];
    public PasswordSettings? Password { get; set; }
}
internal sealed class CanaryMonitor : IDisposable
{
    public static readonly string DataDirectory=Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "RansomFree");
    private readonly string config;
    public Settings Settings { get; }
    private readonly List<FileSystemWatcher> watchers=[];
    private EventLogWatcher? audit;
    private readonly HashSet<string> watched=new(StringComparer.OrdinalIgnoreCase);
    private readonly Dictionary<string,string> lastState=new(StringComparer.OrdinalIgnoreCase);
    private readonly object gate=new();
    private volatile bool watchersHealthy;
    public event Action<Alert>? Alerted;
    public Func<Alert,IDisposable?>? CaptureForensics {get;set;}
    public event Action<string>? HealthChanged;
    public bool AuditConnected { get; private set; }
    public bool WatchersHealthy => watchersHealthy;
    public string[] WatchedPaths(){lock(gate)return watched.ToArray();}
    public (int DeployedItems,bool IntegrityHealthy)? ProtectionEvidence()
    {
        lock(gate)
        {
            var states=Settings.Canaries.Select(c=>lastState.GetValueOrDefault(c.Path)).ToArray();
            return CanaryEvidence.Summarize(states);
        }
    }
    public CanaryMonitor(string? directory=null)
    {
        directory ??= DataDirectory;
        Directory.CreateDirectory(directory);
        config=Path.Combine(directory,"settings.json");
        Settings=File.Exists(config) ? JsonSerializer.Deserialize<Settings>(File.ReadAllText(config)) ?? throw new InvalidDataException("Invalid settings") : new();
    }
    public void Save()
    {
        var temp=config+".tmp";
        File.WriteAllText(temp, JsonSerializer.Serialize(Settings, new JsonSerializerOptions { WriteIndented=true }));
        File.Move(temp,config,true);
    }
    public void EnableAuditing()
    {
        AuditPolicy.EnablePrivilege();
        var original=AuditPolicy.Read();
        Settings.OriginalAuditPolicy ??= original;
        var handles=AuditPolicy.Read(AuditPolicy.Handles);
        Settings.OriginalHandlePolicy ??= handles;
        Save();
        AuditPolicy.Set((original & ~4u) | 3u);
        AuditPolicy.Set((handles & ~4u) | 3u, AuditPolicy.Handles);
        if ((AuditPolicy.Read() & 3)!=3) throw new InvalidOperationException("Windows did not enable file access auditing.");
    }
    private void EnableShareAuditing()
    {
        // Windows enables this policy host-wide; only monitored exact file paths
        // are emitted by our parser. Persist the original before changing it.
        var original=AuditPolicy.Read(AuditPolicy.DetailedFileShare);
        if(Settings.OriginalDetailedSharePolicy==null){Settings.OriginalDetailedSharePolicy=original;Save();}
        AuditPolicy.Set((original&~4u)|3u,AuditPolicy.DetailedFileShare);
        if((AuditPolicy.Read(AuditPolicy.DetailedFileShare)&3)!=3)throw new InvalidOperationException("Windows did not enable SMB share auditing.");
    }
    public void Deploy(string directory, IReadOnlyList<CanarySpec>? specifications=null)
    {
        directory=Path.GetFullPath(directory);
        if (!Directory.Exists(directory)) throw new DirectoryNotFoundException(directory);
        using var deploymentLease=DeploymentPathLease.Acquire(directory);
        if ((File.GetAttributes(directory)&FileAttributes.ReparsePoint)!=0) throw new IOException("Select a local folder rather than a link or junction.");
        var win=Environment.GetFolderPath(Environment.SpecialFolder.Windows).TrimEnd('\\');
        if (directory.Equals(win,StringComparison.OrdinalIgnoreCase) || directory.StartsWith(win+"\\",StringComparison.OrdinalIgnoreCase))
            throw new IOException("Choose a data folder outside the Windows directory.");
        var suffix=Guid.NewGuid().ToString("N")[..6];
        specifications ??= [new($"!_Account_Recovery_{suffix}","docx"),new($"Financial_Records_{suffix}","xlsx"),new($"zz_Confidential_Archive_{suffix}","pdf")];
        if(specifications.Count is <1 or >100) throw new ArgumentException("Choose between 1 and 100 canary files.");
        var names=specifications.Select(CanaryTemplates.FileName).ToArray();
        if(names.Distinct(StringComparer.OrdinalIgnoreCase).Count()!=names.Length) throw new ArgumentException("Canary filenames must be unique within the folder.");
        foreach(var name in names) if(File.Exists(Path.Combine(directory,name)) || Directory.Exists(Path.Combine(directory,name))) throw new IOException("Already exists: "+name+". Choose another name.");
        // Validate/read every source before enabling audit policy or writing any destination.
        var payloads=new List<byte[]>(); long total=0;
        foreach(var spec in specifications)
        {
            var payload=CanaryTemplates.Render(spec); total+=payload.Length;
            if(total>64*1024*1024) throw new InvalidDataException("Deploy at most 64 MiB per batch.");
            payloads.Add(payload);
        }
        EnableAuditing();
        for(var i=0;i<names.Length;i++)
        {
            var path=Path.Combine(directory,names[i]);
            using var stream=new FileStream(path,FileMode.CreateNew,FileAccess.Write,FileShare.Read);
                stream.Write(payloads[i]);
            stream.Flush(true);
            // Persist ownership before applying the audit rule, so partial setup remains visible.
            var spec=specifications[i];
            Settings.Canaries.Add(new Canary(path,Convert.ToHexString(SHA256.HashData(payloads[i]))) {ManagedId=spec.ManagedId,ManagedSignature=spec.ManagedSignature,Tripwire=!string.IsNullOrWhiteSpace(spec.SourcePath)?"Imported; callback unverified":
                !string.IsNullOrWhiteSpace(spec.CallbackUrl)?"HTTPS resource; callback unverified":"Local monitoring only"}); Save();
            AuditPolicy.Attach(path);
        }
    }
    public static string Hash(string path)
    {
        using var stream=new FileStream(path,FileMode.Open,FileAccess.Read,FileShare.ReadWrite|FileShare.Delete);
        return Convert.ToHexString(SHA256.HashData(stream));
    }
    public void Start()
    {
        Stop();
        watchersHealthy=true;
        lock(gate) { watched.Clear(); foreach(var c in Settings.Canaries) watched.Add(c.Path); }
        try
        {
            AuditPolicy.EnablePrivilege();
            if(Settings.MonitorSmbShares)EnableShareAuditing();
            audit=new EventLogWatcher(new EventLogQuery("Security",PathType.LogName,Settings.MonitorSmbShares?"*[System[(EventID=4656 or EventID=4663 or EventID=5145)]]":"*[System[(EventID=4656 or EventID=4663)]]"));
            audit.EventRecordWritten+=OnAudit;
            audit.Enabled=true;
            AuditConnected=true;
        }
        catch(Exception ex) { AuditConnected=false; HealthChanged?.Invoke("Access monitoring unavailable: "+ex.Message); }
        foreach(var folder in Settings.Canaries.Select(c=>Path.GetDirectoryName(c.Path)!).Distinct(StringComparer.OrdinalIgnoreCase))
        {
            try
            {
                var w=new FileSystemWatcher(folder) { NotifyFilter=NotifyFilters.FileName|NotifyFilters.LastWrite|NotifyFilters.Size|NotifyFilters.Security, InternalBufferSize=16384 };
                w.Changed+=(_,e)=>OnFile("File changed",e.FullPath);
                w.Deleted+=(_,e)=>OnFile("File deleted",e.FullPath);
                w.Created+=(_,e)=>OnFile("File created / replaced",e.FullPath);
                w.Renamed+=(_,e)=> { OnFile("File renamed to "+e.Name,e.OldFullPath,e.OldFullPath,e.FullPath); OnFile("File replaced by rename",e.FullPath,e.OldFullPath,e.FullPath); };
                w.Error+=(_,e)=>{watchersHealthy=false;HealthChanged?.Invoke("File watcher gap: "+e.GetException().Message+". Integrity checks remain active.");};
                w.EnableRaisingEvents=true; watchers.Add(w);
            }
            catch(Exception ex) { watchersHealthy=false;HealthChanged?.Invoke("Folder monitoring unavailable: "+ex.Message); }
        }
    }
    private void OnAudit(object? sender,EventRecordWrittenEventArgs e)
    {
        if(e.EventException!=null) { AuditConnected=false; HealthChanged?.Invoke("Audit subscription failed: "+e.EventException.Message); return; }
        using var record=e.EventRecord;
        if(record==null) return;
        try
        {
            Alert? alert;
            lock(gate) alert=AuditParser.Parse(record.ToXml(),watched,Environment.ProcessId);
            if(alert!=null)
            {
                if(CaptureForensics!=null&&alert.Source!="Windows audit 5145")alert=alert with{ForensicLease=CaptureForensics(alert)};
                // Capture on the audit worker before queuing the UI event, to reduce attribution races.
                if(alert.ProcessId is >0 && alert.Executable!=null)
                    alert=alert with { Identity=ProcessControls.Capture(alert.ProcessId.Value,alert.Executable,alert.Time.ToUniversalTime()) };
                Alerted?.Invoke(alert);
            }
        }
        catch(Exception ex) { HealthChanged?.Invoke("Could not process audit event: "+ex.Message); }
    }
    private void OnFile(string operation,string path,string? renameSource=null,string? renameDestination=null)
    {
        lock(gate) { if(!watched.Contains(path)) return; }
        // FileSystemWatcher has no actor identity. Retain its detection as partial
        // evidence; Windows Security 4656/4663 may add a fully attributed event.
        Alerted?.Invoke(new Alert(DateTime.Now,operation,path,"Unavailable for change notifications","Unavailable for change notifications","File watcher"){Attribution=renameSource==null?null:new(){Provider="File watcher",Level="Detection only",Basis="Rename notification has no actor or completed byte counts.",RenameSource=renameSource,RenameDestination=renameDestination}});
        if(!AuditConnected)HealthChanged?.Invoke("Local file activity recorded without actor attribution because Windows audit is unavailable.");
    }
    public void CheckIntegrity()
    {
        foreach(var c in Settings.Canaries.ToArray())
        {
            string state;
            try { state=!File.Exists(c.Path) ? "Missing" : Hash(c.Path)!=c.Hash ? "Content changed / possible encryption" : !AuditPolicy.IsAttached(c.Path) ? "Audit rule missing" : "Healthy"; }
            catch(Exception ex) { state="Cannot verify: "+ex.Message; }
            bool changed;
            lock(gate){changed=state!="Healthy" && lastState.GetValueOrDefault(c.Path)!=state;lastState[c.Path]=state;}
            if(changed)
            {
                Alerted?.Invoke(new(DateTime.Now,$"Canary integrity changed: {state}",c.Path,"Unavailable for integrity checks","Unavailable for integrity checks","Integrity check"));
                if(!AuditConnected)HealthChanged?.Invoke($"Canary integrity change recorded without actor attribution because Windows audit is unavailable ({state}).");
            }
        }
        try { if(((AuditPolicy.Read()&3)!=3 || (AuditPolicy.Read(AuditPolicy.Handles)&3)!=3) && Settings.Canaries.Count>0) HealthChanged?.Invoke("Windows file access auditing is disabled or incomplete. Use Repair monitoring."); }
        catch(Exception ex) { HealthChanged?.Invoke("Cannot verify audit policy: "+ex.Message); }
        if(Settings.MonitorSmbShares)try{if((AuditPolicy.Read(AuditPolicy.DetailedFileShare)&3)!=3)HealthChanged?.Invoke("SMB share auditing is disabled or incomplete; remote share coverage degraded.");}catch(Exception ex){HealthChanged?.Invoke("Cannot verify SMB audit policy: "+ex.Message);}
    }
    public void Repair()
    {
        EnableAuditing();
        foreach(var c in Settings.Canaries.Where(c=>File.Exists(c.Path))) AuditPolicy.Attach(c.Path);
        Start();
    }
    private void Stop()
    {
        if(audit!=null) { audit.EventRecordWritten-=OnAudit; audit.Dispose(); audit=null; }
        AuditConnected=false;
        watchersHealthy=false;
        foreach(var w in watchers) w.Dispose(); watchers.Clear();
    }
    public void Dispose()=>Stop();
}
