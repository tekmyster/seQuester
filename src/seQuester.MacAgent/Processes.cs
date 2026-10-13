using RansomFree.Contracts;

namespace RansomFree.LinuxAgent;

// Native ES evidence plus a task-control port: never a PID-only kill fallback.
internal sealed class ProcessEvidence:IDisposable
{
    public string Executable{get;}
    public string User{get;}
    private readonly string hash;
    private readonly uint[] token;
    private readonly int pid;
    private readonly DateTimeOffset captured;
    private bool disposed;
    public ProcessEvidence(Observation observation)
    {
        if(observation.Source!="macOS Endpoint Security"||observation.AuditToken is not {Length:8}||observation.Pid is null or <=4||observation.Executable==null||observation.User==null)throw new InvalidDataException("Native event identity unavailable.");
        pid=observation.Pid.Value;token=observation.AuditToken.ToArray();Executable=observation.Executable;User=observation.User;captured=new DateTimeOffset(observation.ObservedUtc);
        if(Native.TokenPid(token)!=pid)throw new InvalidDataException("Audit token PID mismatch.");
        using var input=Native.FileAt(Executable,false,256*1024*1024);hash=Native.HashBounded(input,256*1024*1024);
    }
    public bool Allowed(ManagedAllowRule[] rules,string path)=>rules.Any(r=>r.Executable==Executable&&r.Sha256.Equals(hash,StringComparison.OrdinalIgnoreCase)&&(r.ExpiresUtc==null||r.ExpiresUtc>DateTimeOffset.UtcNow)&&(r.Folder==null||path==r.Folder||path.StartsWith(r.Folder.TrimEnd('/')+"/",StringComparison.Ordinal)));
    public (string Outcome,string Message) Stop()
    {
        if(disposed||DateTimeOffset.UtcNow-captured>TimeSpan.FromMinutes(5)||Executable.StartsWith("/System/",StringComparison.Ordinal)||Executable.StartsWith("/usr/libexec/",StringComparison.Ordinal)||Executable.StartsWith("/usr/sbin/",StringComparison.Ordinal)||Executable.StartsWith("/sbin/",StringComparison.Ordinal))return("Rejected","Protected or stale process evidence; no action performed.");
        using(var input=Native.FileAt(Executable,false,256*1024*1024))if(Native.HashBounded(input,256*1024*1024)!=hash)return("Rejected","Executable hash changed; no action performed.");
        return Native.StopTask(pid,token);
    }
    public void Dispose(){disposed=true;}
}
