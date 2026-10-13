using System.Security.Cryptography;
using RansomFree.Contracts;

namespace RansomFree.LinuxAgent;

internal sealed class ProcessEvidence:IDisposable
{
    public int Fd {get;private set;}
    public int Pid {get;}
    public string Executable {get;}
    public string Hash {get;}
    public string User {get;}
    private readonly bool privileged;
    public DateTimeOffset Captured {get;}
    public EventAttribution Attribution {get;}
    public ProcessEvidence(int fd,int pid,DateTime observedUtc,bool commandLine=false)
    {
        Fd=fd;Pid=pid;Captured=new DateTimeOffset(observedUtc);
        if(pid<=4||pid==Environment.ProcessId||!Native.IsAlive(fd))throw new InvalidDataException("Process identity unavailable.");
        Executable=Native.Link($"/proc/{pid}/exe")??throw new IOException("Executable unavailable.");
        if(Executable.EndsWith(" (deleted)",StringComparison.Ordinal))throw new IOException("Executable has been unlinked.");
        using(var input=File.OpenRead($"/proc/{pid}/exe"))Hash=Native.HashBounded(input,256*1024*1024);
        var status=File.ReadAllLines($"/proc/{pid}/status");
        var ids=status.First(x=>x.StartsWith("Uid:",StringComparison.Ordinal)).Split((char[]?)null,StringSplitOptions.RemoveEmptyEntries).Skip(1).ToArray();
        if(ids.Length!=4||ids.Any(x=>!uint.TryParse(x,out _)))throw new InvalidDataException("UID evidence unavailable.");
        User="uid:"+ids[0]+" euid:"+ids[1];
        string? start=null,command=null;int? parent=null;
        try
        {
            var stat=File.ReadAllText($"/proc/{pid}/stat");var parts=stat[(stat.LastIndexOf(')')+2)..].Split(' ',StringSplitOptions.RemoveEmptyEntries);
            if(parts.Length>19){start=parts[19];if(int.TryParse(parts[1],out var p)&&p>=0)parent=p;}
            if(commandLine){using var cmd=File.OpenRead($"/proc/{pid}/cmdline");var bytes=new byte[2048];var count=cmd.Read(bytes);command=new string(System.Text.Encoding.UTF8.GetString(bytes,0,count).Select(c=>char.IsControl(c)?' ':c).ToArray());}
        }
        catch{ /* Optional enrichment is not evidence of a different process. */ }
        Attribution=new(){Provider="fanotify + procfs",Level="Partial attribution",Basis="PIDFD bound to event process; UID, executable, hash and optional command line are later procfs observations, not event-time credentials.",
            UserId=uint.Parse(ids[0]),EffectiveUserId=uint.Parse(ids[1]),ParentProcessId=parent,ProcessStartTicks=start,ExecutableSha256=Hash,CommandLine=command,ProcessName=Path.GetFileName(Executable)};
        privileged=ids.Contains("0")||HasCapabilities(status);
        if(!Native.IsAlive(fd))throw new IOException("Process exited during capture.");
    }
    public bool Allowed(ManagedAllowRule[] rules,string path)=>rules.Any(r=>r.Executable==Executable&&r.Sha256.Equals(Hash,StringComparison.OrdinalIgnoreCase)&&(r.ExpiresUtc==null||r.ExpiresUtc>DateTimeOffset.UtcNow)&&(r.Folder==null||path==r.Folder||path.StartsWith(r.Folder.TrimEnd('/')+"/",StringComparison.Ordinal)));
    public (string Outcome,string Message) Stop()
    {
        if(privileged||Pid<=4||Pid==Environment.ProcessId||DateTimeOffset.UtcNow-Captured>TimeSpan.FromMinutes(5)||!Native.IsAlive(Fd))throw new InvalidOperationException("Protected, stale or exited process; no signal sent.");
        var status=File.ReadAllLines($"/proc/{Pid}/status");
        if(status.First(x=>x.StartsWith("Uid:",StringComparison.Ordinal)).Split((char[]?)null,StringSplitOptions.RemoveEmptyEntries).Skip(1).Contains("0")||HasCapabilities(status))throw new InvalidOperationException("Process became privileged; no signal sent.");
        if(Native.Link($"/proc/{Pid}/exe")!=Executable)throw new InvalidOperationException("Executable changed; no signal sent.");
        using(var input=File.OpenRead($"/proc/{Pid}/exe"))if(Native.HashBounded(input,256*1024*1024)!=Hash)throw new InvalidOperationException("Executable hash changed; no signal sent.");
        if(!Native.Signal(Fd,15))throw new IOException("SIGTERM failed; no success assumed.");
        return Native.WaitForExit(Fd)?("Succeeded","SIGTERM sent; exit confirmed on the event-bound pidfd."):("Indeterminate","SIGTERM sent to event-bound pidfd; process exit is not confirmed within two seconds.");
    }
    public void Dispose(){if(Fd>=0)Native.close(Fd);Fd=-1;}
    private static bool HasCapabilities(string[] status)
    {
        var fields=status.Where(x=>x.StartsWith("CapEff:",StringComparison.Ordinal)||x.StartsWith("CapPrm:",StringComparison.Ordinal)).ToArray();
        return fields.Length!=2||fields.Any(x=>!ulong.TryParse(x.Split(':')[1].Trim(),System.Globalization.NumberStyles.HexNumber,null,out var value)||value!=0);
    }
}
