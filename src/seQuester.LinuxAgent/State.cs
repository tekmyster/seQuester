using System.Security.Cryptography;
using System.Text.Json;
using System.Text.Json.Serialization;
using RansomFree;
using RansomFree.Contracts;

namespace RansomFree.LinuxAgent;

internal sealed record ClientConfiguration
{
    public int SchemaVersion {get;init;}=1;
    public string Server {get;init;}="";
    public Dictionary<string,string> Folders {get;init;}=[];
    public string Monitor {get;init;}=Platform.DefaultMonitor;
    public LinuxAuditOptions Audit {get;init;}=new();
    public RansomFree.Client.Forensics.LinuxNativeClientOptions NativeCompanion {get;init;}=new();
    public bool AllowRemoteProcessStop {get;init;}
    public bool AllowAutomaticProcessStop {get;init;}
    public SyslogOptions Syslog {get;init;}=new();
    public void Validate(string state)
    {
        if(SchemaVersion!=1 || Folders==null || Folders.Count>100 || !Platform.ValidMonitor(Monitor))throw new InvalidDataException("Unsupported client configuration.");
        if(Audit==null)throw new InvalidDataException("Missing Audit options.");Audit.Validate();
        if(NativeCompanion==null)throw new InvalidDataException("Missing native companion options.");NativeCompanion.Validate();
#if MACOS
        if(Audit.Enabled)throw new InvalidDataException("Linux Audit is unavailable on macOS.");
        if(NativeCompanion.Enabled)throw new InvalidDataException("Linux native companion is unavailable on macOS.");
#endif
        using var check=new RansomFree.Client.ManagementClient(Server);
        if(Syslog==null)throw new InvalidDataException("Invalid syslog configuration.");if(Syslog.Enabled)Syslog.Validate();
        foreach(var (alias,path) in Folders)
        {
            if(alias.Length is <1 or >64 || alias.Any(c=>!char.IsAsciiLetterOrDigit(c)&&c!='-'&&c!='_'))throw new InvalidDataException("Invalid local folder alias.");
            Paths.TargetFolder(path,state);
        }
        if(!Platform.SupportsResponse(Monitor)&&(AllowRemoteProcessStop||AllowAutomaticProcessStop))throw new InvalidDataException("Process response is unsupported in the selected platform/monitor mode.");
    }
}
internal sealed record Connection(string Server,string EndpointId,string Credential);
internal sealed record Canary(string Id,string Path,string Digest,string PlanDigest,bool Active,long Length,long ModifiedTicks);
internal sealed record Alert(DateTime Time,string Operation,string Path,string Process,string User,string Source)
{
    public string EventId {get;init;}=Guid.NewGuid().ToString("N");
    public string Product {get;init;}="RansomFree";
    public string Machine {get;init;}=Environment.MachineName;
    public int? ProcessId {get;init;}
    public bool Allowlisted {get;init;}
    [JsonIgnore(Condition=JsonIgnoreCondition.WhenWritingNull)]
    public EventAttribution? Attribution {get;init;}
    [JsonIgnore(Condition=JsonIgnoreCondition.WhenWritingNull)]
    public EventTrust? Trust {get;init;}
    [System.Text.Json.Serialization.JsonIgnore(Condition=System.Text.Json.Serialization.JsonIgnoreCondition.WhenWritingNull)]
    public RansomFree.Contracts.ForensicEvidence? Forensics {get;init;}
    [JsonIgnore(Condition=JsonIgnoreCondition.WhenWritingNull)]
    public int? PolicySyslogSeverity {get;init;}
}
internal sealed record LinuxAuditOptions
{
    public bool Enabled {get;init;}
    public bool CaptureCommandLine {get;init;}
    public int MaxInboxEvents {get;init;}=4096;
    public int MaxInboxMiB {get;init;}=64;
    public void Validate(){if(MaxInboxEvents is <128 or >16384||MaxInboxMiB is <8 or >256)throw new InvalidDataException("Audit inbox limits: 128–16384 events and 8–256 MiB.");}
}
internal static class Paths
{
    public static string NoLinks(string path)
    {
        if(!path.StartsWith('/') || path.Contains('\0') || path.Length>2048 || path.Any(char.IsControl) || path.Split('/').Any(x=>x is "." or ".."))throw new InvalidDataException("Use an explicit absolute Unix path of at most 2048 characters without dot segments.");
        path=Path.GetFullPath(path).TrimEnd('/');if(path.Length==0)throw new InvalidDataException("A filesystem root is not a valid application path.");
        for(string? parent=path;parent!=null;parent=Path.GetDirectoryName(parent))
            if(Path.Exists(parent)&&(File.GetAttributes(parent)&FileAttributes.ReparsePoint)!=0)throw new IOException("Path traverses a symbolic link; no change made.");
        return path;
    }
    public static string TargetFolder(string path,string state)
    {
        path=NoLinks(path);
        foreach(var denied in Platform.ProtectedPaths.Append(state))
            if(path==denied||path.StartsWith(denied+"/",StringComparison.Ordinal))throw new InvalidDataException("System, installation and private state paths are not deployment targets.");
        if(!Directory.Exists(path))throw new DirectoryNotFoundException("Locally approved folder must already exist.");return path;
    }
}
internal sealed class PrivateState
{
    public string Directory {get;}
    internal static readonly JsonSerializerOptions Json=new(){WriteIndented=true,UnmappedMemberHandling=JsonUnmappedMemberHandling.Disallow};
    public PrivateState(string directory)
    {
        Directory=Paths.NoLinks(directory);
        System.IO.Directory.CreateDirectory(Directory,UnixFileMode.UserRead|UnixFileMode.UserWrite|UnixFileMode.UserExecute);
        if((File.GetUnixFileMode(Directory)&(UnixFileMode.GroupRead|UnixFileMode.GroupWrite|UnixFileMode.GroupExecute|UnixFileMode.OtherRead|UnixFileMode.OtherWrite|UnixFileMode.OtherExecute))!=0)throw new IOException("Private state must have mode 0700 and be owned by the service identity.");
    }
    public string PathFor(string name)=>Paths.NoLinks(Path.Combine(Directory,name));
    public T? Read<T>(string name,int max=2097152)
    {
        var path=PathFor(name);if(!File.Exists(path))return default;
        if(new FileInfo(path).Length>max)throw new InvalidDataException("State exceeds its limit; original preserved.");
        if((File.GetUnixFileMode(path)&(UnixFileMode.GroupRead|UnixFileMode.GroupWrite|UnixFileMode.OtherRead|UnixFileMode.OtherWrite))!=0)throw new IOException("Private state file permissions are too broad.");
        return JsonSerializer.Deserialize<T>(File.ReadAllBytes(path),Json)??throw new InvalidDataException("Invalid state; original preserved.");
    }
    public void Save<T>(string name,T value,bool create=false)
    {
        var path=PathFor(name);var temp=PathFor(name+"."+Guid.NewGuid().ToString("N")+".tmp");
        using(var stream=new FileStream(temp,new FileStreamOptions{Mode=FileMode.CreateNew,Access=FileAccess.Write,Share=FileShare.None,UnixCreateMode=UnixFileMode.UserRead|UnixFileMode.UserWrite}))
        {JsonSerializer.Serialize(stream,value,Json);stream.Flush(true);}
        // A failed rename leaves a clearly named private recovery file, never overwrites an unrelated file.
        File.Move(temp,path,!create);
    }
    public FileStream Lease()=>new(PathFor("agent.lock"),FileMode.OpenOrCreate,FileAccess.ReadWrite,FileShare.None);
    public static string Hash(byte[] value)=>Convert.ToHexString(SHA256.HashData(value));
}
