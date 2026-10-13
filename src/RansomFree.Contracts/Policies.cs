namespace RansomFree.Contracts;

public sealed record MonitoringPolicy(int IntegrityIntervalSeconds)
{
    public CanaryDeployment[] Deployments { get; init; }=[];
    public ManagedSyslog? Syslog {get;init;}
    public ManagedAllowRule[] Allowlist {get;init;}=[];
    public AutomaticResponsePolicy AutomaticResponse {get;init;}=new();
    [System.Text.Json.Serialization.JsonIgnore(Condition=System.Text.Json.Serialization.JsonIgnoreCondition.WhenWritingNull)]
    public ActiveResponsePolicy? ActiveResponse {get;init;}
    public EventQueuePolicy EventQueue {get;init;}=new();
    [System.Text.Json.Serialization.JsonIgnore(Condition=System.Text.Json.Serialization.JsonIgnoreCondition.WhenWritingNull)]
    public ForensicPolicy? Forensics {get;init;}
    public static MonitoringPolicy Default=>new(15);
    public bool IsValid()=>IntegrityIntervalSeconds is >=15 and <=3600 && IntegrityIntervalSeconds%15==0 &&
        (Forensics==null||Forensics.IsValid())&&(ActiveResponse==null||ActiveResponse.IsValid())&&EventQueue!=null && EventQueue.IsValid() && AutomaticResponse!=null && AutomaticResponse.IsValid() && (Syslog==null || Syslog.IsValid()) && Allowlist is {Length:<=100} && Allowlist.All(x=>x!=null && x.IsValid()) &&
        Deployments is {Length:<=100} && Deployments.All(x=>x!=null && x.IsValid()) &&
        Deployments.Select(x=>x.Id).Distinct(StringComparer.Ordinal).Count()==Deployments.Length &&
        Deployments.Select(x=>x.FolderAlias+"/"+(x.FileName.EndsWith("."+x.FileType,StringComparison.OrdinalIgnoreCase)?x.FileName:x.FileName+"."+x.FileType)).Distinct(StringComparer.OrdinalIgnoreCase).Count()==Deployments.Length;
    public bool SameContent(MonitoringPolicy other)=>IntegrityIntervalSeconds==other.IntegrityIntervalSeconds && Forensics==other.Forensics && EventQueue==other.EventQueue && AutomaticResponse==other.AutomaticResponse && (ActiveResponse==null?other.ActiveResponse==null:other.ActiveResponse!=null&&ActiveResponse.SameContent(other.ActiveResponse)) && Syslog==other.Syslog && Allowlist.SequenceEqual(other.Allowlist) && Deployments.SequenceEqual(other.Deployments);
}
public sealed record EventQueuePolicy(int MaxEvents=10000,int MaxPayloadMiB=128)
{
    public bool IsValid()=>MaxEvents is >=1000 and <=1000000 && MaxPayloadMiB is >=32 and <=1024;
    public long MaxPayloadBytes=>(long)MaxPayloadMiB*1024*1024;
}
public sealed record AutomaticResponsePolicy(bool Enabled=false,bool OnRead=false,bool OnWrite=true,bool OnDelete=true,bool OnPermissionChange=false,int MaxStopsPerMinute=3)
{
    public bool IsValid()=>MaxStopsPerMinute is >=1 and <=10 && (!Enabled || OnRead || OnWrite || OnDelete || OnPermissionChange);
}
public sealed record ManagedSyslog(bool Enabled,string Host,int Port=514,string Transport="TCP",string Format="RFC3164",bool OctetCounting=false,int Facility=16,int Severity=4)
{
    public bool IsValid()=>Host!=null && Host.Length<=253 && (!Enabled || Uri.CheckHostName(Host)!=UriHostNameType.Unknown) && !Host.Any(char.IsControl) && Port is >=1 and <=65535 && new[]{"UDP","TCP","TLS"}.Contains(Transport) && new[]{"RFC3164","RFC5424"}.Contains(Format) && Facility is >=0 and <=23 && Severity is >=0 and <=7;
}
public sealed record ManagedAllowRule(string Executable,string Sha256,string? Folder=null,DateTimeOffset? ExpiresUtc=null)
{
    public bool IsValid()=>(WindowsPath(Executable)||UnixPath(Executable)) && Sha256 is {Length:64} && Sha256.All(Uri.IsHexDigit) && (Folder==null || WindowsPath(Folder)||UnixPath(Folder));
    private static bool UnixPath(string? value)=>value is {Length:>=2 and <=1024} && value.StartsWith('/') && !value.EndsWith('/') && !value.Any(char.IsControl) && !value.Contains('\\') && !value.Split('/').Skip(1).Any(x=>x is "" or "." or "..");
    private static bool WindowsPath(string? value)=>value is {Length:>=4 and <=1024} && char.IsAsciiLetter(value[0]) && value[1]==':' && value[2]=='\\' && !value.Any(char.IsControl) && value.IndexOfAny(['*','?','"','<','>','|','/'])<0 && !value[2..].Contains(':') && !value.Split('\\').Any(x=>x is "." or "..");
}
public sealed record CanaryDeployment(string Id,string FolderAlias,string FileName,string FileType)
{
    public string? CallbackTokenId {get;init;}
    public string? CallbackUrl {get;init;}
    public static readonly string[] SupportedTypes=["docx","xlsx","pdf","txt","csv","rtf","html","svg","json","xml","md"];
    public bool IsValid()
    {
        if(!Guid.TryParseExact(Id,"N",out _) || string.IsNullOrEmpty(FolderAlias) || FolderAlias.Length>64 ||
            FolderAlias.Any(c=>!char.IsAsciiLetterOrDigit(c) && c!='-' && c!='_') ||
            string.IsNullOrWhiteSpace(FileName) || FileName.Length>160 || FileName!=FileName.Trim() ||
            FileName.Any(c=>char.IsControl(c) || "<>:\"/\\|?*".Contains(c)) || FileName.EndsWith('.') ||
            !SupportedTypes.Contains(FileType))return false;
        if(CallbackTokenId!=null && (CallbackTokenId.Length!=48 || !CallbackTokenId.All(Uri.IsHexDigit)))return false;
        if(CallbackUrl!=null && (CallbackTokenId==null || CallbackUrl.Length>2048 || CallbackUrl.Any(char.IsControl) || !Uri.TryCreate(CallbackUrl,UriKind.Absolute,out var uri) || uri.Scheme!="https" || uri.UserInfo.Length!=0 || uri.Fragment.Length!=0 || !new[]{"docx","xlsx","pdf","svg","html"}.Contains(FileType)))return false;
        var stem=FileName.Split('.')[0].ToUpperInvariant();
        return !new[]{"CON","PRN","AUX","NUL","CLOCK$"}.Contains(stem) &&
            !(stem.Length==4 && (stem.StartsWith("COM") || stem.StartsWith("LPT")) && "123456789¹²³".Contains(stem[3]));
    }
}
public sealed record AssignedPolicy(string? GroupId,long Revision,MonitoringPolicy Settings);
public sealed record PolicyReceipt(string? GroupId,long Revision)
{
    [System.Text.Json.Serialization.JsonIgnore(Condition=System.Text.Json.Serialization.JsonIgnoreCondition.WhenWritingDefault)]
    public int ForensicsVersion {get;init;}
}
public sealed record EndpointGroup(string Id,string Name,long Revision,MonitoringPolicy Settings,long EndpointCount);
public sealed record EndpointPolicyStatus(string EndpointId,string? GroupId,long DesiredRevision,long? AppliedRevision,DateTimeOffset? ReportedUtc);
