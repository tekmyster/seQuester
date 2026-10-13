using System.ComponentModel;
using System.Diagnostics;
using System.Globalization;
using System.Runtime.InteropServices;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Xml.Linq;

namespace RansomFree;

internal static class AuditPolicy
{
    internal const FileSystemRights MonitoredRights=FileSystemRights.ReadData|FileSystemRights.WriteData|FileSystemRights.AppendData|FileSystemRights.Delete|FileSystemRights.ChangePermissions|FileSystemRights.TakeOwnership;
    internal static readonly Guid FileSystem = new("0CCE921D-69AE-11D9-BED3-505054503030");
    internal static readonly Guid Handles = new("0CCE9223-69AE-11D9-BED3-505054503030");
    internal static readonly Guid DetailedFileShare = new("0CCE9244-69AE-11D9-BED3-505054503030");
    [StructLayout(LayoutKind.Sequential)] private struct Policy { public Guid Subcategory; public uint Flags; public Guid Category; }
    [StructLayout(LayoutKind.Sequential)] private struct Luid { public uint Low; public int High; }
    [StructLayout(LayoutKind.Sequential)] private struct Privileges { public uint Count; public Luid Luid; public uint Attributes; }
    [DllImport("advapi32.dll", SetLastError=true)] private static extern bool OpenProcessToken(IntPtr process, uint access, out IntPtr token);
    [DllImport("advapi32.dll", CharSet=CharSet.Unicode, SetLastError=true)] private static extern bool LookupPrivilegeValue(string? system, string name, out Luid luid);
    [DllImport("advapi32.dll", SetLastError=true)] private static extern bool AdjustTokenPrivileges(IntPtr token, bool disable, ref Privileges state, uint size, IntPtr previous, IntPtr returned);
    [DllImport("kernel32.dll")] private static extern bool CloseHandle(IntPtr handle);
    [DllImport("advapi32.dll", SetLastError=true)] private static extern bool AuditQuerySystemPolicy(ref Guid id, uint count, out IntPtr policy);
    [DllImport("advapi32.dll", SetLastError=true)] private static extern bool AuditSetSystemPolicy(ref Policy policy, uint count);
    [DllImport("advapi32.dll")] private static extern void AuditFree(IntPtr buffer);

    public static void EnablePrivilege()
    {
        if (!OpenProcessToken(Process.GetCurrentProcess().Handle, 0x28, out var token)) throw new Win32Exception();
        try
        {
            if (!LookupPrivilegeValue(null, "SeSecurityPrivilege", out var luid)) throw new Win32Exception();
            var state = new Privileges { Count=1, Luid=luid, Attributes=2 };
            if (!AdjustTokenPrivileges(token, false, ref state, 0, IntPtr.Zero, IntPtr.Zero)) throw new Win32Exception();
            var error = Marshal.GetLastWin32Error();
            if (error != 0) throw new Win32Exception(error);
        }
        finally { CloseHandle(token); }
    }
    public static uint Read(Guid? subcategory=null)
    {
        var id=subcategory ?? FileSystem;
        if (!AuditQuerySystemPolicy(ref id, 1, out var p)) throw new Win32Exception();
        try { return Marshal.PtrToStructure<Policy>(p).Flags; } finally { AuditFree(p); }
    }
    public static void Set(uint flags, Guid? subcategory=null)
    {
        var policy = new Policy { Subcategory=subcategory ?? FileSystem, Flags=flags };
        if (!AuditSetSystemPolicy(ref policy, 1)) throw new Win32Exception();
    }
    public static void Attach(string path)
    {
        var file = new FileInfo(path);
        var security = file.GetAccessControl(AccessControlSections.Audit);
        security.AddAuditRule(new FileSystemAuditRule(new SecurityIdentifier(WellKnownSidType.WorldSid, null),
            MonitoredRights, AuditFlags.Success | AuditFlags.Failure));
        file.SetAccessControl(security);
    }
    public static bool IsAttached(string path)
    {
        var rules = new FileInfo(path).GetAccessControl(AccessControlSections.Audit).GetAuditRules(true, true, typeof(SecurityIdentifier));
        return HasRequiredCoverage(rules.Cast<FileSystemAuditRule>());
    }
    internal static bool HasRequiredCoverage(IEnumerable<FileSystemAuditRule> rules)
    {
        FileSystemRights success=0,failure=0;
        foreach(var rule in rules.Where(r=>r.IdentityReference.Value=="S-1-1-0"&&!r.PropagationFlags.HasFlag(PropagationFlags.InheritOnly))){
            if(rule.AuditFlags.HasFlag(AuditFlags.Success))success|=rule.FileSystemRights;
            if(rule.AuditFlags.HasFlag(AuditFlags.Failure))failure|=rule.FileSystemRights;
        }
        return(success&MonitoredRights)==MonitoredRights&&(failure&MonitoredRights)==MonitoredRights;
    }
}

internal record Alert(DateTime Time, string Operation, string Path, string Process, string User, string Source)
{
    public string Product { get; init; }="RansomFree";
    public string EventId { get; init; }=Guid.NewGuid().ToString("N");
    public string Machine { get; init; }=Environment.MachineName;
    public int? ProcessId { get; init; }
    public string? Executable { get; init; }
    public ProcessIdentity? Identity { get; init; }
    [System.Text.Json.Serialization.JsonIgnore]
    public IDisposable? ForensicLease {get;init;}
    public bool Allowlisted { get; init; }
    [System.Text.Json.Serialization.JsonIgnore(Condition=System.Text.Json.Serialization.JsonIgnoreCondition.WhenWritingNull)]
    public RansomFree.Contracts.EventTrust? Trust {get;init;}
    [System.Text.Json.Serialization.JsonIgnore(Condition=System.Text.Json.Serialization.JsonIgnoreCondition.WhenWritingNull)]
    public RansomFree.Contracts.ForensicEvidence? Forensics {get;init;}
    [System.Text.Json.Serialization.JsonIgnore(Condition=System.Text.Json.Serialization.JsonIgnoreCondition.WhenWritingNull)]
    public int? PolicySyslogSeverity {get;init;}
    [System.Text.Json.Serialization.JsonIgnore(Condition=System.Text.Json.Serialization.JsonIgnoreCondition.WhenWritingNull)]
    public string? UserSid {get;init;}
    [System.Text.Json.Serialization.JsonIgnore(Condition=System.Text.Json.Serialization.JsonIgnoreCondition.WhenWritingNull)]
    public string? UserAuthority {get;init;}
    public RansomFree.Contracts.EventAttribution? Attribution {get;init;}
}

internal static class AuditParser
{
    public static Alert? Parse(string xml, ISet<string> watched, int ownPid)
    {
        var root=XDocument.Parse(xml); XNamespace ns="http://schemas.microsoft.com/win/2004/08/events/event";
        var system=root.Root!.Element(ns+"System")!;
        var id=(int)system.Element(ns+"EventID")!;
        var data=root.Descendants(ns+"Data").ToDictionary(x=>(string)x.Attribute("Name")!, x=>x.Value);
        if(id==5145)return ParseShare(system,data,watched,ns);
        if (!data.TryGetValue("ObjectName", out var path) || !watched.Contains(path)) return null;
        data.TryGetValue("ProcessId", out var pid);
        var processId=Hex(pid);
        if (processId==(ulong)ownPid) return null;
        var processName=data.GetValueOrDefault("ProcessName", "");
        var subjectUser=data.GetValueOrDefault("SubjectUserName", "");
        var subjectDomain=data.GetValueOrDefault("SubjectDomainName", "");
        var pidText=pid?.StartsWith("0x",StringComparison.OrdinalIgnoreCase)==true?pid[2..]:pid;
        int? reportedPid=ulong.TryParse(pidText,NumberStyles.HexNumber,CultureInfo.InvariantCulture,out var parsedPid)&&parsedPid<=int.MaxValue?(int)parsedPid:null;
        var sid=data.GetValueOrDefault("SubjectUserSid");
        var account=string.IsNullOrWhiteSpace(subjectUser)?(!string.IsNullOrWhiteSpace(sid)&&sid!="S-1-0-0"?sid:"Unavailable"):
            string.IsNullOrWhiteSpace(subjectDomain)?subjectUser:subjectDomain+"\\"+subjectUser;
        data.TryGetValue("AccessMask", out var maskText); var mask=Hex(maskText);
        if ((mask & 0xD0007)==0) return null;
        var operations=new List<string>();
        if (id==4656)
        {
            var keyword=Hex(system.Element(ns+"Keywords")?.Value);
            operations.Add((keyword & 0x10000000000000)!=0 ? "Access denied" : "Open / access requested");
        }
        else if (id==4663)
        {
            if ((mask & 1)!=0) operations.Add("Content read (copy possible)");
            if ((mask & 6)!=0) operations.Add("Content written");
            if ((mask & 0x10000)!=0) operations.Add("Delete access used");
            if ((mask & 0xC0000)!=0) operations.Add("Permissions changed");
        }
        else return null;
        if (operations.Count==0) return null;
        var occurred=DateTime.TryParse(system.Element(ns+"TimeCreated")?.Attribute("SystemTime")?.Value,CultureInfo.InvariantCulture,DateTimeStyles.RoundtripKind,out var eventTime) ? eventTime.ToLocalTime() : DateTime.Now;
        var full=reportedPid is >0&&!string.IsNullOrWhiteSpace(processName)&&account!="Unavailable";
        var missing=new List<string>();
        if(reportedPid is null or 0)missing.Add("PID");
        if(string.IsNullOrWhiteSpace(processName))missing.Add("executable");
        if(account=="Unavailable")missing.Add("access subject");
        return new Alert(occurred, string.Join(", ", operations), path,
            string.IsNullOrWhiteSpace(processName)?"Unavailable":processName+(reportedPid!=null?$" (PID {reportedPid})":""),
            account,$"Windows audit {id}")
            { ProcessId=reportedPid, Executable=string.IsNullOrWhiteSpace(processName)?null:processName,UserSid=sid,UserAuthority=subjectDomain,
              Attribution=new(){Provider="Windows Security Audit",Level=full?"Full attribution":missing.Count==3?"Detection only":"Partial attribution",
                  Basis="Security event fields captured by Windows at access time; historical PID is not a live response handle."+(missing.Count>0?" Missing: "+string.Join(", ",missing)+".":""),
                  EvidenceId=system.Element(ns+"EventRecordID")?.Value,ProcessName=string.IsNullOrWhiteSpace(processName)?null:System.IO.Path.GetFileName(processName),
                  UserName=account=="Unavailable"?null:account,UserSid=sid,LogonId=data.GetValueOrDefault("SubjectLogonId"),AccessMask=maskText,EventTimeCredentials=account!="Unavailable",CompleteRecordSet=full,
                  Outcome=id==4656?(operations.Contains("Access denied")?"Failed":"Requested"):"Access right used"} };
    }
    private static ulong Hex(string? value) => ulong.TryParse(value?.Replace("0x", "", StringComparison.OrdinalIgnoreCase), NumberStyles.HexNumber, CultureInfo.InvariantCulture, out var n) ? n : 0;
    private static Alert? ParseShare(XElement system,Dictionary<string,string> data,ISet<string> watched,XNamespace ns)
    {
        // Use only the event's local share path. Never resolve a remote path or
        // probe the target, and reject traversal/absolute relative names.
        var local=data.GetValueOrDefault("ShareLocalPath");
        var relative=data.GetValueOrDefault("RelativeTargetName");
        if(local==null||relative==null||local.Length>2048||relative.Length>2048||local.Any(char.IsControl)||relative.Any(char.IsControl))return null;
        if(local.StartsWith(@"\??\",StringComparison.Ordinal))local=local[4..];
        else if(local.StartsWith(@"\\?\",StringComparison.Ordinal))local=local[4..];
        if(local.Length<3||!char.IsAsciiLetter(local[0])||local[1]!=':'||local[2]!='\\'||relative.StartsWith('\\')||relative.StartsWith('/')||relative.Contains(':')||relative.Split('\\','/').Any(p=>p is "." or ".."))return null;
        string path;
        try{path=Path.GetFullPath(Path.Combine(local,relative));}catch(ArgumentException){return null;}catch(NotSupportedException){return null;}
        if(!watched.Contains(path))return null;
        var maskText=data.GetValueOrDefault("AccessMask");
        if((Hex(maskText)&0xD0007)==0)return null;
        var sid=data.GetValueOrDefault("SubjectUserSid");
        var user=data.GetValueOrDefault("SubjectUserName");var domain=data.GetValueOrDefault("SubjectDomainName");
        var account=string.IsNullOrWhiteSpace(user)?sid:string.IsNullOrWhiteSpace(domain)?user:domain+"\\"+user;
        var keywords=Hex(system.Element(ns+"Keywords")?.Value);
        var denied=(keywords&0x10000000000000)!=0;var granted=!denied&&(keywords&0x20000000000000)!=0;
        var address=data.GetValueOrDefault("IpAddress");
        var rawAddress=address;
        if(!System.Net.IPAddress.TryParse(address,out var parsedAddress))address=null;
        else address=(parsedAddress.IsIPv4MappedToIPv6?parsedAddress.MapToIPv4():parsedAddress).ToString();
        int? port=int.TryParse(data.GetValueOrDefault("IpPort"),NumberStyles.None,CultureInfo.InvariantCulture,out var parsedPort)&&parsedPort is >=0 and <=65535?parsedPort:null;
        var share=new RansomFree.Contracts.WindowsShareEvidence{SourceAddress=address,RawSourceAddress=rawAddress,SourcePort=port,ShareName=data.GetValueOrDefault("ShareName"),ShareLocalPath=local,RelativeTargetName=relative,AccessReason=data.GetValueOrDefault("AccessReason"),AuthorizationOutcome=denied?"Denied":granted?"Granted":"Unknown"};
        if(!share.IsValid())throw new InvalidDataException("SMB audit evidence exceeds schema limits.");
        if(!DateTime.TryParse(system.Element(ns+"TimeCreated")?.Attribute("SystemTime")?.Value,CultureInfo.InvariantCulture,DateTimeStyles.RoundtripKind,out var time))throw new InvalidDataException("SMB audit timestamp unavailable.");
        return new Alert(time.ToLocalTime(),denied?"Share access denied":"Share access checked",path,"Unavailable: remote application not supplied by SMB audit",account??"Unavailable","Windows audit 5145"){
            UserSid=sid,UserAuthority=domain,
            Attribution=new(){Provider="Windows Security Audit",Level=account==null?"Detection only":"Partial attribution",Basis="SMB authenticated subject and source endpoint captured by Windows. Event 5145 does not supply the remote process/PID or thread token and does not establish completed NTFS I/O.",EvidenceId=system.Element(ns+"EventRecordID")?.Value,UserSid=sid,UserName=account,LogonId=data.GetValueOrDefault("SubjectLogonId"),AccessMask=maskText,EventTimeCredentials=sid!=null,CompleteRecordSet=false,Outcome=denied?"Failed":granted?"Share check granted":"Unknown",WindowsShare=share}
        };
    }
}
