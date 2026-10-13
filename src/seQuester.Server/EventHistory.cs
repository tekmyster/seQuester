using System.Globalization;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Microsoft.AspNetCore.DataProtection;
using RansomFree.Contracts;

namespace RansomFree.Server;

public sealed record EventHistoryQuery
{
    public string Sort {get;init;}="observed";
    public string Direction {get;init;}="desc";
    public int Limit {get;init;}=50;
    public string? Cursor {get;init;}
    public string? Endpoint {get;init;}
    public string? Host {get;init;}
    public string? Os {get;init;}
    public string? Ip {get;init;}
    public DateTimeOffset? From {get;init;}
    public DateTimeOffset? To {get;init;}
    public string? Notification {get;init;}
    public string? Action {get;init;}
    public string? User {get;init;}
    public string? UserContains {get;init;}
    public string? Process {get;init;}
    public string? ProcessContains {get;init;}
    public int? Pid {get;init;}
    public long? Uid {get;init;}
    public int? ParentPid {get;init;}
    public string? Provider {get;init;}
    public string? Source {get;init;}
    public string? Operation {get;init;}
    public string? Path {get;init;}
    public string? PathContains {get;init;}
    public static readonly string[] Sorts=["observed","action","host","operation","path","user","process","pid","sequence","endpoint","uid","parentPid","provider","source"];
    public bool Numeric=>Sort is "observed" or "pid" or "sequence" or "uid" or "parentPid";
    public void Validate()
    {
        if(!Sorts.Contains(Sort,StringComparer.Ordinal)||Direction is not ("asc" or "desc")||Limit is <1 or >500||Cursor?.Length>16384
            ||Pid is <0||ParentPid is <0||Uid is <0 or >uint.MaxValue
            ||Endpoint!=null&&!Guid.TryParseExact(Endpoint,"N",out _))throw new ArgumentException("Invalid history query.");
        if(Os is not (null or "windows" or "linux" or "macos" or "unknown")||Notification is not (null or "info" or "normal" or "alert" or "warning" or "high" or "critical" or "unclassified")||From>To||Ip!=null&&!System.Net.IPAddress.TryParse(Ip,out _))throw new ArgumentException("Invalid history filter.");
        foreach(var value in new[]{Host,Action,User,UserContains,Process,ProcessContains,Provider,Source,Operation,Path,PathContains})
            if(value!=null&&(value.Length is <1 or >4096||value.Any(char.IsControl)))throw new ArgumentException("Invalid history filter.");
    }
    public string Fingerprint()=>Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(JsonSerializer.Serialize(this with{Cursor=null}))));
    public static EventHistoryQuery Parse(IQueryCollection values)
    {
        var allowed=new HashSet<string>(["sort","direction","limit","cursor","endpoint","host","os","ip","from","to","notification","action","user","userContains","process","processContains","pid","uid","parentPid","provider","source","operation","path","pathContains"],StringComparer.Ordinal);
        foreach(var item in values)if(!allowed.Contains(item.Key)||item.Value.Count!=1)throw new ArgumentException("Unknown or repeated history parameter.");
        string? Get(string name)=>values.TryGetValue(name,out var value)?value[0]:null;
        DateTimeOffset? Date(string name){var raw=Get(name);if(raw==null)return null;if(raw.Length>40||!System.Text.RegularExpressions.Regex.IsMatch(raw,@"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,7})?(?:Z|[+-]\d{2}:\d{2})$")||!DateTimeOffset.TryParse(raw,CultureInfo.InvariantCulture,DateTimeStyles.None,out var date))throw new ArgumentException("Timestamp requires an explicit time zone.");return date;}
        long? Number(string name){var raw=Get(name);if(raw==null)return null;if(!long.TryParse(raw,NumberStyles.None,CultureInfo.InvariantCulture,out var number))throw new ArgumentException("Invalid number.");return number;}
        int? Int(string name){var number=Number(name);if(number>int.MaxValue)throw new ArgumentException("Number out of range.");return (int?)number;}
        return new(){Sort=Get("sort")??"observed",Direction=Get("direction")??"desc",Limit=Int("limit")??50,Cursor=Get("cursor"),Endpoint=Get("endpoint"),Host=Get("host"),Os=Get("os"),Ip=Get("ip") is {} ip&&System.Net.IPAddress.TryParse(ip,out var address)?address.MapToIPv6().IsIPv4MappedToIPv6?address.MapToIPv4().ToString():address.ToString():Get("ip"),From=Date("from"),To=Date("to"),Notification=Get("notification"),Action=Get("action"),User=Get("user"),UserContains=Get("userContains"),Process=Get("process"),ProcessContains=Get("processContains"),Pid=Int("pid"),Uid=Number("uid"),ParentPid=Int("parentPid"),Provider=Get("provider"),Source=Get("source"),Operation=Get("operation"),Path=Get("path"),PathContains=Get("pathContains")};
    }
}
public sealed record HistoryPosition(long Sequence,string EventId,string? Key);
public sealed record HistoryCursor(int Version,string Subject,string Query,long Snapshot,DateTimeOffset Expires,HistoryPosition Position){public long ServiceSnapshot {get;init;}}
public sealed record HistoryRows(IReadOnlyList<StoredEvent> Items,long Snapshot,HistoryPosition? Next){public long ServiceSnapshot {get;init;} public long Total {get;init;}}
public sealed record HistoryEvent(long Sequence,string EndpointId,DateTimeOffset ReceivedUtc,AgentEvent Event,EventActivity Activity)
{
    public string TrustClassification {get;init;}="PolicyUnknown";
    public string MachineName {get;init;}="Not reported";
    public string OperatingSystem {get;init;}="unknown";
    public string? IpAddress {get;init;}
    public string NotificationType {get;init;}="unclassified";
    public string DisplayOperation=>EventHistoryPresentation.Action(Event,Activity);
    public string SequenceText=>Sequence.ToString(CultureInfo.InvariantCulture);
    public string RecordKind=>Sequence<0?"server-service":"endpoint";
    // Presentation hint only. Command creation and the endpoint still revalidate identity and policy.
    public bool ResponseCandidate=>Event.Source is "Windows audit 4663" or "Linux fanotify" or "macOS Endpoint Security"
        &&Event.ProcessId is >4&&Event.ObservedUtc>=DateTimeOffset.UtcNow.AddMinutes(-5)&&Event.ObservedUtc<=DateTimeOffset.UtcNow.AddMinutes(1);
}
public sealed record EventHistoryPage(IReadOnlyList<HistoryEvent> Items,string? NextCursor,long Snapshot){public long Total {get;init;}}

public static class EventHistoryPresentation
{
    public static string Notification(AgentEvent value)=>value.Source is "Forensic enrichment" or "Evidence transfer"?"info":value.Forensics?.Detection.Severity switch{"informational"=>"info","normal" or "alert"=>"alert","warning"=>"warning","high"=>"high","critical"=>"critical",_=>"unclassified"};
    public static string Action(AgentEvent value,EventActivity activity)
    {
        if(value.Source=="Forensic enrichment")return "Forensic Evidence";
        if(value.Source=="Windows syscall"&&value.Attribution?.WindowsSyscall is {} native)
        {
            if(native.Native.Outcome=="failed")return native.Native.ReturnStatus=="0xC0000022"?"Access Denied":"Operation Failed";
            if(native.Native.Outcome=="pending")return "Technical details";
        }
        if(value.Attribution?.LinuxKernel is {Version:4,IoObservation:{} io})
            return io.Diagnostic?"Capture Diagnostic":io.Stage==1?"Write Requested":io.Outcome=="pending"?"Write Pending":io.Outcome=="failure"?io.Errno is 1 or 13?"Access Denied":"Operation Failed":io.AppendRequested==true?"File Appended":"File Changed";
        if(value.Source=="Windows minifilter"&&activity.Outcome=="failed")return value.Attribution?.OsStatus=="0xC0000022"?"Access Denied":"Operation Failed";
        if(value.Source=="Windows minifilter"&&activity.Outcome=="unknown")return "Technical details";
        if(value.Attribution?.LinuxKernel is {Version:3,PermissionObservation:{} permission})
            return permission.Stage==3?"Capture Diagnostic":permission.Stage==1?"Permission Check Requested":"Permission Check Returned";
        var syscall=value.Attribution?.Syscall;syscall=syscall?[(syscall.LastIndexOf(':')+1)..];
        if(value.Source=="Linux Audit"&&value.Attribution?.Outcome=="Failed"&&syscall is "readlink" or "readlinkat")return "Technical details";
        if(value.Source is "Windows minifilter prototype" or "Linux eBPF prototype"&&activity.Outcome=="failed")return "Operation Failed";
        if(value.Operation=="Access denied"||activity.Outcome=="failed")return "Access Denied";
        var actions=activity.Actions;
        if(actions.Contains("open-request",StringComparer.Ordinal))return "Open Requested";
        if(actions.Contains("access-request",StringComparer.Ordinal))return "Access Requested";
        if(actions.Contains("rename-request",StringComparer.Ordinal))return "Rename Requested";
        if(actions.Contains("delete-request",StringComparer.Ordinal))return "Delete Requested";
        if(actions.Contains("metadata-request",StringComparer.Ordinal))return "Metadata Change Requested";
        if(actions.Contains("mapping-request",StringComparer.Ordinal))return "Mapping Requested";
        if(actions.Contains("read",StringComparer.Ordinal)||actions.Contains("transfer",StringComparer.Ordinal))return "Copied/Read";
        if(actions.Any(x=>x is "write" or "truncate" or "content-or-metadata" or "create-or-truncate" or "create-or-replace"))return "File Changed";
        if(actions.Any(x=>x is "rename" or "rename-or-move"))return "File Renamed";
        if(actions.Contains("delete",StringComparer.Ordinal))return "File Deleted";
        if(actions.Any(x=>x is "permissions" or "ownership" or "permissions-or-ownership" or "metadata"))return "Permissions Changed";
        if(actions.Contains("open",StringComparer.Ordinal))return "File Opened";
        if(actions.Any(x=>x is "callback" or "service-access"))return "Canary Activated";
        return "Technical details";
    }
}

public static class EventHistoryApi
{
    private static HistoryEvent Present(Store store,StoredEvent item,IReadOnlyDictionary<string,string>? hosts=null,IReadOnlyDictionary<string,(string Os,string? Ip)>? contacts=null)
    {
        var machine=item.EndpointId=="server"?"Management server":hosts?.GetValueOrDefault(item.EndpointId)??store.EndpointNames([item.EndpointId]).GetValueOrDefault(item.EndpointId,"Not reported");
        contacts??=store.HistoryContacts([item.EndpointId]);var contact=contacts.GetValueOrDefault(item.EndpointId,("unknown",null));
        return new(item.Sequence,item.EndpointId,item.ReceivedUtc,item.Event,EventActivity.From(item.Event)){MachineName=machine,OperatingSystem=contact.Item1,IpAddress=item.Event.Attribution?.WindowsShare?.SourceAddress??item.Event.ServiceContext?.SourceAddress??contact.Item2,NotificationType=EventHistoryPresentation.Notification(item.Event),TrustClassification=store.ClassifyTrust(item).ToString()};
    }
    public static Task<IResult> Handle(HttpContext context,Store store,IDataProtectionProvider protection,string subject)
    {
        try{return Read(context,store,protection,EventHistoryQuery.Parse(context.Request.Query),subject);}
        catch(ArgumentException){return Task.FromResult(Results.BadRequest(new{error="Invalid history query."}) as IResult);}
    }
    public static async Task<IResult> Read(HttpContext context,Store store,IDataProtectionProvider protection,EventHistoryQuery query,string subject)
    {
        var diagnostic=Environment.GetEnvironmentVariable("RF_HISTORY_DIAGNOSTICS")=="1";
        var clock=System.Diagnostics.Stopwatch.StartNew();
        void Mark(string stage){if(diagnostic)Console.Error.WriteLine($"SQ_HISTORY_API {context.TraceIdentifier} {stage} {clock.ElapsedMilliseconds}ms");}
        try
        {
            Mark("start");
            query.Validate();var protector=protection.CreateProtector("seQuester.EventHistory.Cursor.v1");
            var expires=DateTimeOffset.UtcNow.AddMinutes(20);long? snapshot=null,serviceSnapshot=null;HistoryPosition? position=null;
            if(query.Cursor!=null)
            {
                HistoryCursor? cursor;
                try{cursor=JsonSerializer.Deserialize<HistoryCursor>(protector.Unprotect(query.Cursor));}
                catch(Exception ex) when(ex is CryptographicException or JsonException or FormatException){return Results.BadRequest(new{error="Invalid history cursor. Refresh history."});}
                if(cursor==null||cursor.Version is not (1 or 2)||cursor.Subject!=subject||cursor.Query!=query.Fingerprint()||cursor.Expires<=DateTimeOffset.UtcNow||cursor.Snapshot<0||cursor.Position==null||cursor.ServiceSnapshot<0||cursor.Position.Sequence==0||cursor.Position.Sequence==long.MinValue||cursor.Position.Sequence>cursor.Snapshot||cursor.Position.Sequence< -cursor.ServiceSnapshot)
                    return Results.BadRequest(new{error="History cursor expired or does not match this view. Refresh history."});
                snapshot=cursor.Snapshot;serviceSnapshot=cursor.Version==1?0:cursor.ServiceSnapshot;position=cursor.Position;expires=cursor.Expires;
            }
            var page=await store.History(query,snapshot,position,context.RequestAborted,serviceSnapshot);
            Mark("store-complete");
            var hosts=store.EndpointNames(page.Items.Select(item=>item.EndpointId));
            var contacts=store.HistoryContacts(page.Items.Select(item=>item.EndpointId));
            Mark("contacts-complete");
            var next=page.Next==null?null:protector.Protect(JsonSerializer.Serialize(new HistoryCursor(2,subject,query.Fingerprint(),page.Snapshot,expires,page.Next){ServiceSnapshot=page.ServiceSnapshot}));
            Mark("cursor-complete");
            var presented=page.Items.Select(item=>Present(store,item,hosts,contacts)).ToArray();
            Mark("presentation-complete");
            return Results.Ok(new EventHistoryPage(presented,next,page.Snapshot){Total=page.Total});
        }
        catch(ArgumentException){return Results.BadRequest(new{error="Invalid history query."});}
    }
    public static void MapEventHistory(this WebApplication app)
    {
        app.MapPolicySimulation();
        app.MapGet("/api/v1/console/evidence/{sequence:long}",(long sequence,Store store)=>store.EvidenceRecord(sequence) is {} e?Results.Ok(Present(store,e)):Results.NotFound()).RequireAuthorization(p=>p.RequireRole("Reader","Operator","Administrator"));
        app.MapGet("/api/v1/console/event-capabilities",()=>Results.Ok(new{Version=1,Scope="Compiled provider capabilities, not endpoint readiness",Providers=SensorCapabilities.Inventory}))
            .RequireAuthorization(p=>p.RequireRole("Reader","Operator","Administrator"));
        app.MapGet("/api/v1/console/event-history",(HttpContext c,Store store,IDataProtectionProvider protection)=>
            Handle(c,store,protection,c.User.FindFirstValue(ClaimTypes.NameIdentifier)??throw new InvalidOperationException("Authenticated identity missing.")))
            .RequireAuthorization(p=>p.RequireRole("Reader","Operator","Administrator"));
    }
}

public sealed partial class Store
{
    // One classification expression for indexes and query evaluation. These
    // derived keys never replace raw evidence or change alert decisions.
    private static string HistoryActionExpression(bool sqlServer)
    {
        string TextValue(string path)=>sqlServer?$"NULLIF(JSON_VALUE(payload,'$.{path}'),'') COLLATE Latin1_General_100_BIN2":$"NULLIF(json_extract(payload,'$.{path}'),'') COLLATE BINARY";
        string NumberValue(string path)=>sqlServer?$"TRY_CONVERT(bigint,JSON_VALUE(payload,'$.{path}'))":$"CAST(json_extract(payload,'$.{path}') AS INTEGER)";
        var raw=TextValue("Operation");var eventSource=TextValue("Source");var outcome=TextValue("Attribution.Outcome");var syscall=TextValue("Attribution.Syscall");var provider=TextValue("Attribution.Provider");var serviceMethod=TextValue("ServiceContext.Method");
        string Syscall(params string[] names)=>"("+string.Join(" OR ",names.Select(name=>sqlServer?$"{syscall}='{name}' OR {syscall} LIKE '%:{name}'":$"{syscall}='{name}' OR {syscall} GLOB '*:{name}'"))+")";
        string Token(string value)=>sqlServer?$"CHARINDEX(', {value},',', '+{raw}+',')>0":$"instr(', '||{raw}||', ',', {value},')>0";
        var linuxAudit=$"{eventSource}='Linux Audit' AND {provider}='Linux Audit' AND {syscall} IS NOT NULL";
        var windows4663=$"{eventSource}='Windows audit 4663'";
        var inotify=$"{eventSource}='Linux inotify'";var fanotify=$"{eventSource}='Linux fanotify'";var fsevents=$"{eventSource}='macOS FSEvents'";
        var notificationWrite=$"({raw}='Canary modified (encryption possible)' OR {raw}='Canary content/metadata changed (encryption possible)' OR {raw}='Canary path created/replaced' OR {raw}='Canary path moved/replaced')";
        string Literal(string value)=>"'"+value.Replace("'","''")+"'";
        var linuxKernelAction=$"WHEN {eventSource}='Linux kernel' AND {provider}='Linux kernel' AND {raw}='File open observed before final result' AND {outcome}='Unknown' AND {NumberValue("Attribution.LinuxKernel.Version")} IN (1,2) THEN 'Open Requested' ";
        var permissionStage=NumberValue("Attribution.LinuxKernel.PermissionObservation.Stage");
        linuxKernelAction+=$"WHEN {eventSource}='Linux kernel' AND {provider}='Linux kernel' AND {NumberValue("Attribution.LinuxKernel.Version")}=3 THEN CASE WHEN {permissionStage}=1 THEN 'Permission Check Requested' WHEN {permissionStage}=2 THEN 'Permission Check Returned' ELSE 'Capture Diagnostic' END ";
        linuxKernelAction+=$"WHEN {eventSource}='Linux kernel' AND {provider}='Linux kernel' AND {NumberValue("Attribution.LinuxKernel.Version")}=4 THEN CASE WHEN {NumberValue("Attribution.LinuxKernel.IoObservation.Stage")}=3 THEN 'Capture Diagnostic' WHEN {NumberValue("Attribution.LinuxKernel.IoObservation.Stage")}=1 THEN 'Write Requested' WHEN {TextValue("Attribution.LinuxKernel.OperationOutcome")}='pending' THEN 'Write Pending' WHEN {TextValue("Attribution.LinuxKernel.OperationOutcome")}='failure' THEN CASE WHEN {TextValue("Attribution.LinuxKernel.IoObservation.ReturnValue")} IN ('-1','-13') THEN 'Access Denied' ELSE 'Operation Failed' END WHEN {raw}='File append completed' THEN 'File Appended' ELSE 'File Changed' END ";
        var windowsSyscall=$"WHEN {eventSource}='Windows syscall' AND {provider}='Windows syscall' AND {NumberValue("Attribution.WindowsSyscall.Version")}=1 THEN CASE WHEN {outcome}='failed' THEN CASE WHEN {TextValue("Attribution.OsStatus")}='0xC0000022' THEN 'Access Denied' ELSE 'Operation Failed' END WHEN {outcome}='pending' THEN 'Technical details' WHEN {NumberValue("Attribution.WindowsSyscall.Native.Operation")}=1 THEN 'Copied/Read' WHEN {NumberValue("Attribution.WindowsSyscall.Native.Operation")}=2 THEN 'File Changed' WHEN {NumberValue("Attribution.WindowsSyscall.Native.InformationClass")} IN (10,65) THEN 'File Renamed' WHEN {NumberValue("Attribution.WindowsSyscall.Native.InformationClass")} IN (13,64) THEN 'Delete Requested' WHEN {NumberValue("Attribution.WindowsSyscall.Native.InformationClass")}=20 THEN 'File Changed' ELSE 'Permissions Changed' END ";
        var kernelActions=windowsSyscall+linuxKernelAction+string.Concat(KernelActivityRules.All.Select(rule=>{
            var sample=new AgentEvent("",DateTimeOffset.UnixEpoch,rule.Operation,"",null,null,null,rule.Provider){Attribution=new(){Provider=rule.Provider,Outcome="Success"}};
            var label=EventHistoryPresentation.Action(sample,EventActivity.From(sample));
            var result=rule.Evidence=="intent"?Literal(label):$"CASE WHEN {outcome}='Failed' THEN 'Operation Failed' ELSE {Literal(label)} END";
            if(rule.Provider=="Windows minifilter")result=$"CASE WHEN {outcome}='Failed' AND {TextValue("Attribution.OsStatus")}='0xC0000022' THEN 'Access Denied' WHEN {outcome}='Failed' THEN 'Operation Failed' WHEN {outcome}='Success' THEN {Literal(label)} ELSE 'Technical details' END";
            return $"WHEN {eventSource}={Literal(rule.Provider)} AND {provider}={Literal(rule.Provider)} AND {raw}={Literal(rule.Operation)} THEN {result} ";
        }));
        var action=$"CASE WHEN {eventSource}='Forensic enrichment' THEN 'Forensic Evidence' "+kernelActions
            +$"WHEN {eventSource}='Windows audit 5145' THEN CASE WHEN {outcome}='Failed' THEN 'Access Denied' ELSE 'Open Requested' END "
            +$"WHEN {eventSource}='Linux Audit' AND {outcome}='Failed' AND {Syscall("readlink","readlinkat")} THEN 'Technical details' "
            +$"WHEN {raw}='Access denied' OR ({linuxAudit} AND {outcome}='Failed') THEN 'Access Denied' "
            +$"WHEN ({linuxAudit} AND {Syscall("read","pread64","readv","preadv","preadv2","copy_file_range","sendfile","splice")}) OR ({windows4663} AND {Token("Content read (copy possible)")}) OR (({inotify} OR {fanotify}) AND {raw}='Content read (copy possible)') THEN 'Copied/Read' "
            +$"WHEN ({linuxAudit} AND {Syscall("write","pwrite64","writev","pwritev","pwritev2","truncate","ftruncate","creat")}) OR ({windows4663} AND {Token("Content written")}) OR (({inotify} OR {fsevents}) AND {notificationWrite}) OR ({fanotify} AND {raw}='Canary modified (encryption possible)') THEN 'File Changed' "
            +$"WHEN ({linuxAudit} AND {Syscall("rename","renameat","renameat2")}) OR (({inotify} OR {fsevents}) AND {raw}='Canary moved/renamed') THEN 'File Renamed' "
            +$"WHEN ({linuxAudit} AND {Syscall("unlink","unlinkat","rmdir")}) OR ({windows4663} AND {Token("Delete access used")}) OR (({inotify} OR {fsevents}) AND {raw}='Canary deleted') THEN 'File Deleted' "
            +$"WHEN ({linuxAudit} AND {Syscall("chmod","fchmod","fchmodat","fchmodat2","chown","fchown","lchown","fchownat")}) OR ({windows4663} AND {Token("Permissions changed")}) OR (({inotify} OR {fsevents}) AND {raw}='Canary metadata changed') THEN 'Permissions Changed' "
            +$"WHEN {eventSource}='Windows audit 4656' OR ({linuxAudit} AND {Syscall("open","openat","openat2")}) OR (({inotify} OR {fanotify}) AND {raw}='File opened') THEN 'File Opened' "
            +$"WHEN {eventSource}='Server service decoy' AND {serviceMethod}='GET' THEN 'Canary Activated' ELSE 'Technical details' END";
        return action;
    }
    public IReadOnlyDictionary<string,string> EndpointNames(IEnumerable<string> endpointIds)
    {
        var ids=endpointIds.Where(id=>Guid.TryParseExact(id,"N",out _)).Distinct(StringComparer.Ordinal).ToArray();var result=new Dictionary<string,string>(StringComparer.Ordinal);if(ids.Length==0)return result;
        var args=ids.Select((id,index)=>("$endpoint"+index,(object)id)).ToArray();using var c=Open();using var command=Command(c,null,"SELECT id,machine FROM endpoints WHERE id IN ("+string.Join(',',args.Select(x=>x.Item1))+")",args);using var reader=command.ExecuteReader();while(reader.Read())result[reader.GetString(0)]=reader.GetString(1);return result;
    }
    // Existing legacy event/relay APIs and stored payloads are unchanged. Every value
    // is parameterized; SQL identifiers/JSON paths come exclusively from this map.
    public async Task<HistoryRows> History(EventHistoryQuery query,long? snapshot=null,HistoryPosition? after=null,CancellationToken cancellationToken=default,long? serviceSnapshot=null)
    {
        var diagnostic=Environment.GetEnvironmentVariable("RF_HISTORY_DIAGNOSTICS")=="1";
        var clock=System.Diagnostics.Stopwatch.StartNew();
        var diagnosticId=diagnostic?Guid.NewGuid().ToString("N"):"";
        void Mark(string stage){if(diagnostic)Console.Error.WriteLine($"SQ_HISTORY_STORE {diagnosticId} {stage} {clock.ElapsedMilliseconds}ms");}
        Mark("start");
        query.Validate();if(snapshot is <0||serviceSnapshot is <0||after!=null&&snapshot==null)throw new ArgumentException("Invalid history position.");
        using var c=Open();
        if(snapshot==null){using var high=Command(c,null,"SELECT COALESCE(MAX(sequence),0) FROM events");snapshot=Convert.ToInt64(await high.ExecuteScalarAsync(cancellationToken));}
        var hasServices=HasServiceEvidence();serviceSnapshot??=hasServices?LatestServiceSequence():0;
        Mark("snapshot-complete");
        string TextValue(string path)=>sqlServer?$"NULLIF(JSON_VALUE(payload,'$.{path}'),'') COLLATE Latin1_General_100_BIN2":$"NULLIF(json_extract(payload,'$.{path}'),'') COLLATE BINARY";
        string NumberValue(string path)=>sqlServer?$"TRY_CONVERT(bigint,JSON_VALUE(payload,'$.{path}'))":$"CAST(json_extract(payload,'$.{path}') AS INTEGER)";
        var raw=TextValue("Operation");var eventSource=TextValue("Source");var outcome=TextValue("Attribution.Outcome");var syscall=TextValue("Attribution.Syscall");var provider=TextValue("Attribution.Provider");var serviceMethod=TextValue("ServiceContext.Method");
        var host=sqlServer?"(CASE WHEN endpoint='server' THEN 'Management server' ELSE COALESCE((SELECT machine FROM endpoints WHERE id=endpoint),'Not reported') END) COLLATE Latin1_General_100_BIN2":"(CASE WHEN endpoint='server' THEN 'Management server' ELSE COALESCE((SELECT machine FROM endpoints WHERE id=endpoint),'Not reported') END) COLLATE BINARY";
        var action=HistoryActionExpression(sqlServer);
        var hasPlatform=HasPlatformStorage();
        var os=hasPlatform?"COALESCE((SELECT os FROM endpoint_platform WHERE endpoint_platform.endpoint=combined.endpoint),'unknown')":"'unknown'";
        var ip="COALESCE("+TextValue("Attribution.WindowsShare.SourceAddress")+","+TextValue("ServiceContext.SourceAddress")+",(SELECT address FROM endpoint_contact WHERE endpoint_contact.endpoint=combined.endpoint))";
        // Reported evidence severity, not a safety verdict or an unverified trust claim.
        var severity=TextValue("Forensics.Detection.Severity");
        var notification=$"CASE WHEN {eventSource} IN ('Forensic enrichment','Evidence transfer') OR {severity}='informational' THEN 'info' WHEN {severity} IN ('normal','alert') THEN 'alert' WHEN {severity} IN ('warning','high','critical') THEN {severity} ELSE 'unclassified' END";
        var fields=new Dictionary<string,string>(StringComparer.Ordinal)
        {
            ["observed"]=sqlServer?"DATEDIFF_BIG(millisecond,CONVERT(datetimeoffset,'1970-01-01T00:00:00+00:00'),TRY_CONVERT(datetimeoffset,JSON_VALUE(payload,'$.ObservedUtc')))":"CAST(ROUND((julianday(json_extract(payload,'$.ObservedUtc'))-2440587.5)*86400000) AS INTEGER)",
            ["os"]=os,["ip"]=ip,["notification"]=notification,["action"]=action,["host"]=host,["operation"]=raw,["path"]=TextValue("Path"),["user"]=TextValue("User"),["process"]=TextValue("Process"),["pid"]=NumberValue("ProcessId"),
            ["sequence"]="sequence",["endpoint"]="endpoint",["uid"]=NumberValue("Attribution.UserId"),["parentPid"]=NumberValue("Attribution.ParentProcessId"),["provider"]=TextValue("Attribution.Provider"),["source"]=TextValue("Source")
        };
        // Project indexed values in the table branch. With service evidence in a
        // UNION, evaluating these only in the outer query reparsed every payload.
        var projection="";
        if(!sqlServer)
        {
            if(query.Sort=="action"||query.Action!=null){projection+=","+action+" AS history_action";fields["action"]="history_action";}
            if(query.Sort=="observed"||query.From!=null||query.To!=null){projection+=","+fields["observed"]+" AS history_observed";fields["observed"]="history_observed";}
            if(query.Notification!=null){projection+=","+notification+" AS history_notification";fields["notification"]="history_notification";}
            if(query.Process!=null||query.ProcessContains!=null){projection+=","+fields["process"]+" AS history_process";fields["process"]="history_process";}
        }
        var args=new List<(string,object)>{("$snapshot",snapshot.Value),("$services",serviceSnapshot.Value),("$limit",query.Limit+1)};
        var where=new List<string>{"sequence<=$snapshot","sequence>= -$services"};
        void Filter(string field,object? value){if(value==null)return;var key="$filter"+args.Count;where.Add(fields[field]+"="+key);args.Add((key,value));}
        void Contains(string field,string? value){if(value==null)return;var key="$filter"+args.Count;where.Add($"LOWER({fields[field]}) LIKE LOWER({key}) ESCAPE '\\'");args.Add((key,"%"+value.Replace("\\","\\\\").Replace("%","\\%").Replace("_","\\_")+"%"));}
        Filter("endpoint",query.Endpoint);Contains("host",query.Host);Filter("action",query.Action);Filter("user",query.User);Contains("user",query.UserContains);Filter("process",query.Process);Contains("process",query.ProcessContains);Filter("pid",query.Pid);Filter("uid",query.Uid);Filter("parentPid",query.ParentPid);Filter("provider",query.Provider);Filter("source",query.Source);Filter("operation",query.Operation);Filter("path",query.Path);Contains("path",query.PathContains);
        // "normal" was exposed in 0.6.17; retain it as an alias for normal alerts.
        Filter("notification",query.Notification=="normal"?"alert":query.Notification);
        if(query.Ip is {} requestedIp)
        {
            var address=System.Net.IPAddress.Parse(requestedIp);if(address.IsIPv4MappedToIPv6)address=address.MapToIPv4();
            where.Add("("+fields["ip"]+"=$ip OR "+fields["ip"]+"=$mappedIp)");args.Add(("$ip",address.ToString()));args.Add(("$mappedIp",address.MapToIPv6().ToString()));
        }
        if(query.From is {} from){where.Add(fields["observed"]+">=$from");args.Add(("$from",from.ToUnixTimeMilliseconds()));}
        if(query.To is {} to){where.Add(fields["observed"]+"<=$to");args.Add(("$to",to.ToUnixTimeMilliseconds()));}
        var seek="";
        if(after!=null)
        {
            if(after.Sequence==0||after.Sequence==long.MinValue||after.Sequence< -serviceSnapshot.Value||after.Sequence>snapshot.Value||!Guid.TryParseExact(after.EventId,"N",out _))throw new ArgumentException("Invalid position.");
            args.Add(("$sequence",after.Sequence));args.Add(("$event",after.EventId));
            var tie="(sequence<$sequence OR (sequence=$sequence AND event_id<$event))";
            if(after.Key==null)seek="WHERE sort_value IS NULL AND "+tie;
            else
            {
                object key=after.Key;if(query.Numeric){if(!long.TryParse(after.Key,NumberStyles.Integer,CultureInfo.InvariantCulture,out var number))throw new ArgumentException("Invalid numeric position.");key=number;}
                args.Add(("$key",key));var comparison=query.Direction=="asc"?">":"<";
                seek=$"WHERE sort_value IS NULL OR sort_value{comparison}$key OR (sort_value=$key AND {tie})";
            }
        }
        // Nulls remain last in either direction; ascending identity tie-break is fixed.
        // Restrict endpoints before reading wide forensic payloads. A correlated OS
        // predicate over combined history scanned Linux payloads for Windows queries.
        var endpointRestriction="";var serviceRestriction="";
        if(query.Os is {} requestedOs)
        {
            args.Add(("$os",requestedOs));
            endpointRestriction=hasPlatform
                ?requestedOs=="unknown"?" WHERE endpoint NOT IN (SELECT endpoint FROM endpoint_platform WHERE os<>'unknown')":" WHERE endpoint IN (SELECT endpoint FROM endpoint_platform WHERE os=$os)"
                :requestedOs=="unknown"?"":" WHERE 1=0";
            if(requestedOs!="unknown")serviceRestriction=" WHERE 1=0";
        }
        if(query.Endpoint is {} requestedEndpoint)
        {
            // Push exact sensor scope into the source and its narrow index before
            // any path/action JSON predicates inspect wide forensic payloads.
            args.Add(("$historyEndpoint",requestedEndpoint));
            endpointRestriction+=(endpointRestriction.Length==0?" WHERE ":" AND ")+"endpoint=$historyEndpoint";
            serviceRestriction+=(serviceRestriction.Length==0?" WHERE ":" AND ")+"1=0";
        }
        // Narrow the source by sensor identity before evaluating the large action
        // expression. Keep the outer host predicate for identical fallback semantics.
        if(query.Host is {} requestedHost)
        {
            args.Add(("$historyHost","%"+requestedHost.Replace("\\","\\\\").Replace("%","\\%").Replace("_","\\_")+"%"));
            var sensorMatch="(endpoint IN (SELECT id FROM endpoints WHERE LOWER(machine) LIKE LOWER($historyHost) ESCAPE '\\') OR (endpoint NOT IN (SELECT id FROM endpoints) AND LOWER('Not reported') LIKE LOWER($historyHost) ESCAPE '\\'))";
            endpointRestriction+=(endpointRestriction.Length==0?" WHERE ":" AND ")+sensorMatch;
            serviceRestriction+=(serviceRestriction.Length==0?" WHERE ":" AND ")+"LOWER('Management server') LIKE LOWER($historyHost) ESCAPE '\\'";
        }
        // A provably excluded service branch must not force SQLite's UNION
        // materialization for a Windows/Linux/specific-sensor history request.
        var includeServices=hasServices&&query.Endpoint==null&&query.Os is null or "unknown";
        if(includeServices&&query.Host is {} hostFilter&&hostFilter.All(char.IsAscii)
            &&!"Management server".Contains(hostFilter,StringComparison.OrdinalIgnoreCase))includeServices=false;
        var source="SELECT sequence,endpoint,received,payload,event_id"+projection+" FROM events"+endpointRestriction;
        if(includeServices)source+=" UNION ALL SELECT -sequence AS sequence,'server' AS endpoint,received,payload,event_id"+projection+" FROM service_evidence"+serviceRestriction;
        if(!sqlServer&&query.Pid!=null)
            source=source.Replace("FROM events","FROM events INDEXED BY events_history_pid",StringComparison.Ordinal);
        else if(!sqlServer&&(query.Process!=null||query.ProcessContains!=null)&&query.Action==null&&query.Sort!="action"&&query.Notification==null)
            source=source.Replace("FROM events","FROM events INDEXED BY events_history_endpoint_process",StringComparison.Ordinal);
        else if(!sqlServer&&(query.Action!=null||query.Sort=="action"))
            source=source.Replace("FROM events","FROM events INDEXED BY events_history_action_"+(query.Sort=="action"?query.Direction:"asc"),StringComparison.Ordinal);
        else if(!sqlServer&&query.Notification!=null)
            source=source.Replace("FROM events","FROM events INDEXED BY events_history_endpoint_notification",StringComparison.Ordinal);
        else if(!sqlServer&&(query.Host!=null||query.Endpoint!=null))
            source=source.Replace("FROM events","FROM events INDEXED BY events_history_endpoint",StringComparison.Ordinal);
        var countSource=source;
        if(!sqlServer&&query.Sort=="action"&&query.Action==null&&query.Pid==null)
        {
            var countIndex=query.Host!=null||query.Os!=null||query.Endpoint!=null?" INDEXED BY events_history_endpoint":"";
            countSource=countSource.Replace(" INDEXED BY events_history_action_"+query.Direction,countIndex,StringComparison.Ordinal)
                .Replace(","+action+" AS history_action","",StringComparison.Ordinal);
        }
        var countSql=$"WITH combined AS ({countSource}) SELECT COUNT(*) FROM combined WHERE {string.Join(" AND ",where)}";
        if(diagnostic&&!sqlServer)
        {
            using var explainCount=Command(c,null,"EXPLAIN QUERY PLAN "+countSql,args.Where(x=>x.Item1!="$limit").ToArray());
            using var countPlan=await explainCount.ExecuteReaderAsync(cancellationToken);
            while(await countPlan.ReadAsync(cancellationToken))Mark("count-plan "+countPlan.GetString(3));
        }
        using var countCommand=Command(c,null,countSql,args.Where(x=>x.Item1!="$limit").ToArray());var total=Convert.ToInt64(await countCommand.ExecuteScalarAsync(cancellationToken));
        Mark("count-complete");
        // SQLite otherwise prefers a rowid range and sorts every wide payload when both
        // snapshot bounds are present. Keep counts on their narrow index, and use the
        // exact observed-order index only for page retrieval. Direction is validated.
        if(!sqlServer&&query.Sort=="observed"&&query.Os==null&&query.Host==null&&query.Endpoint==null&&query.Notification==null&&query.Pid==null&&query.Action==null&&query.Process==null&&query.ProcessContains==null)
            source=source.Replace("FROM events","FROM events INDEXED BY events_history_observed_"+query.Direction,StringComparison.Ordinal);
        var sql=$"WITH combined AS ({source}), history AS (SELECT sequence,endpoint,received,payload,event_id,{fields[query.Sort]} AS sort_value FROM combined WHERE {string.Join(" AND ",where)}) SELECT sequence,endpoint,received,payload,event_id,sort_value FROM history {seek} ORDER BY CASE WHEN sort_value IS NULL THEN 1 ELSE 0 END ASC,sort_value {query.Direction.ToUpperInvariant()},sequence DESC,event_id DESC LIMIT $limit";
        if(!sqlServer)
        {
            // Sort compact keys, then fetch only the requested page's full evidence.
            // Materializing wide forensic payloads made small filtered pages expensive.
            var order=$"CASE WHEN sort_value IS NULL THEN 1 ELSE 0 END ASC,sort_value {query.Direction.ToUpperInvariant()},sequence DESC,event_id DESC";
            var payload=includeServices?"CASE WHEN sequence>0 THEN (SELECT payload FROM events e WHERE e.sequence=selected.sequence) ELSE (SELECT payload FROM service_evidence s WHERE s.sequence=-selected.sequence) END":"(SELECT payload FROM events e WHERE e.sequence=selected.sequence)";
            var received=includeServices?"CASE WHEN sequence>0 THEN (SELECT received FROM events e WHERE e.sequence=selected.sequence) ELSE (SELECT received FROM service_evidence s WHERE s.sequence=-selected.sequence) END":"(SELECT received FROM events e WHERE e.sequence=selected.sequence)";
            sql=$"WITH combined AS ({source}), history AS (SELECT sequence,endpoint,event_id,{fields[query.Sort]} AS sort_value FROM combined WHERE {string.Join(" AND ",where)}), selected AS MATERIALIZED (SELECT sequence,endpoint,event_id,sort_value FROM history {seek} ORDER BY {order} LIMIT $limit) SELECT sequence,endpoint,{received} AS received,{payload} AS payload,event_id,sort_value FROM selected ORDER BY {order}";
        }
        if(!sqlServer&&query.Sort=="sequence"&&query.Endpoint!=null&&query.Host==null&&query.Os==null&&query.Ip==null&&query.From==null&&query.To==null&&query.Notification==null&&query.Action==null&&query.User==null&&query.UserContains==null&&query.Process==null&&query.ProcessContains==null&&query.Pid==null&&query.Uid==null&&query.ParentPid==null&&query.Provider==null&&query.Source==null&&query.Operation==null&&query.Path==null&&query.PathContains==null)
        {
            // Sensor sequence is a unique non-null indexed key. Avoid materializing
            // and sorting a sensor's entire history to retrieve one or two payloads.
            // Snapshot/cursor semantics remain identical to the general query.
            if(after!=null&&(after.Key!=after.Sequence.ToString(CultureInfo.InvariantCulture)||after.Sequence<=0))throw new ArgumentException("Invalid sequence position.");
            var boundary=after==null?"":" AND sequence"+(query.Direction=="asc"?">":"<")+"$sequence";
            sql="SELECT sequence,endpoint,received,payload,event_id,sequence AS sort_value FROM events INDEXED BY events_history_endpoint WHERE endpoint=$historyEndpoint AND sequence<=$snapshot AND sequence>=0"+boundary+" ORDER BY sequence "+query.Direction.ToUpperInvariant()+" LIMIT $limit";
        }
        if(diagnostic&&!sqlServer)
        {
            using var explain=Command(c,null,"EXPLAIN QUERY PLAN "+sql,args.ToArray());
            using var plan=await explain.ExecuteReaderAsync(cancellationToken);
            while(await plan.ReadAsync(cancellationToken))Mark("plan "+plan.GetString(3));
        }
        using var command=Command(c,null,sql,args.ToArray());using var reader=await command.ExecuteReaderAsync(cancellationToken);
        Mark("reader-open");
        var rows=new List<StoredEvent>();var positions=new List<HistoryPosition>();
        while(await reader.ReadAsync(cancellationToken))
        {
            rows.Add(new(reader.GetInt64(0),reader.GetString(1),DateTimeOffset.FromUnixTimeMilliseconds(reader.GetInt64(2)),JsonSerializer.Deserialize<AgentEvent>(reader.GetString(3))!));
            positions.Add(new(reader.GetInt64(0),reader.GetString(4),reader.IsDBNull(5)?null:Convert.ToString(reader.GetValue(5),CultureInfo.InvariantCulture)));
        }
        var more=rows.Count>query.Limit;if(more)rows.RemoveAt(rows.Count-1);
        Mark("rows-complete");
        return new(rows,snapshot.Value,more?positions[query.Limit-1]:null){ServiceSnapshot=serviceSnapshot.Value,Total=total};
    }
}
