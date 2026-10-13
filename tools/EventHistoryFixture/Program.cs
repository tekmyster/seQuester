using System.Diagnostics;
using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.Http;
using Microsoft.Data.Sqlite;
using Microsoft.Extensions.Primitives;
using RansomFree.Contracts;
using RansomFree.Server;

var root=Path.Combine(Path.GetTempPath(),"sequester-history-"+Guid.NewGuid().ToString("N"));Directory.CreateDirectory(root);
var evidence=new List<string>();void Check(bool value,string label){if(!value)throw new Exception("FAIL: "+label);evidence.Add("PASS: "+label);Console.WriteLine(evidence[^1]);}
{
    var policyStore=new Store(Path.Combine(root,"forensic-policy"));var sensor=policyStore.Enroll(new(policyStore.CreateCode().Code,"forensic-policy-fixture","0.6.10-dev"))!;
    var group=policyStore.CreateGroup("forensic-policy","fixture");
    Check(policyStore.PublishPolicy(group.Id,new(0,MonitoringPolicy.Default with{Forensics=new()}),"fixture")&&policyStore.AssignGroup(sensor.EndpointId,new(group.Id,null),"fixture"),"forensic group policy persists and assigns");
    var assigned=policyStore.Assigned(sensor.EndpointId);
    Check(!policyStore.AcknowledgePolicy(sensor.EndpointId,new(group.Id,assigned.Revision)),"old sensor cannot acknowledge a forensic policy it does not understand");
    Check(policyStore.AcknowledgePolicy(sensor.EndpointId,new(group.Id,assigned.Revision){ForensicsVersion=1}),"capable sensor acknowledges forensic policy with explicit schema version");
    Check(!(MonitoringPolicy.Default with{Forensics=new()}).SameContent(MonitoringPolicy.Default),"forensic policy changes participate in revision conflict checks");
}
var store=new Store(root);var endpoint=store.Enroll(new(store.CreateCode().Code,"history-fixture","fixture"))!;
var second=store.Enroll(new(store.CreateCode().Code,"history-fixture-2","fixture"))!;
Check(store.Inventory().All(x=>x.OperatingSystem==null),"legacy endpoint platform unknown before any report");
foreach(var os in new[]{"windows","linux","macos","unknown"}){Check(store.Heartbeat(endpoint.EndpointId,new("fixture","Monitoring"){OperatingSystem=os}),"heartbeat accepts reported OS "+os);Check(new Store(root).Inventory().Single(x=>x.EndpointId==endpoint.EndpointId).OperatingSystem==os,"reported OS survives reopen "+os);}
var invalidOs=false;try{store.Heartbeat(endpoint.EndpointId,new("fixture","Monitoring"){OperatingSystem="ubuntu"});}catch(ArgumentException){invalidOs=true;}Check(invalidOs,"unrecognized platform rejected, no distro inference");
store.Heartbeat(endpoint.EndpointId,new("fixture","Monitoring"));Check(store.Inventory().Single(x=>x.EndpointId==endpoint.EndpointId).OperatingSystem=="unknown","legacy heartbeat clears obsolete OS claim");
store.Heartbeat(endpoint.EndpointId,new("fixture","Monitoring"){OperatingSystem="windows"});
store.Heartbeat(second.EndpointId,new("fixture","Trust policy pending"){OperatingSystem="linux"});
foreach(var (name,health,os) in new[]{("fixture-failed","Monitoring stopped","macos"),("fixture-unknown","New unrecognized state","unknown")}){var item=store.Enroll(new(store.CreateCode().Code,name,"fixture"))!;store.Heartbeat(item.EndpointId,new("fixture",health){OperatingSystem=os});}
var epoch=DateTimeOffset.Parse("2026-01-01T00:00:00Z",CultureInfo.InvariantCulture);
for(var batch=0;batch<11;batch++)
{
    var events=Enumerable.Range(batch*100,100).Select(i=>new AgentEvent(Guid.NewGuid().ToString("N"),epoch.AddMilliseconds((i%37)*171).ToOffset(TimeSpan.FromHours(i%2==0?4:-5)),i%2==0?"Read intent":"Write","/synthetic/"+(i%11),i%5==0?null:"user"+(i%13),i%7==0?null:"/bin/tool"+(i%9),i%3==0?null:i%127,i%2==0?"Linux Audit":"Linux fanotify")
    {Attribution=new(){Provider="Fixture",Level="Partial attribution",Basis="Synthetic, no real process",UserId=i%5==0?null:(uint)(i%17),ParentProcessId=i%3==0?null:i%21}}).ToArray();
    store.Ingest(batch%2==0?endpoint.EndpointId:second.EndpointId,new(events));
}
var all=store.Events(0,2000);Check(all.Count==1100,"persist 1,100 synthetic rows across two endpoints");
store=new Store(root);Check(store.Events(0,2000).Select(x=>x.Event).SequenceEqual(all.Select(x=>x.Event)),"historical payloads preserved across reopening");
var hosts=store.EndpointNames(all.Select(x=>x.EndpointId));
object? Key(StoredEvent e,string field)=>field switch{"observed"=>e.Event.ObservedUtc.ToUnixTimeMilliseconds(),"action"=>EventHistoryPresentation.Action(e.Event,EventActivity.From(e.Event)),"host"=>hosts[e.EndpointId],"operation"=>e.Event.Operation,"path"=>e.Event.Path,"user"=>e.Event.User,"process"=>e.Event.Process,"pid"=>e.Event.ProcessId,"sequence"=>e.Sequence,"endpoint"=>e.EndpointId,"uid"=>(long?)e.Event.Attribution?.UserId,"parentPid"=>e.Event.Attribution?.ParentProcessId,"provider"=>e.Event.Attribution?.Provider,"source"=>e.Event.Source,_=>throw new Exception()};
int Compare(object? a,object? b,bool desc){if(a==null)return b==null?0:1;if(b==null)return -1;var value=a is string sa&&b is string sb?StringComparer.Ordinal.Compare(sa,sb):Convert.ToInt64(a).CompareTo(Convert.ToInt64(b));return desc?-value:value;}
foreach(var sort in EventHistoryQuery.Sorts)foreach(var direction in new[]{"asc","desc"})
{
    var expected=all.OrderBy(e=>e,Comparer<StoredEvent>.Create((a,b)=>{var c=Compare(Key(a,sort),Key(b,sort),direction=="desc");return c==0?b.Sequence.CompareTo(a.Sequence):c;})).Select(x=>x.Sequence).ToArray();
    HistoryPosition? position=null;long? snapshot=null;var found=new List<long>();var pages=0;
    do{var result=await store.History(new(){Sort=sort,Direction=direction,Limit=137},snapshot,position);snapshot=result.Snapshot;position=result.Next;found.AddRange(result.Items.Select(x=>x.Sequence));if(++pages>20)throw new Exception("Paging did not terminate");}while(position!=null);
    Check(expected.SequenceEqual(found),$"complete-result {sort} {direction}, nulls last, sequence-desc ties, eight pages");
}
var newest=await store.History(new());Check(newest.Items.Count==50&&newest.Total==1100&&newest.Items.Zip(newest.Items.Skip(1)).All(pair=>pair.First.Event.ObservedUtc>pair.Second.Event.ObservedUtc||pair.First.Event.ObservedUtc==pair.Second.Event.ObservedUtc&&pair.First.Sequence>pair.Second.Sequence),"default page is 50 rows, newest first, with truthful total and sequence-desc ties");
foreach(var query in new[]{new EventHistoryQuery{User="user2"},new(){Process="/bin/tool2"},new(){Pid=22},new(){Uid=3},new(){ParentPid=5},new(){Endpoint=second.EndpointId},new(){Provider="Fixture"},new(){Source="Linux Audit"},new(){Operation="Write"},new(){Path="/synthetic/2"}})
{
    var result=await store.History(query with{Limit=500});var matches=all.Where(x=>(query.User==null||x.Event.User==query.User)&&(query.Process==null||x.Event.Process==query.Process)&&(query.Pid==null||x.Event.ProcessId==query.Pid)&&(query.Uid==null||x.Event.Attribution?.UserId==query.Uid)&&(query.ParentPid==null||x.Event.Attribution?.ParentProcessId==query.ParentPid)&&(query.Endpoint==null||x.EndpointId==query.Endpoint)&&(query.Provider==null||x.Event.Attribution?.Provider==query.Provider)&&(query.Source==null||x.Event.Source==query.Source)&&(query.Operation==null||x.Event.Operation==query.Operation)&&(query.Path==null||x.Event.Path==query.Path)).ToArray();
    Check(result.Items.All(x=>matches.Any(y=>x.Sequence==y.Sequence))&&result.Items.Count==Math.Min(matches.Length,500),"exact filter remains server-side: "+JsonSerializer.Serialize(query));
}
var first=await store.History(new(){Sort="user",Limit=100});
store.Ingest(endpoint.EndpointId,new([new(Guid.NewGuid().ToString("N"),epoch,"Write","/new","AAAA","new",4,"fixture")]));
using(var c=new SqliteConnection($"Data Source={Path.Combine(root,"management.db")}")){c.Open();using var cmd=c.CreateCommand();cmd.CommandText="DELETE FROM events WHERE sequence=$sequence";cmd.Parameters.AddWithValue("$sequence",first.Items[0].Sequence);cmd.ExecuteNonQuery();}
var rest=new List<StoredEvent>();var p=first.Next;do{var result=await store.History(new(){Sort="user",Limit=100},first.Snapshot,p);rest.AddRange(result.Items);p=result.Next;}while(p!=null);
Check(rest.All(e=>e.Sequence<=first.Snapshot)&&first.Items.Concat(rest).Select(e=>e.Sequence).Distinct().Count()==1100,"snapshot excludes new arrivals; retention does not shift cursor or skip surviving rows");
foreach(var query in new[]{new EventHistoryQuery{Sort="user; DROP TABLE events"},new(){Direction="DESC"},new(){Limit=501},new(){Pid=-1},new(){Endpoint="other"},new(){User="bad\nvalue"},new(){Cursor=new string('x',17000)}})
{var rejected=false;try{await store.History(query);}catch(ArgumentException){rejected=true;}Check(rejected,"invalid typed query rejected");}
var empty=await store.History(new(){User="' OR 1=1 --"});Check(empty.Items.Count==0,"filter SQL injection treated as literal");
var contains=await store.History(new(){Host="HISTORY-FIXTURE",UserContains="SER2",ProcessContains="TOOL2",PathContains="THETIC/2",Limit=500});Check(contains.Items.Count>0&&contains.Items.All(x=>hosts[x.EndpointId].Contains("history-fixture",StringComparison.OrdinalIgnoreCase)&&x.Event.User!.Contains("ser2",StringComparison.OrdinalIgnoreCase)&&x.Event.Process!.Contains("tool2",StringComparison.OrdinalIgnoreCase)&&x.Event.Path.Contains("thetic/2",StringComparison.OrdinalIgnoreCase)),"friendly column searches combine on the server");
var projection=new EventHistoryQuery{Sort="pid",Direction="asc",Limit=3};var protector=new EphemeralDataProtectionProvider();
async Task<IResult> Call(EventHistoryQuery query,string subject)=>await EventHistoryApi.Read(new DefaultHttpContext(),store,protector,query,subject);
var good=(EventHistoryPage)((IValueHttpResult)await Call(projection,"reader-a")).Value!;
Check(good.NextCursor!=null,"API emits protected cursor");
Check(((IStatusCodeHttpResult)await Call(projection with{Cursor=good.NextCursor},"reader-a")).StatusCode==200,"same principal/query cursor resumes");
Check(((IStatusCodeHttpResult)await Call(projection with{Cursor=good.NextCursor},"reader-b")).StatusCode==400,"cross-principal cursor rejected");
Check(((IStatusCodeHttpResult)await Call(projection with{Cursor=good.NextCursor,Sort="user"},"reader-a")).StatusCode==400,"changed-sort cursor rejected");
Check(((IStatusCodeHttpResult)await Call(projection with{Cursor=good.NextCursor+"x"},"reader-a")).StatusCode==400,"tampered cursor rejected");
var expired=protector.CreateProtector("seQuester.EventHistory.Cursor.v1").Protect(JsonSerializer.Serialize(new HistoryCursor(1,"reader-a",projection.Fingerprint(),good.Snapshot,DateTimeOffset.UtcNow.AddSeconds(-1),new(1,all[0].Event.EventId,"2"))));
Check(((IStatusCodeHttpResult)await Call(projection with{Cursor=expired},"reader-a")).StatusCode==400,"expired cursor rejected");
var missingPosition=protector.CreateProtector("seQuester.EventHistory.Cursor.v1").Protect(JsonSerializer.Serialize(new HistoryCursor(1,"reader-a",projection.Fingerprint(),good.Snapshot,DateTimeOffset.UtcNow.AddMinutes(1),null!)));
Check(((IStatusCodeHttpResult)await Call(projection with{Cursor=missingPosition},"reader-a")).StatusCode==400,"malformed protected cursor position rejected without server error");
Check(EventHistoryQuery.Parse(new QueryCollection()).Limit==50,"request defaults apply 50-row page size");
foreach(var values in new Dictionary<string,StringValues>[] {new(){["sort"]=new(new[]{"pid","user"})},new(){["unknown"]="x"},new(){["pid"]="x"},new(){["parentPid"]="999999999999"}})
{var rejected=false;try{EventHistoryQuery.Parse(new QueryCollection(values));}catch(ArgumentException){rejected=true;}Check(rejected,"ambiguous/invalid HTTP query rejected");}
foreach(var changed in new[]{projection with{Direction="desc"},projection with{Limit=4},projection with{User="user2"},projection with{Process="/bin/tool2"},projection with{Pid=2},projection with{Endpoint=endpoint.EndpointId}})
    Check(((IStatusCodeHttpResult)await Call(changed with{Cursor=good.NextCursor},"reader-a")).StatusCode==400,"cursor isolated from changed direction/page-size/filter "+JsonSerializer.Serialize(changed));
AgentEvent Event(string source,string operation,string syscall="",string outcome="Success")=>new(Guid.NewGuid().ToString("N"),epoch,operation,"/bait","user","reader",42,source){Attribution=string.IsNullOrEmpty(syscall)?null:new(){Provider="Linux Audit",Syscall="audit:"+syscall,Outcome=outcome}};
foreach(var (value,label) in new[]{(Event("Windows audit 4656","Open / access requested"),"File Opened"),(Event("Windows audit 4656","Access denied"),"Access Denied"),(Event("Windows audit 4663","Content read (copy possible)"),"Copied/Read"),(Event("Linux Audit","Audit openat (Success; access intent, not read/copy proof)","openat"),"File Opened"),(Event("Linux Audit","Audit readlink (Failed)","readlink","Failed"),"Technical details"),(Event("Linux inotify","Canary modified (encryption possible)"),"File Changed"),(Event("Linux inotify","Canary moved/renamed"),"File Renamed"),(Event("Linux inotify","Canary deleted"),"File Deleted")})Check(EventHistoryPresentation.Action(value,EventActivity.From(value))==label,"plain action label: "+label);
AgentEvent MatrixEvent(string source,string operation,string? syscall=null,string outcome="Success",string provider="Linux Audit")=>new(Guid.NewGuid().ToString("N"),epoch,operation,"/action-matrix/"+Guid.NewGuid().ToString("N"),"user","reader",42,source){Attribution=syscall==null?null:new(){Provider=provider,Syscall="audit:"+syscall,Outcome=outcome}};
var actionMatrix=new List<(AgentEvent Event,string Label)>
{
    (MatrixEvent("Windows audit 4656","Open / access requested"),"File Opened"),(MatrixEvent("Windows audit 4656","Access denied"),"Access Denied"),
    (MatrixEvent("Windows audit 4663","Content read (copy possible)"),"Copied/Read"),(MatrixEvent("Windows audit 4663","Content written"),"File Changed"),(MatrixEvent("Windows audit 4663","Delete access used"),"File Deleted"),(MatrixEvent("Windows audit 4663","Permissions changed"),"Permissions Changed"),(MatrixEvent("Windows audit 4663","Permissions changed, Content written, Content read (copy possible)"),"Copied/Read"),(MatrixEvent("Windows audit 4663","Content written, Unreviewed right"),"File Changed"),
    (MatrixEvent("Linux Audit","audit","open","Failed"),"Access Denied"),(MatrixEvent("Linux Audit","audit","unknown","Failed"),"Access Denied"),(MatrixEvent("Linux Audit","audit","readlink","Failed"),"Technical details"),(MatrixEvent("Linux Audit","audit","readlinkat","Success"),"Technical details"),(MatrixEvent("Linux Audit","audit","open","Success","Wrong provider"),"Technical details"),(MatrixEvent("Linux Audit","audit","OPENAT"),"Technical details"),
    (MatrixEvent("Linux inotify","Content read (copy possible)"),"Copied/Read"),(MatrixEvent("Linux inotify","File opened"),"File Opened"),(MatrixEvent("Linux inotify","Canary modified (encryption possible)"),"File Changed"),(MatrixEvent("Linux inotify","Canary content/metadata changed (encryption possible)"),"File Changed"),(MatrixEvent("Linux inotify","Canary path created/replaced"),"File Changed"),(MatrixEvent("Linux inotify","Canary path moved/replaced"),"File Changed"),(MatrixEvent("Linux inotify","Canary moved/renamed"),"File Renamed"),(MatrixEvent("Linux inotify","Canary deleted"),"File Deleted"),(MatrixEvent("Linux inotify","Canary metadata changed"),"Permissions Changed"),
    (MatrixEvent("Linux fanotify","Content read (copy possible)"),"Copied/Read"),(MatrixEvent("Linux fanotify","File opened"),"File Opened"),(MatrixEvent("Linux fanotify","Canary modified (encryption possible)"),"File Changed"),(MatrixEvent("Linux fanotify","Canary deleted"),"Technical details"),(MatrixEvent("Linux fanotify","Canary moved/renamed"),"Technical details"),(MatrixEvent("Linux fanotify","Canary content/metadata changed (encryption possible)"),"Technical details"),(MatrixEvent("Linux fanotify","Canary metadata changed"),"Technical details"),
    (MatrixEvent("macOS FSEvents","Canary modified (encryption possible)"),"File Changed"),(MatrixEvent("macOS FSEvents","Canary content/metadata changed (encryption possible)"),"File Changed"),(MatrixEvent("macOS FSEvents","Canary path created/replaced"),"File Changed"),(MatrixEvent("macOS FSEvents","Canary path moved/replaced"),"File Changed"),(MatrixEvent("macOS FSEvents","Canary moved/renamed"),"File Renamed"),(MatrixEvent("macOS FSEvents","Canary deleted"),"File Deleted"),(MatrixEvent("macOS FSEvents","Canary metadata changed"),"Permissions Changed"),(MatrixEvent("macOS FSEvents","File opened"),"Technical details"),(MatrixEvent("macOS FSEvents","Content read (copy possible)"),"Technical details"),
    (MatrixEvent("Unreviewed provider","Content read (copy possible)"),"Technical details"),(MatrixEvent("Unreviewed provider","Content written"),"Technical details"),(MatrixEvent("Unreviewed provider","Canary deleted"),"Technical details"),(MatrixEvent("Unreviewed provider","Access denied"),"Access Denied")
};
foreach(var (label,syscalls) in new[]{("File Opened",new[]{"open","openat","openat2"}),("Copied/Read",new[]{"read","pread64","readv","preadv","preadv2","copy_file_range","sendfile","splice"}),("File Changed",new[]{"write","pwrite64","writev","pwritev","pwritev2","truncate","ftruncate","creat"}),("File Renamed",new[]{"rename","renameat","renameat2"}),("File Deleted",new[]{"unlink","unlinkat","rmdir"}),("Permissions Changed",new[]{"chmod","fchmod","fchmodat","fchmodat2","chown","fchown","lchown","fchownat"})})
    actionMatrix.AddRange(syscalls.Select(syscall=>(MatrixEvent("Linux Audit","audit",syscall),label)));
foreach(var rule in KernelActivityRules.All)
{
    var label=rule.Action switch{"open"=>"File Opened","read"=>"Copied/Read","write"=>"File Changed","rename"=>"File Renamed","metadata" or "permissions"=>"Permissions Changed","open-request"=>"Open Requested","access-request"=>"Access Requested","rename-request"=>"Rename Requested","delete-request"=>"Delete Requested","metadata-request"=>"Metadata Change Requested","mapping-request"=>"Mapping Requested",_=>throw new Exception("Unreviewed kernel label")};
    foreach(var outcome in new[]{"Success","Failed","Unknown"})
        actionMatrix.Add((MatrixEvent(rule.Provider,rule.Operation,"kernel",outcome,rule.Provider),rule.Provider=="Windows minifilter"&&outcome=="Unknown"?"Technical details":outcome=="Failed"&&rule.Evidence!="intent"?"Operation Failed":label));
    actionMatrix.Add((MatrixEvent(rule.Provider,rule.Operation,"kernel","Success","Wrong provider"),"Technical details"));
}
foreach(var item in actionMatrix)Check(EventHistoryPresentation.Action(item.Event,EventActivity.From(item.Event))==item.Label,$"source-aware presentation: {item.Event.Source} / {item.Event.Operation} / {item.Event.Attribution?.Syscall??"no syscall"} => {item.Label}");
store.Ingest(endpoint.EndpointId,new(actionMatrix.Select(x=>x.Event).ToArray()));
var matrixIds=actionMatrix.Select(x=>x.Event.EventId).ToHashSet(StringComparer.Ordinal);var matrixRows=store.Events(0,2000).Where(x=>matrixIds.Contains(x.Event.EventId)).ToArray();
Check(matrixRows.Length==actionMatrix.Count,"source/action matrix persisted without rewriting raw rows");
var actionLabels=new[]{"Access Denied","Copied/Read","File Changed","File Renamed","File Deleted","Permissions Changed","File Opened","Canary Activated","Technical details","Open Requested","Access Requested","Rename Requested","Delete Requested","Metadata Change Requested","Mapping Requested","Operation Failed"};
foreach(var label in actionLabels)
{
    var filtered=await store.History(new(){Action=label,PathContains="/action-matrix/",Limit=500});var returned=filtered.Items.Select(x=>x.Event.EventId).ToHashSet(StringComparer.Ordinal);
    Check(matrixRows.All(row=>returned.Contains(row.Event.EventId)==(EventHistoryPresentation.Action(row.Event,EventActivity.From(row.Event))==label)),"Action filter iff displayed label: "+label);
}
var actionSorted=await store.History(new(){Sort="action",Direction="asc",PathContains="/action-matrix/",Limit=500});
var expectedActionOrder=matrixRows.OrderBy(row=>EventHistoryPresentation.Action(row.Event,EventActivity.From(row.Event)),StringComparer.Ordinal).ThenByDescending(row=>row.Sequence).Select(row=>row.Event.EventId);
Check(actionSorted.Items.Select(row=>row.Event.EventId).SequenceEqual(expectedActionOrder),"Action sort key equals displayed label with sequence-desc ties");
Check(!typeof(EventHistoryPresentation).GetMethods().Any(x=>x.Name.Contains("Correlation",StringComparison.OrdinalIgnoreCase)),"presentation does not invent callback correlation or confirmed-read claims");
if(args.Contains("--scale")||args.Contains("--observed-scale"))
{
    var scaleRoot=Path.Combine(root,"scale");var scale=new Store(scaleRoot);var ep=scale.Enroll(new(scale.CreateCode().Code,"scale","fixture"))!;
    var stopwatch=Stopwatch.StartNew();
    for(var batch=0;batch<100;batch++)scale.Ingest(ep.EndpointId,new(Enumerable.Range(batch*1000,1000).Select(i=>new AgentEvent(Guid.NewGuid().ToString("N"),epoch.AddMilliseconds(i),"Read intent","/fixture/"+i,i%5==0?null:"user"+(i%97),i%7==0?null:"/process/"+(i%37),i%3==0?null:i%10000,"fixture")).ToArray()));
    evidence.Add("Measured 100,000-row SQLite ingest ms: "+stopwatch.ElapsedMilliseconds);
    foreach(var field in args.Contains("--observed-scale")?new[]{"observed"}:new[]{"observed","user","process","pid"})foreach(var dir in new[]{"asc","desc"})
    {
        stopwatch.Restart();var page1=await scale.History(new(){Sort=field,Direction=dir,Limit=500});var page2=await scale.History(new(){Sort=field,Direction=dir,Limit=500},page1.Snapshot,page1.Next);
        Check(page1.Items.Count==500&&page2.Items.Count==500&&!page1.Items.Select(e=>e.Sequence).Intersect(page2.Items.Select(e=>e.Sequence)).Any(),"100,000-row scale page boundaries "+field+" "+dir);
        var joined=page1.Items.Concat(page2.Items).ToArray();Check(joined.Zip(joined.Skip(1)).All(pair=>Compare(Key(pair.First,field),Key(pair.Second,field),dir=="desc")<=0),"100,000-row scale numeric/text order "+field+" "+dir);
        evidence.Add($"Measured SQLite 100,000-row {field} {dir}, first+second 500-row pages: {stopwatch.ElapsedMilliseconds} ms; local fixture, not enterprise SLA.");
    }
}
{
    var filteredStore=new Store(Path.Combine(root,"new-filters"));
    var win=filteredStore.Enroll(new(filteredStore.CreateCode().Code,"WindowsFilterHost","fixture"))!;
    var lin=filteredStore.Enroll(new(filteredStore.CreateCode().Code,"LinuxFilterHost","fixture"))!;
    var legacy=filteredStore.Enroll(new(filteredStore.CreateCode().Code,"LegacyFilterHost","fixture"))!;
    filteredStore.Heartbeat(win.EndpointId,new("fixture","Monitoring"){OperatingSystem="windows"});
    filteredStore.Heartbeat(lin.EndpointId,new("fixture","Monitoring"){OperatingSystem="linux"});
    filteredStore.RecordContact(win.EndpointId,System.Net.IPAddress.Parse("::ffff:192.0.2.10"));
    filteredStore.RecordContact(lin.EndpointId,System.Net.IPAddress.Parse("2001:db8::1"));
    foreach(var sensor in new[]{win,lin,legacy})foreach(var severity in new[]{"informational","normal","alert","warning","high","critical",null})
    {
        var item=new AgentEvent(Guid.NewGuid().ToString("N"),epoch.AddMinutes(Array.IndexOf(new[]{"informational","normal","alert","warning","high","critical",null},severity)),"Read","/fixture","user","process",42,"fixture");
        if(severity!=null)item=item with{Forensics=new(){Detection=new("alert",severity,[],["FIXTURE"])}};
        filteredStore.Ingest(sensor.EndpointId,new([item]));
    }
    var combined=await filteredStore.History(new(){Os="windows",Ip="192.0.2.10",Host="WINDOWSFILTER",From=epoch.AddMinutes(3),To=epoch.AddMinutes(3),Notification="warning"});
    Check(combined.Total==1&&combined.Items.Single().EndpointId==win.EndpointId,"OS/IP/host/inclusive date-time/severity filters combine with AND");
    foreach(var level in new[]{"info","normal","alert","warning","high","critical","unclassified"}){
        var result=await filteredStore.History(new(){Notification=level});var normalAlert=level is "normal" or "alert";Check(result.Total==(normalAlert?6:3)&&result.Items.All(x=>EventHistoryPresentation.Notification(x.Event)==(normalAlert?"alert":level)),"reported notification filter matches presentation: "+level);
    }
    Check((await filteredStore.History(new(){Os="unknown"})).Total==7,"missing OS explicitly matches Unknown");
    var windowsAlerts=await filteredStore.History(new(){Os="windows",Notification="alert",Limit=1});
    Check(windowsAlerts.Total==2&&windowsAlerts.Items.Single().EndpointId==win.EndpointId&&windowsAlerts.Next!=null,"Windows Alert filter includes normal and explicit alert with paging");
    var windowsNext=await filteredStore.History(new(){Os="windows",Notification="alert",Limit=1},windowsAlerts.Snapshot,windowsAlerts.Next);
    Check(windowsNext.Items.Count==1&&windowsNext.Items[0].Event.EventId!=windowsAlerts.Items[0].Event.EventId,"Windows filtered page resumes without omitting an alert");
    Check((await filteredStore.History(new(){Os="windows",Notification="normal"})).Total==2,"legacy normal filter aliases Alert without losing Windows records");
    var hostActions=await filteredStore.History(new(){Host="WINDOWSFILTER",Sort="action",Limit=2});
    Check(hostActions.Total==7&&hostActions.Items.All(x=>x.EndpointId==win.EndpointId),"hostname source restriction preserves case-insensitive action sorting");
    var hostAlertQuery=new EventHistoryQuery{Host="windowsfilter",Os="windows",Notification="alert",Sort="action",Limit=1};
    var hostAlertPage=await filteredStore.History(hostAlertQuery);
    var hostAlertNext=await filteredStore.History(hostAlertQuery,hostAlertPage.Snapshot,hostAlertPage.Next);
    Check(hostAlertPage.Total==2&&hostAlertPage.Items.Count==1&&hostAlertNext.Items.Count==1&&hostAlertPage.Items[0].Sequence!=hostAlertNext.Items[0].Sequence,"Windows hostname/Alert/action sorting retains snapshot paging");
    foreach(var literal in new[]{"%","_","\\"})Check((await filteredStore.History(new(){Host=literal,Sort="action"})).Total==0,"hostname source restriction escapes literal "+literal);
    Check((await filteredStore.History(new(){Ip="2001:db8::1"})).Total==7,"IPv6 contact exact match");
    Check((await filteredStore.History(new(){Ip="192.0.2.10",Os="linux"})).Total==0,"contradictory filters return zero");
    filteredStore.RecordContact(win.EndpointId,System.Net.IPAddress.Parse("192.0.2.11"));
    filteredStore=new Store(Path.Combine(root,"new-filters"));
    Check((await filteredStore.History(new(){Ip="192.0.2.10"})).Total==0&&(await filteredStore.History(new(){Ip="192.0.2.11"})).Total==7,"latest contact address updates and persists without changing event payloads");
    var contacts=filteredStore.HistoryContacts(new[]{win.EndpointId,legacy.EndpointId});Check(contacts[win.EndpointId].Os=="windows"&&contacts[legacy.EndpointId].Ip==null,"API contact metadata preserves missing IP as null");
    var q=new EventHistoryQuery{Os="windows",From=epoch,Limit=2};var firstPage=await filteredStore.History(q);var nextPage=await filteredStore.History(q,firstPage.Snapshot,firstPage.Next);
    Check(firstPage.Total==7&&nextPage.Total==7&&!firstPage.Items.Select(x=>x.Sequence).Intersect(nextPage.Items.Select(x=>x.Sequence)).Any(),"filtered paging keeps totals and distinct rows");
    foreach(var invalid in new[]{new EventHistoryQuery{Os="ubuntu"},new(){Ip="bad ip"},new(){Notification="safe"},new(){From=epoch.AddDays(1),To=epoch}}){var rejected=false;try{await filteredStore.History(invalid);}catch(ArgumentException){rejected=true;}Check(rejected,"invalid new filter rejected");}
    foreach(var raw in new[]{"2026-01-01T00:00:00","yesterday","2026-99-99T00:00:00Z"}){var rejected=false;try{EventHistoryQuery.Parse(new QueryCollection(new Dictionary<string,StringValues>{{"from",raw}}));}catch(ArgumentException){rejected=true;}Check(rejected,"date without valid explicit timezone rejected");}
    var parsed=EventHistoryQuery.Parse(new QueryCollection(new Dictionary<string,StringValues>{{"from","2026-01-01T04:00:00+04:00"},{"ip","::ffff:192.0.2.11"}}));Check(parsed.From==epoch&&parsed.Ip=="192.0.2.11","offset datetime and mapped IP normalize correctly");
    Check(q.Fingerprint()!=(q with{Notification="info"}).Fingerprint()&&q.Fingerprint()!=(q with{Ip="192.0.2.11"}).Fingerprint()&&q.Fingerprint()!=(q with{To=epoch}).Fingerprint(),"new filters participate in protected cursor binding");
    filteredStore.InitializeDecoyServiceStorage();var service=filteredStore.CreateDecoyService(new("Filter service","Fixture",false,0,""){RequestId=Guid.NewGuid().ToString("N")},"fixture");
    filteredStore.ChangeDecoyService(service.Service.Id,new("Filter service","Fixture",true,1,""),"fixture");
    Check(filteredStore.TouchDecoyService(service.Service.Id,service.ActivationPath.Split('/').Last(),"::ffff:192.0.2.50","GET"),"service evidence fixture activated");
    var serviceHistory=await filteredStore.History(new(){Ip="192.0.2.50",Os="unknown",Host="Management server",Notification="unclassified"});
    Check(serviceHistory.Total==1&&serviceHistory.Items.Single().Sequence<0,"service source IP and Unknown OS combine without fabricating client platform; mapped IPv4 matches");

}
var timer=Stopwatch.StartNew();await store.History(new(){Sort="user",Limit=100});timer.Stop();evidence.Add($"Measured SQLite 1,100-row first-page user sort: {timer.ElapsedMilliseconds} ms; not enterprise-scale acceptance.");
{
 var shareStore=new Store(Path.Combine(root,"smb-boundary"));var shareSensor=shareStore.Enroll(new(shareStore.CreateCode().Code,"ShareHost","fixture"))!;
 shareStore.Heartbeat(shareSensor.EndpointId,new("fixture","Monitoring"){OperatingSystem="windows"});shareStore.RecordContact(shareSensor.EndpointId,System.Net.IPAddress.Parse("192.0.2.99"));
 AgentEvent Share(string outcome)=>new(Guid.NewGuid().ToString("N"),DateTimeOffset.UtcNow,outcome=="Denied"?"Share access denied":"Share access checked",@"C:\BoundaryQA\canary.bin",@"LAB\alice",null,null,"Windows audit 5145"){
  Attribution=new(){Provider="Windows Security Audit",Level="Partial attribution",Outcome=outcome=="Denied"?"Failed":"Share check granted",UserSid="S-1-5-21-1-2-3-1001",UserName=@"LAB\alice",LogonId="0x123",AccessMask="0x1",EventTimeCredentials=true,WindowsShare=new(){SourceAddress="192.0.2.10",RawSourceAddress="::ffff:192.0.2.10",SourcePort=49152,ShareName=@"\\*\BoundaryQA",ShareLocalPath=@"C:\BoundaryQA",RelativeTargetName="canary.bin",AuthorizationOutcome=outcome}}
 };
 var deniedShare=Share("Denied");var grantedShare=Share("Granted");Check(WindowsShareEvidence.Matches(deniedShare)&&WindowsShareEvidence.Matches(grantedShare),"SMB fixture has valid evidence semantics");
 shareStore.Ingest(shareSensor.EndpointId,new([deniedShare,grantedShare]));
 var deniedPage=await shareStore.History(new(){Ip="192.0.2.10",Action="Access Denied"});
 Check(deniedPage.Total==1&&deniedPage.Items.Single().Event.EventId==deniedShare.EventId,"SMB denied source IP and action filters use remote evidence");
 var grantedPage=await shareStore.History(new(){Ip="192.0.2.10",Action="Open Requested"});
 Check(grantedPage.Total==1&&EventHistoryPresentation.Action(grantedPage.Items.Single().Event,EventActivity.From(grantedPage.Items.Single().Event))=="Open Requested"&&EventActivity.From(grantedPage.Items.Single().Event).Outcome=="unknown","SMB granted check remains request evidence in SQL and display");
 Check((await shareStore.History(new(){Ip="192.0.2.99"})).Total==0,"SMB source does not substitute reporting sensor IP");
 var deniedItem=deniedPage.Items.Single();var presented=new HistoryEvent(deniedItem.Sequence,deniedItem.EndpointId,deniedItem.ReceivedUtc,deniedItem.Event,EventActivity.From(deniedItem.Event));
 Check(deniedItem.Event.ProcessId==null&&!presented.ResponseCandidate,"SMB worker or remote PID is not fabricated or eligible for process response");
}
{
 var isolated=new Store(Path.Combine(root,"sequence-page"));var a=isolated.Enroll(new(isolated.CreateCode().Code,"sequence-a","fixture"))!;var b=isolated.Enroll(new(isolated.CreateCode().Code,"sequence-b","fixture"))!;
 for(var i=0;i<41;i++)isolated.Ingest(i%2==0?a.EndpointId:b.EndpointId,new([new(Guid.NewGuid().ToString("N"),DateTimeOffset.UtcNow,"Read","/owned/sequence",null,null,null,"Fixture")]));
 foreach(var direction in new[]{"asc","desc"}){
  var q=new EventHistoryQuery{Endpoint=a.EndpointId,Sort="sequence",Direction=direction,Limit=3};var initialSequencePage=await isolated.History(q);var snapshot=initialSequencePage.Snapshot;var found=initialSequencePage.Items.Select(e=>e.Sequence).ToList();var next=initialSequencePage.Next;
  isolated.Ingest(a.EndpointId,new([new(Guid.NewGuid().ToString("N"),DateTimeOffset.UtcNow,"Read","/owned/newer",null,null,null,"Fixture")]));
  while(next!=null){var page=await isolated.History(q,snapshot,next);Check(page.Snapshot==snapshot&&page.Total==initialSequencePage.Total,"scoped sequence cursor retains fixed snapshot and count "+direction);found.AddRange(page.Items.Select(e=>e.Sequence));next=page.Next;}
  var expected=isolated.Events(0,100).Where(e=>e.EndpointId==a.EndpointId&&e.Sequence<=snapshot).Select(e=>e.Sequence);expected=direction=="asc"?expected.Order():expected.OrderDescending();
  Check(found.SequenceEqual(expected)&&found.Distinct().Count()==found.Count,"scoped indexed sequence paging excludes other sensors and later arrivals "+direction);
  var rejected=false;try{await isolated.History(q,snapshot,new(found[0],Guid.NewGuid().ToString("N"),"999999"));}catch(ArgumentException){rejected=true;}Check(rejected,"scoped sequence cursor rejects a mismatched sequence key "+direction);
 }
}
{
 var actorRoot=Path.Combine(root,"actor-filter-index");var actors=new Store(actorRoot);
 var a=actors.Enroll(new(actors.CreateCode().Code,"actor-a","fixture"))!;var b=actors.Enroll(new(actors.CreateCode().Code,"actor-b","fixture"))!;
 foreach(var sensor in new[]{a,b})foreach(var pid in new int?[]{99,99,99,99,0,null})
  actors.Ingest(sensor.EndpointId,new([new(Guid.NewGuid().ToString("N"),DateTimeOffset.UtcNow,"Read","/owned/actor",null,null,pid,"Fixture")]));
 using(var connection=new SqliteConnection(new SqliteConnectionStringBuilder{DataSource=Path.Combine(actorRoot,"management.db")}.ToString())){
  connection.Open();using var command=connection.CreateCommand();
  command.CommandText="EXPLAIN QUERY PLAN SELECT event_id FROM events WHERE CAST(json_extract(payload,'$.ProcessId') AS INTEGER)=99 AND endpoint=$endpoint AND sequence<999 ORDER BY sequence";
  command.Parameters.AddWithValue("$endpoint",a.EndpointId);using var reader=command.ExecuteReader();var plan=new List<string>();while(reader.Read())plan.Add(reader.GetString(3));
  Check(plan.Any(x=>x.Contains("events_history_pid",StringComparison.Ordinal)),"exact endpoint/PID lookup selects the actor filter index");
 }
 foreach(var endpointId in new string?[]{null,a.EndpointId})foreach(var direction in new[]{"asc","desc"})foreach(var pid in new[]{99,0}){
  var q=new EventHistoryQuery{Endpoint=endpointId,Pid=pid,Sort="observed",Direction=direction,Limit=2};var actorFirst=await actors.History(q);
  var ids=actorFirst.Items.Select(x=>x.Event.EventId).ToList();var next=actorFirst.Next;
  while(next!=null){var page=await actors.History(q,actorFirst.Snapshot,next);ids.AddRange(page.Items.Select(x=>x.Event.EventId));next=page.Next;Check(page.Total==actorFirst.Total,"indexed actor paging retains count and snapshot");}
  var wanted=actors.Events(0,100).Where(x=>x.Event.ProcessId==pid&&(endpointId==null||x.EndpointId==endpointId)).Select(x=>x.Event.EventId).ToHashSet();
  Check(ids.Count==wanted.Count&&ids.Distinct().Count()==ids.Count&&wanted.SetEquals(ids),"indexed actor filter preserves all same-PID events, endpoint scope and nullable PID semantics "+direction+"/"+pid);
 }
}
if(args.Contains("--action-scale"))
{
    var actionRoot=Path.Combine(root,"wide-action-scale");var actionStore=new Store(actionRoot);
    var sensor=actionStore.Enroll(new(actionStore.CreateCode().Code,"wide-action-scale","fixture"))!;
    var other=actionStore.Enroll(new(actionStore.CreateCode().Code,"other-action-scale","fixture"))!;
    actionStore.Heartbeat(sensor.EndpointId,new("fixture","Monitoring"){OperatingSystem="linux"});
    actionStore.Heartbeat(other.EndpointId,new("fixture","Monitoring"){OperatingSystem="windows"});
    actionStore.InitializeDecoyServiceStorage();
    var scaleService=actionStore.CreateDecoyService(new("Wide history service","Fixture",false,0,""){RequestId=Guid.NewGuid().ToString("N")},"fixture");
    actionStore.ChangeDecoyService(scaleService.Service.Id,new("Wide history service","Fixture",true,1,""),"fixture");
    Check(actionStore.TouchDecoyService(scaleService.Service.Id,scaleService.ActivationPath.Split('/').Last(),"192.0.2.50","GET"),"wide action fixture includes actual server-service UNION branch");
    var calls=new[]{"read","write","rename","unlink","openat"};
    var labels=new[]{"Copied/Read","File Changed","File Renamed","File Deleted","File Opened"};
    var expected=new List<(string Id,string Action,long Order)>();
    var actionTimer=Stopwatch.StartNew();
    for(var batch=0;batch<100;batch++)
    {
        var events=Enumerable.Range(batch*100,100).Select(i=>new AgentEvent(Guid.NewGuid().ToString("N"),epoch.AddMilliseconds(i),"audit operation","/wide/"+new string('x',8192)+"/"+i,"fixture",i%1000==0?"/usr/bin/fixture_%\\needle":"/usr/bin/fixture",i%97,"Linux Audit")
            {Attribution=new(){Provider="Linux Audit",Syscall=calls[i%5],Outcome="Success"}}).ToArray();
        actionStore.Ingest(sensor.EndpointId,new(events));
        foreach(var item in events)expected.Add((item.EventId,EventHistoryPresentation.Action(item,EventActivity.From(item)),expected.Count+1));
    }
    actionStore.Ingest(other.EndpointId,new([new AgentEvent(Guid.NewGuid().ToString("N"),epoch,"Access denied","/other",null,null,null,"fixture")]));
    evidence.Add("Measured wide 10,000-row action ingest ms: "+actionTimer.ElapsedMilliseconds);
    foreach(var direction in new[]{"asc","desc"})
    {
        var query=new EventHistoryQuery{Endpoint=sensor.EndpointId,Sort="action",Direction=direction,Limit=500};actionTimer.Restart();
        var firstPage=await actionStore.History(query);var nextPage=await actionStore.History(query,firstPage.Snapshot,firstPage.Next);
        var order=direction=="asc"?expected.OrderBy(x=>x.Action,StringComparer.Ordinal):expected.OrderByDescending(x=>x.Action,StringComparer.Ordinal);
        var wanted=order.ThenByDescending(x=>x.Order).Take(1000).Select(x=>x.Id);
        Check(firstPage.Total==10000&&nextPage.Total==10000&&firstPage.Items.Concat(nextPage.Items).Select(x=>x.Event.EventId).SequenceEqual(wanted),"wide action index preserves exact displayed labels, endpoint scope, snapshot count and next-page ties: "+direction);
        evidence.Add($"Measured wide 10,000-row action {direction} first+second pages ms: {actionTimer.ElapsedMilliseconds}");
    }
    foreach(var label in labels)
    {
        var page=await actionStore.History(new(){Endpoint=sensor.EndpointId,Action=label,Limit=500});
        Check(page.Total==2000&&page.Items.Count==500&&page.Items.All(x=>EventHistoryPresentation.Action(x.Event,EventActivity.From(x.Event))==label),"wide action filter retains truthful totals and presentation parity: "+label);
    }
    foreach(var direction in new[]{"asc","desc"})
    {
        var page=await actionStore.History(new(){Os="linux",Sort="action",Direction=direction,Limit=25});
        Check(page.Total==10000&&page.Items.Count==25&&page.Items.All(x=>x.EndpointId==sensor.EndpointId),"wide action OS filter with service UNION retains scope and totals: "+direction);
    }
    var combinedPage=await actionStore.History(new(){Sort="action",Limit=25});
    Check(combinedPage.Total==10002&&combinedPage.Items.Count==25,"wide action unfiltered service UNION retains both sources and truthful totals");
    var expression=(string)typeof(Store).GetMethod("HistoryActionExpression",System.Reflection.BindingFlags.NonPublic|System.Reflection.BindingFlags.Static)!.Invoke(null,[false])!;
    using var connection=new SqliteConnection("Data Source="+Path.Combine(actionRoot,"management.db"));connection.Open();
    foreach(var direction in new[]{"asc","desc"})
    {
        using var command=connection.CreateCommand();
        command.CommandText=$"EXPLAIN QUERY PLAN SELECT sequence,event_id FROM events INDEXED BY events_history_action_{direction} WHERE endpoint=$endpoint ORDER BY CASE WHEN ({expression}) IS NULL THEN 1 ELSE 0 END ASC,({expression}) {direction.ToUpperInvariant()},sequence DESC,event_id DESC LIMIT 500";
        command.Parameters.AddWithValue("$endpoint",sensor.EndpointId);using var reader=command.ExecuteReader();var plan=new List<string>();while(reader.Read())plan.Add(reader.GetString(3));
        Check(plan.Any(x=>x.Contains("events_history_action_"+direction,StringComparison.Ordinal))&&!plan.Any(x=>x.Contains("TEMP B-TREE",StringComparison.Ordinal)),"wide action order uses derived index without temporary sort: "+direction);
    }
    var reopened=new Store(actionRoot);Check((await reopened.History(new(){Action="Access Denied",Endpoint=other.EndpointId})).Total==1,"action indexes survive reopen and retain failed-operation classification");
    foreach(var processQuery in new[]{new EventHistoryQuery{Process="/usr/bin/fixture_%\\needle"},new(){ProcessContains="_%\\needle"},new(){ProcessContains="_%\\NEEDLE"}})
    {
        var query=processQuery with{Endpoint=sensor.EndpointId,Sort="sequence",Direction="asc",Limit=6};actionTimer.Restart();
        var processFirst=await reopened.History(query);var processNext=await reopened.History(query,processFirst.Snapshot,processFirst.Next);
        Check(processFirst.Total==10&&processNext.Total==10&&processFirst.Items.Concat(processNext.Items).All(x=>x.Event.Process=="/usr/bin/fixture_%\\needle")&&processFirst.Items.Concat(processNext.Items).Select(x=>x.Sequence).SequenceEqual(Enumerable.Range(0,10).Select(i=>(long)i*1000+1)),"wide process filtering preserves exact/escaped contains, case semantics, totals and cursor ordering");
        evidence.Add($"Measured wide 10,000-row process first+second pages ms: {actionTimer.ElapsedMilliseconds}");
    }
    Check((await reopened.History(new(){Endpoint=other.EndpointId,ProcessContains="needle"})).Total==0,"process index cannot cross sensor boundaries or manufacture null actor metadata");
    using(var command=connection.CreateCommand())
    {
        command.CommandText="EXPLAIN SELECT COUNT(*) FROM events INDEXED BY events_history_endpoint_process WHERE endpoint=$endpoint AND LOWER(NULLIF(json_extract(payload,'$.Process'),'') COLLATE BINARY) LIKE '%needle%' AND sequence<=10001";
        command.Parameters.AddWithValue("$endpoint",sensor.EndpointId);using var reader=command.ExecuteReader();var functions=new List<string>();
        while(reader.Read())if(reader.GetString(1)=="Function"&&!reader.IsDBNull(5))functions.Add(reader.GetString(5));
        Check(!functions.Any(x=>x.Contains("json_extract",StringComparison.Ordinal)),"process count executes against compact indexed evidence without decoding wide JSON payloads");
    }
}
File.WriteAllLines(Path.Combine(root,"results.txt"),evidence);Console.WriteLine($"Evidence: {root}");Console.WriteLine("SQL Server/native browser/enterprise scale acceptance not inferred.");
if(args.Length>=2){try{await HistoryHttpChecks.Run(args[0],args[1],root,Check,()=>File.WriteAllLines(Path.Combine(root,"results.txt"),evidence),args.Contains("--preview"),args.Contains("--admin-preview"));}finally{File.WriteAllLines(Path.Combine(root,"results.txt"),evidence);}}
