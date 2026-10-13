using Microsoft.Data.SqlClient;
using Microsoft.Extensions.Configuration;
using RansomFree.Contracts;
using RansomFree.Persistence;
using RansomFree.Server;
var connection=Environment.GetEnvironmentVariable("RF_HISTORY_TRUST_SQL");
if(string.IsNullOrWhiteSpace(connection)){Console.WriteLine("PENDING SQL runtime: set RF_HISTORY_TRUST_SQL to an isolated, migrated, empty sequester_wsq03_* database with validated TLS.");return 2;}
var parsed=new SqlConnectionStringBuilder(connection);
if(!parsed.InitialCatalog.StartsWith("sequester_wsq03_",StringComparison.OrdinalIgnoreCase))throw new InvalidOperationException("Requires dedicated sequester_wsq03_* test database. No DDL or cleanup is performed.");
var settings=new DatabaseSettings(new ConfigurationBuilder().AddInMemoryCollection(new Dictionary<string,string?>{["Database:Provider"]="SqlServer",["Database:ConnectionString"]=connection}).Build());
var root=Path.Combine("D:\\Codex\\RansomFree\\tests","history-trust-sql-"+Guid.NewGuid().ToString("N"));Directory.CreateDirectory(root);
var store=new Store(root,settings);if(store.Inventory().Count!=0||store.Events(0,1).Count!=0||store.ReadTrustPolicy().Revision!=0)throw new InvalidOperationException("Test database must be empty; existing records preserved.");
var results=new List<string>();void Check(bool ok,string label){if(!ok)throw new Exception(label);results.Add("PASS: "+label);Console.WriteLine(results[^1]);File.WriteAllLines(Path.Combine(root,"results.txt"),results);}
var endpoint=store.Enroll(new(store.CreateCode().Code,"SQL history trust fixture","fixture"))!;var now=DateTimeOffset.UtcNow;
var events=Enumerable.Range(0,1100).Select(i=>new AgentEvent(Guid.NewGuid().ToString("N"),now.AddMilliseconds(-i),"Read intent","/fixture/"+i,i%5==0?null:"user"+(i%13),i%7==0?null:"/process/"+(i%9),i%3==0?null:i%127,"Linux Audit")).ToArray();
foreach(var batch in events.Chunk(100))store.Ingest(endpoint.EndpointId,new(batch));
store=new Store(root,settings);var all=store.Events(0,2000);Check(all.Count==1100,"SQL persistence/reopen retains 1100 events");
object? Key(StoredEvent e,string field)=>field switch{"user"=>e.Event.User,"process"=>e.Event.Process,"pid"=>e.Event.ProcessId,_=>throw new Exception()};
int Compare(object? a,object? b,bool descending){if(a==null)return b==null?0:1;if(b==null)return -1;var n=a is string x&&b is string y?StringComparer.Ordinal.Compare(x,y):Convert.ToInt64(a).CompareTo(Convert.ToInt64(b));return descending?-n:n;}
foreach(var field in new[]{"user","process","pid"})foreach(var direction in new[]{"asc","desc"})
{
    var query=new EventHistoryQuery{Sort=field,Direction=direction,Limit=137};HistoryPosition? position=null;long? snapshot=null;var found=new List<StoredEvent>();
    do{var page=await store.History(query,snapshot,position);snapshot=page.Snapshot;position=page.Next;found.AddRange(page.Items);if(found.Count>1100)throw new Exception("SQL cursor did not terminate");}while(position!=null);
    var expected=all.OrderBy(e=>e,Comparer<StoredEvent>.Create((a,b)=>{var n=Compare(Key(a,field),Key(b,field),direction=="desc");return n==0?a.Sequence.CompareTo(b.Sequence):n;}));
    Check(found.Select(e=>e.Sequence).SequenceEqual(expected.Select(e=>e.Sequence)),"SQL complete numeric/text null-last cursor traversal "+field+" "+direction);
}
foreach(var query in new[]{new EventHistoryQuery{User="user2"},new(){Process="/process/2"},new(){Pid=10}}){var page=await store.History(query);Check(page.Items.Count>0&&page.Items.All(e=>(query.User==null||e.Event.User==query.User)&&(query.Process==null||e.Event.Process==query.Process)&&(query.Pid==null||e.Event.ProcessId==query.Pid)),"SQL exact actor filter");}
var group=store.CreateGroup("SQL fixture group","fixture-admin");store.AssignGroup(endpoint.EndpointId,new(group.Id,null),"fixture-admin");store.InitializeTrustStorage();
var rule=new TrustRule(Guid.NewGuid().ToString("N"),"organization","server","account",["read"],"informational",now.AddMinutes(-1),now.AddHours(1)){Enabled=true,Authority=endpoint.EndpointId,AccountId="1000",AccountKind="uid"};
var child=rule with{Id=Guid.NewGuid().ToString("N"),Scope="group",ScopeId=group.Id,ParentRuleId=rule.Id};var host=child with{Id=Guid.NewGuid().ToString("N"),Scope="host",ScopeId=endpoint.EndpointId,ParentRuleId=child.Id};
var policy=store.PublishTrustPolicy(new(0,"enforce",[rule,child,host],[],"unused"),"fixture-admin");Check(new Store(root,settings).ReadTrustPolicy().Digest()==policy.Digest(),"SQL hierarchical policy transaction survives reopen");
var assignment=store.TrustAssignment(endpoint.EndpointId);Check(store.RecordTrustReceipt(endpoint.EndpointId,new(1,policy.Revision,policy.Digest(),group.Id,"enforce")),"SQL exact receipt persisted");
var conflict=false;try{store.PublishTrustPolicy(new(0,"enforce",[],[],"unused"),"fixture-admin");}catch(TrustPolicyConflictException){conflict=true;}Check(conflict,"SQL stale publication conflict preserves active policy");
Console.WriteLine(root);Console.WriteLine("SQL runtime only. No external Wazuh or packaged native acceptance inferred.");return 0;
