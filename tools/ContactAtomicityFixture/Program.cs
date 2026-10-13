using System.Net;
using System.Text.Json;
using Microsoft.Data.Sqlite;
using RansomFree.Contracts;
using RansomFree.Server;

var root=Path.Combine(@"D:\Codex\RansomFree\boundary-20261006","contact-atomicity-"+Guid.NewGuid().ToString("N"));
Directory.CreateDirectory(root);var store=new Store(root);var checks=new List<string>();
void Check(bool passed,string name){if(!passed)throw new Exception(name);checks.Add(name);Console.WriteLine("PASS: "+name);}
void Sql(string sql){using var c=new SqliteConnection("Data Source="+Path.Combine(root,"management.db"));c.Open();using var cmd=c.CreateCommand();cmd.CommandText=sql;cmd.ExecuteNonQuery();}
void RefuseContact(bool enabled)=>Sql(enabled?"CREATE TRIGGER qa_contact_refuse_insert BEFORE INSERT ON endpoint_contact BEGIN SELECT RAISE(ABORT,'owned contact failure'); END; CREATE TRIGGER qa_contact_refuse_update BEFORE UPDATE ON endpoint_contact BEGIN SELECT RAISE(ABORT,'owned contact failure'); END;":"DROP TRIGGER qa_contact_refuse_insert; DROP TRIGGER qa_contact_refuse_update;");
var enrolled=store.Enroll(new(store.CreateCode().Code,"contact-qa","fixture"))!;var id=enrolled.EndpointId;
var ip=IPAddress.Parse("192.0.2.10");var secondIp=IPAddress.Parse("192.0.2.11");
AgentEvent Event()=>new(Guid.NewGuid().ToString("N"),DateTimeOffset.UtcNow,"read",@"C:\QA\canary.txt","qa-user",@"C:\QA\actor.exe",1234,"owned contact fixture");
var first=Event();Check(store.Ingest(id,new([first]),ip)==new BatchReceipt(1,0),"event and initial server-observed address commit together");
Check(store.HistoryContacts([id])[id].Ip==ip.ToString(),"history sees actual connection address");
Check(store.Ingest(id,new([first]),secondIp)==new BatchReceipt(0,1)&&store.Events(0,100).Count==1,"identical event replay keeps duplicate count and updates source IP");
Check(store.HistoryContacts([id])[id].Ip==secondIp.ToString(),"duplicate replay still records the new connection address");
try{store.Ingest(id,new([first with{User="different"}]),ip);throw new Exception("Conflict accepted");}catch(EventConflictException){}
Check(store.HistoryContacts([id])[id].Ip==secondIp.ToString()&&store.Events(0,100).Count==1,"event conflict changes neither evidence nor contact");
RefuseContact(true);var failed=Event();
try{store.Ingest(id,new([failed]),ip);throw new Exception("Contact failure accepted");}catch(SqliteException ex){Check(ex.SqliteErrorCode==19,"owned trigger refuses contact persistence");}
Check(store.Events(0,100).All(e=>e.Event.EventId!=failed.EventId)&&store.HistoryContacts([id])[id].Ip==secondIp.ToString(),"contact failure rolls back the entire new event batch");
var before=store.Inventory().Single(e=>e.EndpointId==id);
try{store.Heartbeat(id,new("qa-new","heartbeat changed"),ip);throw new Exception("Heartbeat contact failure accepted");}catch(SqliteException){}
Check(store.Inventory().Single(e=>e.EndpointId==id).AgentVersion==before.AgentVersion,"contact failure rolls back heartbeat state");
RefuseContact(false);
Check(store.Ingest(id,new([failed]),ip)==new BatchReceipt(1,0),"unchanged retry succeeds after transient contact failure");
Check(store.Heartbeat(id,new("qa-new","heartbeat changed"),IPAddress.Parse("::ffff:192.0.2.12")),"heartbeat and mapped IPv4 contact commit together");
Check(store.HistoryContacts([id])[id].Ip=="192.0.2.12"&&store.Inventory().Single(e=>e.EndpointId==id).AgentVersion=="qa-new","mapped IPv4 normalization and heartbeat data preserved");
var absent=Guid.NewGuid().ToString("N");Check(store.Ingest(absent,new([Event()]),ip)==null&&!store.Heartbeat(absent,new("qa","absent"),ip),"unknown sensor cannot write events, heartbeat or contact");
store.Revoke(id);Check(store.Ingest(id,new([Event()]),ip)==null&&!store.Heartbeat(id,new("qa","revoked"),ip),"revoked sensor cannot update evidence or contact");
File.WriteAllText(Path.Combine(root,"RESULTS.json"),JsonSerializer.Serialize(new{Passed=true,Checks=checks,Scope="Isolated SQLite functional, rollback, immutable replay, source-IP and revocation checks; SQL Server runtime not exercised",Root=root},new JsonSerializerOptions{WriteIndented=true}));
Console.WriteLine($"PASS: {checks.Count} atomic contact checks; {root}");
