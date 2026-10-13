using System.Xml.Linq;
using System.Text.Json;
using RansomFree;
using RansomFree.Client;
using RansomFree.Contracts;
var count=0;
void Check(bool value,string label){if(!value)throw new Exception(label);count++;Console.WriteLine("PASS: "+label);}
const string path=@"C:\BoundaryQA\canary.bin";
var watched=new HashSet<string>(StringComparer.OrdinalIgnoreCase){path};
string Xml(string keywords="0x8010000000000000",string relative="canary.bin",string? ip="192.0.2.10",string? sid="S-1-5-21-1-2-3-1001"){
 XNamespace n="http://schemas.microsoft.com/win/2004/08/events/event";
 var fields=new Dictionary<string,string?>{{"SubjectUserSid",sid},{"SubjectUserName","alice"},{"SubjectDomainName","LAB"},{"SubjectLogonId","0x123"},{"ObjectType","File"},{"IpAddress",ip},{"IpPort","49152"},{"ShareName",@"\\*\BoundaryQA"},{"ShareLocalPath",@"\??\C:\BoundaryQA"},{"RelativeTargetName",relative},{"AccessMask","0x1"},{"AccessReason","%%4416: %%1802 D:(D;;FR;;;WD)"}};
 return new XElement(n+"Event",new XElement(n+"System",new XElement(n+"EventID",5145),new XElement(n+"EventRecordID",345),new XElement(n+"Keywords",keywords),new XElement(n+"TimeCreated",new XAttribute("SystemTime","2026-10-06T12:00:00Z"))),new XElement(n+"EventData",fields.Where(x=>x.Value!=null).Select(x=>new XElement(n+"Data",new XAttribute("Name",x.Key),x.Value)))).ToString();
}
AgentEvent Wire(Alert a)=>new(a.EventId,new(a.Time),a.Operation,a.Path,a.User,a.Executable??a.Process,a.ProcessId,a.Source){Attribution=a.Attribution};
var denied=AuditParser.Parse(Xml(),watched,999)!;var wire=Wire(denied);
Check(denied.Operation=="Share access denied"&&denied.User==@"LAB\alice"&&denied.ProcessId==null&&denied.Executable==null,"share denial retains authenticated user without fabricated process/PID");
Check(denied.Attribution!.WindowsShare!.SourceAddress=="192.0.2.10"&&denied.Attribution.WindowsShare.SourcePort==49152&&denied.Attribution.LogonId=="0x123","source endpoint and logon correlation fields");
Check(wire.Attribution!.IsValid()&&WindowsShareEvidence.Matches(wire),"versioned share evidence matches event");
Check(!LocalActorEvidence.IsComplete(wire),"share subject is not full remote actor attribution");
Check(EventActivity.From(wire).Outcome=="failed"&&EventActivity.From(wire).Evidence=="share-authorization","share denial has distinct evidence semantics");
var granted=Wire(AuditParser.Parse(Xml("0x8020000000000000"),watched,999)!);
Check(EventActivity.From(granted).Outcome=="unknown"&&granted.Attribution!.Outcome=="Share check granted","granted share check never claims completed NTFS I/O");
var mapped=AuditParser.Parse(Xml(ip:"::ffff:192.0.2.10"),watched,999)!.Attribution!.WindowsShare!;
Check(mapped.SourceAddress=="192.0.2.10"&&mapped.RawSourceAddress=="::ffff:192.0.2.10","mapped IPv4 normalized while raw address is preserved");
Check(AuditParser.Parse(Xml(ip:"invalid"),watched,999)!.Attribution!.WindowsShare!.SourceAddress==null,"invalid source address explicitly unavailable");
Check(AuditParser.Parse(Xml(keywords:"0x0"),watched,999)!.Attribution!.Outcome=="Unknown","absent outcome is not manufactured");
Check(AuditParser.Parse(Xml(),new HashSet<string>(),999)==null,"unmonitored share files are excluded");
foreach(var relative in new[]{@"..\canary.bin",@"\canary.bin",@"C:\canary.bin","canary.bin:stream",@"x\..\canary.bin"})Check(AuditParser.Parse(Xml(relative:relative),watched,999)==null,"unsafe relative target excluded: "+relative);
Check(!WindowsShareEvidence.Matches(wire with{ProcessId=4,Process="System"}),"SMB worker PID cannot masquerade as remote process");
Check(!WindowsShareEvidence.Matches(wire with{Source="Windows minifilter"}),"provider mismatch rejected");
Check(!WindowsShareEvidence.Matches(wire with{Attribution=wire.Attribution! with{CompleteRecordSet=true,Level="Full attribution"}}),"false full attribution rejected");
Check(!WindowsShareEvidence.Matches(wire with{Operation="Content read (copy possible)"}),"share authorization cannot become read evidence");
var roundtrip=JsonSerializer.Deserialize<AgentEvent>(JsonSerializer.Serialize(wire))!;
Check(WindowsShareEvidence.Matches(roundtrip)&&roundtrip.Attribution!.WindowsShare==wire.Attribution!.WindowsShare,"JSON preserves all share evidence");
const string multiline="%%4416:\t%%1801\tD:(A;;FA;;;WD)\n\t\t%%4417:\t%%1805\n\t";
var multilineXml=XDocument.Parse(Xml());XNamespace shareNs="http://schemas.microsoft.com/win/2004/08/events/event";
multilineXml.Descendants(shareNs+"Data").Single(x=>(string?)x.Attribute("Name")=="AccessReason").Value=multiline;
var multilineEvent=Wire(AuditParser.Parse(multilineXml.ToString(),watched,999)!);
Check(WindowsShareEvidence.Matches(multilineEvent)&&multilineEvent.Attribution!.WindowsShare!.AccessReason==multiline,"Windows multiline access-check evidence preserved exactly");
Check(JsonSerializer.Deserialize<AgentEvent>(JsonSerializer.Serialize(multilineEvent))!.Attribution!.WindowsShare!.AccessReason==multiline,"multiline reason survives SIEM JSON roundtrip");
var crlfReason=multiline.Replace("\n","\r\n");var crlfEvidence=wire.Attribution!.WindowsShare! with{AccessReason=crlfReason};
Check(crlfEvidence.IsValid()&&JsonSerializer.Deserialize<WindowsShareEvidence>(JsonSerializer.Serialize(crlfEvidence))!.AccessReason==crlfReason,"CRLF reason accepted and preserved in structured output");
foreach(var control in new[]{'\0','\u001b','\u000b','\u007f'})Check(!(wire.Attribution!.WindowsShare! with{AccessReason="reason"+control}).IsValid(),"non-report control character remains rejected: "+(int)control);
Check(!(wire.Attribution!.WindowsShare! with{AccessReason=new string('x',4097)}).IsValid(),"oversized reason remains rejected");
Check(!(wire.Attribution!.WindowsShare! with{ShareLocalPath="C:\\BoundaryQA\n"}).IsValid(),"path controls remain rejected");
if(args.Length==2&&args[0]=="--live-capture"){
 using var live=JsonDocument.Parse(File.ReadAllText(args[1]));var matched=0;
 foreach(var record in live.RootElement.GetProperty("Records").EnumerateArray()){
  var fields=record.GetProperty("Data");var relative=fields.GetProperty("RelativeTargetName").GetString()!;if(relative==@"\")continue;
  var local=fields.GetProperty("ShareLocalPath").GetString()!;if(local.StartsWith(@"\??\"))local=local[4..];
  var liveWatched=new HashSet<string>(StringComparer.OrdinalIgnoreCase){Path.Combine(local,relative)};
  var xml=new XElement(shareNs+"Event",new XElement(shareNs+"System",new XElement(shareNs+"EventID",5145),new XElement(shareNs+"EventRecordID",record.GetProperty("Record").GetString()),new XElement(shareNs+"Keywords",record.GetProperty("Keywords").GetString()),new XElement(shareNs+"TimeCreated",new XAttribute("SystemTime",record.GetProperty("Utc").GetString()!))),new XElement(shareNs+"EventData",fields.EnumerateObject().Select(f=>new XElement(shareNs+"Data",new XAttribute("Name",f.Name),f.Value.GetString()))));
  var parsed=Wire(AuditParser.Parse(xml.ToString(),liveWatched,999)!);
  Check(WindowsShareEvidence.Matches(parsed)&&parsed.Attribution!.WindowsShare!.AccessReason==fields.GetProperty("AccessReason").GetString(),"captured native record retains exact reason: "+relative);
  Check(parsed.Attribution!.UserSid==fields.GetProperty("SubjectUserSid").GetString()&&parsed.Attribution.WindowsShare!.SourceAddress==fields.GetProperty("IpAddress").GetString()&&parsed.ProcessId==null,"captured native record retains subject/source without remote PID: "+relative);
  matched++;
 }
 Check(matched==3,"all three actual SMB file checks validated");
}
var directory=Path.Combine(@"D:\Codex\RansomFree\boundary-20261006",Guid.NewGuid().ToString("N"));Directory.CreateDirectory(directory);
{
 var spool=new EventSpool(directory,Guid.NewGuid().ToString("N"));
 spool.Enqueue(wire);var batch=spool.Peek();
 var rejected=false;try{spool.Acknowledge(batch,new(1,0){AttributionVersion=1});}catch(InvalidDataException){rejected=true;}
 Check(rejected&&spool.Status.Pending==1,"older server acknowledgment retains share evidence");
 spool.Acknowledge(batch,new(1,0){AttributionVersion=1,WindowsShareVersion=1});
 Check(spool.Status.Pending==0,"explicit share capability permits queue acknowledgment");
}
if(args.Length==2&&args[0]=="--remote-events"){
 var remote=File.ReadLines(args[1]).Select(x=>JsonSerializer.Deserialize<AgentEvent>(x)!).Where(x=>x.Source=="Windows minifilter").ToArray();
 Check(remote.Length>0,"actual client MUP observations present");
 foreach(var e in remote){
  var k=e.Attribution!.WindowsKernel!;
  Check(k.Version==6&&WindowsKernelEvidence.Matches(e),"actual MUP evidence passes ingress validation");
  Check(k.FileIoBoundary=="client-network-filesystem"&&k.RemoteProviderStatus=="unavailable: MUP provider not verified","provider unavailable remains explicit");
  Check(WindowsKernelEvidence.Matches(JsonSerializer.Deserialize<AgentEvent>(JsonSerializer.Serialize(e))!),"remote token evidence survives structured roundtrip");
  Check(!(k with{Version=5}).IsValid()&&!(k with{Flags=k.Flags&~1024u}).IsValid()&&!(k with{RemoteProviderStatus="SMB"}).IsValid(),"remote scope cannot masquerade as local or verified provider");
 }
 var remoteSpool=new EventSpool(Path.Combine(directory,"remote"),Guid.NewGuid().ToString("N"));remoteSpool.Enqueue(remote[0]);var remoteBatch=remoteSpool.Peek();
 var oldRejected=false;try{remoteSpool.Acknowledge(remoteBatch,new(1,0){AttributionVersion=1,WindowsKernelVersion=5,ForensicsVersion=1,ProcessCreationVersion=1,ActorAcquisitionVersion=1,TrustVersion=1,WhitelistVersion=1});}catch(InvalidDataException){oldRejected=true;}
 Check(oldRejected&&remoteSpool.Status.Pending==1,"version 5 receipt cannot discard version 6 evidence");
 remoteSpool.Acknowledge(remoteBatch,new(1,0){AttributionVersion=1,WindowsKernelVersion=6,ForensicsVersion=1,ProcessCreationVersion=1,ActorAcquisitionVersion=1,TrustVersion=1,WhitelistVersion=1});
 Check(remoteSpool.Status.Pending==0,"version 6 receipt acknowledges remote evidence");
}
Console.WriteLine($"PASS: {count} Windows boundary checks");
namespace RansomFree{internal sealed record ProcessIdentity;}
