using System.Xml.Linq;
using RansomFree;
var checks=0;void Check(bool value,string name){if(!value)throw new Exception(name);checks++;Console.WriteLine("PASS: "+name);}
const string path=@"C:\SeQuesterLab\Canaries\payroll.xlsx";
var watched=new HashSet<string>(StringComparer.OrdinalIgnoreCase){path};
string Xml(string? missing=null,string? pid="0x2a",string source="4663"){
    XNamespace ns="http://schemas.microsoft.com/win/2004/08/events/event";
    var fields=new Dictionary<string,string?>{{"ObjectName",path},{"ProcessId",pid},{"ProcessName",@"C:\Windows\System32\cmd.exe"},{"SubjectUserName","alice"},{"SubjectDomainName","LAB"},{"SubjectUserSid","S-1-5-21-1-2-3-1001"},{"AccessMask","0x1"}};
    if(missing!=null)foreach(var key in missing.Split(','))fields.Remove(key);
    return new XElement(ns+"Event",new XElement(ns+"System",new XElement(ns+"EventID",source),new XElement(ns+"EventRecordID","321"),new XElement(ns+"TimeCreated",new XAttribute("SystemTime","2026-09-24T01:00:00Z"))),new XElement(ns+"EventData",fields.Select(x=>new XElement(ns+"Data",new XAttribute("Name",x.Key),x.Value)))).ToString();
}
var complete=AuditParser.Parse(Xml(),watched,999)!;
Check(complete.ProcessId==42&&complete.User==@"LAB\alice"&&complete.Attribution?.Level=="Full attribution","direct Security record retains user, image and PID");
foreach(var field in new[]{"ProcessId","ProcessName","SubjectUserName,SubjectUserSid","ProcessId,ProcessName,SubjectUserName,SubjectUserSid"}){
 var item=AuditParser.Parse(Xml(field),watched,999);
 Check(item!=null&&item.Attribution!.Level!="Full attribution"&&item.Attribution.Basis.Contains("Missing:"),"partial evidence is retained with reasons: "+field);
}
Check(AuditParser.Parse(Xml("SubjectUserName"),watched,999)!.User=="S-1-5-21-1-2-3-1001","numeric SID survives account-name absence");
foreach(var pid in new[]{"0x0","invalid","0xffffffffffffff"}){
 var item=AuditParser.Parse(Xml(pid:pid),watched,999)!;
 Check(item.Attribution!.Level!="Full attribution"&&item.ProcessId is null or 0,"invalid/unavailable PID never invents an actor: "+pid);
}
Check(AuditParser.Parse(Xml(),watched,42)==null,"sensor's own process remains excluded");
Check(AuditParser.Parse(Xml(),new HashSet<string>(),999)==null,"unmonitored file remains excluded");
Check(AuditParser.Parse(Xml(source:"1234"),watched,999)==null,"unrecognized Security event is rejected");
Check(complete.Attribution!.EvidenceId=="321"&&complete.Attribution.EventTimeCredentials,"record identity and event-time provenance retained");
Console.WriteLine($"PASS: {checks} Windows audit parser cases");
var deniedXml=XDocument.Parse(Xml(source:"4656"));XNamespace auditNs="http://schemas.microsoft.com/win/2004/08/events/event";
deniedXml.Root!.Element(auditNs+"System")!.Add(new XElement(auditNs+"Keywords","0x8010000000000000"));
var denied=AuditParser.Parse(deniedXml.ToString(),watched,999)!;
Check(denied.Operation=="Access denied"&&denied.Attribution!.Outcome=="Failed"&&denied.ProcessId==42&&denied.User==@"LAB\alice","4656 audit failure retains exact actor and failed outcome");
if(OperatingSystem.IsWindows()){
 var world=new System.Security.Principal.SecurityIdentifier("S-1-1-0");
 System.Security.AccessControl.FileSystemAuditRule Rule(System.Security.AccessControl.AuditFlags flags)=>new(world,AuditPolicy.MonitoredRights,flags);
 Check(!AuditPolicy.HasRequiredCoverage([Rule(System.Security.AccessControl.AuditFlags.Success)]),"success-only SACL cannot report healthy denied-access coverage");
 Check(!AuditPolicy.HasRequiredCoverage([Rule(System.Security.AccessControl.AuditFlags.Failure)]),"failure-only SACL cannot report healthy successful-access coverage");
 Check(AuditPolicy.HasRequiredCoverage([Rule(System.Security.AccessControl.AuditFlags.Success),Rule(System.Security.AccessControl.AuditFlags.Failure)]),"split success and failure SACL rules are combined correctly");
}
Console.WriteLine($"PASS: {checks} Windows audit and denied-access checks");
namespace RansomFree{internal sealed record ProcessIdentity;}
