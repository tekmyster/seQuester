using RansomFree.Contracts;
using RansomFree.Server;
using System.Text.Json;

if(args.Length!=1||args[0] is not ("--fixture" or "--fixture-storage-dc" or "--apply-current" or "--apply-storage-dc"))throw new ArgumentException("Explicit fixture or guarded current-server maintenance mode required");
var fixture=args[0].StartsWith("--fixture",StringComparison.Ordinal);
var retainAssignment=args[0] is "--fixture-storage-dc" or "--apply-storage-dc";
if(!fixture&&Environment.MachineName!="CPTNYC_DC01")throw new InvalidOperationException("Exact management host required");
var root=fixture?Path.Combine(@"D:\Codex\RansomFree\boundary-20261006","quota-policy-"+Guid.NewGuid().ToString("N")):@"E:\Sequestor\Server\data-20261005-r1";
if(!fixture&&!File.Exists(Path.Combine(root,"management.db")))throw new IOException("Authoritative existing database required");
var store=new Store(root);var checks=new List<string>();
void Check(bool passed,string name){if(!passed)throw new Exception(name);checks.Add(name);}
var targets=new[]{(Id:"6968ef5bf7354785803bee43b31d5b54",Host:"DESKTOP-6U8VLDH",Quota:4096),(Id:"b4754be0335d49c99a21180046dd0a9f",Host:"CPTNYC_DC01",Quota:2048)};
if(retainAssignment)targets=
    [("420f9eceef2540c88b158cfaf4c8730f","CPTNYCSTR01",4096),("b4754be0335d49c99a21180046dd0a9f","CPTNYC_DC01",4096)];
else if(!fixture)targets=targets.Take(1).ToArray();
string? unrelated=null;
if(fixture)
{
 var a=store.Enroll(new(store.CreateCode().Code,targets[0].Host,"fixture"))!;
 var b=store.Enroll(new(store.CreateCode().Code,targets[1].Host,"fixture"))!;
 targets=[(a.EndpointId,targets[0].Host,targets[0].Quota),(b.EndpointId,targets[1].Host,targets[1].Quota)];
 unrelated=store.Enroll(new(store.CreateCode().Code,retainAssignment?"CPTNYC_NVR":"unrelated","fixture"))!.EndpointId;
 var shared=store.CreateGroup("existing shared fixture","owned fixture");
 var settings=shared.Settings with{IntegrityIntervalSeconds=30,Forensics=new(PreservationThreshold:"high",CacheEntries:73)};
 Check(store.PublishPolicy(shared.Id,new(0,settings),"owned fixture"),"seed nondefault shared policy");
 Check(store.AssignGroup(targets[0].Id,new(shared.Id,null),"owned fixture")&&store.AssignGroup(unrelated,new(shared.Id,null),"owned fixture"),"seed shared assignment");
}
var unrelatedBefore=unrelated==null?null:store.Assigned(unrelated);
var rows=new List<object>();
foreach(var target in targets)
{
 var endpoint=store.Inventory().Single(e=>e.EndpointId==target.Id);
 if(endpoint.MachineName!=target.Host||endpoint.Revoked)throw new InvalidOperationException("Exact active endpoint binding required");
 var before=store.Assigned(target.Id);var forensic=before.Settings.Forensics??new ForensicPolicy();
 if(forensic.EvidenceStoreMiB>=target.Quota){rows.Add(new{target.Host,State="already-sufficient",before.GroupId,before.Revision,forensic.EvidenceStoreMiB});continue;}
 var settings=before.Settings with{Forensics=forensic with{EvidenceStoreMiB=target.Quota}};
 Check(settings.IsValid()&&(settings with{Forensics=before.Settings.Forensics}).SameContent(before.Settings),target.Host+": only forensic store quota changes");
 if(retainAssignment&&before.GroupId is {} currentGroup)
 {
  var members=store.PolicyStatuses().Where(s=>s.GroupId==currentGroup).Select(s=>store.Inventory().Single(e=>e.EndpointId==s.EndpointId)).ToArray();
  if(members.Any(e=>e.MachineName is not ("CPTNYCSTR01" or "CPTNYC_DC01" or "CPTNYC_NVR" or "DESKTOP-6U8VLDH")))
   throw new InvalidOperationException("Existing shared group includes endpoints outside the authorized Windows capacity scope");
  if(!store.PublishPolicy(currentGroup,new(before.Revision,settings),"authorized Windows evidence-capacity maintenance 20261006"))throw new InvalidOperationException("Policy revision changed concurrently");
  var retained=store.Assigned(target.Id);
  Check(retained.GroupId==before.GroupId&&retained.Settings.SameContent(settings),target.Host+": group assignment and all other settings retained");
  rows.Add(new{target.Host,State="updated-existing-group",Group=retained.GroupId,Revision=retained.Revision,PreviousQuotaMiB=forensic.EvidenceStoreMiB,QuotaMiB=target.Quota,AffectedHosts=members.Select(e=>e.MachineName).ToArray()});
  continue;
 }
 var name="Evidence preservation capacity - "+target.Host;
 var group=store.Groups().SingleOrDefault(g=>g.Name==name)??store.CreateGroup(name,"authorized local evidence-capacity maintenance 20261006");
 // A retry may find an unused prepared group. Never change a shared policy.
 if(store.PolicyStatuses().Any(s=>s.EndpointId!=target.Id&&s.GroupId==group.Id))throw new InvalidOperationException("Prepared policy is assigned to another endpoint");
 if(!group.Settings.SameContent(settings)&&!store.PublishPolicy(group.Id,new(group.Revision,settings),"authorized local evidence-capacity maintenance 20261006"))throw new InvalidOperationException("Policy revision changed concurrently");
 if(before.GroupId!=group.Id&&!store.AssignGroup(target.Id,new(group.Id,before.GroupId),"authorized local evidence-capacity maintenance 20261006"))throw new InvalidOperationException("Endpoint assignment changed concurrently");
 var after=store.Assigned(target.Id);
 Check(after.Settings.SameContent(settings),target.Host+": persisted assigned policy matches complete intended settings");
 rows.Add(new{target.Host,State="updated",PreviousGroup=before.GroupId,PreviousRevision=before.Revision,Group=after.GroupId,Revision=after.Revision,PreviousQuotaMiB=forensic.EvidenceStoreMiB,QuotaMiB=target.Quota});
}
if(fixture)
{
 var unrelatedAfter=store.Assigned(unrelated!);
 if(retainAssignment)
 {
  Check(unrelatedAfter.GroupId==unrelatedBefore!.GroupId&&(unrelatedAfter.Settings with{Forensics=unrelatedBefore.Settings.Forensics}).SameContent(unrelatedBefore.Settings),"shared Windows group retains assignment and every nonquota setting");
  Check(unrelatedAfter.Settings.Forensics!.EvidenceStoreMiB==4096,"shared Windows capacity change persisted without reassignment");
 }
 else
 {
  Check(unrelatedAfter.GroupId==unrelatedBefore!.GroupId&&unrelatedAfter.Revision==unrelatedBefore.Revision&&unrelatedAfter.Settings.SameContent(unrelatedBefore.Settings),"shared policy and unrelated endpoint remain unchanged");
  Check(store.Groups().Single(g=>g.Name=="existing shared fixture").Settings.Forensics!.EvidenceStoreMiB==1024,"original shared quota remains unchanged");
 }
}
Console.WriteLine(JsonSerializer.Serialize(new{Passed=true,Fixture=fixture,Checks=checks,Changes=rows,Root=root,Scope="Audited server monitoring policies only; historical failed preservation records unchanged; sensor application and fresh preservation remain separate gates"},new JsonSerializerOptions{WriteIndented=true}));
