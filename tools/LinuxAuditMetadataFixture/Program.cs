using System.Text.Json;
using RansomFree.Client.Forensics;
using RansomFree.Contracts;
var checks=0;
void Check(bool ok,string why){if(!ok)throw new Exception(why);checks++;}
AgentEvent Event(EventAttribution? a=null,string source="Linux Audit")=>new(Guid.NewGuid().ToString("N"),DateTimeOffset.UtcNow,"Access denied","/owned/target", "uid:1000","/exited/actor",null,source){Attribution=a??new(){Provider="Linux Audit",Level="Full attribution",Basis="owned historical audit fixture",CompleteRecordSet=true,EventTimeCredentials=true,ParentProcessId=123,CommandLine="/exited/actor --read /owned/target",UserId=1000,EffectiveUserId=1001,FileSystemUserId=1002,GroupId=2000,EffectiveGroupId=2001,FileSystemGroupId=2002,SessionId=77,Outcome="Failed",OsStatus="-13"}};
var e=Event();using var lease=ActorLease.Capture(e,"sensor");
Check(lease.Process.ParentPid==123,"audit parent PID survives unavailable process");
Check(lease.Process.ParentStartKey==null&&lease.Process.ParentInstanceId==null&&lease.Process.ParentStartedUtc==null,"parent PID does not fabricate durable parent identity");
Check(lease.Process.ParentStatus.State=="partial","incomplete parent identity stays partial");
Check(lease.Process.CommandLine==e.Attribution!.CommandLine&&lease.Process.CommandLineStatus.State=="captured","historical command line survives unavailable process");
Check(lease.Process.CommandLineStatus.Reason.Contains("mutable-application-memory"),"proctitle is evidence rather than executable verification");
Check(lease.Image==null&&lease.Binding.State=="unavailable"&&lease.Process.InstanceId==null,"audit metadata never creates an executable or process-instance binding");
Check(lease.Process.ProcessSessionId==null&&lease.Process.EventSubject.SessionId==77,"audit login session is not mislabeled POSIX process session");
Check(lease.Process.EventSubject.Gid==2000&&lease.Process.EventSubject.EffectiveGid==2001&&lease.Process.EventSubject.FileSystemGid==2002,"distinct group security contexts retained");
var json=JsonSerializer.Serialize(e);Check(JsonSerializer.Deserialize<AgentEvent>(json)!.Attribution!.FileSystemGroupId==2002,"additive fsgid round trips");
var legacy=JsonSerializer.Serialize(e with{Attribution=e.Attribution with{FileSystemGroupId=null}});Check(!legacy.Contains("FileSystemGroupId")&&JsonSerializer.Deserialize<AgentEvent>(legacy)!.Attribution!.FileSystemGroupId==null,"old events remain readable without new group field");
foreach(var changed in new[]{e.Attribution with{CompleteRecordSet=false},e.Attribution with{EventTimeCredentials=false},e.Attribution with{Provider="Untrusted"},e.Attribution with{Version=2},e.Attribution with{CommandLine="bad\nrecord"}}){using var bad=ActorLease.Capture(Event(changed),"sensor");Check(bad.Process.CommandLine==null&&bad.Process.ParentPid==null,"unqualified metadata is not promoted");}
using(var other=ActorLease.Capture(Event(e.Attribution,"Other source"),"sensor"))Check(other.Process.CommandLine==null&&other.Process.ParentPid==null,"other source cannot claim audit provenance");
using(var missing=ActorLease.Capture(Event(e.Attribution with{ParentProcessId=null,CommandLine=null,FileSystemGroupId=null}),"sensor"))Check(missing.Process.ParentPid==null&&missing.Process.CommandLine==null&&missing.Process.EventSubject.FileSystemGid==null,"unavailable fields stay unavailable");
using(var limit=ActorLease.Capture(Event(e.Attribution with{CommandLine=new string('x',2048)}),"sensor"))Check(limit.Process.CommandLineStatus.State=="partial","at-limit command line is not claimed complete");
using(var cap=ActorLease.Capture(Event(e.Attribution with{CommandLine=new string('x',128),CommandLineTruncated=true}),"sensor"))Check(cap.Process.CommandLineStatus.State=="partial","kernel-capped audit title stays partial for exited actors");
using(var exited=ActorLease.Capture(e with{ProcessId=int.MaxValue},"owned-exited-fixture"))
    Check(exited.Process.Pid==int.MaxValue&&exited.Process.InstanceId==null&&exited.Process.CommandLine==e.Attribution.CommandLine,"known exited PID retains audit evidence without invented instance");
using(var mismatch=ActorLease.Capture(e with{ProcessId=Environment.ProcessId},"owned-reuse-fixture"))
{
    Check(mismatch.Image==null&&mismatch.Binding.State=="unavailable","different current image refuses historical audit actor binding");
    Check(mismatch.Process.InstanceId==null&&mismatch.Process.StartKey==null&&mismatch.Process.StartedUtc==null,"failed historical binding discards provisional current-PID correlation");
    Check(mismatch.Process.ParentPid==123&&mismatch.Process.CommandLine==e.Attribution.CommandLine,"event-time metadata remains after PID/image mismatch");
}
if(OperatingSystem.IsLinux())
{
    var actual=e with{ObservedUtc=DateTimeOffset.UtcNow,Process=Environment.ProcessPath,ProcessId=Environment.ProcessId};
    using var live=ActorLease.Capture(actual,"owned-live-fixture");
    Check(live.Image!=null&&live.Binding.State=="captured","live procfs actor retained independently of historical metadata");
    Check(live.Process.Owner.FileSystemGid!=null&&live.Process.Owner.Status.State=="captured","actual procfs filesystem GID retained");
    Check(live.Process.EventSubject.FileSystemGid==2002&&live.Process.Owner.FileSystemGid!=null,"historical accessing credentials stay separate from later owner observation");
    using var proc=ActorLease.Capture(actual with{Attribution=actual.Attribution! with{CommandLine=null}},"owned-live-fixture");
    Check(proc.Process.CommandLine!.Length>128,"fixture actually has a long independently captured command");
    var prefix=proc.Process.CommandLine[..128];
    using var cappedLive=ActorLease.Capture(actual with{Attribution=actual.Attribution! with{CommandLine=prefix,CommandLineTruncated=true}},"owned-live-fixture");
    Check(cappedLive.Process.CommandLine==proc.Process.CommandLine&&cappedLive.Process.CommandLineStatus.Reason=="procfs-after-observation","bound later full command is not replaced by capped audit prefix");
}
var targetMissing=e with{Path="Kernel audit: target path unavailable",Attribution=e.Attribution with{CompleteRecordSet=false,PathRole="UNAVAILABLE"}};
using(var actor=ActorLease.Capture(targetMissing,"owned-target-unavailable"))
{
 var collector=new ForensicCollector("owned-target-unavailable",Path.Combine(Path.GetTempPath(),"sequester-metadata-fixture-"+Guid.NewGuid().ToString("N")));
 var evidence=collector.Begin(targetMissing,actor);
 Check(evidence.Observation.Path==null&&evidence.Observation.Storage=="unknown"&&evidence.Observation.File.Status.State=="unavailable","missing target does not fabricate forensic file path or metadata");
 Check(evidence.ActorExecutable.ObservedPath==targetMissing.Process&&evidence.Process.Pid==targetMissing.ProcessId,"missing target does not discard actor identity");
}
Console.WriteLine(JsonSerializer.Serialize(new{Passed=true,Checks=checks,Scope="Audit metadata mapping and unavailable-process fallback; not native Linux callback expansion or denied-open actor preservation."}));
