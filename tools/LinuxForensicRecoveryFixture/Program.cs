using System.Diagnostics;
using System.Security.Cryptography;
using System.Text.Json;
using RansomFree.Client;
using RansomFree.Client.Forensics;
using RansomFree.Contracts;
if(args.Length==2&&args[0]=="raw-rotation"){RawRotationChecks.Run(Path.GetFullPath(args[1]));return;}
if(args.Length==1&&args[0]=="process-binding-status"){ProcessBindingChecks.Run();return;}
if(args.Length==2&&args[0]=="raw-preparation"){RawPreparationChecks.Run(Path.GetFullPath(args[1]));return;}
if(args.Length==1&&args[0]=="atomic-integration"){AtomicIntegrationChecks.Run();return;}
if(args.Length==2&&args[0]=="owned-runtime-native-io"){await OwnedRuntimeNativeChecks.Run(Path.GetFullPath(args[1]),ioOperations:true);return;}
if(args.Length==2&&args[0]=="native-companion-signer"){await NativeCompanionRuntimeChecks.CheckSigner(Path.GetFullPath(args[1]));return;}
if(args.Length==2&&args[0]=="native-companion-runtime"){await NativeCompanionRuntimeChecks.Run(Path.GetFullPath(args[1]));return;}
if(args.Length==2&&args[0]=="native-companion-runtime-child"){await NativeCompanionRuntimeChecks.Child(Path.GetFullPath(args[1]));return;}
if(args.Length==3&&args[0]=="native-companion-transport"){await NativeCompanionTransportChecks.Run(Path.GetFullPath(args[1]),Path.GetFullPath(args[2]));return;}
if(args.Length==2&&args[0]=="native-companion-transport-child"){await NativeCompanionTransportChecks.Child(Path.GetFullPath(args[1]));return;}
if(args.Length==1&&args[0]=="native-companion-client"){NativeCompanionClientChecks.Run();return;}
if(args.Length==2&&args[0]=="native-health-socket"){await NativeHealthSocketChecks.Run(Path.GetFullPath(args[1]));return;}
if(args.Length==3&&args[0]=="native-health-socket-child"){await NativeHealthSocketChecks.Child(Path.GetFullPath(args[1]),args[2]);return;}
if(args.Length==1&&args[0]=="native-health-readiness"){NativeHealthReadinessChecks.Run();return;}
if(args.Length==2&&args[0]=="native-registered-owner-failures"){await NativeRegisteredOwnerChecks.Run(Path.GetFullPath(args[1]));return;}
if(args.Length==2&&args[0]=="owned-runtime-native-module-trust"){await OwnedRuntimeNativeChecks.Run(Path.GetFullPath(args[1]),inspectActorMatching:true,observeSourceHealth:true,evaluateKernelTrust:true,signedKernelTrust:true,ownedModule:true);return;}
if(args.Length==3&&args[0]=="native-module-owner"){NativeModuleOwnerChecks.Run(Path.GetFullPath(args[1]),Path.GetFullPath(args[2]));return;}
if(args.Length==2&&args[0]=="native-source-policy"){NativeSourcePolicyChecks.Run(Path.GetFullPath(args[1]));return;}
if(args.Length==2&&args[0]=="native-installation-definition"){NativeInstallationChecks.Run(Path.GetFullPath(args[1]));return;}
if(args.Length==2&&args[0]=="native-package-file"){NativePackageFileChecks.Run(Path.GetFullPath(args[1]));return;}
if(args.Length==2&&args[0]=="native-package-admission"){NativePackageAdmissionChecks.Run(Path.GetFullPath(args[1]));return;}
if(args.Length==2&&args[0]=="native-target-admission"){NativeTargetAdmissionChecks.Run(Path.GetFullPath(args[1]));return;}
if(args.Length==2&&args[0]=="native-bind-target"){NativeBindTargetChecks.Run(Path.GetFullPath(args[1]));return;}
if(args.Length==2&&args[0]=="native-policy-socket"){await NativePolicySocketChecks.Run(Path.GetFullPath(args[1]));return;}
if(args.Length==3&&args[0]=="native-policy-socket-child"){await NativePolicySocketChecks.Child(Path.GetFullPath(args[1]),args[2]);return;}

if(args.Length==2&&args[0]=="signed-native-policy"){SignedNativePolicyChecks.Run(Path.GetFullPath(args[1]));return;}
if(args.Length==2&&args[0]=="native-policy-admission"){NativePolicyAdmissionChecks.Run(Path.GetFullPath(args[1]));return;}
if(args.Length==2&&args[0]=="native-policy-lease"){NativePolicyLeaseChecks.Run(Path.GetFullPath(args[1]));return;}
if(args.Length==2&&args[0]=="protected-directory"){ProtectedDirectoryChecks.Run(Path.GetFullPath(args[1]));return;}
if(args.Length==2&&args[0]=="private-directory-creation"){PrivateDirectoryCreationChecks.Run(Path.GetFullPath(args[1]));return;}
if(args.Length==3&&args[0]=="native-bridge"){NativeBridgeChecks.Run(Path.GetFullPath(args[1]),Path.GetFullPath(args[2]));return;}
if(args.Length==3&&args[0]=="native-bridge-linux"){await NativeBridgeLinuxChecks.Run(Path.GetFullPath(args[1]),Path.GetFullPath(args[2]));return;}
if(args.Length==3&&args[0]=="native-bridge-socket"){await NativeBridgeLinuxChecks.Run(Path.GetFullPath(args[1]),Path.GetFullPath(args[2]),socketAcknowledgments:true);return;}
if(args.Length==3&&args[0]=="native-bridge-socket-child"){await NativeBridgeSocketChecks.Child(Path.GetFullPath(args[1]),args[2]);return;}
if(args.Length==4&&args[0]=="native-bridge-consume"){NativeBridgeLinuxChecks.Consume(Path.GetFullPath(args[1]),Path.GetFullPath(args[2]),args[3]);return;}
if(args.Length==3&&args[0]=="linux-trust-binding"){LinuxTrustBindingChecks.Run(Path.GetFullPath(args[1]),Path.GetFullPath(args[2]));return;}
if(args.Length==3&&args[0]=="linux-actor-match"){LinuxActorMatchChecks.Run(Path.GetFullPath(args[1]),Path.GetFullPath(args[2]));return;}
if(args.Length==2&&args[0]=="owned-runtime-native"){await OwnedRuntimeNativeChecks.Run(Path.GetFullPath(args[1]));return;}
if(args.Length==2&&args[0]=="owned-runtime-native-match"){await OwnedRuntimeNativeChecks.Run(Path.GetFullPath(args[1]),inspectActorMatching:true);return;}
if(args.Length==2&&args[0]=="owned-runtime-native-source-health"){await OwnedRuntimeNativeChecks.Run(Path.GetFullPath(args[1]),inspectActorMatching:true,observeSourceHealth:true);return;}
if(args.Length==2&&args[0]=="owned-runtime-native-trust"){await OwnedRuntimeNativeChecks.Run(Path.GetFullPath(args[1]),inspectActorMatching:true,observeSourceHealth:true,evaluateKernelTrust:true);return;}
if(args.Length==2&&args[0]=="owned-runtime-native-signed-trust"){await OwnedRuntimeNativeChecks.Run(Path.GetFullPath(args[1]),inspectActorMatching:true,observeSourceHealth:true,evaluateKernelTrust:true,signedKernelTrust:true);return;}
if(args.Length==2&&args[0]=="owned-runtime-v2-startup-death"){await OwnedRuntimeV2StartupDeathChecks.Run(Path.GetFullPath(args[1]));return;}
if(args.Length==1&&args[0]=="controlled-protocol"){ControlledProtocolChecks.Run();return;}
if(args.Length==1&&args[0]=="controlled-target-set"){ControlledTargetSetChecks.Run();return;}
if(args.Length==1&&args[0]=="controlled-map-set"){ControlledMapSetChecks.Run();return;}
if(args.Length==1&&args[0]=="controlled-launch"){ControlledLaunchChecks.Run();return;}
if(args.Length==3&&args[0]=="controlled-map-set-native"){ControlledMapSetChecks.RunNative(args[1],args[2]);return;}
if(args.Length==1&&args[0]=="controlled-protocol-v2"){ControlledProtocolV2Checks.Run();return;}
if(args.Length==2&&args[0]=="controlled-v2-native-ready"){ControlledProtocolV2Checks.ReadNativeReady(args[1]);return;}
if(args.Length==2&&args[0]=="controlled-v2-native-frames"){ControlledV2NativeFrameChecks.Run(args[1]);return;}
if(args.Length==1&&args[0]=="controller-close"){await ControllerCloseChecks.Run();return;}
if(args.Length==2&&args[0]=="owned-loader"){await OwnedLoaderChecks.Run(Path.GetFullPath(args[1]));return;}
if(args.Length==2&&args[0]=="owned-lifetime-faults"){await OwnedLifetimeFaultChecks.Run(Path.GetFullPath(args[1]));return;}
if(args.Length==2&&args[0]=="owned-loader-child"){await OwnedLoaderChecks.Child(args[1]);return;}
if(args.Length==2&&args[0]=="controlled-protocol-native"){ControlledProtocolChecks.ReadNativeCases(args[1]);return;}
if(args.Length==1&&args[0]=="loader-frames"){await LoaderFrameChecks.Run();return;}
if(args.Length==1&&args[0]=="lost-map"){LostMapChecks.Run();return;}
if(args.Length==1&&args[0]=="source-work-barrier"){await SourceWorkBarrierChecks.Run();return;}
if(args.Length==1&&args[0]=="source-health-sample"){await SourceHealthSampleChecks.Run();return;}
if(args.Length==3&&args[0]=="lost-map-native"){await LostMapChecks.RunNative(args[1],args[2]);return;}
if(args.Length<3)throw new ArgumentException("Pass run|child, immutable seed file and new isolated root; child also takes a cut name");
var seed=JsonSerializer.Deserialize<Seed>(File.ReadAllBytes(args[1]))!;
if(seed.SourceArchiveSha256!="a0b444564eb2e7477f154ce52c0c0ec6c0c2dbb6512e3befbac314f370361eca")throw new InvalidDataException("Accepted native R19 archive required");
var raw=Convert.FromBase64String(seed.Native);var actorBytes=Convert.FromBase64String(seed.Bytes);
if(!Convert.ToHexString(SHA256.HashData(actorBytes)).Equals(seed.Sha256,StringComparison.OrdinalIgnoreCase))throw new InvalidDataException("Seed actor hash mismatch");
const string sensor="11111111111111111111111111111111",collector="22222222222222222222222222222222";
var observation=LinuxKernelDecoder.Decode(raw,sensor,collector,1,DateTimeOffset.Parse("2026-10-03T04:00:00Z"));
var snapshot=new LinuxActorSnapshot(seed.Status,actorBytes,seed.Sha256,seed.Status.Size.ToString()==observation.Attribution!.LinuxKernel!.ActorSize);
var root=Path.GetFullPath(args[2]);
if(args[0]=="io-work-capacity"){IoWorkCapacityChecks.Run(root,sensor,collector,raw);return;}
if(args[0]=="prepared-retry"){await PreparedRetryChecks.Run(root,sensor,raw,observation,snapshot,Path.GetFullPath(args[1]));return;}
if(args[0]=="controlled-journal"){await SourceControlJournalChecks.Run(root,sensor,Path.GetFullPath(args[1]));return;}
if(args[0]=="target-association"){TargetAssociationChecks.Run(root,sensor,raw);return;}
if(args[0]=="reconciliation-journal"){await SourceReconciliationChecks.Run(root,sensor,Path.GetFullPath(args[1]));return;}
if(args[0]=="reconciliation-child"){SourceReconciliationChecks.Child(root,sensor,args[3]);return;}
if(args[0]=="source-policy"){await SourcePolicyChecks.Run(root,sensor,collector,Path.GetFullPath(args[1]));return;}
if(args[0]=="source-policy-child"){SourcePolicyChecks.Child(root,sensor,collector,args[3]);return;}
if(args[0]=="canonical-ingress"){await CanonicalIngressChecks.Run(root,sensor,raw,Path.GetFullPath(args[1]));return;}
if(args[0]=="canonical-child"){CanonicalIngressChecks.Child(root,sensor,raw,args[3]);return;}
if(args[0]=="canonical-enospc"){await CanonicalIngressChecks.DiskPressure(root,sensor,raw);return;}
if(args[0]=="native-pins"){await NativePinChecks.Run(root,sensor,raw,Path.GetFullPath(args[1]));return;}
if(args[0]=="deferred-work"){await DeferredWorkChecks.Run(root,sensor,raw);return;}
if(args[0]=="stopped-raw-recovery"){await StoppedRawRecoveryChecks.Run(root,sensor,raw,Path.GetFullPath(args[1]));return;}
if(args[0]=="stopped-raw-child"){await StoppedRawRecoveryChecks.Child(root,sensor,raw,args[3]);return;}
if(args[0]=="controlled-ingress"){ControlledIngressChecks.Run(root,sensor,raw);return;}
if(args[0]=="source-activation"){await SourceActivationChecks.Run(root,sensor,raw,Path.GetFullPath(args[1]));return;}
if(args[0]=="pre-native-failure"){await PreNativeFailureChecks.Run(root,sensor,raw,snapshot);return;}
if(args[0]=="owner-methods"){await OwnerMethodChecks.Run(root,sensor,Path.GetFullPath(args[1]));return;}
if(args[0]=="shared-capacity"){await SharedCapacityChecks.Run(root,sensor,raw);return;}
if(args[0]=="serial-native-worker"){await SerialNativeWorkerChecks.Run(root,sensor,raw,snapshot);return;}
if(args[0]=="native-delivery"){await NativeDeliveryChecks.Run(root,sensor,raw,snapshot,Path.GetFullPath(args[1]));return;}
if(args[0]=="native-delivery-child"){NativeDeliveryChecks.Child(root,sensor,raw,snapshot,args[3]);return;}
if(args[0]=="native-pin-child"){NativePinChecks.Child(root,sensor,raw,args[3]);return;}
if(args[0]=="private-io"){await PrivateIoChecks.Run(root,sensor,raw,snapshot);return;}
if(args[0]=="raw-ingress"){await RawIngressChecks.Run(root,sensor,collector,Path.GetFullPath(args[1]),raw);return;}
if(args[0]=="ingress-child"){RawIngressChecks.Child(root,sensor,collector,args[3]);return;}
if(args[0]=="ingress-enospc"){await RawIngressChecks.DiskPressure(root,sensor,collector);return;}
if(args[0] is "snapshot-enospc-admitted" or "snapshot-enospc-allocate")
{
    await NativeDiskPressureChecks.Run(args[0],root,sensor,raw,observation,snapshot);return;
}
if(args[0]=="admitted-child")
{
    SnapshotAdmissionChecks.RunChild(root,sensor,raw,observation,snapshot,args[3]);return;
}
if(args[0]=="migration-child")
{
    using var migrated=new LinuxForensicJournal(root,sensor,migrationCheckpoint:point=>{if(point==args[3])Environment.Exit(73);});
    throw new Exception("Migration crash cut not reached");
}
if(args[0]=="lifecycle-child")
{
    using var journal=new LinuxForensicJournal(root,sensor);
    var source=new LinuxSourceSession(journal,Path.Combine(root,"bank"),sensor,5,observation.Attribution!.LinuxKernel!.ProviderEpoch,new(0),layoutReplayForTest:true);
    var record=source.Admit(raw,new(),observation.ObservedUtc).Record!;
    journal.CommitObservation(raw,record.Observation,record.Policy);
    File.WriteAllText(Path.Combine(root,"session-id.txt"),source.Id);
    Environment.Exit(73);return;
}
if(args[0]=="raw-cut")
{
    var cut=int.Parse(args[3]);if(cut is not (0 or 5))throw new ArgumentException("Unknown raw intent cut");
    using var reserve=new LinuxRawIntakeReserve(root,sensor,5,(stage,index)=>{if(stage=="intent-committed"&&index==cut)Environment.Exit(73);});
    for(int i=1;i<=6;i++)reserve.Commit(raw,LinuxKernelDecoder.Decode(raw,sensor,collector,i,observation.ObservedUtc),new());
    throw new Exception("Raw intent crash cut not reached");
}
if(args[0]=="raw-enospc")
{
    if(!OperatingSystem.IsLinux()||Directory.Exists(root)||!root.StartsWith("/var/tmp/sequester-linux-recovery-",StringComparison.Ordinal))throw new ArgumentException("Fresh owned Linux qualification path required");
    using(var reserve=new LinuxRawIntakeReserve(root,sensor,5))
    {
        Console.WriteLine(JsonSerializer.Serialize(new{Ready=true,reserve.PhysicalAllocationEstablished,Slots=5,EmergencySlots=1}));
        if(await Console.In.ReadLineAsync()!="commit")throw new InvalidDataException("Physical exhaustion controller handshake failed");
        for(int i=1;i<=5;i++)if(!reserve.Commit(raw,LinuxKernelDecoder.Decode(raw,sensor,collector,i,observation.ObservedUtc),new()))throw new Exception("Reserved raw slot refused after physical ENOSPC");
        if(reserve.Commit(raw,LinuxKernelDecoder.Decode(raw,sensor,collector,6,observation.ObservedUtc),new())||reserve.Overflow?.Reason!="RAW_BACKLOG_EXHAUSTED")throw new Exception("Emergency slot did not retain explicit unknown range");
    }
    using(var reopened=new LinuxRawIntakeReserve(root,sensor,5))
        Console.WriteLine(JsonSerializer.Serialize(new{Passed=reopened.Records.Count==5&&reopened.Overflow!=null,reopened.PhysicalAllocationEstablished,Records=reopened.Records.Count,Overflow=reopened.Overflow}));
    return;
}
if(args[0]=="child")
{
    var cut=args[3];
    void Cut(string name){if(name==cut)Environment.Exit(73);}
    using var journal=new LinuxForensicJournal(root,sensor);
    journal.CommitObservation(raw,observation,new());Cut("raw-committed");
    journal.CommitSnapshot(observation.EventId,snapshot);Cut("snapshot-committed");
    var spool=new EventSpool(Path.Combine(root,"spool"),sensor);
    await using(var pipeline=new ForensicPipeline(sensor,root,Console.Error.WriteLine))
        if(!pipeline.TrySubmitPrepared(journal,observation.EventId,spool,Cut))throw new Exception("Child work not admitted");
    throw new Exception("Requested crash cut not reached");
}
if(args[0]!="run"||Directory.Exists(root))throw new ArgumentException("Fresh isolated fixture root required");
Directory.CreateDirectory(root);var checks=new List<string>();
void Check(bool ok,string text){if(!ok)throw new Exception(text);checks.Add(text);Console.WriteLine("PASS: "+text);}
void Reject(Action action,string text)
{try{action();}catch(Exception e)when(e is IOException or InvalidDataException or InvalidOperationException or ArgumentException){Check(true,text);return;}throw new Exception("Expected rejection: "+text);}
async Task Deliver(LinuxForensicJournal journal,string directory,EventSpool spool,Action<string>? checkpoint=null,bool expectError=false)
{
    var errors=new List<string>();
    await using(var pipeline=new ForensicPipeline(sensor,directory,errors.Add))Check(pipeline.TrySubmitPrepared(journal,observation.EventId,spool,checkpoint),"durable job admitted: "+Path.GetFileName(directory));
    Check((errors.Count>0)==expectError,"worker error remains visible with durable work retained: "+Path.GetFileName(directory)+" "+string.Join("; ",errors));
}
var cuts=new[]{"raw-committed","snapshot-committed","original-precommit","original-prepared","original-spooled","completion-prepared","completion-spooled","upload-registered","work-finished"};
foreach(var cut in cuts)
{
    var directory=Path.Combine(root,cut);var start=new ProcessStartInfo(Environment.ProcessPath!){UseShellExecute=false,RedirectStandardOutput=true,RedirectStandardError=true};
    if(string.Equals(Path.GetFileNameWithoutExtension(Environment.ProcessPath),"dotnet",StringComparison.OrdinalIgnoreCase))start.ArgumentList.Add(typeof(Seed).Assembly.Location);
    foreach(var arg in new[]{"child",Path.GetFullPath(args[1]),directory,cut})start.ArgumentList.Add(arg);
    using(var child=Process.Start(start)!)
    {
        var stdout=child.StandardOutput.ReadToEndAsync();var stderr=child.StandardError.ReadToEndAsync();
        await FixtureProcessTiming.Wait(child);
        var log=await stdout+await stderr;File.WriteAllText(Path.Combine(root,cut+".log"),log);
        Check(child.ExitCode==73,"real child process exited at "+cut+": "+log);
    }
    using var journal=new LinuxForensicJournal(directory,sensor);var before=journal.Read(observation.EventId);
    journal.CommitObservation(raw,observation,new());
    Check(journal.Read(observation.EventId).CompletionId==before.CompletionId,"completion ID survives crash and duplicate raw delivery: "+cut);
    if(before.Acquisition==null)journal.CommitUnavailable(observation.EventId,"restart-before-acquisition; old-native-provider-not-reopened");
    var spool=new EventSpool(Path.Combine(directory,"spool"),sensor);
    if(cut=="original-spooled")
    {
        var batch=spool.Peek();spool.Acknowledge(batch,new(batch.Events.Length,0){ForensicsVersion=1,LinuxKernelVersion=1,LinuxActorAcquisitionVersion=1});
        Check(spool.Count==0,"previously delivered original can be acknowledged before completion recovery");
    }
    await Deliver(journal,directory,spool);
    var after=journal.Read(observation.EventId);
    Check(after.Done&&journal.Pending().Length==0&&spool.Count==2,"one original and one completion survive restart: "+cut);
    Check(before.Original==null||before.Original.AsSpan().SequenceEqual(after.Original),"original bytes never regenerated after commit: "+cut);
    Check(before.Completion==null||before.Completion.AsSpan().SequenceEqual(after.Completion),"completion bytes never regenerated after commit: "+cut);
    var completed=JsonSerializer.Deserialize<AgentEvent>(after.Completion!)!;
    Check(completed.EventId==before.CompletionId&&completed.Forensics!.RelatedEventId==observation.EventId&&LinuxKernelEvidence.Matches(completed),"stable completion linkage and native evidence: "+cut);
    var f=completed.Forensics!;
    Check(cut=="raw-committed"?f.ActorExecutable.Sha256==null&&f.Preservation.Status.State=="unavailable":f.ActorExecutable.Sha256!.Equals(seed.Sha256,StringComparison.OrdinalIgnoreCase)&&f.Preservation.HashMatched==true,"retained snapshot or explicit acquisition-unavailable outcome: "+cut);
    Check(cut=="raw-committed"?!Directory.Exists(Path.Combine(directory,"evidence","uploads")):Directory.GetFiles(Path.Combine(directory,"evidence","uploads"),"*.pending.json").Length==1,"exactly one upload registration when applicable: "+cut);
    if(cut=="original-spooled")Check(JsonSerializer.Deserialize<AgentEvent>(after.Original!)!.Forensics!.CollectorEpoch!=f.CollectorEpoch,"new completion uses new collector epoch after restart");
    await Deliver(journal,directory,spool);
    Check(spool.Count==2&&journal.Read(observation.EventId).Completion!.AsSpan().SequenceEqual(after.Completion),"finished job replay cannot create additional event bytes: "+cut);
}

// Snapshot corruption after a durable original must not mutate that original or
// turn the source executable pathname/PID into a recovery fallback.
{
    var directory=Path.Combine(root,"corrupt-snapshot");using var journal=new LinuxForensicJournal(directory,sensor);
    journal.CommitObservation(raw,observation,new());journal.CommitSnapshot(observation.EventId,snapshot);
    var spool=new EventSpool(Path.Combine(directory,"spool"),sensor);
    await Deliver(journal,directory,spool,name=>{if(name=="original-spooled")throw new IOException("owned cut");},true);
    var original=journal.Read(observation.EventId).Original!;var a=journal.Read(observation.EventId).Acquisition!;
    var path=Path.Combine(directory,"linux-forensic-intake",a.SnapshotId+".bin");
    using(var file=new FileStream(path,FileMode.Open,FileAccess.Write)){file.WriteByte((byte)(actorBytes[0]^1));file.Flush(true);}
    await Deliver(journal,directory,spool);var final=journal.Read(observation.EventId);
    var f=JsonSerializer.Deserialize<AgentEvent>(final.Completion!)!.Forensics!;
    Check(final.Original!.AsSpan().SequenceEqual(original)&&f.ActorExecutable.Sha256==null&&f.ActorExecutable.LinuxAcquisition?.RecoveryStatus?.State=="failed"&&f.ActorExecutable.BindingStatus.State=="failed","corrupt snapshot preserves original and yields explicit linked failure without a usable hash");
    Check(f.Process.Pid==observation.ProcessId&&f.ActorExecutable.File.StableId==a.NativeStatus!.SourceStableId&&File.Exists(path),"historical process/source metadata and damaged bytes remain retained");
}
// Admission remains bounded and never drops old records to admit a fifth.
{
    var directory=Path.Combine(root,"completion-spool-full");using var journal=new LinuxForensicJournal(directory,sensor);
    journal.CommitObservation(raw,observation,new());journal.CommitSnapshot(observation.EventId,snapshot);
    var spool=new EventSpool(Path.Combine(directory,"spool"),sensor);spool.Configure(new(1000,32));
    for(int i=0;i<999;i++)spool.Enqueue(new(Guid.NewGuid().ToString("N"),observation.ObservedUtc,"Fixture backlog",Path.Combine(directory,"owned-target"),null,null,null,"Fixture"));
    await Deliver(journal,directory,spool,expectError:true);var before=journal.Read(observation.EventId);
    Check(before.Completion!=null&&!before.Done&&spool.Count==1000&&!Directory.Exists(Path.Combine(directory,"evidence","uploads")),"full completion spool retains frozen completion and cannot register an upload first");
    while(spool.Count>0){var batch=spool.Peek();spool.Acknowledge(batch,new(batch.Events.Length,0){ForensicsVersion=1,LinuxKernelVersion=1,LinuxActorAcquisitionVersion=1});}
    await Deliver(journal,directory,spool);
    Check(journal.Read(observation.EventId).Done&&spool.Count==2&&journal.Read(observation.EventId).Completion!.AsSpan().SequenceEqual(before.Completion),"queue recovery delivers the exact saved pair after earlier original acknowledgment");
}
{
    var directory=Path.Combine(root,"upload-registration-failed");using var journal=new LinuxForensicJournal(directory,sensor);
    journal.CommitObservation(raw,observation,new());journal.CommitSnapshot(observation.EventId,snapshot);
    Directory.CreateDirectory(Path.Combine(directory,"evidence"));var conflicting=Path.Combine(directory,"evidence","uploads");File.WriteAllText(conflicting,"owned fixture: retain this obstruction");
    var spool=new EventSpool(Path.Combine(directory,"spool"),sensor);await Deliver(journal,directory,spool,expectError:true);
    var before=journal.Read(observation.EventId);Check(before.Completion!=null&&!before.Done&&spool.Count==2,"upload registration failure retains both spooled events and pending job");
    File.Move(conflicting,conflicting+"-obstruction-retained.txt",false);
    await Deliver(journal,directory,spool);
    var completed=JsonSerializer.Deserialize<AgentEvent>(journal.Read(observation.EventId).Completion!)!;
    var original=JsonSerializer.Deserialize<AgentEvent>(journal.Read(observation.EventId).Original!)!;
    await Task.WhenAll(Enumerable.Range(0,8).Select(_=>Task.Run(()=>new EvidenceUploadQueue(directory).Register(original,completed))));
    Check(journal.Read(observation.EventId).Done&&spool.Count==2&&Directory.GetFiles(conflicting,"*.pending.json").Length==1&&journal.Read(observation.EventId).Completion!.AsSpan().SequenceEqual(before.Completion),"retry and concurrent identical registration retain one exact upload pair");
    Reject(()=>new EvidenceUploadQueue(directory).Register(original with{Operation="changed"},completed),"changed upload original cannot replace committed registration");
}
{
    var directory=Path.Combine(root,"invalid-acquisition");using var journal=new LinuxForensicJournal(directory,sensor);journal.CommitObservation(raw,observation,new());
    Reject(()=>journal.CommitSnapshot(observation.EventId,snapshot with{NativeStatus=seed.Status with{ProviderEpoch=seed.Status.ProviderEpoch^1}}),"native provider epoch mismatch cannot commit snapshot");
    Reject(()=>journal.CommitSnapshot(observation.EventId,snapshot with{Sha256=new string('0',64)}),"bad actor digest cannot commit snapshot");
    Reject(()=>journal.CommitSnapshot(observation.EventId,snapshot with{NativeStatus=seed.Status with{ThreadId=seed.Status.ThreadId+1}}),"wrong accessing thread cannot commit snapshot");
    Check(journal.Read(observation.EventId).Acquisition==null,"invalid snapshot attempts leave the raw observation pending");
    journal.CommitUnavailable(observation.EventId,"native-provider-no-longer-available");journal.RecordDrop(observation.EventId,"unresolved");
    Check(journal.Read(observation.EventId).DropState=="unresolved","unresolved native release stays distinct from evidence delivery");
    Reject(()=>journal.CommitSnapshot(observation.EventId,snapshot),"final unavailable acquisition cannot silently become a captured copy");
}
{
    var directory=Path.Combine(root,"capacity");using var journal=new LinuxForensicJournal(directory,sensor);
    for(int n=1;n<=4;n++)journal.CommitObservation(raw,LinuxKernelDecoder.Decode(raw,sensor,collector,n,observation.ObservedUtc),new());
    Reject(()=>journal.CommitObservation(raw,LinuxKernelDecoder.Decode(raw,sensor,collector,5,observation.ObservedUtc),new()),"fifth pending observation rejected visibly with four committed records retained");
    Check(journal.Pending().Length==4,"pending admission is bounded independently of existing 32-worker capacity");
    Reject(()=>journal.CommitObservation(raw,observation,new(false)),"same event cannot silently change its frozen preservation policy");
    Reject(()=>journal.RecordDrop(observation.EventId,"returned"),"native release cannot be recorded before acquisition commitment");
    Reject(()=>new LinuxForensicJournal(directory,sensor),"concurrent journal ownership rejected");
}
{
    var directory=Path.Combine(root,"quota");using var journal=new LinuxForensicJournal(directory,sensor,LinuxForensicJournal.PerWorkReservation);
    Reject(()=>journal.CommitObservation(raw,observation,new()),"insufficient journal reservation refuses admission without eviction");
    Check(journal.Pending().Length==0,"quota failure does not manufacture an observation commitment");
}
{
    var directory=Path.Combine(root,"exact-bytes");var spool=new EventSpool(directory,sensor);var encoded=EventSpool.Encode(observation);
    spool.EnqueueExact(encoded);spool.EnqueueExact(encoded);Check(spool.Count==1,"identical canonical event append is idempotent");
    Reject(()=>spool.EnqueueExact(System.Text.Encoding.UTF8.GetBytes(JsonSerializer.Serialize(observation,new JsonSerializerOptions{WriteIndented=true}))),"immutable append refuses silently reserialized event bytes");
    Reject(()=>spool.EnqueueExact(EventSpool.Encode(observation with{Operation="changed"})),"same event ID with changed payload rejected");
}
await RawReserveChecks.Run(root,sensor,collector,raw,observation.ObservedUtc,Path.GetFullPath(args[1]),Check);
RawIntegrityChecks.Run(root,sensor,collector,raw,observation.ObservedUtc,Check);
RawDeliveryChecks.Run(root,sensor,raw,observation.ObservedUtc,Check);
SnapshotAdmissionChecks.Run(root,sensor,raw,observation,snapshot,Check);
await SnapshotAdmissionChecks.RunCrashCuts(root,sensor,observation,snapshot,Path.GetFullPath(args[1]),Check);
await SnapshotMigrationChecks.Run(root,sensor,raw,observation,snapshot,Path.GetFullPath(args[1]),Check);
await SourceLifecycleChecks.Run(root,sensor,raw,observation,snapshot,Path.GetFullPath(args[1]),Check);
await NativeProgressChecks.Run(root,sensor,raw,observation,snapshot,Path.GetFullPath(args[1]),Check);
var result=new{Passed=true,Checks=checks.Count,CrashCuts=cuts,SeedArchiveSha256=seed.SourceArchiveSha256,Scope="Managed journal/common pipeline with actual child exits and archived native actor bytes; append-only raw reserve with explicit emergency range. Linux physical allocation requires native fixture. No live source, native DROP/blocked-read, power-loss or slot reuse qualification; no production upload."};
File.WriteAllText(Path.Combine(root,"RESULTS.json"),JsonSerializer.Serialize(result,new JsonSerializerOptions{WriteIndented=true}));Console.WriteLine(JsonSerializer.Serialize(result));
record Seed(string SourceArchiveSha256,string Native,string Bytes,LinuxActorLeaseStatus Status,string Sha256);
