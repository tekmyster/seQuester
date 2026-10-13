using System.Buffers.Binary;
using System.Security.Cryptography;
using RansomFree.Client;
using RansomFree.Contracts;

static class JournalChecks
{
    [System.Runtime.Versioning.SupportedOSPlatform("windows")]
    internal static void Run()
    {
        var root=Path.Combine(@"D:\Codex\RansomFree\boundary-20261006","acquisition-journal-"+Guid.NewGuid().ToString("N"));Directory.CreateDirectory(root);
        var checks=0;void Check(bool passed,string description){if(!passed)throw new Exception(description);checks++;}
        void Reject(Action action,string description){try{action();}catch(Exception e)when(e is IOException or InvalidDataException){checks++;return;}throw new Exception("Accepted "+description);}
        const string provider="1234567890ABCDEF1234567890ABCDEF";
        var raw=new byte[3800];BinaryPrimitives.WriteUInt32LittleEndian(raw,4);BinaryPrimitives.WriteUInt32LittleEndian(raw.AsSpan(4),3800);
        BinaryPrimitives.WriteUInt64LittleEndian(raw.AsSpan(8),10);BinaryPrimitives.WriteUInt64LittleEndian(raw.AsSpan(16),20);
        var id=Guid.NewGuid().ToString("N");var e=new AgentEvent(id,DateTimeOffset.UtcNow,"File open","owned-fixture",null,null,null,"Windows minifilter"){
            Attribution=new(){WindowsKernel=new(){Instance=10UL.ToString("X16"),Sequence=20}}};
        var observation=new WindowsKernelAcquisitionJournal(root);var journal=new WindowsKernelOperationJournal(root);
        observation.Require(id,raw,provider,10,true);
        Check(!File.Exists(journal.RecordPath(id))&&File.Exists(Path.Combine(root,id+".acq-required")),"required marker is durable before raw intake");
        journal.Prepare(id,raw);Check(!journal.Schedule(journal.RecordPath(id)),"missing required companion cannot schedule or recover as legacy");
        bool ack=false,collected=false;var health=new List<string>();
        Reject(()=>WindowsKernelSource.Intake(journal,e,raw,()=>collected=true,()=>ack=true,_=>{},health.Add,()=>throw new IOException("owned query failure")),"required query failure cannot reach optional collection or ACK");
        Check(!ack&&!collected&&File.ReadAllBytes(journal.RecordPath(id)).SequenceEqual(raw),"failed query retains exact raw bytes and withholds ACK");
        var frame=new byte[128];BinaryPrimitives.WriteUInt32LittleEndian(frame,1);BinaryPrimitives.WriteUInt32LittleEndian(frame.AsSpan(4),128);Convert.FromHexString(provider).CopyTo(frame,8);
        foreach(var pair in new[]{(24,10UL),(32,10UL),(40,20UL),(80,100UL)})BinaryPrimitives.WriteUInt64LittleEndian(frame.AsSpan(pair.Item1),pair.Item2);
        BinaryPrimitives.WriteUInt32LittleEndian(frame.AsSpan(88),0xC0000225);
        var bad=(byte[])frame.Clone();bad[40]^=1;
        Reject(()=>observation.Capture(id,raw,(_,_)=>bad),"wrong operation companion cannot commit");
        Check(!File.Exists(Path.Combine(root,id+".acq1")),"rejected reply has no durable companion");
        observation.Capture(id,raw,(_,_)=>frame);
        var recovered=new WindowsKernelAcquisitionJournal(root);
        recovered.Capture(id,raw,(_,_)=>throw new Exception("Durable reply queried again"));
        var attached=recovered.Attach(e,raw);
        Check(attached.Attribution!.WindowsKernel!.AcquisitionObservation is {Version:1,State:0,ReasonCode:"ACTOR_ACQ_NO_EXACT_ASSOCIATION"},"restart restores immutable exact companion and SIEM reason");
        Check(attached.Attribution.WindowsKernel.AcquisitionObservation!.OperationRecordSha256==Convert.ToHexString(SHA256.HashData(raw)),"companion links to unchanged raw record hash");
        WindowsKernelSource.Intake(journal,e,raw,()=>collected=true,()=>ack=true,_=>{},health.Add,()=>recovered.Capture(id,raw,(_,_)=>frame));
        Check(ack&&collected&&journal.Schedule(journal.RecordPath(id)),"ACK and scheduling occur only after valid durable companion");
        var changed=(byte[])raw.Clone();changed[100]^=1;
        Reject(()=>recovered.Require(id,changed,provider,10,true),"requirement collision cannot replace original raw linkage");
        var legacyId=Guid.NewGuid().ToString("N");var legacy=observation;
        legacy.Require(legacyId,raw,null,0,false);journal.Prepare(legacyId,raw);
        legacy.Capture(legacyId,raw,(_,_)=>throw new Exception("Legacy source queried"));
        Check(journal.Schedule(journal.RecordPath(legacyId))&&legacy.Attach(e with{EventId=legacyId},raw).Attribution!.WindowsKernel!.AcquisitionObservation is {Version:0,QueryAttempted:false,State:null},"legacy is explicit unavailable without invented native outcome");
        var historicalId=Guid.NewGuid().ToString("N");journal.Prepare(historicalId,raw);
        Check(journal.Schedule(journal.RecordPath(historicalId))&&legacy.Attach(e with{EventId=historicalId},raw).Attribution!.WindowsKernel!.AcquisitionObservation!.Status.Reason=="pre-companion-record","historical records preserve separate provenance");
        var retiredId=Guid.NewGuid().ToString("N");observation.Require(retiredId,raw,provider,10,true);journal.Prepare(retiredId,raw);
        var scheduled=new List<string>();observation.RecoverRetired(provider,10,scheduled.Add,health.Add);
        Check(scheduled.Count==0&&!WindowsKernelAcquisitionJournal.Ready(journal.RecordPath(retiredId)),"same-provider reconnect does not downgrade missing mandatory companion");
        const string nextProvider="ABCDEF1234567890ABCDEF1234567890";
        observation.RecoverRetired(nextProvider,11,scheduled.Add,health.Add);
        Check(scheduled.Contains(journal.RecordPath(retiredId))&&WindowsKernelAcquisitionJournal.Ready(journal.RecordPath(retiredId)),"different locally observed provider permits explicit collection failure delivery");
        var retired=observation.Attach(e with{EventId=retiredId},raw).Attribution!.WindowsKernel!.AcquisitionObservation!;
        Check(retired is {Version:2,QueryAttempted:null,State:null,NativeStatus:null,RawSha256:null,RecoveryProvider:nextProvider,RecoveryEpoch:11}&&retired.ReasonCode=="ACTOR_ACQ_COMPANION_UNAVAILABLE_PROVIDER_RETIRED","retirement retains source linkage and unknown prior query without inventing native outcome");
        Check(retired.Provider==provider&&retired.Epoch==10&&retired.OperationRecordSha256==Convert.ToHexString(SHA256.HashData(raw)),"retirement retains exact original provider, event key and raw operation hash");
        Check(!(retired with{RecoveryProvider=provider,RecoveryEpoch=10}).IsValid(e.Attribution.WindowsKernel!)&&!(retired with{QueryAttempted=false}).IsValid(e.Attribution.WindowsKernel!),"same identity or fabricated query attempt cannot qualify retirement");
        var retirementPath=Path.Combine(root,retiredId+".acq-unavailable");var retirementBytes=File.ReadAllBytes(retirementPath);
        new WindowsKernelAcquisitionJournal(root).RecoverRetired(nextProvider,12,_=>{},health.Add);
        Check(File.ReadAllBytes(retirementPath).SequenceEqual(retirementBytes),"subsequent restart preserves first immutable retirement proof");
        File.WriteAllBytes(Path.Combine(root,retiredId+".acq1"),frame);
        Reject(()=>WindowsKernelAcquisitionJournal.Ready(journal.RecordPath(retiredId)),"conflicting recovered failure and native outcome cannot silently select a result");
        File.WriteAllBytes(Path.Combine(root,id+".acq1"),bad); // owned corruption fixture only
        Reject(()=>WindowsKernelAcquisitionJournal.Ready(journal.RecordPath(id)),"corrupt persisted companion cannot become ready");
        Check(File.ReadAllBytes(journal.RecordPath(id)).SequenceEqual(raw)&&File.ReadAllBytes(Path.Combine(root,id+".acq1")).SequenceEqual(bad),"corrupt fixture and original raw evidence are retained");
        Console.WriteLine($"PASS {checks} acquisition journal/restart/ACK checks; retained fixture {root}");
    }
}
