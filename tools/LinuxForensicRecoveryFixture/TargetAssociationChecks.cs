using System.Globalization;
using System.Text.Json;
using System.Text.Json.Nodes;
using RansomFree.Client;
using RansomFree.Client.Forensics;
using RansomFree.Contracts;

internal static class TargetAssociationChecks
{
    internal static void Run(string root,string sensor,byte[] legacy)
    {
        if(Directory.Exists(root))throw new IOException("Fresh target association fixture required");
        var checks=0;
        void Check(bool value,string label){checks++;if(!value)throw new IOException(label);}
        var original=JsonNode.Parse(legacy)!.AsObject();var epoch=original["providerEpoch"]!.GetValue<ulong>();
        var old=LinuxKernelDecoder.Decode(legacy,sensor,new string('2',32),1,DateTimeOffset.UtcNow);
        Check(old.Attribution!.LinuxKernel is {Version:1,NativeSchemaVersion:5,TargetIdentity:null}&&old.Attribution.TargetStableId==null,"schema5 target remains unavailable");
        Check(!JsonSerializer.Serialize(old).Contains("TargetIdentity",StringComparison.Ordinal),"legacy serialization gains no fabricated target or changed optional field");
        foreach(var mode in new[]{"first","second","wrong-ordinal","replacement","missing-link","wrong-control","legacy-under-v2","malformed","foreign-epoch"})
        {
            var dir=Path.Combine(root,mode);using var journal=new LinuxForensicJournal(dir,sensor);
            using var bank=new LinuxRawIngressReserve(Path.Combine(dir,"raw"),sensor,Guid.NewGuid().ToString("N"),epoch.ToString(CultureInfo.InvariantCulture),5,true);
            var barrier=new LinuxSourceWorkBarrier();var source=journal.PrepareControlledSource(bank,new(),"0",DateTimeOffset.UtcNow,512L*1024*1024);
            var ready=ControlledProtocolV2Checks.Ready();ready["providerEpoch"]=epoch;
            if(mode=="wrong-control")
            {
                foreach(var name in new[]{"targetCount","targets","targetsPinned","watchMapId","watchMapFrozen"})ready.Remove(name);
                ready["controlVersion"]=1;ready["schemaVersion"]=5;ready["targetPinned"]=true;ready["targetDevice"]=uint.MaxValue;ready["targetInode"]=ulong.MaxValue-1;
            }
            if(mode!="missing-link")
            {
                journal.RecordSourceOwnerOpenAttempt(source.Id,DateTimeOffset.UtcNow);
                journal.RecordOwnerMethodReturn(source.Id,ActivationFixture.OwnerReturn(source.Id));
                journal.CommitSourceControlLink(source.Id,ControlledProtocolV2Checks.Encode(ready),DateTimeOffset.UtcNow);
            }
            var value=original.DeepClone().AsObject();value["schemaVersion"]=6;value["testMode"]=0;
            value["targetDevice"]=uint.MaxValue;value["targetInode"]=mode=="second"?ulong.MaxValue:ulong.MaxValue-1;
            value["targetOrdinal"]=mode is "second" or "wrong-ordinal"?1:0;
            if(mode=="replacement")value["targetInode"]=ulong.MaxValue-2;
            if(mode=="legacy-under-v2")value=original.DeepClone().AsObject();
            if(mode=="malformed")value["targetInode"]=0;
            if(mode=="foreign-epoch")value["providerEpoch"]=epoch==1?2UL:1UL;
            var bytes=JsonSerializer.SerializeToUtf8Bytes(value);var entry=bank.Commit(bytes,barrier.Current,DateTimeOffset.UtcNow).Entry!;
            var indexed=journal.IndexRawIngress(source.Id,bank,entry);
            if(mode is "first" or "second")
            {
                var result=indexed.CanonicalEvent!;var target=result.Attribution!.LinuxKernel!.TargetIdentity!;
                Check(indexed.Status=="RAW_VALID"&&result.Attribution.LinuxKernel.Version==2&&target.Ordinal==(mode=="second"?1u:0u),"exact v2 membership: "+mode);
                Check(target.StableId==result.Attribution.TargetStableId&&result.Source=="Linux kernel"&&result.Attribution.LinuxKernel.ActorInode==old.Attribution.LinuxKernel!.ActorInode,"target identity remains separate from actor executable: "+mode);
                Check(journal.IndexRawIngress(source.Id,bank,entry).CanonicalEventId==result.EventId,"exact target association survives historical reindex: "+mode);
            }
            else
            {
                var reason=mode switch{"foreign-epoch"=>"RAW_FOREIGN_EPOCH","malformed"=>"NATIVE_SCHEMA_DECODE_FAILED",_=>"NATIVE_TARGET_BINDING_FAILED"};
                Check(indexed.CanonicalEvent==null&&indexed.CanonicalEventId==null&&indexed.RequiresSourceStop&&indexed.Diagnostic?.Reason==reason,"failed binding remains diagnostic only: "+mode);
                Check(journal.ReadSource(source.Id).State=="CONTINUITY_FAULTED"&&journal.IndexRawIngress(source.Id,bank,entry).Diagnostic?.Reason==reason,"failed association and reason persist: "+mode);
            }
            Check(bank.ReadRaw(entry).SequenceEqual(bytes),"raw event retained exactly: "+mode);
        }
        var resultSummary=new{Passed=true,Checks=checks,Scope="Managed schema6 decoder and exact durable ready target association; schema5 regression; no native controller, service activation or all-operation qualification"};
        File.WriteAllText(Path.Combine(root,"RESULTS.json"),JsonSerializer.Serialize(resultSummary));Console.WriteLine(JsonSerializer.Serialize(resultSummary));
    }
}
