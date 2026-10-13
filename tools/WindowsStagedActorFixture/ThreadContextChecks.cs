using System.Buffers.Binary;
using RansomFree.Client;
using RansomFree.Client.Forensics;
using RansomFree.Contracts;

internal static class ThreadContextChecks
{
    internal static void Run(string root,string sensor,Action<bool,string> check)
    {
        void Reject(Action action,string name){try{action();}catch(Exception ex)when(ex is InvalidDataException or IOException){check(true,name);return;}throw new Exception("Accepted invalid context: "+name);}
        var original=Wire.RawRecord(root);var context=new byte[184];
        BinaryPrimitives.WriteUInt32LittleEndian(original.AsSpan(80),9); // Minor function is independent of requestor mode.
        BinaryPrimitives.WriteUInt32LittleEndian(original.AsSpan(92),1); // Native SQ_EVENT layout: UserMode at offset 92.
        void N(int offset,uint value)=>BinaryPrimitives.WriteUInt32LittleEndian(context.AsSpan(offset),value);
        void Q(int offset,ulong value)=>BinaryPrimitives.WriteUInt64LittleEndian(context.AsSpan(offset),value);
        N(0,1);N(4,184);original.AsSpan(8,16).CopyTo(context.AsSpan(8));
        original.AsSpan(3608,144).CopyTo(context.AsSpan(24));Q(168,(ulong)DateTimeOffset.UtcNow.AddHours(-1).ToFileTime());
        N(176,0x80);N(180,1);
        var bytes=WindowsKernelDecoder.Extend(original,context);
        var reply=original.Concat(context).ToArray();
        check(WindowsKernelDecoder.ExtendFromReply(original,reply).AsSpan().SequenceEqual(bytes),"exact queue-head base and extension are combined byte for byte");
        var corruptReply=(byte[])reply.Clone();corruptReply[88]^=1;Reject(()=>WindowsKernelDecoder.ExtendFromReply(original,corruptReply),"same instance and sequence cannot substitute changed base outcome bytes");
        var e=WindowsKernelDecoder.Decode(bytes,sensor,p=>p,false);var k=e.Attribution!.WindowsKernel!;
        File.WriteAllText(Path.Combine(root,"context-v5-input.json"),System.Text.Json.JsonSerializer.Serialize(e));
        check(k.Version==5&&k.IsValid()&&k.ThreadOwnerStatus=="captured","version 5 distinct owner snapshot is valid");
        check(k.BaseRecordSha256==Convert.ToHexString(System.Security.Cryptography.SHA256.HashData(original))&&k.ThreadContextSha256==Convert.ToHexString(System.Security.Cryptography.SHA256.HashData(context)),"separate base and extension digests match their original bytes");
        check(k.ThreadOwnerPrimary!.Sid=="S-1-5-18"&&k.ThreadEffective.Sid=="S-1-5-20"&&k.ThreadImpersonating==true,"impersonated user remains distinct from thread owner");
        check(k.ThreadProcessCreatedFileTime!=k.ProcessCreatedFileTime&&k.CallbackDataFlags==0x80&&k.RequestorMode==1,"thread-owner lifetime and callback origin are independently retained");
        var primaryOnly=(byte[])original.Clone();original.AsSpan(3608,144).CopyTo(primaryOnly.AsSpan(3464));BinaryPrimitives.WriteUInt32LittleEndian(primaryOnly.AsSpan(3316),1);
        var primaryOnlyEvent=WindowsKernelDecoder.Decode(WindowsKernelDecoder.Extend(primaryOnly,context),sensor,p=>p,false);
        using(var actor=new ActorLease()){
            actor.ApplyKernel(primaryOnlyEvent,sensor);
            check(actor.Process.Impersonating==false&&actor.Process.EffectiveThreadContext!.Sid=="S-1-5-18"&&actor.Process.ThreadToken.Sid==null,"no impersonation uses thread-owner primary and never fabricates an impersonation token");
        }
        var attached=(byte[])original.Clone();BinaryPrimitives.WriteUInt32LittleEndian(attached.AsSpan(3780),123457);
        attached[3608+80]=19; // Independent synthetic attached requestor SID S-1-5-19; owner remains S-1-5-18.
        var attachedEvent=WindowsKernelDecoder.Decode(WindowsKernelDecoder.Extend(attached,context),sensor,p=>p,false);
        using(var actor=new ActorLease()){
            actor.ApplyKernel(attachedEvent,sensor);
            check(actor.Process.Owner.Sid=="S-1-5-19"&&actor.Process.ThreadOwner!.Sid=="S-1-5-18"&&actor.Process.ThreadToken.Sid=="S-1-5-20","attached requestor, thread owner and impersonated user never collapse into one identity");
        }
        using(var actor=new ActorLease()){
            actor.ApplyKernel(e,sensor);
            check(actor.Process.ThreadOwner!.Sid=="S-1-5-18"&&actor.Process.ThreadToken.Sid=="S-1-5-20"&&actor.Process.Owner.Sid=="S-1-5-18","forensic mapping preserves all owner/effective snapshots");
            check(actor.Process.ThreadOwnerCreatedFileTime==k.ThreadProcessCreatedFileTime,"forensic mapping retains thread-owner process instance");
        }
        var changed=(byte[])context.Clone();changed[16]^=1;Reject(()=>WindowsKernelDecoder.Extend(original,changed),"queue-head sequence mismatch rejected");
        changed=(byte[])context.Clone();changed[8]^=1;Reject(()=>WindowsKernelDecoder.Extend(original,changed),"provider-instance mismatch rejected");
        Reject(()=>WindowsKernelDecoder.Extend(original,context[..183]),"truncated context rejected");
        changed=(byte[])bytes.Clone();changed[3816]^=1;Reject(()=>WindowsKernelDecoder.Decode(changed,sensor,p=>p,false),"durable extension linkage revalidated on recovery");
        changed=(byte[])bytes.Clone();changed[3980]=0;Reject(()=>WindowsKernelDecoder.Decode(changed,sensor,p=>p,false),"requestor mode cannot contradict original operation");
        var legacy=WindowsKernelDecoder.Decode(original,sensor,p=>p,false).Attribution!.WindowsKernel!;
        check(legacy.Version==4&&legacy.ThreadOwnerPrimary==null&&legacy.ThreadOwnerStatus=="legacy-provider-unavailable","legacy records remain explicit about missing separate owner evidence");
        check(e.EventId!=WindowsKernelDecoder.Decode(original,sensor,p=>p,false).EventId,"schema upgrade cannot collide with an already committed legacy observation");
        foreach(var (offset,value,expected) in new[]{(56,0u,"thread-unavailable"),(3776,1u,"irql-not-passive")}){
            var raw=(byte[])original.Clone();BinaryPrimitives.WriteUInt32LittleEndian(raw.AsSpan(offset),value);
            if(offset==56)BinaryPrimitives.WriteUInt32LittleEndian(raw.AsSpan(3780),0);
            var absent=(byte[])context.Clone();Array.Clear(absent,24,152);for(var i=28;i<48;i+=4)BinaryPrimitives.WriteUInt32LittleEndian(absent.AsSpan(i),0xC0000225);
            var missing=WindowsKernelDecoder.Decode(WindowsKernelDecoder.Extend(raw,absent),sensor,p=>p,false).Attribution!.WindowsKernel!;
            check(missing.ThreadOwnerStatus==expected,"unsupported context labelled "+expected);
            check(!(missing with{ThreadOwnerStatus="captured"}).IsValid(),"unavailable context cannot claim a captured owner");
        }
        var spool=new EventSpool(Path.Combine(root,"context-v5-spool"),sensor);spool.Enqueue(e);
        Reject(()=>spool.Acknowledge(spool.Peek(),new(1,0){AttributionVersion=1,WindowsKernelVersion=4}),"version 4 receipt cannot discard version 5 context");
        check(spool.Count==1,"unacknowledged extended evidence remains durable");
        spool.Acknowledge(spool.Peek(),new(1,0){AttributionVersion=1,WindowsKernelVersion=5});check(spool.Count==0,"version 5 receipt drains exact extended evidence");
        var journal=new WindowsKernelOperationJournal(Path.Combine(root,"context-v5-journal"));var ack=false;var delivered=false;
        WindowsKernelSource.Intake(journal,e,bytes,()=>throw new IOException("owned enrichment failure"),()=>{
            check(File.ReadAllBytes(journal.RecordPath(e.EventId)).AsSpan().SequenceEqual(bytes),"complete extended raw record flushed before ACK");ack=true;
        },path=>delivered=File.Exists(path),_=>{});
        check(ack&&delivered,"enrichment failure does not discard operation-time extended tokens");
        var changedContext=(byte[])bytes.Clone();changedContext[3976]^=1;
        Reject(()=>journal.Prepare(e.EventId,changedContext),"duplicate operation key with changed extension cannot overwrite durable evidence");
        check(WindowsKernelEvidence.RequiredVersion(new[]{e,WindowsKernelDecoder.Decode(original,sensor,p=>p,false)})==5,"mixed legacy and extended batches require version 5 acknowledgement");
    }
}
