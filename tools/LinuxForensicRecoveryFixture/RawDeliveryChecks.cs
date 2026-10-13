using System.Security.Cryptography;
using System.Text.Json;
using System.Text.Json.Nodes;
using RansomFree.Client;
using RansomFree.Client.Forensics;
using RansomFree.Contracts;

static class RawDeliveryChecks
{
    internal static void Run(string root,string sensor,byte[] raw,DateTimeOffset time,Action<bool,string> check)
    {
        byte[] Changed(string field,ulong value){var node=JsonNode.Parse(raw)!.AsObject();node[field]=value;return JsonSerializer.SerializeToUtf8Bytes(node);}
        void Reject(Action action,string message)
        {try{action();}catch(Exception ex)when(ex is IOException or InvalidDataException or ArgumentException){check(true,message);return;}throw new Exception("Expected rejection: "+message);}
        var directory=Path.Combine(root,"native-delivery-mapping");LinuxRawIntakeReserve.RawRecord first;
        var zero=Changed("cookie",0);string zeroFirst;
        using(var map=new LinuxRawDeliveryMap(directory,sensor,5))
        {
            var a=map.Admit(raw,new(),time);first=a.Record!;
            check(a.RawCommitted&&!a.Duplicate&&a.IdentityKind=="provider-cookie","first provider/cookie creates one canonical durable delivery");
            var b=map.Admit(raw,new(false),time.AddHours(1));
            check(b.Duplicate&&b.Record==first&&map.Records.Count==1&&b.Record.Policy.PreserveActorOnAlert,"duplicate native bytes keep original ID, receipt time and first policy");
            var invalidPolicyDuplicate=map.Admit(raw,new(MaximumActorMiB:0),time.AddHours(2));
            check(invalidPolicyDuplicate.Duplicate&&invalidPolicyDuplicate.Record==first&&map.Failure==null,"exact committed duplicate resolves even when newly supplied policy is invalid");
            var z1=map.Admit(zero,new(),time);var z2=map.Admit(zero,new(),time);
            zeroFirst=z1.Record!.Observation.EventId;
            check(z1.IdentityKind=="collector-delivery-only"&&!z1.Duplicate&&!z2.Duplicate&&zeroFirst!=z2.Record!.Observation.EventId&&map.Records.Count==3,"zero-cookie deliveries stay separate; no invented native deduplication");
            check(z1.Record.Observation.Attribution!.LinuxKernel!.CollectorSequence==2,"duplicate deliveries consume no canonical collector sequence");
        }
        using(var map=new LinuxRawDeliveryMap(directory,sensor,5))
        {
            var recovered=map.Admit(raw,new(false,"critical"),time.AddDays(1));
            check(recovered.Duplicate&&recovered.Record!.Observation==first.Observation&&recovered.Record.Policy==first.Policy&&map.Records.Count==3,"reopen reconstructs canonical mapping directly from committed raw bank");
            check(recovered.Record!.FrameIntegrity=="verified-recovered"&&recovered.Record.PreviousCallerAcknowledgment=="unknown-before-this-open","duplicate after recovery exposes verified bytes and unknown prior caller acknowledgment");
            var zeroAgain=map.Admit(zero,new(),time.AddDays(1));
            check(zeroAgain.Record!.Observation.EventId!=zeroFirst&&zeroAgain.Record.FrameIntegrity=="verified-current-owner","new collector separates another zero-cookie delivery from historical deliveries");
            var differentEpoch=Changed("providerEpoch",42);var sameCookie=map.Admit(differentEpoch,new(),time);
            check(!sameCookie.Duplicate&&sameCookie.Record!.Observation.EventId!=first.Observation.EventId&&map.Records.Count==5,"same cookie in a different provider epoch remains a distinct operation");
            var full=map.Admit(Changed("cookie",700),new(),time);
            check(!full.RawCommitted&&full.Record==null&&full.Overflow?.Reason=="RAW_BACKLOG_EXHAUSTED","full raw map retains an emergency boundary without an invented canonical row");
            check(map.Admit(raw,new(),time).Duplicate&&map.Records.Count==5,"exact previously committed native delivery remains resolvable after overflow");
        }
        var conflict=Path.Combine(root,"native-delivery-conflict");
        using(var map=new LinuxRawDeliveryMap(conflict,sensor,5))
        {
            map.Admit(raw,new(),time);var changed=Changed("pid",12345);
            Reject(()=>map.Admit(changed,new(),time),"same provider/cookie with changed native body is rejected");
            check(map.Failure=="RAW_NATIVE_IDENTITY_CONFLICT"&&map.Records.Count==1,"native identity conflict stops admission and retains the canonical original");
            Reject(()=>map.Admit(Changed("cookie",701),new(),time),"identity conflict cannot silently continue to new observations");
        }
        using(var map=new LinuxRawDeliveryMap(conflict,sensor,5))
            check(map.Records.Count==1&&map.Records[0].PreviousCallerAcknowledgment=="unknown-before-this-open","reopened retained record does not assert prior error or source continuity was resolved");
        var ambiguous=Path.Combine(root,"native-delivery-ambiguous-history");
        using(var bank=new LinuxRawIntakeReserve(ambiguous,sensor,5))
            for(int i=1;i<=2;i++)bank.Commit(raw,LinuxKernelDecoder.Decode(raw,sensor,Guid.Empty.ToString("N"),i,time),new());
        var path=Path.Combine(ambiguous,"raw-reserve-v2.bin");var before=SHA256.HashData(File.ReadAllBytes(path));
        Reject(()=>new LinuxRawDeliveryMap(ambiguous,sensor,5),"legacy bank with multiple event IDs for same native key requires explicit reconciliation");
        check(before.AsSpan().SequenceEqual(SHA256.HashData(File.ReadAllBytes(path))),"mapping conflict does not rewrite retained ambiguous history");
    }
}
