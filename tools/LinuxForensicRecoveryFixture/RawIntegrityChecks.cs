using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using RansomFree.Client;
using RansomFree.Client.Forensics;
using RansomFree.Contracts;

static class RawIntegrityChecks
{
    internal static void Run(string root,string sensor,string collector,byte[] raw,DateTimeOffset time,Action<bool,string> check)
    {
        void Reject(Action action,string label)
        {try{action();}catch(Exception ex)when(ex is IOException or InvalidDataException or ArgumentException or JsonException){check(true,label);return;}throw new Exception("Expected rejection: "+label);}
        var observation=LinuxKernelDecoder.Decode(raw,sensor,collector,1,time);
        const string expected="{\"PreserveActorOnAlert\":true,\"PreservationThreshold\":\"alert\",\"MaximumActorMiB\":256,\"EvidenceStoreMiB\":1024,\"CacheEntries\":256}";
        check(Encoding.UTF8.GetString(LinuxRawPolicyCodec.Encode(new()))==expected&&LinuxRawPolicyCodec.Decode(Encoding.UTF8.GetBytes(expected))==new ForensicPolicy(),"frozen policy codec has an explicit backward compatible golden representation");
        foreach(var invalid in new[]{expected.Replace("\"alert\"","\"high\",\"Unknown\":1"),expected.Replace("256,","256, ",StringComparison.Ordinal),expected.Replace("\"CacheEntries\":256","\"CacheEntries\":256,\"CacheEntries\":256")})
            Reject(()=>LinuxRawPolicyCodec.Decode(Encoding.UTF8.GetBytes(invalid)),"unknown, noncanonical or duplicate policy fields cannot be silently reinterpreted");
        var templateRoot=Path.Combine(root,"raw-integrity-template");
        using(var reserve=new LinuxRawIntakeReserve(templateRoot,sensor,5))
        {
            reserve.Commit(raw,observation,new());
            check(reserve.Records[0].FrameIntegrity=="verified-current-owner"&&reserve.Records[0].PreviousCallerAcknowledgment=="not-a-recovered-record","fresh committed record reports current-owner verification");
        }
        var template=File.ReadAllBytes(Path.Combine(templateRoot,"raw-reserve-v2.bin"));
        const int intent=4096,frame=4096+6*256;
        // Semantic intent mutations recompute its checksum. These would pass a
        // checksum-only scan; recovery must compare the decoded complete tuple.
        var mutations=new (string Name,int Offset,bool Rehash)[]{
            ("intent-event",48,true),("intent-epoch",64,true),("intent-cookie",72,true),("intent-raw-hash",80,true),
            ("intent-collector",112,true),("intent-sequence",128,true),("intent-index",8,true),("intent-length",12,true),
            ("intent-hash",136,false),("intent-padding",168,false)};
        foreach(var test in mutations)
        {
            var bytes=(byte[])template.Clone();bytes[intent+test.Offset]^=1;
            if(test.Rehash)SHA256.HashData(bytes.AsSpan(intent,136)).CopyTo(bytes.AsSpan(intent+136));
            Corrupt(test.Name,bytes);
        }
        foreach(var test in new[]{("frame-magic",0),("frame-length",8),("frame-index",12),("frame-hash",16),("frame-body",48),("frame-padding",131071)})
        {var bytes=(byte[])template.Clone();bytes[frame+test.Item2]^=1;Corrupt(test.Item1,bytes);}
        var header=(byte[])template.Clone();header[16]^=1;SHA256.HashData(header.AsSpan(0,128)).CopyTo(header.AsSpan(128));Corrupt("header-sensor",header);
        var missingIntent=(byte[])template.Clone();missingIntent.AsSpan(intent,256).Clear();Corrupt("frame-without-intent",missingIntent);
        var emergency=(byte[])template.Clone();var bodyLength=BinaryPrimitives.ReadInt32LittleEndian(emergency.AsSpan(frame+8));
        emergency.AsSpan(frame,131072).CopyTo(emergency.AsSpan(frame+5*131072));emergency.AsSpan(frame,131072).Clear();
        emergency.AsSpan(intent,256).CopyTo(emergency.AsSpan(intent+5*256));emergency.AsSpan(intent,256).Clear();
        BinaryPrimitives.WriteInt32LittleEndian(emergency.AsSpan(intent+5*256+8),5);
        SHA256.HashData(emergency.AsSpan(intent+5*256,136)).CopyTo(emergency.AsSpan(intent+5*256+136));
        BinaryPrimitives.WriteInt32LittleEndian(emergency.AsSpan(frame+5*131072+12),5);
        Corrupt("raw-body-in-emergency-slot",emergency);
        void Corrupt(string name,byte[] bytes)
        {
            var directory=Path.Combine(root,"raw-corrupt-"+name);EvidenceStore.EnsurePrivate(directory);
            var path=Path.Combine(directory,"raw-reserve-v2.bin");EvidenceDurability.SaveNew(path,bytes);
            var hash=SHA256.HashData(bytes);Reject(()=>new LinuxRawIntakeReserve(directory,sensor,5),"recovery rejects "+name);
            check(hash.AsSpan().SequenceEqual(SHA256.HashData(File.ReadAllBytes(path))),"negative evidence retained unchanged: "+name);
        }
        foreach(var stage in new[]{"intent-written","intent-flushed","intent-readback","frame-written","frame-flushed","frame-readback"})
        {
            var directory=Path.Combine(root,"raw-fault-"+stage);
            using(var reserve=new LinuxRawIntakeReserve(directory,sensor,5,(point,_)=>{if(point==stage)throw new IOException("injected after "+stage);}))
            {
                Reject(()=>reserve.Commit(raw,observation,new()),"injected post-operation failure refuses caller success: "+stage);
                Reject(()=>reserve.Commit(raw,LinuxKernelDecoder.Decode(raw,sensor,collector,2,time),new()),"post-operation failure makes admission sticky: "+stage);
                check(reserve.Records.Count==0,"failed caller receives no acknowledged in-memory record: "+stage);
            }
            if(stage.StartsWith("intent",StringComparison.Ordinal))
                Reject(()=>new LinuxRawIntakeReserve(directory,sensor,5),"post-intent failure recovers explicit unknown frame: "+stage);
            else
            {
                using var reopened=new LinuxRawIntakeReserve(directory,sensor,5);
                check(reopened.Records.Count==1&&reopened.Records[0].FrameIntegrity=="verified-recovered"&&reopened.Records[0].PreviousCallerAcknowledgment=="unknown-before-this-open","post-frame failure recovers verified bytes without a prior caller ACK: "+stage);
            }
        }
        var invalidRoot=Path.Combine(root,"raw-pre-admission-rejection");
        using(var reserve=new LinuxRawIntakeReserve(invalidRoot,sensor,5))
        {
            foreach(var kernel in new[]{observation.Attribution!.LinuxKernel! with{NativeObservationSha256="AA"},observation.Attribution.LinuxKernel! with{ProviderEpoch="01"},observation.Attribution.LinuxKernel! with{Cookie="01"}})
                Reject(()=>reserve.Commit(raw,observation with{Attribution=observation.Attribution with{LinuxKernel=kernel}},new()),"short digest or noncanonical numeric identity refused before intent write");
            Reject(()=>reserve.Commit(new byte[65537],observation,new()),"one byte over native input bound is an explicit pre-admission failure");
            check(reserve.Records.Count==0&&reserve.Overflow==null,"pre-admission rejection does not invent a persisted source loss marker");
        }
    }
}
