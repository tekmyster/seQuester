using System.Buffers.Binary;
using System.Formats.Tar;
using System.IO.Compression;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using RansomFree.Client;
using RansomFree.Contracts;

static class LeaseProtocolChecks
{
    // Replay the accepted native metadata and bytes through a deterministic port.
    // This exercises managed binding/stream/error logic, not live ioctl admission.
    public static void Run(byte[] archive,JsonElement[] records,Action<bool,string> check)
    {
        var artifacts=new Dictionary<string,byte[]>();
        using(var zip=new GZipStream(new MemoryStream(archive),CompressionMode.Decompress))
        using(var tar=new TarReader(zip))
            while(tar.GetNextEntry() is {} entry)if(System.Text.RegularExpressions.Regex.IsMatch(entry.Name,@"^evidence-[0-9]+\.bin$"))
            {
                check(entry.EntryType==TarEntryType.RegularFile&&entry.Length is >0 and <=4194304&&!artifacts.ContainsKey(entry.Name),"bounded unique archived actor artifact: "+entry.Name);
                using var data=new MemoryStream();entry.DataStream!.CopyTo(data);artifacts.Add(entry.Name,data.ToArray());
            }
        var sensor=Guid.NewGuid().ToString("N");var collector=Guid.NewGuid().ToString("N");long sequence=0;var copies=0;
        void Reject(Action action,string name){try{action();}catch(InvalidDataException){check(true,name);return;}throw new Exception("Invalid native snapshot accepted: "+name);}
        foreach(var record in records)
        {
            if(!record.TryGetProperty("FinalStatus",out var rawStatus))continue;
            var raw=Encode(rawStatus);var status=LinuxActorLeaseStatus.Decode(raw);
            var observation=LinuxKernelDecoder.Decode(Encoding.UTF8.GetBytes(record.GetProperty("Event").GetRawText()),sensor,collector,++sequence,DateTimeOffset.UtcNow).Attribution!.LinuxKernel!;
            check(status.Matches(observation),"archived final status matches complete event identity: "+sequence);
            if(!record.TryGetProperty("Artifact",out var name))
            {
                check(!status.Ready,"failed deadline result cannot become readable bytes");
                using var failed=new LinuxActorLeaseDevice(new Port(raw,[]));Reject(()=>failed.ReadReadySnapshot(observation),"failed native completion refuses select/read");continue;
            }
            var bytes=artifacts[name.GetString()!];var port=new Port(raw,bytes);using var device=new LinuxActorLeaseDevice(port);
            var snapshot=device.ReadReadySnapshot(observation);copies++;
            check(snapshot.Bytes.Span.SequenceEqual(bytes)&&snapshot.Sha256.Equals(record.GetProperty("ActualSha256").GetString(),StringComparison.OrdinalIgnoreCase)&&snapshot.Sha256==Convert.ToHexString(SHA256.HashData(bytes)),"exact archived actor bytes and SHA-256: "+copies);
            check(port.Drops==0&&port.Selects==1&&snapshot.NativeStatus==status,"reading does not discard native bytes before durable preservation: "+copies);
            check(!observation.WhitelistEligible,"captured bytes do not imply executable provenance or whitelist eligibility: "+copies);
            device.Drop(observation);check(port.Drops==1,"drop revalidates full identity: "+copies);
            if(copies!=1)continue;
            Reject(()=>LinuxActorLeaseStatus.Decode(raw[..159]),"truncated native status rejected");
            var unknown=raw.ToArray();BinaryPrimitives.WriteUInt32LittleEndian(unknown.AsSpan(152),3);Reject(()=>LinuxActorLeaseStatus.Decode(unknown),"unqualified native status schema rejected");
            var huge=raw.ToArray();BinaryPrimitives.WriteUInt64LittleEndian(huge.AsSpan(40),4194305);Reject(()=>LinuxActorLeaseStatus.Decode(huge),"native actor exceeds qualified allocation bound rejected");
            static string Next(string n)=>checked(ulong.Parse(n)+1).ToString(System.Globalization.CultureInfo.InvariantCulture);
            foreach(var wrong in new[]{observation with{Cookie=Next(observation.Cookie)},observation with{ProviderEpoch=Next(observation.ProviderEpoch)},observation with{ProcessId=observation.ProcessId+1},observation with{ThreadId=observation.ThreadId+1},observation with{ProcessStartNs=Next(observation.ProcessStartNs)},observation with{TaskStartNs=Next(observation.TaskStartNs)},observation with{SelfExecId=Next(observation.SelfExecId)},observation with{ActorInode=Next(observation.ActorInode)},observation with{ActorDevice=observation.ActorDevice+1},observation with{AssociationAfter=Next(observation.AssociationAfter)},observation with{AssociationError=-117}})
            {
                var denied=new Port(raw,bytes);using var mismatch=new LinuxActorLeaseDevice(denied);
                Reject(()=>mismatch.ReadReadySnapshot(wrong),"mismatched lease tuple rejected before select");
                Reject(()=>mismatch.Drop(wrong),"mismatched lease tuple cannot drop another observation");
                check(denied.Selects==0&&denied.Drops==0,"mismatched key performs no selection or disposal");
            }
            using(var reader=new LinuxActorLeaseDevice(new Port(raw,bytes)))
            {
                var grown=reader.ReadReadySnapshot(observation with{ActorSize="1"});
                check(grown.Bytes.Length==(int)status.Size,"post-exclusion native size controls byte allocation and exact read");
                check(!grown.SizeMatchesEarlierObservation,"earlier observed size difference remains explicit");
                check(grown.Sha256==snapshot.Sha256,"earlier size mismatch cannot substitute or truncate snapshot bytes");
            }
            var cut=new Port(raw,bytes[..^1]);using(var reader=new LinuxActorLeaseDevice(cut))Reject(()=>reader.ReadReadySnapshot(observation),"short native byte stream rejected");
            var extra=new Port(raw,[..bytes,0]);using(var reader=new LinuxActorLeaseDevice(extra))Reject(()=>reader.ReadReadySnapshot(observation),"long native byte stream rejected");
            var changed=new Port(raw,bytes){ChangeSecondStatus=true};using(var reader=new LinuxActorLeaseDevice(changed))Reject(()=>reader.ReadReadySnapshot(observation),"status mutation during read rejects snapshot");
            var badCount=new Port(raw,bytes){InvalidReadCount=true};using(var reader=new LinuxActorLeaseDevice(badCount))Reject(()=>reader.ReadReadySnapshot(observation),"native out-of-range read count rejected");
        }
        check(copies==38&&artifacts.Count==38,"all 38 archived native actor snapshots verified through managed reader");
    }
    internal static byte[] Encode(JsonElement value)
    {
        var bytes=new byte[160];var words=new[]{"id","cookie","started_ns","finished_ns","deadline_ns","size","inode","device","bytes","tgid","tid","process_start_ns","task_start_ns","self_exec_id","association_generation","provider_epoch"};
        for(var i=0;i<words.Length;i++)BinaryPrimitives.WriteUInt64LittleEndian(bytes.AsSpan(i*8),value.GetProperty(words[i]).GetUInt64());
        var tail=new[]{"state","error","write_lease","metadata_changed","association_state","association_error","schema_version","struct_size"};
        for(var i=0;i<tail.Length;i++)BinaryPrimitives.WriteInt32LittleEndian(bytes.AsSpan(128+i*4),value.GetProperty(tail[i]).GetInt32());
        return bytes;
    }
    private sealed class Port(byte[] status,byte[] bytes):ILinuxActorLeaseTransport
    {
        private int position,statusReads;public int Selects,Drops;public bool ChangeSecondStatus,InvalidReadCount;
        public void Control(uint command,byte[] request)
        {
            if(command==LinuxActorLeaseDevice.StatusCommand)
            {
                if(request.Length!=160)throw new Exception("Wrong status buffer");status.CopyTo(request,0);statusReads++;
                if(ChangeSecondStatus&&statusReads>1)BinaryPrimitives.WriteUInt64LittleEndian(request.AsSpan(40),1);
            }
            else if(command==LinuxActorLeaseDevice.SelectCommand){if(request.Length!=8)throw new Exception("Wrong select buffer");Selects++;position=0;}
            else if(command==LinuxActorLeaseDevice.DropCommand){if(request.Length!=8)throw new Exception("Wrong drop buffer");Drops++;}
            else throw new Exception("Unexpected native command");
        }
        public int Read(byte[] destination,int count){if(InvalidReadCount)return count+1;var n=Math.Min(137,Math.Min(count,bytes.Length-position));bytes.AsSpan(position,n).CopyTo(destination);position+=n;return n;}
        public void Dispose(){}
    }
}
