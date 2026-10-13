using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using RansomFree.Client.Forensics;
using RansomFree.Contracts;

// Qualification only. Read the stopped source's existing outbox without retries,
// repairs, rebasing snapshot identities or manufacturing a native confirmation.
internal static class ProactiveAckProof
{
    internal sealed record Row(string SnapshotId,string ProcessIndex,string Classification,string ClaimSha256,int Attempts,string? LastReply,DateTimeOffset QueuedUtc,DateTimeOffset RetryUntilUtc,FileIdentityEvidence SnapshotIdentity,Dictionary<string,string> FileHashes);
    internal sealed record Proof(string Schema,DateTimeOffset SourceStoppedUtc,string ControlledSnapshotId,Row[] Rows,int Confirmed,int Pending,int NonConfirmed);
    static JsonElement Read(string path)=>JsonSerializer.Deserialize<JsonElement>(File.ReadAllBytes(path));
    static string S(JsonElement e,string name)=>e.GetProperty(name).GetString()!;
    static string Hash(byte[] b)=>Convert.ToHexString(SHA256.HashData(b));
    static void Need(bool value,string reason){if(!value)throw new InvalidDataException("Proactive ACK proof: "+reason);}
    static uint N(byte[] b,int o)=>BinaryPrimitives.ReadUInt32LittleEndian(b.AsSpan(o));
    static ulong Q(byte[] b,int o)=>BinaryPrimitives.ReadUInt64LittleEndian(b.AsSpan(o));
    internal static Proof Verify(string capture,string sensor,string controlledRecord,DateTimeOffset stopped)
    {
        var root=Path.Combine(capture,"kernel-actor-intake");var controlled=S(Read(controlledRecord),"SnapshotId");
        var records=Directory.GetFiles(root,"*.process.json").Select(path=>(path,record:Read(path))).Where(x=>S(x.record,"State")=="captured").ToArray();
        var intents=Directory.GetFiles(root,"*.ack-intent.json");Need(records.Length==intents.Length&&intents.Length>0,"one durable intent per captured process snapshot required");
        var rows=new List<Row>();var used=new HashSet<string>(StringComparer.Ordinal);var owned=new HashSet<string>(StringComparer.Ordinal);
        foreach(var path in intents)
        {
            var i=Read(path);var id=S(i,"SnapshotId");var index=S(i,"ProcessIndex");
            Need(Guid.TryParseExact(id,"N",out _)&&used.Add(id)&&Path.GetFileName(path)==id+".ack-intent.json"&&Path.GetFileName(index)==index&&index.EndsWith(".process.json",StringComparison.Ordinal),"intent names/unique identity");
            var pair=records.Single(x=>Path.GetFileName(x.path)==index);var r=pair.record;var key=r.GetProperty("Ready");
            Need(i.GetProperty("Version").GetInt32()==1&&S(i,"Sensor")==sensor&&i.GetProperty("MaximumAttempts").GetInt32()==4&&r.GetProperty("Version").GetInt32()==1&&S(r,"Sensor")==sensor&&S(r,"SnapshotId")==id,"intent/record linkage");
            var queued=i.GetProperty("QueuedUtc").GetDateTimeOffset();var until=i.GetProperty("RetryUntilUtc").GetDateTimeOffset();Need(until==queued.AddSeconds(30)&&queued<=stopped,"local retry window");
            var provider=S(key,"Provider");var instance=key.GetProperty("OperationInstance").GetUInt64();
            var generation=key.GetProperty("Generation").GetUInt64();var candidate=key.GetProperty("Candidate").GetUInt64();var pid=key.GetProperty("Pid").GetInt32();var created=key.GetProperty("Created").GetInt64();
            Need(provider==S(i,"Provider")&&instance==i.GetProperty("Instance").GetUInt64()&&generation>0&&candidate>0&&key.GetProperty("ReadySequence").GetUInt64()>0,"strong process key");
            Need(index==Hash(Encoding.UTF8.GetBytes($"{sensor}:{provider}:{instance:X16}:{generation:X16}:{candidate:X16}:{pid}:{created}"))+".process.json","process index key");
            var files=new Dictionary<string,string>(StringComparer.Ordinal);
            byte[] FileBytes(string name){var b=File.ReadAllBytes(Path.Combine(root,name));files.Add(name,Hash(b));owned.Add(name);return b;}
            FileBytes(Path.GetFileName(path));var recordBytes=FileBytes(index);var wal=FileBytes(index+".wal");var offset=0;byte[]? prepare=null;
            for(uint kind=1;kind<=2;kind++)
            {
                Need(wal.Length-offset>=48&&wal.AsSpan(offset,8).SequenceEqual("SQACQ001"u8)&&N(wal,offset+8)==kind,"WAL frame header");var length=checked((int)N(wal,offset+12));Need(length<=32768&&length<=wal.Length-offset-48,"WAL frame length");
                var payload=wal.AsSpan(offset+16,length).ToArray();Need(SHA256.HashData(wal.AsSpan(offset,16+length)).AsSpan().SequenceEqual(wal.AsSpan(offset+16+length,32)),"WAL frame hash");
                if(kind==1){prepare=payload;Need(payload.AsSpan().SequenceEqual(recordBytes),"WAL PREPARE exact record");}else Need(payload.AsSpan().SequenceEqual(SHA256.HashData(prepare!)),"WAL COMMIT");offset+=48+length;
            }
            Need(offset==wal.Length,"WAL has no trailing data");
            var expected=r.GetProperty("SnapshotFile").Deserialize<FileIdentityEvidence>()!;FileIdentityEvidence actual;
            using(var file=File.OpenRead(Path.Combine(root,id+".bin")))
            {
                actual=NativeFileIdentity.Read(file);Need(NativeFileIdentity.Same(expected,actual)&&file.Length==key.GetProperty("ByteLength").GetInt64()&&Convert.ToHexString(SHA256.HashData(file))==S(r,"Sha256")&&NativeFileIdentity.Same(actual,NativeFileIdentity.Read(file)),"immutable native snapshot identity and bytes");
            }
            FileBytes(id+".bin");var claim=Convert.FromBase64String(S(i,"Claim"));var digest=S(i,"ClaimSha256");
            Need(claim.Length==160&&Hash(claim)==digest&&new[]{0,4,56,60,64,68,72,76}.Select(o=>N(claim,o)).SequenceEqual(new uint[]{4,21,0,0,11,2,checked((uint)actual.Size!),1}),"ACK claim header/hash");
            Need(Convert.ToHexString(claim.AsSpan(8,16))==provider&&Q(claim,24)==generation&&Q(claim,32)==candidate&&Q(claim,40)==(ulong)pid&&Q(claim,48)==(ulong)created&&Convert.ToHexString(claim.AsSpan(80,32))==S(r,"Sha256")&&claim.AsSpan(112,16).SequenceEqual(Guid.ParseExact(id,"N").ToByteArray())&&claim.AsSpan(128,32).SequenceEqual(SHA256.HashData(Encoding.UTF8.GetBytes($"{actual.StableId}|{actual.Size}|{actual.ChangeMarker}"))),"ACK claim immutable snapshot binding");
            var starts=Directory.GetFiles(root,id+".ack-attempt-*.json").Where(x=>!x.EndsWith(".result.json",StringComparison.Ordinal)).Order().ToArray();Need(starts.Length<=4,"retry bound");string? last=null;
            for(var a=1;a<=starts.Length;a++)
            {
                Need(Path.GetFileName(starts[a-1])==id+".ack-attempt-"+a+".json","contiguous attempts");var attempt=JsonSerializer.Deserialize<JsonElement>(FileBytes(Path.GetFileName(starts[a-1])));var reply=JsonSerializer.Deserialize<JsonElement>(FileBytes(id+".ack-attempt-"+a+".result.json"));
                foreach(var e in new[]{attempt,reply})Need(e.GetProperty("Version").GetInt32()==1&&S(e,"SnapshotId")==id&&S(e,"ClaimSha256")==digest&&e.GetProperty("Attempt").GetInt32()==a,"attempt/result linkage");
                var begun=attempt.GetProperty("StartedUtc").GetDateTimeOffset();Need(queued<=begun&&begun<until&&begun<=stopped&&reply.GetProperty("RecordedUtc").GetDateTimeOffset()==begun,"attempt timestamps");
                last=S(reply,"Outcome");Need(last=="ACK_REPLY_UNAVAILABLE"||last=="ACK_CONFIRMED"&&a==starts.Length,"attempt reply state");
                Need(last=="ACK_CONFIRMED"?reply.GetProperty("NativeCode").ValueKind==JsonValueKind.Null:!string.IsNullOrWhiteSpace(reply.GetProperty("NativeCode").GetString()),"reply status explicit");
            }
            string classification;var terminalPath=Path.Combine(root,id+".ack-outcome.json");var ackPath=Path.Combine(root,id+".ack");
            if(File.Exists(terminalPath))
            {
                var t=JsonSerializer.Deserialize<JsonElement>(FileBytes(id+".ack-outcome.json"));classification=S(t,"Outcome");var at=t.GetProperty("RecordedUtc").GetDateTimeOffset();var attempt=t.GetProperty("Attempt").GetInt32();
                Need(t.GetProperty("Version").GetInt32()==1&&S(t,"SnapshotId")==id&&S(t,"ClaimSha256")==digest&&at>=queued&&at<=stopped&&!t.TryGetProperty("ReplacesOutcomeSha256",out _),"terminal linkage/time");
                if(classification=="ACK_CONFIRMED")Need(attempt==starts.Length&&starts.Length>0&&last==classification&&FileBytes(id+".ack").AsSpan().SequenceEqual(claim)&&t.GetProperty("NativeCode").ValueKind==JsonValueKind.Null,"confirmed terminal and native receipt");
                else
                {
                    Need(!File.Exists(ackPath)&&last!="ACK_CONFIRMED","non-confirmed terminal has no confirmed receipt/reply");
                    Need(classification=="ACK_TRANSPORT_EXHAUSTED"&&attempt==4&&starts.Length==4&&last=="ACK_REPLY_UNAVAILABLE"||classification=="ACK_RETRY_WINDOW_EXPIRED"&&attempt==0&&at>=until,"expected non-confirmed terminal policy");
                }
            }
            else
            {
                Need(!File.Exists(ackPath)&&last!="ACK_CONFIRMED","pending cannot conceal confirmed receipt/reply");
                classification="PERSISTED_PENDING_AT_SHUTDOWN"; // Local test classification; not a native outcome.
            }
            Need(id!=controlled||classification=="ACK_CONFIRMED","controlled actor must have native confirmation");
            rows.Add(new(id,index,classification,digest,starts.Length,last,queued,until,actual,files));
        }
        Need(rows.Any(x=>x.SnapshotId==controlled)&&records.All(x=>used.Contains(S(x.record,"SnapshotId"))),"all captured records and controlled actor accounted");
        Need(Directory.GetFiles(root).Where(x=>Path.GetFileName(x).Contains(".ack",StringComparison.Ordinal)).All(x=>owned.Contains(Path.GetFileName(x))),"no orphan or unverified ACK files");
        return new("sequester.proactive-ack-accounting/v2",stopped,controlled,rows.ToArray(),rows.Count(x=>x.Classification=="ACK_CONFIRMED"),rows.Count(x=>x.Classification=="PERSISTED_PENDING_AT_SHUTDOWN"),rows.Count(x=>x.Classification is "ACK_TRANSPORT_EXHAUSTED" or "ACK_RETRY_WINDOW_EXPIRED"));
    }
}
