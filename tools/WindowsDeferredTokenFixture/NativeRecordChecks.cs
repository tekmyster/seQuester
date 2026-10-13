using System.Text.Json;
using RansomFree.Client;
using RansomFree.Contracts;
using RansomFree.Server;

internal static class NativeRecordChecks
{
    internal static void Run(string directory)
    {
        var rows=File.ReadAllLines(Path.Combine(directory,"results.jsonl")).Select(x=>JsonDocument.Parse(x)).ToArray();
        if(rows.Length!=34||File.ReadAllText(Path.Combine(directory,"exit.txt")).Trim()!="0"||File.ReadAllText(Path.Combine(directory,"stderr.txt")).Length!=0)throw new InvalidDataException("Successful native fixture required");
        var sensor=Guid.NewGuid().ToString("N");
        var queueDirectory=Path.Combine(directory,"managed-replay-"+Guid.NewGuid().ToString("N"));
        var observations=new List<AgentEvent>();
        using(var spool=new EventSpool(queueDirectory,sensor))
        for(var i=0;i<33;i++){
            var raw=File.ReadAllBytes(Path.Combine(directory,$"raw-{i}.bin"));
            if(raw.Length!=WindowsKernelDecoder.DeferredEventBytes)throw new InvalidDataException("Native frame size differs");
            var legacy=WindowsKernelDecoder.ExtendFromReply(raw[..WindowsKernelDecoder.EventBytes],raw[..WindowsKernelDecoder.ExtendedEventBytes]);
            var packet=WindowsKernelDecoder.ExtendWithDeferred(legacy,raw[WindowsKernelDecoder.ExtendedEventBytes..]);
            var e=WindowsKernelDecoder.Decode(packet,sensor,p=>p,false);var k=e.Attribution!.WindowsKernel!;var d=k.DeferredTokenContext!;var truth=rows[i].RootElement;
            if(!k.IsValid()||k.Version!=7||k.ProcessId!=truth.GetProperty("pid").GetInt32()||k.ThreadId!=truth.GetProperty("tid").GetUInt32()||k.ProcessCreatedFileTime!=truth.GetProperty("process_birth").GetInt64()||
                d.ThreadOwnerPrimary.Sid!="S-1-5-18"||d.RequestorPrimary.Sid!="S-1-5-18"||d.ThreadImpersonating!=(i<32)||e.Attribution.UserSid!=(i<32?"S-1-5-19":"S-1-5-18")||e.Process==null||
                k.CaptureIrql!=1||k.ThreadEffective.Captured!=0||e.Attribution.CompleteRecordSet||e.Attribution.EventTimeCredentials)throw new InvalidDataException("Native identity, separation or timing changed during decoding");
            var restored=JsonSerializer.Deserialize<AgentEvent>(JsonSerializer.Serialize(e));
            if(restored==null||!WindowsKernelEvidence.Matches(restored)||restored.Attribution!.WindowsKernel!.DeferredTokenContext!.RawSha256!=d.RawSha256)throw new InvalidDataException("Native JSON round-trip lost evidence");
            spool.Enqueue(e);
            observations.Add(e);
        }
        var serverDirectory=Path.Combine(queueDirectory,"isolated-server");var store=new Store(serverDirectory);
        var enrollment=store.Enroll(new(store.CreateCode().Code,"owned-native-replay","0.6.26-test"))??throw new Exception("Isolated enrollment failed");
        var ingested=store.Ingest(enrollment.EndpointId,new(observations.ToArray()),System.Net.IPAddress.Loopback);
        if(ingested?.Accepted!=33)throw new Exception("Native observations not persisted by server store");
        var persisted=new Store(serverDirectory).Events(0,100);
        if(persisted.Count!=33||persisted.Any(e=>!WindowsKernelEvidence.Matches(e.Event)||e.Event.Attribution!.WindowsKernel!.DeferredTokenContext==null))throw new Exception("Server restart lost native token evidence");
        File.WriteAllText(Path.Combine(queueDirectory,"native-events.json"),JsonSerializer.Serialize(observations));
        using(var recovered=new EventSpool(queueDirectory,sensor)){
            if(recovered.Count!=33)throw new InvalidDataException("Native evidence lost during queue restart");
            var batch=recovered.Peek();
            if(batch.Events.Length!=33||batch.Events.Any(e=>!WindowsKernelEvidence.Matches(e)||e.Attribution?.WindowsKernel?.DeferredTokenContext==null))throw new InvalidDataException("Recovered queue lost deferred fields");
            try{recovered.Acknowledge(batch,new BatchReceipt(33,0){AttributionVersion=1,WindowsKernelVersion=6});throw new Exception("Older server acknowledgement accepted");}
            catch(InvalidDataException){if(recovered.Count!=33)throw new Exception("Unacknowledged evidence removed");}
            recovered.Acknowledge(batch,new BatchReceipt(33,0){AttributionVersion=1,WindowsKernelVersion=8});
            if(recovered.Count!=0)throw new Exception("Supported acknowledgement did not retire batch");
        }
        foreach(var row in rows)row.Dispose();
        var result=new{Passed=true,NativeRecords=33,SchemaVersion=7,SeparatedSecurityContexts=true,ExplicitLaterMetadata=true,JsonRoundTrip=true,QueueRestart=true,OlderServerAckRejected=true,SupportedAckVerified=true,IsolatedServerPersistence=true,IsolatedServerRestart=true,HttpApiValidated=false,QueueDirectory=queueDirectory,ProductionIntegrated=false};
        File.WriteAllText(Path.Combine(queueDirectory,"acceptance.json"),JsonSerializer.Serialize(result));
        Console.WriteLine(JsonSerializer.Serialize(result));
    }
}
