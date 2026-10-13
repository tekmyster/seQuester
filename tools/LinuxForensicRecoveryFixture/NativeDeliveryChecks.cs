using System.Diagnostics;
using System.Text.Json;
using System.Text.Json.Nodes;
using Microsoft.Data.Sqlite;
using RansomFree.Client;
using RansomFree.Client.Forensics;
using RansomFree.Contracts;

static class NativeDeliveryChecks
{
    internal static void Child(string root,string sensor,byte[] raw,LinuxActorSnapshot snapshot,string cut)
    {
        using var s=new NativePinChecks.Scope(root,sensor,raw);var work=s.Issue();
        File.WriteAllText(Path.Combine(root,"context.json"),JsonSerializer.Serialize(new{Event=work.EventId,Session=s.Id}));
        void Cut(string point){if(point==cut)Environment.Exit(73);}
        var claim=s.Claim(work,Cut);s.Journal.AuthorizeNativePin(claim,Cut);s.Journal.MarkNativePinStarting(claim,Cut);
        using var admission=s.Journal.AdmitSnapshot(work.EventId,snapshot.NativeStatus,Cut);
        admission.BeginRead(s.Journal.Read(work.EventId).Observation,snapshot.NativeStatus);
        admission.Append(snapshot.Bytes.Span);admission.Finish(snapshot.NativeStatus);
        s.Journal.CommitAdmittedSnapshot(admission,Cut);
        throw new Exception("Requested native delivery crash cut not reached");
    }
    internal static async Task Run(string root,string sensor,byte[] raw,LinuxActorSnapshot snapshot,string seed)
    {
        if(Directory.Exists(root))throw new ArgumentException("Fresh native delivery fixture root required");Directory.CreateDirectory(root);int checks=0;
        void Check(bool ok,string label){if(!ok)throw new Exception(label);checks++;Console.WriteLine("PASS: "+label);}
        void Reject(Action action,string label)
        {try{action();}catch(Exception ex)when(ex is InvalidDataException or InvalidOperationException or ArgumentException){Check(true,label);return;}throw new Exception("Unexpected acceptance: "+label);}
        foreach(var cut in new[]{"native-pin-committed","native-authorization-committed","native-start-committed","allocation-intent-committed","private-allocation-complete","admitted-private-verified","admitted-receipt-committed"})
        {
            var directory=Path.Combine(root,cut);
            var start=new ProcessStartInfo(Environment.ProcessPath!){UseShellExecute=false,RedirectStandardOutput=true,RedirectStandardError=true};
            if(Path.GetFileNameWithoutExtension(Environment.ProcessPath)=="dotnet")start.ArgumentList.Add(typeof(NativeDeliveryChecks).Assembly.Location);
            foreach(var arg in new[]{"native-delivery-child",seed,directory,cut})start.ArgumentList.Add(arg);
            using(var child=Process.Start(start)!)
            {
                var stdout=child.StandardOutput.ReadToEndAsync();var stderr=child.StandardError.ReadToEndAsync();await FixtureProcessTiming.Wait(child);
                Check(child.ExitCode==73,"actual child exit: "+cut+" "+await stdout+await stderr);
            }
            var context=JsonNode.Parse(File.ReadAllBytes(Path.Combine(directory,"context.json")))!;var id=context["Event"]!.GetValue<string>();
            using var journal=new LinuxForensicJournal(directory,sensor);var before=journal.Read(id);var pin=journal.ReadNativeWorkEvidence(id)!;
            Check(pin.State=="PIN_INTERRUPTED_UNKNOWN"&&pin.ActualReturnUtc==null&&before.Acquisition==null,"restart retains unknown native acquisition and no invented return: "+cut);
            var intent=journal.ReadSnapshotIntent(id);var spool=new EventSpool(Path.Combine(directory,"spool"),sensor);var errors=new List<string>();
            await using(var pipeline=new ForensicPipeline(sensor,directory,errors.Add))Check(pipeline.TrySubmitPrepared(journal,id,spool),"unknown native job admitted: "+cut);
            Check(errors.Count==0&&spool.Count==2&&journal.Read(id).Done,"original and linked completion survive unknown capture: "+cut+" "+string.Join(";",errors));
            var batch=spool.Peek();var original=batch.Events.Single(e=>e.EventId==id);var completion=batch.Events.Single(e=>e.EventId==before.CompletionId);
            foreach(var e in batch.Events)
            {
                Check(e.User==before.Observation.User&&e.Process==before.Observation.Process&&e.ProcessId==before.Observation.ProcessId&&e.Attribution==before.Observation.Attribution,"exact original user/process/PID/raw evidence retained: "+cut);
                Check(e.Forensics!.IsValid()&&LinuxKernelEvidence.Matches(e)&&e.Forensics.ActorExecutable.LinuxNativeWork==pin,"versioned native timeline survives event contract: "+cut);
            }
            var captured=cut=="admitted-receipt-committed";var f=completion.Forensics!;
            Check(f.Collection.State=="partial"&&f.Detection.ReasonCodes.Contains("LINUX_NATIVE_WORK_OUTCOME_UNKNOWN"),"unknown outcome stays explicit even with a verified copy: "+cut);
            Check(captured?f.ActorExecutable.Sha256==snapshot.Sha256.ToUpperInvariant()&&f.Preservation.HashMatched==true:
                f.ActorExecutable.Sha256==null&&f.Preservation.ArtifactRelativePath==null&&journal.Read(id).Acquisition==null,"only committed verified private receipt authorizes actor copy recovery: "+cut);
            Check(journal.ReadNativeWorkEvidence(id)==pin&&journal.Read(id).DropState=="not-attempted","delivery does not manufacture native return or release: "+cut);
            if(!captured)Check(journal.ReadSnapshotIntent(id)==intent,"unverified private intent is retained unchanged: "+cut);
            var ack=new BatchReceipt(2,0){AttributionVersion=1,ForensicsVersion=1,LinuxKernelVersion=1,LinuxActorAcquisitionVersion=1};
            Reject(()=>spool.Acknowledge(batch,ack),"old server acknowledgement cannot delete new timeline: "+cut);
            Check(spool.Count==2,"unsupported timeline stays queued: "+cut);spool.Acknowledge(batch,ack with{LinuxNativeWorkVersion=1});
            Check(spool.Count==0,"explicit timeline acknowledgement clears exact batch: "+cut);
            File.WriteAllBytes(Path.Combine(directory,"events.json"),JsonSerializer.SerializeToUtf8Bytes(batch));
        }
        {
            using var s=new NativePinChecks.Scope(Path.Combine(root,"actual-return-and-corruption"),sensor,raw);var work=s.Issue();var claim=s.Claim(work);
            Reject(()=>s.Journal.RecoverVerifiedPrivateReceiptForDelivery(work.EventId),"active native owner cannot publish final recovery outcome");
            s.Journal.AuthorizeNativePin(claim);s.Journal.MarkNativePinStarting(claim);var now=DateTimeOffset.UtcNow;
            s.Journal.RecordNativePinReturn(claim,now,"OWNED_UNRESOLVED_RETURN");var pin=s.Journal.ReadNativeWorkEvidence(work.EventId)!;
            Check(pin.State=="PIN_INTERRUPTED_UNKNOWN"&&pin.ActualReturnUtc==now&&pin.ReturnOutcome=="unresolved","actual return and unknown acquisition are separately retained");
            using var actor=s.Journal.RestoreActor(work.EventId);
            Check(actor.Image==null&&actor.Process.Pid==s.Journal.Read(work.EventId).Observation.ProcessId&&actor.LinuxNativeWork==pin,"unknown restore never reopens actor path or live PID");
            foreach(var field in new[]{"CompletionId","RawSha256","PolicySha256","Collector","Epoch","Cookie","Lease"})
            {
                using var c=new SqliteConnection(new SqliteConnectionStringBuilder{DataSource=Path.Combine(s.Root,"linux-forensic-intake/journal.db"),Pooling=false}.ToString());c.Open();
                using var read=c.CreateCommand();read.CommandText="SELECT intent FROM native_pins";var bytes=(byte[])read.ExecuteScalar()!;
                var node=JsonNode.Parse(bytes)!;node[field]=field=="Lease"?JsonValue.Create(-999L):JsonValue.Create(new string('0',field.EndsWith("Sha256",StringComparison.Ordinal)?64:32));
                using var update=c.CreateCommand();update.CommandText="UPDATE native_pins SET intent=$value";var value=update.Parameters.AddWithValue("$value",JsonSerializer.SerializeToUtf8Bytes(node));update.ExecuteNonQuery();
                try{Reject(()=>s.Journal.RestoreActor(work.EventId).Dispose(),"corrupt native pin linkage rejected: "+field);}
                finally{value.Value=bytes;update.ExecuteNonQuery();}
            }
            Check(!(pin with{StartingGeneration=0}).IsValid(work.EventId,null)&&!(pin with{AuthorizationId=null}).IsValid(work.EventId,null)&&
                !(pin with{StartingReason="fabricated"}).IsValid(work.EventId,null)&&!(pin with{State="PIN_COMMITTED"}).IsValid(work.EventId,null),"contradictory public timeline shapes rejected");
            var collector=new ForensicCollector(sensor,s.Root);
            AgentEvent Original(LinuxForensicJournal.Work w)
            {using var lease=s.Journal.RestoreActor(work.EventId);return w.Observation with{Forensics=collector.Begin(w.Observation,lease)};}
            using var db=new SqliteConnection(new SqliteConnectionStringBuilder{DataSource=Path.Combine(s.Root,"linux-forensic-intake/journal.db"),Pooling=false}.ToString());db.Open();
            using var readIntent=db.CreateCommand();readIntent.CommandText="SELECT intent FROM native_pins";var saved=(byte[])readIntent.ExecuteScalar()!;
            var changed=JsonNode.Parse(saved)!;changed["IssuedUtc"]=DateTimeOffset.UtcNow.AddSeconds(1);
            using var updateIntent=db.CreateCommand();updateIntent.CommandText="UPDATE native_pins SET intent=$value";var payload=updateIntent.Parameters.AddWithValue("$value",JsonSerializer.SerializeToUtf8Bytes(changed));
            try{Reject(()=>s.Journal.PrepareOriginal(work.EventId,w=>{var e=Original(w);updateIntent.ExecuteNonQuery();return e;}),"timeline mutation during enrichment cannot commit original payload");}
            finally{payload.Value=saved;updateIntent.ExecuteNonQuery();}
            Check(s.Journal.Read(work.EventId).Original==null,"failed timeline revalidation leaves no partial original");
            var prepared=s.Journal.PrepareOriginal(work.EventId,Original);
            payload.Value=JsonSerializer.SerializeToUtf8Bytes(changed);updateIntent.ExecuteNonQuery();
            try
            {
                Reject(()=>s.Journal.PrepareCompletion(work.EventId,_=>throw new Exception("Completion callback must not run")),"timeline cannot change between original and linked completion");
                Check(s.Journal.PrepareOriginal(work.EventId,_=>throw new Exception("Prepared replay must not regenerate")).SequenceEqual(prepared),"durable original replay remains byte-identical during corruption investigation");
            }
            finally{payload.Value=saved;updateIntent.ExecuteNonQuery();}
        }
        var result=new{Passed=true,Checks=checks,Schema=12,Scope="Actual crash and private file recovery; exact original attribution plus unknown native timeline through common spool, no kernel controller or production deployment"};
        File.WriteAllText(Path.Combine(root,"RESULTS.json"),JsonSerializer.Serialize(result));Console.WriteLine(JsonSerializer.Serialize(result));
    }
}
