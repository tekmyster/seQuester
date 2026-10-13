using System.Diagnostics;
using System.Security.Cryptography;
using System.Text.Json;
using System.Text.Json.Nodes;
using Microsoft.Data.Sqlite;
using RansomFree.Client;
using RansomFree.Client.Forensics;
using RansomFree.Contracts;

static class SourceLifecycleChecks
{
    internal static async Task Run(string root,string sensor,byte[] raw,AgentEvent observation,LinuxActorSnapshot snapshot,string seedPath,Action<bool,string> check)
    {
        var epoch=observation.Attribution!.LinuxKernel!.ProviderEpoch;var time=observation.ObservedUtc;
        byte[] Changed(string field,ulong value){var node=JsonNode.Parse(raw)!.AsObject();node[field]=value;return JsonSerializer.SerializeToUtf8Bytes(node);}
        void Reject(Action action,string message)
        {try{action();}catch(Exception ex)when(ex is IOException or InvalidDataException or InvalidOperationException or ArgumentException or SqliteException){check(true,message);return;}throw new Exception("Expected rejection: "+message);}
        LinuxSourceSession Source(LinuxForensicJournal journal,string directory,string? newEpoch=null,long bankQuota=512L*1024*1024)=>new(journal,Path.Combine(directory,"bank"),sensor,5,newEpoch??epoch,new(0),layoutReplayForTest:true,bankQuota:bankQuota);
        foreach(var (name,input) in new[]{("malformed",new byte[]{123,125}),("oversize",new byte[65537]),("bad-identity",Changed("pid",ulong.MaxValue))})
        {
            var directory=Path.Combine(root,"source-"+name);using var j=new LinuxForensicJournal(directory,sensor);var s=Source(j,directory);
            Reject(()=>s.Admit(input,new(),time),"source rejects "+name+" before a raw commit");
            var boundaries=j.ReadSourceBoundaries(s.Id);
            check(s.Records.Count==0&&s.State.State=="CONTINUITY_FAULTED"&&boundaries is [{Reason:"PREDECODE_UNKNOWN"}]&&boundaries[0].InputLength==input.Length,"predecode boundary includes exact length with no fabricated observation: "+name);
            var port=new SnapshotAdmissionChecks.Port(snapshot.NativeStatus,snapshot.Bytes.ToArray());using var device=new LinuxActorLeaseDevice(port);
            Reject(()=>s.Capture(device,observation.EventId),"faulted source forbids native access: "+name);
            check(port.StatusReads==0&&port.Selects==0&&port.Drops==0,"no native call occurs after predecode failure: "+name);
            int close=0;s.CloseForTest(new(0),()=>close++);check(close==1&&s.State.State=="CLOSED"&&j.ReadSourceBoundaries(s.Id).All(x=>x.OpenEnded),"actual close retains historical unknown range: "+name);
        }
        foreach(var (name,sample,reason) in new[]{("increase",new LinuxSourceSession.LostSample(1),"LOADER_LOST_COUNTER_INCREASED"),("unavailable",new LinuxSourceSession.LostSample(null,"EIO"),"LOADER_LOST_COUNTER_UNAVAILABLE")})
        {
            var directory=Path.Combine(root,"source-loss-"+name);using var j=new LinuxForensicJournal(directory,sensor);var s=Source(j,directory);s.Admit(raw,new(),time);
            check(!s.SampleLoss(sample)&&j.ReadSourceBoundaries(s.Id).Single().Reason==reason,"actual loader loss signal faults even with no cookie jump: "+name);
            check(j.ReadSourceBoundaries(s.Id).Single().Unresolved.Length==1,"raw-only backlog remains in source boundary");s.CloseForTest(sample,()=>{});
        }
        {
            var directory=Path.Combine(root,"source-loss-reset");using var j=new LinuxForensicJournal(directory,sensor);var s=new LinuxSourceSession(j,Path.Combine(directory,"bank"),sensor,5,epoch,new(9),layoutReplayForTest:true);
            check(!s.SampleLoss(new(8))&&j.ReadSourceBoundaries(s.Id).Single().Reason=="LOADER_LOST_COUNTER_RESET","loader counter reset cannot be reported as continuous delivery");s.CloseForTest(new(8),()=>{});
        }
        {
            var directory=Path.Combine(root,"source-cookie-jumps");using var j=new LinuxForensicJournal(directory,sensor);var s=Source(j,directory);
            for(int i=0;i<5;i++){check(s.SampleLoss(new(0)),"unchanged loader counter remains valid");s.Admit(Changed("cookie",(ulong)(10000+i*40000)),new(),time);}
            check(s.State.State=="OPEN"&&j.ReadSourceBoundaries(s.Id).Length==0&&s.Records.Count==5,"large cookie jumps do not invent lost-operation ranges");
            var full=s.Admit(Changed("cookie",990000),new(),time);
            check(!full.RawCommitted&&s.State.State=="CONTINUITY_FAULTED"&&j.ReadSourceBoundaries(s.Id).Single().Reason=="RAW_BANK_UNKNOWN","full bank retains emergency boundary and faults source");
            Reject(()=>Source(j,Path.Combine(directory,"next")),"no automatic bank rotation while old controller is unresolved");
            var path=Path.Combine(directory,"bank","raw-reserve-v2.bin");s.CloseForTest(new(0),()=>{});var retained=SHA256.HashData(File.ReadAllBytes(path));
            var next=Source(j,Path.Combine(directory,"next"),(ulong.Parse(epoch)+1).ToString());check(next.State.State=="OPEN"&&next.State.BankId!=s.State.BankId,"new bank/session becomes admissible only after actual old close");next.CloseForTest(new(0),()=>{});
            check(retained.AsSpan().SequenceEqual(SHA256.HashData(File.ReadAllBytes(path))),"closed full bank remains byte-identical after next session");
        }
        foreach(var stage in new[]{"raw","allocation-intent","write-intent","bytes-verified","manifest-committed"})
        {
            var directory=Path.Combine(root,"source-epoch-"+stage);using var j=new LinuxForensicJournal(directory,sensor);var s=Source(j,directory);var record=s.Admit(raw,new(),time).Record!;
            var id=record.Observation.EventId;j.CommitObservation(raw,record.Observation,record.Policy);
            LinuxSnapshotAdmission? admission=null;
            if(stage=="allocation-intent")Reject(()=>j.AdmitSnapshot(id,snapshot.NativeStatus,p=>{if(p=="allocation-intent-committed")throw new IOException("owned cut");}),"owned cut leaves allocation-intent before epoch transition");
            else if(stage!="raw")admission=j.AdmitSnapshot(id,snapshot.NativeStatus);
            var port=new SnapshotAdmissionChecks.Port(snapshot.NativeStatus,snapshot.Bytes.ToArray());using var device=new LinuxActorLeaseDevice(port);
            if(stage is "bytes-verified" or "manifest-committed")
            {
                device.ReadReadySnapshotInto(record.Observation,admission!);
                if(stage=="bytes-verified")Reject(()=>j.CommitAdmittedSnapshot(admission!,p=>{if(p=="admitted-receipt-committed")throw new IOException("owned cut");}),"owned cut leaves verified private receipt before epoch transition");
                else j.CommitAdmittedSnapshot(admission!);
            }
            admission?.Dispose();var calls=port.StatusReads;var selects=port.Selects;
            Reject(()=>s.Admit(Changed("providerEpoch",ulong.Parse(epoch)+1),new(),time),"provider epoch transition refuses new observation in old source: "+stage);
            Reject(()=>s.Capture(device,id),"old source cannot acquire by stale numeric ID: "+stage);
            Reject(()=>s.Release(device,id),"old source cannot release by stale numeric ID: "+stage);
            check(port.StatusReads==calls&&port.Selects==selects&&port.Drops==0,"epoch transition issues no old-ID native call: "+stage);
            var a=j.Read(id).Acquisition!;
            check(stage is "bytes-verified" or "manifest-committed"?a.Status.State=="captured"&&a.SnapshotSha256!.Equals(snapshot.Sha256,StringComparison.OrdinalIgnoreCase):a.Status.State=="unavailable","epoch change retains finalized private evidence or explicit unavailable: "+stage);
            check(s.Records.Count==1&&j.ReadSourceBoundaries(s.Id).Single().ObservedEpoch==(ulong.Parse(epoch)+1).ToString(),"epoch boundary preserves old raw record and observed new epoch: "+stage);s.CloseForTest(new(0),()=>{});
        }
        {
            var directory=Path.Combine(root,"source-close-journal-failure");using var j=new LinuxForensicJournal(directory,sensor);var s=Source(j,directory);int close=0;
            Sql(directory,"CREATE TRIGGER owned_fail_source BEFORE INSERT ON source_boundaries BEGIN SELECT RAISE(FAIL,'owned source journal failure'); END;");
            Reject(()=>s.CloseForTest(new(0),()=>close++),"source close intent storage failure remains visible");
            check(close==0&&s.Failure=="SOURCE_CLOSE_INTENT_UNCOMMITTED"&&s.State.State=="OPEN","failed close intent does not start native close or claim completion");
            Reject(()=>s.Admit(raw,new(),time),"in-memory close failure blocks input despite persisted OPEN state");
            Sql(directory,"DROP TRIGGER owned_fail_source;");s.CloseForTest(new(0),()=>close++);check(close==1&&s.State.State=="CLOSED","retry persists close intent before actual controller close");
        }
        {
            var directory=Path.Combine(root,"source-boundary-journal-failure");using var j=new LinuxForensicJournal(directory,sensor);var s=Source(j,directory);
            Sql(directory,"CREATE TRIGGER owned_fail_source BEFORE INSERT ON source_boundaries BEGIN SELECT RAISE(FAIL,'owned boundary failure'); END;");
            Reject(()=>s.SampleLoss(new(3)),"loader loss plus SQLite failure surfaces uncommitted boundary");
            check(s.Failure=="SOURCE_BOUNDARY_UNCOMMITTED:LOADER_LOST_COUNTER_INCREASED"&&s.State.State=="OPEN","boundary transaction failure leaves sticky runtime fault, never false success");
            Reject(()=>s.Admit(raw,new(),time),"storage failure cannot be healed by a later successful raw frame");
            Sql(directory,"DROP TRIGGER owned_fail_source;");s.CloseForTest(new(3),()=>{});
            var boundary=j.ReadSourceBoundaries(s.Id)[0];
            check(boundary.Reason=="LOADER_LOST_COUNTER_INCREASED"&&boundary.PreviousLost=="0"&&boundary.SampledLost=="3","storage recovery persists the original loss reason and sample before closing");
        }
        {
            var directory=Path.Combine(root,"source-close-blocked");using var j=new LinuxForensicJournal(directory,sensor);var s=Source(j,directory);
            using var entered=new ManualResetEventSlim();using var release=new ManualResetEventSlim();
            var closing=Task.Run(()=>s.CloseForTest(new(0),()=>{entered.Set();release.Wait();}));
            try
            {
                check(entered.Wait(TimeSpan.FromSeconds(5)),"controlled close entered blocking callback");
                check(s.State.State=="CLOSE_UNKNOWN_OPEN"&&!closing.IsCompleted&&s.State.CloseReturnedUtc==null,"blocked close retains unknown state with no fabricated completion time");
                Reject(()=>Source(j,Path.Combine(directory,"second")),"blocked close forbids a second source owner");
                Reject(()=>s.Admit(raw,new(),time),"blocked close forbids further input");
                Reject(()=>s.CloseForTest(new(0),()=>throw new Exception("second close invoked")),"blocked close cannot be invoked twice");
            }
            finally{release.Set();await closing.WaitAsync(TimeSpan.FromSeconds(5));}
            check(s.State.State=="CLOSED"&&s.State.CloseReturnedUtc!=null,"CLOSED appears only after actual controller close returns");
        }
        {
            var directory=Path.Combine(root,"source-close-throws");using var j=new LinuxForensicJournal(directory,sensor);var s=Source(j,directory);int calls=0;
            Reject(()=>s.CloseForTest(new(0),()=>{calls++;throw new IOException("owned native close failure");}),"throwing controller close retains unresolved ownership");
            Reject(()=>s.CloseForTest(new(0),()=>calls++),"throwing native close cannot be retried into a false success");
            check(calls==1&&s.State.State=="CLOSE_UNKNOWN_OPEN"&&s.State.CloseReturnedUtc==null,"native close failure has no fabricated return receipt");
        }
        {
            var directory=Path.Combine(root,"source-close-final-transaction-failure");using var j=new LinuxForensicJournal(directory,sensor);var s=Source(j,directory);int close=0;
            Sql(directory,"CREATE TRIGGER owned_fail_closed BEFORE UPDATE ON source_lifecycle WHEN NEW.state='CLOSED' BEGIN SELECT RAISE(FAIL,'owned final close failure'); END;");
            Reject(()=>s.CloseForTest(new(0),()=>close++),"actual close with failed final transaction stays explicitly unknown");
            var returnedBefore=DateTimeOffset.UtcNow;
            check(close==1&&s.State.State=="CLOSE_UNKNOWN_OPEN","actual return is not confused with persisted close completion");
            Sql(directory,"DROP TRIGGER owned_fail_closed;");s.CloseForTest(new(0),()=>close++);check(close==1&&s.State.State=="CLOSED","final close commit retry never closes native controller twice");
            check(s.State.CloseReturnedUtc<=returnedBefore,"final transaction retry retains original observed native close-return time");
        }
        {
            var directory=Path.Combine(root,"source-reopen-closed");string id;byte[] retained;
            using(var j=new LinuxForensicJournal(directory,sensor)){var s=Source(j,directory);id=s.Admit(raw,new(),time).Record!.Observation.EventId;s.CloseForTest(new(0),()=>{});}
            var path=Path.Combine(directory,"bank","raw-reserve-v2.bin");retained=SHA256.HashData(File.ReadAllBytes(path));
            using(var j=new LinuxForensicJournal(directory,sensor))
            {
                var s=Source(j,directory);check(j.ReadSourceBoundaries(s.Id) is [{Reason:"COLLECTOR_RESTART_UNKNOWN"}],"reopened bank persists restart boundary before next admission");
                var duplicate=s.Admit(raw,new(false),time.AddDays(1));check(duplicate.Duplicate&&duplicate.Record!.Observation.EventId==id&&duplicate.Record.PreviousCallerAcknowledgment=="unknown-before-this-open","reopen preserves canonical old record and unknown caller acknowledgment");
                var port=new SnapshotAdmissionChecks.Port(snapshot.NativeStatus,snapshot.Bytes.ToArray());using var device=new LinuxActorLeaseDevice(port);
                Reject(()=>s.Capture(device,id),"historical duplicate cannot authorize new live acquisition");check(port.StatusReads==0,"recovered canonical raw identity is not a live native capability");s.CloseForTest(new(0),()=>{});
            }
            check(retained.AsSpan().SequenceEqual(SHA256.HashData(File.ReadAllBytes(path))),"restart/lifecycle evidence never rewrites retained raw bank");
        }
        {
            var directory=Path.Combine(root,"source-actual-restart");await Child("lifecycle-child",directory,null);
            var id=File.ReadAllText(Path.Combine(directory,"session-id.txt"));using var j=new LinuxForensicJournal(directory,sensor);
            check(j.ReadSource(id).State=="CONTINUITY_FAULTED"&&j.ReadSourceBoundaries(id).Any(b=>b.Reason=="COLLECTOR_RESTART_UNKNOWN"),"actual process exit/reopen persists interrupted source boundary");
            check(j.Pending().All(x=>j.Read(x).Acquisition?.Status.State=="unavailable"),"restart converts unfinalized work to explicit unavailable without native calls");
            Reject(()=>Source(j,Path.Combine(directory,"next")),"restart does not invent proof that old controller close returned");
        }
        foreach(var cut in new[]{"lifecycle-migration-before-commit","lifecycle-migration-after-commit"})
        {
            var directory=Path.Combine(root,cut);using(var j=new LinuxForensicJournal(directory,sensor))j.CommitObservation(raw,observation,new());
            Sql(directory,"DROP TABLE source_owner_returns; DROP TABLE source_activation; DROP TABLE native_pins; DROP TABLE source_ingress; DROP TABLE canonical_events; DROP TABLE source_ownership; DROP TABLE source_policy; DROP TABLE source_bank_formats; DROP TABLE source_reconciliation; DROP TABLE source_control; DROP TABLE native_progress; DROP TABLE source_boundaries; DROP TABLE source_lifecycle; DROP TABLE source_banks; PRAGMA user_version=3;");
            await Child("migration-child",directory,cut);
            check(Scalar(directory,"PRAGMA user_version;")==(cut.EndsWith("before-commit",StringComparison.Ordinal)?3:4),"lifecycle migration has atomic old/new schema at actual process exit: "+cut);
            using var migrated=new LinuxForensicJournal(directory,sensor);check(migrated.Read(observation.EventId).Observation==observation,"lifecycle migration retains preexisting exact observation");
        }
        {
            var directory=Path.Combine(root,"source-same-epoch-isolation");using var j=new LinuxForensicJournal(directory,sensor);var old=Source(j,Path.Combine(directory,"old"));
            var prior=old.Admit(raw,new(),time).Record!;j.CommitObservation(raw,prior.Observation,prior.Policy);old.CloseForTest(new(0),()=>{});var oldAcquisition=j.Read(prior.Observation.EventId).Acquisition;
            var current=Source(j,Path.Combine(directory,"current"));var next=current.Admit(raw,new(),time).Record!;j.CommitObservation(raw,next.Observation,next.Policy);
            check(!current.SampleLoss(new(1)),"loss faults only the current session when provider epoch is reused");
            check(oldAcquisition?.Status.Reason=="ACTOR_COPY_UNAVAILABLE_CONTROLLER_CLOSED"&&j.Read(prior.Observation.EventId).Acquisition==oldAcquisition&&j.Read(next.Observation.EventId).Acquisition?.Status.Reason=="ACTOR_COPY_UNAVAILABLE_SOURCE_CONTINUITY","current-session fault cannot change historical work finalized after actual prior close");
            check(j.ReadSourceBoundaries(current.Id).Single().Unresolved.Select(x=>x.EventId).SequenceEqual(new[]{next.Observation.EventId}),"source unknown range keys are scoped to the exact collector, not epoch alone");current.CloseForTest(new(1),()=>{});
        }
        {
            var directory=Path.Combine(root,"source-capture-release");using var j=new LinuxForensicJournal(directory,sensor);var s=Source(j,directory);
            var r=s.Admit(raw,new(),time).Record!;var port=new SnapshotAdmissionChecks.Port(snapshot.NativeStatus,snapshot.Bytes.ToArray());using var device=s.TakeOpenPermit().OpenForTest(()=>new LinuxActorLeaseDevice(port));
            check(s.Capture(device,r.Observation.EventId)&&j.Read(r.Observation.EventId).Acquisition?.Status.State=="captured"&&port.Selects==1,"source gate captures only canonical current raw work using admitted destination");
            s.Release(device,r.Observation.EventId);s.Release(device,r.Observation.EventId);
            check(port.Drops==1&&j.Read(r.Observation.EventId).DropState=="returned","durable verified source acquisition permits exactly one recorded native release");
            s.CloseForTest(new(0),()=>{});check(j.ReadSourceBoundaries(s.Id).Last().Unresolved.Length==0,"closed source distinguishes returned leases from unresolved work");
        }
        {
            var directory=Path.Combine(root,"source-decoder-oom");using var j=new LinuxForensicJournal(directory,sensor);var s=Source(j,directory);
            try{s.AdmitWithAllocationFailureForTest(raw,new(),time);throw new Exception("OOM injection escaped fixture");}
            catch(OutOfMemoryException){check(true,"decoder allocation failure is propagated without another required allocation");}
            check(s.Failure=="SOURCE_BOUNDARY_UNCOMMITTED:OUT_OF_MEMORY"&&s.Records.Count==0,"decoder OOM leaves a sticky source stop and no raw frame");
            Reject(()=>s.Admit(raw,new(),time),"subsequent input cannot resume after decoder OOM");Reject(()=>s.TakeOpenPermit(),"OOM source cannot grant a controller permit");s.CloseForTest(new(0),()=>{});
            check(j.ReadSourceBoundaries(s.Id).Single().SampleError=="SOURCE_BOUNDARY_UNCOMMITTED:OUT_OF_MEMORY","later durable close records the OOM health reason");
        }
        {
            var directory=Path.Combine(root,"source-opening-permits");using var j=new LinuxForensicJournal(directory,sensor);var s=Source(j,directory);var permit=s.TakeOpenPermit();int opens=0;
            using var controller=permit.OpenForTest(()=>{opens++;return new(new SnapshotAdmissionChecks.Port(snapshot.NativeStatus,snapshot.Bytes.ToArray()));});
            Reject(()=>permit.OpenForTest(()=>{opens++;return new(new SnapshotAdmissionChecks.Port(snapshot.NativeStatus,snapshot.Bytes.ToArray()));}),"source opening permit is single-use");
            Reject(()=>s.TakeOpenPermit(),"source cannot issue a second opening permit");check(opens==1,"only one controller factory executes for one source");
            var record=s.Admit(raw,new(),time).Record!;using var foreign=new LinuxActorLeaseDevice(new SnapshotAdmissionChecks.Port(snapshot.NativeStatus,snapshot.Bytes.ToArray()));
            Reject(()=>s.Capture(foreign,record.Observation.EventId),"foreign controller cannot perform current source acquisition");s.Close(new(0));
            Reject(()=>permit.OpenForTest(()=>throw new Exception("closed permit used")),"closed source permit cannot reopen its controller");
        }
        foreach(var kind in new[]{"unavailable-counter","overflow"})
        {
            var directory=Path.Combine(root,"source-initial-"+kind);using var j=new LinuxForensicJournal(directory,sensor);var bankPath=Path.Combine(directory,"bank");
            if(kind=="overflow")using(var map=new LinuxRawDeliveryMap(bankPath,sensor,5))for(int i=1;i<=6;i++)map.Admit(Changed("cookie",(ulong)i),new(),time);
            var s=new LinuxSourceSession(j,bankPath,sensor,5,epoch,kind=="overflow"?new(0):new(null,"EIO"),layoutReplayForTest:true);
            Reject(()=>s.TakeOpenPermit(),"initial "+kind+" grants no controller opening permit");check(s.State.State=="CONTINUITY_FAULTED","initial source fault remains durable: "+kind);s.CloseForTest(new(0),()=>{});
        }
        {
            var directory=Path.Combine(root,"source-boundary-bounds");using var j=new LinuxForensicJournal(directory,sensor);var s=Source(j,directory);
            var keys=Enumerable.Range(0,9000).Select(i=>new LinuxForensicJournal.SourceWorkKey(Guid.NewGuid().ToString("N"),epoch,i.ToString(),i)).ToArray();
            j.TransitionSource(s.Id,"CONTINUITY_FAULTED",new("FIXTURE_BOUNDED_KEYS",time,null,"0",null,new string('x',2*1048576),null,keys));
            var b=j.ReadSourceBoundaries(s.Id).Single();
            check(b.SampleError?.Length==128&&b.SampleErrorTruncated&&b.Unresolved.Length+b.UnresolvedOmitted==9000&&b.UnresolvedOmitted>0,"large diagnostic text and key list have explicit bounded truncation");
            check(Scalar(directory,"SELECT max(length(boundary)) FROM source_boundaries;")<=1048576,"boundary is bounded before SQLite accepts it");s.CloseForTest(new(0),()=>{});
        }
        {
            var directory=Path.Combine(root,"source-raw-bank-quota");using var j=new LinuxForensicJournal(directory,sensor);
            Reject(()=>Source(j,directory,bankQuota:1),"raw bank logical quota rejects source opening");
            check(Scalar(directory,"SELECT count(*) FROM source_lifecycle;")==0,"quota failure admits neither a lifecycle nor native work");
        }
        async Task Child(string mode,string directory,string? cut)
        {
            var start=new ProcessStartInfo(Environment.ProcessPath!){UseShellExecute=false,RedirectStandardOutput=true,RedirectStandardError=true};
            if(string.Equals(Path.GetFileNameWithoutExtension(Environment.ProcessPath),"dotnet",StringComparison.OrdinalIgnoreCase))start.ArgumentList.Add(typeof(SourceLifecycleChecks).Assembly.Location);
            foreach(var a in new[]{mode,seedPath,directory})start.ArgumentList.Add(a);if(cut!=null)start.ArgumentList.Add(cut);
            using var p=Process.Start(start)!;var output=p.StandardOutput.ReadToEndAsync();var errors=p.StandardError.ReadToEndAsync();await FixtureProcessTiming.Wait(p);
            var log=await output+await errors;File.WriteAllText(Path.Combine(root,Path.GetFileName(directory)+".log"),log);check(p.ExitCode==73,"actual lifecycle child exit: "+mode+"/"+cut+" "+log);
        }
    }
    private static long Scalar(string directory,string sql)
    {using var c=Connection(directory);using var q=c.CreateCommand();q.CommandText=sql;return Convert.ToInt64(q.ExecuteScalar());}
    private static void Sql(string directory,string sql)
    {using var c=Connection(directory);using var q=c.CreateCommand();q.CommandText=sql;q.ExecuteNonQuery();}
    private static SqliteConnection Connection(string directory)
    {var c=new SqliteConnection(new SqliteConnectionStringBuilder{DataSource=Path.Combine(directory,"linux-forensic-intake","journal.db"),Pooling=false}.ToString());c.Open();return c;}
}
