using System.Text.Json;
using System.Text.Json.Nodes;
using Microsoft.Data.Sqlite;
using RansomFree.Client.Forensics;

static class ControlledIngressChecks
{
    internal static void Run(string root,string sensor,byte[] raw)
    {
        if(Directory.Exists(root))throw new ArgumentException("Fresh control ingress fixture required");Directory.CreateDirectory(root);int checks=0;
        void Check(bool ok,string name){if(!ok)throw new Exception(name);checks++;Console.WriteLine("PASS: "+name);}
        using(var s=new NativePinChecks.Scope(Path.Combine(root,"missing-ack-native-pin"),sensor,raw,false))
        {
            var work=s.Issue();
            try{s.Claim(work);throw new Exception("Unacknowledged source granted native pin");}catch(InvalidOperationException){Check(true,"attempted activation without exact committed ACK cannot grant native pin");}
            Check(!s.Journal.HasWork(work.EventId)&&s.Journal.ReadNativePin(work.EventId)==null,"no partial work or pin from missing ACK");s.Barrier.Return(work);
        }
        foreach(var mode in new[]{"normal","ack-before-write-return","pre-ack","invalid-ack","loss-at-ack","failed-ack-commit","completion-before-ack","fault-persistence-retry"})
        {
            var dir=Path.Combine(root,mode);var epoch=JsonNode.Parse(raw)!["providerEpoch"]!.GetValue<ulong>();
            using var journal=new LinuxForensicJournal(dir,sensor);using var bank=new LinuxRawIngressReserve(Path.Combine(dir,"bank"),sensor,Guid.NewGuid().ToString("N"),epoch.ToString(System.Globalization.CultureInfo.InvariantCulture),5,true);
            var barrier=new LinuxSourceWorkBarrier();var source=journal.PrepareControlledSource(bank,new(),"0",DateTimeOffset.UtcNow,512L*1024*1024);
            journal.RecordSourceOwnerOpenAttempt(source.Id,DateTimeOffset.UtcNow);journal.RecordOwnerMethodReturn(source.Id,ActivationFixture.OwnerReturn(source.Id));
            var ready=JsonSerializer.SerializeToUtf8Bytes(new{controlledReady=true,controlVersion=1,schemaVersion=5,loadedProgramIds=new[]{1,2,3,4,5},attachedProgramIds=new[]{2,3,4},observeAttached=false,denialAttached=false,scratchMapFrozen=true,scratchMapId=11,configMapFrozen=true,configMapId=12,eventsMapId=13,lostMapId=14,providerEpoch=epoch,activationNonce=new string('a',32),targetInode=321,targetDevice=17,targetPinned=true,mode=0,lostAtReady=0,activationFrame="one-command-then-eof"});
            journal.CommitSourceControlLink(source.Id,ready,DateTimeOffset.UtcNow);
            var ingress=new LinuxControlledIngress(journal,bank,barrier,source.Id);ActivationFixture.BeforeWrite(journal,source.Id);journal.MarkSourceControlWriteStarted(source.Id,DateTimeOffset.UtcNow);
            if(mode!="ack-before-write-return")journal.RecordSourceActivationWrite(source.Id,ActivationFixture.Returned(journal,source.Id));
            byte[] Ack(int lost=0)=>JsonSerializer.SerializeToUtf8Bytes(new{controlledActivated=true,controlVersion=1,sessionId=source.Id,providerEpoch=epoch,activationNonce=new string('a',32),attachedProgramIds=new[]{2,3,4,1,5},observeAttached=true,denialAttached=true,lostAtActivation=lost});
            if(mode=="fault-persistence-retry")
            {
                using var c=new SqliteConnection(new SqliteConnectionStringBuilder{DataSource=Path.Combine(dir,"linux-forensic-intake/journal.db"),Pooling=false}.ToString());c.Open();using var q=c.CreateCommand();q.CommandText="CREATE TRIGGER owned_first_fault_failure BEFORE INSERT ON source_boundaries BEGIN SELECT RAISE(FAIL,'owned fault persistence failure'); END;";q.ExecuteNonQuery();
                ingress.LatchFault("OWNED_FIRST_FAULT","first-error");var first=barrier.Current.FirstInterruption!;
                Check(barrier.Current.State=="Faulted"&&journal.ReadSource(source.Id).State=="OPEN","immediate fault latch performs no SQLite write");
                try{ingress.PersistFaultOnce();throw new Exception("Fault write failure ignored");}catch(SqliteException){Check(true,"first fault persistence failure remains explicit");}
                ingress.LatchFault("OWNED_SECOND_FAULT","second-error");q.CommandText="DROP TRIGGER owned_first_fault_failure;";q.ExecuteNonQuery();
                ingress.PersistFaultOnce();ingress.PersistFaultOnce();ingress.Fault("OWNED_THIRD_FAULT");
                var boundaries=journal.ReadSourceBoundaries(source.Id);
                Check(boundaries.Length==1&&boundaries[0].Reason==first.Reason&&boundaries[0].RecordedUtc==first.RecordedUtc&&boundaries[0].SampleError=="first-error","retry and later faults retain one exact original fault record");
                var outcome=ingress.Receive(raw,DateTimeOffset.UtcNow);var retained=outcome.Indexed!;
                Check(outcome.Kind==LinuxControlledIngress.Disposition.DiagnosticRetained,"raw-only fault cannot be scheduled as canonical work");
                Check(retained.Status=="RAW_AFTER_FAULT"&&retained.CanonicalEventId==null&&bank.ReadRaw(bank.Entries.Single()).SequenceEqual(raw),"fault retry never promotes residual raw observation");
            }
            else if(mode is "normal" or "ack-before-write-return")
            {
                Check(ingress.Receive(Ack(),DateTimeOffset.UtcNow).Kind==LinuxControlledIngress.Disposition.ControlRecorded&&ingress.Activated,"exact ACK enables this fresh ingress");
                var received=ingress.Receive(raw,DateTimeOffset.UtcNow);var observation=received.Indexed!;
                Check(received.Kind==(mode=="normal"?LinuxControlledIngress.Disposition.CanonicalReady:LinuxControlledIngress.Disposition.CanonicalWaitingForActivation),"canonical receipt explicitly distinguishes pending write confirmation: "+mode);
                Check(observation.Status=="RAW_VALID"&&bank.ReadRaw(bank.Entries.Single()).SequenceEqual(raw),"post-ACK canonical observation retains exact OS bytes");
                var work=barrier.TryIssue(observation.CanonicalEventId!)!;
                if(mode=="ack-before-write-return")
                {
                    try{journal.CommitNativePin(source.Id,bank,bank.Entries.Single(),barrier,work);throw new Exception("Pending write granted native pin");}catch(InvalidOperationException){Check(true,"queued post-ACK observation waits for actual write receipt");}
                    journal.RecordSourceActivationWrite(source.Id,ActivationFixture.Returned(journal,source.Id));
                    Check(journal.ReadDeferredCanonical(source.Id,bank).Single()==bank.Entries.Single(),"original canonical raw remains available after actual write confirmation");
                }
                var pin=journal.CommitNativePin(source.Id,bank,bank.Entries.Single(),barrier,work);
                Check(journal.AuthorizeNativePin(pin),"confirmed owned ACK supports durable authorization");journal.AbortNativePinBeforeStart(pin);
                try{_ =new LinuxControlledIngress(journal,bank,barrier,source.Id);throw new Exception("Runtime reconstructed from historic ACK");}catch(InvalidOperationException){Check(true,"historical activated source cannot create fresh ingress");}
            }
            else if(mode=="pre-ack")
            {
                var earlyReceipt=ingress.Receive(raw,DateTimeOffset.UtcNow);var early=earlyReceipt.Indexed!;
                Check(earlyReceipt.Kind==LinuxControlledIngress.Disposition.DiagnosticRetained,"pre-ACK raw receipt explicitly denies dispatch");
                Check(early.Status=="RAW_AFTER_FAULT"&&early.CanonicalEvent==null&&early.CanonicalEventId==null,"pre-ACK operation stays raw-only with faulted receive view");
                Check(bank.ReadRaw(bank.Entries.Single()).SequenceEqual(raw)&&bank.Entries.Single().View.FirstInterruption!.Reason=="NATIVE_BEFORE_ACTIVATION_ACK","pre-ACK exact bytes and first ordering fault retained");
                ingress.Receive(Ack(),DateTimeOffset.UtcNow);
                Check(!ingress.Activated&&journal.ReadSourceControl(source.Id)!.Activated==null&&bank.Entries.Length==2&&bank.ReadRaw(bank.Entries[1]).SequenceEqual(Ack())&&barrier.TryIssue(Guid.NewGuid().ToString("N"))==null,"late retained raw ACK never reauthorizes early operation or source");
                Check(journal.ReadDeferredCanonical(source.Id,bank).Length==0,"raw-only ordering failure cannot become deferred operational work");
            }
            else if(mode=="loss-at-ack")
            {
                var ack=Ack(1);ingress.Receive(ack,DateTimeOffset.UtcNow);
                Check(!ingress.Activated&&barrier.Current.Reason=="ACTIVATION_LOSS_CHANGED","loss change during activation disables acquisition");
                Check(journal.ReadSourceControl(source.Id)!.Activated==null&&bank.ReadRaw(bank.Entries.Single()).SequenceEqual(ack),"changed-loss ACK remains exact raw evidence without activating record");
            }
            else if(mode=="completion-before-ack")
            {
                var complete=JsonSerializer.SerializeToUtf8Bytes(new{controlledComplete=true,controlVersion=1,activated=true,observerAttempted=true,reason="CONTROLLED_STOPPED",nativeError=0,retainedLinksDestroyed=5,drainResult=0,lost=0,lostError=(int?)null});
                ingress.Receive(complete,DateTimeOffset.UtcNow);
                Check(!ingress.Activated&&journal.ReadSourceControl(source.Id)!.Activated==null,"completed loader never fabricates missing ACK");
                var late=Ack();ingress.Receive(late,DateTimeOffset.UtcNow);
                Check(bank.ReadRaw(bank.Entries.Single()).SequenceEqual(late)&&barrier.Current.State=="Faulted","late post-completion ACK retained raw without fresh authority");
            }
            else
            {
                if(mode=="failed-ack-commit")
                {
                    using var c=new SqliteConnection(new SqliteConnectionStringBuilder{DataSource=Path.Combine(dir,"linux-forensic-intake/journal.db"),Pooling=false}.ToString());c.Open();using var q=c.CreateCommand();q.CommandText="CREATE TRIGGER owned_ack_failure BEFORE UPDATE ON source_control BEGIN SELECT RAISE(FAIL,'owned ACK persistence failure'); END;";q.ExecuteNonQuery();
                }
                var ack=mode=="invalid-ack"?"{\"controlledActivated\":true}"u8.ToArray():Ack();var invalid=ingress.Receive(ack,DateTimeOffset.UtcNow);var result=invalid.Indexed!;
                Check(invalid.Kind==LinuxControlledIngress.Disposition.DiagnosticRetained,"invalid ACK explicitly denies dispatch: "+mode);
                Check(result.Status=="RAW_INVALID"&&result.CanonicalEventId==null,"failed ACK yields diagnostic only: "+mode);
                Check(bank.ReadRaw(bank.Entries.Single()).SequenceEqual(ack)&&journal.ReadSourceControl(source.Id)!.Activated==null,"failed ACK bytes survive without invented committed authority: "+mode);
            }
            if(mode is not ("normal" or "ack-before-write-return"))Check(barrier.Current.State=="Faulted"&&journal.ReadSource(source.Id).State=="CONTINUITY_FAULTED","fault survives in-memory and durable source state: "+mode);
        }
        var resultSummary=new{Passed=true,Checks=checks,Scope="Exact control/raw routing and durable ACK admission using fixture metadata; no process, map, native controller or source activation"};File.WriteAllText(Path.Combine(root,"RESULTS.json"),JsonSerializer.Serialize(resultSummary));Console.WriteLine(JsonSerializer.Serialize(resultSummary));
    }
}
