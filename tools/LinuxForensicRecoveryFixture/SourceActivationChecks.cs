using RansomFree.Contracts;
using System.Diagnostics;
using System.Text.Json;
using Microsoft.Data.Sqlite;
using RansomFree.Client;
using RansomFree.Client.Forensics;

static class SourceActivationChecks
{
    internal static async Task Run(string root,string sensor,byte[] raw,string seedPath)
    {
        if(Directory.Exists(root))throw new ArgumentException("Fresh isolated activation fixture required");Directory.CreateDirectory(root);int checks=0;
        void Check(bool ok,string text){if(!ok)throw new Exception(text);checks++;Console.WriteLine("PASS: "+text);}
        void Reject(Action action,string text){try{action();throw new Exception("Accepted invalid activation: "+text);}catch(Exception e)when(e is InvalidDataException or InvalidOperationException or SqliteException){Check(true,text);}}
        foreach(var mode in new[]{"normal","missing-sample","changed-loss","unavailable-loss","foreign-map","foreign-command","short-write","failed-write","failed-eof","managed-eof","ack-before-receipt","write-commit-failure","write-postcommit-failure","racing-receipt","utc-clock-step"})
        {
            using var s=new NativePinChecks.Scope(Path.Combine(root,mode),sensor,raw,acknowledge:false,writeReceipt:false,prepareActivation:false);
            var j=s.Journal;var id=s.Id;var sample=ActivationFixture.Sample(j,id);
            Check(j.ReadSourceHealthControl(id).Control!=null&&!j.ReadSourceHealthControl(id).ActivationWriteConfirmed,"fresh health read retains link without inventing missing activation: "+mode);
            if(mode=="missing-sample")
            {
                Reject(()=>j.MarkSourceControlWriteStarted(id,DateTimeOffset.UtcNow),"missing sample prevents activation write intent");
                Check(j.ReadSourceControl(id)!.WriteStartedUtc==null&&!j.SourceActivationWriteConfirmed(id),"no invented attempted or successful write");continue;
            }
            if(mode=="foreign-map"||mode=="foreign-command")
            {
                var foreign=mode=="foreign-map"?sample with{Map=sample.Map with{Id=999}}:sample with{CommandSha256=new string('0',64)};
                Reject(()=>j.CommitSourceActivationSample(id,foreign),"foreign linked activation evidence rejected: "+mode);
                Check(j.ReadSourceActivation(id)==null,"foreign sample has no partial persisted authority: "+mode);continue;
            }
            if(mode=="changed-loss")sample=sample with{Lost="1"};
            if(mode=="unavailable-loss")sample=sample with{Lost=null,Error="posix:5"};
            j.CommitSourceActivationSample(id,sample);j.CommitSourceActivationSample(id,sample);
            Check(j.ReadSourceActivation(id)!.Sample==sample,"one exact original preactivation sample persists: "+mode);
            Reject(()=>j.CommitSourceActivationSample(id,sample with{SampleId=Guid.NewGuid().ToString("N")}),"sample identity cannot be regenerated: "+mode);
            if(mode is "changed-loss" or "unavailable-loss")
            {
                Reject(()=>j.MarkSourceControlWriteStarted(id,DateTimeOffset.UtcNow),"failed continuity evidence prevents write intent: "+mode);
                Check(j.ReadSourceControl(id)!.WriteStartedUtc==null,"loss failure preserves sample without inventing write attempt: "+mode);
                Reject(()=>j.ReadSourceHealthControl(id),"fresh health read rejects changed or unavailable activation loss: "+mode);continue;
            }
            var receipt=ActivationFixture.Returned(j,id);
            Reject(()=>j.RecordSourceActivationWrite(id,receipt),"write return cannot precede durable intent: "+mode);
            j.MarkSourceControlWriteStarted(id,DateTimeOffset.UtcNow);
            if(mode=="normal")
            {
                Reject(()=>j.RecordSourceActivationWrite(id,receipt with{CommandSha256=new string('0',64)}),"same-length different activation buffer digest rejected");
                Reject(()=>j.RecordSourceActivationWrite(id,receipt with{ReturnedMonotonic=receipt.AttemptedMonotonic-1}),"reversed monotonic write/EOF return rejected");
                Reject(()=>j.RecordSourceActivationWrite(id,receipt with{AttemptedMonotonic=sample.SampledMonotonic-1}),"attempt preceding prewrite sample rejected");
                Reject(()=>j.RecordSourceActivationWrite(id,receipt with{MonotonicFrequency=receipt.MonotonicFrequency+1}),"foreign monotonic clock frequency rejected");
                Check(j.ReadSourceActivation(id)!.Write==null,"invalid digest/order never persists write authority");
            }
            var ready=LinuxControlledLoaderProtocol.ParseReady(j.ReadSourceControl(id)!.Ready);
            var ack=JsonSerializer.SerializeToUtf8Bytes(new{controlledActivated=true,controlVersion=1,sessionId=id,providerEpoch=ready.Epoch,activationNonce=ready.Nonce,attachedProgramIds=ready.Programs.Skip(1).Take(3).Concat(new[]{ready.Programs[0],ready.Programs[4]}).ToArray(),observeAttached=true,denialAttached=true,lostAtActivation=ready.Lost});
            j.RecordSourceControlActivated(id,ack);var work=s.Issue();
            Reject(()=>s.Claim(work),"ACK alone cannot authorize native work: "+mode);
            Check(!j.HasWork(work.EventId)&&j.ReadNativePin(work.EventId)==null,"unconfirmed pipe return creates no partial pin: "+mode);
            receipt=mode switch
            {
                "short-write"=>receipt with{Written=receipt.Requested-1},
                "failed-write"=>receipt with{Written=-1,WriteError=32},
                "failed-eof"=>receipt with{CloseResult=-1,CloseError=5},
                "managed-eof"=>receipt with{CloseResult=null,CloseError=null,CloseFailure="OwnedManagedCloseFailure"},
                "utc-clock-step"=>receipt with{ReturnedUtc=receipt.AttemptedUtc.AddHours(-1)},
                _=>receipt
            };
            if(mode=="write-commit-failure")
            {
                Sql(s.Root,"CREATE TRIGGER owned_activation_write_fail BEFORE UPDATE ON source_activation BEGIN SELECT RAISE(FAIL,'owned activation receipt failure'); END;");
                Reject(()=>j.RecordSourceActivationWrite(id,receipt),"receipt transaction failure remains explicit");
                Check(!j.SourceActivationWriteConfirmed(id),"failed receipt commit grants no native authority");
                Sql(s.Root,"DROP TRIGGER owned_activation_write_fail;");
            }
            if(mode=="write-postcommit-failure")
            {
                try{j.RecordSourceActivationWrite(id,receipt,point=>{if(point=="activation-write-committed")throw new IOException("Owned interrupted postcommit observation");});throw new Exception("Postcommit injection ignored");}catch(IOException){Check(j.ReadSourceActivation(id)!.Write==receipt,"actual committed receipt survives interrupted return observation");}
            }
            if(mode=="racing-receipt")
            {
                var other=receipt with{ReturnedUtc=receipt.ReturnedUtc.AddTicks(7)};
                Reject(()=>j.RecordSourceActivationWrite(id,receipt,point=>
                {
                    if(point=="activation-write-before-transaction")Sql(s.Root,"UPDATE source_activation SET write_receipt=X'"+Convert.ToHexString(JsonSerializer.SerializeToUtf8Bytes(other))+"';");
                }),"transaction boundary cannot replace a concurrently committed different receipt");
                Check(j.ReadSourceActivation(id)!.Write==other,"competing immutable receipt survives conditional write");receipt=other;
            }
            j.RecordSourceActivationWrite(id,receipt);j.RecordSourceActivationWrite(id,receipt);
            Check(j.ReadSourceActivation(id)!.Write==receipt,"write and EOF return retain exact original facts: "+mode);
            var health=j.ReadSourceHealthControl(id);
            Check(health.Control!.Ready.AsSpan().SequenceEqual(j.ReadSourceControl(id)!.Ready)&&health.ActivationWriteConfirmed==j.SourceActivationWriteConfirmed(id),"fresh single-connection health decision matches existing validators: "+mode);
            if(mode=="normal")
            {
                var invalid=receipt with{CommandSha256=new string('0',64)};
                Sql(s.Root,"UPDATE source_activation SET write_receipt=X'"+Convert.ToHexString(JsonSerializer.SerializeToUtf8Bytes(invalid))+"';");
                Reject(()=>j.ReadSourceHealthControl(id),"health read rejects receipt changed after prior accepted sample");
                Sql(s.Root,"UPDATE source_activation SET write_receipt=X'"+Convert.ToHexString(JsonSerializer.SerializeToUtf8Bytes(receipt))+"';");
                Check(j.ReadSourceHealthControl(id).ActivationWriteConfirmed,"restored exact durable receipt is freshly revalidated");
                var original=j.ReadSourceControl(id)!.Ready;
                Sql(s.Root,"UPDATE source_control SET ready=X'00';");
                Reject(()=>j.ReadSourceHealthControl(id),"health read rejects corrupt ready frame after prior accepted sample");
                Sql(s.Root,"UPDATE source_control SET ready=X'"+Convert.ToHexString(original)+"';");
                Check(j.ReadSourceHealthControl(id).ActivationWriteConfirmed,"restored exact ready frame is freshly revalidated");
            }
            Reject(()=>j.RecordSourceActivationWrite(id,receipt with{ReturnedUtc=receipt.ReturnedUtc.AddTicks(1)}),"receipt retry cannot regenerate timestamp: "+mode);
            if(mode is "short-write" or "failed-write" or "failed-eof" or "managed-eof")
            {
                Check(!j.SourceActivationWriteConfirmed(id),"incomplete activation return never grants native authority: "+mode);
                Reject(()=>s.Claim(work),"failed write/EOF denies native pin despite valid ACK: "+mode);s.Barrier.Return(work);
            }
            else
            {
                Check(j.SourceActivationWriteConfirmed(id),"full original write and EOF confirmed: "+mode);var claim=s.Claim(work);j.AbortNativePinBeforeStart(claim);
                Check(j.ReadNativePin(work.EventId)!.Start==null,"accepted fixture authority never pretends native execution: "+mode);
            }
        }
        foreach(var cut in new[]{"activation-migration-before-commit","activation-migration-after-commit"})
        {
            var directory=Path.Combine(root,cut);using(var initial=new LinuxForensicJournal(directory,sensor)){}
            Sql(directory,"DROP TABLE source_owner_returns; DROP TABLE source_activation; PRAGMA user_version=10;");
            var start=new ProcessStartInfo(Environment.ProcessPath!){UseShellExecute=false,RedirectStandardOutput=true,RedirectStandardError=true};
            if(Path.GetFileNameWithoutExtension(Environment.ProcessPath)=="dotnet")start.ArgumentList.Add(typeof(SourceActivationChecks).Assembly.Location);
            foreach(var arg in new[]{"migration-child",seedPath,directory,cut})start.ArgumentList.Add(arg);
            using var child=Process.Start(start)!;var stdout=child.StandardOutput.ReadToEndAsync();var stderr=child.StandardError.ReadToEndAsync();await FixtureProcessTiming.Wait(child);
            Check(child.ExitCode==73,"actual migration process exit: "+cut+" "+await stdout+await stderr);
            Check((long)Sql(directory,"PRAGMA user_version;")! ==(cut.EndsWith("before-commit",StringComparison.Ordinal)?10:11),"activation migration is atomic: "+cut);
            using var upgraded=new LinuxForensicJournal(directory,sensor);
            Check((long)Sql(directory,"SELECT count(*) FROM source_activation;")! ==0,"upgrade creates no fabricated activation receipts: "+cut);
        }
        var result=new{Passed=true,Checks=checks,Schema=12,Cases=17,Scope="Durable activation continuity/write/EOF evidence and native admission, injected pipe/map facts; actual migration process exits; no native source activation"};File.WriteAllText(Path.Combine(root,"RESULTS.json"),JsonSerializer.Serialize(result));Console.WriteLine(JsonSerializer.Serialize(result));
    }
    private static object? Sql(string root,string sql)
    {using var c=new SqliteConnection(new SqliteConnectionStringBuilder{DataSource=Path.Combine(root,"linux-forensic-intake/journal.db"),Pooling=false}.ToString());c.Open();using var q=c.CreateCommand();q.CommandText=sql;return q.ExecuteScalar();}
}
