using System.Globalization;
using System.Security.Cryptography;
using System.Text.Json;
using Microsoft.Data.Sqlite;
using RansomFree.Client;
using RansomFree.Client.Forensics;
using RansomFree.Contracts;

// Actual child exit at finite qualification checkpoints, not a simulated
// HasExited result or a signal sent to a numeric PID.
internal static class OwnedRuntimeV2StartupDeathChecks
{
    internal sealed record Config(string Root,LinuxControlledSourceRuntime.Qualification Runtime,string Point);
    private sealed record Descriptor(int Fd,uint? MapId,string? Target,string FdInfo);
    private static Descriptor[] Descriptors(string pid,HashSet<uint> maps)
    {
        var result=new List<Descriptor>();
        foreach(var path in Directory.EnumerateFiles("/proc/"+pid+"/fdinfo"))
        {
            string raw;
            try{raw=File.ReadAllText(path);}catch(FileNotFoundException){continue;}
            var field=raw.Split('\n').FirstOrDefault(x=>x.StartsWith("map_id:",StringComparison.Ordinal));
            uint? id=field==null?null:uint.Parse(field.Split(':',2)[1].Trim(),CultureInfo.InvariantCulture);
            var fd=int.Parse(Path.GetFileName(path),CultureInfo.InvariantCulture);
            string? target;
            try{target=new FileInfo("/proc/"+pid+"/fd/"+fd).LinkTarget;}catch(FileNotFoundException){continue;}
            if(id.HasValue&&maps.Contains(id.Value)||target=="/dev/sq_actor_lease")result.Add(new(fd,id,target,raw));
        }
        return result.OrderBy(x=>x.Fd).ToArray();
    }
    internal static async Task Run(string configPath)
    {
        var config=JsonSerializer.Deserialize<Config>(File.ReadAllBytes(configPath))!;
        if(!OperatingSystem.IsLinux()||File.ReadAllText("/sys/class/dmi/id/product_uuid").Trim().ToLowerInvariant()!="82082842-9a2e-bd81-8cc0-1b589de10dc2"||
            Directory.EnumerateDirectories("/sys/class/net").Any(p=>Directory.Exists(Path.Combine(p,"device")))||
            Directory.Exists(config.Root)||!config.Root.StartsWith("/var/tmp/sequester-owned-runtime-",StringComparison.Ordinal)||
            Path.GetDirectoryName(config.Runtime.Directory)!=config.Root||config.Runtime.Launch.ControlVersion!=2||
            config.Point is not ("MAP_PROOF_SAVED" or "LOST_MAP_OPENED" or "LINKED_PREWRITE"))
            throw new ArgumentException("Fresh owned zero-NIC Linux v2 qualification root and explicit cut required");
        const string sensor="11111111111111111111111111111111";
        using var journal=new LinuxForensicJournal(config.Root,sensor);
        var spool=new EventSpool(Path.Combine(config.Root,"spool"),sensor);
        await using var pipeline=new ForensicPipeline(sensor,config.Root,Console.Error.WriteLine);
        var checks=new List<string>();void Check(bool value,string label){if(!value)throw new InvalidDataException(label);checks.Add(label);}
        LinuxControlledSourceRuntime.StartupCheckpoint? cut=null;LinuxOwnedLoaderProcess? child=null;
        Descriptor[] before=[];Descriptor[] afterChild=[];var ids=new HashSet<uint>();
        var runtime=LinuxControlledSourceRuntime.StartForQualification(config.Runtime,journal,pipeline,spool,sensor,new(),Console.Error.WriteLine,
            async (point,owned)=>
            {
                if(point.Point!=config.Point)return;
                if(cut!=null)throw new InvalidOperationException("Cut cannot run twice");
                cut=point;child=owned;ids=point.Ready.Maps.Append(point.Ready.WatchMapId!.Value).ToHashSet();
                before=Descriptors("self",ids);
                EvidenceDurability.SaveNew(Path.Combine(config.Root,"checkpoint.json"),JsonSerializer.SerializeToUtf8Bytes(new{
                    Checkpoint=point,ParentDescriptors=before,ChildPid=owned.Pid,ChildDescriptors=Descriptors(owned.Pid.ToString(CultureInfo.InvariantCulture),ids),
                    TargetSetSha256=point.Ready.Targets!.Digest,RecordedUtc=DateTimeOffset.UtcNow}));
                // The retained pidfd identifies the actual owned child. Its
                // completion includes exit and both redirected stream drains.
                await Task.Run(owned.RequestStop);
                await owned.Completion;
                afterChild=Descriptors("self",ids);
                EvidenceDurability.SaveNew(Path.Combine(config.Root,"child-exited.json"),JsonSerializer.SerializeToUtf8Bytes(new{
                    owned.HasExited,Completed=owned.Completion.IsCompletedSuccessfully,owned.ExitCode,owned.ActivationAttempted,owned.ActivationWrite,
                    ParentDescriptors=afterChild,Child=owned.Snapshot(),RecordedUtc=DateTimeOffset.UtcNow}));
            });
        Exception? startupError=null;
        try{await runtime.Started;}catch(Exception ex){startupError=ex;}
        // This cannot be substituted by a timeout or cancellation receipt.
        var outcome=await runtime.Completion;
        var after=Descriptors("self",ids);
        try
        {
            Check(cut!=null&&child!=null,"exact requested checkpoint was reached once");
            Check(startupError!=null&&runtime.Started.IsFaulted,"monitoring activation was rejected");
            var timing=outcome.StartupTimings;
            Check(timing.Length is >0 and <=64&&timing[0].Point=="STARTUP_ENTERED"&&timing.Any(x=>x.Point=="STARTUP_FAILED"),"actual startup failure retains bounded phase observations");
            Check(timing.Select(x=>x.Sequence).SequenceEqual(Enumerable.Range(1,timing.Length))&&timing.All(x=>x.Version==1&&x.RecordedUtc!=default&&x.RecordedMonotonic>0&&x.MonotonicFrequency==System.Diagnostics.Stopwatch.Frequency)&&timing.Zip(timing.Skip(1),(a,b)=>a.RecordedMonotonic<=b.RecordedMonotonic).All(x=>x),"startup diagnostics preserve actual monotonic order without fabricated ready authority");
            Check(!timing.Any(x=>x.Point=="STARTUP_READY"||x.Point=="ACK_INGRESS_COMMITTED"),"failed pre-activation startup has no ready or acknowledged timing observation");
            Check(cut!.Phase=="STARTING"&&!cut.ActivationWriteAttempted&&!child!.ActivationAttempted&&child.ActivationWrite==null,"no activation write or active phase");
            Check(child!.HasExited&&child.Completion.IsCompletedSuccessfully&&outcome.Child!.State=="DISPOSED","owned child exit, both drains and disposal completed");
            Check(before.Count(x=>x.MapId!=null)==(config.Point=="MAP_PROOF_SAVED"?5:6)&&ids.All(id=>before.Any(x=>x.MapId==id)),"all actual parent map descriptors counted including separate lost sampler");
            Check(before.Where(x=>x.MapId!=null).All(x=>(Convert.ToInt32(x.FdInfo.Split('\n').Single(s=>s.StartsWith("flags:")).Split(':',2)[1].Trim(),8)&3)==0),"every parent map descriptor is read-only");
            Check(afterChild.Select(x=>(x.Fd,x.MapId,x.Target)).SequenceEqual(before.Select(x=>(x.Fd,x.MapId,x.Target))),"child exit did not prematurely close parent maps or controller");
            Check(after.Length==0,"all parent maps and actor controller closed after owned teardown");
            Check(outcome.State=="COMPLETED"&&outcome.PendingDelivery==0&&outcome.CanonicalBacklogPresent==false,"startup failure released ownership without pending work");
            Check(outcome.Errors.All(x=>x.StartsWith("OWNED_SOURCE_STARTUP_FAILED:",StringComparison.Ordinal)),"no map, controller, receipt or child cleanup failure");
            Check(journal.Pending().Length==0&&spool.Count==0,"no actor observations or forensic completions invented");
            using var db=new SqliteConnection(new SqliteConnectionStringBuilder{DataSource=Path.Combine(config.Root,"linux-forensic-intake/journal.db"),Mode=SqliteOpenMode.ReadOnly,Pooling=false}.ToString());db.Open();
            long Count(string table){using var q=db.CreateCommand();q.CommandText="SELECT count(*) FROM "+table;return Convert.ToInt64(q.ExecuteScalar());}
            foreach(var table in new[]{"work","native_pins","native_progress","canonical_events"})Check(Count(table)==0,table+" contains no activation or actor work");
            var linked=config.Point=="LINKED_PREWRITE";
            Check(cut.ControllerOpened==linked&&before.Count(x=>x.Target=="/dev/sq_actor_lease")== (linked?1:0),"actual controller descriptor matches recorded startup stage");
            Check(Count("source_lifecycle")== (linked?1:0)&&Count("source_control")== (linked?1:0)&&Count("source_owner_returns")== (linked?2:0),"only actual source and controller method receipts exist");
            if(linked)
            {
                Check(outcome.Startup=="FAILED_AFTER_LINK"&&outcome.Close=="CLOSE_RETURNED_OK"&&outcome.RawRecoveryState=="COMPLETE","linked failure used actual close and stopped-input recovery");
                var control=journal.ReadSourceControl(cut.Session!)!;
                Check(control.WriteStartedUtc==null&&control.Activated==null&&journal.ReadSourceActivation(cut.Session!)?.Write==null,"durable control has no write or activation acknowledgement");
                if(control.Completion!=null)
                {
                    var completion=LinuxControlledLoaderProtocol.ParseCompletion(control.Completion,2);
                    Check(!completion.Activated&&!completion.ObserverAttempted,"actual loader completion did not attach observer");
                }
                // Preserve the sidecar but remove its well-known name. Recovery
                // must derive target association from exact durable ready bytes.
                var proof=Path.Combine(config.Runtime.Directory,"source-map-proof.json");File.Move(proof,proof+".diagnostic-only");
                var ready=LinuxControlledLoaderProtocol.ParseReady(control.Ready);
                Check(Convert.ToHexString(SHA256.HashData(control.Ready))==cut.ReadyFrameSha256&&ready.Targets!.Digest==LinuxControlledSourceRuntime.ValidatePreparedTargets(config.Runtime)!.Digest,"journal raw ready independently reconstructs exact target digest");
                journal.RecoverStoppedRaw(cut.Session!);
                Check(await journal.DeliverStoppedRaw(cut.Session!,pipeline,spool)&&spool.Count==0,"stopped recovery requires no sidecar or native reactivation");
                var replayed=journal.ReadSourceControl(cut.Session!)!;
                Check(replayed.Ready.AsSpan().SequenceEqual(control.Ready)&&replayed.WriteStartedUtc==null&&replayed.Activated==null&&Descriptors("self",ids).Length==0,"recovery preserved exact control evidence and opened no native handles");
            }
            else Check(outcome.Startup=="FAILED_NO_CONTROLLER"&&outcome.Session==null&&outcome.Close=="NOT_ATTEMPTED"&&outcome.RawRecoveryState=="NOT_APPLICABLE","pre-controller failure invents no session or close receipt");
            journal.AdmitOwnedRuntime();journal.ReleaseOwnedRuntime(null);
            Check(true,"new owner admission allowed only after completed teardown");
            var result=new{Passed=true,Point=config.Point,Checks=checks,Outcome=outcome,ParentDescriptorsAfter=after,StartupError=startupError!.GetType().Name,
                FinalCounter=outcome.Session==null?null:journal.ReadSourceControl(outcome.Session)?.Completion is {} raw?LinuxControlledLoaderProtocol.ParseCompletion(raw,2).Lost:(ulong?)null,
                Scope="Finite controlled-v2 preactivation child-death qualification, not installed monitoring or operation coverage"};
            EvidenceDurability.SaveNew(Path.Combine(config.Root,"QUALIFICATION.json"),JsonSerializer.SerializeToUtf8Bytes(result));
            Console.WriteLine(JsonSerializer.Serialize(result));
        }
        catch(Exception ex)
        {
            EvidenceDurability.SaveNew(Path.Combine(config.Root,"QUALIFICATION-FAILURE.json"),JsonSerializer.SerializeToUtf8Bytes(new{Passed=false,Error=ex.ToString(),Checks=checks,Outcome=outcome,ParentDescriptorsAfter=after}));throw;
        }
    }
}
