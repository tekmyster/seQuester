using System.Collections.Concurrent;
using System.Text.Json;
using System.Threading.Channels;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using RansomFree;
using RansomFree.Client;
using RansomFree.Client.Forensics;
using RansomFree.Contracts;

namespace RansomFree.LinuxAgent;

internal sealed record PublicStatus(string Path);
internal sealed class LinuxWorker(PrivateState state,ClientConfiguration config,PublicStatus publicStatus,ILogger<LinuxWorker> log):BackgroundService
{
    private sealed record JournalEntry(string Digest,ResponseReceipt Receipt,bool Acknowledged=false,DateTimeOffset RecordedUtc=default);
    private readonly Channel<Observation> observations=Channel.CreateBounded<Observation>(new BoundedChannelOptions(4096){SingleReader=true,FullMode=BoundedChannelFullMode.Wait});
    private readonly Dictionary<string,(Alert Alert,ProcessEvidence Process)> evidence=[];
    private readonly Queue<Alert> recent=[];
    private readonly Queue<DateTimeOffset> stops=[];
    private long lost;
    private string health="Starting";
    private string connectivity="Not connected";
    private DateTimeOffset? lastSync;
    private string? lastMonitorWarning;
    private DateTimeOffset? lastMonitorWarningUtc;
    protected override async Task ExecuteAsync(CancellationToken ct)
    {
        var connection=state.Read<Connection>("connection.json")??throw new InvalidOperationException("Endpoint enrollment required before monitoring.");
        if(new Uri(connection.Server)!=new Uri(config.Server))throw new InvalidDataException("Configuration and enrollment server differ; credentials preserved.");
        using var management=new ManagementClient(connection.Server,connection.Credential);
        using var spool=new EventSpool(state.Directory,connection.EndpointId,retainJournalLifetime:OperatingSystem.IsLinux());
        if(spool.RecoveredIncompleteActorEvents>0)
        {
            lastMonitorWarning=$"Recovered {spool.RecoveredIncompleteActorEvents} historical local events with incomplete actor attribution for delivery";
            lastMonitorWarningUtc=DateTimeOffset.UtcNow;
        }
        var cache=new PolicyCache(state.Directory,connection.EndpointId);cache.Load();spool.Configure(cache.Current.Settings.EventQueue);
        var trustCache=new TrustPolicyCache(state.Directory,connection.EndpointId,connection.Server);
        try{trustCache.Load();}catch(Exception ex){log.LogWarning("Trust cache unavailable ({Type}); alerts retained and automatic response paused.",ex.GetType().Name);}
        var journal=state.Read<Dictionary<string,JournalEntry>>("responses.json")??[];
        var deployment=new Deployments(state,config);deployment.ValidateInventory();
        SyslogOptions Options()
        {
            var s=cache.Current.Settings.Syslog;
            return s==null?config.Syslog:new(){Enabled=s.Enabled,Host=s.Host,Port=s.Port,Transport=s.Transport,Format=s.Format,Facility=s.Facility,Severity=s.Severity,OctetCounting=s.OctetCounting};
        }
        using var syslog=new UnixSyslogOutbox(state,Options().Enabled);
        await using var forensics=new ForensicPipeline(connection.EndpointId,state.Directory,message=>{health=message;log.LogError("{Health}",message);});
        await using var uploads=new EvidenceUploadWorker(management,state.Directory,message=>{health=message;log.LogError("{Health}",message);});
        await using var nativeCompanion=new LinuxNativeCompanionClient(config.NativeCompanion,connection.EndpointId,connection.Server,state.Directory,spool,management,
            message=>log.LogWarning("{NativeCompanionHealth}",message));
        bool Record(Observation observation)
        {
            ProcessEvidence? process=null;
#if MACOS
            if(observation.AuditToken!=null){try{process=new(observation);}catch{ /* Keep ES attribution, but do not invent actionable evidence. */ }}
#else
            if(observation.PidFd>=0)
            {
                try{process=new(observation.PidFd,observation.Pid??0,observation.ObservedUtc,config.Audit.CaptureCommandLine);}
                catch{Native.close(observation.PidFd);}
            }
#endif
            var executable=process?.Executable??observation.Executable??"Unavailable";
            // Keep the wire contract bounded so one long executable name cannot
            // poison a FIFO batch. Local response checks retain the full identity.
            if(executable.Length>1024)executable=executable[..1000]+" [truncated]";
            var attribution=observation.Attribution;
#if !MACOS
            attribution??=process?.Attribution;
#endif
            attribution??=new(){Provider=observation.Source,Level=observation.Pid!=null?"Partial attribution":"Detection only",Basis="No complete process/user evidence from this source."};
            var alert=new Alert(observation.ObservedUtc,observation.Operation,observation.Path,executable,process?.User??observation.User??"Unavailable",observation.Source)
            {EventId=observation.EventId??Guid.NewGuid().ToString("N"),ProcessId=observation.Pid,Allowlisted=process?.Allowed(cache.Current.Settings.Allowlist,observation.Path)??false,Attribution=attribution};
            if(!LocalActorEvidence.IsComplete(alert.Source,alert.User,alert.Process,alert.ProcessId))
            {
                lastMonitorWarning="Local file signal recorded with incomplete actor attribution; review sensor health and evidence source.";
                lastMonitorWarningUtc=DateTimeOffset.UtcNow;
                log.LogWarning("Local file signal retained with incomplete actor attribution ({Source}, {Operation}).",alert.Source,alert.Operation);
            }
            var wire=new AgentEvent(alert.EventId,new DateTimeOffset(alert.Time),alert.Operation,alert.Path,alert.User,alert.Process,alert.ProcessId,alert.Source){Attribution=attribution};
            if(observation.Forensics is {} responseEvidence){alert=alert with{Forensics=forensics.LinkResponse(responseEvidence,alert.EventId,new DateTimeOffset(alert.Time))};wire=wire with{Forensics=alert.Forensics};}
#if MACOS
            var actor=new TrustActor(); // ES account/hash adapter must supply reviewed event-time evidence before exceptions can match.
            const string trustOs="macos";
#else
            var actor=TrustEventEvaluation.LinuxActor(connection.EndpointId,wire);
            const string trustOs="linux";
#endif
            var trust=TrustEventEvaluation.Evaluate(trustCache,connection.EndpointId,cache.Current.GroupId,trustOs,wire,actor,DateTimeOffset.UtcNow);
            alert=alert with{Trust=trust,Allowlisted=trust.Result.Mode=="legacy"&&alert.Allowlisted,PolicySyslogSeverity=trust.Result.Decision.Severity=="informational"?6:null};wire=wire with{Trust=trust};
            if(process!=null)evidence[alert.EventId]=(alert,process);
            recent.Enqueue(alert);while(recent.Count>100){var old=recent.Dequeue();if(evidence.Remove(old.EventId,out var retired))retired.Process.Dispose();}
            try
            {
                if(LocalActorEvidence.IsRequired(wire.Source))forensics.Submit(wire,cache.Current.Settings.Forensics??new(),pending=>{spool.Enqueue(pending);alert=alert with{Forensics=pending.Forensics};},completed=>
                {
                    spool.Enqueue(completed);
                    if(completed.Forensics?.Detection.Disposition!="log-only")syslog.Enqueue(new Alert(completed.ObservedUtc.UtcDateTime,completed.Operation,completed.Path,completed.Process??"Unavailable",completed.User??"Unavailable",completed.Source){EventId=completed.EventId,ProcessId=completed.ProcessId,Attribution=completed.Attribution,Forensics=completed.Forensics,PolicySyslogSeverity=6},Options());
                });
                else spool.Enqueue(wire);
            }
            catch(Exception ex){health="Management queue failed: "+ex.GetType().Name;log.LogError("{Health}; new evidence may be unqueued.",health);return false;}
            try{syslog.Enqueue(alert,Options());}catch(Exception ex){health="Syslog queue failed: "+ex.GetType().Name;}
            log.LogWarning("Canary event {EventId}: {Operation}; source {Source}",alert.EventId,alert.Operation,alert.Source);
            if(observation.Source==Platform.Name+" monitor health")
            {
                lastMonitorWarning=observation.Operation;lastMonitorWarningUtc=observation.ObservedUtc;
                // Audit continuity events remain in the durable event stream,
                // not latched forever as the current collector health.
                if(observation.Path!="Audit sensor")health=observation.Operation;
            }
            var auto=cache.Current.Settings.AutomaticResponse;
            if(auto.Enabled&&config.AllowAutomaticProcessStop&&process!=null&&!alert.Allowlisted&&!trust.Result.Decision.SuppressResponse&&Platform.AutomaticTrigger(auto,alert.Operation))
            {
                var now=DateTimeOffset.UtcNow;
                while(stops.TryPeek(out var time)&&time<now.AddMinutes(-1))stops.Dequeue();
                if(stops.Count<auto.MaxStopsPerMinute)
                {
                    stops.Enqueue(now);var command=new ResponseCommand(Guid.NewGuid().ToString("N"),alert.EventId,"end-process","Automatic policy","Locally enabled automatic policy",now,now.AddMinutes(1));
                    try{var result=Execute(command,true);Record(new Observation(alert.Path,"Automatic process response: "+result.Outcome+"; "+result.Message,Platform.Name+" response",Pid:alert.ProcessId,Executable:alert.Process,User:alert.User){Forensics=alert.Forensics is {} forensic?forensic with{Response=new("end-process",result.Outcome,alert.EventId)}:null});}catch(Exception ex){health="Automatic response unavailable: "+ex.GetType().Name;}
                }
            }
            return true;
        }
        ResponseReceipt Execute(ResponseCommand command,bool automatic=false)
        {
            if(!Guid.TryParseExact(command.Id,"N",out _)||!Guid.TryParseExact(command.EventId,"N",out _)||command.Action!="end-process")throw new InvalidDataException("Invalid response command.");
            var digest=PrivateState.Hash(JsonSerializer.SerializeToUtf8Bytes(command));
            if(journal.TryGetValue(command.Id,out var prior)){if(prior.Digest!=digest)throw new InvalidDataException("Response identity conflict.");return prior.Receipt;}
            // Only acknowledged, dated receipts older than 30 days can age out.
            // Old commands are already expired and cannot be signalled again.
            var expired=journal.Where(x=>x.Value.Acknowledged&&x.Value.RecordedUtc!=default&&x.Value.RecordedUtc<DateTimeOffset.UtcNow.AddDays(-30)).Select(x=>x.Key).ToArray();
            if(expired.Length>0){foreach(var id in expired)journal.Remove(id);state.Save("responses.json",journal);}
            if(journal.Count>=2000)throw new InvalidDataException("Response journal full; no action performed.");
            ResponseReceipt Save(string outcome,string message){var result=new ResponseReceipt(command.Id,outcome,message);journal[command.Id]=new(digest,result,automatic,DateTimeOffset.UtcNow);state.Save("responses.json",journal);return result;}
            var now=DateTimeOffset.UtcNow;
            if(command.Target!=null)return Save("Rejected","Native process response is not qualified on this platform; no signal was sent.");
            if(!(automatic?config.AllowAutomaticProcessStop:config.AllowRemoteProcessStop)||command.ExpiresUtc<=now||command.CreatedUtc>now.AddMinutes(1)||command.ExpiresUtc<=command.CreatedUtc||command.ExpiresUtc-command.CreatedUtc>TimeSpan.FromMinutes(2))return Save("Rejected","Local approval missing or command time bounds invalid.");
            if(!evidence.TryGetValue(command.EventId,out var target))return Save("Rejected","Fresh local native process identity unavailable.");
            if(automatic&&target.Alert.Trust?.Result.Decision.SuppressResponse==true)return Save("Rejected","Automatic response restricted by trust policy.");
            if(automatic&&target.Alert.Trust is {} recorded)
            {
                var a=target.Alert;var original=new AgentEvent(a.EventId,new DateTimeOffset(a.Time),a.Operation,a.Path,a.User,a.Process,a.ProcessId,a.Source){Attribution=a.Attribution};
                if(TrustEventEvaluation.Evaluate(trustCache,connection.EndpointId,cache.Current.GroupId,recorded.OperatingSystem,original,recorded.Actor,now).Result.Decision.SuppressResponse)return Save("Rejected","Trust policy changed or needs refresh; no automatic action.");
            }
            if(target.Alert.Trust?.Result.Mode=="legacy"&&target.Process.Allowed(cache.Current.Settings.Allowlist,target.Alert.Path))return Save("Rejected","Process allowlisted by legacy policy.");
            Save("Indeterminate","Intent persisted; process outcome not yet confirmed. Never automatically replay uncertain execution.");
            try{var outcome=target.Process.Stop();return Save(outcome.Outcome,outcome.Message);}catch(Exception ex){return Save("Indeterminate","No confirmed process exit: "+ex.GetType().Name);}
        }
        foreach(var finding in deployment.CheckStartup())Record(new(finding.Path,finding.Operation,Platform.Name+" startup integrity"));
        using var monitors=new LinuxMonitors(config.Monitor,item=>{if(!observations.Writer.TryWrite(item)){Interlocked.Increment(ref lost);if(item.PidFd>=0)Native.close(item.PidFd);}});
#if !MACOS
        var audit=new AuditInbox(state,config.Audit.Enabled);
#endif
        string SensorStatus()=>
#if MACOS
            monitors.Mode;
#else
            monitors.Mode+" | "+audit.Status;
#endif
        try
        {
            deployment.Apply(cache.Current.Settings);monitors.Update(deployment.Items);health=deployment.Items.Count==0?"No canaries configured":"Canary monitoring configured";
            var policyDue=DateTimeOffset.MinValue;var deliveryDue=DateTimeOffset.MinValue;var statusDue=DateTimeOffset.MinValue;var integrityDue=DateTimeOffset.MinValue;
            while(!ct.IsCancellationRequested)
            {
                for(var count=0;count<256&&observations.Reader.TryRead(out var item);count++)Record(item);
                var missing=Interlocked.Exchange(ref lost,0);if(missing>0)Record(new("Agent monitor",$"Client event channel overflow: {missing} events not captured",Platform.Name+" monitor health"));
                var now=DateTimeOffset.UtcNow;
                if(now>=deliveryDue)
                {
                    deliveryDue=now.AddSeconds(15);
                    try
                    {
#if MACOS
                        var summary=health+" | "+SensorStatus();
                        var heartbeat=new HeartbeatRequest(Platform.Version,summary.Length>512?summary[..512]:summary);
#else
                        var summary=EndpointHealthSummary.Format(health,monitors.IsRunning,audit.Status,audit.LastVerifiedUtc);
                        var inventory=deployment.ProtectionEvidence;
                        summary+=" | "+(inventory is null?"Bait file metadata verification unknown":!inventory.Complete?"Bait file metadata verification incomplete; deployed count not reported":$"Bait file metadata last verified {inventory.VerifiedUtc:yyyy-MM-ddTHH:mm:ssZ}");
                        var protection=LinuxProtectionStatus.Build(inventory is {Complete:true}?inventory.DeployedItems:null,deployment.Items.Count(x=>x.Active),inventory?.IntegrityHealthy,monitors.IsRunning,health,audit.Status);
                        var heartbeat=new HeartbeatRequest(Platform.Version,summary.Length>512?summary[..512]:summary){Protection=protection};
#endif
                        if(trustCache.Warning(cache.Current.GroupId,now) is {} trustWarning)summary+=" | "+trustWarning;
                        heartbeat=heartbeat with{Health=summary.Length>512?summary[..512]:summary};
                        await management.HeartbeatAsync(heartbeat,ct);
                        for(var batch=0;batch<10;batch++){var pending=spool.Peek();if(pending.Events.Length==0)break;spool.Acknowledge(pending,await management.SendEventsAsync(pending,ct));}
                        foreach(var entry in journal.Values.Where(x=>!x.Acknowledged).Take(10).ToArray())
                        {await management.SendResponseReceiptAsync(entry.Receipt,ct);journal[entry.Receipt.Id]=entry with{Acknowledged=true};state.Save("responses.json",journal);}
                        var commands=await management.PollResponsesAsync(ct);if(commands.Length>100)throw new InvalidDataException("Response batch exceeds limit.");
                        foreach(var command in commands){var result=Execute(command);await management.SendResponseReceiptAsync(result,ct);journal[command.Id]=journal[command.Id] with{Acknowledged=true};state.Save("responses.json",journal);}
                        connectivity="Connected";lastSync=DateTimeOffset.UtcNow;
                    }
                    catch(OperationCanceledException) when(ct.IsCancellationRequested){break;}
                    catch(Exception ex){connectivity="Offline / sync failed: "+ex.GetType().Name;log.LogWarning("Management sync failed ({Type}); pending queue/receipts retained.",ex.GetType().Name);}
                }
                if(now>=policyDue)
                {
                    policyDue=now.AddSeconds(60);
                    try
                    {
                        var policy=await management.GetPolicyAsync(ct);deployment.ValidatePolicy(policy.Settings);
                        if(policy.GroupId==cache.Current.GroupId&&(policy.Revision<cache.Current.Revision||policy.Revision==cache.Current.Revision&&!policy.Settings.SameContent(cache.Current.Settings)))throw new InvalidDataException("Policy revision conflict; not deployed.");
                        deployment.Apply(policy.Settings);monitors.Update(deployment.Items);
#if MACOS
                        monitors.RequireRequestedCoverage();
#endif
                        cache.Save(policy);spool.Configure(policy.Settings.EventQueue);syslog.SetEnabled(Options().Enabled);
                        await management.AcknowledgePolicyAsync(policy,ct);
                        var assignedTrust=await management.GetTrustPolicyAsync(ct,linuxKernelTrustSourceActive:nativeCompanion.KernelHashReadyAtRecentSample,linuxNativeHashSourceActive:nativeCompanion.NativeHashReadyAtRecentSample);trustCache.Save(assignedTrust,DateTimeOffset.UtcNow);
                        await management.AcknowledgeTrustPolicyAsync(assignedTrust,ct);
                        health=deployment.Items.Count==0?"No canaries configured":"Canary monitoring configured";
                    }
                    catch(OperationCanceledException) when(ct.IsCancellationRequested){break;}
                    catch(Exception ex){health="Policy pending: "+ex.GetType().Name;log.LogWarning("{Health}; existing files preserved and no success receipt sent.",health);}
                }
                if(now>=integrityDue)
                {
                    integrityDue=now.AddSeconds(cache.Current.Settings.IntegrityIntervalSeconds);
                    foreach(var finding in deployment.CheckMetadata())Record(new(finding.Path,finding.Operation,Platform.Name+" periodic metadata"));
                }
                if(now>=statusDue)
                {
                    statusDue=now.AddSeconds(5);
#if !MACOS
                    audit.Poll(deployment.Items,Record);
#endif
                    try
                    {
                        monitors.Update(deployment.Items);
                        var target=Paths.NoLinks(publicStatus.Path);var temp=target+"."+Guid.NewGuid().ToString("N")+".tmp";
                        // Public here means the explicitly approved rfclient-ui group, not all users.
                        using(var output=new FileStream(Paths.NoLinks(temp),new FileStreamOptions{Mode=FileMode.CreateNew,Access=FileAccess.Write,Share=FileShare.None,UnixCreateMode=UnixFileMode.UserRead|UnixFileMode.UserWrite|UnixFileMode.GroupRead}))
                        {JsonSerializer.Serialize(output,new{Version=Platform.Version,UpdatedUtc=DateTimeOffset.UtcNow,Health=health+(trustCache.Warning(cache.Current.GroupId,now) is {} warning?" | "+warning:""),LastMonitorWarning=lastMonitorWarning,LastMonitorWarningUtc=lastMonitorWarningUtc,Connectivity=connectivity,LastSyncUtc=lastSync,Monitor=SensorStatus(),NativeCompanion=nativeCompanion.Current,Canaries=deployment.Items.Count,PolicyRevision=cache.Current.Revision,Queue=spool.Status,PendingSyslog=syslog.Count,SyslogStatus=syslog.LastStatus,Events=recent.Reverse().ToArray()});output.Flush(true);}
                        File.SetUnixFileMode(temp,UnixFileMode.UserRead|UnixFileMode.UserWrite|UnixFileMode.GroupRead);
                        File.Move(temp,target,true);
                    }
                    catch(Exception ex){log.LogWarning("Status/monitor refresh unavailable ({Type}).",ex.GetType().Name);}
                }
                await Task.Delay(100,ct);
            }
        }
        finally{monitors.Dispose();foreach(var item in evidence.Values)item.Process.Dispose();while(observations.Reader.TryRead(out var pending))if(pending.PidFd>=0)Native.close(pending.PidFd);}
    }
}
