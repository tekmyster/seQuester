using System.Security.AccessControl;
using System.Security.Cryptography;
using System.Security.Principal;
using System.Text;
using System.Text.Json;
using System.Reflection;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using RansomFree;
using RansomFree.Client;
using RansomFree.Client.Forensics;
using RansomFree.Contracts;

if(args.Contains("--version")){Console.WriteLine(AgentBuild.Version);return;}
var console=args.Contains("--console");
// Diagnostics are read-only and must not provision folders, ACLs, credentials, or monitoring.
if(args.Contains("--diagnose"))
{
    var position=Array.IndexOf(args,"--server");
    if(position<0 || position+1>=args.Length)throw new ArgumentException("Specify --diagnose --server https://server.example.");
    using var diagnosticClient=new ManagementClient(args[position+1]);
    var diagnostic=await diagnosticClient.DiagnoseAsync();
    Console.WriteLine(JsonSerializer.Serialize(diagnostic));Environment.ExitCode=diagnostic.Reachable?0:2;return;
}
var directory=Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),"RansomFree","Agent");
if(console && Array.IndexOf(args,"--data") is var index && index>=0 && index+1<args.Length)directory=Path.GetFullPath(args[index+1]);
for(string? ancestor=directory;ancestor!=null;ancestor=Path.GetDirectoryName(ancestor))
    if(Directory.Exists(ancestor) && (File.GetAttributes(ancestor)&FileAttributes.ReparsePoint)!=0)throw new IOException("Agent data path must not traverse a link or junction.");
Directory.CreateDirectory(directory);
// Production directory is readable/writable only by SYSTEM and local administrators.
if(!console)
{
    var security=new DirectorySecurity();security.SetAccessRuleProtection(true,false);
    foreach(var sid in new[]{WellKnownSidType.LocalSystemSid,WellKnownSidType.BuiltinAdministratorsSid})
        security.AddAccessRule(new FileSystemAccessRule(new SecurityIdentifier(sid,null),FileSystemRights.FullControl,InheritanceFlags.ContainerInherit|InheritanceFlags.ObjectInherit,PropagationFlags.None,AccessControlType.Allow));
    new DirectoryInfo(directory).SetAccessControl(security);
}
if(args.Contains("--set-admin-password") || args.Contains("--verify-maintenance") || args.Contains("--set-decoy-session-policy"))
{
    string ReadSecret(string prompt)
    {
        Console.WriteLine(prompt);if(Console.IsInputRedirected)return Console.ReadLine()??"";
        var value=new StringBuilder();while(true){var key=Console.ReadKey(true);if(key.Key==ConsoleKey.Enter)break;if(key.Key==ConsoleKey.Backspace){if(value.Length>0)value.Length--;continue;}if(!char.IsControl(key.KeyChar)&&value.Length<256)value.Append(key.KeyChar);}return value.ToString();
    }
    if(args.Contains("--set-admin-password") || args.Contains("--set-decoy-session-policy"))
    {
        try{using var service=new System.ServiceProcess.ServiceController("RansomFreeAgent");if(service.Status!=System.ServiceProcess.ServiceControllerStatus.Stopped)throw new InvalidOperationException("Stop the installed service through an authorized maintenance procedure before changing its password.");}
        catch(InvalidOperationException ex) when(ex.InnerException is System.ComponentModel.Win32Exception native && native.NativeErrorCode==1060){}
    }
    using var settings=new CanaryMonitor(directory);var old=ReadSecret("Agent administration password (blank only for first provisioning):");
    if(settings.Settings.Password==null && (args.Contains("--verify-maintenance")||args.Contains("--set-decoy-session-policy")) || settings.Settings.Password!=null && !PasswordHash.Verify(old,settings.Settings.Password))
    {Console.WriteLine("Administration verification failed.");Environment.ExitCode=3;return;}
    if(args.Contains("--set-admin-password")){var next=ReadSecret("New administration password (12–256 characters):");settings.Settings.Password=PasswordHash.Create(next);settings.Save();Console.WriteLine("Administration password saved. No service was started.");}
    else if(args.Contains("--set-decoy-session-policy"))
    {
        var policyIndex=Array.IndexOf(args,"--set-decoy-session-policy");if(policyIndex+1>=args.Length)throw new ArgumentException("Provide the local session policy file.");
        DecoySessionPolicyFile.Publish(args[policyIndex+1],directory);Console.WriteLine("Session policy saved. Start the service through the approved maintenance procedure.");
    }
    else Console.WriteLine("Administration verified for this maintenance invocation.");
    return;
}
if(args.Contains("--enroll"))
{
    var position=Array.IndexOf(args,"--server");if(position<0 || position+1>=args.Length)throw new ArgumentException("Specify --server https://server.example; supply enrollment code on standard input.");
    var destination=Path.Combine(directory,"connection.json");
    if(File.Exists(destination))throw new InvalidOperationException("Already enrolled. Use a reviewed re-enrollment procedure; existing credentials were not overwritten.");
    var server=args[position+1];using var client=new ManagementClient(server);
    Console.WriteLine("Enrollment code (standard input; never use a command-line argument):");
    var code=Console.ReadLine()??throw new InvalidOperationException("Enrollment code required.");
    var result=await client.EnrollAsync(new(code,Environment.MachineName,AgentBuild.Version));
    var protectedCredential=Convert.ToBase64String(ProtectedData.Protect(Encoding.UTF8.GetBytes(result.Credential),null,DataProtectionScope.LocalMachine));
    using(var stream=new FileStream(destination,FileMode.CreateNew,FileAccess.Write,FileShare.None))
    {JsonSerializer.Serialize(stream,new AgentConnection(server,result.EndpointId,protectedCredential));stream.Flush(true);}
    Console.WriteLine("Endpoint enrolled. No canaries deployed.");return;
}
var builder=Host.CreateApplicationBuilder();
builder.Services.AddWindowsService(o=>o.ServiceName="RansomFreeAgent");
builder.Services.AddSingleton(new AgentPaths(directory,!console));builder.Services.AddSingleton<AgentConsoleState>();builder.Services.AddHostedService<AgentWorker>();builder.Services.AddHostedService<AgentConsoleService>();
builder.Services.AddHostedService<ReadOnlyConsoleService>();
builder.Services.AddSingleton<DecoySessionStatus>();builder.Services.AddHostedService<DecoySessionService>();
using var qaStop=new CancellationTokenSource();
if(console && Array.IndexOf(args,"--run-seconds") is var run && run>=0 && run+1<args.Length)
{
    if(!int.TryParse(args[run+1],out var seconds) || seconds is <1 or >60)throw new ArgumentException("Console QA duration must be 1–60 seconds.");
    qaStop.CancelAfter(TimeSpan.FromSeconds(seconds));
}
await builder.Build().RunAsync(qaStop.Token);

internal sealed record AgentPaths(string Directory,bool EnableConsolePipe=true);
internal sealed record AgentConnection(string Server,string EndpointId,string ProtectedCredential);
internal sealed class AgentWorker(AgentPaths paths,AgentConsoleState consoleState,DecoySessionStatus decoyStatus,ILogger<AgentWorker> logger) : BackgroundService
{
    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        try{await RunAgentAsync(stoppingToken);}
        catch(OperationCanceledException) when(stoppingToken.IsCancellationRequested){}
        catch{Environment.ExitCode=1;throw;}
    }
    private async Task RunAgentAsync(CancellationToken stoppingToken)
    {
        using var monitor=new CanaryMonitor(paths.Directory);
        using var syslog=new SyslogOutbox(paths.Directory,monitor.Settings.Syslog.Enabled);
        ManagementClient? management=null;EventSpool? spool=null;PolicyCache? policyCache=null;ResponseJournal? responseJournal=null;var recoveredActorEvents=0;
        TrustPolicyCache? trustCache=null;string? endpointId=null;
        var connectionPath=Path.Combine(paths.Directory,"connection.json");
        if(File.Exists(connectionPath))
        {
            var connection=JsonSerializer.Deserialize<AgentConnection>(File.ReadAllText(connectionPath))??throw new InvalidDataException("Invalid connection settings.");
            var credential=Encoding.UTF8.GetString(ProtectedData.Unprotect(Convert.FromBase64String(connection.ProtectedCredential),null,DataProtectionScope.LocalMachine));
            management=new ManagementClient(connection.Server,credential);spool=new EventSpool(paths.Directory,connection.EndpointId);recoveredActorEvents=spool.RecoveredIncompleteActorEvents;
            policyCache=new PolicyCache(paths.Directory,connection.EndpointId);
            endpointId=connection.EndpointId;trustCache=new TrustPolicyCache(paths.Directory,endpointId,connection.Server);
            try{trustCache.Load();}catch(Exception ex){logger.LogWarning("Trust cache unavailable ({Type}); alerts retained and automatic response paused.",ex.GetType().Name);}
            try{responseJournal=new ResponseJournal(paths.Directory);}catch(Exception ex){logger.LogError("Remote response journal unavailable ({Type}); remote actions disabled and existing file preserved.",ex.GetType().Name);}
            try{policyCache.Load();}
            catch(Exception ex) when(ex is IOException or InvalidDataException or JsonException or UnauthorizedAccessException)
            {logger.LogWarning("Managed policy cache unavailable ({Type}); keeping default monitoring until retrieval succeeds. Existing cache preserved.",ex.GetType().Name);}
            spool.Configure(policyCache.Current.Settings.EventQueue);
        }
        using var ownedClient=management;
        SyslogOptions EffectiveSyslog()
        {
            var managed=policyCache?.Current.Settings.Syslog;
            return managed==null?monitor.Settings.Syslog:new SyslogOptions{Enabled=managed.Enabled,Host=managed.Host,Port=managed.Port,Transport=managed.Transport,Format=managed.Format,OctetCounting=managed.OctetCounting,Facility=managed.Facility,Severity=managed.Severity};
        }
        bool Allowlisted(Alert alert)=>(trustCache==null||alert.Trust?.Result.Mode=="legacy")&&(monitor.Settings.Allowlist.Any(r=>r.Matches(alert)) ||
            (policyCache?.Current.Settings.Allowlist.Any(r=>new AllowRule(r.Executable,r.Sha256,r.Folder,r.ExpiresUtc?.UtcDateTime).Matches(alert))??false));
        syslog.SetEnabled(EffectiveSyslog().Enabled);
        var logGate=new object();var health=recoveredActorEvents>0?$"Recovered {recoveredActorEvents} historical local events with incomplete actor attribution for delivery":"Starting";
        string HealthSummary()=>health+(trustCache?.Warning(policyCache?.Current.GroupId,DateTimeOffset.UtcNow) is {} warning?" | "+warning:"")+(decoyStatus.Warning is {} decoyWarning?" | "+decoyWarning:"");
        AutomaticResponder? automatic=null;
        monitor.HealthChanged+=message=>{health=message;logger.LogWarning("Monitoring health changed: {Health}",message);};
        var forensicSensor=endpointId??Guid.NewGuid().ToString("N");
        await using var forensics=new ForensicPipeline(forensicSensor,paths.Directory,message=>{health=message;logger.LogError("{Health}",message);});
        await using var uploads=new EvidenceUploadWorker(management,paths.Directory,message=>{health=message;logger.LogError("{Health}",message);});
        monitor.CaptureForensics=alert=>ActorLease.Capture(new AgentEvent(alert.EventId,new DateTimeOffset(alert.Time),alert.Operation,alert.Path,alert.User,alert.Executable,alert.ProcessId,alert.Source){Attribution=alert.Attribution},forensicSensor);
        string? WireProcess(Alert alert)=>alert.Attribution?.WindowsSyscall!=null?alert.Executable:alert.Executable??alert.Process;
        void PublishAlert(Alert alert)
        {
            lock(logGate)
            {
                if(alert.Source=="Windows minifilter"&&alert.Forensics==null&&WindowsKernelSource.RestorePrepared(paths.Directory,alert.EventId) is {} restored)
                    alert=alert with{Time=restored.ObservedUtc.UtcDateTime,Operation=restored.Operation,Path=restored.Path,User=restored.User??"Unavailable",Process=restored.Process??"Unavailable",Executable=restored.Process,ProcessId=restored.ProcessId,Forensics=restored.Forensics,Attribution=restored.Attribution,Trust=restored.Trust};
                if(alert.Source=="Agent response"&&alert.Forensics is {} sourceEvidence)alert=alert with{Forensics=forensics.LinkResponse(sourceEvidence,alert.EventId,new DateTimeOffset(alert.Time))};
                if(trustCache!=null&&endpointId!=null&&alert.Forensics==null&&alert.Source!="Forensic enrichment")
                {
                    var windowsActor=alert.Source is "Windows audit 4656" or "Windows audit 4663"||alert.Source=="Windows minifilter"&&alert.Attribution is {CompleteRecordSet:true,WindowsKernel:{} kernelActor}&&kernelActor.Subject.Captured==31;
                    var actor=windowsActor&&alert.UserSid is {Length:<=184} sid&&alert.UserAuthority is {Length:>0 and <=256} authority
                        ?new TrustActor(Authority:authority,AccountId:sid,Verified:true,AccountKind:"sid"):new TrustActor();
                    var native=windowsActor&&alert.Identity is {TrustVerified:true,ImageCheckedUtc:not null}?alert.Identity:null;
                    if(native!=null)actor=actor with{Executable=native.Executable,Sha256=native.Hash,Verified=true};
                    else if(windowsActor&&alert.Executable is {Length:>3} executable&&char.IsAsciiLetter(executable[0])&&executable[1]==':'&&executable[2]=='\\')actor=actor with{Executable=executable,Verified=true};
                    var wire=new AgentEvent(alert.EventId,new DateTimeOffset(alert.Time),alert.Operation,alert.Path,alert.User,WireProcess(alert),alert.ProcessId,alert.Source){Attribution=alert.Attribution};
                    var acquired=windowsActor?(alert.ForensicLease as ActorLease)?.AcquiredTrustIdentity(wire):null;
                    if(acquired is {} verified)actor=actor with{Executable=wire.Process,Sha256=verified.Sha256,Verified=true};
                    if(wire.Attribution==null&&!LocalActorEvidence.IsComplete(wire))wire=wire with{Attribution=new(){Provider=alert.Source,Level="Detection only",Basis="The monitoring source detected file activity but cannot supply complete user, process and PID evidence."}};
                    alert=alert with{Trust=TrustEventEvaluation.Evaluate(trustCache,endpointId,policyCache?.Current.GroupId,"windows",wire,actor,DateTimeOffset.UtcNow,acquired!=null?"windows-operation-bound-snapshot-v1":null,acquired?.CreatedUtc,acquired?.CheckedUtc)};
                    if(acquired==null&&native!=null)alert=alert with{Trust=alert.Trust with{ProcessBasis="windows-handle-locked-image-v1",ProcessCreatedUtc=DateTimeOffset.FromFileTime(native.CreatedUtcFileTime),ImageCheckedUtc=native.ImageCheckedUtc}};
                    alert=alert with{PolicySyslogSeverity=alert.Trust.Result.Decision.Severity=="informational"?6:null};
                }
                if(alert.Forensics==null&&LocalActorEvidence.IsRequired(alert.Source))
                {
                    var input=new AgentEvent(alert.EventId,new DateTimeOffset(alert.Time),alert.Operation,alert.Path,alert.User,WireProcess(alert),alert.ProcessId,alert.Source){Trust=alert.Trust,Attribution=alert.Attribution,Forensics=alert.Forensics};
                    forensics.Submit(input,policyCache?.Current.Settings.Forensics??new(),
                        pending=>PublishAlert(alert with{Forensics=pending.Forensics,ForensicLease=null}),
                        completed=>PublishAlert(new Alert(completed.ObservedUtc.UtcDateTime,completed.Operation,completed.Path,completed.Process??"Unavailable",completed.User??"Unavailable",completed.Source){EventId=completed.EventId,ProcessId=completed.ProcessId,Executable=completed.Process,Attribution=completed.Attribution,Forensics=completed.Forensics,PolicySyslogSeverity=6}),alert.ForensicLease as ActorLease,
                        deferAtCapacity:input.Source=="Windows minifilter"&&input.Attribution?.WindowsKernel!=null);
                    return;
                }
                if(alert.Source=="Windows minifilter")
                {
                    if(spool==null)throw new IOException("Kernel evidence requires an enrolled durable management spool");
                    WindowsKernelSource.SavePrepared(paths.Directory,new AgentEvent(alert.EventId,new DateTimeOffset(alert.Time),alert.Operation,alert.Path,alert.User,WireProcess(alert),alert.ProcessId,alert.Source){Trust=alert.Trust,Attribution=alert.Attribution,Forensics=alert.Forensics});
                }
                try
                {
                    alert=alert with {Allowlisted=Allowlisted(alert)};
                    var file=Path.Combine(paths.Directory,"activity.jsonl");if(File.Exists(file) && new FileInfo(file).Length>5_000_000)File.Move(file,file+".previous",true);
                    File.AppendAllText(file,JsonSerializer.Serialize(alert)+Environment.NewLine);
                }
                catch(Exception ex){logger.LogError("Local activity log failed ({Type}); inspect local storage.",ex.GetType().Name);health="Local activity log failed";}
                // A failure in one destination must not prevent attempting the others.
                try{if(alert.Source!="Forensic enrichment"||alert.Forensics?.Detection.Disposition!="log-only")syslog.Enqueue(alert,EffectiveSyslog());}
                catch(Exception ex){logger.LogError("Syslog queue failed ({Type}).",ex.GetType().Name);health="Syslog queue failed";}
                try
                {
                    var wire=new AgentEvent(alert.EventId,new DateTimeOffset(alert.Time),alert.Operation,alert.Path,alert.User,WireProcess(alert),alert.ProcessId,alert.Source){Trust=alert.Trust,Attribution=alert.Attribution,Forensics=alert.Forensics};
                    if(wire.Attribution==null&&!LocalActorEvidence.IsComplete(wire))wire=wire with{Attribution=new(){Provider=alert.Source,Level="Detection only",Basis="The monitoring source detected file activity but cannot supply complete user, process and PID evidence."}};
                    spool?.Enqueue(wire);
                }
                catch(Exception ex){logger.LogError("Management event queue failed ({Type}).",ex.GetType().Name);health="Management event queue failed";if(alert.Source=="Windows minifilter"||alert.Attribution?.WindowsSyscall!=null)throw;}
                consoleState.Record(alert);
                if(alert.Source!="Forensic enrichment")automatic?.Enqueue(alert);
            }
        }
        monitor.Alerted+=PublishAlert;
        consoleState.Configure(()=>
        {
            var queue=spool?.Status;
            return new(AgentBuild.Version,HealthSummary(),monitor.Settings.Canaries.Count,monitor.AuditConnected,policyCache?.Current.Revision??0,queue?.Pending??0,syslog.Count,[])
            {QueueCapacity=queue?.MaxEvents??0,QueuePayloadBytes=queue?.PayloadBytes??0,QueuePayloadLimitBytes=queue?.MaxPayloadBytes??0};
        },()=>monitor.Settings.Password,Allowlisted,PublishAlert);
        bool TrustAllowsResponse(Alert alert)
        {
            if(trustCache==null||endpointId==null)return true;
            var wire=new AgentEvent(alert.EventId,new DateTimeOffset(alert.Time),alert.Operation,alert.Path,alert.User,WireProcess(alert),alert.ProcessId,alert.Source);
            return !TrustEventEvaluation.Evaluate(trustCache,endpointId,policyCache?.Current.GroupId,"windows",wire,alert.Trust?.Actor??new(),DateTimeOffset.UtcNow).Result.Decision.SuppressResponse;
        }
        await using var automaticLifetime=automatic=new AutomaticResponder(paths.Directory,()=>policyCache?.Current.Settings.AutomaticResponse??new(),consoleState,PublishAlert,logger,TrustAllowsResponse);
        monitor.Start();health=monitor.Settings.Canaries.Count==0?"No canaries configured":monitor.AuditConnected?"Monitoring":"Audit unavailable";
        // An operator enables this only after installing a qualified signed driver.
        // No service installation, boot configuration or security-policy change is performed here.
        void PublishKernel(AgentEvent e,ActorLease? earlyActor)
        {
            var identity=e.ProcessId is >0&&e.Process!=null?ProcessControls.Capture(e.ProcessId.Value,e.Process,e.ObservedUtc.UtcDateTime):null;
            if(identity?.CreatedUtcFileTime!=(e.Attribution?.WindowsKernel?.ProcessCreatedFileTime??e.Attribution?.WindowsSyscall?.Native.ProcessCreatedFileTime))identity=null;
            var slash=e.User?.LastIndexOf('\\')??-1;
            PublishAlert(new Alert(e.ObservedUtc.UtcDateTime,e.Operation,e.Path,e.Process??"Unavailable",e.User??"Unavailable",e.Source){EventId=e.EventId,Executable=e.Process,ProcessId=e.ProcessId,UserSid=e.Attribution?.UserSid,UserAuthority=slash>0?e.User![..slash]:null,Attribution=e.Attribution,Identity=identity,ForensicLease=earlyActor,Forensics=e.Forensics,Trust=e.Trust});
        }
        await using var kernel=File.Exists(Path.Combine(paths.Directory,"windows-kernel.enabled"))
            ?new WindowsKernelSource(forensicSensor,paths.Directory,monitor.WatchedPaths,
                e=>PublishKernel(e,null),
                message=>{health=message;logger.LogWarning("Kernel source: {Health}",message);},PublishKernel,
                captureStagedExecutables:File.Exists(Path.Combine(paths.Directory,"windows-kernel-staging.enabled")),
                captureProactiveExecutables:File.Exists(Path.Combine(paths.Directory,"windows-kernel-proactive.enabled")),
                captureRemoteFilesystem:File.Exists(Path.Combine(paths.Directory,"windows-kernel-remote.enabled")),
                captureDeferredTokenContext:File.Exists(Path.Combine(paths.Directory,"windows-kernel-deferred-tokens.enabled"))):null;
        await using var syscall=File.Exists(Path.Combine(paths.Directory,"windows-syscall.enabled"))&&spool!=null
            ?new WindowsSyscallSource(forensicSensor,paths.Directory,kernel,forensics,()=>policyCache?.Current.Settings.Forensics??new(),
                e=>PublishKernel(e,null),message=>{health=message;logger.LogWarning("Syscall source: {Health}",message);}):null;
        if(policyCache!=null)
        {
            try{ManagedDeployments.Apply(paths.Directory,monitor,policyCache.Current.Settings);}
            catch(Exception ex){health="Managed deployment pending: "+ex.GetType().Name;logger.LogWarning("Cached deployment plan could not be applied ({Type}).",ex.GetType().Name);}
        }
        logger.LogInformation("Agent runtime started; {Count} configured canaries.",monitor.Settings.Canaries.Count);
        using var timer=new PeriodicTimer(TimeSpan.FromSeconds(15));
        var integrityClock=System.Diagnostics.Stopwatch.StartNew();var policyClock=System.Diagnostics.Stopwatch.StartNew();var checkedIntegrity=false;var checkedPolicy=false;
        try
        {
            do
            {
                var interval=policyCache?.Current.Settings.IntegrityIntervalSeconds??15;
                if(monitor.Settings.Canaries.Count>0 && (!checkedIntegrity || integrityClock.Elapsed.TotalSeconds>=interval))
                {monitor.CheckIntegrity();integrityClock.Restart();checkedIntegrity=true;}
                if(management!=null && spool!=null)
                {
                    try
                    {
                        var summary=HealthSummary();var protection=WindowsProtectionStatus.Build(monitor.ProtectionEvidence(),monitor.Settings.Canaries.Count,monitor.AuditConnected,monitor.WatchersHealthy,health);
                        await management.HeartbeatAsync(new HeartbeatRequest(AgentBuild.Version,summary.Length>512?summary[..512]:summary){OperatingSystem="windows",Protection=protection},stoppingToken);
                        // Management delivery is unconditional for enrolled endpoints, independent
                        // of direct-client or server-relay syslog choices. Drain a bounded backlog
                        // immediately after reconnection; failed/invalid receipts preserve the queue.
                        for(var deliveryBatch=0;deliveryBatch<10;deliveryBatch++)
                        {
                            var batch=spool.Peek();if(batch.Events.Length==0)break;
                            spool.Acknowledge(batch,await management.SendEventsAsync(batch,stoppingToken));
                        }
                    }
                    catch(OperationCanceledException) when(stoppingToken.IsCancellationRequested){break;}
                    catch(Exception ex){logger.LogWarning("Management delivery failed ({Type}); unacknowledged queue records remain retained for retry.",ex.GetType().Name);}
                    if(responseJournal!=null)
                    {
                        try
                        {
                            foreach(var receipt in responseJournal.PendingReceipts()){await management.SendResponseReceiptAsync(receipt,stoppingToken);responseJournal.Acknowledge(receipt.Id);}
                            await management.ReportNativeResponseCapabilitiesAsync(new(1,"windows",1),stoppingToken);
                            var commands=await management.PollResponsesAsync(stoppingToken);if(commands.Length>10)throw new InvalidDataException("Response batch exceeds its limit.");
                            // Fetch current policy before native actions, rather than executing
                            // against a cached authorization that may have been revoked.
                            AssignedPolicy? responsePolicy=null;
                            if(commands.Any(c=>c.Target!=null)&&policyCache!=null){responsePolicy=await management.GetPolicyAsync(stoppingToken);policyCache.Save(responsePolicy);}
                            foreach(var command in commands){var receipt=responseJournal.Execute(command,consoleState,policy:responsePolicy,sensor:endpointId);await management.SendResponseReceiptAsync(receipt,stoppingToken);responseJournal.Acknowledge(receipt.Id);}
                        }
                        catch(OperationCanceledException) when(stoppingToken.IsCancellationRequested){break;}
                        catch(Exception ex){logger.LogWarning("Remote response synchronization failed ({Type}); execution journal retained.",ex.GetType().Name);}
                    }
                    if(policyCache!=null && (!checkedPolicy || policyClock.Elapsed.TotalSeconds>=60))
                    {
                        checkedPolicy=true;policyClock.Restart();
                        try
                        {
                            var policy=await management.GetPolicyAsync(stoppingToken);policyCache.Save(policy);spool?.Configure(policy.Settings.EventQueue);
                            syslog.SetEnabled(EffectiveSyslog().Enabled);
                            ManagedDeployments.Apply(paths.Directory,monitor,policy.Settings);
                            health=monitor.Settings.Canaries.Count==0?"No canaries configured":monitor.AuditConnected?"Monitoring":"Audit unavailable";
                            await management.AcknowledgePolicyAsync(policy,stoppingToken);
                            if(trustCache!=null){var trust=await management.GetTrustPolicyAsync(stoppingToken);trustCache.Save(trust,DateTimeOffset.UtcNow);await management.AcknowledgeTrustPolicyAsync(trust,stoppingToken);}
                        }
                        catch(OperationCanceledException) when(stoppingToken.IsCancellationRequested){break;}
                        catch(Exception ex){health="Policy application pending: "+ex.GetType().Name;logger.LogWarning("Policy synchronization/application failed ({Type}); existing canaries preserved; no success receipt sent.",ex.GetType().Name);}
                    }
                }
            }while(await timer.WaitForNextTickAsync(stoppingToken));
        }
        catch(OperationCanceledException) when(stoppingToken.IsCancellationRequested){}
    }
}

// Enrollment, heartbeat, console and read-only CLI share the installed build identity.
internal static class AgentBuild
{
    internal static string Version {get;} = typeof(AgentBuild).Assembly
        .GetCustomAttribute<AssemblyInformationalVersionAttribute>()?.InformationalVersion.Split('+')[0]
        ?? typeof(AgentBuild).Assembly.GetName().Version?.ToString() ?? "unavailable";
}
