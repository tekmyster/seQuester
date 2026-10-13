using System.Collections.Concurrent;
using RansomFree.Contracts;

namespace RansomFree.Client.Forensics;

// One admitted installation/source session. There is deliberately no network
// client, credential, updater, forced unload, or production CLI activation here.
// The installer and service entry point require separate qualification.
internal static class LinuxNativeCompanionRuntime
{
    internal static async Task<LinuxControlledSourceRuntime.Outcome?> RunAsync(string configurationDirectory,Action<string> report,CancellationToken cancel)
    {
        void Report(string message){try{report(message);}catch{ /* Reporting is not a resource-release boundary. */ }}
        using var package=LinuxNativePackageAdmission.Open(configurationDirectory);
        var definition=package.Definition;var config=definition.Configuration;
        using var privateRoot=LinuxProtectedDirectory.OpenRoot(config.PrivateDirectory);privateRoot.RequirePrivate();privateRoot.RequireQualifiedLocalExt4();
        var rawBankQuotaBytes=LinuxNativeRawStorageCapacity.Read(privateRoot,config.SensorId);
        Report("NATIVE_RAW_BANK_CAPACITY_BYTES:"+rawBankQuotaBytes);
        using var targets=LinuxNativeTargetAdmission.Open(definition.Manifest.Targets);
        using var exports=LinuxProtectedDirectory.OpenRoot(config.ExportDirectory,config.ServiceGroup);
        // I/O entry/result and permission observations share a bounded delivery
        // backlog. Four native leases remain the independent acquisition limit.
        using var journal=new LinuxForensicJournal(config.PrivateDirectory,config.SensorId,
            pendingWorkLimit:definition.Manifest.ControlVersion==4?16:4);
        Report("NATIVE_PENDING_WORK_LIMIT:"+journal.PendingWorkLimit);
        using var spool=new EventSpool(Path.Combine(config.PrivateDirectory,"spool"),config.SensorId,retainJournalLifetime:true);
        var actorPath=Path.Combine(config.PrivateDirectory,"evidence","actors");EvidenceStore.EnsurePrivate(actorPath);
        using var actors=LinuxProtectedDirectory.OpenRoot(actorPath);actors.RequirePrivate();
        await using var pipeline=new ForensicPipeline(config.SensorId,config.PrivateDirectory,Report);
        using var policyOwner=new LinuxNativePolicyAdmission(journal,config.Server,config.SensorId,Convert.FromBase64String(config.PublicKeyBase64));
        var exporter=new LinuxNativeBridgeExport(exports,config.SensorId);
        var firstPolicy=new TaskCompletionSource<LinuxNativeSourcePolicy>(TaskCreationOptions.RunContinuationsAsynchronously);
        LinuxNativeSourcePolicy? policy=null;LinuxControlledSourceRuntime? source=null;LinuxNativeModuleOwner? module=null;
        var published=new ConcurrentDictionary<string,byte>(StringComparer.Ordinal);
        using var servicesStop=new CancellationTokenSource();
        await using var policySocket=new LinuxNativePolicySocket(config.ChannelDirectory,config.ServiceUid,config.ServiceGroup,config.SensorId,config.Server);
        await using var deliverySocket=new LinuxNativeBridgeSocket(config.ChannelDirectory,config.ServiceUid,config.ServiceGroup,config.SensorId,config.Server);
        await using var healthSocket=new LinuxNativeHealthSocket(config.ChannelDirectory,config.ServiceUid,config.ServiceGroup,config.SensorId,config.Server,
            ()=>Volatile.Read(ref source)?.ObserveServiceHealth());
        LinuxNativePolicyLease Admit(SignedNativePolicy envelope)
        {
            // PolicySocket serializes this callback. A binding exists before
            // firstPolicy completes, so a second relay cannot revoke an unseen
            // first lease while startup constructs its binding.
            if(policy!=null)
            {
                // An exchange which failed before confirmation invalidated its
                // lease. No source/module has been started from that binding.
                if(!firstPolicy.Task.IsCompleted&&policy.Observe()==null)Volatile.Write(ref policy,null);
                else return policy.AcceptReplacement(envelope);
            }
            var lease=policyOwner.AcceptLease(envelope);
            try
            {
                var snapshot=lease.Current();var binding=new LinuxNativeSourcePolicy(policyOwner,lease,config.SensorId,snapshot.Monitoring.Settings.Forensics??new());
                Volatile.Write(ref policy,binding);return lease;
            }
            catch{lease.Invalidate();throw;}
        }
        void Confirm(LinuxNativePolicyLease lease)
        {
            var binding=Volatile.Read(ref policy);
            var sample=binding?.Observe();
            if(sample==null||!ReferenceEquals(sample.Lease,lease)||!policyOwner.IsActiveLease(lease))
                throw new InvalidDataException("Confirmed relay requires its current admitted policy binding");
            firstPolicy.TrySetResult(binding!);
        }
        Task ExportPass()
        {
            foreach(var receipt in journal.PendingNativeImportRetirements())
            {exporter.AcknowledgeImport(journal,spool,receipt);published.TryRemove(receipt.SourceEventId,out _);}
            var pending=journal.PendingNativeExports(128);
            foreach(var id in published.Keys)if(!pending.Contains(id,StringComparer.Ordinal))published.TryRemove(id,out _);
            foreach(var id in pending)
                if(!published.ContainsKey(id)){exporter.PublishCommitted(journal,id,actors);published.TryAdd(id,0);}
            return Task.CompletedTask;
        }
        async Task Loop(Func<Task> operation,string channel,TimeSpan successDelay)
        {
            string? priorError=null;
            while(!servicesStop.IsCancellationRequested)
            {
                var delay=successDelay;
                try{await operation().ConfigureAwait(false);priorError=null;}
                catch(OperationCanceledException)when(servicesStop.IsCancellationRequested){break;}
                catch(Exception e)when(e is not OutOfMemoryException)
                {
                    if(channel=="HEALTH")Report(LinuxNativeHealthSocket.FailureDiagnostic(e));
                    var reason="NATIVE_COMPANION_"+channel+":"+e.GetType().Name;
                    if(reason!=priorError){Report(reason);priorError=reason;}
                    if(channel=="EXPORT")Volatile.Read(ref source)?.RequestStop("NATIVE_EXPORT_UNAVAILABLE");
                    delay=TimeSpan.FromSeconds(1);
                }
                if(delay>TimeSpan.Zero)try{await Task.Delay(delay,servicesStop.Token).ConfigureAwait(false);}catch(OperationCanceledException)when(servicesStop.IsCancellationRequested){break;}
            }
        }
        var tasks=new List<Task>(4);
        LinuxControlledSourceRuntime.Outcome? outcome=null;
        bool startupPolicyExpired=false;
        try
        {
            // Register inside the drain boundary so a partial startup cannot
            // leave already scheduled channel work running after failure.
            tasks.Add(Task.Run(()=>Loop(async()=>{_=await policySocket.AcceptAsync(policyOwner,Admit,servicesStop.Token,Confirm).ConfigureAwait(false);},"POLICY",TimeSpan.Zero)));
            tasks.Add(Task.Run(()=>Loop(async()=>{var receipt=await deliverySocket.AcceptAsync(exporter,journal,spool,servicesStop.Token).ConfigureAwait(false);published.TryRemove(receipt.SourceEventId,out _);},"DELIVERY",TimeSpan.Zero)));
            tasks.Add(Task.Run(()=>Loop(()=>healthSocket.AcceptAsync(servicesStop.Token),"HEALTH",TimeSpan.Zero)));
            tasks.Add(Task.Run(()=>Loop(ExportPass,"EXPORT",TimeSpan.FromSeconds(1))));
            Report("NATIVE_COMPANION_WAITING_FOR_SIGNED_POLICY");
            var admitted=await firstPolicy.Task.WaitAsync(cancel).ConfigureAwait(false);
            var snapshot=admitted.Observe()??throw new InvalidDataException("Initial signed source policy expired or was revoked");
            cancel.ThrowIfCancellationRequested();package.RequireCurrent();targets.RequireCurrent();
            module=LinuxNativeModuleOwner.Prepare(package,targets);module.Load();
            if(module.State!="LoadedOwned")throw new IOException("Native module admission did not obtain ownership");
            cancel.ThrowIfCancellationRequested();
            source=module.StartRegisteredSource(journal,pipeline,spool,snapshot.Snapshot.Monitoring.Settings.Forensics??new(),admitted,Report,rawBankQuotaBytes);
            await source.Started.WaitAsync(cancel).ConfigureAwait(false);Report("NATIVE_COMPANION_SOURCE_ACTIVE");
            outcome=await source.Completion.WaitAsync(cancel).ConfigureAwait(false);
        }
        catch(LinuxNativePolicyUnavailableException error)when(error.Reason=="LINUX_NATIVE_POLICY_EXPIRED_OR_REVOKED")
        {
            startupPolicyExpired=true;
            Report("NATIVE_COMPANION_POLICY_EXPIRED_DURING_STARTUP");
        }
        finally
        {
            // Registration can succeed before StartRegisteredSource throws.
            // Always recover the module's actual registered instance for stop.
            var actual=module?.RegisteredSource;actual?.RequestStop("NATIVE_COMPANION_STOP");
            Report("NATIVE_COMPANION_CLOSE_DRAINING");servicesStop.Cancel();
            var channels=Task.WhenAll(policySocket.DisposeAsync().AsTask(),deliverySocket.DisposeAsync().AsTask(),healthSocket.DisposeAsync().AsTask(),Task.WhenAll(tasks));
            if(module!=null)
            {
                while(true)
                {
                    try
                    {
                        // Dispose has its own resumable resource-release bits.
                        // After a release failure, do not call RetryReceipt,
                        // which correctly rejects an owner already releasing.
                        if(module.State is "Prepared" or "LoadIntentPending" or "LoadFailedNoOwnership" or "UnloadVerifiedAbsent")
                        {module.Dispose();break;}
                        module.RetryReceipt();
                        if(module.RegisteredSource is {} registered)
                        {
                            var drain=module.StopSourceAndUnloadAsync();
                            while(!drain.IsCompleted)
                            {
                                await Task.WhenAny(drain,Task.Delay(1000)).ConfigureAwait(false);
                                registered.RetryReceipts();try{module.RetryReceipt();}catch(Exception e)when(e is not OutOfMemoryException){Report("NATIVE_MODULE_RECEIPT_PENDING:"+e.GetType().Name);}
                            }
                            outcome=await drain.ConfigureAwait(false);
                        }
                        else if(module.State is "LoadedOwned" or "UnloadIntentPending" or "UnloadReturned")module.UnloadBeforeSource();
                        if(module.State is "Prepared" or "LoadIntentPending" or "LoadFailedNoOwnership" or "UnloadVerifiedAbsent")
                        {module.Dispose();break;}
                    }
                    catch(Exception e)when(e is not OutOfMemoryException){Report("NATIVE_COMPANION_CLOSE_UNRESOLVED:"+e.GetType().Name);}
                    // No cancellation token, detach, numeric PID kill or forced
                    // delete_module may turn unresolved ownership into success.
                    await Task.Delay(1000).ConfigureAwait(false);
                }
            }
            await channels.ConfigureAwait(false);
            try{await ExportPass().ConfigureAwait(false);}catch(Exception e)when(e is not OutOfMemoryException){Report("NATIVE_FINAL_EXPORT_PENDING:"+e.GetType().Name);}
            Report("NATIVE_COMPANION_NATIVE_CLOSED");
        }
        // Returning an outcome permits the existing strict recovery gate only
        // after StopSourceAndUnloadAsync and every channel drain returned.
        // Missing/error/pending outcomes still produce a visible failed exit.
        if(startupPolicyExpired&&LinuxNativeCompanionService.CompletedExitCode(outcome,false)!=LinuxNativeCompanionService.PolicyExpiredRestartExitCode)
            throw new InvalidOperationException("Startup policy expired without a complete recovery-qualified closure outcome");
        return outcome;
    }
}
