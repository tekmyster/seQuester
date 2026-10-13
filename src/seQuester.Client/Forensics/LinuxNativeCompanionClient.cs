using System.Diagnostics;
using System.Runtime.InteropServices;
using RansomFree.Contracts;

namespace RansomFree.Client.Forensics;

public sealed record LinuxNativeClientOptions
{
    public bool Enabled {get;init;}
    public string ChannelDirectory {get;init;}="/run/sequester-native";
    public string ExportDirectory {get;init;}="/var/lib/sequester-native-export";
    public uint ServiceGroup {get;init;}
    public void Validate()
    {
        if(!Enabled)return;
        if(ServiceGroup is 0 or uint.MaxValue||!LinuxNativeInstallation.CanonicalPath(ChannelDirectory)||!LinuxNativeInstallation.CanonicalPath(ExportDirectory)||
            ChannelDirectory==ExportDirectory||ChannelDirectory.StartsWith(ExportDirectory+"/",StringComparison.Ordinal)||ExportDirectory.StartsWith(ChannelDirectory+"/",StringComparison.Ordinal))
            throw new InvalidDataException("Native companion requires separate canonical channel/export paths and its dedicated service group");
    }
}

// Capabilities and credentials stay with the existing ordinary sensor. This
// client only relays signed policy, imports exact committed evidence and reads
// historical live status. It cannot create a native owner or suppress an event.
public sealed class LinuxNativeCompanionClient:IAsyncDisposable
{
    public sealed record Status(bool Enabled,bool ReadyAtRecentSample,string Health,string Policy,string Delivery,
        DateTimeOffset UpdatedUtc,string? LastImportedSourceEventId,int? RootProcessId,string? RootInstanceId)
    {public string CloseState {get;init;}="OPEN";}
    [DllImport("libc",EntryPoint="geteuid")]private static extern uint UserId();
    private readonly LinuxNativeClientOptions options;
    private readonly string sensor,origin;
    private readonly ManagementClient management;
    private readonly LinuxNativeBridgeImport importer;
    private readonly LinuxNativeHealthTracker health=new();
    private readonly Action<string> report;
    private readonly Action<string>? qualificationCheckpoint;
    private readonly CancellationTokenSource stop=new();
    private readonly object gate=new();
    private readonly object shutdownGate=new();
    private readonly Task[] tasks;
    private Task? closing;
    private string healthMessage="STARTING",policyMessage="STARTING",deliveryMessage="STARTING";
    private DateTimeOffset updated=DateTimeOffset.UtcNow;
    private string? lastImported;
    private string? deliveryCursor;
    private string closeState="OPEN";
    public bool ReadyAtRecentSample=>options.Enabled&&Volatile.Read(ref closeState)=="OPEN"&&health.ReadyAtRecentSample;
    public bool KernelHashReadyAtRecentSample=>ReadyAtRecentSample&&health.Current?.Reply.Source?.ControlVersion==2;
    public bool NativeHashReadyAtRecentSample=>ReadyAtRecentSample&&health.Current?.Reply.Source?.ControlVersion==4;
    public Status Current
    {
        get
        {
            lock(gate)
            {
                var value=health.Current;
                return new(options.Enabled,ReadyAtRecentSample,healthMessage,policyMessage,deliveryMessage,updated,lastImported,value?.Reply.Pid,value?.Reply.InstanceId){CloseState=Volatile.Read(ref closeState)};
            }
        }
    }
    public LinuxNativeCompanionClient(LinuxNativeClientOptions options,string sensor,string server,string privateDirectory,EventSpool spool,ManagementClient management,Action<string> report)
        :this(options,sensor,server,privateDirectory,spool,management,report,null){}
    // No configuration, server policy or installed caller selects a callback.
    internal static LinuxNativeCompanionClient CreateForQualification(LinuxNativeClientOptions options,string sensor,string server,string privateDirectory,EventSpool spool,
        ManagementClient management,Action<string> report,Action<string> checkpoint)=>new(options,sensor,server,privateDirectory,spool,management,report,checkpoint??throw new ArgumentNullException(nameof(checkpoint)));
    private LinuxNativeCompanionClient(LinuxNativeClientOptions options,string sensor,string server,string privateDirectory,EventSpool spool,ManagementClient management,Action<string> report,Action<string>? qualificationCheckpoint)
    {
        ArgumentNullException.ThrowIfNull(options);options.Validate();this.options=options with{};
        if(!Guid.TryParseExact(sensor,"N",out _))throw new ArgumentException("Enrolled native sensor identity required");
        origin=new Uri(server,UriKind.Absolute).AbsoluteUri;
        if(!NativePolicySnapshot.ValidOrigin(origin))throw new ArgumentException("Canonical HTTPS management origin required");
        this.sensor=sensor;this.management=management;this.report=report;this.qualificationCheckpoint=qualificationCheckpoint;importer=new(privateDirectory,sensor,spool);
        if(!options.Enabled){healthMessage=policyMessage=deliveryMessage="DISABLED";tasks=[];return;}
        if(!OperatingSystem.IsLinux()||RuntimeInformation.ProcessArchitecture!=Architecture.X64||UserId()==0)
            throw new PlatformNotSupportedException("The native bridge client requires an ordinary Linux x64 sensor account");
        tasks=[Task.Run(()=>Loop(HealthPass,TimeSpan.FromSeconds(2),"health")),Task.Run(()=>Loop(PolicyPass,TimeSpan.FromSeconds(30),"policy")),
            Task.Run(()=>Loop(DeliveryPass,TimeSpan.FromSeconds(1),"delivery"))];
    }
    private bool Set(string channel,string value)
    {
        lock(gate)
        {
            var prior=channel=="health"?healthMessage:channel=="policy"?policyMessage:deliveryMessage;
            if(channel=="health")healthMessage=value;else if(channel=="policy")policyMessage=value;else deliveryMessage=value;
            updated=DateTimeOffset.UtcNow;return prior!=value;
        }
    }
    private async Task Loop(Func<CancellationToken,Task> action,TimeSpan interval,string channel)
    {
        while(!stop.IsCancellationRequested)
        {
            try{await action(stop.Token).ConfigureAwait(false);}
            catch(OperationCanceledException)when(stop.IsCancellationRequested){break;}
            catch(Exception e)when(e is not OutOfMemoryException)
            {
                if(channel=="health")health.Invalidate();
                if(channel=="health")try{report(LinuxNativeHealthSocket.FailureDiagnostic(e));}catch{}
                var message="UNAVAILABLE:"+e.GetType().Name;
                if(Set(channel,message))try{report("Native companion "+channel+" "+message);}catch{ /* Reporting cannot grant readiness or discard queued evidence. */ }
            }
            try{await Task.Delay(interval,stop.Token).ConfigureAwait(false);}catch(OperationCanceledException)when(stop.IsCancellationRequested){break;}
        }
        if(channel=="health")health.Invalidate();Set(channel,"STOPPED");
    }
    private async Task HealthPass(CancellationToken cancel)
    {
        var value=await LinuxNativeHealthSocket.QueryAsync(options.ChannelDirectory,options.ServiceGroup,sensor,origin,cancel).ConfigureAwait(false);
        if(!health.Accept(value,Stopwatch.GetTimestamp()))throw new InvalidDataException("Root health response failed volatile ordering");
        Set("health",value.Reason);
    }
    private async Task PolicyPass(CancellationToken cancel)
    {
        await LinuxNativePolicySocket.RelayAsync(options.ChannelDirectory,options.ServiceGroup,sensor,origin,management.RelayNativePolicyAsync,cancel).ConfigureAwait(false);
        Set("policy","SIGNED_POLICY_RELAY_ACCEPTED");
    }
    private async Task DeliveryPass(CancellationToken cancel)
    {
        using var root=LinuxProtectedDirectory.OpenRoot(options.ExportDirectory,options.ServiceGroup);
        var names=root.Names(256);var count=0;var failed=0;string? failure=null;
        // Root-owned incomplete publication files remain available for root
        // recovery; they are never interpreted as finished event packets.
        foreach(var name in DeliveryPage(names,deliveryCursor))
        {
            cancel.ThrowIfCancellationRequested();deliveryCursor=name;
            try
            {
                var receipt=importer.Import(root,name[..^5],qualificationCheckpoint);
                await LinuxNativeBridgeSocket.ConfirmAsync(options.ChannelDirectory,options.ServiceGroup,sensor,origin,receipt,cancel).ConfigureAwait(false);
                lock(gate){lastImported=receipt.SourceEventId;}count++;
            }
            catch(OperationCanceledException)when(cancel.IsCancellationRequested){throw;}
            catch(Exception e)when(e is not OutOfMemoryException){failed++;failure=e.GetType().Name;}
        }
        var status=failed>0?"LOCAL_IMPORT_INCOMPLETE:"+failed+":"+failure:count==0?"NO_PENDING_EXPORTS":"LOCAL_IMPORT_ACKNOWLEDGED";
        if(Set("delivery",status)&&failed>0)try{report("Native companion delivery "+status+"; affected packets retained");}catch{}
    }
    internal static string[] DeliveryPage(IEnumerable<string> names,string? cursor)
    {
        var complete=names.Where(n=>n.EndsWith(".json",StringComparison.Ordinal)&&Guid.TryParseExact(n[..^5],"N",out _)).Order(StringComparer.Ordinal).ToArray();
        // A damaged packet must not starve later valid packets. Cursor only
        // orders attempts; it never deletes or acknowledges an unimported file.
        return complete.Where(n=>cursor==null||StringComparer.Ordinal.Compare(n,cursor)>0)
            .Concat(complete.Where(n=>cursor!=null&&StringComparer.Ordinal.Compare(n,cursor)<=0)).Take(16).ToArray();
    }
    public ValueTask DisposeAsync(){lock(shutdownGate)return new(closing??=StopAndDrain());}
    private async Task StopAndDrain()
    {
        Volatile.Write(ref closeState,"CLOSE_DRAINING");health.Invalidate();stop.Cancel();
        try{await Task.WhenAll(tasks).ConfigureAwait(false);Volatile.Write(ref closeState,"CLOSED");}
        catch{Volatile.Write(ref closeState,"CLOSE_FAILED");throw;}
        finally{stop.Dispose();}
    }
}
