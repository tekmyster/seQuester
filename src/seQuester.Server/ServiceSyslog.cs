using RansomFree;
namespace RansomFree.Server;

internal sealed class ServiceSyslogStatus
{
    public string Message {get;set;}="Disabled";
    public long LastSentSequence {get;set;}
}
internal static class ServiceSyslogMessage
{
    public static Alert Create(ServiceEvidence evidence)
    {
        var e=evidence.Event;var context=e.ServiceContext??throw new InvalidDataException("Service context missing; evidence retained.");
        return new(e.ObservedUtc.UtcDateTime,e.Operation,e.Path,"Unavailable","Unavailable","Server service decoy")
        {EventId=e.EventId,EventSequence=evidence.Sequence,SourceAddress=context.SourceAddress,CanaryName=context.Name,CanaryType="N05",Description=context.Description,Location=context.Location,Note=context.Note,ServiceContext=context,Detail="Observed service request; no endpoint user/process attribution"};
    }
}
internal interface IServiceSyslogTransport {Task<string> Send(Alert alert,SyslogOptions destination,CancellationToken ct);}
internal sealed class ServiceSyslogTransport:IServiceSyslogTransport
{
    public Task<string> Send(Alert alert,SyslogOptions destination,CancellationToken ct)=>SyslogClient.SendAsync(alert,destination,ct);
}
internal sealed class ServiceSyslogPump(Store store,ServerSyslogConfiguration configuration,ProtectedNotificationFiles files,ServiceSyslogStatus status,IServiceSyslogTransport transport)
{
    public async Task Step(CancellationToken ct)
    {
        var settings=configuration.Read();var progress=files.Read<ServerEventSyslogProgress>("service-syslog-progress.protected")??new(0);
        if(progress.Sequence<0)throw new InvalidDataException("Invalid service checkpoint; original preserved.");status.LastSentSequence=progress.Sequence;
        if(!settings.Destination.Enabled||!settings.ServiceHits){status.Message="Disabled; service hits retained";return;}
        if(settings.ServiceAfterSequence==null)throw new InvalidDataException("Service activation checkpoint missing.");
        if(Math.Max(progress.Sequence,settings.ServiceAfterSequence.Value)>store.LatestServiceSequence())throw new InvalidDataException("Service relay checkpoint exceeds available evidence; restore matching evidence and checkpoint before resuming.");
        if(progress.Sequence<settings.ServiceAfterSequence){progress=new(settings.ServiceAfterSequence.Value);files.Write("service-syslog-progress.protected",progress);status.LastSentSequence=progress.Sequence;}
        var events=store.ServiceEvents(progress.Sequence);if(events.Count==0){status.Message="Waiting for alerts";return;}
        foreach(var item in events)
        {
            settings=configuration.Read();if(!settings.Destination.Enabled||!settings.ServiceHits){status.Message="Disabled; service hits retained";return;}
            status.Message=await transport.Send(ServiceSyslogMessage.Create(item),settings.Destination,ct);
            progress=new(item.Sequence);files.Write("service-syslog-progress.protected",progress);status.LastSentSequence=progress.Sequence;
        }
    }
}
internal sealed class ServiceSyslogRelay(ServiceSyslogPump pump,ProtectedNotificationFiles files,ServiceSyslogStatus status,ILogger<ServiceSyslogRelay> logger):BackgroundService
{
    protected override async Task ExecuteAsync(CancellationToken ct)
    {
        try
        {
            using var lease=new FileStream(files.Resolve("service-syslog-worker.lock"),FileMode.OpenOrCreate,FileAccess.ReadWrite,FileShare.None);
            while(!ct.IsCancellationRequested)
            {
                try
                {
                    await pump.Step(ct);
                }
                catch(OperationCanceledException) when(ct.IsCancellationRequested){break;}
                catch(Exception ex){status.Message="Delivery pending: "+ex.GetType().Name;logger.LogWarning("Service syslog delivery pending ({Type}); evidence retained.",ex.GetType().Name);}
                await Task.Delay(TimeSpan.FromSeconds(5),ct);
            }
        }
        catch(OperationCanceledException) when(ct.IsCancellationRequested){}
        catch(Exception ex){status.Message="Worker blocked: "+ex.GetType().Name;logger.LogError("Service syslog worker blocked ({Type}); evidence retained.",ex.GetType().Name);}
    }
}
