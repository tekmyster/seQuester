namespace RansomFree.Server;

internal sealed class ServiceEmailStatus
{
    private EmailDeliverySnapshot current=new("Disabled","Service email disabled",0,null);
    public EmailDeliverySnapshot Current=>Volatile.Read(ref current);
    public void Set(EmailDeliverySnapshot next)=>Volatile.Write(ref current,next);
}
internal static class ServiceEmailMessage
{
    public static string Body(ServiceEvidence item)
    {
        var c=item.Event.ServiceContext??throw new InvalidDataException("Service context unavailable.");
        return $"seQuester — service canary triggered\n\nCanary: {c.Name}\nDescription: {c.Description}\nLocation: {c.Location}\nNote: {c.Note}\nService ID: {c.ServiceId}\nRevision: {c.Revision}\nObserved UTC: {item.Event.ObservedUtc:O}\nSource address: {c.SourceAddress}\nRequest: {c.Method}\nEvent ID: {item.Event.EventId}\n\nReview Alerts > Service details. Source address is network evidence, not a verified user or process. Context reflects the service definition at the time of the request.";
    }
}
internal sealed class ServiceEmailPump(Store store,CallbackEmailConfiguration configuration,ProtectedNotificationFiles files,IEmailTransport sender,ServiceEmailStatus status)
{
    const string StateFile="service-email-progress.protected";
    public async Task Step(CancellationToken ct)
    {
        var settings=configuration.Read();var progress=files.Read<EmailProgress>(StateFile)??new();
        if(progress.Sequence<0||progress.PendingSequence is <1||progress.PendingSequence is {} pending&&pending<=progress.Sequence||progress.AcceptedRecipients is {Length:>20})throw new InvalidDataException("Invalid service email checkpoint; preserved.");
        if(!settings.Enabled||!settings.ServiceHits){status.Set(new("Disabled","Service email paused; pending evidence retained",progress.Sequence,progress.PendingSequence));return;}
        if(settings.ServiceStartAfterSequence==null)throw new InvalidDataException("Service email activation checkpoint missing.");
        if(Math.Max(progress.Sequence,settings.ServiceStartAfterSequence.Value)>store.LatestServiceSequence())throw new InvalidDataException("Service email checkpoint exceeds available evidence; restore matching evidence and checkpoint before resuming.");
        if(progress.Sequence<settings.ServiceStartAfterSequence){progress=new(settings.ServiceStartAfterSequence.Value);files.Write(StateFile,progress);}
        var events=store.ServiceEvents(progress.Sequence);
        if(progress.PendingSequence is {} expected&&(events.Count==0||events[0].Sequence!=expected))throw new InvalidDataException("Pending service event missing; restore evidence before resuming.");
        foreach(var item in events)
        {
            settings=configuration.Read();if(!settings.Enabled||!settings.ServiceHits)break;
            var context=item.Event.ServiceContext??throw new InvalidDataException("Service context missing.");
            if(progress.PendingSequence!=item.Sequence)progress=progress with{PendingSequence=item.Sequence,AcceptedRecipients=[]};
            progress=progress with{AcceptedRecipients=(progress.AcceptedRecipients??[]).Where(r=>settings.Recipients.Contains(r,StringComparer.OrdinalIgnoreCase)).ToArray()};files.Write(StateFile,progress);
            foreach(var recipient in settings.Recipients)
            {
                if(progress.AcceptedRecipients!.Contains(recipient,StringComparer.OrdinalIgnoreCase))continue;
                var current=configuration.Read();if(!current.Enabled||!current.ServiceHits||current.Revision!=settings.Revision)return;
                status.Set(new("Sending","Submitting service email",progress.Sequence,item.Sequence));
                await sender.Send(settings,recipient,$"{settings.SubjectPrefix} Canary triggered: {context.Name}",ServiceEmailMessage.Body(item),ct);
                progress=progress with{AcceptedRecipients=[..progress.AcceptedRecipients!,recipient]};files.Write(StateFile,progress);
                status.Set(new("Accepted","SMTP relay accepted; mailbox delivery unconfirmed",progress.Sequence,item.Sequence,DateTimeOffset.UtcNow));
            }
            var latest=configuration.Read();if(!latest.Enabled||!latest.ServiceHits||latest.Revision!=settings.Revision)return;
            progress=new(item.Sequence);files.Write(StateFile,progress);status.Set(new("Waiting","Waiting for service hits",progress.Sequence,null,status.Current.LastAcceptedUtc));
        }
        if(events.Count==0)status.Set(new("Waiting","Waiting for service hits",progress.Sequence,progress.PendingSequence,status.Current.LastAcceptedUtc));
    }
}
internal sealed class ServiceEmailWorker(ProtectedNotificationFiles files,ServiceEmailPump pump,ServiceEmailStatus status,ILogger<ServiceEmailWorker> logger):BackgroundService
{
    protected override async Task ExecuteAsync(CancellationToken ct)
    {
        try
        {
            using var lease=new FileStream(files.Resolve("service-email-worker.lock"),FileMode.OpenOrCreate,FileAccess.ReadWrite,FileShare.None);
            while(!ct.IsCancellationRequested)
            {
                try{await pump.Step(ct);}
                catch(OperationCanceledException) when(ct.IsCancellationRequested){break;}
                catch(Exception ex){status.Set(status.Current with{State="Pending",Message="Service email pending: "+ex.GetType().Name});logger.LogWarning("Service email pending ({Type}); evidence retained.",ex.GetType().Name);}
                await Task.Delay(TimeSpan.FromSeconds(status.Current.State=="Pending"?30:5),ct);
            }
        }
        catch(OperationCanceledException) when(ct.IsCancellationRequested){}
        catch(Exception ex){status.Set(new("Blocked","Service email worker unavailable: "+ex.GetType().Name,0,null));logger.LogError("Service email worker unavailable ({Type}).",ex.GetType().Name);}
    }
}
