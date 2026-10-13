using System.Security.Claims;
using Microsoft.AspNetCore.Antiforgery;
using Microsoft.AspNetCore.Identity;
using RansomFree;

namespace RansomFree.Server;

internal sealed record ServerSyslogSettings(long Revision,SyslogOptions Destination,bool EndpointEvents,bool CallbackHits,long? EndpointAfterSequence=null,long? CallbackAfterSequence=null){public bool ServiceHits {get;init;} public long? ServiceAfterSequence {get;init;} public bool IncludeLogOnlyEvents {get;init;}}
internal sealed record SaveServerSyslogBody(long ExpectedRevision,SyslogOptions Destination,bool EndpointEvents,bool CallbackHits,string AdministratorPassword,string? Code=null,string? RecoveryCode=null){public bool ServiceHits {get;init;} public bool IncludeLogOnlyEvents {get;init;}}
internal sealed record ServerEventSyslogProgress(long Sequence);
internal sealed class EndpointSyslogDeliveryStatus
{
    public string Message {get;set;}="Disabled";
    public long LastSentSequence {get;set;}
}
public sealed partial class Store
{
    public long LatestEventSequence(){using var c=Open();using var cmd=Command(c,null,"SELECT COALESCE(MAX(sequence),0) FROM events");return Convert.ToInt64(cmd.ExecuteScalar());}
    public string EventMachine(string endpoint){using var c=Open();using var cmd=Command(c,null,"SELECT machine FROM endpoints WHERE id=$id",("$id",endpoint));return cmd.ExecuteScalar() as string??"Unknown endpoint";}
}
internal sealed class ServerSyslogConfiguration(ProtectedNotificationFiles files,IConfiguration configuration)
{
    private readonly object gate=new();
    public ServerSyslogSettings Read()
    {
        lock(gate)
        {
            var legacy=configuration.GetSection("Callbacks:Syslog").Get<SyslogOptions>()??new();
            var saved=files.Read<ServerSyslogSettings>("server-syslog-settings.protected")??new(0,legacy,false,legacy.Enabled,null,legacy.Enabled?0:null);
            Validate(saved);return saved;
        }
    }
    private static void Validate(ServerSyslogSettings settings)
    {
        if(settings.Revision<0||settings.EndpointAfterSequence is <0||settings.CallbackAfterSequence is <0||settings.ServiceAfterSequence is <0||settings.Destination==null)throw new ArgumentException("Invalid server syslog configuration.");
        if(settings.Destination.Enabled)
        {
            settings.Destination.Validate();
            if(!settings.EndpointEvents&&!settings.CallbackHits&&!settings.ServiceHits)throw new ArgumentException("Select an alert source.");
        }
    }
    public ServerSyslogSettings Save(SaveServerSyslogBody body,Store store,CallbackConfiguration callbacks)
    {
        lock(gate)
        {
            var old=Read();if(old.Revision!=body.ExpectedRevision)throw new NotificationSettingsConflictException();
            if(body.Destination?.Enabled==true&&body.CallbackHits&&callbacks.Storage==null)throw new ArgumentException("Callback storage is not configured.");
            var next=new ServerSyslogSettings(checked(old.Revision+1),body.Destination!,body.EndpointEvents,body.CallbackHits,
                old.EndpointAfterSequence??(body.Destination?.Enabled==true&&body.EndpointEvents?store.LatestEventSequence():null),
                old.CallbackAfterSequence??(body.Destination?.Enabled==true&&body.CallbackHits?callbacks.Storage?.LatestSequence():null))
                {ServiceHits=body.ServiceHits,IncludeLogOnlyEvents=body.IncludeLogOnlyEvents,ServiceAfterSequence=old.ServiceAfterSequence??(body.Destination?.Enabled==true&&body.ServiceHits?store.LatestServiceSequence():null)};
            Validate(next);files.Write("server-syslog-settings.protected",next);return next;
        }
    }
}
internal sealed class EndpointSyslogRelay(Store store,ServerSyslogConfiguration configuration,ProtectedNotificationFiles files,EndpointSyslogDeliveryStatus status,ILogger<EndpointSyslogRelay> logger):BackgroundService
{
    protected override async Task ExecuteAsync(CancellationToken ct)
    {
        FileStream? lease=null;
        try
        {
            lease=new FileStream(files.Resolve("endpoint-syslog-worker.lock"),FileMode.OpenOrCreate,FileAccess.ReadWrite,FileShare.None);
            while(!ct.IsCancellationRequested)
            {
                try
                {
                    var settings=configuration.Read();var progress=files.Read<ServerEventSyslogProgress>("endpoint-syslog-progress.protected")??new(0);
                    if(progress.Sequence<0)throw new InvalidDataException("Invalid endpoint syslog checkpoint; original preserved.");
                    status.LastSentSequence=progress.Sequence;
                    if(!settings.Destination.Enabled||!settings.EndpointEvents)status.Message="Disabled; server relay pending events retained";
                    else
                    {
                        if(settings.EndpointAfterSequence is null)throw new InvalidDataException("Endpoint syslog activation checkpoint missing.");
                        if(progress.Sequence<settings.EndpointAfterSequence){progress=new(settings.EndpointAfterSequence.Value);files.Write("endpoint-syslog-progress.protected",progress);}
                        foreach(var stored in store.Events(progress.Sequence,100))
                        {
                            settings=configuration.Read();if(!settings.Destination.Enabled||!settings.EndpointEvents)break;
                            var e=stored.Event;
                            var logOnly=store.ClassifyTrust(stored)==TrustEventClassification.LogOnly;
                            if(logOnly&&!settings.IncludeLogOnlyEvents)
                            {
                                progress=new(stored.Sequence);files.Write("endpoint-syslog-progress.protected",progress);status.LastSentSequence=progress.Sequence;
                                status.Message="Whitelisted event retained in history; alert forwarding suppressed";continue;
                            }
                            var alert=new Alert(e.ObservedUtc.UtcDateTime,e.Operation,e.Path,e.Process??"Unavailable",e.User??"Unavailable",e.Source)
                            {
                                EventId=e.EventId,Machine=store.EventMachine(stored.EndpointId),EndpointId=stored.EndpointId,EventSequence=stored.Sequence,ProcessId=e.ProcessId,Attribution=e.Attribution,Forensics=e.Forensics,
                                Trust=e.Trust,PolicySyslogSeverity=logOnly||e.Source is "Forensic enrichment" or "Evidence transfer"?6:store.TrustSyslogSeverity(stored),
                                ForwardedBy=Environment.MachineName,CanaryName=e.Path.Split('\\','/').LastOrDefault()??e.Path,Detail=logOnly?"Server relay of whitelisted log-only evidence; no alert requested":"Server relay of endpoint-reported evidence",
                                NotificationSuppressed=logOnly
                            };
                            status.Message=await SyslogClient.SendAsync(alert,settings.Destination,ct);
                            progress=new(stored.Sequence);files.Write("endpoint-syslog-progress.protected",progress);status.LastSentSequence=progress.Sequence;
                        }
                    }
                }
                catch(OperationCanceledException) when(ct.IsCancellationRequested){break;}
                catch(Exception ex){status.Message="Delivery pending: "+ex.GetType().Name;logger.LogWarning("Server endpoint syslog relay failed ({Type}); source events retained.",ex.GetType().Name);}
                try{await Task.Delay(TimeSpan.FromSeconds(5),ct);}catch(OperationCanceledException) when(ct.IsCancellationRequested){break;}
            }
        }
        catch(Exception ex) when(ex is not OperationCanceledException){status.Message="Worker blocked: "+ex.GetType().Name;logger.LogError("Server syslog relay unavailable ({Type}).",ex.GetType().Name);}
        finally{lease?.Dispose();}
    }
}
internal static class ServerSyslogApi
{
    public static void MapServerSyslog(this WebApplication app)
    {
        var group=app.MapGroup("/api/v1/console/server-syslog").RequireAuthorization(p=>p.RequireRole("Administrator"));
        group.MapGet("",(ServerSyslogConfiguration configuration,CallbackDeliveryStatus callbacks,EndpointSyslogDeliveryStatus endpoints,ServiceSyslogStatus services)=>Results.Ok(new{settings=configuration.Read(),callbacks=new{callbacks.Message,callbacks.LastSentSequence},endpoints=new{endpoints.Message,endpoints.LastSentSequence},services=new{services.Message,services.LastSentSequence}}));
        group.MapPost("",async(HttpContext c,IAntiforgery csrf,SaveServerSyslogBody body,ServerSyslogConfiguration configuration,CallbackConfiguration callbacks,Store store,UserManager<LocalUser> users,SignInManager<LocalUser> signIn,AuthDb db)=>
        {
            if(!await NotificationAuthorization.Check(c,csrf,body.AdministratorPassword,body.Code,body.RecoveryCode,users,signIn,db))return Results.Unauthorized();
            try
            {
                store.CallbackAudit("Server syslog change requested",c.User.FindFirstValue(ClaimTypes.NameIdentifier)!,body.ExpectedRevision.ToString());
                var saved=configuration.Save(body,store,callbacks);store.CallbackAudit("Server syslog saved",c.User.FindFirstValue(ClaimTypes.NameIdentifier)!,saved.Revision.ToString());return Results.Ok(saved);
            }
            catch(NotificationSettingsConflictException){return Results.Conflict(new{error="Syslog settings changed. Refresh before saving."});}
            catch(ArgumentException ex){return Results.BadRequest(new{error=ex.Message});}
        });
    }
}
