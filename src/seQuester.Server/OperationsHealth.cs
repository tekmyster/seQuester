using Microsoft.EntityFrameworkCore;

namespace RansomFree.Server;

public sealed record OperationCheck(string Component,string State,string Detail);
public sealed record OperationsSnapshot(DateTimeOffset CheckedUtc,bool StorageReadable,bool ProductionReady,OperationCheck[] Checks);
internal sealed class OperationsState
{
    private OperationsSnapshot current=new(DateTimeOffset.MinValue,false,false,[new("Management","Unknown","Initial checks pending")]);
    public OperationsSnapshot Current=>Volatile.Read(ref current);
    public void Set(OperationsSnapshot value)=>Volatile.Write(ref current,value);
}
public sealed partial class Store
{
    public (long Endpoints,long Events,long Reports,long OpenResponses) OperationalCounts()
    {
        using var c=Open();using var t=c.BeginTransaction(System.Data.IsolationLevel.Serializable);
        long Count(string sql){using var cmd=Command(c,t,sql);return Convert.ToInt64(cmd.ExecuteScalar());}
        var result=(Count("SELECT COUNT(*) FROM endpoints WHERE revoked=0"),Count("SELECT COUNT(*) FROM events"),Count("SELECT COUNT(*) FROM reports"),Count("SELECT COUNT(*) FROM response_commands WHERE status IN ('Pending','Offered')"));
        t.Commit();return result;
    }
}
internal sealed class OperationsProbe(Store store,IServiceScopeFactory scopes,CallbackConfiguration callbacks,CallbackDeliveryStatus delivery,CallbackEmailStatus email,EndpointSyslogDeliveryStatus endpointSyslog,DirectorySessionValidator directory,IConfiguration config,OperationsState state):BackgroundService
{
    protected override async Task ExecuteAsync(CancellationToken ct)
    {
        using var timer=new PeriodicTimer(TimeSpan.FromSeconds(30));
        try
        {
            do
            {
                var checks=new List<OperationCheck>();var readable=true;
                try
                {
                    var counts=store.OperationalCounts();
                    checks.Add(new("Management storage","Readable",$"{counts.Endpoints} active endpoints; {counts.Events} retained events; {counts.Reports} reports; {counts.OpenResponses} requests without a final state (may include expired requests)"));
                }
                catch(Exception ex){readable=false;checks.Add(new("Management storage","Unavailable",ex.GetType().Name));}
                try
                {
                    using var scope=scopes.CreateScope();var db=scope.ServiceProvider.GetRequiredService<AuthDb>();
                    if(!await db.Database.CanConnectAsync(ct)){readable=false;checks.Add(new("Identity storage","Unavailable","Database connection failed"));}
                    else checks.Add(new("Identity storage","Readable","Connection succeeded; this is not a write or recovery check"));
                }
                catch(OperationCanceledException) when(ct.IsCancellationRequested){break;}
                catch(Exception ex){readable=false;checks.Add(new("Identity storage","Unavailable",ex.GetType().Name));}
                if(callbacks.Storage==null)checks.Add(new("Callback storage","Unconfigured","Callback receiver integration is disabled"));
                else
                {
                    try{callbacks.Storage.Hits(0,1);checks.Add(new("Callback inbox","Readable","Inbox query succeeded; receiver listeners, DNS and SMTP routing are not verified"));}
                    catch(Exception ex){readable=false;checks.Add(new("Callback inbox","Unavailable",ex.GetType().Name));}
                }
                checks.Add(new("Callback syslog","Reported",delivery.Message+"; checkpoint "+delivery.LastSentSequence+". Transport sends do not prove Wazuh persistence."));
                checks.Add(new("Endpoint syslog relay","Reported",endpointSyslog.Message+"; checkpoint "+endpointSyslog.LastSentSequence+". Direct client syslog is configured separately in Policies."));
                checks.Add(new("Callback email",email.Current.State,email.Current.Message+"; checkpoint "+email.Current.LastCompletedSequence+". SMTP acceptance is not mailbox delivery."));
                checks.Add(new("Directory sessions",directory.Enabled?"Configured":"Disabled",directory.Enabled?$"LDAPS revalidation; cache up to {directory.MaximumCacheSeconds} seconds; role restrictions {(directory.RoleRestrictions?"configured":"off")}. Connectivity not probed.":"Existing directory sessions are not rechecked against AD; enable before a directory-backed production deployment."));
                checks.Add(new("Storage topology",store.Provider,store.Provider=="SqlServer"?"SQL Server configured; worker HA, scale and recovery acceptance remain unfinished":"Single-node SQLite development storage; SQL Server is available by explicit configuration/migration"));
                checks.Add(new("Identity key protection",OperatingSystem.IsWindows()||!string.IsNullOrEmpty(config["IdentityKeys:CertificatePath"])?"Configured":"Unconfigured",OperatingSystem.IsWindows()?"Windows DPAPI or configured certificate; recovery not tested":!string.IsNullOrEmpty(config["IdentityKeys:CertificatePath"])?"Certificate configured; recovery not tested":"Linux identity keys require a configured encryption certificate"));
                checks.Add(new("Release","Not approved","Unsigned development build; functional, regression and UI/runtime testing deferred"));
                state.Set(new(DateTimeOffset.UtcNow,readable,false,checks.ToArray()));
            }while(await timer.WaitForNextTickAsync(ct));
        }
        catch(OperationCanceledException) when(ct.IsCancellationRequested){}
    }
}
internal static class OperationsHealth
{
    public static void MapOperationsHealth(this WebApplication app)
    {
        app.MapGet("/api/v1/console/operations",(OperationsState state)=>Results.Ok(state.Current))
            .RequireAuthorization(p=>p.RequireRole("Administrator","Operator","Reader"));
    }
}
