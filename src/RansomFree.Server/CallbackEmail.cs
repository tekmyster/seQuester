using System.Net;
using System.Net.Mail;
using System.Security.Claims;
using System.Text;
using System.Text.Json;
using Microsoft.AspNetCore.Antiforgery;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.Identity;
using RansomFree.Callbacks;

namespace RansomFree.Server;

// Outbound management email is separate from the inbound SMTP canary sink.
internal sealed record CallbackEmailSettings
{
    public long Revision {get;init;}
    public bool Enabled {get;init;}
    public string Host {get;init;}="";
    public int Port {get;init;}=587;
    public string From {get;init;}="";
    public string[] Recipients {get;init;}=[];
    public string Username {get;init;}="";
    public string Password {get;init;}="";
    public string SubjectPrefix {get;init;}="[seQuester]";
    public int MinimumIntervalSeconds {get;init;}=10;
    public long? StartAfterSequence {get;init;}
    public bool ServiceHits {get;init;}
    public long? ServiceStartAfterSequence {get;init;}
    public CallbackEmailSettings Validate(bool requireConfigured=false)
    {
        if(Revision<0 || StartAfterSequence is <0 || ServiceStartAfterSequence is <0 || Host==null || Host.Length>253 || Host.Any(char.IsWhiteSpace) || Host.Any(char.IsControl) ||
           Port is <1 or >65535 || Username==null || Username.Length>256 || Username.Any(char.IsControl) || Password==null || Password.Length>4096 || Password.Any(c=>c is '\r' or '\n' or '\0') ||
           From==null || Recipients==null || Recipients.Length>20 || SubjectPrefix==null || SubjectPrefix.Length>80 || SubjectPrefix.Any(char.IsControl) || MinimumIntervalSeconds is <1 or >300)
            throw new ArgumentException("Invalid email settings or field limits.");
        static bool Address(string? s)=>s is {Length:>0 and <=254} && !s.Any(char.IsWhiteSpace) && !s.Any(char.IsControl) && MailAddress.TryCreate(s,out var a) && a.Address==s && s.Contains('@');
        if(From.Length>0&&!Address(From) || Recipients.Any(s=>!Address(s)) || Recipients.Distinct(StringComparer.OrdinalIgnoreCase).Count()!=Recipients.Length)
            throw new ArgumentException("Use distinct, plain email addresses without display names (maximum 20 recipients).");
        if(Host.Length>0&&Uri.CheckHostName(Host)==UriHostNameType.Unknown)throw new ArgumentException("SMTP host must be a hostname or IP address, not a URL.");
        if((Enabled||requireConfigured) && (Host.Length==0 || From.Length==0 || Recipients.Length==0 || Username.Length>0&&Password.Length==0))
            throw new ArgumentException("Configure the SMTP host, sender, recipients and password when authenticated SMTP is selected.");
        if(Username.Length==0&&Password.Length>0)throw new ArgumentException("A stored SMTP password requires a username; clear it to use a restricted unauthenticated relay.");
        return this;
    }
    public object Public()=>new{Revision,Enabled,Host,Port,From,Recipients,Username,HasPassword=Password.Length>0,SubjectPrefix,MinimumIntervalSeconds,Security="STARTTLS required",StartAfterSequence,ServiceHits,ServiceStartAfterSequence};
}
internal sealed record SaveCallbackEmailBody(long ExpectedRevision,bool Enabled,string Host,int Port,string From,string[] Recipients,string Username,string? Password,bool ClearPassword,string SubjectPrefix,int MinimumIntervalSeconds,string AdministratorPassword,string? Code=null,string? RecoveryCode=null){public bool ServiceHits {get;init;}}
internal sealed record TestCallbackEmailBody(string AdministratorPassword,string? Code=null,string? RecoveryCode=null);
internal sealed record EmailProgress(long Sequence=0,long? PendingSequence=null,string[]? AcceptedRecipients=null);
internal sealed record EmailDeliverySnapshot(string State,string Message,long LastCompletedSequence,long? PendingSequence,DateTimeOffset? LastAcceptedUtc=null);
internal sealed class CallbackEmailStatus
{
    private EmailDeliverySnapshot current=new("Disabled","Email delivery is disabled",0,null);
    public EmailDeliverySnapshot Current=>Volatile.Read(ref current);
    public void Set(EmailDeliverySnapshot value)=>Volatile.Write(ref current,value);
}
internal sealed class ProtectedNotificationFiles
{
    private readonly string directory;
    private readonly IDataProtector protector;
    public ProtectedNotificationFiles(IConfiguration configuration,IDataProtectionProvider protection)
    {
        directory=configuration["RF_DATA_DIR"]??throw new InvalidOperationException("Private server state is required.");
        if(!Path.IsPathFullyQualified(directory))throw new InvalidOperationException("Server state path must be absolute.");
        Check(directory);Directory.CreateDirectory(directory);protector=protection.CreateProtector("RansomFree.Notifications.v1");
    }
    private static void Check(string file)
    {
        for(string? p=Path.GetFullPath(file);p!=null;p=Path.GetDirectoryName(p))
            if((File.Exists(p)||Directory.Exists(p))&&(File.GetAttributes(p)&FileAttributes.ReparsePoint)!=0)throw new IOException("Notification state must not traverse links.");
    }
    public string Resolve(string name){var file=Path.Combine(directory,name);Check(file);return file;}
    public T? Read<T>(string name)
    {
        var file=Resolve(name);if(!File.Exists(file))return default;
        if(new FileInfo(file).Length>131072)throw new InvalidDataException("Notification state exceeds its bound; original file preserved.");
        return JsonSerializer.Deserialize<T>(protector.CreateProtector(name).Unprotect(File.ReadAllText(file)))??throw new InvalidDataException("Invalid protected notification state; original file preserved.");
    }
    public void Write<T>(string name,T state)
    {
        var file=Resolve(name);var temporary=file+"."+Guid.NewGuid().ToString("N")+".tmp";
        var bytes=Encoding.UTF8.GetBytes(protector.CreateProtector(name).Protect(JsonSerializer.Serialize(state)));
        if(bytes.Length>131072)throw new InvalidDataException("Notification state exceeds its bound.");
        try
        {
            using(var stream=new FileStream(temporary,FileMode.CreateNew,FileAccess.Write,FileShare.None)){stream.Write(bytes);stream.Flush(true);}
            Check(file);File.Move(temporary,file,true);
        }
        finally{if(File.Exists(temporary))File.Delete(temporary);}
    }
}
internal sealed class CallbackEmailConfiguration(ProtectedNotificationFiles files)
{
    private readonly object gate=new();
    public CallbackEmailSettings Read(){lock(gate)return (files.Read<CallbackEmailSettings>("callback-email-settings.protected")??new()).Validate();}
    public CallbackEmailSettings Save(SaveCallbackEmailBody body,CallbackStorage? storage,Store? store=null)
    {
        lock(gate)
        {
            var old=Read();if(old.Revision!=body.ExpectedRevision)throw new NotificationSettingsConflictException();
            if(body.ClearPassword&&!string.IsNullOrEmpty(body.Password))throw new ArgumentException("Choose a new password or clear the existing password, not both.");
            if(old.Password.Length>0&&!body.ClearPassword&&string.IsNullOrEmpty(body.Password)&&
               (!string.Equals(old.Host,body.Host?.Trim(),StringComparison.OrdinalIgnoreCase)||old.Username!=body.Username?.Trim()))
                throw new ArgumentException("Re-enter or clear the SMTP password when changing its host or username.");
            if(body.Enabled&&storage==null&&!body.ServiceHits)throw new ArgumentException("Configure a token receiver or select service alerts.");
            if(body.ServiceHits&&store==null)throw new ArgumentException("Service evidence storage is required.");
            var next=new CallbackEmailSettings{Revision=checked(old.Revision+1),Enabled=body.Enabled,Host=body.Host?.Trim()!,Port=body.Port,From=body.From?.Trim()!,Recipients=body.Recipients?.Select(s=>s?.Trim()!).ToArray()!,Username=body.Username?.Trim()!,
                Password=body.ClearPassword?"":string.IsNullOrEmpty(body.Password)?old.Password:body.Password,SubjectPrefix=body.SubjectPrefix,MinimumIntervalSeconds=body.MinimumIntervalSeconds,
                StartAfterSequence=old.StartAfterSequence??(body.Enabled?storage?.LatestSequence():null),ServiceHits=body.ServiceHits,
                ServiceStartAfterSequence=old.ServiceStartAfterSequence??(body.Enabled&&body.ServiceHits?store!.LatestServiceSequence():null)}.Validate();
            files.Write("callback-email-settings.protected",next);return next;
        }
    }
}
internal sealed class NotificationSettingsConflictException:Exception;
internal static class CallbackEmailMessage
{
    public static string Subject(CallbackEmailSettings settings,CallbackToken? token,string transport)=>$"{settings.SubjectPrefix} Canary triggered: {token?.Name??"Unknown token"} ({transport})";
    public static string Body(CallbackToken? token,CallbackHit hit)=>$"""
seQuester | Quiver - Canary triggered

Canary: {token?.Name??"Unknown token"}
Type: {token?.Type??"Unknown"}
Location: {Value(token?.Location)}
Description: {Value(token?.Description)}
Note: {Value(token?.Note)}

Received (UTC): {DateTimeOffset.FromUnixTimeMilliseconds(hit.Received):yyyy-MM-dd HH:mm:ss.fff 'UTC'}
Transport: {hit.Transport}
Source address: {hit.SourceAddress}
Trigger detail (untrusted): {hit.Detail}
Token ID: {hit.TokenId}
Callback sequence: {hit.Sequence}

Review this sequence in Management > Canary tokens > Callback activity.
Location, description and note are administrator-entered context, not a verified current file location.
This is passive network evidence, not proof of copying, malicious intent, a Windows username or a process ID.
The source can be a proxy, resolver, scanner or mail server. No process-stop authority is implied.
Repeated same token/source/transport requests are coalesced by the receiver for 60 seconds.
""";
    private static string Value(string? value)=>string.IsNullOrWhiteSpace(value)?"Not provided":value;
}
internal interface IEmailTransport {Task Send(CallbackEmailSettings settings,string recipient,string subject,string body,CancellationToken ct);}
internal sealed class CallbackEmailSender:IEmailTransport
{
    private readonly SemaphoreSlim gate=new(1,1);
    private DateTimeOffset nextSend;
    public async Task Send(CallbackEmailSettings settings,string recipient,string subject,string body,CancellationToken ct)
    {
        settings.Validate(true);await gate.WaitAsync(ct);
        try
        {
            var wait=nextSend-DateTimeOffset.UtcNow;if(wait>TimeSpan.Zero)await Task.Delay(wait,ct);
            using var deadline=CancellationTokenSource.CreateLinkedTokenSource(ct);deadline.CancelAfter(TimeSpan.FromSeconds(30));
            using var message=new MailMessage{From=new MailAddress(settings.From),Subject=subject,Body=body,IsBodyHtml=false,SubjectEncoding=Encoding.UTF8,BodyEncoding=Encoding.UTF8};
            message.To.Add(new MailAddress(recipient));message.Headers.Add("Auto-Submitted","auto-generated");
            // Mandatory STARTTLS with normal certificate validation; no plaintext or TLS bypass.
            using var client=new SmtpClient(settings.Host,settings.Port){EnableSsl=true,UseDefaultCredentials=false,DeliveryMethod=SmtpDeliveryMethod.Network};
            if(settings.Username.Length>0)client.Credentials=new NetworkCredential(settings.Username,settings.Password);
            await client.SendMailAsync(message,deadline.Token);
        }
        finally{nextSend=DateTimeOffset.UtcNow.AddSeconds(settings.MinimumIntervalSeconds);gate.Release();}
    }
}
internal sealed class CallbackEmailWorker(CallbackConfiguration callbacks,CallbackEmailConfiguration configuration,ProtectedNotificationFiles files,CallbackEmailSender sender,CallbackEmailStatus status,ILogger<CallbackEmailWorker> logger):BackgroundService
{
    protected override async Task ExecuteAsync(CancellationToken ct)
    {
        FileStream? lease=null;
        try
        {
            lease=new FileStream(files.Resolve("callback-email-worker.lock"),FileMode.OpenOrCreate,FileAccess.ReadWrite,FileShare.None);
            while(!ct.IsCancellationRequested)
            {
                try
                {
                    var settings=configuration.Read();var progress=files.Read<EmailProgress>("callback-email-progress.protected")??new();
                    if(progress.Sequence<0 || progress.PendingSequence is <1 || progress.PendingSequence is {} pending&&pending<=progress.Sequence || progress.AcceptedRecipients is {Length:>20})throw new InvalidDataException("Invalid email progress; original state preserved.");
                    if(!settings.Enabled)status.Set(new("Disabled","Email paused; pending callbacks retained",progress.Sequence,progress.PendingSequence));
                    else if(callbacks.Storage==null)status.Set(new("Unconfigured","Callback storage is not configured",progress.Sequence,progress.PendingSequence));
                    else
                    {
                        if(settings.StartAfterSequence is null)throw new InvalidDataException("Email activation checkpoint is missing.");
                        if(progress.Sequence<settings.StartAfterSequence){progress=new(settings.StartAfterSequence.Value);files.Write("callback-email-progress.protected",progress);}
                        var hits=callbacks.Storage.Hits(progress.Sequence);
                        if(progress.PendingSequence is {} expected&&(hits.Count==0||hits[0].Sequence!=expected))throw new InvalidDataException("Pending callback is missing; restore inbox before resuming.");
                        foreach(var hit in hits)
                        {
                            settings=configuration.Read();if(!settings.Enabled)break;var token=callbacks.Storage.Get(hit.TokenId);
                            if(token is {Revoked:false,EmailAlerts:true} && hit.Sequence>token.EmailAfterSequence)
                            {
                                if(progress.PendingSequence!=hit.Sequence){progress=progress with{PendingSequence=hit.Sequence,AcceptedRecipients=[]};files.Write("callback-email-progress.protected",progress);}
                                progress=progress with{AcceptedRecipients=(progress.AcceptedRecipients??[]).Where(r=>settings.Recipients.Contains(r,StringComparer.OrdinalIgnoreCase)).ToArray()};
                                files.Write("callback-email-progress.protected",progress);
                                status.Set(new("Sending","Submitting callback email to configured relay",progress.Sequence,hit.Sequence));
                                foreach(var recipient in settings.Recipients)
                                {
                                    if(progress.AcceptedRecipients!.Contains(recipient,StringComparer.OrdinalIgnoreCase))continue;
                                    var current=configuration.Read();if(!current.Enabled||current.Revision!=settings.Revision)break;
                                    await sender.Send(settings,recipient,CallbackEmailMessage.Subject(settings,token,hit.Transport),CallbackEmailMessage.Body(token,hit),ct);
                                    progress=progress with{AcceptedRecipients=[..progress.AcceptedRecipients!,recipient]};files.Write("callback-email-progress.protected",progress);
                                    status.Set(new("Accepted","SMTP relay accepted a message; mailbox delivery is unconfirmed",progress.Sequence,hit.Sequence,DateTimeOffset.UtcNow));
                                }
                                var now=configuration.Read();if(!now.Enabled||now.Revision!=settings.Revision)break;
                                if(settings.Recipients.Any(r=>!progress.AcceptedRecipients!.Contains(r,StringComparer.OrdinalIgnoreCase)))break;
                            }
                            progress=new(hit.Sequence);files.Write("callback-email-progress.protected",progress);
                            status.Set(new("Waiting","Waiting for callback activity; checkpoint includes intentionally skipped tokens",progress.Sequence,null,status.Current.LastAcceptedUtc));
                        }
                        if(hits.Count==0)status.Set(status.Current with{State="Waiting",Message="Waiting for callback activity",LastCompletedSequence=progress.Sequence,PendingSequence=progress.PendingSequence});
                    }
                }
                catch(OperationCanceledException) when(ct.IsCancellationRequested){break;}
                catch(Exception ex){status.Set(status.Current with{State="Pending",Message="Email delivery pending: "+ex.GetType().Name+"; source and checkpoint preserved"});logger.LogWarning("Callback email failed ({Type}); content and credentials are not logged.",ex.GetType().Name);}
                try{await Task.Delay(TimeSpan.FromSeconds(status.Current.State=="Pending"?30:5),ct);}catch(OperationCanceledException) when(ct.IsCancellationRequested){break;}
            }
        }
        catch(Exception ex) when(ex is not OperationCanceledException){status.Set(new("Blocked","Email worker unavailable: "+ex.GetType().Name,0,null));logger.LogError("Callback email worker unavailable ({Type}).",ex.GetType().Name);}
        finally{lease?.Dispose();}
    }
}
internal static class NotificationAuthorization
{
    public static async Task<bool> Check(HttpContext c,IAntiforgery csrf,string password,string? code,string? recovery,UserManager<LocalUser> users,SignInManager<LocalUser> signIn,AuthDb db)
    {
        try{await csrf.ValidateRequestAsync(c);}catch(AntiforgeryValidationException){return false;}
        return await HumanIdentity.ReauthenticateAdministrator(c,password,code,recovery,users,signIn,db) && await HumanIdentity.StillAdministrator(c,db);
    }
}
internal static class CallbackEmailApi
{
    public static void MapCallbackEmail(this WebApplication app)
    {
        var group=app.MapGroup("/api/v1/console/email").RequireAuthorization(p=>p.RequireRole("Administrator"));
        group.MapGet("",(CallbackEmailConfiguration configuration,CallbackEmailStatus status,ServiceEmailStatus services)=>Results.Ok(new{settings=configuration.Read().Public(),delivery=status.Current,services=services.Current}));
        group.MapPost("",async(HttpContext c,IAntiforgery csrf,SaveCallbackEmailBody body,CallbackEmailConfiguration configuration,CallbackConfiguration callbacks,Store audit,UserManager<LocalUser> users,SignInManager<LocalUser> signIn,AuthDb db)=>
        {
            if(!await NotificationAuthorization.Check(c,csrf,body.AdministratorPassword,body.Code,body.RecoveryCode,users,signIn,db))return Results.Unauthorized();
            try
            {
                audit.CallbackAudit("Email configuration change requested",c.User.FindFirstValue(ClaimTypes.NameIdentifier)!,body.ExpectedRevision.ToString());
                var saved=configuration.Save(body,callbacks.Storage,audit);audit.CallbackAudit("Email configuration saved",c.User.FindFirstValue(ClaimTypes.NameIdentifier)!,saved.Revision.ToString());return Results.Ok(saved.Public());
            }
            catch(NotificationSettingsConflictException){return Results.Conflict(new{error="Email settings changed. Refresh before saving."});}
            catch(ArgumentException ex){return Results.BadRequest(new{error=ex.Message});}
        });
        group.MapPost("/test",async(HttpContext c,IAntiforgery csrf,TestCallbackEmailBody body,CallbackEmailConfiguration configuration,CallbackEmailSender sender,Store audit,UserManager<LocalUser> users,SignInManager<LocalUser> signIn,AuthDb db)=>
        {
            if(!await NotificationAuthorization.Check(c,csrf,body.AdministratorPassword,body.Code,body.RecoveryCode,users,signIn,db))return Results.Unauthorized();
            var settings=configuration.Read();try{settings.Validate(true);}catch(ArgumentException ex){return Results.BadRequest(new{error=ex.Message});}
            audit.CallbackAudit("Test email requested",c.User.FindFirstValue(ClaimTypes.NameIdentifier)!,settings.Revision.ToString());var accepted=0;
            try
            {
                foreach(var recipient in settings.Recipients){await sender.Send(settings,recipient,settings.SubjectPrefix+" Delivery test","Administrator-requested seQuester email delivery test. This is not a canary trigger. SMTP acceptance does not prove mailbox delivery.",c.RequestAborted);accepted++;}
                audit.CallbackAudit("Test email accepted by SMTP",c.User.FindFirstValue(ClaimTypes.NameIdentifier)!,settings.Revision.ToString());return Results.Ok(new{message="SMTP accepted the test for all configured recipients. Verify their mailboxes.",accepted});
            }
            catch(Exception ex) when(ex is not OperationCanceledException||!c.RequestAborted.IsCancellationRequested){return Results.Json(new{error="Test submission failed: "+ex.GetType().Name+". Some recipients may already have received it; verify before retrying.",accepted},statusCode:502);}
        });
    }
}
