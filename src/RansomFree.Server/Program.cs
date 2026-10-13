using System.Net;
using System.Security.Cryptography;
using System.Text;
using System.Threading.RateLimiting;
using RansomFree.Contracts;
using RansomFree.Server;

var builder=WebApplication.CreateBuilder(new WebApplicationOptions {Args=args,ContentRootPath=AppContext.BaseDirectory});
if(!builder.Environment.IsDevelopment())throw new InvalidOperationException("Enterprise identity and deployment gates are not implemented yet. This server build is restricted to Development and must not be exposed publicly.");
var admin=builder.Configuration["RF_ADMIN_KEY"];
if(admin is null || admin.Length!=64 || !admin.All(Uri.IsHexDigit))throw new InvalidOperationException("Set RF_ADMIN_KEY to an independently generated random 32-byte hex secret. No default administrator credential exists.");
var directory=builder.Configuration["RF_DATA_DIR"] ?? throw new InvalidOperationException("Set RF_DATA_DIR to a private local directory owned by the server account.");
var lab=builder.Environment.IsDevelopment() && builder.Configuration["RF_ALLOW_LOOPBACK_HTTP"]=="true";
builder.WebHost.ConfigureKestrel(o=> {o.Limits.MaxRequestBodySize=512*1024;o.Limits.RequestHeadersTimeout=TimeSpan.FromSeconds(15);});
var database=new RansomFree.Persistence.DatabaseSettings(builder.Configuration);
builder.Services.AddSingleton(database);
builder.Services.AddSingleton(_=>new SqliteWriteAdmission(!database.SqlServer));
builder.Services.AddSingleton(_=>new Store(Path.GetFullPath(directory),database));
builder.Services.AddSingleton(sp=>new EvidenceReceiver(sp.GetRequiredService<Store>(),Path.GetFullPath(directory),
    builder.Configuration.GetValue<long>("Forensics:MaximumUploadMiB",256)*1024*1024,
    builder.Configuration.GetValue<long>("Forensics:PerSensorStoreMiB",1024)*1024*1024,
    builder.Configuration.GetValue<long>("Forensics:TotalStoreMiB",10240)*1024*1024));
builder.Services.AddSingleton(_=>new CallbackConfiguration(builder.Configuration));
builder.Services.AddSingleton<CallbackDeliveryStatus>();
builder.Services.AddHostedService<CallbackSyslog>();
builder.Services.AddSingleton<ProtectedNotificationFiles>();
builder.Services.AddSingleton<NativePolicySigner>();
builder.Services.AddSingleton<CallbackEmailConfiguration>();
builder.Services.AddSingleton<CallbackEmailStatus>();
builder.Services.AddSingleton<CallbackEmailSender>();
builder.Services.AddSingleton<IEmailTransport>(sp=>sp.GetRequiredService<CallbackEmailSender>());
builder.Services.AddSingleton<ServiceEmailStatus>();
builder.Services.AddSingleton<ServiceEmailPump>();
builder.Services.AddHostedService<ServiceEmailWorker>();
builder.Services.AddHostedService<CallbackEmailWorker>();
builder.Services.AddSingleton<ServerSyslogConfiguration>();
builder.Services.AddSingleton<EndpointSyslogDeliveryStatus>();
builder.Services.AddHostedService<EndpointSyslogRelay>();
builder.Services.AddSingleton<ServiceSyslogStatus>();
builder.Services.AddSingleton<IServiceSyslogTransport,ServiceSyslogTransport>();
builder.Services.AddSingleton<ServiceSyslogPump>();
builder.Services.AddHostedService<ServiceSyslogRelay>();
builder.Services.AddHostedService<ReportScheduler>();
builder.AddHumanIdentity(Path.GetFullPath(directory),lab);
builder.AddSingleSignOn();
builder.Services.AddSingleton(new DirectorySessionValidator(builder.Configuration));
builder.Services.AddSingleton<OperationsState>();
builder.Services.AddHostedService<OperationsProbe>();
builder.Services.AddRateLimiter(o=>
{
    o.RejectionStatusCode=429;
    o.GlobalLimiter=ServerRequestLimits.Create(
        builder.Configuration.GetValue("RequestLimits:ReportingPerMinute",600),
        builder.Configuration.GetValue("RequestLimits:ArtifactPerMinute",600));
});
var app=builder.Build();
if(args.Contains("--initialize-native-policy-signing"))
{
    if(args.Length!=1)throw new ArgumentException("Run native policy key initialization as a separate local maintenance command");
    Console.WriteLine(System.Text.Json.JsonSerializer.Serialize(app.Services.GetRequiredService<NativePolicySigner>().Initialize()));
    await app.DisposeAsync();return;
}
if(args.Contains("--migrate-database")&&args.Contains("--import-sqlite"))throw new ArgumentException("Run schema migration and data import as separate maintenance steps.");
if(args.Contains("--migrate-database"))
{
    await DatabaseMigration.ApplyAsync(app,database);
    Console.WriteLine("Schema migrations applied. No application listeners or workers were started.");
    await app.DisposeAsync();return;
}
if(args.Contains("--import-sqlite"))
{
    SqliteImport.Run(database,builder.Configuration,args);
    Console.WriteLine("Selected components imported. Preserve the original identity key ring and callback syslog checkpoint before cutover; no listeners were started.");
    await app.DisposeAsync();return;
}
await app.InitializeIdentityAsync();
app.Use(async(ctx,next)=>
{
    ctx.Response.Headers.CacheControl="no-store";ctx.Response.Headers.XContentTypeOptions="nosniff";
    var ssoOrigins=string.Join(' ',app.Services.GetRequiredService<SsoConfiguration>().Providers.Select(p=>new Uri(p.Authority).GetLeftPart(UriPartial.Authority)).Distinct());
    ctx.Response.Headers.ContentSecurityPolicy="default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self' "+ssoOrigins;
    ctx.Response.Headers["Referrer-Policy"]="no-referrer";
    if(!ctx.Request.IsHttps && !(lab && ctx.Connection.RemoteIpAddress is { } ip && IPAddress.IsLoopback(ip))) {ctx.Response.StatusCode=400;return;}
    try{await next(ctx);}catch(DirectoryUnavailableException)
    {
        ctx.Response.StatusCode=503;await ctx.Response.WriteAsJsonAsync(new {error="Directory sign-in is unavailable. Contact your administrator."});
    }
    catch(EventConflictException)
    {
        ctx.Response.StatusCode=409;await ctx.Response.WriteAsJsonAsync(new {error="An event ID was reused with different content. Batch not accepted."});
    }
    catch(Exception ex) when(ex is not OperationCanceledException)
    {
        if(ex is Microsoft.Data.Sqlite.SqliteException sqlite)
            app.Logger.LogError("Request failed ({ExceptionType}); SQLite code {DatabaseCode}/{DatabaseExtendedCode}; request ID {RequestId}",ex.GetType().Name,sqlite.SqliteErrorCode,sqlite.SqliteExtendedErrorCode,ctx.TraceIdentifier);
        else
            app.Logger.LogError("Request failed ({ExceptionType}); request ID {RequestId}",ex.GetType().Name,ctx.TraceIdentifier);
        if(!ctx.Response.HasStarted){ctx.Response.StatusCode=500;await ctx.Response.WriteAsJsonAsync(new {error="Request failed",requestId=ctx.TraceIdentifier});}
    }
});
app.UseRateLimiter();
app.UseAuthentication();
app.UseDirectorySessions();
app.UseAccountRecoveryRestrictions();
app.UseAuthorization();
app.Use(async(ctx,next)=>
{
    if(SqliteWriteAdmission.IsApiWrite(ctx.Request))
        await ctx.RequestServices.GetRequiredService<SqliteWriteAdmission>().Execute(ctx,()=>next(ctx));
    else await next(ctx);
});
app.UseDefaultFiles();app.UseStaticFiles();
string? Bearer(HttpContext c)
{
    var h=c.Request.Headers.Authorization;
    return h.Count==1 && h[0] is { } s && s.StartsWith("Bearer ",StringComparison.Ordinal) && s.Length==71 && s[7..].All(Uri.IsHexDigit)?s[7..]:null;
}
bool Admin(HttpContext c)=>Bearer(c) is { } key && CryptographicOperations.FixedTimeEquals(Encoding.UTF8.GetBytes(key),Encoding.UTF8.GetBytes(admin));
app.MapHumanIdentity(Admin);
app.MapEvidenceTransfer(c=>Bearer(c) is {} token?c.RequestServices.GetRequiredService<Store>().Authenticate(token):null,Admin);
app.MapAccountAdministration();
app.MapSingleSignOn();
app.MapOrganizationSecurity();
app.MapAccountRecovery();
app.MapReports();
app.MapReportSchedules();
app.MapEndpointAdministration();
app.MapIncidents();
app.MapIncidentExports();
app.MapIncidentAssignment();
app.MapCallbacks();
app.MapCallbackEmail();
app.MapServerSyslog();
app.MapOperationsHealth();
app.MapPolicies(c=>Bearer(c) is { } token?c.RequestServices.GetRequiredService<Store>().Authenticate(token):null);
app.MapTrustGovernance(c=>Bearer(c) is { } token?c.RequestServices.GetRequiredService<Store>().Authenticate(token):null);
app.MapNativePolicy(c=>Bearer(c) is {} token?c.RequestServices.GetRequiredService<Store>().Authenticate(token):null,Admin);
app.MapDecoyServices();
app.MapDecoyJobs(c=>Bearer(c) is { } token?c.RequestServices.GetRequiredService<Store>().Authenticate(token):null);
app.MapResponseCommands(c=>Bearer(c) is { } token?c.RequestServices.GetRequiredService<Store>().Authenticate(token):null);
app.MapActiveResponsePreview();
bool Text(string? s,int max)=>!string.IsNullOrWhiteSpace(s) && s.Length<=max && !s.Any(char.IsControl);
app.MapGet("/health/live",()=>Results.Ok(new {status="alive",apiVersion=1,
    serverVersion=typeof(Store).Assembly.GetCustomAttributes(typeof(System.Reflection.AssemblyInformationalVersionAttribute),false)
        .OfType<System.Reflection.AssemblyInformationalVersionAttribute>().Single().InformationalVersion.Split('+')[0]}));
app.MapPost("/api/v1/admin/enrollment-codes",(HttpContext c,Store s)=>Admin(c)?Results.Ok(s.CreateCode()):Results.Unauthorized());
app.MapGet("/api/v1/admin/endpoints",(HttpContext c,Store s)=>Admin(c)?Results.Ok(s.Inventory()):Results.Unauthorized());
app.MapPost("/api/v1/admin/endpoints/{id}/revoke",(string id,HttpContext c,Store s)=>!Admin(c)?Results.Unauthorized():s.Revoke(id)?Results.NoContent():Results.NotFound());
app.MapGet("/api/v1/admin/events",(HttpContext c,Store s,long after=0,int limit=100)=>!Admin(c)?Results.Unauthorized():after<0 || limit is <1 or >500?Results.BadRequest():Results.Ok(s.Events(after,limit)));
app.MapGet("/api/v1/admin/event-history",async(HttpContext c,Store s,Microsoft.AspNetCore.DataProtection.IDataProtectionProvider protection)=>!Admin(c)?Results.Unauthorized():await EventHistoryApi.Handle(c,s,protection,"bootstrap-admin"));
app.MapPost("/api/v1/enroll",(EnrollmentRequest r,Store s)=>
{
    if(!Text(r.Code,64) || r.Code.Length!=64 || !r.Code.All(Uri.IsHexDigit) || !Text(r.MachineName,255) || !Text(r.AgentVersion,64))return Results.BadRequest();
    var result=s.Enroll(r);return result is null?Results.Unauthorized():Results.Ok(result);
});
app.MapPost("/api/v1/agent/heartbeat",(HttpContext c,HeartbeatRequest r,Store s)=>
{
    var id=Bearer(c) is { } token?s.Authenticate(token):null;if(id is null)return Results.Unauthorized();
    if(!Text(r.AgentVersion,64) || !Text(r.Health,512)||r.OperatingSystem is not (null or "windows" or "linux" or "macos" or "unknown")||r.Protection!=null&&!r.Protection.IsValid())return Results.BadRequest();
    if(!s.Heartbeat(id,r,c.Connection.RemoteIpAddress))return Results.Unauthorized();
    return Results.NoContent();
});
app.MapPost("/api/v1/agent/capabilities",(HttpContext c,Store s)=>Bearer(c) is {} token&&s.Authenticate(token)!=null?Results.Ok(new{AttributionVersion=1,WindowsSyscallVersion=1,TrustVersion=1,WhitelistVersion=1,LinuxKernelTrustVersion=1,LinuxNativeHashTrustVersion=1,LinuxPermissionPairVersion=1,ForensicsVersion=1,EvidenceUploadVersion=1,WindowsKernelVersion=8,WindowsShareVersion=1,ActorAcquisitionVersion=1,WindowsAcquisitionObservationVersion=1,WindowsAcquisitionRecoveryVersion=1,ProcessCreationVersion=1,LinuxKernelVersion=1,LinuxKernelTargetIdentityVersion=1,LinuxPermissionObservationVersion=1,LinuxIoObservationVersion=1,LinuxActorAcquisitionVersion=1,LinuxNativeWorkVersion=2}):Results.Unauthorized());
app.MapPost("/api/v1/agent/events",(HttpContext c,EventBatch batch,Store s)=>
{
    var id=Bearer(c) is { } token?s.Authenticate(token):null;if(id is null)return Results.Unauthorized();
    if(batch.Events is null || batch.Events.Length is <1 or >100 || batch.Events.Any(e=>e is null || !Guid.TryParseExact(e.EventId,"N",out _) || !Text(e.Operation,512) || !Text(e.Path,4096) || !Text(e.Source,100) || e.User?.Length>512 || e.Process?.Length>1024 || e.ProcessId is <0 || e.ObservedUtc>DateTimeOffset.UtcNow.AddMinutes(5)))return Results.BadRequest();
    if(batch.Events.Any(e=>e.Attribution!=null&&!e.Attribution.IsValid()))return Results.BadRequest();
    if(batch.Events.Any(e=>!WindowsKernelEvidence.Matches(e)))return Results.BadRequest();
    if(batch.Events.Any(e=>!WindowsSyscallObservation.Matches(e)))return Results.BadRequest();
    if(batch.Events.Any(e=>!WindowsShareEvidence.Matches(e)))return Results.BadRequest();
    if(batch.Events.Any(e=>!LinuxKernelEvidence.Matches(e)))return Results.BadRequest();
    if(batch.Events.Any(e=>e.Forensics!=null&&(!e.Forensics.IsValid()||e.Forensics.EventId!=e.EventId||e.Forensics.SensorId!=id)))return Results.BadRequest();
    if(batch.Events.Any(e=>e.Trust!=null&&!e.Trust.IsValid()))return Results.BadRequest();
    if(batch.Events.Any(e=>e.ServiceContext!=null||e.Source is "Server service decoy" or "Evidence transfer"||e.Forensics?.Transfer!=null))return Results.BadRequest();
    var receipt=s.Ingest(id,batch,c.Connection.RemoteIpAddress);return receipt is null?Results.Unauthorized():Results.Ok(receipt with{AttributionVersion=1,WindowsSyscallVersion=1,TrustVersion=1,WhitelistVersion=1,LinuxKernelTrustVersion=1,LinuxNativeHashTrustVersion=1,LinuxPermissionPairVersion=1,ForensicsVersion=1,WindowsKernelVersion=8,WindowsShareVersion=1,ActorAcquisitionVersion=1,WindowsAcquisitionObservationVersion=1,WindowsAcquisitionRecoveryVersion=1,ProcessCreationVersion=1,LinuxKernelVersion=1,LinuxKernelTargetIdentityVersion=1,LinuxPermissionObservationVersion=1,LinuxIoObservationVersion=1,LinuxActorAcquisitionVersion=1,LinuxNativeWorkVersion=2});
});
app.Run();
