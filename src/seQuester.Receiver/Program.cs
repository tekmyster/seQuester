using System.Net;
using System.Threading.RateLimiting;
using RansomFree.Callbacks;

var builder=WebApplication.CreateBuilder(args);
// Framework information-level HTTP logs include request targets and query strings.
// Callback evidence deliberately excludes those, credentials and request bodies.
builder.Logging.AddFilter("Microsoft.AspNetCore",LogLevel.Warning);
if(!builder.Environment.IsDevelopment())throw new InvalidOperationException("Unsigned feature build. Receiver production release is gated on deferred QA.");
var directory=builder.Configuration["RF_CALLBACK_DATA"]??throw new InvalidOperationException("Set RF_CALLBACK_DATA to pre-provisioned callback storage.");
builder.Services.AddSingleton(new CallbackStorage(directory,true,new RansomFree.Persistence.DatabaseSettings(builder.Configuration)));
builder.Services.AddHostedService<DnsReceiver>();
builder.Services.AddHostedService<EmailTripwire>();
builder.WebHost.ConfigureKestrel(o=>{o.Limits.MaxRequestBodySize=8192;o.Limits.MaxConcurrentConnections=200;o.Limits.RequestHeadersTimeout=TimeSpan.FromSeconds(5);});
builder.Services.AddRateLimiter(o=>{o.RejectionStatusCode=429;o.GlobalLimiter=PartitionedRateLimiter.Create<HttpContext,string>(_=>RateLimitPartition.GetTokenBucketLimiter("callbacks",_=>new(){TokenLimit=300,TokensPerPeriod=100,ReplenishmentPeriod=TimeSpan.FromSeconds(1),AutoReplenishment=true,QueueLimit=0}));});
var app=builder.Build();app.UseRateLimiter();
app.Use(async(c,next)=>
{
    c.Response.Headers.CacheControl="no-store";c.Response.Headers.XContentTypeOptions="nosniff";c.Response.Headers["Referrer-Policy"]="no-referrer";
    var lab=builder.Configuration["RF_ALLOW_LOOPBACK_HTTP"]=="true" && c.Connection.RemoteIpAddress is {} ip && IPAddress.IsLoopback(ip);
    if(!c.Request.IsHttps && !lab){c.Response.StatusCode=400;return;}
    try{await next(c);}catch(Exception ex) when(ex is not OperationCanceledException){app.Logger.LogError("Callback persistence failed ({Type}).",ex.GetType().Name);if(!c.Response.HasStarted)c.Response.StatusCode=503;}
});
// Separate process: no administrator API, endpoint credentials, file uploads, cookies, or document serving.
var pixel=Convert.FromBase64String("iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mNk+A8AAQUBAScY42YAAAAASUVORK5CYII=");
app.MapGet("/t/{id}/pixel.png",(string id,HttpContext c,CallbackStorage store)=>
{
    if(store.Get(id) is {Type:"css-clone",Destination:not null} token && Uri.TryCreate(c.Request.Headers.Referer.ToString(),UriKind.Absolute,out var source) && source.GetLeftPart(UriPartial.Authority)==token.Destination)return Results.Bytes(pixel,"image/png");
    store.Record(id,"HTTPS",c.Connection.RemoteIpAddress?.ToString()??"unknown",c.Request.Headers.UserAgent.ToString());
    return Results.Bytes(pixel,"image/png");
});
app.MapGet("/health/live",()=>Results.Ok(new{status="alive",role="callback receiver"}));
app.MapGet("/t/{id}/open",async(string id,HttpContext c,CallbackStorage store)=>
{
    if(store.Get(id) is not {Revoked:false,Destination:not null} token || token.Type is not ("fast-redirect" or "slow-redirect"))return Results.NotFound();
    if(!Uri.TryCreate(token.Destination,UriKind.Absolute,out var destination) || destination.Scheme!="https" || destination.UserInfo.Length!=0)return Results.NotFound();
    if(!store.Record(id,"HTTPS",c.Connection.RemoteIpAddress?.ToString()??"unknown",c.Request.Headers.UserAgent.ToString()))return Results.NotFound();
    if(token.Type=="slow-redirect")await Task.Delay(TimeSpan.FromSeconds(2),c.RequestAborted);
    if(store.Get(id) is not {Revoked:false})return Results.NotFound();
    return Results.Redirect(destination.AbsoluteUri);
});
app.MapMcpTripwire();
app.MapKubernetesTripwire();
app.MapNetworkFolderTripwire();
app.Run();
