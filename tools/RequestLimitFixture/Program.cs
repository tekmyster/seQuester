using Microsoft.AspNetCore.Http;
using RansomFree.Server;

var checks=0;
void Check(bool ok,string name){if(!ok)throw new Exception(name);checks++;Console.WriteLine("PASS "+name);}
bool Take(System.Threading.RateLimiting.PartitionedRateLimiter<HttpContext> limiter,string path)
{var context=new DefaultHttpContext();context.Request.Path=path;using var lease=limiter.AttemptAcquire(context);return lease.IsAcquired;}
using(var limiter=ServerRequestLimits.Create())
{
 Check(Enumerable.Range(0,600).All(_=>Take(limiter,"/api/v1/agent/evidence/example/chunks/0")),"artifact pool admits its bounded capacity");
 Check(!Take(limiter,"/api/v1/agent/evidence/other/finish"),"artifact saturation rejects more uploads");
 Check(!Take(limiter,"/api/v1/admin/actor-evidence/sensor/id/artifact")&&!Take(limiter,"/api/v1/console/actor-evidence/sensor/id/manifest"),"downloads share the bounded artifact pool");
 Check(Take(limiter,"/api/v1/agent/heartbeat")&&Take(limiter,"/api/v1/agent/events")&&Take(limiter,"/api/v1/agent/policy"),"saturated uploads preserve heartbeat/event/policy capacity");
 Check(Enumerable.Range(0,597).All(_=>Take(limiter,"/api/v1/admin/event-history")),"reporting retains the existing 600-request budget");
 Check(!Take(limiter,"/api/v1/agent/heartbeat"),"reporting traffic remains rate limited");
}
using(var limiter=ServerRequestLimits.Create())
{
 Check(Enumerable.Range(0,600).All(_=>Take(limiter,"/api/v1/admin/event-history")),"independent reporting saturation setup");
 Check(!Take(limiter,"/api/v1/agent/evidence-lookalike")&&!Take(limiter,"/other/evidence"),"lookalike paths cannot create additional pools");
 Check(Take(limiter,"/api/v1/agent/evidence/start"),"reporting saturation does not destroy resumable upload capacity");
}

using(var limiter=ServerRequestLimits.Create(2400,1200))
{
 Check(Enumerable.Range(0,2400).All(_=>Take(limiter,"/api/v1/agent/events")),"configured reporting pool admits deployment capacity");
 Check(!Take(limiter,"/api/v1/agent/heartbeat"),"configured reporting pool still rejects excess traffic");
 Check(Enumerable.Range(0,1200).All(_=>Take(limiter,"/api/v1/admin/actor-evidence/sensor/id/artifact")),"configured artifact pool remains independent");
 Check(!Take(limiter,"/api/v1/agent/evidence/start"),"configured artifact pool still rejects excess traffic");
}
foreach(var pair in new[]{(0,600),(10001,600),(600,-1),(600,10001)})
{
 var rejected=false;try{using var invalid=ServerRequestLimits.Create(pair.Item1,pair.Item2);}catch(ArgumentOutOfRangeException){rejected=true;}
 Check(rejected,"invalid rate configuration refused: "+pair);
}

Console.WriteLine($"PASS {checks} request-budget checks");
