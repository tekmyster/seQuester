using System.Threading.RateLimiting;

namespace RansomFree.Server;

public static class ServerRequestLimits
{
    // Artifact chunks/downloads must not consume the budget used by heartbeats,
    // event ingestion, policy delivery and the console. Both pools stay bounded.
    public static PartitionedRateLimiter<HttpContext> Create(int reportingPerMinute=600,int artifactPerMinute=600)
    {
        // Reject invalid startup configuration rather than silently disabling a
        // limiter. Defaults preserve existing installations; each pool is global.
        if(reportingPerMinute is <1 or >10000)throw new ArgumentOutOfRangeException(nameof(reportingPerMinute));
        if(artifactPerMinute is <1 or >10000)throw new ArgumentOutOfRangeException(nameof(artifactPerMinute));
        return PartitionedRateLimiter.Create<HttpContext,string>(context =>
            RateLimitPartition.GetFixedWindowLimiter(IsArtifact(context.Request.Path) ? "artifact" : "reporting",
                _ => new FixedWindowRateLimiterOptions { PermitLimit=IsArtifact(context.Request.Path)?artifactPerMinute:reportingPerMinute,Window=TimeSpan.FromMinutes(1),QueueLimit=0 }));
    }

    private static bool IsArtifact(PathString path) =>
        path.StartsWithSegments("/api/v1/agent/evidence") ||
        path.StartsWithSegments("/api/v1/admin/actor-evidence") ||
        path.StartsWithSegments("/api/v1/console/actor-evidence");
}
