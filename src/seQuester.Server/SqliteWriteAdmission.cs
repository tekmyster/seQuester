using System.Threading.RateLimiting;

namespace RansomFree.Server;

// SQLite admits one writer. Queue HTTP writers asynchronously rather than
// consuming request threads in the provider's synchronous busy retry loop.
// This is admission, not a transaction replacement or permission check.
public sealed class SqliteWriteAdmission : IDisposable
{
    private readonly bool enabled;
    private readonly ConcurrencyLimiter limiter;
    public SqliteWriteAdmission(bool enabled, int queueLimit = 128)
    {
        this.enabled = enabled;
        limiter = new(new ConcurrencyLimiterOptions { PermitLimit = 1,
            QueueLimit = queueLimit, QueueProcessingOrder = QueueProcessingOrder.OldestFirst });
    }
    public async Task<bool> Execute(HttpContext context, Func<Task> action)
    {
        if (!enabled) { await action(); return true; }
        using var lease = await limiter.AcquireAsync(1, context.RequestAborted);
        if (!lease.IsAcquired)
        {
            context.Response.StatusCode = StatusCodes.Status503ServiceUnavailable;
            context.Response.Headers.RetryAfter = "1";
            await context.Response.WriteAsJsonAsync(new { error = "Database write queue is full; retry the unchanged request." }, context.RequestAborted);
            return false;
        }
        await action();
        return true;
    }
    public static bool IsApiWrite(HttpRequest request)
    {
        // This POST authenticates through a SELECT and returns fixed capabilities.
        // Every sensor calls it before sending events or uploading evidence. It
        // must remain responsive while another request holds the writer permit.
        // Keep this exception exact; other POST handlers can mutate audit state.
        if (HttpMethods.IsPost(request.Method) &&
            (request.Path.Equals(new PathString("/api/v1/agent/capabilities"), StringComparison.OrdinalIgnoreCase) ||
             request.Path.Equals(new PathString("/api/v1/agent/native-policy"), StringComparison.OrdinalIgnoreCase)))
            return false;
        return request.Path.StartsWithSegments("/api/v1") &&
            !HttpMethods.IsGet(request.Method) && !HttpMethods.IsHead(request.Method) && !HttpMethods.IsOptions(request.Method);
    }
    public void Dispose() => limiter.Dispose();
}
