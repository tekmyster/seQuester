namespace RansomFree.Client;

// All callers await the same normal resource drain. Publish its task before
// invoking cancellation callbacks, which may reenter disposal synchronously.
internal sealed class AsyncDisposeOnce(Func<Task> close)
{
    private readonly object gate = new();
    private Task? completion;

    internal Task DisposeAsync()
    {
        lock (gate)
        {
            if (completion is not null) return completion;
            var result = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
            completion = result.Task;
            _ = FinishAsync(result);
            return completion;
        }
    }

    private async Task FinishAsync(TaskCompletionSource result)
    {
        try
        {
            await close().ConfigureAwait(false);
            result.TrySetResult();
        }
        catch (Exception error)
        {
            // Cache the original failure for every caller; a second cleanup
            // must not replace it with a disposed cancellation-token error.
            result.TrySetException(error);
        }
    }
}
