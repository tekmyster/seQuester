using System.Diagnostics;
using System.Text.Json;

static class FixtureProcessTiming
{
    // Only managed diagnostic child processes. This never authorizes native
    // controller cancellation, DROP or a successful close/recovery result.
    internal static async Task Wait(Process child)
    {
        var bound=OperatingSystem.IsLinux()?TimeSpan.FromSeconds(120):TimeSpan.FromSeconds(30);
        var watch=Stopwatch.StartNew();
        Console.WriteLine(JsonSerializer.Serialize(new{FixtureChildWait="started",Pid=child.Id,BoundSeconds=bound.TotalSeconds}));
        try{await child.WaitForExitAsync().WaitAsync(bound);}
        catch(TimeoutException)
        {
            Console.Error.WriteLine(JsonSerializer.Serialize(new{FixtureChildWait="timeout",Pid=child.Id,ElapsedSeconds=watch.Elapsed.TotalSeconds,ExitEstablished=false}));throw;
        }
        Console.WriteLine(JsonSerializer.Serialize(new{FixtureChildWait="returned",Pid=child.Id,ElapsedSeconds=watch.Elapsed.TotalSeconds,ExitCode=child.ExitCode}));
    }
}
