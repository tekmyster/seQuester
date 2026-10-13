using System.Diagnostics;
using System.Text.Json;

internal static class TimerSpinChecks
{
    internal static async Task Run()
    {
        using var stop=new CancellationTokenSource();
        var periods=new[]{50,100,100,1000,2000,5000,15000};var counts=new long[periods.Length];
        async Task Loop(int index)
        {
            try{while(true){await Task.Delay(periods[index],stop.Token);Interlocked.Increment(ref counts[index]);}}
            catch(OperationCanceledException)when(stop.IsCancellationRequested){}
        }
        var tasks=Enumerable.Range(0,periods.Length).Select(i=>Task.Run(()=>Loop(i))).ToArray();
        await Task.Delay(5000);var before=counts.ToArray();using var process=Process.GetCurrentProcess();
        var cpu=process.TotalProcessorTime;var timer=Stopwatch.StartNew();
        await Task.Delay(15000);var elapsed=timer.Elapsed.TotalSeconds;var used=(process.TotalProcessorTime-cpu).TotalMilliseconds;
        var completed=counts.Select((v,i)=>v-before[i]).ToArray();stop.Cancel();await Task.WhenAll(tasks);
        if(completed[0]<150||completed[1]<75||completed[2]<75)throw new Exception("Timer callbacks did not remain active during fixture");
        Console.WriteLine(JsonSerializer.Serialize(new{Passed=true,NoServiceChanged=true,NoNativeActivation=true,Scope="Isolated runtime timer/spin comparison only, not file detection qualification",SpinLimit=Environment.GetEnvironmentVariable("DOTNET_ThreadPool_UnfairSemaphoreSpinLimit")??"runtime-default",LogicalCores=Environment.ProcessorCount,ElapsedSeconds=elapsed,CpuMs=used,OneCorePercent=used/10/elapsed,MachineCpuPercent=used/10/elapsed/Environment.ProcessorCount,PeriodsMs=periods,Completed=completed}));
    }
}
