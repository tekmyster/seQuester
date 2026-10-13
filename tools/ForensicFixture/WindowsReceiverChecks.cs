using System.Diagnostics;
using RansomFree.Client;

internal static class WindowsReceiverChecks
{
    internal static void Child()
    {
        ThreadPool.GetMinThreads(out var oldMin,out var minIo);
        ThreadPool.GetMaxThreads(out var oldMax,out var maxIo);
        using var release=new ManualResetEventSlim();using var occupied=new ManualResetEventSlim();
        using var pooledRan=new ManualResetEventSlim();using var received=new ManualResetEventSlim();
        using var stop=new CancellationTokenSource();
        Task? receiver=null;
        try
        {
            if(!ThreadPool.SetMinThreads(1,minIo)||!ThreadPool.SetMaxThreads(1,maxIo))throw new Exception("Could not constrain isolated fixture pool");
            ThreadPool.QueueUserWorkItem(_=>{occupied.Set();release.Wait();});
            if(!occupied.Wait(TimeSpan.FromSeconds(5)))throw new Exception("Pool worker did not enter blocker");
            ThreadPool.QueueUserWorkItem(_=>pooledRan.Set());
            var polls=0;var threadId=0;
            receiver=WindowsKernelSource.StartReceiver(()=>
            {
                threadId=Environment.CurrentManagedThreadId;
                while(!stop.Token.WaitHandle.WaitOne(20))
                {
                    if(Thread.CurrentThread.IsThreadPoolThread||Environment.CurrentManagedThreadId!=threadId)throw new Exception("Receiver moved onto shared pool");
                    if(Interlocked.Increment(ref polls)==5)received.Set();
                }
            });
            if(!received.Wait(TimeSpan.FromSeconds(5)))throw new Exception("Receiver stalled behind occupied shared pool");
            if(pooledRan.IsSet)throw new Exception("Contention test failed to keep shared pool occupied");
            stop.Cancel();
            if(!receiver.Wait(TimeSpan.FromSeconds(5)))throw new Exception("Receiver cancellation depended on shared pool");
            var fault=WindowsKernelSource.StartReceiver(()=>throw new IOException("receiver-test-fault"));
            try{fault.GetAwaiter().GetResult();throw new Exception("Receiver failure lost");}catch(IOException ex)when(ex.Message=="receiver-test-fault"){}
            Console.WriteLine("PASS receiver polls, cancellation and fault propagation while shared pool is occupied");
        }
        finally
        {
            stop.Cancel();release.Set();
            ThreadPool.SetMaxThreads(oldMax,maxIo);ThreadPool.SetMinThreads(oldMin,minIo);
            receiver?.GetAwaiter().GetResult();
            if(!pooledRan.Wait(TimeSpan.FromSeconds(5)))throw new Exception("Shared pool did not recover");
        }
    }
    internal static void Run(Action<bool,string> check)
    {
        // Pool limits are changed only in this new child process, never in the
        // sensor, other tests, or a process owned by the user.
        var start=new ProcessStartInfo(Environment.ProcessPath!){UseShellExecute=false,CreateNoWindow=true,WindowStyle=ProcessWindowStyle.Hidden,RedirectStandardOutput=true,RedirectStandardError=true};
        if(Path.GetFileNameWithoutExtension(Environment.ProcessPath).Equals("dotnet",StringComparison.OrdinalIgnoreCase))start.ArgumentList.Add(typeof(WindowsReceiverChecks).Assembly.Location);
        start.ArgumentList.Add("--receiver-starvation");
        using var process=Process.Start(start)!;
        var stdout=process.StandardOutput.ReadToEndAsync();var stderr=process.StandardError.ReadToEndAsync();
        if(!process.WaitForExit(30000)){process.Kill(true);throw new Exception("Owned receiver fixture timed out");}
        check(process.ExitCode==0&&stdout.GetAwaiter().GetResult().Contains("PASS receiver polls"),"dedicated receiver survives shared-pool starvation and cancels without a pooled continuation: "+stderr.GetAwaiter().GetResult());
    }
}
