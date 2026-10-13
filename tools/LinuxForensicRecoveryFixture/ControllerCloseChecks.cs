using System.ComponentModel;
using System.Text.Json;
using RansomFree.Client;

static class ControllerCloseChecks
{
    internal static async Task Run()
    {
        int checks=0;
        void Check(bool ok,string label){if(!ok)throw new Exception(label);checks++;Console.WriteLine("PASS: "+label);}
        var healthy=new Transport();var once=new LinuxActorLeaseDevice(healthy);once.Dispose();once.Dispose();
        Check(healthy.Calls==1,"successful controller disposal is one native close");
        var failed=new Transport{Failure=new Win32Exception(5,"owned close failure")};var device=new LinuxActorLeaseDevice(failed);
        try{device.Dispose();throw new Exception("Close failure hidden");}catch(Win32Exception ex){Check(ex.NativeErrorCode==5,"first close retains original OS error");}
        try{device.Dispose();throw new Exception("Repeated close reported success");}catch(IOException ex){Check(ReferenceEquals(ex.InnerException,failed.Failure),"repeated disposal retains failed ownership outcome");}
        Check(failed.Calls==1,"failed close is never retried against a recycled descriptor");
        using var entered=new ManualResetEventSlim();using var release=new ManualResetEventSlim();
        var blocked=new Transport{Entered=entered,Release=release};var owned=new LinuxActorLeaseDevice(blocked);var actual=Task.Run(owned.Dispose);
        try
        {
            Check(entered.Wait(TimeSpan.FromSeconds(10)),"actual controller close entered");
            using var cancellation=new CancellationTokenSource();cancellation.Cancel();
            try{await actual.WaitAsync(cancellation.Token);throw new Exception("Canceled wait completed close");}catch(OperationCanceledException){Check(!actual.IsCompleted,"canceled wait leaves real controller close outstanding");}
            Check(blocked.Calls==1,"outstanding close has one actual invocation");
        }
        finally{release.Set();await actual;}
        owned.Dispose();Check(blocked.Calls==1&&actual.IsCompletedSuccessfully,"only actual native return establishes successful disposal");
        Console.WriteLine(JsonSerializer.Serialize(new{Passed=true,Checks=checks,Scope="Injected controller close errors and blocked calls; actual native libc close requires isolated Linux qualification"}));
    }
    private sealed class Transport:ILinuxActorLeaseTransport
    {
        internal int Calls;
        internal Exception? Failure;
        internal ManualResetEventSlim? Entered,Release;
        public void Control(uint command,byte[] request)=>throw new InvalidOperationException("No fixture control authority");
        public int Read(byte[] destination,int count)=>throw new InvalidOperationException("No fixture read authority");
        public void Dispose(){Interlocked.Increment(ref Calls);Entered?.Set();if(Release!=null&&!Release.Wait(TimeSpan.FromSeconds(30)))throw new TimeoutException("Owned close pause not released");if(Failure!=null)throw Failure;}
    }
}
