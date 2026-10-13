using RansomFree.Contracts;
using System.Text.Json;
using RansomFree.Client;

static class OwnedLifetimeFaultChecks
{
    internal static async Task Run(string root)
    {
        if(!OperatingSystem.IsLinux()||Directory.Exists(root))throw new ArgumentException("Fresh owned Linux lifetime fixture required");Directory.CreateDirectory(root);int checks=0;var cases=new List<object>();
        void Check(bool ok,string label){if(!ok)throw new Exception(label);checks++;Console.WriteLine("PASS: "+label);}
        foreach(var mode in new[]{"queued-fault","managed-close-failure","reported-close-error","bind-failure"})
        {
            var args=new List<string>();if(Path.GetFileNameWithoutExtension(Environment.ProcessPath)=="dotnet")args.Add(typeof(OwnedLifetimeFaultChecks).Assembly.Location);
            args.AddRange(["owned-loader-child",mode is "managed-close-failure" or "reported-close-error"?"await-stop":mode]);
            var faults=new LinuxOwnedLoaderProcess.TestFaults(mode=="managed-close-failure",mode=="reported-close-error",mode=="bind-failure");
            var owner=LinuxOwnedLoaderProcess.StartForTest(Environment.ProcessPath!,args.ToArray(),faults);
            try
            {
                var ready=LinuxControlledLoaderProtocol.ParseReady((await owner.ReadFrameAsync())!);
                Check(ready.Epoch==7,"real child ready retained: "+mode);
                if(mode=="queued-fault")
                {
                    var failure=await owner.FramingFault.WaitAsync(TimeSpan.FromSeconds(30));
                    Check(!owner.HasExited&&failure.BufferedPrefix.Length==65537&&failure.BufferedPrefix.Span.IndexOfAnyExcept((byte)'x')<0,"independent framing fault retains exact65537-byte prefix while child live");
                    Check((await owner.ReadFrameAsync())!.AsSpan().SequenceEqual("QUEUED"u8),"previously queued frame survives independent fault signal");
                    try{owner.ActivateOnce(ready,Guid.NewGuid().ToString("N"));throw new Exception("Faulted loader activated");}catch(InvalidOperationException){Check(true,"observed parser fault denies activation");}
                    owner.RequestStop();await owner.Completion;
                    Check(owner.Snapshot().UnframedDrainBytes==8192&&owner.Snapshot().BufferedFailureBytes==65537,"reader prefix and residual pipe counts remain separate and exact");
                }
                else if(mode=="bind-failure")
                {
                    Check(owner.Snapshot().State=="STARTUP_BIND_FAILED_WAITING_FOR_EXIT"&&!owner.Completion.IsCompleted,"binding failure retains live child without safe signal authority");
                    try{owner.ActivateOnce(ready,Guid.NewGuid().ToString("N"));throw new Exception("Unbound loader activated");}catch(InvalidOperationException){Check(true,"unbound loader cannot activate");}
                    owner.RequestStop();Check(owner.Snapshot().SignalError==null,"binding failure never falls back to numeric PID signal");
                    try{owner.Dispose();throw new Exception("Live unbound child disposed");}catch(InvalidOperationException){Check(true,"unbound child still requires actual exit and pipe drainage");}
                    Check(await owner.ReadFrameAsync()==null,"natural child exit closes stdout after bind failure");await owner.Completion;
                }
                else
                {
                    owner.RequestStop();var first=owner.Snapshot().InputClose;owner.RequestStop();
                    Check(first!=null&&ReferenceEquals(first,owner.Snapshot().InputClose),"first input close outcome immutable across stop retry: "+mode);
                    Check(owner.Snapshot().SignalError==0,"input close failure does not prevent pidfd SIGTERM: "+mode);
                    Check((await owner.ReadFrameAsync())!.AsSpan().SequenceEqual("STOPPED"u8),"real child receives stop and produces final output: "+mode);
                    Check(await owner.ReadFrameAsync()==null,"both failure paths observe actual stdout EOF: "+mode);await owner.Completion;
                    Check(mode=="managed-close-failure"?first!.Result==null&&first.Error==null&&first.ManagedFailure==nameof(InvalidDataException):first!.Result==-1&&first.Error==5&&first.ManagedFailure==null,"managed versus injected libc failure not conflated: "+mode);
                }
                Check(owner.ExitCode==0&&owner.Completion.IsCompletedSuccessfully,"actual child and pipes complete: "+mode);
            }
            finally
            {
                owner.RequestStop();
                try{while(await owner.ReadFrameAsync()!=null){}}
                catch(Exception ex)when(ex is IOException or InvalidDataException or System.Threading.Channels.ChannelClosedException){}
                await owner.Completion;owner.Dispose();
            }
            var diagnostic=owner.Snapshot();
            Check(diagnostic.State=="DISPOSED"&&(mode=="bind-failure"?diagnostic.PidfdClose==null:diagnostic.PidfdClose is {Result:0,Error:0}),"owned pidfd cleanup has exact outcome: "+mode);
            cases.Add(new{Mode=mode,Diagnostic=diagnostic});
        }
        var result=new{Passed=true,Checks=checks,Cases=cases,Scope="Real Linux owned children, framing, pipes and pidfd; managed/close-error/bind faults explicitly injected; no actor controller or runtime activation"};
        File.WriteAllText(Path.Combine(root,"RESULTS.json"),JsonSerializer.Serialize(result));Console.WriteLine(JsonSerializer.Serialize(new{Passed=true,Checks=checks}));
    }
}
