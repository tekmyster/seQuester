using System.Buffers.Binary;
using System.ComponentModel;
using System.Diagnostics;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using System.Text;
using System.Text.Json;
using RansomFree.Client.Forensics;
using RansomFree.Contracts;

// Real root/nonroot IPC qualification. Source samples here are explicitly
// synthetic: native source evidence is qualified by the separate owned run.
internal static class NativeHealthSocketChecks
{
    private const string Sensor="11111111111111111111111111111111",Origin="https://qualification.invalid/";
    [DllImport("libc")]private static extern uint geteuid();
    [DllImport("libc",SetLastError=true)]private static extern int chown(string path,uint uid,uint gid);
    internal static LinuxControlledSourceRuntime.ServiceHealth Sample()
    {
        var a=Stopwatch.GetTimestamp();var now=DateTimeOffset.UtcNow;
        var evidence=new LinuxKernelSourceHealthEvidence(1,0,0,now,now,now,now,a,a,a,a,Stopwatch.GetTimestamp(),Stopwatch.Frequency);
        return new(Guid.NewGuid().ToString("N"),Sensor,"ACTIVE",Guid.NewGuid().ToString("N"),Guid.NewGuid().ToString("N"),"123",new string('A',64),new string('B',64),now.AddMinutes(1),evidence,"LINUX_SOURCE_HEALTH_SAMPLED");
    }
    internal static async Task Child(string root,string mode)
    {
        if(geteuid()!=65534)throw new Exception("Exact unprivileged health child required");
        LinuxNativeHealthSocket.Observation? observation=null;var transientErrors=new List<string>();
        if(mode is "active" or "none" or "stopped" or "foreign" or "blocked")
        {
            try
            {
                for(var attempt=0;attempt<4;attempt++)
                {
                    try{observation=await LinuxNativeHealthSocket.QueryAsync(root,65534,Sensor,Origin,CancellationToken.None);break;}
                    catch(Exception e)when((mode is "active" or "none" or "stopped")&&attempt<3&&e is IOException or SocketException or OperationCanceledException)
                    {transientErrors.Add(e.GetType().Name);await Task.Delay(100);}
                }
            }
            catch(Exception e)when(mode is "foreign" or "blocked" && e is IOException or SocketException or OperationCanceledException){}
            if((mode is "foreign" or "blocked")&&observation!=null)throw new Exception("Unexpected health reply after rejection/stop");
        }
        else
        {
            using var parent=LinuxProtectedDirectory.OpenRoot(root,65534);parent.RequireSocket(LinuxNativeHealthSocket.Name);
            using var socket=new Socket(AddressFamily.Unix,SocketType.Stream,ProtocolType.Unspecified);
            await socket.ConnectAsync(new UnixDomainSocketEndPoint(parent.SocketPath(LinuxNativeHealthSocket.Name)));_=LinuxNativePolicySocket.RequirePeer(socket,0);
            using var stream=new NetworkStream(socket);var request=new LinuxNativeHealthSocket.Request(1,Sensor,Origin,Guid.NewGuid().ToString("N"));
            if(mode is "oversize" or "empty" or "truncated")
            {
                var header=new byte[4];BinaryPrimitives.WriteUInt32LittleEndian(header,mode=="oversize"?32769u:mode=="empty"?0u:100u);
                await stream.WriteAsync(header);if(mode=="truncated")await stream.WriteAsync(new byte[]{123});socket.Shutdown(SocketShutdown.Send);
            }
            else if(mode is "duplicate" or "unknown")
            {
                var json=JsonSerializer.Serialize(request);var bytes=Encoding.UTF8.GetBytes(json[..^1]+(mode=="unknown"?",\"Extra\":true}":",\"Version\":1}"));
                var header=new byte[4];BinaryPrimitives.WriteUInt32LittleEndian(header,(uint)bytes.Length);await stream.WriteAsync(header);await stream.WriteAsync(bytes);
            }
            else await LinuxNativePolicySocket.Write(stream,mode=="wrong-sensor"?request with{SensorId=Guid.NewGuid().ToString("N")}:mode=="wrong-server"?request with{Server="https://other.invalid/"}:request with{Nonce="invalid"},CancellationToken.None);
            try{if(await stream.ReadAsync(new byte[1]).AsTask().WaitAsync(TimeSpan.FromSeconds(15))!=0)throw new Exception("Rejected health request received a reply");}catch(IOException){}
        }
        Console.WriteLine(JsonSerializer.Serialize(new{Uid=geteuid(),Pid=Environment.ProcessId,Mode=mode,Observation=observation,TransientErrors=transientErrors}));
    }
    internal static async Task Run(string root)
    {
        if(!OperatingSystem.IsLinux()||geteuid()!=0||Directory.Exists(root))throw new ArgumentException("Fresh root Linux health socket fixture required");
        Directory.CreateDirectory(root,UnixFileMode.UserRead|UnixFileMode.UserWrite|UnixFileMode.UserExecute|UnixFileMode.GroupRead|UnixFileMode.GroupExecute);
        if(chown(root,0,65534)!=0)throw new Win32Exception(Marshal.GetLastPInvokeError());
        var checks=new List<string>();void Check(bool value,string message){if(!value)throw new Exception(message);checks.Add(message);}
        async Task Reject(Task action,Func<Exception,bool> expected,string message)
        {try{await action.WaitAsync(TimeSpan.FromSeconds(25));}catch(Exception e)when(expected(e)){Check(true,message);return;}throw new Exception("Unexpected success: "+message);}
        Process Start(string mode)
        {
            var info=new ProcessStartInfo("/usr/bin/setpriv"){UseShellExecute=false,RedirectStandardOutput=true,RedirectStandardError=true};
            foreach(var arg in new[]{"--reuid","65534","--regid","65534","--clear-groups","--",Environment.ProcessPath!,"native-health-socket-child",root,mode})info.ArgumentList.Add(arg);
            return Process.Start(info)??throw new IOException("Health child start failed");
        }
        async Task<LinuxNativeHealthSocket.Observation?> Finish(Process child,string mode,Task<string> stdout,Task<string> stderr)
        {
            await child.WaitForExitAsync().WaitAsync(TimeSpan.FromSeconds(30));var output=await stdout;var errors=await stderr;
            File.WriteAllText(Path.Combine(root,checks.Count+"-"+mode+".json"),output);File.WriteAllText(Path.Combine(root,checks.Count+"-"+mode+".stderr.log"),errors);
            Check(child.ExitCode==0,"unprivileged health child completed: "+mode+" "+errors);
            using var document=JsonDocument.Parse(output);var v=document.RootElement;
            Check(v.GetProperty("Uid").GetUInt32()==65534&&v.GetProperty("Pid").GetInt32()==child.Id,"actual UID/PID matches child: "+mode);
            return v.GetProperty("Observation").Deserialize<LinuxNativeHealthSocket.Observation>();
        }
        string state="none";var calls=0;
        await using(var listener=new LinuxNativeHealthSocket(root,65534,65534,Sensor,Origin,()=>
        {
            calls++;var source=Sample();return state switch{"none"=>null,"stopped"=>source with{Phase="COMPLETED",Sample=null},"foreign"=>source with{SensorId=Guid.NewGuid().ToString("N")},_=>source};
        }))
        {
            using(var parent=LinuxProtectedDirectory.OpenRoot(root,65534)){parent.RequireSocket(LinuxNativeHealthSocket.Name);Check(true,"actual health socket has root/group0660 identity");}
            using(var cancel=new CancellationTokenSource())
            {
                var pending=listener.AcceptAsync(cancel.Token);
                await Reject(listener.AcceptAsync(CancellationToken.None),e=>e is InvalidOperationException,"concurrent health accept refused");cancel.Cancel();
                await Reject(pending,e=>e is OperationCanceledException,"idle health accept canceled");
            }
            var wrongPeer=listener.AcceptAsync(CancellationToken.None);
            using(var socket=new Socket(AddressFamily.Unix,SocketType.Stream,ProtocolType.Unspecified))
            {
                await socket.ConnectAsync(new UnixDomainSocketEndPoint(Path.Combine(root,LinuxNativeHealthSocket.Name)));
                await Reject(wrongPeer,e=>e is UnauthorizedAccessException,"root client rejected for exact ordinary UID");
            }
            var tracker=new LinuxNativeHealthTracker();long priorSequence=0;string? instance=null;
            foreach(var mode in new[]{"active","none","stopped","foreign","oversize","empty","truncated","unknown","duplicate","wrong-sensor","wrong-server","bad-nonce","active"})
            {
                state=mode;var before=calls;using var exchange=new CancellationTokenSource(TimeSpan.FromSeconds(60));
                var accepted=listener.AcceptAsync(exchange.Token);using var child=Start(mode);
                var stdout=child.StandardOutput.ReadToEndAsync();var stderr=child.StandardError.ReadToEndAsync();
                var valid=mode is "active" or "none" or "stopped";
                if(valid)
                {
                    // A cold process on a contended host may time out. Keep
                    // the strict five-second product deadline, record retries,
                    // and require a successful fresh exchange in the same child.
                    var exited=child.WaitForExitAsync(exchange.Token);var attempts=0;
                    while(true)
                    {
                        if(await Task.WhenAny(accepted,exited)==exited)
                        {
                            exchange.Cancel();try{await accepted;}catch(Exception e)when(e is OperationCanceledException or IOException or SocketException){}break;
                        }
                        try{await accepted;}catch(Exception e)when(e is OperationCanceledException or IOException or SocketException){}
                        if(++attempts>4)throw new Exception("Health retry bound exceeded");
                        accepted=listener.AcceptAsync(exchange.Token);
                    }
                }
                else await Reject(accepted,e=>e is IOException or InvalidDataException,"health exchange rejected: "+mode);
                var result=await Finish(child,mode,stdout,stderr);
                Check(valid?calls-before is >=1 and <=4:calls-before==(mode=="foreign"?1:0),"invalid requests cannot invoke source health callback: "+mode);
                if(!valid){Check(result==null,"rejected exchange contains no readiness: "+mode);continue;}
                Check(result!=null&&result.Reply.Pid==Environment.ProcessId&&result.Reply.StartTicks.Length>0&&result.Reply.BootId==File.ReadAllText("/proc/sys/kernel/random/boot_id").Trim(),"reply bound to actual root PID/start/boot: "+mode);
                Check(result!.ActiveAtSample==(mode=="active"),"explicit readiness accurately describes synthetic transport sample: "+mode);
                Check(result.Reply.Sequence>priorSequence&&(instance==null||result.Reply.InstanceId==instance),"live listener sequence increases within one instance");
                Check(tracker.Accept(result,Stopwatch.GetTimestamp())&&tracker.ReadyAtRecentSample==(mode=="active"),"ordinary tracker accepts live response state: "+mode);
                priorSequence=result.Reply.Sequence;instance=result.Reply.InstanceId;
            }
        }
        using(var parent=LinuxProtectedDirectory.OpenRoot(root,65534))Check(!parent.Names(256).Contains(LinuxNativeHealthSocket.Name),"normal health shutdown retires exact socket node");
        using(var release=new ManualResetEventSlim())
        {
            var entered=new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
            await using var listener=new LinuxNativeHealthSocket(root,65534,65534,Sensor,Origin,()=>{entered.TrySetResult();release.Wait();return Sample();});
            var accepted=listener.AcceptAsync(CancellationToken.None);using var child=Start("blocked");var stdout=child.StandardOutput.ReadToEndAsync();var stderr=child.StandardError.ReadToEndAsync();Task? stopping=null;
            try
            {
                await entered.Task.WaitAsync(TimeSpan.FromSeconds(25));
                Check(await Finish(child,"blocked",stdout,stderr)==null,"client deadline returns no ready result while actual sample remains blocked");
                Check(!accepted.IsCompleted,"client timeout cannot detach the in-flight sample");stopping=listener.DisposeAsync().AsTask();
                Check(!stopping.IsCompleted&&listener.CloseState=="CLOSE_DRAINING","shutdown remains draining until actual in-flight sample returns");
                Check(ReferenceEquals(stopping,listener.DisposeAsync().AsTask()),"concurrent health shutdown shares one drain");
            }
            finally{release.Set();}
            await Reject(accepted,e=>e is OperationCanceledException,"cancellation after sample cannot send a ready reply");await stopping!;
            Check(listener.CloseState=="CLOSED","actual sample return completes socket drain and closure");
        }
        using(var parent=LinuxProtectedDirectory.OpenRoot(root,65534))Check(!parent.Names(256).Contains(LinuxNativeHealthSocket.Name),"drained health shutdown retires exact socket node");
        var resultSummary=new{Passed=true,Checks=checks.Count,Details=checks,Root=root,Scope="Actual root/UID65534 health socket and tracker; source health samples are synthetic, no native source activation"};
        File.WriteAllBytes(Path.Combine(root,"RESULTS.json"),JsonSerializer.SerializeToUtf8Bytes(resultSummary));Console.WriteLine(JsonSerializer.Serialize(resultSummary));
    }
}
