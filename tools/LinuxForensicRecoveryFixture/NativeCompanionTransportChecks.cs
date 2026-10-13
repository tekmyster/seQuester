using System.ComponentModel;
using System.Diagnostics;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using System.Text.Json;
using RansomFree.Client;
using RansomFree.Client.Forensics;

// Actual ordinary worker and root IPC, with an explicitly synthetic source
// health sample and a retained, previously qualified native evidence packet.
internal static class NativeCompanionTransportChecks
{
    private const string Sensor="11111111111111111111111111111111",Origin="https://qualification.invalid/";
    [DllImport("libc")]private static extern uint geteuid();
    [DllImport("libc",SetLastError=true)]private static extern int chown(string path,uint uid,uint gid);
    private sealed class NoNetwork:HttpMessageHandler
    {
        internal int Calls;
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request,CancellationToken cancel)
        {Interlocked.Increment(ref Calls);throw new IOException("Qualification must not contact a server");}
    }
    internal static async Task Child(string root)
    {
        if(geteuid()!=65534)throw new Exception("Exact ordinary companion UID required");
        var checks=new List<string>();void Check(bool value,string name){if(!value)throw new Exception(name);checks.Add(name);}
        var state=Path.Combine(root,"ordinary");var spool=new EventSpool(state,Sensor);
        using var handler=new NoNetwork();using var management=new ManagementClient(new HttpClient(handler){BaseAddress=new Uri(Origin)});
        using var release=new ManualResetEventSlim();var entered=new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var checkpoints=new List<string>();var messages=new List<string>();
        var options=new LinuxNativeClientOptions{Enabled=true,ServiceGroup=65534,ChannelDirectory=Path.Combine(root,"channel"),ExportDirectory=Path.Combine(root,"exports")};
        var companion=LinuxNativeCompanionClient.CreateForQualification(options,Sensor,Origin,state,spool,management,
            text=>{lock(messages)messages.Add(text);},point=>{lock(checkpoints)checkpoints.Add(point);if(point=="bridge-export-opened"){entered.TrySetResult();release.Wait();}});
        Task? stopping=null;
        try
        {
            await entered.Task.WaitAsync(TimeSpan.FromSeconds(90));
            Check(spool.Count==0,"held export has not fabricated an imported event");
            var deadline=Stopwatch.GetTimestamp()+120L*Stopwatch.Frequency;
            while(!companion.ReadyAtRecentSample&&Stopwatch.GetTimestamp()<deadline)await Task.Delay(100);
            var before=companion.Current;
            Check(before.ReadyAtRecentSample&&before.CloseState=="OPEN"&&before.RootProcessId>1,"independent live health loop progresses while real import descriptor is held");
            Console.WriteLine(JsonSerializer.Serialize(new{Step="READY",Uid=geteuid(),Pid=Environment.ProcessId,Status=before}));Console.Out.Flush();
            if(await Console.In.ReadLineAsync()!="stop")throw new Exception("Expected controlled stop command");
            stopping=companion.DisposeAsync().AsTask();var draining=companion.Current;
            Check(!stopping.IsCompleted&&draining.CloseState=="CLOSE_DRAINING"&&!draining.ReadyAtRecentSample,"ordinary shutdown immediately revokes readiness and waits for held import");
            Check(ReferenceEquals(stopping,companion.DisposeAsync().AsTask()),"concurrent ordinary shutdown shares actual drain task");
            Check(spool.Count==0,"cancellation does not invent durable import completion");
            Console.WriteLine(JsonSerializer.Serialize(new{Step="DRAINING",Uid=geteuid(),Pid=Environment.ProcessId,Status=draining}));Console.Out.Flush();
            if(await Console.In.ReadLineAsync()!="release")throw new Exception("Expected descriptor release command");
            release.Set();await stopping.WaitAsync(TimeSpan.FromSeconds(90));
            var closed=companion.Current;
            Check(closed.CloseState=="CLOSED"&&!closed.ReadyAtRecentSample,"actual import return completes ordinary shutdown without stale readiness");
            Check(spool.Count==2,"held import finishes original and completion durably after cancellation");
            using var exports=LinuxProtectedDirectory.OpenRoot(options.ExportDirectory,65534);
            var name=exports.Names(256).Single();var bytes=exports.Read(name,LinuxNativeBridgePacket.MaximumBytes).Bytes;
            var packet=LinuxNativeBridgePacket.Parse(bytes,Sensor);var pair=packet.Validate(Sensor);
            var events=spool.Peek().Events;
            Check(events.Length==2&&EventSpool.Encode(events[0]).AsSpan().SequenceEqual(pair.OriginalBytes)&&EventSpool.Encode(events[1]).AsSpan().SequenceEqual(pair.CompletionBytes),"ordinary queue retains exact linked native original/completion bytes");
            var preservation=pair.Completion.Forensics!.Preservation;var actor=File.ReadAllBytes(Path.Combine(state,preservation.ArtifactRelativePath!));
            Check(pair.Actor!=null&&actor.AsSpan().SequenceEqual(pair.Actor)&&LinuxNativeBridgePacket.Hash(actor)==preservation.Sha256,"preserved actor copy exactly matches event SHA256 and source bytes");
            Check(File.ReadAllBytes(Path.Combine(state,preservation.ManifestRelativePath!)).AsSpan().SequenceEqual(pair.Manifest),"forensic manifest bytes retained exactly");
            var receiptPath=Path.Combine(state,"native-bridge-receipts",packet.SourceEventId+".json");var committed=File.ReadAllBytes(receiptPath);
            var retry=new LinuxNativeBridgeImport(state,Sensor,spool).Import(exports,packet.SourceEventId);
            Check(JsonSerializer.SerializeToUtf8Bytes(retry).AsSpan().SequenceEqual(committed)&&spool.Count==2,"retry after canceled acknowledgement reuses exact receipt without duplicate events");
            Check(exports.Read(name,LinuxNativeBridgePacket.MaximumBytes).Bytes.AsSpan().SequenceEqual(bytes),"root packet retained after unavailable acknowledgement and idempotent retry");
            lock(checkpoints)Check(checkpoints.SequenceEqual(new[]{"bridge-export-opened","bridge-actor-imported","bridge-manifest-imported","bridge-original-imported","bridge-completion-imported","bridge-upload-registered","bridge-receipt-committed"}),"real import boundaries complete in actor/event/upload/receipt order");
            Check(handler.Calls==0,"absent root policy socket cannot initiate a management network request");
            Check(closed.LastImportedSourceEventId==null,"local receipt is not mislabeled as root acknowledgement");
            var result=new{Passed=true,Checks=checks.Count,Details=checks,Uid=geteuid(),Pid=Environment.ProcessId,Before=before,Draining=draining,Closed=closed,NetworkCalls=handler.Calls,Checkpoints=checkpoints,Messages=messages,Receipt=retry};
            File.WriteAllBytes(Path.Combine(state,"CHILD.json"),JsonSerializer.SerializeToUtf8Bytes(result));
            Console.WriteLine(JsonSerializer.Serialize(new{Step="CLOSED",Uid=geteuid(),Pid=Environment.ProcessId,Checks=checks.Count}));Console.Out.Flush();
        }
        finally{release.Set();await companion.DisposeAsync();}
    }
    internal static async Task Run(string packets,string root)
    {
        if(!OperatingSystem.IsLinux()||geteuid()!=0||Directory.Exists(root))throw new ArgumentException("Fresh root companion transport fixture required");
        var checks=new List<string>();void Check(bool value,string name){if(!value)throw new Exception(name);checks.Add(name);}
        void DirectoryFor(string path,uint uid,uint gid,UnixFileMode mode)
        {Directory.CreateDirectory(path,mode);if(chown(path,uid,gid)!=0)throw new Win32Exception(Marshal.GetLastPInvokeError());}
        const UnixFileMode privateMode=UnixFileMode.UserRead|UnixFileMode.UserWrite|UnixFileMode.UserExecute;
        const UnixFileMode groupMode=privateMode|UnixFileMode.GroupRead|UnixFileMode.GroupExecute;
        DirectoryFor(root,0,0,groupMode|UnixFileMode.OtherRead|UnixFileMode.OtherExecute);
        var channel=Path.Combine(root,"channel");var exportsPath=Path.Combine(root,"exports");
        DirectoryFor(channel,0,65534,groupMode);DirectoryFor(exportsPath,0,65534,groupMode);DirectoryFor(Path.Combine(root,"ordinary"),65534,65534,privateMode);
        var packet=Enumerable.Range(0,5).Select(i=>LinuxNativeBridgePacket.Parse(File.ReadAllBytes(Path.Combine(packets,"packet-"+i+".json")),Sensor)).First(p=>p.ActorBase64!=null);
        using(var exports=LinuxProtectedDirectory.OpenRoot(exportsPath,65534))new LinuxNativeBridgeExport(exports,Sensor).Publish(packet);
        await using var listener=new LinuxNativeHealthSocket(channel,65534,65534,Sensor,Origin,NativeHealthSocketChecks.Sample);
        using var cancel=new CancellationTokenSource();var errors=new List<string>();
        var serving=Task.Run(async()=>{while(!cancel.IsCancellationRequested){try{await listener.AcceptAsync(cancel.Token);}catch(OperationCanceledException)when(cancel.IsCancellationRequested){break;}catch(Exception e)when(e is IOException or SocketException or OperationCanceledException){lock(errors)errors.Add(e.GetType().Name);}}});
        var info=new ProcessStartInfo("/usr/bin/setpriv"){UseShellExecute=false,RedirectStandardInput=true,RedirectStandardOutput=true,RedirectStandardError=true};
        foreach(var a in new[]{"--reuid","65534","--regid","65534","--clear-groups","--",Environment.ProcessPath!,"native-companion-transport-child",root})info.ArgumentList.Add(a);
        using var child=Process.Start(info)??throw new IOException("Ordinary companion child failed to start");
        var stderr=child.StandardError.ReadToEndAsync();var lines=new List<string>();
        async Task ReadStep(string step)
        {
            var line=await child.StandardOutput.ReadLineAsync().WaitAsync(TimeSpan.FromSeconds(180));
            if(line==null)throw new Exception("Ordinary child exited before "+step+": "+await stderr);lines.Add(line);
            using var doc=JsonDocument.Parse(line);var e=doc.RootElement;
            Check(e.GetProperty("Step").GetString()==step&&e.GetProperty("Uid").GetUInt32()==65534&&e.GetProperty("Pid").GetInt32()==child.Id,"actual ordinary UID/PID transition: "+step);
        }
        try
        {
            await ReadStep("READY");await child.StandardInput.WriteLineAsync("stop");await child.StandardInput.FlushAsync();await ReadStep("DRAINING");
            Check(!child.HasExited,"actual ordinary process still owns blocked import while draining");
            await child.StandardInput.WriteLineAsync("release");await child.StandardInput.FlushAsync();await ReadStep("CLOSED");
            await child.WaitForExitAsync().WaitAsync(TimeSpan.FromSeconds(90));Check(child.ExitCode==0,"ordinary worker exits normally after durable import");
            using var evidence=JsonDocument.Parse(File.ReadAllBytes(Path.Combine(root,"ordinary/CHILD.json")));var v=evidence.RootElement;
            Check(v.GetProperty("Passed").GetBoolean()&&v.GetProperty("Uid").GetUInt32()==65534&&v.GetProperty("Pid").GetInt32()==child.Id&&v.GetProperty("Checks").GetInt32()==15,"all fifteen real ordinary-worker assertions retained");
            Check(v.GetProperty("Before").GetProperty("RootProcessId").GetInt32()==Environment.ProcessId,"ordinary live health binds actual serving root process");
            using var exports=LinuxProtectedDirectory.OpenRoot(exportsPath,65534);
            Check(exports.Read(packet.SourceEventId+".json",LinuxNativeBridgePacket.MaximumBytes).Bytes.AsSpan().SequenceEqual(packet.Encode(Sensor)),"root independently confirms unacknowledged source packet retained exactly");
        }
        finally
        {
            // Release through the owned protocol only, never a detached read,
            // forced process kill or VM reset while actual I/O is unresolved.
            if(!child.HasExited){try{await child.StandardInput.WriteLineAsync("stop\nrelease");await child.StandardInput.FlushAsync();}catch(IOException){}await child.WaitForExitAsync();}
            cancel.Cancel();await listener.DisposeAsync();await serving;
            File.WriteAllLines(Path.Combine(root,"child.stdout.jsonl"),lines);File.WriteAllText(Path.Combine(root,"child.stderr.log"),await stderr);
        }
        Check(listener.CloseState=="CLOSED"&&!File.Exists(Path.Combine(channel,LinuxNativeHealthSocket.Name)),"root health channel actually drained and retired after ordinary exit");
        var result=new{Passed=true,Checks=checks.Count+15,RootChecks=checks.Count,OrdinaryChecks=15,Details=checks,Root=root,RootPid=Environment.ProcessId,ChildPid=child.Id,HealthErrors=errors,Scope="Actual UID65534 ordinary client, root health IPC and blocked durable import; source health samples synthetic, replayed qualified native evidence; no new native activation or server contact"};
        File.WriteAllBytes(Path.Combine(root,"RESULTS.json"),JsonSerializer.SerializeToUtf8Bytes(result));Console.WriteLine(JsonSerializer.Serialize(result));
    }
}
