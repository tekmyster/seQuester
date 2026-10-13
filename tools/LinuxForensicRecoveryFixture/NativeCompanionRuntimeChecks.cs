using System.Diagnostics;
using System.Net;
using System.Net.Http.Json;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text.Json;
using Microsoft.Data.Sqlite;
using RansomFree.Client;
using RansomFree.Client.Forensics;
using RansomFree.Contracts;

// Root runtime and ordinary client composition with real native capture.
// Only the server transport is simulated, using an ephemeral qualification key.
internal static class NativeCompanionRuntimeChecks
{
    private const string Sensor="11111111111111111111111111111111",Origin="https://qualification.invalid/";
    [DllImport("libc")]private static extern uint geteuid();
    [DllImport("libc",SetLastError=true)]private static extern int chown(string path,uint uid,uint gid);
    private sealed record SignerInput(string PrivateKey,TrustPolicy Trust);
    private sealed class Signer(RSA key,TrustPolicy trust,string state):HttpMessageHandler
    {
        internal bool Paused;internal int Calls;
        protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request,CancellationToken cancel)
        {
            if(request.Method!=HttpMethod.Post||request.RequestUri?.AbsoluteUri!=Origin+"api/v1/agent/native-policy")throw new InvalidDataException("Unexpected qualification transport request");
            if(Volatile.Read(ref Paused))return new(HttpStatusCode.ServiceUnavailable);
            using var body=JsonDocument.Parse(await request.Content!.ReadAsByteArrayAsync(cancel));
            var nonce=body.RootElement.GetProperty("challenge").GetString()!;var now=DateTimeOffset.UtcNow;
            var envelope=SignedNativePolicy.Sign(new(Origin,Sensor,nonce,now,now.AddMinutes(5),new(Sensor,null,trust,trust.Digest(),now,now.AddMinutes(5)),new(null,1,MonitoringPolicy.Default)),key);
            var id=Interlocked.Increment(ref Calls);File.WriteAllBytes(Path.Combine(state,"signed-policy-"+id+".json"),JsonSerializer.SerializeToUtf8Bytes(envelope));
            return new(HttpStatusCode.OK){Content=JsonContent.Create(envelope)};
        }
    }
    internal static async Task CheckSigner(string directory)
    {
        if(Directory.Exists(directory))throw new ArgumentException("Fresh isolated signer fixture directory required");Directory.CreateDirectory(directory);
        using var key=RSA.Create(3072);var trust=new TrustPolicy(1,"enforce",[],[],"fixture",DateTimeOffset.UtcNow.AddSeconds(-1)){Version=3};
        using var handler=new Signer(key,trust,directory);using var client=new ManagementClient(new HttpClient(handler){BaseAddress=new Uri(Origin)},new string('A',64));
        var challenge=new string('B',64);var envelope=await client.RelayNativePolicyAsync(challenge);
        var snapshot=envelope.Verify(key.ExportSubjectPublicKeyInfo(),Origin,Sensor,challenge,DateTimeOffset.UtcNow);
        if(handler.Calls!=1||snapshot.Trust.Digest!=trust.Digest())throw new Exception("Fixture signed relay failed");
        Volatile.Write(ref handler.Paused,true);var rejected=false;
        try{_=await client.RelayNativePolicyAsync(challenge);}catch(HttpRequestException){rejected=true;}
        if(!rejected||handler.Calls!=1)throw new Exception("Paused fixture signer accepted a new policy");
        Console.WriteLine(JsonSerializer.Serialize(new{Passed=true,Checks=2,Scope="Authenticated in-process fixture signer transport and paused refusal; no socket/source activation or network contact"}));
    }
    internal static async Task Child(string root)
    {
        if(geteuid()!=65534)throw new Exception("Actual ordinary companion UID required");
        var input=JsonSerializer.Deserialize<SignerInput>((await Console.In.ReadLineAsync())!)!;
        using var key=RSA.Create();key.ImportPkcs8PrivateKey(Convert.FromBase64String(input.PrivateKey),out _);
        var state=Path.Combine(root,"ordinary");var spool=new EventSpool(state,Sensor);
        // A fixture-only credential exercises the normal authenticated Send
        // path; the in-process signer is the only transport and has no network.
        using var signer=new Signer(key,input.Trust,state);using var management=new ManagementClient(new HttpClient(signer){BaseAddress=new Uri(Origin)},new string('A',64));
        var reports=new List<string>();await using var companion=new LinuxNativeCompanionClient(new(){Enabled=true,ServiceGroup=65534,ChannelDirectory=Path.Combine(root,"channel"),ExportDirectory=Path.Combine(root,"exports")},Sensor,Origin,state,spool,management,
            text=>{lock(reports)reports.Add(text);});
        while(await Console.In.ReadLineAsync() is {} command)
        {
            if(command=="pause-policy")Volatile.Write(ref signer.Paused,true);
            else if(command=="stop")await companion.DisposeAsync();
            else if(command!="status")throw new InvalidDataException("Unknown child command");
            var status=new{Uid=geteuid(),Pid=Environment.ProcessId,Status=companion.Current,Events=spool.Count,PolicyPaused=signer.Paused,SignedPolicies=signer.Calls};
            Console.WriteLine(JsonSerializer.Serialize(status));Console.Out.Flush();
            if(command=="stop")
            {
                File.WriteAllBytes(Path.Combine(state,"events.json"),JsonSerializer.SerializeToUtf8Bytes(spool.Peek()));
                File.WriteAllBytes(Path.Combine(state,"FINAL.json"),JsonSerializer.SerializeToUtf8Bytes(new{State=status,Reports=reports}));break;
            }
        }
    }
    internal static async Task Run(string configuration)
    {
        var input=JsonSerializer.Deserialize<OwnedRuntimeNativeChecks.Config>(File.ReadAllBytes(configuration))!;
        if(!OperatingSystem.IsLinux()||geteuid()!=0||Directory.Exists(input.Root)||!input.Root.StartsWith("/var/lib/sequester-owned-runtime-",StringComparison.Ordinal)||input.Trust is not {Version:3,Mode:"enforce"})
            throw new ArgumentException("Fresh actual native companion installation required");
        var root=Path.GetDirectoryName(input.Root)!;const UnixFileMode privateMode=UnixFileMode.UserRead|UnixFileMode.UserWrite|UnixFileMode.UserExecute;
        Directory.CreateDirectory(input.Root,privateMode);using var key=RSA.Create(3072);
        var installed=NativeRuntimeModuleFixture.Stage(input,key.ExportSubjectPublicKeyInfo());
        File.WriteAllBytes(Path.Combine(root,"public-key.der"),key.ExportSubjectPublicKeyInfo());
        foreach(var name in new[]{"channel","exports","ordinary"})
        {
            var path=Path.Combine(root,name);Directory.CreateDirectory(path,privateMode|(name=="ordinary"?0:UnixFileMode.GroupRead|UnixFileMode.GroupExecute));
            if(chown(path,name=="ordinary"?65534u:0,65534)!=0)throw new IOException("Fixture directory ownership failed");
        }
        File.SetUnixFileMode(root,privateMode|UnixFileMode.OtherExecute);
        var stages=new List<object>();var checks=new List<string>();void Check(bool value,string text){if(!value)throw new Exception(text);checks.Add(text);}
        void Report(string message){lock(stages)stages.Add(new{Utc=DateTimeOffset.UtcNow,Monotonic=Stopwatch.GetTimestamp(),Message=message});Console.Error.WriteLine(message);}
        using var stop=new CancellationTokenSource();
        Task<LinuxControlledSourceRuntime.Outcome?> Start(CancellationToken token)=>Task.Run(()=>LinuxNativeCompanionRuntime.RunAsync(installed,Report,token));
        async Task Drain(Task<LinuxControlledSourceRuntime.Outcome?> task,CancellationTokenSource cancellation)
        {cancellation.Cancel();try{await task;}catch(OperationCanceledException)when(cancellation.IsCancellationRequested){}}
        var runtime=Start(stop.Token);Task<LinuxControlledSourceRuntime.Outcome?>? restarted=null;using var restartStop=new CancellationTokenSource();
        var info=new ProcessStartInfo("/usr/bin/setpriv"){UseShellExecute=false,RedirectStandardInput=true,RedirectStandardOutput=true,RedirectStandardError=true};
        foreach(var a in new[]{"--reuid","65534","--regid","65534","--clear-groups","--",Environment.ProcessPath!,"native-companion-runtime-child",root})info.ArgumentList.Add(a);
        using var child=Process.Start(info)??throw new IOException("Ordinary companion start failed");var stderr=child.StandardError.ReadToEndAsync();var childReplies=new List<JsonElement>();
        await child.StandardInput.WriteLineAsync(JsonSerializer.Serialize(new SignerInput(Convert.ToBase64String(key.ExportPkcs8PrivateKey()),input.Trust)));await child.StandardInput.FlushAsync();
        async Task<JsonElement> ChildCommand(string command)
        {
            await child.StandardInput.WriteLineAsync(command);await child.StandardInput.FlushAsync();
            var line=await child.StandardOutput.ReadLineAsync().WaitAsync(TimeSpan.FromSeconds(90));
            if(line==null)throw new IOException("Ordinary companion exited: "+await stderr);using var doc=JsonDocument.Parse(line);var value=doc.RootElement.Clone();childReplies.Add(value);
            if(value.GetProperty("Uid").GetUInt32()!=65534||value.GetProperty("Pid").GetInt32()!=child.Id)throw new InvalidDataException("Actual ordinary process identity mismatch");return value;
        }
        void Reply(object value){Console.WriteLine(JsonSerializer.Serialize(value));Console.Out.Flush();}
        List<AgentEvent> Events(string column)
        {
            if(column is not ("observation" or "original" or "completion"))throw new ArgumentException("Fixed event column required");
            using var c=new SqliteConnection(new SqliteConnectionStringBuilder{DataSource=Path.Combine(input.Root,"linux-forensic-intake/journal.db"),Mode=SqliteOpenMode.ReadOnly,Pooling=false}.ToString());c.Open();
            using var q=c.CreateCommand();q.CommandText="SELECT "+column+" FROM work WHERE "+column+" IS NOT NULL ORDER BY rowid";using var rows=q.ExecuteReader();var result=new List<AgentEvent>();while(rows.Read())result.Add(JsonSerializer.Deserialize<AgentEvent>((byte[])rows[0])!);return result;
        }
        bool aborted=false;
        string? NativeState(string id)
        {
            using var c=new SqliteConnection(new SqliteConnectionStringBuilder{DataSource=Path.Combine(input.Root,"linux-forensic-intake/journal.db"),Mode=SqliteOpenMode.ReadOnly,Pooling=false}.ToString());c.Open();
            using var q=c.CreateCommand();q.CommandText="SELECT state FROM native_pins WHERE event_id=$id";q.Parameters.AddWithValue("$id",id);return q.ExecuteScalar() as string;
        }
        try
        {
            JsonElement state;var deadline=Stopwatch.GetTimestamp()+240L*Stopwatch.Frequency;
            do
            {
                if(runtime.IsCompleted){await runtime;throw new IOException("Root runtime exited before readiness");}
                state=await ChildCommand("status");if(state.GetProperty("Status").GetProperty("ReadyAtRecentSample").GetBoolean())break;
                if(Stopwatch.GetTimestamp()>deadline)throw new IOException("Actual companion readiness deadline exceeded");await Task.Delay(250);
            }while(true);
            Check(state.GetProperty("Status").GetProperty("RootProcessId").GetInt32()==Environment.ProcessId,"ordinary status authenticates actual active root companion PID");
            var runtimeDirectory=Directory.GetDirectories(input.Root,"source-*").Single();
            Reply(new{Ready=true,RuntimeDirectory=runtimeDirectory,Ordinary=state});
            while(true)
            {
                var command=await Console.In.ReadLineAsync();if(command is null or "stop" or "abort-qualification"){aborted=command!="stop";break;}
                if(command!="status")throw new InvalidDataException("Unknown root fixture command");
                var complete=Events("completion").Select(e=>e.Forensics!.RelatedEventId).ToHashSet();
                Reply(new{Completed=runtime.IsCompleted,Work=Events("observation").Select(e=>new{e.EventId,e.User,e.Process,e.ProcessId,NativeState=NativeState(e.EventId),Done=complete.Contains(e.EventId)}),Ordinary=await ChildCommand("status")});
            }
            var paused=await ChildCommand("pause-policy");Check(paused.GetProperty("PolicyPaused").GetBoolean(),"qualification signer paused before companion shutdown/restart");
            await Drain(runtime,stop);
            var outcome=JsonSerializer.Deserialize<LinuxControlledSourceRuntime.Outcome>(File.ReadAllBytes(Path.Combine(runtimeDirectory,"outcome.json")))!;
            Check(outcome.Close=="CLOSE_RETURNED_OK"&&outcome.NativeClosure is {IssuedWorkDrained:true,ChildAndPipesReturned:true,MapHandlesClosed:true,ChildHandlesClosed:true},"real root composition drains actual native work child maps and controller");
            Check(!Directory.Exists("/sys/module/sq_actor_lease")&&!File.Exists("/dev/sq_actor_lease"),"registered module unloaded normally before delivery-only restart");
            var originals=Events("original");var completions=Events("completion");
            File.WriteAllBytes(Path.Combine(input.Root,"events.json"),JsonSerializer.SerializeToUtf8Bytes(new{Originals=originals,Completions=completions}));
            if(aborted){Reply(new{Closed=true,AbortedQualification=true,Outcome=outcome});return;}
            Check(originals.Count==5&&completions.Count==5,"five actual actor original/completion pairs retained after stop");
            using(var exports=LinuxProtectedDirectory.OpenRoot(Path.Combine(root,"exports"),65534))
            {
                var pending=exports.Names(256).Where(n=>n.EndsWith(".json",StringComparison.Ordinal)).ToArray();
                Check(pending.Length>=1,"at least one final shutdown packet remains without an acknowledgement listener");
                foreach(var name in pending)File.WriteAllBytes(Path.Combine(root,"final-export-"+name),exports.Read(name,LinuxNativeBridgePacket.MaximumBytes).Bytes);
            }
            var importDeadline=Stopwatch.GetTimestamp()+120L*Stopwatch.Frequency;
            do{state=await ChildCommand("status");if(state.GetProperty("Events").GetInt32()==10)break;if(Stopwatch.GetTimestamp()>importDeadline)throw new IOException("Final shutdown packet import deadline exceeded");await Task.Delay(250);}while(true);
            Check(!state.GetProperty("Status").GetProperty("ReadyAtRecentSample").GetBoolean(),"ordinary sensor imports final packets without claiming closed root source readiness");
            restarted=Start(restartStop.Token);
            var retirementDeadline=Stopwatch.GetTimestamp()+120L*Stopwatch.Frequency;
            while(true)
            {
                if(restarted.IsCompleted){await restarted;throw new IOException("Root delivery restart exited");}
                using var exports=LinuxProtectedDirectory.OpenRoot(Path.Combine(root,"exports"),65534);
                if(exports.Names(256).Length==0)break;
                if(Stopwatch.GetTimestamp()>retirementDeadline)throw new IOException("Exact receipt retirement deadline exceeded");await Task.Delay(250);
            }
            Check(!Directory.Exists("/sys/module/sq_actor_lease"),"restart accepts durable receipts while unsigned/unavailable policy prevents new module activation");
            await Drain(restarted,restartStop);var final=await ChildCommand("stop");await child.WaitForExitAsync();
            Check(child.ExitCode==0&&final.GetProperty("Events").GetInt32()==10&&final.GetProperty("Status").GetProperty("CloseState").GetString()=="CLOSED","ordinary worker retains ten events and drains normally");
            Check(Events("original").Count==5&&Events("completion").Count==5&&new EventSpool(Path.Combine(input.Root,"spool"),Sensor).Count==0,"receipt retirement removes only redundant root delivery queue; canonical source evidence retained");
            using(var replayJournal=new LinuxForensicJournal(input.Root,Sensor))
            using(var replayExports=LinuxProtectedDirectory.OpenRoot(Path.Combine(root,"exports"),65534))
            using(var replayActors=LinuxProtectedDirectory.OpenRoot(Path.Combine(input.Root,"evidence/actors")))
            {
                foreach(var path in Directory.GetFiles(Path.Combine(root,"ordinary/native-bridge-receipts"),"*.json"))
                {
                    var receipt=JsonSerializer.Deserialize<LinuxNativeBridgeImport.Receipt>(File.ReadAllBytes(path))!;
                    var hash=new LinuxNativeBridgeExport(replayExports,Sensor).PublishCommitted(replayJournal,receipt.SourceEventId,replayActors);
                    Check(hash==receipt.PacketSha256&&replayExports.Names(256).Length==0,"fresh exporter with stale inventory cannot recreate acknowledged packet "+receipt.SourceEventId);
                }
            }
            var summary=new{Passed=true,Checks=checks.Count,Details=checks,Outcome=outcome,RootPid=Environment.ProcessId,ChildPid=child.Id,OrdinaryFinal=final,Scope="Actual root runtime and cap-free client/native capture; ephemeral simulated management signer, no installed systemd or network-server acceptance"};
            File.WriteAllBytes(Path.Combine(root,"COMPANION-RESULTS.json"),JsonSerializer.SerializeToUtf8Bytes(summary));Reply(new{Closed=true,Outcome=outcome,Originals=originals.Count,Completions=completions.Count,Checks=checks.Count});
        }
        finally
        {
            try{await Drain(runtime,stop);if(restarted!=null)await Drain(restarted,restartStop);}
            finally
            {
                // A completed startup failure must still stop the independent
                // ordinary child. An unresolved actual native drain above
                // continues to retain the owned guest without a forced kill.
                if(!child.HasExited){try{_=await ChildCommand("stop");}catch(IOException){}await child.WaitForExitAsync();}
                File.WriteAllBytes(Path.Combine(root,"companion-stages.json"),JsonSerializer.SerializeToUtf8Bytes(stages));
                File.WriteAllBytes(Path.Combine(root,"ordinary-replies.json"),JsonSerializer.SerializeToUtf8Bytes(childReplies));File.WriteAllText(Path.Combine(root,"ordinary.stderr.log"),await stderr);
            }
        }
    }
}
