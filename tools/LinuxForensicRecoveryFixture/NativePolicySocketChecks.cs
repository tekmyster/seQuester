using System.Buffers.Binary;
using System.ComponentModel;
using System.Diagnostics;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using RansomFree.Client.Forensics;
using RansomFree.Contracts;

internal static class NativePolicySocketChecks
{
    private const string Sensor="11111111111111111111111111111111",Origin="https://qualification.invalid/";
    [DllImport("libc")]private static extern uint geteuid();
    [DllImport("libc",SetLastError=true)]private static extern int chown(string path,uint uid,uint gid);
    [DllImport("libc",SetLastError=true)]private static extern int socket(int domain,int type,int protocol);
    [DllImport("libc",SetLastError=true)]private static extern int bind(int fd,byte[] address,uint length);
    [DllImport("libc")]private static extern int close(int fd);
    private static LinuxProtectedDirectory.Identity RetainedSocket(LinuxProtectedDirectory directory,string name)
    {
        var fd=socket(1,1|0x80000,0);if(fd<0)throw new Win32Exception(Marshal.GetLastPInvokeError());
        try
        {
            var path=Encoding.UTF8.GetBytes(directory.SocketPath(name));if(path.Length>107)throw new Exception("Socket path bound");
            var address=new byte[path.Length+3];address[0]=1;path.CopyTo(address,2);
            if(bind(fd,address,(uint)address.Length)!=0)throw new Win32Exception(Marshal.GetLastPInvokeError());
            directory.ConfigureSocket(name);return directory.RequireSocket(name);
        }
        finally{close(fd);} // libc close leaves the pathname for reconciliation.
    }
    private static NativePolicySnapshot Snapshot(string nonce)
    {
        var now=DateTimeOffset.UtcNow;var rules=new TrustPolicy(1,"enforce",[],[],"socket fixture",DateTimeOffset.Parse("2026-01-01T00:00:00Z")){Version=3};
        return new(Origin,Sensor,nonce,now,now.AddMinutes(2),new(Sensor,null,rules,rules.Digest(),now,now.AddMinutes(2)),new(null,0,MonitoringPolicy.Default));
    }
    internal static async Task Child(string directory,string mode)
    {
        if(geteuid()!=65534)throw new Exception("Unprivileged policy child required");
        // An ephemeral qualification signer is delivered only through this
        // anonymous pipe. No test private key is written to disk or logs.
        using var key=RSA.Create();key.ImportPkcs8PrivateKey(Convert.FromBase64String((await Console.In.ReadLineAsync())!),out _);
        SignedNativePolicy? signed=null;bool accepted=false;
        if(mode is "valid" or "cancel-after-admission")
        {
            try{await LinuxNativePolicySocket.RelayAsync(directory,65534,Sensor,Origin,(nonce,_)=>Task.FromResult(signed=SignedNativePolicy.Sign(Snapshot(nonce),key)),CancellationToken.None);accepted=true;}
            catch(IOException)when(mode=="cancel-after-admission"){}
        }
        else
        {
            using var parent=LinuxProtectedDirectory.OpenRoot(directory,65534);parent.RequireSocket(LinuxNativePolicySocket.Name);
            using var socket=new Socket(AddressFamily.Unix,SocketType.Stream,ProtocolType.Unspecified);
            await socket.ConnectAsync(new UnixDomainSocketEndPoint(parent.SocketPath(LinuxNativePolicySocket.Name)));_=LinuxNativePolicySocket.RequirePeer(socket,0);
            using var stream=new NetworkStream(socket);var id=Guid.NewGuid().ToString("N");
            var request=new LinuxNativePolicySocket.Request(1,Sensor,Origin,id);var token=CancellationToken.None;
            if(mode is "oversize" or "empty" or "truncated")
            {
                var header=new byte[4];BinaryPrimitives.WriteUInt32LittleEndian(header,mode=="oversize"?LinuxNativePolicySocket.MaximumFrame+1u:mode=="empty"?0u:100u);
                await stream.WriteAsync(header);if(mode=="truncated")await stream.WriteAsync(new byte[]{123});socket.Shutdown(SocketShutdown.Send);
            }
            else if(mode is "unknown" or "duplicate")
            {
                var json=JsonSerializer.Serialize(request);var bytes=Encoding.UTF8.GetBytes(json[..^1]+(mode=="unknown"?",\"Extra\":true}":",\"Version\":1}"));var header=new byte[4];BinaryPrimitives.WriteUInt32LittleEndian(header,(uint)bytes.Length);
                await stream.WriteAsync(header);await stream.WriteAsync(bytes);
            }
            else
            {
                await LinuxNativePolicySocket.Write(stream,mode=="wrong-sensor"?request with{SensorId=Guid.NewGuid().ToString("N")}:mode=="wrong-server"?request with{Server="https://other.invalid/"}:request,token);
                if(mode is "bad-signature" or "wrong-reply")
                {
                    var challenge=await LinuxNativePolicySocket.Read<LinuxNativePolicySocket.Challenge>(stream,token);signed=SignedNativePolicy.Sign(Snapshot(challenge.Nonce),key);
                    if(mode=="bad-signature")signed=signed with{SignatureBase64=Convert.ToBase64String(new byte[384])};
                    await LinuxNativePolicySocket.Write(stream,new LinuxNativePolicySocket.Reply(1,mode=="wrong-reply"?Guid.NewGuid().ToString("N"):id,signed),token);
                }
            }
            var end=new byte[1];try{if(await stream.ReadAsync(end).AsTask().WaitAsync(TimeSpan.FromSeconds(25))!=0)throw new Exception("Invalid request was not closed");}catch(IOException){}
        }
        Console.WriteLine(JsonSerializer.Serialize(new{Uid=geteuid(),Pid=Environment.ProcessId,Mode=mode,Accepted=accepted,Envelope=signed}));
    }
    internal static async Task Run(string root)
    {
        if(!OperatingSystem.IsLinux()||geteuid()!=0||Directory.Exists(root))throw new ArgumentException("Fresh root Linux socket fixture required");
        Directory.CreateDirectory(root,UnixFileMode.UserRead|UnixFileMode.UserWrite|UnixFileMode.UserExecute|UnixFileMode.GroupRead|UnixFileMode.GroupExecute);
        if(chown(root,0,65534)!=0)throw new Win32Exception(Marshal.GetLastPInvokeError());
        var checks=new List<string>();void Check(bool ok,string label){if(!ok)throw new Exception(label);checks.Add(label);}
        async Task Reject(Func<Task> action,Func<Exception,bool> expected,string label)
        {try{await action();}catch(Exception ex)when(expected(ex)){Check(true,label);return;}throw new Exception("Accepted: "+label);}
        using var key=RSA.Create(3072);File.WriteAllBytes(Path.Combine(root,"public-key.der"),key.ExportSubjectPublicKeyInfo());
        using var journal=new LinuxForensicJournal(Path.Combine(root,"owner-state"),Sensor);
        using var owner=new LinuxNativePolicyAdmission(journal,Origin,Sensor,key.ExportSubjectPublicKeyInfo());
        using var listener=new LinuxNativePolicySocket(root,65534,65534,Sensor,Origin);
        using(var protectedDirectory=LinuxProtectedDirectory.OpenRoot(root,65534)){protectedDirectory.RequireSocket(LinuxNativePolicySocket.Name);Check(true,"bound socket has exact root/group0660 permission and protected ancestors");}
        await Reject(()=>{using var collision=new LinuxNativePolicySocket(root,65534,65534,Sensor,Origin);return Task.CompletedTask;},e=>e is SocketException,"second bind refuses existing listener path");
        using(var cancellation=new CancellationTokenSource())
        {
            var waiting=listener.AcceptAsync(owner,cancellation.Token);
            await Reject(async()=>{_=await listener.AcceptAsync(owner,CancellationToken.None);},e=>e is InvalidOperationException,"concurrent exchange refused without replacing root challenge");
            cancellation.Cancel();await Reject(async()=>{_=await waiting;},e=>e is OperationCanceledException,"idle accept cancellation releases exchange slot");
        }
        var rejectedRoot=listener.AcceptAsync(owner,CancellationToken.None);
        using(var socket=new Socket(AddressFamily.Unix,SocketType.Stream,ProtocolType.Unspecified))
        {
            await socket.ConnectAsync(new UnixDomainSocketEndPoint(Path.Combine(root,LinuxNativePolicySocket.Name)));
            await Reject(async()=>{_=await rejectedRoot;},e=>e is UnauthorizedAccessException,"root connection rejected when exact ordinary service UID was configured");
            await Reject(()=>{_=LinuxNativePolicySocket.RequirePeer(socket,65534);return Task.CompletedTask;},e=>e is UnauthorizedAccessException,"client-side peer check rejects a root server when a different UID is expected");
        }
        LinuxNativePolicyLease? prior=null;
        var confirmations=0;
        foreach(var mode in new[]{"valid","oversize","empty","truncated","unknown","duplicate","wrong-sensor","wrong-server","wrong-reply","bad-signature","valid"})
        {
            var beforeConfirmations=confirmations;
            var accepted=listener.AcceptAsync(owner,envelope=>owner.AcceptLease(envelope),CancellationToken.None,_=>Interlocked.Increment(ref confirmations));var start=new ProcessStartInfo("/usr/bin/setpriv"){UseShellExecute=false,RedirectStandardInput=true,RedirectStandardOutput=true,RedirectStandardError=true};
            foreach(var arg in new[]{"--reuid","65534","--regid","65534","--clear-groups","--",Environment.ProcessPath!,"native-policy-socket-child",root,mode})start.ArgumentList.Add(arg);
            using var child=Process.Start(start)??throw new IOException("Unprivileged policy child failed to start");
            var stdout=child.StandardOutput.ReadToEndAsync();var stderr=child.StandardError.ReadToEndAsync();await child.StandardInput.WriteLineAsync(Convert.ToBase64String(key.ExportPkcs8PrivateKey()));child.StandardInput.Close();
            if(mode=="valid")
            {
                var next=await accepted.WaitAsync(TimeSpan.FromSeconds(25));Check(next.IsCurrent&&next.Current().SensorId==Sensor,"real unprivileged signed relay creates admitted root policy lease");
                Check(prior==null||!prior.IsCurrent,"new signed relay revokes old policy lease");prior=next;
                Check(confirmations==beforeConfirmations+1,"startup confirmation occurs only after successful acceptance write");
            }
            else
            {
                await Reject(async()=>{_=await accepted.WaitAsync(TimeSpan.FromSeconds(25));},e=>e is InvalidDataException or IOException,"malformed/untrusted request refused: "+mode);
                Check(prior!.IsCurrent,"rejected unauthenticated policy does not alter existing signed assignment: "+mode);
                Check(confirmations==beforeConfirmations,"failed exchange cannot release a startup policy waiter: "+mode);
            }
            await child.WaitForExitAsync().WaitAsync(TimeSpan.FromSeconds(30));var output=await stdout;var error=await stderr;
            var prefix=checks.Count+"-"+mode;File.WriteAllText(Path.Combine(root,prefix+".json"),output);File.WriteAllText(Path.Combine(root,prefix+".stderr.log"),error);
            Check(child.ExitCode==0,"unprivileged child completed with explicit response: "+mode+" "+error);
            using var result=JsonDocument.Parse(output);Check(result.RootElement.GetProperty("Uid").GetUInt32()==65534&&result.RootElement.GetProperty("Pid").GetInt32()==child.Id&&result.RootElement.GetProperty("Accepted").GetBoolean()==(mode=="valid"),"OS UID/PID and child acceptance match controlled process: "+mode);
        }
        var pendingClose=listener.AcceptAsync(owner,CancellationToken.None);listener.Dispose();
        await Reject(async()=>{_=await pendingClose;},e=>e is OperationCanceledException or ObjectDisposedException or SocketException,"listener disposal cancels its pending exchange");
        using(var draining=new LinuxNativePolicySocket(root,65534,65534,Sensor,Origin))
        using(var release=new ManualResetEventSlim())
        {
            var entered=new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);LinuxNativePolicyLease? committed=null;var startupConfirmed=false;
            var accepting=draining.AcceptAsync(owner,envelope=>{committed=owner.AcceptLease(envelope);entered.TrySetResult();release.Wait();return committed;},CancellationToken.None,_=>startupConfirmed=true);
            var start=new ProcessStartInfo("/usr/bin/setpriv"){UseShellExecute=false,RedirectStandardInput=true,RedirectStandardOutput=true,RedirectStandardError=true};
            foreach(var arg in new[]{"--reuid","65534","--regid","65534","--clear-groups","--",Environment.ProcessPath!,"native-policy-socket-child",root,"cancel-after-admission"})start.ArgumentList.Add(arg);
            using var child=Process.Start(start)??throw new IOException("Policy shutdown child failed to start");var stdout=child.StandardOutput.ReadToEndAsync();var stderr=child.StandardError.ReadToEndAsync();
            await child.StandardInput.WriteLineAsync(Convert.ToBase64String(key.ExportPkcs8PrivateKey()));child.StandardInput.Close();Task? stopping=null;
            try
            {
                await entered.Task.WaitAsync(TimeSpan.FromSeconds(30));Check(committed!.IsCurrent,"shutdown test reached actual signed durable admission");
                stopping=draining.DisposeAsync().AsTask();Check(!stopping.IsCompleted,"policy shutdown waits for accepted admission callback to return");
                Check(ReferenceEquals(stopping,draining.DisposeAsync().AsTask()),"concurrent policy stops share one drain result");
            }
            finally{release.Set();}
            await Reject(async()=>{_=await accepting;},e=>e is OperationCanceledException,"shutdown cancellation remains visible after signed admission returns");
            await stopping!;Check(!committed!.IsCurrent&&!prior!.IsCurrent,"drained policy shutdown revokes newly admitted and replaced policy leases");
            Check(!startupConfirmed,"cancellation after durable admission cannot publish revoked startup authority");
            await child.WaitForExitAsync().WaitAsync(TimeSpan.FromSeconds(30));var output=await stdout;File.WriteAllText(Path.Combine(root,"shutdown-admission.json"),output);File.WriteAllText(Path.Combine(root,"shutdown-admission.stderr.log"),await stderr);
            using var proof=JsonDocument.Parse(output);var v=proof.RootElement;
            Check(child.ExitCode==0&&v.GetProperty("Uid").GetUInt32()==65534&&v.GetProperty("Pid").GetInt32()==child.Id&&!v.GetProperty("Accepted").GetBoolean(),"policy child receives closure without a false successful relay receipt");
            using var parent=LinuxProtectedDirectory.OpenRoot(root,65534);Check(!parent.Names(256).Contains(LinuxNativePolicySocket.Name),"drained policy shutdown retires exact socket node");
        }
        owner.Dispose();Check(!prior!.IsCurrent,"closed admission owner revokes last relayed lease");
        using(var parent=LinuxProtectedDirectory.OpenRoot(root,65534))Check(!parent.Names(256).Contains(LinuxNativePolicySocket.Name),"managed listener close releases its own socket node");
        using(var parent=LinuxProtectedDirectory.OpenRoot(root,65534))
        {
            var orphan=RetainedSocket(parent,LinuxNativePolicySocket.Name);
            await Reject(()=>{using var collision=new LinuxNativePolicySocket(root,65534,65534,Sensor,Origin);return Task.CompletedTask;},e=>e is SocketException,"startup refuses retained closed socket instead of unlinking it");
            await Reject(()=>{parent.RetireOwnedSocket(LinuxNativePolicySocket.Name,orphan with{Inode=orphan.Inode+1});return Task.CompletedTask;},e=>e is IOException,"shutdown reconciliation refuses unexpected inode");
            Check(parent.RequireSocket(LinuxNativePolicySocket.Name)==orphan,"rejected reconciliation retains exact unexpected socket node");
            parent.RetireOwnedSocket(LinuxNativePolicySocket.Name,orphan);Check(!parent.Names(256).Contains(LinuxNativePolicySocket.Name),"shutdown reconciliation removes and fsyncs exact closed socket");
            parent.RetireOwnedSocket(LinuxNativePolicySocket.Name,orphan);Check(true,"repeated shutdown reconciliation accepts committed absence");
            parent.PublishNew(LinuxNativePolicySocket.Name,[1,2,3]);
            await Reject(()=>{parent.RetireOwnedSocket(LinuxNativePolicySocket.Name,orphan);return Task.CompletedTask;},e=>e is IOException,"shutdown reconciliation rejects regular replacement file");
            Check(parent.Read(LinuxNativePolicySocket.Name,3).Bytes.SequenceEqual(new byte[]{1,2,3}),"unexpected replacement file retained unchanged");
        }
        File.WriteAllText(Path.Combine(root,"RESULTS.json"),JsonSerializer.Serialize(new{Passed=true,Checks=checks.Count,Details=checks,Root=root,Scope="Actual Unix socket, root and UID65534 peer checks, signed policy admission, malformed frame/context rejection and bounded exchange ownership; no installed source activation"}));
        Console.WriteLine(JsonSerializer.Serialize(new{Passed=true,Checks=checks.Count,Root=root}));
    }
}
