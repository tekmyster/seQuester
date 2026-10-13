using System.Buffers.Binary;
using System.Diagnostics;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using System.Text;
using System.Text.Json;
using RansomFree.Client;
using RansomFree.Client.Forensics;

internal static class NativeBridgeSocketChecks
{
    internal const string Sensor="11111111111111111111111111111111",Origin="https://qualification.invalid/";
    [DllImport("libc")]private static extern uint geteuid();
    internal static async Task Child(string directory,string mode)
    {
        if(geteuid()!=65534)throw new Exception("Unprivileged delivery child required");
        var receipt=JsonSerializer.Deserialize<LinuxNativeBridgeImport.Receipt>((await Console.In.ReadLineAsync())!)!;
        bool accepted=false;
        if(mode=="valid")
        {
            await LinuxNativeBridgeSocket.ConfirmAsync(directory,65534,Sensor,Origin,receipt,CancellationToken.None);accepted=true;
        }
        else
        {
            using var parent=LinuxProtectedDirectory.OpenRoot(directory,65534);parent.RequireSocket(LinuxNativeBridgeSocket.Name);
            using var socket=new Socket(AddressFamily.Unix,SocketType.Stream,ProtocolType.Unspecified);
            await socket.ConnectAsync(new UnixDomainSocketEndPoint(parent.SocketPath(LinuxNativeBridgeSocket.Name)));_=LinuxNativePolicySocket.RequirePeer(socket,0);
            using var stream=new NetworkStream(socket);var id=Guid.NewGuid().ToString("N");
            var request=new LinuxNativeBridgeSocket.Request(1,Sensor,Origin,id,receipt);
            request=mode switch
            {
                "wrong-sensor"=>request with{SensorId=Guid.NewGuid().ToString("N")},
                "wrong-server"=>request with{Server="https://other.invalid/"},
                "wrong-hash"=>request with{Receipt=receipt with{PacketSha256=new string('0',64)}},
                "wrong-completion"=>request with{Receipt=receipt with{CompletionEventId=Guid.NewGuid().ToString("N")}},
                "unpublished"=>request with{Receipt=receipt with{SourceEventId=Guid.NewGuid().ToString("N")}},
                _=>request
            };
            if(mode is "oversize" or "empty" or "truncated")
            {
                var header=new byte[4];BinaryPrimitives.WriteUInt32LittleEndian(header,mode=="oversize"?LinuxNativeBridgeSocket.MaximumFrame+1u:mode=="empty"?0u:100u);
                await stream.WriteAsync(header);if(mode=="truncated")await stream.WriteAsync(new byte[]{123});socket.Shutdown(SocketShutdown.Send);
            }
            else if(mode is "unknown" or "duplicate")
            {
                var json=JsonSerializer.Serialize(request);var bytes=Encoding.UTF8.GetBytes(json[..^1]+(mode=="unknown"?",\"Extra\":true}":",\"Version\":1}"));
                var header=new byte[4];BinaryPrimitives.WriteUInt32LittleEndian(header,(uint)bytes.Length);await stream.WriteAsync(header);await stream.WriteAsync(bytes);
            }
            else await LinuxNativePolicySocket.Write(stream,request,CancellationToken.None);
            if(mode=="disconnect-after-send")socket.Shutdown(SocketShutdown.Both);
            else
            {
                var end=new byte[1];try{if(await stream.ReadAsync(end).AsTask().WaitAsync(TimeSpan.FromSeconds(25))!=0)throw new Exception("Rejected acknowledgment returned success");}catch(IOException){}
            }
        }
        Console.WriteLine(JsonSerializer.Serialize(new{Uid=geteuid(),Pid=Environment.ProcessId,Mode=mode,Accepted=accepted}));
    }
    internal static async Task Exchange(LinuxNativeBridgeSocket listener,LinuxNativeBridgeExport exporter,LinuxForensicJournal journal,EventSpool spool,
        string directory,string artifacts,LinuxNativeBridgeImport.Receipt receipt,string mode,Action<bool,string> check)
    {
        var accepted=listener.AcceptAsync(exporter,journal,spool,CancellationToken.None);
        var start=new ProcessStartInfo("/usr/bin/setpriv"){UseShellExecute=false,RedirectStandardInput=true,RedirectStandardOutput=true,RedirectStandardError=true};
        foreach(var arg in new[]{"--reuid","65534","--regid","65534","--clear-groups","--",Environment.ProcessPath!,"native-bridge-socket-child",directory,mode})start.ArgumentList.Add(arg);
        using var child=Process.Start(start)??throw new IOException("Unprivileged acknowledgment child failed to start");
        var stdout=child.StandardOutput.ReadToEndAsync();var stderr=child.StandardError.ReadToEndAsync();await child.StandardInput.WriteLineAsync(JsonSerializer.Serialize(receipt));child.StandardInput.Close();
        Exception? failure=null;LinuxNativeBridgeImport.Receipt? returned=null;
        try{returned=await accepted.WaitAsync(TimeSpan.FromSeconds(25));}catch(Exception e)when(e is IOException or InvalidDataException or SocketException or KeyNotFoundException){failure=e;}
        check(mode=="valid"?failure==null&&returned==receipt:mode=="disconnect-after-send"?failure is null or IOException or SocketException:failure!=null,"root exact local-import acknowledgment result: "+mode);
        await child.WaitForExitAsync().WaitAsync(TimeSpan.FromSeconds(30));var output=await stdout;var error=await stderr;
        var prefix=Path.Combine(artifacts,"exchange-"+child.Id+"-"+mode);File.WriteAllText(prefix+".json",output);File.WriteAllText(prefix+".stderr.log",error);
        check(child.ExitCode==0,"unprivileged acknowledgment child completed: "+mode+" "+error);
        using var proof=JsonDocument.Parse(output);var v=proof.RootElement;
        check(v.GetProperty("Uid").GetUInt32()==65534&&v.GetProperty("Pid").GetInt32()==child.Id&&v.GetProperty("Accepted").GetBoolean()==(mode=="valid"),"actual acknowledgment peer UID/PID and bounded reply: "+mode);
    }
    internal static async Task Drain(LinuxNativeBridgeExport exporter,LinuxForensicJournal journal,EventSpool spool,string directory,string artifacts,
        LinuxNativeBridgeImport.Receipt receipt,Action<bool,string> check)
    {
        using var listener=new LinuxNativeBridgeSocket(directory,65534,65534,Sensor,Origin);
        using var release=new ManualResetEventSlim();var entered=new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var accepted=listener.AcceptAsync(exporter,journal,spool,CancellationToken.None,point=>
        {if(point=="bridge-import-ledger-committed"){entered.TrySetResult();release.Wait();}});
        var start=new ProcessStartInfo("/usr/bin/setpriv"){UseShellExecute=false,RedirectStandardInput=true,RedirectStandardOutput=true,RedirectStandardError=true};
        foreach(var arg in new[]{"--reuid","65534","--regid","65534","--clear-groups","--",Environment.ProcessPath!,"native-bridge-socket-child",directory,"expect-disconnected"})start.ArgumentList.Add(arg);
        using var child=Process.Start(start)??throw new IOException("Delivery drain child failed to start");var stdout=child.StandardOutput.ReadToEndAsync();var stderr=child.StandardError.ReadToEndAsync();
        await child.StandardInput.WriteLineAsync(JsonSerializer.Serialize(receipt));child.StandardInput.Close();
        Task? stopping=null;
        try
        {
            await entered.Task.WaitAsync(TimeSpan.FromSeconds(30));check(true,"actual ordinary-user acknowledgment reached durable root ledger before shutdown");
            stopping=listener.DisposeAsync().AsTask();check(!stopping.IsCompleted,"delivery shutdown remains pending while accepted retirement is in progress");
            check(ReferenceEquals(stopping,listener.DisposeAsync().AsTask()),"concurrent delivery stops share one drain result");
        }
        finally{release.Set();}
        bool cancelled=false;try{await accepted;}catch(OperationCanceledException){cancelled=true;}catch(IOException){cancelled=true;}
        await stopping!;check(cancelled,"accepted delivery finished durable retirement then observed shutdown cancellation");
        await child.WaitForExitAsync().WaitAsync(TimeSpan.FromSeconds(30));var output=await stdout;File.WriteAllText(Path.Combine(artifacts,"shutdown-delivery.json"),output);File.WriteAllText(Path.Combine(artifacts,"shutdown-delivery.stderr.log"),await stderr);
        using var proof=JsonDocument.Parse(output);var v=proof.RootElement;
        check(child.ExitCode==0&&v.GetProperty("Uid").GetUInt32()==65534&&v.GetProperty("Pid").GetInt32()==child.Id&&!v.GetProperty("Accepted").GetBoolean(),"shutdown child receives closure without fabricated acknowledgment");
        check(spool.Count==0&&journal.PendingNativeImportRetirements().Length==0&&journal.Read(receipt.SourceEventId).Done,"drained acknowledgment retained source evidence and completed duplicate retirement");
        using var parent=LinuxProtectedDirectory.OpenRoot(directory,65534);check(!parent.Names(256).Contains(LinuxNativeBridgeSocket.Name),"drained delivery stop retired its exact socket node");
    }
}
