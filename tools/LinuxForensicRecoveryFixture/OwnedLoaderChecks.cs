using RansomFree.Contracts;
using System.Runtime.InteropServices;
using System.Text;
using System.Text.Json;
using RansomFree.Client;

static class OwnedLoaderChecks
{
    internal static async Task Child(string mode)
    {
        var stop=new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        using var signal=PosixSignalRegistration.Create(PosixSignal.SIGTERM,context=>{context.Cancel=true;stop.TrySetResult();});
        var stdout=Console.OpenStandardOutput();var stderr=Console.OpenStandardError();
        if(mode=="flood")
        {var bytes=Enumerable.Range(0,4096).Select(i=>(byte)(i%251)).ToArray();for(var i=0;i<64;i++)await stderr.WriteAsync(bytes);await stderr.FlushAsync();}
        var ready=new{controlledReady=true,controlVersion=1,schemaVersion=5,loadedProgramIds=new[]{1,2,3,4,5},attachedProgramIds=new[]{2,3,4},observeAttached=false,denialAttached=false,scratchMapFrozen=true,scratchMapId=11,configMapFrozen=true,configMapId=12,eventsMapId=13,lostMapId=14,providerEpoch=7,activationNonce=new string('a',32),targetInode=321,targetDevice=17,targetPinned=true,mode=0,lostAtReady=0,activationFrame="one-command-then-eof"};
        async Task Line(byte[] bytes){await stdout.WriteAsync(bytes);await stdout.WriteAsync(new byte[]{10});await stdout.FlushAsync();}
        await Line(JsonSerializer.SerializeToUtf8Bytes(ready));
        if(mode=="bind-failure"){await Task.Delay(1500);return;}
        if(mode=="await-stop"){await stop.Task;await Line("STOPPED"u8.ToArray());return;}
        if(mode=="queued-fault")
        {await Line("QUEUED"u8.ToArray());await stdout.WriteAsync(Enumerable.Repeat((byte)'x',65537+8192).ToArray());await stdout.FlushAsync();await stop.Task;return;}
        if(mode=="early-exit")return;
        if(mode=="partial-eof")
        {await stdout.WriteAsync("unfinished"u8.ToArray());await stdout.FlushAsync();return;}
        if(mode=="overlong")
        {await stdout.WriteAsync(Enumerable.Repeat((byte)'x',65537+8192).ToArray());await stdout.FlushAsync();await stop.Task;return;}
        using var input=new MemoryStream();await Console.OpenStandardInput().CopyToAsync(input);
        await Line(JsonSerializer.SerializeToUtf8Bytes(new{Input=Convert.ToBase64String(input.ToArray())}));
        if(mode=="flood")for(var i=0;i<256;i++)await Line(Encoding.ASCII.GetBytes(i.ToString("D4")+new string('x',1020)));
        await Line("END"u8.ToArray());await stop.Task;
        await Line("STOPPED"u8.ToArray());
    }
    internal static async Task Run(string root)
    {
        if(!OperatingSystem.IsLinux()||Directory.Exists(root))throw new ArgumentException("Fresh owned Linux process fixture required");Directory.CreateDirectory(root);int checks=0;var receipts=new List<object>();
        void Check(bool ok,string label){if(!ok)throw new Exception(label);checks++;Console.WriteLine("PASS: "+label);}
        foreach(var mode in new[]{"normal","flood","canceled-wait","overlong","partial-eof","early-exit"})
        {
            var arguments=new List<string>();if(Path.GetFileNameWithoutExtension(Environment.ProcessPath)=="dotnet")arguments.Add(typeof(OwnedLoaderChecks).Assembly.Location);
            arguments.AddRange(["owned-loader-child",mode]);
            var owner=LinuxOwnedLoaderProcess.StartForTest(Environment.ProcessPath!,arguments.ToArray());
            try
            {
            var raw=await owner.ReadFrameAsync();var ready=LinuxControlledLoaderProtocol.ParseReady(raw??throw new Exception("No ready frame"));
            Check(ready.Epoch==7,"owned raw stdout retains exact ready: "+mode);
            if(mode=="early-exit")
            {Check(await owner.ReadFrameAsync()==null,"actual child exit closes stdout");await owner.Completion;Check(owner.ExitCode==0,"actual exit observed without PID signalling");}
            else if(mode=="partial-eof")
            {
                try{await owner.ReadFrameAsync();throw new Exception("Partial frame accepted");}
                catch(Exception ex)when(ex is EndOfStreamException or System.Threading.Channels.ChannelClosedException){Check(true,"partial EOF reaches owner as a framing failure");}
                await owner.Completion;
                Check(owner.Snapshot().StdoutFailure?.Contains("LOADER_PARTIAL_FRAME")==true&&owner.ExitCode==0,"partial frame failure retains actual successful child exit separately");
            }
            else if(mode=="overlong")
            {
                try{await owner.ReadFrameAsync();throw new Exception("Overlong frame accepted");}
                catch(Exception ex)when(ex is InvalidDataException or System.Threading.Channels.ChannelClosedException){Check(true,"overlong frame reaches owner before child exit");}
                Check(!owner.HasExited,"framing failure does not pretend child teardown");owner.RequestStop();await owner.Completion;
                Check(owner.Snapshot().StdoutFailure!=null&&owner.Snapshot().SignalError==0,"failed parser drains and pidfd stop waits actual child exit");
                Check(owner.Snapshot().UnframedDrainBytes==8192,"failed parser drains exact residual bytes without inventing frames");
            }
            else
            {
                if(mode=="canceled-wait")
                {
                    using var cancel=new CancellationTokenSource(TimeSpan.FromMilliseconds(30));
                    try{await owner.ReadFrameAsync(cancel.Token);throw new Exception("Empty frame wait was not canceled");}catch(OperationCanceledException){Check(true,"cancellation ends only managed frame wait");}
                    Check(!owner.HasExited&&!owner.Completion.IsCompleted,"canceled wait leaves child and pipe drains alive");
                    try{owner.Dispose();throw new Exception("Live loader was disposed");}catch(InvalidOperationException){Check(true,"live child ownership cannot be discarded");}
                }
                var session=Guid.NewGuid().ToString("N");var write=owner.ActivateOnce(ready,session);
                Check(write.Written==write.Requested&&write.WriteError==0&&write.CloseResult==0&&write.CloseError==0,"one native activation write and explicit EOF close: "+mode);
                try{owner.ActivateOnce(ready,session);throw new Exception("Duplicate activation accepted");}catch(InvalidOperationException){Check(true,"activation cannot be retried: "+mode);}
                using var echo=JsonDocument.Parse((await owner.ReadFrameAsync())!);
                Check(Convert.FromBase64String(echo.RootElement.GetProperty("Input").GetString()!).SequenceEqual(LinuxControlledLoaderProtocol.ActivationFrame(ready,session)),"child receives exact single activation frame through EOF: "+mode);
                int count=0;byte[]? frame;
                while((frame=await owner.ReadFrameAsync())!=null&&!frame.AsSpan().SequenceEqual("END"u8))
                {if(mode!="flood"||Encoding.ASCII.GetString(frame)!=count.ToString("D4")+new string('x',1020))throw new Exception("Flood frame order/data differs");count++;}
                Check(frame!=null&&count==(mode=="flood"?256:0),"bounded stdout queue drains exact frame order: "+mode);
                owner.RequestStop();owner.RequestStop();Check((await owner.ReadFrameAsync())!.AsSpan().SequenceEqual("STOPPED"u8),"owned pidfd SIGTERM permits final child output: "+mode);
                Check(await owner.ReadFrameAsync()==null,"stdout reaches real EOF: "+mode);await owner.Completion;
                Check(owner.ExitCode==0&&owner.Snapshot().SignalError==0,"child exit and both pipe drains complete: "+mode);
                if(mode=="flood")
                {
                    var expected=Enumerable.Range(0,8192).Select(i=>(byte)((i%4096)%251)).ToArray();var d=owner.Snapshot();
                    Check(d.StderrBytes==262144&&Convert.FromBase64String(d.StderrTailBase64).SequenceEqual(expected),"stderr flood independently drains with exact bounded8192-byte binary tail");
                }
            }
            var diagnostic=owner.Snapshot();receipts.Add(new{Mode=mode,Pid=owner.Pid,ExitCode=owner.ExitCode,Diagnostic=diagnostic,Write=owner.ActivationWrite});
            Check(owner.Completion.IsCompletedSuccessfully,"dispose follows real process/pipe completion: "+mode);
            }
            finally
            {
                owner.RequestStop();
                try{while(await owner.ReadFrameAsync()!=null){}}
                catch(Exception ex)when(ex is IOException or InvalidDataException or System.Threading.Channels.ChannelClosedException){}
                await owner.Completion;owner.Dispose();
            }
        }
        var result=new{Passed=true,Checks=checks,Cases=receipts,Scope="Actual owned Linux child processes, redirected pipes, one native write/EOF, pidfd SIGTERM, flood/framing/cancellation; fixture child only, no kernel controller or source activation"};
        File.WriteAllText(Path.Combine(root,"RESULTS.json"),JsonSerializer.Serialize(result));Console.WriteLine(JsonSerializer.Serialize(new{Passed=true,Checks=checks}));
    }
}
