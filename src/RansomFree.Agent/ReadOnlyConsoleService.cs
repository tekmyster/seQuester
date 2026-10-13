using System.Buffers.Binary;
using System.IO.Pipes;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Text.Json;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using RansomFree.Contracts;

internal sealed class ReadOnlyConsoleService(AgentPaths paths,AgentConsoleState state,ILogger<ReadOnlyConsoleService> logger):BackgroundService
{
    protected override async Task ExecuteAsync(CancellationToken ct)
    {
        if(!paths.EnableConsolePipe)return;
        var approvals=Path.Combine(paths.Directory,"tray-readers.json");if(!File.Exists(approvals))return;
        string[] readers;
        try
        {
            if(new FileInfo(approvals).Length>16384)throw new InvalidDataException("Tray reader approvals exceed their limit.");
            readers=JsonSerializer.Deserialize<string[]>(File.ReadAllBytes(approvals))??throw new InvalidDataException("Invalid tray reader approvals.");
            if(readers.Length is <1 or >32 || readers.Any(s=>!TrayReaderIdentity.IsSupported(s)) || readers.Distinct(StringComparer.Ordinal).Count()!=readers.Length)throw new InvalidDataException("Approve distinct individual local, domain or Entra user SIDs only.");
        }
        catch(Exception ex){logger.LogError("Read-only tray disabled: invalid or unreadable approvals ({Type}). Monitoring is not stopped.",ex.GetType().Name);return;}
        var approved=readers.ToHashSet(StringComparer.Ordinal);var security=new PipeSecurity();security.SetAccessRuleProtection(true,false);
        security.AddAccessRule(new PipeAccessRule(new SecurityIdentifier(WellKnownSidType.LocalSystemSid,null),PipeAccessRights.FullControl,AccessControlType.Allow));
        foreach(var sid in approved)security.AddAccessRule(new PipeAccessRule(new SecurityIdentifier(sid),PipeAccessRights.ReadWrite,AccessControlType.Allow));
        using var pipe=AgentConsoleService.CreateLocalPipe(security,"RansomFree.Agent.ReadOnly.v1");
        while(!ct.IsCancellationRequested)
        {
            try
            {
                await pipe.WaitForConnectionAsync(ct);using var timeout=CancellationTokenSource.CreateLinkedTokenSource(ct);timeout.CancelAfter(TimeSpan.FromSeconds(10));
                string? actor=null;pipe.RunAsClient(()=>{using var identity=WindowsIdentity.GetCurrent();if(identity.User!=null&&approved.Contains(identity.User.Value))actor=identity.User.Value;});
                if(actor==null)continue;
                var length=new byte[4];await pipe.ReadExactlyAsync(length,timeout.Token);var count=BinaryPrimitives.ReadInt32LittleEndian(length);if(count is <2 or >1024)continue;
                var bytes=new byte[count];await pipe.ReadExactlyAsync(bytes,timeout.Token);var request=JsonSerializer.Deserialize<AgentConsoleRequest>(bytes);Array.Clear(bytes);
                var reply=request is {Operation:"status",Password:null,EventId:null}?state.Handle(request,actor):new AgentConsoleReply(false,"This channel is read-only.");
                if(reply.Status is {} status)reply=reply with{Status=status with{Events=status.Events.Select(e=>e with{CanEndProcess=false}).ToArray()}};
                var response=JsonSerializer.SerializeToUtf8Bytes(reply);if(response.Length>1048576)continue;
                BinaryPrimitives.WriteInt32LittleEndian(length,response.Length);await pipe.WriteAsync(length,timeout.Token);await pipe.WriteAsync(response,timeout.Token);await pipe.FlushAsync(timeout.Token);
            }
            catch(OperationCanceledException) when(ct.IsCancellationRequested){break;}
            catch(Exception ex){logger.LogWarning("Read-only tray request failed ({Type}); request contents omitted.",ex.GetType().Name);}
            finally{if(pipe.IsConnected)try{pipe.Disconnect();}catch(IOException){}}
        }
    }
}
