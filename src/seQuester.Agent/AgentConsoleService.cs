using System.Buffers.Binary;
using System.IO.Pipes;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;
using System.Text;
using System.Text.Json;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using RansomFree;
using RansomFree.Contracts;

internal sealed class AgentConsoleState
{
    private readonly object gate=new();
    private readonly Queue<Alert> recent=[];
    private Func<AgentConsoleStatus>? snapshot;
    private Func<PasswordSettings?>? password;
    private Func<Alert,bool>? allowlisted;
    private Action<Alert>? publish;
    private DateTime retryAfter;
    private int failures;
    public void Configure(Func<AgentConsoleStatus> getSnapshot,Func<PasswordSettings?> getPassword,Func<Alert,bool> isAllowlisted,Action<Alert> publishAlert)
    {snapshot=getSnapshot;password=getPassword;allowlisted=isAllowlisted;publish=publishAlert;}
    public void Record(Alert alert){lock(gate){recent.Enqueue(alert);while(recent.Count>100)recent.Dequeue();}}
    public AgentConsoleReply Handle(AgentConsoleRequest request,string actor)
    {
        if(snapshot==null)return new(false,"Agent is initializing.");
        if(request.Operation=="status")
        {
            AgentConsoleEvent[] events;lock(gate)events=recent.Reverse().Select(a=>new AgentConsoleEvent(a.EventId,a.Time,a.Operation,a.Path,a.Executable??a.Process,a.User,a.Source,a.Allowlisted,a.Identity!=null && a.Source=="Windows audit 4663" && !a.Allowlisted){ProcessId=a.ProcessId,SuppressPopup=a.Trust?.Result.Decision.SuppressPopup==true}).ToArray();
            return new(true,"Connected",snapshot() with{Events=events});
        }
        if(request.Operation!="end-process")return new(false,"Unsupported operation.");
        if(DateTime.UtcNow<retryAfter)return new(false,"Administration verification is temporarily delayed.");
        var verifier=password?.Invoke();
        if(verifier==null)return new(false,"Provision an agent administration password before using response actions.");
        if(request.Password==null || !PasswordHash.Verify(request.Password,verifier))
        {
            failures++;retryAfter=DateTime.UtcNow.AddSeconds(Math.Min(60,Math.Pow(2,Math.Min(failures,6))));
            publish?.Invoke(new(DateTime.Now,"Agent administration denied","Agent console","",actor,"Agent administration"));return new(false,"Administration verification failed.");
        }
        failures=0;return Respond(request.EventId,actor);
    }
    public AgentConsoleReply Respond(string? eventId,string actor,ActiveResponseTarget? target=null,ActiveResponsePolicy? responsePolicy=null)
    {
        Alert? evidence;lock(gate)evidence=recent.FirstOrDefault(a=>a.EventId==eventId);
        if(evidence?.Identity==null || (target==null?evidence.Source!="Windows audit 4663":evidence.Source!="Windows minifilter") || allowlisted?.Invoke(evidence)==true || DateTime.UtcNow-evidence.Time.ToUniversalTime()>TimeSpan.FromMinutes(5))return new(false,"Fresh, non-allowlisted process evidence is required. No process was stopped.");
        if(target!=null)
        {
            var wire=new AgentEvent(evidence.EventId,evidence.Time.ToUniversalTime(),evidence.Operation,evidence.Path,evidence.User,evidence.Process,evidence.ProcessId,evidence.Source){Attribution=evidence.Attribution,Forensics=evidence.Forensics,Trust=evidence.Trust};
            if(responsePolicy?.IsValid()!=true||responsePolicy.Mode=="observe"||!responsePolicy.Actions.Contains("end-process"))return new(false,"The current policy does not permit this response. No process was stopped.");
            AgentEvent[] completions;lock(gate)completions=recent.Where(a=>a.Source=="Forensic enrichment").Reverse().Select(a=>new AgentEvent(a.EventId,a.Time.ToUniversalTime(),a.Operation,a.Path,a.User,a.Executable??a.Process,a.ProcessId,a.Source){Forensics=a.Forensics}).ToArray();
            foreach(var completion in completions){wire=ActiveResponseEvidence.AttachPreservation(wire,completion);if(wire.Forensics?.Preservation.Status.State=="captured")break;}
            var policy=responsePolicy with{Actions=["end-process"]};
            var preview=ActiveResponseEvidence.Preview(target.SensorId,wire,policy,DateTimeOffset.UtcNow);
            if(!target.IsValid()||target.OperatingSystem!="windows"||!preview.Eligible||preview.Target!=target||
                !long.TryParse(target.Process.StartKey,System.Globalization.NumberStyles.None,System.Globalization.CultureInfo.InvariantCulture,out var start)||
                evidence.Identity.Pid!=target.Process.Pid||evidence.Identity.CreatedUtcFileTime!=start||
                !string.Equals(evidence.Identity.Hash,target.ActorSha256,StringComparison.OrdinalIgnoreCase)||
                !string.Equals(evidence.Identity.Executable,target.Executable,StringComparison.OrdinalIgnoreCase))return new(false,"Process or executable evidence changed. No process was stopped.");
        }
        try
        {
            ProcessControls.End(evidence.Identity);
            publish?.Invoke(new(DateTime.Now,"Process stopped by administrator",evidence.Path,evidence.Process,actor,"Agent response"));
            return new(true,"Process exit confirmed.");
        }
        catch(Exception ex)
        {
            publish?.Invoke(new(DateTime.Now,"Process response failed: "+ex.GetType().Name,evidence.Path,evidence.Process,actor,"Agent response"));
            return new(false,"Process response failed or exit was not confirmed. Inspect activity before retrying.");
        }
    }
}
internal sealed class AgentConsoleService(AgentPaths paths,AgentConsoleState state,ILogger<AgentConsoleService> logger):BackgroundService
{
    [StructLayout(LayoutKind.Sequential)] private struct SecurityAttributes {public int Length;public IntPtr Descriptor;[MarshalAs(UnmanagedType.Bool)]public bool Inherit;}
    [DllImport("kernel32.dll",CharSet=CharSet.Unicode,SetLastError=true)]
    private static extern SafePipeHandle CreateNamedPipe(string name,uint openMode,uint pipeMode,uint instances,uint outputSize,uint inputSize,uint timeout,ref SecurityAttributes security);
    internal static NamedPipeServerStream CreateLocalPipe(PipeSecurity security,string name="RansomFree.Agent.v1")
    {
        var descriptor=security.GetSecurityDescriptorBinaryForm();var pin=GCHandle.Alloc(descriptor,GCHandleType.Pinned);
        try
        {
            var attributes=new SecurityAttributes{Length=Marshal.SizeOf<SecurityAttributes>(),Descriptor=pin.AddrOfPinnedObject()};
            // DUPLEX | OVERLAPPED | FIRST_PIPE_INSTANCE; byte mode | REJECT_REMOTE_CLIENTS.
            var handle=CreateNamedPipe(@"\\.\pipe\"+name,3|0x40000000|0x00080000,8,1,1048576,4096,0,ref attributes);
            if(handle.IsInvalid){var error=Marshal.GetLastWin32Error();handle.Dispose();throw new System.ComponentModel.Win32Exception(error);}
            return new NamedPipeServerStream(PipeDirection.InOut,true,false,handle);
        }
        finally{pin.Free();}
    }
    protected override async Task ExecuteAsync(CancellationToken ct)
    {
        if(!paths.EnableConsolePipe)return;
        var security=new PipeSecurity();security.SetAccessRuleProtection(true,false);
        foreach(var sid in new[]{WellKnownSidType.LocalSystemSid,WellKnownSidType.BuiltinAdministratorsSid})security.AddAccessRule(new PipeAccessRule(new SecurityIdentifier(sid,null),PipeAccessRights.FullControl,AccessControlType.Allow));
        using var pipe=CreateLocalPipe(security);
        while(!ct.IsCancellationRequested)
        {
            try
            {
                await pipe.WaitForConnectionAsync(ct);
                using var timeout=CancellationTokenSource.CreateLinkedTokenSource(ct);timeout.CancelAfter(TimeSpan.FromSeconds(10));
                string? actor=null;
                pipe.RunAsClient(()=>{using var identity=WindowsIdentity.GetCurrent();if(identity.IsSystem || new WindowsPrincipal(identity).IsInRole(WindowsBuiltInRole.Administrator))actor=identity.Name;});
                if(actor==null)continue;
                var size=new byte[4];await pipe.ReadExactlyAsync(size,timeout.Token);var count=BinaryPrimitives.ReadInt32LittleEndian(size);if(count is <2 or >4096)continue;
                var bytes=new byte[count];await pipe.ReadExactlyAsync(bytes,timeout.Token);
                var request=JsonSerializer.Deserialize<AgentConsoleRequest>(bytes);Array.Clear(bytes);
                if(request==null)continue;
                var reply=state.Handle(request,actor);var response=JsonSerializer.SerializeToUtf8Bytes(reply);
                if(response.Length>1048576)response=JsonSerializer.SerializeToUtf8Bytes(new AgentConsoleReply(false,"Activity response exceeded its limit."));
                BinaryPrimitives.WriteInt32LittleEndian(size,response.Length);await pipe.WriteAsync(size,timeout.Token);await pipe.WriteAsync(response,timeout.Token);await pipe.FlushAsync(timeout.Token);
            }
            catch(OperationCanceledException) when(ct.IsCancellationRequested){break;}
            catch(Exception ex){logger.LogWarning("Agent console request failed ({Type}); no request contents logged.",ex.GetType().Name);}
            finally{if(pipe.IsConnected)try{pipe.Disconnect();}catch(IOException){}}
        }
    }
}
