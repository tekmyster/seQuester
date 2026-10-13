using System.Buffers.Binary;
using System.IO.Pipes;
using System.Runtime.InteropServices;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Text.Json;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Microsoft.Win32.SafeHandles;
using RansomFree;
using RansomFree.Contracts;

// No native decoy action executes in this SYSTEM process. Only a fixed protocol is exposed.
internal sealed class DecoySessionStatus
{
    private string? warning;
    public string? Warning=>Volatile.Read(ref warning);
    public void Set(string? value)=>Volatile.Write(ref warning,value);
}
internal sealed class DecoySessionService(AgentPaths paths,DecoySessionStatus status,ILogger<DecoySessionService> logger):BackgroundService
{
    [DllImport("kernel32.dll",SetLastError=true)]static extern bool GetNamedPipeClientProcessId(SafePipeHandle pipe,out uint pid);
    [DllImport("kernel32.dll",SetLastError=true)]static extern SafeProcessHandle OpenProcess(uint access,bool inherit,uint pid);
    [DllImport("kernel32.dll",CharSet=CharSet.Unicode,SetLastError=true)]static extern bool QueryFullProcessImageName(SafeProcessHandle process,uint flags,System.Text.StringBuilder path,ref int size);
    [DllImport("kernel32.dll",SetLastError=true)]static extern bool GetNamedPipeClientSessionId(SafePipeHandle pipe,out uint session);
    [DllImport("advapi32.dll",SetLastError=true)]static extern bool GetTokenInformation(nint token,int kind,byte[] buffer,int size,out int needed);
    static readonly string[] TrustedOwners=["S-1-5-18","S-1-5-32-544"];
    static void VerifyAcl(FileSystemInfo item)
    {
        FileSystemSecurity security=item is DirectoryInfo directory?directory.GetAccessControl():((FileInfo)item).GetAccessControl();
        if(security.GetOwner(typeof(SecurityIdentifier)) is not {} owner||!TrustedOwners.Contains(owner.Value,StringComparer.Ordinal))throw new IOException("Broker storage owner is not trusted.");
        foreach(FileSystemAccessRule rule in security.GetAccessRules(true,true,typeof(SecurityIdentifier)))
            if(rule.AccessControlType==AccessControlType.Allow&&!TrustedOwners.Contains(rule.IdentityReference.Value,StringComparer.Ordinal))throw new IOException("Broker storage is not restricted to administrators and SYSTEM.");
    }
    DecoySessionPolicy ReadPolicy(string policyPath)
    {
        using var pin=DeploymentPathLease.Acquire(paths.Directory,policyPath);VerifyAcl(new DirectoryInfo(paths.Directory));VerifyAcl(new FileInfo(policyPath));
        using var file=new FileStream(policyPath,FileMode.Open,FileAccess.Read,FileShare.Read);if(file.Length is <2 or >131072)throw new InvalidDataException("Session policy exceeds its limit.");
        var data=new byte[(int)file.Length];file.ReadExactly(data);return DecoySessionProtocol.ReadPolicy(data);
    }
    void VerifyManagedStorage()
    {
        VerifyAcl(new DirectoryInfo(paths.Directory));
        foreach(var file in Directory.EnumerateFiles(paths.Directory,"decoy-jobs*"))
        {if((File.GetAttributes(file)&FileAttributes.ReparsePoint)!=0)throw new IOException("Managed ledger is linked.");VerifyAcl(new FileInfo(file));}
    }
    static void VerifyManagedCompanion(NamedPipeServerStream pipe)
    {
        if(!GetNamedPipeClientProcessId(pipe.SafePipeHandle,out var pid))throw new IOException("Companion process unavailable.");
        using var process=OpenProcess(0x1000,false,pid);if(process.IsInvalid)throw new IOException("Companion process unavailable.");
        var image=new System.Text.StringBuilder(32768);var size=image.Capacity;
        var programFiles=Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles);var product=Path.Combine(programFiles,"RansomFree");var folder=Path.Combine(product,"DecoyHost");var expected=Path.Combine(folder,"RansomFree.DecoyHost.exe");
        if(!QueryFullProcessImageName(process,0,image,ref size)||!image.ToString().Equals(expected,StringComparison.OrdinalIgnoreCase))throw new IOException("Use the installed companion.");
        using var pin=DeploymentPathLease.Acquire(folder,expected);
        foreach(FileSystemInfo item in new FileSystemInfo[]{new DirectoryInfo(product),new DirectoryInfo(folder),new FileInfo(expected)})
        {
            FileSystemSecurity acl=item is DirectoryInfo d?d.GetAccessControl():((FileInfo)item).GetAccessControl();
            if(acl.GetOwner(typeof(SecurityIdentifier)) is not {} owner||!TrustedOwners.Contains(owner.Value,StringComparer.Ordinal))throw new IOException("Companion owner untrusted.");
            const FileSystemRights writes=FileSystemRights.Write|FileSystemRights.Delete|FileSystemRights.DeleteSubdirectoriesAndFiles|FileSystemRights.ChangePermissions|FileSystemRights.TakeOwnership;
            foreach(FileSystemAccessRule rule in acl.GetAccessRules(true,true,typeof(SecurityIdentifier)))if(rule.AccessControlType==AccessControlType.Allow&&(rule.PropagationFlags&PropagationFlags.InheritOnly)==0&&(rule.FileSystemRights&writes)!=0&&!TrustedOwners.Contains(rule.IdentityReference.Value,StringComparer.Ordinal))throw new IOException("Companion installation is writable.");
        }
    }
    protected override async Task ExecuteAsync(CancellationToken ct)
    {
        if(!paths.EnableConsolePipe)return;
        using(var identity=WindowsIdentity.GetCurrent())if(!identity.IsSystem){logger.LogWarning("Decoy session broker requires the installed SYSTEM service; disabled.");return;}
        var policyPath=Path.Combine(paths.Directory,"decoy-session-policy.json");
        status.Set("Decoy setup pending");
        try
        {
            using var storagePin=DeploymentPathLease.Acquire(paths.Directory);VerifyManagedStorage();
            using var coordinator=new FileStream(Path.Combine(paths.Directory,"decoy-jobs-coordinator.lock"),FileMode.OpenOrCreate,FileAccess.ReadWrite,FileShare.None);
            var connectionPath=Path.Combine(paths.Directory,"connection.json");
            DecoyJobSync? managed=null;
            if(File.Exists(connectionPath)){using var connectionPin=DeploymentPathLease.Acquire(paths.Directory,connectionPath);VerifyAcl(new FileInfo(connectionPath));managed=new(paths.Directory);}
            try
            {
            var nextSync=DateTimeOffset.MinValue;
            while(!ct.IsCancellationRequested)
            {
                VerifyManagedStorage();
                if(managed!=null&&DateTimeOffset.UtcNow>=nextSync)
                {
                    nextSync=DateTimeOffset.UtcNow.AddSeconds(15);
                    try{await managed.RunOnce(ct);}catch(Exception ex)when(ex is not OperationCanceledException){status.Set("Managed decoy sync needs attention; retained work preserved");logger.LogWarning("Managed decoy sync deferred ({Type}).",ex.GetType().Name);}
                }
                var initial=File.Exists(policyPath)?ReadPolicy(policyPath):null;
                var userSids=(initial?.Jobs.Select(j=>j.UserSid)??Enumerable.Empty<string>()).Concat(managed?.Store.Current() is {} current?[current.Job.Job.UserSid]:Array.Empty<string>()).Distinct(StringComparer.Ordinal).ToArray();
                if(userSids.Length==0){await Task.Delay(TimeSpan.FromSeconds(10),ct);continue;}
                var security=new PipeSecurity();security.SetAccessRuleProtection(true,false);
                security.AddAccessRule(new PipeAccessRule(new SecurityIdentifier(WellKnownSidType.LocalSystemSid,null),PipeAccessRights.FullControl,AccessControlType.Allow));
                foreach(var userSid in userSids)security.AddAccessRule(new PipeAccessRule(new SecurityIdentifier(userSid),PipeAccessRights.ReadWrite,AccessControlType.Allow));
                using var pipe=AgentConsoleService.CreateLocalPipe(security,DecoySessionProtocol.PipeName);
                try
                {
                    using var idle=CancellationTokenSource.CreateLinkedTokenSource(ct);idle.CancelAfter(TimeSpan.FromSeconds(10));await pipe.WaitForConnectionAsync(idle.Token);using var timeout=CancellationTokenSource.CreateLinkedTokenSource(ct);timeout.CancelAfter(TimeSpan.FromSeconds(10));
                    var size=new byte[4];await pipe.ReadExactlyAsync(size,timeout.Token);var length=BinaryPrimitives.ReadInt32LittleEndian(size);if(length is <2 or >4096)continue;
                    var data=new byte[length];await pipe.ReadExactlyAsync(data,timeout.Token);
                    // Impersonate only after a request has been read, then immediately revert.
                    if(!GetNamedPipeClientSessionId(pipe.SafePipeHandle,out var session)||session==0)continue;
                    string? sid=null,logon=null;
                    pipe.RunAsClient(()=>{using var identity=WindowsIdentity.GetCurrent();if(identity.IsSystem||identity.User==null||new WindowsPrincipal(identity).IsInRole(WindowsBuiltInRole.Administrator))return;var bytes=new byte[256];if(!GetTokenInformation(identity.Token,10,bytes,bytes.Length,out _))return;sid=identity.User.Value;logon=Convert.ToHexString(bytes.AsSpan(8,8));});
                    if(sid==null||logon==null)continue;
                    using var message=JsonDocument.Parse(data);var isManaged=message.RootElement.EnumerateObject().Any(p=>p.Name.Equals("Operation",StringComparison.OrdinalIgnoreCase)&&p.Value.ValueKind==JsonValueKind.String&&p.Value.GetString()!.StartsWith("job-",StringComparison.Ordinal));
                    if(isManaged)
                    {
                        VerifyManagedCompanion(pipe);VerifyManagedStorage();var managedRequest=DecoyJobsProtocol.Read<DecoyJobSessionRequest>(data);
                        var managedReply=managed?.Store.Handle(sid,session,logon,managedRequest)??new DecoyJobSessionReply("No managed assignments");
                        var bytes=JsonSerializer.SerializeToUtf8Bytes(managedReply);if(bytes.Length>16384)throw new InvalidDataException("Managed reply exceeds limit.");
                        BinaryPrimitives.WriteInt32LittleEndian(size,bytes.Length);await pipe.WriteAsync(size,timeout.Token);await pipe.WriteAsync(bytes,timeout.Token);await pipe.FlushAsync(timeout.Token);
                        status.Set("Managed decoy check pending");continue;
                    }
                    if(!File.Exists(policyPath))continue;
                    var policy=ReadPolicy(policyPath);if(!policy.Jobs.Any(j=>j.UserSid==sid))continue;
                    var request=DecoySessionProtocol.ReadRequest(data);
                    var ledgerPath=Path.Combine(paths.Directory,"decoy-session-ledger.db");
                    using var rootPin=DeploymentPathLease.Acquire(paths.Directory);VerifyAcl(new DirectoryInfo(paths.Directory));
                    var pins=new List<DeploymentPathLease>();
                    DecoySessionReply reply;
                    try
                    {
                        foreach(var path in new[]{ledgerPath,ledgerPath+"-wal",ledgerPath+"-shm",ledgerPath+"-journal"})if(File.Exists(path)){if((File.GetAttributes(path)&FileAttributes.ReparsePoint)!=0)throw new IOException("Broker ledger is linked.");VerifyAcl(new FileInfo(path));}
                        if(File.Exists(ledgerPath))pins.Add(DeploymentPathLease.Acquire(paths.Directory,ledgerPath));
                        reply=new DecoySessionLedger(ledgerPath).Handle(policy,sid,session,logon,request);
                    }
                    finally{foreach(var pin in pins)pin.Dispose();}
                    // A user-session receipt is not an independently verified protection status.
                    status.Set(reply.State switch{"No assignments"=>"Decoy status unverified","Assignment" or "Session result recorded"=>"Decoy setup pending",_=>"Decoy setup needs attention"});
                    var response=JsonSerializer.SerializeToUtf8Bytes(reply);if(response.Length>16384)throw new InvalidDataException("Broker response exceeds its limit.");
                    BinaryPrimitives.WriteInt32LittleEndian(size,response.Length);await pipe.WriteAsync(size,timeout.Token);await pipe.WriteAsync(response,timeout.Token);await pipe.FlushAsync(timeout.Token);
                }
                catch(OperationCanceledException)when(ct.IsCancellationRequested){break;}
                catch(OperationCanceledException){}
                catch(Exception ex){status.Set("Decoy setup needs attention");logger.LogWarning("Decoy session request unconfirmed ({Type}); no privileged decoy action executed.",ex.GetType().Name);}
                finally{if(pipe.IsConnected)try{pipe.Disconnect();}catch(IOException){}}
            }
            }
            finally{managed?.Dispose();}
        }
        catch(OperationCanceledException)when(ct.IsCancellationRequested){}
        catch(Exception ex){status.Set("Decoy setup needs attention");logger.LogError("Decoy session broker disabled ({Type}); existing monitoring continues.",ex.GetType().Name);}
    }
}
