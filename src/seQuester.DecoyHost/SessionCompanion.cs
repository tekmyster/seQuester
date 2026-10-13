using System.Buffers.Binary;
using System.Diagnostics;
using System.IO.Pipes;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using Microsoft.Win32.SafeHandles;
using RansomFree.Contracts;
using RansomFree.WindowsDecoys;

internal static class SessionCompanion
{
    [DllImport("kernel32.dll",SetLastError=true)]static extern bool GetNamedPipeServerProcessId(SafePipeHandle pipe,out uint pid);
    [DllImport("kernel32.dll",SetLastError=true)]static extern SafeProcessHandle OpenProcess(uint access,bool inherit,uint pid);
    [DllImport("kernel32.dll",CharSet=CharSet.Unicode,SetLastError=true)]static extern bool QueryFullProcessImageName(SafeProcessHandle process,uint flags,StringBuilder name,ref int size);
    static void VerifyJournalAcl(FileSystemInfo item,string sid)
    {
        var allowed=new[]{sid,"S-1-5-18","S-1-5-32-544"};FileSystemSecurity acl=item is DirectoryInfo dir?dir.GetAccessControl():((FileInfo)item).GetAccessControl();
        if(acl.GetOwner(typeof(SecurityIdentifier)) is not {} owner||!allowed.Contains(owner.Value,StringComparer.Ordinal))throw new IOException("Journal owner is not trusted.");
        foreach(FileSystemAccessRule rule in acl.GetAccessRules(true,true,typeof(SecurityIdentifier)))if(rule.AccessControlType==AccessControlType.Allow&&!allowed.Contains(rule.IdentityReference.Value,StringComparer.Ordinal))throw new IOException("Use a private journal folder for this user.");
    }
    public static async Task<DecoySessionReply> Send(DecoySessionRequest request,CancellationToken ct)=>DecoySessionProtocol.ReadReply(await SendBytes(request,ct));
    static async Task<DecoyJobSessionReply> SendManaged(DecoyJobSessionRequest request,CancellationToken ct)=>DecoyJobsProtocol.Read<DecoyJobSessionReply>(await SendBytes(request,ct));
    static async Task<byte[]> SendBytes(object request,CancellationToken ct)
    {
        using var timeout=CancellationTokenSource.CreateLinkedTokenSource(ct);timeout.CancelAfter(TimeSpan.FromSeconds(12));
        using var pipe=new NamedPipeClientStream(".",DecoySessionProtocol.PipeName,PipeDirection.InOut,PipeOptions.Asynchronous,TokenImpersonationLevel.Impersonation);
        await pipe.ConnectAsync(2500,timeout.Token);
        if(!GetNamedPipeServerProcessId(pipe.SafePipeHandle,out var pid))throw new IOException("Broker identity unavailable.");
        using var process=OpenProcess(0x1000,false,pid);if(process.IsInvalid)throw new IOException("Broker process unavailable.");
        var name=new StringBuilder(32768);var size=name.Capacity;var expected=Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles),"RansomFree","Agent","RansomFree.Agent.exe");
        if(!QueryFullProcessImageName(process,0,name,ref size)||!name.ToString().Equals(expected,StringComparison.OrdinalIgnoreCase))throw new IOException("Broker installation mismatch.");
        // SCM confirms both the running PID and LocalSystem service configuration; no privileged token access required.
        RansomFree.InstalledAgentIdentity.Verify(pid,expected);
        var bytes=JsonSerializer.SerializeToUtf8Bytes(request);if(bytes.Length>4096)throw new InvalidDataException("Request exceeds limit.");
        var length=new byte[4];BinaryPrimitives.WriteInt32LittleEndian(length,bytes.Length);await pipe.WriteAsync(length,timeout.Token);await pipe.WriteAsync(bytes,timeout.Token);await pipe.FlushAsync(timeout.Token);
        await pipe.ReadExactlyAsync(length,timeout.Token);var count=BinaryPrimitives.ReadInt32LittleEndian(length);if(count is <2 or >16384)throw new InvalidDataException("Broker reply exceeds limit.");
        var reply=new byte[count];await pipe.ReadExactlyAsync(reply,timeout.Token);return reply;
    }
    public static async Task<string> RunOnce(string journalDirectory,CancellationToken ct)
    {
        using var identity=WindowsIdentity.GetCurrent();if(identity.IsSystem||Process.GetCurrentProcess().SessionId==0||new WindowsPrincipal(identity).IsInRole(WindowsBuiltInRole.Administrator))throw new InvalidOperationException("Run the companion in a non-elevated interactive user session.");
        if(!Path.IsPathFullyQualified(journalDirectory)||journalDirectory.StartsWith("\\\\",StringComparison.Ordinal)||journalDirectory.Length>180)throw new ArgumentException("Use an existing local journal folder.");
        var journalRoot=Path.GetFullPath(journalDirectory);if(journalRoot.Length<=3||!Directory.Exists(journalRoot))throw new ArgumentException("An existing non-root journal folder is required.");
        using var pin=RansomFree.DeploymentPathLease.Acquire(journalRoot);
        var sid=identity.User?.Value??throw new InvalidOperationException("User identity unavailable.");VerifyJournalAcl(new DirectoryInfo(journalRoot),sid);
        var lockPath=Path.Combine(journalRoot,"session.lock");if(Path.Exists(lockPath)&&(File.GetAttributes(lockPath)&FileAttributes.ReparsePoint)!=0)throw new IOException("Journal lock is linked.");
        if(File.Exists(lockPath))VerifyJournalAcl(new FileInfo(lockPath),sid);
        using var journalLock=new FileStream(lockPath,FileMode.OpenOrCreate,FileAccess.ReadWrite,FileShare.None);
        var managed=await SendManaged(new("job-poll"),ct);
        if(managed.State=="Reconcile")
        {
            var approved=managed.Managed??throw new InvalidDataException("Reconciliation job missing.");DecoyJobsProtocol.Validate(approved);
            if(approved.Job.UserSid!=sid||managed.LogonId==null||managed.SessionId!=checked((uint)Process.GetCurrentProcess().SessionId)||managed.Challenge==null||!DecoyJobsProtocol.Nonce(managed.Challenge))throw new InvalidDataException("Reconciliation identity mismatch.");
            var observationPath=Path.Combine(journalRoot,approved.Job.JobId+".observation.json");DecoyNativeReport observation;
            if(File.Exists(observationPath))
            {
                using var observationPin=RansomFree.DeploymentPathLease.Acquire(journalRoot,observationPath);VerifyJournalAcl(new FileInfo(observationPath),sid);
                using var input=new FileStream(observationPath,FileMode.Open,FileAccess.Read,FileShare.Read);if(input.Length is <2 or >4096)throw new InvalidDataException("Observation file exceeds limit.");var data=new byte[(int)input.Length];input.ReadExactly(data);observation=DecoyJobsProtocol.Read<DecoyNativeReport>(data);
            }
            else
            {
                long? nativeRevision=null;var nativeState="Unavailable";
                try{var native=DecoyReconciliation.Observe(approved.Job.StateDirectory,approved.Job.ApprovedRoot,new(approved.Job.DecoyId,approved.Job.Kind,approved.Job.Name,approved.Job.Drive));nativeRevision=native.Revision;nativeState=native.State;}
                catch(Exception ex)when(ex is IOException or UnauthorizedAccessException or InvalidOperationException or KeyNotFoundException or System.ComponentModel.Win32Exception){}
                observation=new(approved.Job.JobId,approved.Job.DecoyId,approved.PolicyRevision,sid,managed.SessionId,managed.LogonId,managed.Challenge,DateTimeOffset.UtcNow,nativeRevision,nativeState);
                using var output=new FileStream(observationPath,FileMode.CreateNew,FileAccess.Write,FileShare.None);JsonSerializer.Serialize(output,observation);output.Flush(true);
            }
            DecoyJobsProtocol.Validate(observation);
            if(observation.JobId!=approved.Job.JobId||observation.DecoyId!=approved.Job.DecoyId||observation.PolicyRevision!=approved.PolicyRevision||observation.Challenge!=managed.Challenge||observation.UserSid!=sid||observation.SessionId!=managed.SessionId||observation.LogonId!=managed.LogonId)throw new InvalidDataException("Retained observation belongs to another challenge/session.");
            return (await SendManaged(new("job-observation",Observation:observation),ct)).State;
        }
        var usesManaged=managed.State!="No managed assignments";
        DecoySessionReply reply;
        if(usesManaged)
        {
            if(managed.Assignment==null)return managed.State;
            var approved=managed.Managed??throw new InvalidDataException("Managed approval missing.");DecoyJobsProtocol.Validate(approved);
            if(approved.Job!=managed.Assignment.Job)throw new InvalidDataException("Managed job differs from assignment.");reply=new(managed.State,managed.Assignment);
        }
        else reply=await Send(new("poll"),ct);
        if(reply.Assignment is not {} assignment)return reply.State;
        var job=assignment.Job;DecoySessionProtocol.Validate(job);
        if(job.UserSid!=identity.User?.Value||assignment.Nonce is not {Length:64}||!assignment.Nonce.All(Uri.IsHexDigit))throw new InvalidDataException("Assignment identity mismatch.");
        var path=Path.Combine(journalRoot,job.JobId+".json");var digest=Convert.ToHexString(SHA256.HashData(JsonSerializer.SerializeToUtf8Bytes(job)));
        var receipt=DecoySessionJournal.Recover(journalRoot,job,assignment.Nonce,item=>VerifyJournalAcl(item,sid));
        if(receipt==null)
        {
            if(assignment.ExpiresUtc<=DateTimeOffset.UtcNow||assignment.ExpiresUtc>DateTimeOffset.UtcNow.AddMinutes(2))
                return usesManaged?(await SendManaged(new("job-receipt",new(job.JobId,assignment.Nonce,"Unconfirmed")),ct)).State:"Assignment expired or clock needs attention";
            if(Directory.EnumerateFiles(journalRoot,"*.json").Take(4096).Count()>=4096)throw new IOException("Journal capacity reached; evidence preserved.");
            using(var file=new FileStream(path,FileMode.CreateNew,FileAccess.Write,FileShare.None)){JsonSerializer.Serialize(file,new DecoyJournalRecord(digest,assignment.Nonce,null));file.Flush(true);}
            try
            {
                if(assignment.ExpiresUtc<=DateTimeOffset.UtcNow)throw new InvalidOperationException("Assignment expired before execution.");
                var engine=new VirtualDecoys(job.StateDirectory,job.ApprovedRoot);var plan=new VirtualDecoyPlan(job.DecoyId,job.Kind,job.Name,job.Drive);
                if(job.Action=="observe")
                {
                    var observed=engine.Observe(plan);receipt=new(job.JobId,assignment.Nonce,"Observed",observed.Revision,observed.State);
                }
                else
                {
                    var result=job.Action switch
                    {
                        "create"=>engine.Create(plan),"activate"=>engine.SetActive(job.DecoyId,job.ExpectedRevision!.Value,true,expectedPlan:plan),
                        "disable"=>engine.SetActive(job.DecoyId,job.ExpectedRevision!.Value,false,expectedPlan:plan),"retire"=>engine.SetActive(job.DecoyId,job.ExpectedRevision!.Value,false,true,plan),
                        "repair"=>engine.Repair(job.DecoyId,job.ExpectedRevision!.Value,plan),_=>throw new InvalidDataException("Unsupported action.")
                    };
                    var expectedState=job.Action switch{"create" or "disable"=>"Disabled","activate"=>"Active","retire"=>"Retired",_=>result.DesiredActive?"Active":"Disabled"};
                    receipt=new(job.JobId,assignment.Nonce,result.State==expectedState?"Applied":"Unconfirmed",result.Revision,result.State);
                }
            }
            catch(Exception ex)when(ex is not OutOfMemoryException){receipt=new(job.JobId,assignment.Nonce,"Unconfirmed");}
            // Separate immutable completion file avoids truncating the durable intent on failure.
            var completed=path+".completed";
            using(var file=new FileStream(completed,FileMode.CreateNew,FileAccess.Write,FileShare.None)){JsonSerializer.Serialize(file,new DecoyJournalRecord(digest,assignment.Nonce,receipt));file.Flush(true);}
            File.Move(completed,path,true);
        }
        var recorded=usesManaged?new DecoySessionReply((await SendManaged(new("job-receipt",receipt),ct)).State):await Send(new("receipt",receipt),ct);
        return recorded.State=="Session result recorded"&&receipt.State is "Failed" or "Unconfirmed"?"Decoy setup needs attention":recorded.State;
    }
}
