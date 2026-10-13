using System.Diagnostics;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace RansomFree.LinuxAgent;

internal sealed record AuditRuleStatus(string RunId,DateTimeOffset UpdatedUtc,string BootId,int AuditdPid,string? AuditdStartTicks,string? DesiredSha256,int Expected,int Added,bool Success,string Phase,string? FailureCategory,string? FailureStage=null);
internal static class AuditRuleReconciler
{
    const string Rules="/etc/ransomfree-client/sequester-audit.rules";
    public const string StatusPath=AuditDispatcher.Root+"/rules-status.json";
    static string ReadRules()
    {
        Native.ValidateAdminPath(Rules,false,true);
        using var input=Native.FileAt(Rules,false);if(input.Length>1024*1024)throw new InvalidDataException("Reviewed rule file exceeds limit.");
        using var reader=new StreamReader(input,Encoding.UTF8,true);return reader.ReadToEnd();
    }
    static async Task<string> ReadBounded(StreamReader reader,int maximum,CancellationToken ct)
    {
        var result=new StringBuilder();var buffer=new char[4096];
        for(int n;(n=await reader.ReadAsync(buffer.AsMemory(),ct))>0;){if(result.Length+n>maximum)throw new IOException("Auditctl output exceeds limit.");result.Append(buffer,0,n);}
        return result.ToString();
    }
    static async Task<string> Command(string tool,IEnumerable<string> arguments)
    {
        var start=new ProcessStartInfo(tool){UseShellExecute=false,RedirectStandardOutput=true,RedirectStandardError=true};
        start.Environment.Clear();start.Environment["LC_ALL"]="C";start.Environment["PATH"]="/usr/sbin:/usr/bin:/sbin:/bin";
        foreach(var argument in arguments)start.ArgumentList.Add(argument);
        using var process=Process.Start(start)??throw new IOException("Auditctl did not start.");
        using var timeout=new CancellationTokenSource(TimeSpan.FromSeconds(15));
        var output=ReadBounded(process.StandardOutput,4*1024*1024,timeout.Token);var error=ReadBounded(process.StandardError,65536,timeout.Token);
        try{await Task.WhenAll(output,error,process.WaitForExitAsync(timeout.Token));}
        catch
        {
            timeout.Cancel();
            try{if(!process.HasExited)process.Kill();await process.WaitForExitAsync().WaitAsync(TimeSpan.FromSeconds(2));}
            catch(Exception cleanup) when(cleanup is InvalidOperationException or System.ComponentModel.Win32Exception or TimeoutException){/* Own child only; fail closed below. */}
            throw new IOException("Own auditctl operation timed out or output was unavailable; partial state requires review.");
        }
        if(process.ExitCode!=0)throw new IOException("Auditctl failed with exit code "+process.ExitCode+"; partial state requires review.");
        return await output;
    }
    static async Task<(int Pid,string Start)> AuditdIdentity(string tool)
    {
        var pid=AuditKernelStatus.ActivePid(await Command(tool,["-s"]));
        return(pid,AuditHealth.StartTicks(pid));
    }
    public static Task<int> Run()=>AuditCommandExit.Run(RunCore,Console.Error);
    static async Task RunCore()
    {
        if(!Native.Root)throw new UnauthorizedAccessException("Rule reconciliation requires the approved root service.");
        Native.ValidateAdminPath(AuditDispatcher.Root,true);
        var lockPath=AuditDispatcher.Root+"/rules.lock";
        if(File.Exists(lockPath))Native.ValidateAdminPath(lockPath,false);
        using var lease=new FileStream(lockPath,new FileStreamOptions{Mode=FileMode.OpenOrCreate,Access=FileAccess.ReadWrite,Share=FileShare.None,UnixCreateMode=UnixFileMode.UserRead|UnixFileMode.UserWrite});
        var run=Guid.NewGuid().ToString("N");var boot=AuditHealth.BootId();int expected=0,added=0,pid=0;string? startTicks=null,digest=null;var stage="Starting";
        void Report(bool success,string phase,string? failure=null)
        {
            var temporary=AuditDispatcher.Root+"/"+Guid.NewGuid().ToString("N")+".tmp";
            using(var file=new FileStream(temporary,new FileStreamOptions{Mode=FileMode.CreateNew,Access=FileAccess.Write,Share=FileShare.None,UnixCreateMode=UnixFileMode.UserRead|UnixFileMode.UserWrite|UnixFileMode.GroupRead}))
            {JsonSerializer.Serialize(file,new AuditRuleStatus(run,DateTimeOffset.UtcNow,boot,pid,startTicks,digest,expected,added,success,phase,failure,failure==null?null:stage),PrivateState.Json);file.Flush(true);}
            File.Move(temporary,StatusPath,true);
        }
        Report(false,"Starting");
        try
        {
            stage="Configuration";var configuration=AuditDispatcher.Read<ClientConfiguration>(Platform.ConfigPath);
            if(!configuration.Audit.Enabled)throw new InvalidOperationException("Audit disabled; rule service must be disabled explicitly.");
            stage="DesiredRules";var text=ReadRules();var desired=AuditRulePlan.Desired(text);expected=desired.Length;
            digest=Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(text)));
            // Administrator-owned reviewed rules are the authority. Never open
            // canary contents or read private rfclient credentials to reconcile.
            stage="CanaryMetadata";foreach(var rule in desired)
            {
                if(!configuration.Folders.Values.Any(folder=>rule.Path.StartsWith(folder.TrimEnd('/')+"/",StringComparison.Ordinal)))throw new InvalidDataException("Reviewed rule outside configured folders.");
                Paths.NoLinks(rule.Path);var info=new FileInfo(rule.Path);
                if(!info.Exists||(info.Attributes&(FileAttributes.Directory|FileAttributes.ReparsePoint))!=0)throw new IOException("Reviewed canary path unavailable; rules unchanged.");
                if(System.Runtime.InteropServices.RuntimeInformation.ProcessArchitecture==System.Runtime.InteropServices.Architecture.Arm64&&rule.Arch!="b64")throw new InvalidDataException("Unsupported ARM64 compat rule.");
            }
            stage="AuditctlExecutable";var tool=File.Exists("/usr/sbin/auditctl")?"/usr/sbin/auditctl":"/sbin/auditctl";Native.ValidateAdminPath(tool,false);
            stage="KernelAuditStatus";(pid,startTicks)=await AuditdIdentity(tool);Report(false,"Reconciling");
            stage="LiveRuleReconciliation";
            var result=await AuditRulePlan.Reconcile(desired,()=>Command(tool,["-l"]),async rule=>{await Command(tool,rule.Arguments);},n=>{added=n;Report(false,"Reconciling");});
            stage="FinalIdentityVerification";if(await AuditdIdentity(tool)!=(pid,startTicks)||ReadRules()!=text)throw new IOException("Auditd or reviewed rules changed during reconciliation.");
            Report(true,"Verified");
            Console.WriteLine($"PASS: reviewed audit rules verified; expected={result.Expected}; alreadyPresent={result.AlreadyPresent}; added={result.Added}; unrelatedPreserved={result.UnrelatedPreserved}; auditdPid={pid}. No rules deleted.");
        }
        catch(Exception ex)
        {
            Report(false,"Failed",ex.GetType().Name);
            Console.Error.WriteLine($"Audit rule reconciliation failed: stage={stage}; category={ex.GetType().Name}; expected={expected}; verifiedAdded={added}. Inspect protected status and exact live inventory; no rules cleared and no blind retry.");
            throw;
        }
    }
}
