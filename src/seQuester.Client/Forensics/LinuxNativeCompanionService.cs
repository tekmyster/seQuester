using System.Runtime.InteropServices;
using System.Text.Json;

namespace RansomFree.Client.Forensics;

// Dedicated root service entry. The normal worker never reads this directory
// and cannot choose an alternate privileged package/configuration path.
public static class LinuxNativeCompanionService
{
    // This exit is the only one systemd may restart. The runtime has already
    // drained the registered source and verified normal module unload before
    // returning its outcome. Startup errors and unresolved closure never use it.
    internal const int PolicyExpiredRestartExitCode=75;
    internal static int CompletedExitCode(LinuxControlledSourceRuntime.Outcome? outcome,bool requestedStop)
    {
        if(requestedStop)return 0;
        return outcome is {State:"COMPLETED",Close:"CLOSE_RETURNED_OK",PendingDelivery:0,
            CanonicalBacklogPresent:false,UnindexedRawRecords:0,RawRecoveryState:"COMPLETE",
            Stop:{Reason:"LINUX_NATIVE_POLICY_EXPIRED_OR_REVOKED"},Errors:{Length:0},
            NativeClosure:{Controller:"CLOSE_RETURNED_OK",IssuedWorkDrained:true,ChildAndPipesReturned:true,
                MapHandlesClosed:true,ChildHandlesClosed:true}}?PolicyExpiredRestartExitCode:1;
    }
    public const string ConfigurationDirectory="/etc/sequester-native";
    [DllImport("libc",EntryPoint="geteuid")]private static extern uint UserId();
    private static void RequirePlatform()
    {
        if(!OperatingSystem.IsLinux()||RuntimeInformation.ProcessArchitecture!=Architecture.X64||UserId()!=0)
            throw new PlatformNotSupportedException("Native companion requires the qualified Linux x64 kernel and root service account");
    }
    public static string ValidateInstallation()
    {
        RequirePlatform();using var package=LinuxNativePackageAdmission.Open(ConfigurationDirectory);
        using var targets=LinuxNativeTargetAdmission.Open(package.Definition.Manifest.Targets);
        var c=package.Definition.Configuration;var m=package.Definition.Manifest;
        return JsonSerializer.Serialize(new{Valid=true,NativeActivation=false,c.SensorId,c.Server,Kernel=m.Kernel,m.Architecture,TargetCount=m.Targets.Length,c.ManifestSha256,
            Scope="Package and target admission only; no module loaded or source started"});
    }
    public static string PrepareInstallation(string rootRequestPath)
    {RequirePlatform();return LinuxNativeInstallationPreparation.Prepare(rootRequestPath);}
    public static async Task<int> RunAsync(Action<string> report,CancellationToken cancel)
    {
        RequirePlatform();ArgumentNullException.ThrowIfNull(report);
        try
        {
            var outcome=await LinuxNativeCompanionRuntime.RunAsync(ConfigurationDirectory,report,cancel).ConfigureAwait(false);
            // An unrequested source exit remains a failure even after its
            // resources have drained. A service manager must not call it ready.
            var result=CompletedExitCode(outcome,cancel.IsCancellationRequested);
            if(result==PolicyExpiredRestartExitCode)report("NATIVE_COMPANION_POLICY_EXPIRED_CLOSED_RESTART_REQUIRED");
            return result;
        }
        catch(OperationCanceledException)when(cancel.IsCancellationRequested){return 0;}
        catch(Exception error)when(error is not OutOfMemoryException)
        {
            // RunAsync only returns/throws after its owned drain boundary.
            // A rejected installation must be a visible failed service exit,
            // rather than an unhandled SIGABRT/core dump or a ready status.
            try{report("NATIVE_COMPANION_FAILED:"+error.GetType().Name+":"+error.Message);}catch{}
            return 1;
        }
    }
}
