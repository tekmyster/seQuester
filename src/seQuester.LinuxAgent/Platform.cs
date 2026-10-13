using System.Reflection;
namespace RansomFree.LinuxAgent;

internal static class Platform
{
    public const string Name="Linux",DefaultMonitor="inotify";
    // Enrollment, heartbeat and --version must report the packaged assembly version.
    public static readonly string Version=typeof(Platform).Assembly.GetCustomAttribute<AssemblyInformationalVersionAttribute>()?.InformationalVersion.Split('+')[0]
        ?? throw new InvalidOperationException("The sensor build is missing its version metadata.");
    public const string DataPath="/var/lib/ransomfree-client",ConfigPath="/etc/ransomfree-client/client.json",StatusPath="/run/ransomfree-client/status.json";
    public static bool Supported=>OperatingSystem.IsLinux()&&(System.Runtime.InteropServices.RuntimeInformation.ProcessArchitecture is System.Runtime.InteropServices.Architecture.X64 or System.Runtime.InteropServices.Architecture.Arm64);
    public static bool ValidMonitor(string mode)=>mode is "inotify" or "fanotify";
    public static bool SupportsResponse(string mode)=>mode=="fanotify";
    public static bool SupportsAutomatic(RansomFree.Contracts.AutomaticResponsePolicy policy)=>!policy.OnDelete&&!policy.OnPermissionChange;
    public static bool AutomaticTrigger(RansomFree.Contracts.AutomaticResponsePolicy policy,string operation)=>(policy.OnRead&&operation.StartsWith("Content read",StringComparison.Ordinal))||(policy.OnWrite&&operation.StartsWith("Canary modified",StringComparison.Ordinal));
    public static string[] ProtectedPaths=>["/proc","/sys","/dev","/run","/etc","/boot","/usr","/bin","/sbin","/lib","/lib64","/opt"];
}
