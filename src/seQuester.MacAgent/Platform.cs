namespace RansomFree.LinuxAgent;

internal static class Platform
{
    public const string Name="macOS",Version="0.9.0-macos-dev",DefaultMonitor="fsevents";
    public const string Root="/Library/Application Support/RansomFree";
    public const string DataPath=Root+"/Data",ConfigPath=Root+"/Config/client.json",StatusPath=Root+"/Status/status.json";
    public static bool Supported=>OperatingSystem.IsMacOS()&&(System.Runtime.InteropServices.RuntimeInformation.ProcessArchitecture is System.Runtime.InteropServices.Architecture.X64 or System.Runtime.InteropServices.Architecture.Arm64);
    public static bool ValidMonitor(string mode)=>mode is "fsevents" or "endpoint-security";
    public static bool SupportsResponse(string mode)=>mode=="endpoint-security";
    public static bool SupportsAutomatic(RansomFree.Contracts.AutomaticResponsePolicy policy)=>!policy.OnRead;
    public static bool AutomaticTrigger(RansomFree.Contracts.AutomaticResponsePolicy policy,string operation)=>(policy.OnWrite&&(operation=="Canary write"||operation=="Canary close after modification"))||(policy.OnDelete&&operation=="Canary deleted")||(policy.OnPermissionChange&&operation=="Canary permissions changed");
    public static string[] ProtectedPaths=>["/System","/Library","/private","/dev","/etc","/var","/tmp","/usr","/bin","/sbin","/opt"];
}
