using System.ComponentModel;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;

namespace RansomFree;

internal static class InstalledAgentIdentity
{
    private sealed class ServiceHandle:SafeHandleZeroOrMinusOneIsInvalid
    {public ServiceHandle():base(true){}protected override bool ReleaseHandle()=>CloseServiceHandle(handle);}
    [DllImport("advapi32.dll",SetLastError=true)]private static extern bool CloseServiceHandle(IntPtr handle);
    [DllImport("advapi32.dll",CharSet=CharSet.Unicode,SetLastError=true)]private static extern ServiceHandle OpenSCManager(string? machine,string? database,uint access);
    [DllImport("advapi32.dll",CharSet=CharSet.Unicode,SetLastError=true)]private static extern ServiceHandle OpenService(ServiceHandle manager,string name,uint access);
    [DllImport("advapi32.dll",SetLastError=true)]private static extern bool QueryServiceStatusEx(ServiceHandle service,int level,out Status status,int size,out int needed);
    [DllImport("advapi32.dll",CharSet=CharSet.Unicode,SetLastError=true)]private static extern bool QueryServiceConfig(ServiceHandle service,IntPtr config,int size,out int needed);
    [StructLayout(LayoutKind.Sequential)]private struct Status{public uint Type,State,Controls,Win32Exit,ServiceExit,Checkpoint,WaitHint,Pid,Flags;}
    [StructLayout(LayoutKind.Sequential)]private struct Config{public uint Type,Start,Error;public IntPtr Binary,Group;public uint Tag;public IntPtr Dependencies,Account,Display;}
    public static void Verify(uint pid,string expectedPath)
    {
        using var manager=OpenSCManager(null,null,1);if(manager.IsInvalid)throw new Win32Exception(Marshal.GetLastWin32Error());
        using var service=OpenService(manager,"RansomFreeAgent",5);if(service.IsInvalid)throw new IOException("Installed agent service is unavailable.");
        if(!QueryServiceStatusEx(service,0,out var status,Marshal.SizeOf<Status>(),out _)||status.State!=4||status.Pid!=pid)throw new IOException("Pipe does not belong to the running installed service.");
        QueryServiceConfig(service,IntPtr.Zero,0,out var needed);if(needed is <1 or >65536)throw new IOException("Invalid service configuration size.");
        var memory=Marshal.AllocHGlobal(needed);
        try
        {
            if(!QueryServiceConfig(service,memory,needed,out _))throw new Win32Exception(Marshal.GetLastWin32Error());
            var config=Marshal.PtrToStructure<Config>(memory);var binary=Marshal.PtrToStringUni(config.Binary)?.Trim().Trim('"');var account=Marshal.PtrToStringUni(config.Account);
            if(!string.Equals(binary,expectedPath,StringComparison.OrdinalIgnoreCase)||account is null||!account.Equals("LocalSystem",StringComparison.OrdinalIgnoreCase))throw new IOException("Agent service configuration is not trusted.");
        }
        finally{Marshal.FreeHGlobal(memory);}
    }
}
