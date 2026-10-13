using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
if(!OperatingSystem.IsLinux()||RuntimeFeature.IsDynamicCodeSupported||args.Length!=0||Environment.GetEnvironmentVariable("SEQUESTER_LAUNCHER_FIXTURE")!="1"||!File.Exists("/.dockerenv"))throw new InvalidOperationException("Disposable Linux Native AOT fixture only.");
if(Native.prctl(65,1,0,0,0)!=0)throw new System.ComponentModel.Win32Exception(Marshal.GetLastPInvokeError());
if(Native.prctl(66,0,0,0,0)!=1)throw new IOException("MDWE flag verification failed.");
const string path="/opt/ransomfree-client/current/audit/launch-relay.sh";
var arg=Marshal.StringToCoTaskMemUTF8(path);var argv=Marshal.AllocHGlobal(IntPtr.Size*2);
Marshal.WriteIntPtr(argv,arg);Marshal.WriteIntPtr(argv,IntPtr.Size,0);
Console.WriteLine("Fixture: kernel MDWE=1 verified; exec wrapper with zero arguments and empty environment.");
Native.execve(path,argv,0);
throw new System.ComponentModel.Win32Exception(Marshal.GetLastPInvokeError());
internal static class Native
{
    [DllImport("libc",SetLastError=true)] internal static extern int prctl(int option,nuint a,nuint b,nuint c,nuint d);
    [DllImport("libc",SetLastError=true)] internal static extern int execve(string path,nint argv,nint environment);
}
