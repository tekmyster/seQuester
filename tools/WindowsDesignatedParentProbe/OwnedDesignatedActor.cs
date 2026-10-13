using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Text;
using Microsoft.Win32.SafeHandles;

// Qualification only. Both parent and child are fixture-owned. No PID lookup is
// used to recover the child: PROCESS_INFORMATION handles remain held throughout.
internal sealed class OwnedDesignatedActor : IDisposable
{
    internal SafeFileHandle Handle {get;}
    private readonly SafeFileHandle thread;
    internal uint Pid {get;}
    internal long Created {get;}
    internal uint CreatorTid {get;}
    private OwnedDesignatedActor(Information info,uint creatorTid)
    {
        Handle=new(info.Process,true);thread=new(info.Thread,true);Pid=info.Pid;CreatorTid=creatorTid;
        try{Created=Times(Handle);}catch{NativeTerminate(Handle,2);WaitForSingleObject(Handle,15000);thread.Dispose();Handle.Dispose();throw;}
    }
    internal static long Times(SafeFileHandle handle)
    {
        if(!GetProcessTimes(handle,out var created,out _,out _,out _))throw new Win32Exception();
        if(created<=0)throw new IOException("Held process creation time unavailable");return created;
    }
    internal static SafeFileHandle OpenParent(int pid)
    {
        var handle=OpenProcess(0x100000|0x1000|0x80,false,(uint)pid);
        if(handle.IsInvalid){handle.Dispose();throw new Win32Exception();}return handle;
    }
    internal static OwnedDesignatedActor Start(string exe,string[] args,SafeFileHandle parent)
    {
        var values=new[]{exe}.Concat(args).ToArray();
        if(IntPtr.Size!=8||Marshal.SizeOf<StartupEx>()!=112)throw new PlatformNotSupportedException("This qualification requires the Windows x64 startup layout");
        if(values.Any(x=>x.Contains('"')||x.EndsWith('\\')))throw new ArgumentException("Unexpected quote or trailing slash in owned fixture argument");
        var command=new StringBuilder(string.Join(" ",values.Select(x=>"\""+x+"\"")));
        nuint size=0;var sizingSucceeded=InitializeProcThreadAttributeList(0,1,0,ref size);
        var sizeError=Marshal.GetLastWin32Error();
        if(sizingSucceeded||sizeError!=122||size is 0 or >16384)throw new Win32Exception(sizeError,"Unexpected attribute-list sizing result");
        var list=Marshal.AllocHGlobal((int)size);var parentValue=Marshal.AllocHGlobal(IntPtr.Size);var initialized=false;
        var parentReference=false;var prior=Environment.GetEnvironmentVariable("SQ_FIXTURE_LOCAL_SERVICE");
        try
        {
            parent.DangerousAddRef(ref parentReference);Marshal.WriteIntPtr(parentValue,parent.DangerousGetHandle());
            if(!InitializeProcThreadAttributeList(list,1,0,ref size))throw new Win32Exception();initialized=true;
            if(!UpdateProcThreadAttribute(list,0,0x00020000,parentValue,(nuint)IntPtr.Size,0,0))throw new Win32Exception();
            var startup=new StartupEx{Startup=new(){Size=(uint)Marshal.SizeOf<StartupEx>(),Flags=1,ShowWindow=0},Attributes=list};
            // This changes only this isolated fixture process's inherited block.
            Environment.SetEnvironmentVariable("SQ_FIXTURE_LOCAL_SERVICE","1");
            var tid=GetCurrentThreadId();
            if(!CreateProcessW(exe,command,0,0,false,0x00080000|0x08000000|0x00000004,0,Path.GetDirectoryName(exe),ref startup,out var info))throw new Win32Exception();
            return new(info,tid);
        }
        finally
        {
            Environment.SetEnvironmentVariable("SQ_FIXTURE_LOCAL_SERVICE",prior);
            if(initialized)DeleteProcThreadAttributeList(list);
            if(parentReference)parent.DangerousRelease();Marshal.FreeHGlobal(parentValue);Marshal.FreeHGlobal(list);
        }
    }
    internal void Resume(){if(ResumeThread(thread)==uint.MaxValue)throw new Win32Exception();}
    internal bool Wait(uint milliseconds){var value=WaitForSingleObject(Handle,milliseconds);return value switch{0=>true,258=>false,_=>throw new Win32Exception()};}
    internal uint ExitCode{get{if(!GetExitCodeProcess(Handle,out var code))throw new Win32Exception();return code;}}
    public void Dispose()
    {
        try{if(!Wait(0)){if(!NativeTerminate(Handle,2)||!Wait(15000))throw new IOException("Owned designated actor did not terminate");}}
        finally{thread.Dispose();Handle.Dispose();}
    }
    [StructLayout(LayoutKind.Sequential)]private struct StartupInfo
    {
        internal uint Size;internal nint Reserved,Desktop,Title;internal uint X,Y,XSize,YSize,XChars,YChars,Fill,Flags;
        internal ushort ShowWindow,ReservedBytes;internal nint ReservedBuffer,Input,Output,Error;
    }
    [StructLayout(LayoutKind.Sequential)]private struct StartupEx{internal StartupInfo Startup;internal nint Attributes;}
    [StructLayout(LayoutKind.Sequential)]private struct Information{internal nint Process,Thread;internal uint Pid,Tid;}
    [DllImport("kernel32.dll",SetLastError=true)][return:MarshalAs(UnmanagedType.Bool)]private static extern bool InitializeProcThreadAttributeList(nint list,uint count,uint flags,ref nuint size);
    [DllImport("kernel32.dll",SetLastError=true)][return:MarshalAs(UnmanagedType.Bool)]private static extern bool UpdateProcThreadAttribute(nint list,uint flags,nuint attribute,nint value,nuint size,nint previous,nint returned);
    [DllImport("kernel32.dll")]private static extern void DeleteProcThreadAttributeList(nint list);
    [DllImport("kernel32.dll",SetLastError=true,CharSet=CharSet.Unicode,ExactSpelling=true)][return:MarshalAs(UnmanagedType.Bool)]private static extern bool CreateProcessW(string application,StringBuilder command,nint processAttributes,nint threadAttributes,[MarshalAs(UnmanagedType.Bool)]bool inherit,uint flags,nint environment,string? directory,ref StartupEx startup,out Information info);
    [DllImport("kernel32.dll",SetLastError=true)]private static extern uint ResumeThread(SafeFileHandle thread);
    [DllImport("kernel32.dll",SetLastError=true)]private static extern uint WaitForSingleObject(SafeFileHandle handle,uint milliseconds);
    [DllImport("kernel32.dll",SetLastError=true)][return:MarshalAs(UnmanagedType.Bool)]private static extern bool GetProcessTimes(SafeFileHandle handle,out long created,out long exited,out long kernel,out long user);
    [DllImport("kernel32.dll",SetLastError=true)]private static extern SafeFileHandle OpenProcess(uint access,[MarshalAs(UnmanagedType.Bool)]bool inherit,uint pid);
    [DllImport("kernel32.dll",SetLastError=true)][return:MarshalAs(UnmanagedType.Bool)]private static extern bool GetExitCodeProcess(SafeFileHandle process,out uint code);
    [DllImport("kernel32.dll",EntryPoint="TerminateProcess",SetLastError=true)][return:MarshalAs(UnmanagedType.Bool)]private static extern bool NativeTerminate(SafeFileHandle process,uint code);
    [DllImport("kernel32.dll")]private static extern uint GetCurrentThreadId();
}
