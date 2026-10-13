using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;

namespace RansomFree.LinuxAgent;

internal static class Native
{
    private const string Lib="/usr/lib/libSystem.B.dylib";
    [DllImport(Lib,SetLastError=true)]public static extern int close(int fd);
    [DllImport(Lib,SetLastError=true)]private static extern int open(string path,int flags,uint mode=0);
    [DllImport(Lib,SetLastError=true)]private static extern int openat(int fd,string path,int flags,uint mode=0);
    [DllImport(Lib,EntryPoint="fstat$INODE64",SetLastError=true)]private static extern int fstatIntel(int fd,byte[] value);
    [DllImport(Lib,EntryPoint="fstat",SetLastError=true)]private static extern int fstatArm(int fd,byte[] value);
    [DllImport(Lib)]private static extern uint geteuid();
    [DllImport(Lib)]private static extern int task_for_pid(uint parent,int pid,out uint task);
    [DllImport(Lib)]private static extern int task_info(uint task,int flavor,[Out] uint[] information,ref uint count);
    [DllImport(Lib)]private static extern int task_terminate(uint task);
    [DllImport(Lib)]private static extern int mach_port_deallocate(uint parent,uint task);
    [StructLayout(LayoutKind.Sequential)]private readonly struct AuditToken(uint[] words)
    {public readonly uint A=words[0],B=words[1],C=words[2],D=words[3],E=words[4],F=words[5],G=words[6],H=words[7];}
    [DllImport("/usr/lib/libbsm.dylib")]private static extern int audit_token_to_pid(AuditToken token);
    [DllImport("/usr/lib/libbsm.dylib")]private static extern uint audit_token_to_euid(AuditToken token);
    [DllImport("/usr/lib/libbsm.dylib")]private static extern uint audit_token_to_ruid(AuditToken token);
    public static int TokenPid(uint[] token)=>token.Length==8?audit_token_to_pid(new(token)):-1;
    public static bool Root=>geteuid()==0;
    public static void ValidateAdminPath(string path,bool directory,bool privateMode=false)
    {
        var fd=Check(open(Paths.NoLinks(path),0x100|0x1000000|4|(directory?0x100000:0)));
        try
        {
            var info=new byte[256];Check(Stat(fd,info));var mode=BitConverter.ToUInt16(info,4);
            if(BitConverter.ToUInt32(info,16)!=0||(mode&0xf000)!=(directory?0x4000:0x8000)||(mode&(privateMode?0x3f:0x12))!=0)
                throw new IOException("Use a root-owned regular config or private directory without group/world write access.");
        }
        finally{close(fd);}
    }
    private static int Stat(int fd,byte[] value)=>RuntimeInformation.ProcessArchitecture==Architecture.X64?fstatIntel(fd,value):fstatArm(fd,value);
    private static int Check(int value){if(value<0)throw new IOException("macOS file operation failed, errno "+Marshal.GetLastPInvokeError());return value;}
    public static FileStream FileAt(string path,bool create,long limit=16*1024*1024)
    {
        var parts=Paths.NoLinks(path).Split('/',StringSplitOptions.RemoveEmptyEntries);
        const int directory=0x100000,nofollow=0x100,cloexec=0x1000000,nonblock=4;
        var parent=Check(open("/",directory|cloexec));
        try
        {
            foreach(var part in parts[..^1]){var next=Check(openat(parent,part,directory|nofollow|cloexec));close(parent);parent=next;}
            var fd=Check(openat(parent,parts[^1],nofollow|cloexec|nonblock|(create?1|0x200|0x800:0),0x1a4));
            var handle=new SafeFileHandle((nint)fd,true);
            try
            {
                // Darwin 64-bit inode stat ABI: mode at 4, size at 96 (x64 and arm64).
                var info=new byte[256];Check(Stat(fd,info));
                if((BitConverter.ToUInt16(info,4)&0xf000)!=0x8000)throw new IOException("Only regular canary files are permitted.");
                if(!create&&BitConverter.ToInt64(info,96)>limit)throw new IOException("Integrity read limit exceeded.");
                if(create)File.SetUnixFileMode(handle,UnixFileMode.UserRead|UnixFileMode.UserWrite|UnixFileMode.GroupRead|UnixFileMode.OtherRead);
                return new FileStream(handle,create?FileAccess.Write:FileAccess.Read);
            }
            catch{handle.Dispose();throw;}
        }
        finally{close(parent);}
    }
    public static void VerifyRootExecutable(string path)
    {
        Paths.NoLinks(path);
        for(string? current=path;current!=null;current=Path.GetDirectoryName(current))
        {
            var fd=Check(open(current,0x100|0x1000000|4));
            try{var info=new byte[256];Check(Stat(fd,info));if(BitConverter.ToUInt32(info,16)!=0||(BitConverter.ToUInt16(info,4)&0x12)!=0)throw new IOException("Endpoint Security helper and ancestors must be root owned and not group/world writable.");}
            finally{close(fd);}
        }
    }
    public static string HashBounded(Stream stream,long limit)
    {
        using var hash=System.Security.Cryptography.IncrementalHash.CreateHash(System.Security.Cryptography.HashAlgorithmName.SHA256);
        var bytes=new byte[65536];long total=0;
        for(int size;(size=stream.Read(bytes))>0;){total+=size;if(total>limit)throw new IOException("Integrity read limit exceeded.");hash.AppendData(bytes,0,size);}
        return Convert.ToHexString(hash.GetHashAndReset());
    }
    public static (string Outcome,string Message) StopTask(int pid,uint[] expectedToken)
    {
        if(!Root||pid<=4||pid==Environment.ProcessId||expectedToken.Length!=8||TokenPid(expectedToken)!=pid||audit_token_to_euid(new(expectedToken))==0||audit_token_to_ruid(new(expectedToken))==0)
            return("Rejected","Protected process or missing native identity/root approval; no action performed.");
        // mach_task_self() is a C macro for an exported port-name variable, not a
        // guessed callable symbol. The send right returned below binds a task
        // object, unlike kill(pid), which could address a subsequently reused PID.
        var library=NativeLibrary.Load(Lib);
        try
        {
            var self=unchecked((uint)Marshal.ReadInt32(NativeLibrary.GetExport(library,"mach_task_self_")));
            if(task_for_pid(self,pid,out var task)!=0||task==0)return("Rejected","macOS denied task control; no action performed. Protected/hardened targets may be inaccessible.");
            try
            {
                var actual=new uint[8];uint count=8;
                if(task_info(task,15,actual,ref count)!=0||count!=8||!actual.SequenceEqual(expectedToken))return("Rejected","Task audit token no longer matches the captured event; no action performed.");
                return task_terminate(task)==0?("Indeterminate","task_terminate accepted for the event-bound Mach task; process exit not independently confirmed."):("Rejected","macOS rejected task termination; no successful action assumed.");
            }
            finally{mach_port_deallocate(self,task);}
        }
        finally{NativeLibrary.Free(library);}
    }
}
