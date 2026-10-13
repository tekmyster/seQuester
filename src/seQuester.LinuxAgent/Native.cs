using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;
using System.Text;

namespace RansomFree.LinuxAgent;

internal static class Native
{
    [DllImport("libc")]private static extern uint geteuid();
    public static bool Root=>geteuid()==0;
    public static void ValidateAdminPath(string path,bool directory,bool privateMode=false)
    {
        var fd=Check(open(Paths.NoLinks(path),0x20000|0x80000|0x800|(directory?0x10000:0)));
        try
        {
            var info=new byte[256];Check(statx(fd,"",0x1000,0x20b,info));
            var mode=BitConverter.ToUInt16(info,28);
            if((BitConverter.ToUInt32(info,0)&0x20b)!=0x20b||BitConverter.ToUInt32(info,20)!=0||(mode&0xf000)!=(directory?0x4000:0x8000)||(mode&(privateMode?0x3f:0x12))!=0)
                throw new IOException("Use a root-owned regular config or private directory without group/world write access.");
        }
        finally{close(fd);}
    }
    [DllImport("libc",SetLastError=true)]public static extern int close(int fd);
    [DllImport("libc",SetLastError=true)]public static extern nint read(int fd,byte[] buffer,nuint length);
    [DllImport("libc",SetLastError=true)]public static extern int inotify_init1(int flags);
    [DllImport("libc",SetLastError=true)]public static extern int inotify_add_watch(int fd,string path,uint mask);
    [DllImport("libc",SetLastError=true)]public static extern int fanotify_init(uint flags,uint eventFlags);
    [DllImport("libc",SetLastError=true)]public static extern int fanotify_mark(int fd,uint flags,ulong mask,int directoryFd,string path);
    [DllImport("libc",SetLastError=true)]public static extern int open(string path,int flags,uint mode=0);
    [DllImport("libc",SetLastError=true)]public static extern int openat(int directoryFd,string path,int flags,uint mode=0);
    [DllImport("libc",SetLastError=true)]public static extern nint readlink(string path,byte[] buffer,nuint size);
    [DllImport("libc",SetLastError=true)]public static extern long syscall(long number,int pidfd,int signal,nint info,uint flags);
    [DllImport("libc",SetLastError=true)]private static extern int statx(int fd,string path,int flags,uint mask,byte[] buffer);
    [StructLayout(LayoutKind.Sequential)]private struct PollFd{public int Fd;public short Events;public short Returned;}
    [DllImport("libc",SetLastError=true)]private static extern int poll(ref PollFd descriptor,nuint count,int timeout);
    public static bool IsAlive(int fd){var item=new PollFd{Fd=fd,Events=1};return fd>=0&&poll(ref item,1,0)==0;}
    public static bool WaitForExit(int fd){var item=new PollFd{Fd=fd,Events=1};return fd>=0&&poll(ref item,1,2000)>0&&(item.Returned&1)!=0;}
    public static int Check(int fd){if(fd<0)throw new IOException("Linux operation failed, errno "+Marshal.GetLastPInvokeError());return fd;}
    public static string? Link(string path)
    {var bytes=new byte[4096];var length=readlink(path,bytes,(nuint)bytes.Length);return length<=0||length>=bytes.Length?null:Encoding.UTF8.GetString(bytes,0,(int)length);}
    // Walk every component using directory descriptors. O_NOFOLLOW on each step
    // prevents an attacker replacing an approved ancestor with a symlink mid-create.
    public static FileStream FileAt(string path,bool create,long maximumLength=16*1024*1024,bool requireAdminOwnership=false)
    {
        var parts=Paths.NoLinks(path).Split('/',StringSplitOptions.RemoveEmptyEntries);
        var dir=Check(open("/",0x10000|0x80000));
        try
        {
            foreach(var part in parts[..^1]){var next=Check(openat(dir,part,0x10000|0x20000|0x80000));close(dir);dir=next;}
            var fd=Check(openat(dir,parts[^1],0x20000|0x80000|0x800|(create?1|0x40|0x80:0),0x1a4));
            var handle=new SafeFileHandle((nint)fd,true);
            try
            {
                // statx has a fixed, architecture-independent 256-byte UAPI layout.
                var metadata=new byte[256];
                var requiredMask=requireAdminOwnership?0x20bu:0x201u;
                Check(statx(fd,"",0x1000,requiredMask,metadata));
                if((BitConverter.ToUInt32(metadata,0)&requiredMask)!=requiredMask||(BitConverter.ToUInt16(metadata,28)&0xf000)!=0x8000)
                    throw new IOException("Canary is not a regular file; special objects are never read.");
                if(requireAdminOwnership&&(BitConverter.ToUInt32(metadata,20)!=0||(BitConverter.ToUInt16(metadata,28)&0x12)!=0))
                    throw new IOException("Recovery descriptor must remain root-owned without group/world write access.");
                if(maximumLength<0||!create&&BitConverter.ToUInt64(metadata,40)>(ulong)maximumLength)throw new IOException("Regular file exceeds the permitted read limit.");
                if(create)File.SetUnixFileMode(handle,UnixFileMode.UserRead|UnixFileMode.UserWrite|UnixFileMode.GroupRead|UnixFileMode.OtherRead);
                return new FileStream(handle,create?FileAccess.Write:FileAccess.Read);
            }
            catch{handle.Dispose();throw;}
        }
        finally{close(dir);}
    }
    // pidfd_send_signal syscall is 424 on supported Linux x64 and arm64.
    public static bool Signal(int pidfd,int signal)=>syscall(424,pidfd,signal,0,0)==0;
    public static string HashBounded(Stream stream,long limit)
    {
        using var hash=System.Security.Cryptography.IncrementalHash.CreateHash(System.Security.Cryptography.HashAlgorithmName.SHA256);
        var buffer=new byte[65536];long total=0;
        for(int size;(size=stream.Read(buffer))>0;){total+=size;if(total>limit)throw new IOException("Integrity read limit exceeded.");hash.AppendData(buffer,0,size);}
        return Convert.ToHexString(hash.GetHashAndReset());
    }
}
