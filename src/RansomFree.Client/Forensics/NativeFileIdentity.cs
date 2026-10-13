using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Text;
using Microsoft.Win32.SafeHandles;
using RansomFree.Contracts;
namespace RansomFree.Client.Forensics;

public static class NativeFileIdentity
{
    [StructLayout(LayoutKind.Sequential)] private struct Basic {public long Creation,Access,Write,Change;public uint Attributes;}
    [StructLayout(LayoutKind.Sequential)] private struct Id {public ulong Volume;[MarshalAs(UnmanagedType.ByValArray,SizeConst=16)]public byte[] Value;}
    [DllImport("kernel32.dll",SetLastError=true,EntryPoint="GetFileInformationByHandleEx")]private static extern bool BasicInfo(SafeFileHandle file,int kind,out Basic value,uint size);
    [DllImport("kernel32.dll",SetLastError=true,EntryPoint="GetFileInformationByHandleEx")]private static extern bool IdInfo(SafeFileHandle file,int kind,out Id value,uint size);
    [DllImport("kernel32.dll",CharSet=CharSet.Unicode,SetLastError=true)]private static extern uint GetFinalPathNameByHandle(SafeFileHandle file,StringBuilder path,uint size,uint flags);
    [DllImport("libc",SetLastError=true)]private static extern int statx(int fd,string path,int flags,uint mask,byte[] buffer);
    [DllImport("libc",SetLastError=true)]private static extern nint readlink(string path,byte[] buffer,nuint size);
    public static string? Link(string path)
    {var buffer=new byte[4096];var n=readlink(path,buffer,(nuint)buffer.Length);return n>0&&n<buffer.Length?Encoding.UTF8.GetString(buffer,0,(int)n):null;}
    public static FileIdentityEvidence Read(FileStream stream)
    {
        if(OperatingSystem.IsWindows())
        {
            if(!BasicInfo(stream.SafeFileHandle,0,out var basic,(uint)Marshal.SizeOf<Basic>())||!IdInfo(stream.SafeFileHandle,18,out var id,(uint)Marshal.SizeOf<Id>()))throw new Win32Exception(Marshal.GetLastWin32Error());
            var path=new StringBuilder(32768);var count=GetFinalPathNameByHandle(stream.SafeFileHandle,path,(uint)path.Capacity,0);
            var resolved=count>0&&count<path.Capacity?path.ToString():null;
            return new(){StableId=$"windows:{id.Volume:X16}:{Convert.ToHexString(id.Value)}",Size=stream.Length,CreatedUtc=Time(basic.Creation),ModifiedUtc=Time(basic.Write),AccessedUtc=Time(basic.Access),ChangedUtc=Time(basic.Change),ChangeMarker=$"{basic.Change}:{basic.Write}:{basic.Creation}",ResolvedPath=resolved,Status=EvidenceStatus.Captured("opened-file-handle")};
        }
        if(OperatingSystem.IsLinux())
        {
            var bytes=new byte[256];if(statx(stream.SafeFileHandle.DangerousGetHandle().ToInt32(),"",0x1000,0xfff,bytes)!=0)throw new Win32Exception(Marshal.GetLastPInvokeError());
            var mask=BitConverter.ToUInt32(bytes,0);if((mask&0x3c0)!=0x3c0||(BitConverter.ToUInt16(bytes,28)&0xf000)!=0x8000)throw new IOException("Stable regular-file metadata is unavailable.");
            DateTimeOffset? Stamp(int offset)=>DateTimeOffset.FromUnixTimeSeconds(BitConverter.ToInt64(bytes,offset)).AddTicks(BitConverter.ToUInt32(bytes,offset+8)/100);
            return new(){StableId=$"linux:{BitConverter.ToUInt32(bytes,136)}:{BitConverter.ToUInt32(bytes,140)}:{BitConverter.ToUInt64(bytes,32)}",Size=checked((long)BitConverter.ToUInt64(bytes,40)),CreatedUtc=(mask&0x800)!=0?Stamp(80):null,ModifiedUtc=(mask&0x40)!=0?Stamp(112):null,AccessedUtc=(mask&0x20)!=0?Stamp(64):null,ChangedUtc=(mask&0x80)!=0?Stamp(96):null,ChangeMarker=$"{BitConverter.ToInt64(bytes,96)}:{BitConverter.ToUInt32(bytes,104)}:{BitConverter.ToInt64(bytes,112)}:{BitConverter.ToUInt32(bytes,120)}",ResolvedPath=Link("/proc/self/fd/"+stream.SafeFileHandle.DangerousGetHandle()),Status=EvidenceStatus.Captured("statx-opened-file-descriptor")};
        }
        throw new PlatformNotSupportedException();
    }
    private static DateTimeOffset? Time(long value)=>value>0?DateTimeOffset.FromFileTime(value):null;
    public static string CacheKey(FileIdentityEvidence file)=>$"{file.StableId}|{file.Size}|{file.ChangeMarker}";
    public static bool Same(FileIdentityEvidence a,FileIdentityEvidence b)=>a.StableId!=null&&a.ChangeMarker!=null&&a.Size!=null&&CacheKey(a)==CacheKey(b);
}
