using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Text;

namespace RansomFree.Client.Forensics;

internal sealed partial class LinuxProtectedDirectory
{
    // Linux x86-64 statmount(457), mnt_id_req v0 and the fixed 512-byte
    // statmount ABI from include/uapi/linux/mount.h. No mount is modified.
    [DllImport("libc",EntryPoint="syscall",SetLastError=true)]
    private static extern long QueryMount(long number,[In] byte[] request,[Out] byte[] response,nuint size,uint flags);
    internal readonly record struct DirectMountKey(ulong Unique,ulong Legacy,uint Major,uint Minor,long Magic);
    internal static string? ReadDirectMount(DirectMountKey key)
    {
        if(!OperatingSystem.IsLinux()||RuntimeInformation.ProcessArchitecture!=Architecture.X64)
            return null;
        var request=new byte[24];BitConverter.TryWriteBytes(request.AsSpan(),24u);
        BitConverter.TryWriteBytes(request.AsSpan(8),key.Unique);BitConverter.TryWriteBytes(request.AsSpan(16),0x23ul);
        var response=new byte[1024];
        if(QueryMount(457,request,response,(nuint)response.Length,0)!=0)
        {
            var error=Marshal.GetLastPInvokeError();
            // Unsupported API or unavailable privilege uses the existing
            // fully validated mountinfo path. Never grant extra capabilities.
            if(error is 38 or 22 or 1 or 13)return null;
            throw new Win32Exception(error,"Direct mount query failed");
        }
        return ParseDirectMount(response,key);
    }
    internal static string ParseDirectMount(byte[] response,DirectMountKey key)
    {
        if(response.Length<512)throw new IOException("Direct mount response is truncated");
        var size=BitConverter.ToUInt32(response,0);var mask=BitConverter.ToUInt64(response,8);
        if(size<513||size>response.Length||(mask&0x23)!=0x23||key.Unique==0||key.Legacy==0||
            BitConverter.ToUInt64(response,40)!=key.Unique||BitConverter.ToUInt32(response,56)!=key.Legacy||
            BitConverter.ToUInt32(response,16)!=key.Major||BitConverter.ToUInt32(response,20)!=key.Minor||
            BitConverter.ToInt64(response,24)!=key.Magic)
            throw new IOException("Direct mount identity or required fields differ from the held descriptor");
        var offset=BitConverter.ToUInt32(response,36);
        if(offset>=size-512)throw new IOException("Direct mount type offset exceeds the response");
        var text=response.AsSpan(checked(512+(int)offset),checked((int)size-512-(int)offset));
        var end=text.IndexOf((byte)0);
        if(end<=0||end>255||text[..end].ContainsAnyExceptInRange((byte)0x21,(byte)0x7e))
            throw new IOException("Direct mount type is unavailable or malformed");
        return Encoding.ASCII.GetString(text[..end]);
    }
}
