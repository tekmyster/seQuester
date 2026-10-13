using System.ComponentModel;
using System.Buffers;
using System.Globalization;
using System.Runtime.InteropServices;
using System.Text;
using Microsoft.Win32.SafeHandles;

namespace RansomFree.Client.Forensics;

internal sealed partial class LinuxProtectedDirectory
{
    // This is an admission receipt for the currently held mount in this process
    // namespace, not a mount ID intended to survive a reboot.
    internal sealed record MountIdentity(ulong MountId,uint DeviceMajor,uint DeviceMinor,string Type,long Magic,int FileSystemId0,int FileSystemId1);
    [DllImport("libc",EntryPoint="fstatfs",SetLastError=true)]private static extern int FileSystemStat(SafeFileHandle file,[Out] byte[] value);
    private static MountIdentity QualifiedMount(SafeFileHandle file)
    {
        if(!OperatingSystem.IsLinux()||RuntimeInformation.ProcessArchitecture!=Architecture.X64)
            throw new PlatformNotSupportedException("Qualified filesystem ABI requires Linux x64");
        var fs=new byte[120];if(FileSystemStat(file,fs)!=0)throw new Win32Exception(Marshal.GetLastPInvokeError());
        var magic=BitConverter.ToInt64(fs,0);
        if(magic!=0xef53)throw new IOException("Native installation requires the qualified local ext4 filesystem");
        var sx=new byte[256];if(Statx(file,"",0x1000,0x17ff,sx)!=0)throw new Win32Exception(Marshal.GetLastPInvokeError());
        if((BitConverter.ToUInt32(sx,0)&0x1000)==0)throw new IOException("Native installation mount identity unavailable");
        var mount=BitConverter.ToUInt64(sx,144);var major=BitConverter.ToUInt32(sx,136);var minor=BitConverter.ToUInt32(sx,140);
        // EXT2/3 share the magic value; tie the retained descriptor to the exact
        // mountinfo entry before calling its filesystem ext4. No pathname prefix
        // or /proc/mounts heuristic is used to identify a mount.
        string? type=null;
        var unique=new byte[256];
        if(Statx(file,"",0x1000,0x4000,unique)!=0)throw new Win32Exception(Marshal.GetLastPInvokeError());
        if((BitConverter.ToUInt32(unique,0)&0x4000)!=0)
        {
            var key=new DirectMountKey(BitConverter.ToUInt64(unique,144),mount,major,minor,magic);
            type=mountValidation!=null?mountValidation.ObserveDirect(key):ReadDirectMount(key);
        }
        if(type==null)
        {
            if(mountValidation!=null)type=mountValidation.Observe(mount,major,minor);
            else{using var input=File.OpenRead("/proc/self/mountinfo");type=ReadMountType(ReadMountInventory(input),mount,major,minor);}
        }
        if(mount==0||major==0||type!="ext4")throw new IOException("Held file is not on the qualified local ext4 mount");
        return new(mount,major,minor,type,magic,BitConverter.ToInt32(fs,56),BitConverter.ToInt32(fs,60));
    }
    // Inspect only the first field on unrelated lines. Splitting every field
    // of every mount repeatedly allocates thousands of strings in admission
    // sampling. Read a fresh inventory on every call and retain the existing
    // strict validation and duplicate detection for the selected mount.
    internal static string? ReadMountType(string inventory,ulong mount,uint major,uint minor)
    {
        var id=mount.ToString(CultureInfo.InvariantCulture);string? type=null;
        var rest=inventory.AsSpan();
        while(!rest.IsEmpty)
        {
            var end=rest.IndexOf('\n');var line=end<0?rest:rest[..end];rest=end<0?[]:rest[(end+1)..];
            if(line.IsEmpty)continue;
            var space=line.IndexOf(' ');var first=space<0?line:line[..space];
            if(!first.SequenceEqual(id))continue;
            var fields=line.ToString().Split(' ');var separator=Array.IndexOf(fields,"-");
            if(type!=null||separator<6||fields.Length!=separator+4||fields[2]!=$"{major}:{minor}")
                throw new IOException("Mount identity is ambiguous or inconsistent");
            type=fields[separator+1];
        }
        return type;
    }
    internal MountIdentity RequireQualifiedLocalExt4()
    {lock(gate){ObjectDisposedException.ThrowIf(disposed,this);RequireDirectory(Describe(handle),group);return QualifiedMount(handle);}}
    internal static string ReadMountInventory(Stream input)
    {
        const int maximum=1024*1024;var bytes=ArrayPool<byte>.Shared.Rent(4096);var used=0;
        try
        {
            while(true)
            {
                if(used>maximum)throw new IOException("Mount inventory exceeds admission bound");
                var capacity=Math.Min(bytes.Length,maximum+1);
                if(used==capacity)
                {
                    var grown=ArrayPool<byte>.Shared.Rent(Math.Min(capacity*2,maximum+1));
                    bytes.AsSpan(0,used).CopyTo(grown);ArrayPool<byte>.Shared.Return(bytes,clearArray:true);bytes=grown;
                    capacity=Math.Min(bytes.Length,maximum+1);
                }
                var count=input.Read(bytes,used,capacity-used);if(count==0)break;used+=count;
            }
            return Encoding.UTF8.GetString(bytes,0,used);
        }
        finally{ArrayPool<byte>.Shared.Return(bytes,clearArray:true);}
    }
}
