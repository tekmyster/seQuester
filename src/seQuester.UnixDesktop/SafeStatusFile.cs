using System.Runtime.InteropServices;
using System.Text.Json;
using Microsoft.Win32.SafeHandles;

namespace RansomFree.UnixDesktop;

internal static class SafeStatusFile
{
    [DllImport("libc",EntryPoint="geteuid")]private static extern uint LinuxUid();
    [DllImport("/usr/lib/libSystem.B.dylib",EntryPoint="geteuid")]private static extern uint MacUid();
    [DllImport("libc",EntryPoint="open",SetLastError=true)]private static extern int LinuxOpen(string path,int flags);
    [DllImport("libc",EntryPoint="openat",SetLastError=true)]private static extern int LinuxOpenAt(int fd,string path,int flags);
    [DllImport("libc",EntryPoint="close")]private static extern int LinuxClose(int fd);
    [DllImport("libc",SetLastError=true)]private static extern int statx(int fd,string path,int flags,uint mask,byte[] info);
    [DllImport("/usr/lib/libSystem.B.dylib",EntryPoint="open",SetLastError=true)]private static extern int MacOpen(string path,int flags);
    [DllImport("/usr/lib/libSystem.B.dylib",EntryPoint="openat",SetLastError=true)]private static extern int MacOpenAt(int fd,string path,int flags);
    [DllImport("/usr/lib/libSystem.B.dylib",EntryPoint="close")]private static extern int MacClose(int fd);
    [DllImport("/usr/lib/libSystem.B.dylib",EntryPoint="fstat$INODE64",SetLastError=true)]private static extern int IntelStat(int fd,byte[] info);
    [DllImport("/usr/lib/libSystem.B.dylib",EntryPoint="fstat",SetLastError=true)]private static extern int ArmStat(int fd,byte[] info);
    public static bool IsRoot=>OperatingSystem.IsLinux()?LinuxUid()==0:MacUid()==0;
    public static string StatusPath=>OperatingSystem.IsLinux()?"/run/ransomfree-client/status.json":"/Library/Application Support/RansomFree/Status/status.json";
    private static int Check(int fd)=>fd>=0?fd:throw new IOException("Status is unavailable. Confirm the service is running and your read-only group access is approved.");
    public static EndpointSnapshot Read()
    {
        var linux=OperatingSystem.IsLinux();
        var directory=linux?0x10000:0x100000;var nofollow=linux?0x20000:0x100;var cloexec=linux?0x80000:0x1000000;var nonblock=linux?0x800:4;
        int OpenAt(int fd,string path,int flags)=>linux?LinuxOpenAt(fd,path,flags):MacOpenAt(fd,path,flags);
        void Close(int fd){if(linux)LinuxClose(fd);else MacClose(fd);}
        var parts=StatusPath.Split('/',StringSplitOptions.RemoveEmptyEntries);
        var parent=Check(linux?LinuxOpen("/",directory|cloexec):MacOpen("/",directory|cloexec));
        try
        {
            foreach(var part in parts[..^1]){var next=Check(OpenAt(parent,part,directory|nofollow|cloexec));Close(parent);parent=next;}
            var fd=Check(OpenAt(parent,parts[^1],nofollow|cloexec|nonblock));
            using var handle=new SafeFileHandle(fd,true);
            var info=new byte[256];var result=linux?statx(fd,"",0x1000,0x201,info):RuntimeInformation.ProcessArchitecture==Architecture.X64?IntelStat(fd,info):ArmStat(fd,info);
            Check(result);
            var mode=BitConverter.ToUInt16(info,linux?28:4);var size=BitConverter.ToInt64(info,linux?40:96);
            if((mode&0xf000)!=0x8000||(mode&0x12)!=0||size is <2 or >2097152||(linux&&(BitConverter.ToUInt32(info,0)&0x201)!=0x201))throw new IOException("Unsafe or oversized status file rejected.");
            using var input=new FileStream(handle,FileAccess.Read);
            using var bytes=new MemoryStream();var buffer=new byte[16384];
            for(int count;(count=input.Read(buffer))>0;){if(bytes.Length+count>2097152)throw new IOException("Status size limit exceeded.");bytes.Write(buffer,0,count);}
            var snapshot=JsonSerializer.Deserialize<EndpointSnapshot>(bytes.ToArray(),new JsonSerializerOptions{MaxDepth=16})??throw new IOException("Status missing.");
            if(snapshot.Events==null||snapshot.Events.Length>100||snapshot.UpdatedUtc==default||snapshot.Canaries<0||snapshot.PendingSyslog<0||snapshot.PolicyRevision<0
                ||snapshot.Events.Any(e=>e is null||!Guid.TryParseExact(e.EventId,"N",out _)||e.Time==default))throw new IOException("Invalid status snapshot.");
            return snapshot;
        }
        finally{Close(parent);}
    }
}

internal sealed record EndpointSnapshot(string Version,DateTimeOffset UpdatedUtc,string Health,string Connectivity,DateTimeOffset? LastSyncUtc,string Monitor,int Canaries,long PolicyRevision,EndpointQueue? Queue,int PendingSyslog,string SyslogStatus,EndpointEvent[] Events);
internal sealed record EndpointQueue(int Pending,long PayloadBytes,int MaxEvents,long MaxPayloadBytes);
internal sealed record EndpointEvent(string EventId,DateTimeOffset Time,string Operation,string Path,string Process,string User,string Source,bool Allowlisted)
{public int? ProcessId {get;init;} public RansomFree.Contracts.EventAttribution? Attribution {get;init;} public RansomFree.Contracts.EventTrust? Trust {get;init;}}
