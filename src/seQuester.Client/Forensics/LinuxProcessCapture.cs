using System.ComponentModel;
using System.Globalization;
using System.Runtime.InteropServices;
using System.Text;
using RansomFree.Contracts;
namespace RansomFree.Client.Forensics;

internal static class LinuxProcessCapture
{
    [DllImport("libc",SetLastError=true)]private static extern long syscall(long number,int pid,uint flags);
    [DllImport("libc")]private static extern int close(int fd);
    [DllImport("libc")]private static extern long sysconf(int name);
    [StructLayout(LayoutKind.Sequential)]private struct Timespec {public long Seconds,Nanoseconds;}
    [DllImport("libc",SetLastError=true)]private static extern int clock_gettime(int clock,out Timespec stamp);
    [StructLayout(LayoutKind.Sequential)]private struct Poll {public int Fd;public short Events,Returned;}
    [DllImport("libc",SetLastError=true)]private static extern int poll(ref Poll fd,nuint count,int timeout);
    private static readonly string BootId=File.ReadAllText("/proc/sys/kernel/random/boot_id").Trim();
    private static readonly long Ticks=sysconf(2); // _SC_CLK_TCK
    private static (string Start,int Parent,uint Session) Stat(int pid)
    {var raw=File.ReadAllText($"/proc/{pid}/stat");var fields=raw[(raw.LastIndexOf(')')+2)..].Split(' ',StringSplitOptions.RemoveEmptyEntries);return(fields[19],int.Parse(fields[1],CultureInfo.InvariantCulture),uint.Parse(fields[3],CultureInfo.InvariantCulture));}
    public static void Capture(ActorLease lease,AgentEvent value,string sensor)
    {
        if(RuntimeInformation.ProcessArchitecture is not (Architecture.X64 or Architecture.Arm64))throw new PlatformNotSupportedException();
        var pid=value.ProcessId!.Value;var fd=(int)syscall(434,pid,0); // pidfd_open on supported x64/arm64
        if(fd<0)throw new Win32Exception(Marshal.GetLastPInvokeError());
        try
        {
            var before=Stat(pid);var start=BootId+":"+before.Start;
            // /proc btime has only second precision; bracket realtime with CLOCK_BOOTTIME instead.
            if(Ticks<=0||clock_gettime(7,out var bootBefore)!=0||clock_gettime(0,out var realtime)!=0||clock_gettime(7,out var bootAfter)!=0)throw new Win32Exception();
            double Seconds(Timespec t)=>t.Seconds+t.Nanoseconds/1_000_000_000d;
            var bootEpoch=DateTimeOffset.FromUnixTimeSeconds(realtime.Seconds).AddTicks(realtime.Nanoseconds/100).AddSeconds(-Seconds(bootAfter));
            var started=bootEpoch.AddSeconds(double.Parse(before.Start,CultureInfo.InvariantCulture)/Ticks);
            var upper=started.AddSeconds(1d/Ticks+Seconds(bootAfter)-Seconds(bootBefore));
            LinuxProcessBindingException.RequireStart(value.Attribution?.ProcessStartTicks,before.Start,upper,value.ObservedUtc);
            lease.Process=lease.Process with{StartedUtc=started,StartKey=start,InstanceId=ActorLease.Correlate(sensor,pid,start),ParentPid=before.Parent,ProcessSessionId=before.Session,SessionStatus=EvidenceStatus.Captured("procfs-stat-process-session-id"),Status=EvidenceStatus.Captured("pidfd-and-boot-start-ticks; wall-time-estimated")};
            var path=NativeFileIdentity.Link($"/proc/{pid}/exe")??throw new IOException("Executable link unavailable.");
            var comparable=path.EndsWith(" (deleted)",StringComparison.Ordinal)?path[..^10]:path;
            if(!string.Equals(comparable,value.Process,StringComparison.Ordinal))throw new LinuxProcessBindingException(LinuxProcessBindingException.ImageMismatch);
            lease.Image=File.OpenRead($"/proc/{pid}/exe");lease.File=NativeFileIdentity.Read(lease.Image);
            var afterOpen=Stat(pid);var live=new Poll{Fd=fd,Events=1};
            using(var current=File.OpenRead($"/proc/{pid}/exe"))
                if(before.Start!=afterOpen.Start||poll(ref live,1,0)!=0||!NativeFileIdentity.Same(lease.File,NativeFileIdentity.Read(current)))throw new LinuxProcessBindingException(LinuxProcessBindingException.ChangedDuringCapture);
            lease.Process=lease.Process with{ExecutablePath=path};
            lease.Binding=EvidenceStatus.Captured("process-instance-checked-before-and-after-image-open; disk-image-not-memory-integrity");
            PrincipalEvidence owner;
            try
            {
                var status=File.ReadAllLines($"/proc/{pid}/status");
                uint[] Numbers(string key)=>status.FirstOrDefault(x=>x.StartsWith(key+":"))?.Split((char[]?)null,StringSplitOptions.RemoveEmptyEntries).Skip(1).Select(x=>uint.Parse(x,CultureInfo.InvariantCulture)).ToArray()??[];
                var uid=Numbers("Uid");var gid=Numbers("Gid");var groups=Numbers("Groups");
                owner=new(){Uid=uid.Length>0?uid[0]:null,EffectiveUid=uid.Length>1?uid[1]:null,FileSystemUid=uid.Length>3?uid[3]:null,Gid=gid.Length>0?gid[0]:null,EffectiveGid=gid.Length>1?gid[1]:null,FileSystemGid=gid.Length>3?gid[3]:null,SupplementaryGroups=groups.Take(64).ToArray(),SessionId=before.Session,Status=new(uid.Length>=4&&gid.Length>=4&&groups.Length<=64?"captured":"partial","procfs-after-observation-not-event-time-credentials")};
            }
            catch(Exception ex)when(ActorLease.OptionalFailure(ex)){owner=new(){Status=ActorLease.FailedField("process-owner-unavailable-after-image-capture",ex)};}
            string? command=null;EvidenceStatus commandStatus;
            try{using var input=File.OpenRead($"/proc/{pid}/cmdline");var bytes=new byte[2049];var length=input.ReadAtLeast(bytes,bytes.Length,false);command=Encoding.UTF8.GetString(bytes,0,Math.Min(length,2048)).Replace('\0',' ').Trim();commandStatus=new(length>2048?"partial":"captured",length>2048?"procfs-command-line-truncated":"procfs-after-observation");}catch(Exception ex)when(ActorLease.OptionalFailure(ex)){commandStatus=ActorLease.FailedField("process-command-line-unavailable",ex);}
            // procfs metadata remains provisional until PID identity is checked again. A retained image survives this failure.
            try{var after=Stat(pid);var p=new Poll{Fd=fd,Events=1};using var current=File.OpenRead($"/proc/{pid}/exe");if(before.Start!=after.Start||poll(ref p,1,0)!=0||!NativeFileIdentity.Same(lease.File,NativeFileIdentity.Read(current)))throw new IOException("Process exited, PID was reused or executable changed during optional metadata reads.");}
            catch(Exception ex)when(ActorLease.OptionalFailure(ex)){owner=new(){Status=ActorLease.FailedField("optional-metadata-process-no-longer-observable",ex)};command=null;commandStatus=ActorLease.FailedField("optional-metadata-process-no-longer-observable",ex);}
            lease.Process=lease.Process with{Owner=owner,CommandLine=command,CommandLineStatus=commandStatus};
            string? parentKey=null;DateTimeOffset? parentStart=null;string? parentPath=null;var parentStatus=EvidenceStatus.Unavailable("parent-process-unavailable");
            try
            {
                var parent=Stat(before.Parent);parentKey=BootId+":"+parent.Start;parentStart=bootEpoch.AddSeconds(double.Parse(parent.Start,CultureInfo.InvariantCulture)/Ticks);
                if(parentStart>started){parentKey=null;parentStart=null;parentStatus=new("partial","parent-pid-reused-after-child-start");}
                else
                {
                    parentPath=NativeFileIdentity.Link($"/proc/{before.Parent}/exe");
                    if(Stat(before.Parent).Start!=parent.Start){parentKey=null;parentStart=null;parentPath=null;parentStatus=new("partial","parent-pid-reused-during-capture");}
                    else parentStatus=parentPath!=null?EvidenceStatus.Captured("parent-start-not-newer-than-child; procfs-later-observation"):new("partial","parent-image-unavailable");
                }
            }
            catch(Exception ex)when(ActorLease.OptionalFailure(ex)){parentKey=null;parentStart=null;parentPath=null;parentStatus=ActorLease.FailedField("parent-metadata-unavailable",ex);}
            lease.Process=lease.Process with{ParentStartKey=parentKey,ParentStartedUtc=parentStart,ParentInstanceId=parentKey!=null?ActorLease.Correlate(sensor,before.Parent,parentKey):null,ParentExecutablePath=parentPath,ParentStatus=parentStatus,Status=new(owner.Status.State=="captured"&&commandStatus.State=="captured"?"captured":"partial","pidfd-start-time-and-retained-image; inspect-optional-metadata-status")};
        }
        finally{close(fd);}
    }
}
