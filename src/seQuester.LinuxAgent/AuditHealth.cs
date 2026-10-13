using System.Globalization;
using System.Runtime.InteropServices;
using System.Text;

namespace RansomFree.LinuxAgent;

internal static class AuditHealth
{
    // pidfd_open is 434 on both supported Linux architectures.
    [DllImport("libc",EntryPoint="syscall",SetLastError=true)] static extern int PidFdOpen(long number,int pid,uint flags);
    public static string BootId()=>File.ReadAllText("/proc/sys/kernel/random/boot_id").Trim();
    public static string StartTicks(int pid)
    {
        var text=File.ReadAllText($"/proc/{pid}/stat");var close=text.LastIndexOf(')');
        if(close<0)throw new InvalidDataException("Process stat unavailable.");
        var fields=text[(close+2)..].Split(' ',StringSplitOptions.RemoveEmptyEntries);
        if(fields.Length<20||fields[0] is "Z" or "X"||!ulong.TryParse(fields[19],NumberStyles.None,CultureInfo.InvariantCulture,out _))throw new InvalidDataException("Process is exited or its start identity is unavailable.");
        return fields[19];
    }
    public static string? Failure(AuditBridgeStatus status,bool fromCollector=false)
    {
        var age=DateTimeOffset.UtcNow-status.UpdatedUtc;
        if(!status.Running||status.DispatcherPid<=1||status.HeartbeatSequence<1||age>TimeSpan.FromSeconds(20)||age<TimeSpan.FromSeconds(-5))return "Dispatcher heartbeat missing, stopped or stale";
        if(!Guid.TryParseExact(status.InstanceId,"N",out _)||status.BootId!=BootId())return "Dispatcher boot/instance identity unavailable";
        var fd=PidFdOpen(434,status.DispatcherPid,0);
        if(fd<0)return "Dispatcher active process cannot be verified";
        try
        {
            if(!Native.IsAlive(fd)||StartTicks(status.DispatcherPid)!=status.DispatcherStartTicks)return "Dispatcher exited or PID was reused";
            var uid=File.ReadLines($"/proc/{status.DispatcherPid}/status").First(x=>x.StartsWith("Uid:",StringComparison.Ordinal)).Split((char[]?)null,StringSplitOptions.RemoveEmptyEntries);
            if(uid.Length!=5||uid[1]!="0"||uid[2]!="0")return "Dispatcher is not running as root";
            using var input=File.OpenRead($"/proc/{status.DispatcherPid}/cmdline");var buffer=new byte[8193];var count=input.Read(buffer);
            if(count>8192||!Encoding.UTF8.GetString(buffer,0,count).Split('\0').Contains("--audit-collect"))return "Active process is not the separate audit collector";
            var executable=Native.Link($"/proc/{status.DispatcherPid}/exe");
            if(executable==null||Path.GetFileName(executable)!="RansomFree.LinuxAgent")return "Dispatcher executable identity unavailable";
            Native.ValidateAdminPath(executable,false);
            if(status.Transport!="Native AOT relay"||!status.TransportConnected||status.RelayPid<=1||status.RelayStartTicks==null)return "Native AOT relay is not connected";
            if(status.LastRelayFrameUtc is not {} frame||DateTimeOffset.UtcNow-frame>TimeSpan.FromSeconds(20)||frame>DateTimeOffset.UtcNow.AddSeconds(5))return "Relay transport heartbeat missing or stale";
            var relayFd=PidFdOpen(434,status.RelayPid,0);
            if(relayFd<0)return "Relay process cannot be verified";
            try
            {
                if(!Native.IsAlive(relayFd)||StartTicks(status.RelayPid)!=status.RelayStartTicks)return "Relay exited or PID was reused";
                var relayExe=Native.Link($"/proc/{status.RelayPid}/exe");
                if(relayExe==null||Path.GetFileName(relayExe)!="RansomFree.AuditRelay")return "Unexpected relay executable";
                Native.ValidateAdminPath(relayExe,false);
                var stat=File.ReadAllText($"/proc/{status.RelayPid}/stat");var fields=stat[(stat.LastIndexOf(')')+2)..].Split(' ',StringSplitOptions.RemoveEmptyEntries);
                if(!int.TryParse(fields[1],out var parent)||parent<=1)return "Relay parent identity unavailable";
                var rules=AuditDispatcher.Read<AuditRuleStatus>(AuditRuleReconciler.StatusPath);
                if(!rules.Success||rules.BootId!=status.BootId||rules.AuditdPid!=parent||rules.AuditdStartTicks!=StartTicks(parent))return "Rule reconciliation missing, failed or belongs to a previous auditd instance";
                // The cap-free collector cannot ptrace/read exe links for the
                // more-privileged auditd. Bind the relay parent to the kernel-
                // registered auditd identity verified by the root rule helper.
                // Interactive root --audit-health retains its extra exe check.
                if(!fromCollector&&Path.GetFileName(Native.Link($"/proc/{parent}/exe"))!="auditd")return "Relay is not a live auditd child";
                if(!Native.IsAlive(relayFd))return "Relay exited during health check";
            }
            finally{Native.close(relayFd);}
            return Native.IsAlive(fd)&&StartTicks(status.DispatcherPid)==status.DispatcherStartTicks?null:"Dispatcher exited during health check";
        }
        catch(Exception ex){return "Dispatcher process verification unavailable: "+ex.GetType().Name;}
        finally{Native.close(fd);}
    }
    public static async Task AssertLive()
    {
        Native.ValidateAdminPath(AuditDispatcher.Root,true);
        var verifier=new AuditHeartbeatVerifier();
        void Validate(AuditBridgeStatus status)
        {
            string? failure;
            if(Native.Root)failure=Failure(status);
            else
            {
                var summary=verifier.Evaluate(new(status.UpdatedUtc,status.Running,status.BootId??"",status.InstanceId??"",status.DispatcherPid,status.DispatcherStartTicks??"",status.HeartbeatSequence,status.CollectorHealth),BootId(),DateTimeOffset.UtcNow);
                failure=summary.StartsWith("Linux Audit degraded:",StringComparison.Ordinal)?summary:null;
            }
            if(failure!=null){Console.Error.WriteLine("Audit health check: "+failure);throw new InvalidOperationException("Audit health verification failed.");}
        }
        var first=AuditDispatcher.Read<AuditBridgeStatus>(AuditDispatcher.Root+"/status.json");
        Validate(first);
        await Task.Delay(TimeSpan.FromSeconds(6));
        var second=AuditDispatcher.Read<AuditBridgeStatus>(AuditDispatcher.Root+"/status.json");
        Validate(second);
        if(first.InstanceId!=second.InstanceId||first.DispatcherPid!=second.DispatcherPid||first.DispatcherStartTicks!=second.DispatcherStartTicks||first.RelayPid!=second.RelayPid||first.RelayStartTicks!=second.RelayStartTicks||second.HeartbeatSequence<=first.HeartbeatSequence||second.UpdatedUtc<=first.UpdatedUtc)throw new InvalidOperationException("Collector/relay restarted or heartbeat did not advance during validation.");
        Console.WriteLine(Native.Root?"PASS: same live collector and auditd-child relay identities; heartbeat advanced. This does not prove rule coverage or end-to-end attribution.":"PASS: protected root collector reports healthy collector/relay identities; same-instance heartbeat advanced. No client ptrace privilege required. Per-event attribution and rule coverage require separate verification.");
    }
}
