using System.Diagnostics;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace RansomFree.LinuxAgent;

// Explicit operator invocation only. Reads one existing active canary, never deploys
// files, installs/restarts services, rewrites audit rules or contacts management.
internal static class AuditLiveValidation
{
    public static async Task Run(string selected)
    {
        if(!Native.Root)throw new UnauthorizedAccessException("Live audit validation requires an approved root invocation.");
        var path=Paths.NoLinks(selected);
        using(var inventory=Native.FileAt(Platform.DataPath+"/canaries.json",false))
        {
            if(inventory.Length>2097152)throw new InvalidDataException("Inventory exceeds limit.");
            var canaries=JsonSerializer.Deserialize<Canary[]>(inventory,PrivateState.Json)??throw new InvalidDataException("Inventory unavailable.");
            if(!canaries.Any(c=>c.Active&&c.Path==path))throw new InvalidOperationException("Select an existing active canary explicitly; arbitrary files are refused.");
        }
        var config=AuditDispatcher.Read<ClientConfiguration>(Platform.ConfigPath);
        if(!config.Audit.Enabled||!config.Folders.Values.Any(f=>path.StartsWith(f.TrimEnd('/')+"/",StringComparison.Ordinal)))throw new InvalidOperationException("Audit disabled or canary outside approved folders.");
        await AuditHealth.AssertLive();
        string Hash(){using var input=Native.FileAt(path,false);return Native.HashBounded(input,16*1024*1024);}
        var beforeHash=Hash();
        var baseline=AuditDispatcher.Read<AuditBridgeStatus>(AuditDispatcher.Root+"/status.json");
        Native.ValidateAdminPath("/usr/bin/cat",false);
        var start=new ProcessStartInfo("/usr/bin/cat"){UseShellExecute=false,RedirectStandardOutput=true,RedirectStandardError=true};start.ArgumentList.Add("--");start.ArgumentList.Add(path);
        var began=DateTimeOffset.UtcNow;
        using var child=Process.Start(start)??throw new IOException("Controlled read process did not start.");
        var pid=child.Id;
        using var deadline=new CancellationTokenSource(TimeSpan.FromSeconds(15));
        try{await child.StandardOutput.BaseStream.CopyToAsync(Stream.Null,deadline.Token);await child.WaitForExitAsync(deadline.Token);}
        catch(OperationCanceledException){if(!child.HasExited)child.Kill();throw new IOException("Own controlled read child exceeded timeout; validation failed.");}
        if(child.ExitCode!=0||Hash()!=beforeHash)throw new IOException("Controlled read failed or canary changed; validation failed.");
        var until=DateTimeOffset.UtcNow.AddSeconds(25);
        while(DateTimeOffset.UtcNow<until)
        {
            var status=AuditDispatcher.Read<AuditBridgeStatus>(AuditDispatcher.Root+"/status.json");
            if(AuditHealth.Failure(status) is {} failure)throw new IOException(failure);
            if(status.Epoch!=baseline.Epoch||status.InstanceId!=baseline.InstanceId||status.RelayPid!=baseline.RelayPid||status.RelayStartTicks!=baseline.RelayStartTicks||status.DroppedInputRecords!=baseline.DroppedInputRecords||status.RejectedRecords!=baseline.RejectedRecords)throw new IOException("Collector/relay restarted or evidence gap occurred during validation.");
            foreach(var file in AuditDispatcher.Files().Order(StringComparer.Ordinal).Where(f=>long.Parse(Path.GetFileName(f)[..20])>baseline.LastSequence).Take(4096))
            {
                var packet=AuditDispatcher.Read<AuditPacket>(file);var a=packet.Attribution;
                if(packet.Pid!=pid||packet.ObservedUtc<began.AddSeconds(-1)||packet.Executable!="/usr/bin/cat"||a.ParentProcessId!=Environment.ProcessId||a.UserId!=0||a.EffectiveUserId!=0||!a.EventTimeCredentials||a.Level!="Full attribution")continue;
                foreach(var target in packet.Paths.Where(p=>p.Path==path))
                {
                    if(status.UpdatedUtc<=baseline.UpdatedUtc||status.HeartbeatSequence<=baseline.HeartbeatSequence||status.InputBytes<=baseline.InputBytes||status.LastSequence<=baseline.LastSequence)continue;
                    var eventId=Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(packet.Identity+"|"+path+"|"+target.Role)).AsSpan(0,16)).ToLowerInvariant();
                    Console.WriteLine(JsonSerializer.Serialize(new{Result="PASS native collector attribution only",EventId=eventId,packet.Identity,packet.ObservedUtc,Pid=pid,a.ParentProcessId,a.UserId,a.EffectiveUserId,packet.Executable,a.Level,CanaryPath=path,PreservedSha256=beforeHash,status.DispatcherPid,status.RelayPid,status.HeartbeatSequence,status.LastSequence,ManagementAndWazuh="NOT VERIFIED; independently match EventId and actor fields at both destinations"}));return;
                }
            }
            await Task.Delay(500);
        }
        throw new IOException("No fresh full-attribution record for the controlled read; stale status or detection-only events are not a pass.");
    }
}
