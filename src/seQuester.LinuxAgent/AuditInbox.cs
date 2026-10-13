using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using RansomFree.Contracts;

namespace RansomFree.LinuxAgent;

// Root auditd owns the bounded inbox; endpoint can read it but cannot forge records.
// Advance a private cursor only after every matching event is in the management outbox.
internal sealed class AuditInbox(PrivateState state,bool enabled)
{
    sealed record Cursor(string Epoch,long Sequence,long Drops,long Rejected);
    Cursor? cursor=state.Read<Cursor>("audit-cursor.json");
    sealed record RejectedPacket(string Epoch,long Sequence,string Reason,DateTimeOffset RecordedUtc,string OriginalBase64);
    readonly AuditHeartbeatVerifier verifier=new();
    public string Status {get;private set;}=enabled?"Audit connection not verified":"Audit disabled";
    public DateTimeOffset? LastVerifiedUtc {get;private set;}
    static string EventId(string value)=>Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(value)).AsSpan(0,16)).ToLowerInvariant();
    public void Poll(IEnumerable<Canary> canaries,Func<Observation,bool> record)
    {
        if(!enabled)return;
        try
        {
            Native.ValidateAdminPath(AuditDispatcher.Root,true);
            var bridge=AuditDispatcher.Read<AuditBridgeStatus>(AuditDispatcher.Root+"/status.json");
            if(!Guid.TryParseExact(bridge.Epoch,"N",out _)||bridge.LastSequence<0||bridge.FirstSequence<1||bridge.DroppedInputRecords<0||bridge.RejectedRecords<0)throw new InvalidDataException("Invalid bridge status.");
            Status=verifier.Evaluate(new(bridge.UpdatedUtc,bridge.Running,bridge.BootId??"",bridge.InstanceId??"",bridge.DispatcherPid,bridge.DispatcherStartTicks??"",bridge.HeartbeatSequence,bridge.CollectorHealth),AuditHealth.BootId(),DateTimeOffset.UtcNow);
            if(EndpointHealthSummary.AuditReady(Status))LastVerifiedUtc=bridge.UpdatedUtc;
            var next=cursor??new Cursor(bridge.Epoch,0,0,0);
            if(next.Epoch!=bridge.Epoch)
            {
                if(!record(new("Audit sensor","Audit inbox identity changed; prior coverage cannot be established","Linux monitor health")))return;
                next=new(bridge.Epoch,0,0,0);
            }
            if(next.Sequence<bridge.FirstSequence-1||next.Drops!=bridge.DroppedInputRecords||next.Rejected!=bridge.RejectedRecords)
            {
                if(!record(new("Audit sensor",$"Audit continuity warning: unread inbox range or parser/input boundary; cumulative input drops {bridge.DroppedInputRecords}, parser rejections/resets {bridge.RejectedRecords}. Counts are not file accesses; inspect collector history.","Linux monitor health")))return;
                next=next with{Sequence=Math.Max(next.Sequence,bridge.FirstSequence-1),Drops=bridge.DroppedInputRecords,Rejected=bridge.RejectedRecords};
                state.Save("audit-cursor.json",next);cursor=next;
            }
            var targets=canaries.Where(x=>x.Active).Select(x=>x.Path).ToHashSet(StringComparer.Ordinal);
            var files=AuditDispatcher.Files().Take(16385).ToArray();if(files.Length>16384)throw new IOException("Audit inbox exceeds inventory limit.");
            foreach(var file in files.Order(StringComparer.Ordinal).Where(f=>long.Parse(Path.GetFileName(f)[..20])>next.Sequence).Take(128))
            {
                var sequence=long.Parse(Path.GetFileName(file)[..20]);
                if(sequence!=next.Sequence+1)
                {
                    if(!record(new("Audit sensor","Audit inbox sequence gap; event evidence may be missing","Linux monitor health")))return;
                }
                var raw=AuditDispatcher.ReadBytes(file);
                AuditPacket packet;
                try{packet=AuditPacketEvidence.Normalize(JsonSerializer.Deserialize<AuditPacket>(raw,PrivateState.Json)??throw new InvalidDataException("Empty audit packet."));}
                catch(Exception ex) when(ex is JsonException or InvalidDataException)
                {
                    var quarantineName=$"audit-quarantine-{bridge.Epoch}-{sequence:D20}.json";
                    var retained=state.Read<RejectedPacket>(quarantineName);var original=Convert.ToBase64String(raw);
                    if(retained!=null){if(retained.OriginalBase64!=original)throw new IOException("Audit packet identity changed after quarantine; cursor retained.");}
                    else{
                        var quarantined=Directory.EnumerateFiles(state.Directory,"audit-quarantine-*.json").Select(p=>new FileInfo(p)).ToArray();
                        if(quarantined.Length>=1024||quarantined.Sum(p=>p.Length)+raw.Length*2L>64*1024*1024)throw new IOException("Audit quarantine capacity reached; source evidence and cursor retained.");
                        state.Save(quarantineName,new RejectedPacket(bridge.Epoch,sequence,ex.GetType().Name,DateTimeOffset.UtcNow,original));
                    }
                    if(!record(new("Audit sensor","Malformed audit packet retained in local quarantine; later packets can continue","Linux monitor health"){EventId=EventId(bridge.Epoch+"|quarantine|"+sequence)}))return;
                    next=next with{Sequence=sequence};state.Save("audit-cursor.json",next);cursor=next;continue;
                }
                if(packet.Paths.Length==0)
                {
                    var a=packet.Attribution;
                    var observation=new Observation("Kernel audit: target path unavailable",$"Audit {packet.Operation} ({a.Outcome}); target path unavailable; raw evidence retained","Linux Audit",packet.Pid,Executable:packet.Executable,User:AuditPacketEvidence.User(a))
                    {ObservedUtc=packet.ObservedUtc.UtcDateTime,EventId=EventId(packet.Identity+"|target-unavailable"),Attribution=a};
                    if(!record(observation)){Status="Audit forwarding paused; management queue unavailable";return;}
                }
                foreach(var path in packet.Paths)
                {
                    if(!targets.Contains(path.Path))continue;
                    var a=packet.Attribution with{PathRole=path.Role,TargetStableId=path.StableId};
                    var user=AuditPacketEvidence.User(a);
                    var intent=packet.Operation is "open" or "openat" or "openat2"?"; access intent, not read/copy proof":"";
                    var observation=new Observation(path.Path,$"Audit {packet.Operation} ({a.Outcome}{intent})","Linux Audit",packet.Pid,Executable:packet.Executable,User:user)
                    {ObservedUtc=packet.ObservedUtc.UtcDateTime,EventId=EventId(packet.Identity+"|"+path.Path+"|"+path.Role),Attribution=a};
                    if(!record(observation)){Status="Audit forwarding paused; management queue unavailable";return;}
                }
                next=next with{Sequence=sequence};state.Save("audit-cursor.json",next);cursor=next;
            }
        }
        catch(Exception ex){Status="Audit unavailable: "+ex.GetType().Name+"; partial attribution";}
    }
}
