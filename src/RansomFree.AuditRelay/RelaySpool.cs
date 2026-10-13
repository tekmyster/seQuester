using System.Runtime.InteropServices;
using System.Text.Json;
using System.Text.Json.Serialization;
using RansomFree.LinuxAgent;

namespace RansomFree.AuditRelay;

[JsonSerializable(typeof(Dictionary<Guid,long>))]
internal partial class RelayLossJsonContext:JsonSerializerContext {}

// One durable owner for stdin bytes until the collector acknowledges raw
// persistence. No parser, actor enrichment, response or external network.
[System.Runtime.Versioning.SupportedOSPlatform("linux")]
internal sealed class RelaySpool:IDisposable
{
    const string Root="/var/lib/sequester-audit/relay-spool-v2";
    readonly AuditReplayJournal journal;
    readonly object gate=new();
    readonly Dictionary<Guid,long> losses;
    bool disposed;
    [DllImport("libc",SetLastError=true)] static extern int fsync(int fd);
    public RelaySpool()
    {
        journal=new(Root,(p,d)=>Native.ValidateAdminPath(p,d));
        try
        {
            var path=Root+"/losses.json";
            if(File.Exists(path))
            {
                Native.ValidateAdminPath(path,false);if(new FileInfo(path).Length>131072)throw new InvalidDataException("Relay loss state exceeds its bound.");
                losses=JsonSerializer.Deserialize(File.ReadAllBytes(path),RelayLossJsonContext.Default.DictionaryGuidInt64)??throw new InvalidDataException("Missing relay loss state.");
            }
            else losses=[];
            if(losses.Count>256||losses.Any(x=>x.Key==Guid.Empty||x.Value<=0))throw new InvalidDataException("Invalid retained relay loss state.");
            var interrupted=Directory.EnumerateFiles(Root,"*.loss.tmp").Take(257).ToArray();
            if(interrupted.Length>256)throw new IOException("Interrupted relay loss inventory exceeds its bound; evidence retained.");
            foreach(var temporary in interrupted)
            {
                Native.ValidateAdminPath(temporary,false);if(new FileInfo(temporary).Length>131072)throw new InvalidDataException("Interrupted relay loss state exceeds its bound.");
                var pending=JsonSerializer.Deserialize(File.ReadAllBytes(temporary),RelayLossJsonContext.Default.DictionaryGuidInt64)??throw new InvalidDataException("Missing interrupted relay loss state.");
                foreach(var pair in pending)
                {
                    if(pair.Key==Guid.Empty||pair.Value<=0)throw new InvalidDataException("Invalid interrupted relay loss counter.");
                    losses[pair.Key]=Math.Max(losses.GetValueOrDefault(pair.Key),pair.Value);
                }
                if(losses.Count>256)throw new IOException("Interrupted relay loss-instance capacity exhausted; state retained.");
            }
            if(interrupted.Length>0)
            {
                SaveLosses();
                foreach(var temporary in interrupted)File.Delete(temporary);
                SyncDirectory();
            }
        }
        catch{journal.Dispose();throw;}
    }
    void SaveLosses()
    {
        var path=Root+"/losses.json";var temporary=Root+"/"+Guid.NewGuid().ToString("N")+".loss.tmp";
        using(var file=new FileStream(temporary,new FileStreamOptions{Mode=FileMode.CreateNew,Access=FileAccess.Write,Share=FileShare.None,UnixCreateMode=UnixFileMode.UserRead|UnixFileMode.UserWrite}))
        {JsonSerializer.Serialize(file,losses,RelayLossJsonContext.Default.DictionaryGuidInt64);file.Flush(true);}
        if(File.Exists(path))Native.ValidateAdminPath(path,false);File.Move(temporary,path,true);
        SyncDirectory();
    }
    static void SyncDirectory(){var fd=Native.Check(Native.open(Root,0x10000|0x20000|0x80000));try{Native.Check(fsync(fd));}finally{Native.close(fd);}}
    public bool RecoverLosses()
    {
        lock(gate)
        {
            foreach(var pair in losses.ToArray())
            {
                if(pair.Value>journal.ReportedLoss(pair.Key))
                {
                    try{journal.Admit(new(pair.Key,journal.NextSequence(pair.Key),pair.Value,[]));}
                    catch(AuditReplayCapacityException){return false;}
                }
                losses.Remove(pair.Key);SaveLosses();
            }
            return true;
        }
    }
    public bool Admit(Guid instance,byte[] bytes)
    {
        lock(gate)
        {
            // Pending old-process loss boundaries must be durably admitted
            // before new stdin bytes, preserving their stream ordering.
            if(!RecoverLosses())return Drop(instance);
            try{journal.Admit(new(instance,journal.NextSequence(instance),journal.ReportedLoss(instance),bytes));return true;}
            catch(AuditReplayCapacityException){return Drop(instance);}
        }
    }
    bool Drop(Guid instance)
    {
        if(!losses.ContainsKey(instance)&&losses.Count>=256)throw new IOException("Relay loss-instance capacity exhausted; state retained.");
        losses[instance]=checked(Math.Max(losses.GetValueOrDefault(instance),journal.ReportedLoss(instance))+1);SaveLosses();return false;
    }
    public AuditReplayEntry? FirstPending(){lock(gate)return journal.FirstPending();}
    public bool HasPendingLosses {get{lock(gate)return losses.Count>0;}}
    public (long Frames,long Bytes,long UnreportedLosses) Status
    {
        get{lock(gate)return(journal.PendingCount,journal.PendingBytes,losses.Sum(x=>Math.Max(0,x.Value-journal.ReportedLoss(x.Key))));}
    }
    public void Acknowledge(AuditReplayEntry entry)
    {
        lock(gate)
        {
            var first=journal.FirstPending();
            if(first==null||first.Order!=entry.Order||first.Frame.RelayInstance!=entry.Frame.RelayInstance||first.Frame.Sequence!=entry.Frame.Sequence)throw new InvalidDataException("Relay acknowledgement does not own the oldest pending frame.");
            journal.RetireThrough(entry.Order);
        }
    }
    public void Dispose(){lock(gate){if(disposed)return;disposed=true;journal.Dispose();}}
}
