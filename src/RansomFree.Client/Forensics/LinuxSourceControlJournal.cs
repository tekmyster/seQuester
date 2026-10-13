using RansomFree.Contracts;
using System.Globalization;
using Microsoft.Data.Sqlite;

namespace RansomFree.Client.Forensics;

// Durable control-plane evidence. Recording a link or attempted write does not
// prove observer attachment, delivery continuity or a historical native close.
internal sealed partial class LinuxForensicJournal
{
    internal sealed record SourceControl(byte[] Ready,DateTimeOffset LinkedUtc,DateTimeOffset? WriteStartedUtc,byte[]? Activated,byte[]? Completion);
    private static void MigrateSourceControl(SqliteConnection c,Action<string>? checkpoint)
    {
        using var t=c.BeginTransaction();Execute(c,t,"""
            CREATE TABLE source_control(session_id TEXT PRIMARY KEY REFERENCES source_lifecycle(session_id),
              ready BLOB NOT NULL CHECK(length(ready)<=4096),linked_utc TEXT NOT NULL,write_started_utc TEXT,
              activated BLOB CHECK(length(activated)<=4096),completion BLOB CHECK(length(completion)<=4096));
            PRAGMA user_version=6;
            """);checkpoint?.Invoke("control-migration-before-commit");t.Commit();checkpoint?.Invoke("control-migration-after-commit");
    }
    internal SourceControl? ReadSourceControl(string id)
    {lock(gate){using var c=Open();return ReadSourceControl(c,id);}}
    private SourceControl? ReadSourceControl(SqliteConnection c,string id)
    {
            using var q=Command(c,null,"SELECT ready,linked_utc,write_started_utc,activated,completion FROM source_control WHERE session_id=$id",("$id",id));using var r=q.ExecuteReader();
            if(!r.Read())return null;
            var result=new SourceControl((byte[])r[0],DateTimeOffset.Parse(r.GetString(1),CultureInfo.InvariantCulture),r.IsDBNull(2)?null:DateTimeOffset.Parse(r.GetString(2),CultureInfo.InvariantCulture),r.IsDBNull(3)?null:(byte[])r[3],r.IsDBNull(4)?null:(byte[])r[4]);
            var ready=LinuxControlledLoaderProtocol.ParseReady(result.Ready);
            var source=ReadSource(c,id);
            if(ready.Epoch.ToString(CultureInfo.InvariantCulture)!=source.ProviderEpoch||ready.Lost.ToString(CultureInfo.InvariantCulture)!=source.LostAtOpen||result.LinkedUtc==default||result.WriteStartedUtc==default(DateTimeOffset))throw new InvalidDataException("Controlled source linkage corrupted");
            if(result.Activated!=null){if(result.WriteStartedUtc==null)throw new InvalidDataException("Activation acknowledgment without attempted write");LinuxControlledLoaderProtocol.ParseActivated(result.Activated,ready,id);}
            if(result.Completion!=null)
            {
                var completed=LinuxControlledLoaderProtocol.ParseCompletion(result.Completion,ready.ControlVersion);
                if(completed.ObserverAttempted&&result.WriteStartedUtc==null||result.Activated!=null&&!completed.Activated)throw new InvalidDataException("Controlled completion contradicts persisted activation evidence");
            }
            return result;
    }
    internal void CommitSourceControlLink(string id,ReadOnlyMemory<byte> raw,DateTimeOffset linkedUtc)
    {
        var ready=LinuxControlledLoaderProtocol.ParseReady(raw);
        if(linkedUtc==default)throw new ArgumentException("Actual link time required");
        lock(gate)
        {
            var source=ReadSource(id);
            if(source.State!="OPEN"||source.ProviderEpoch!=ready.Epoch.ToString(CultureInfo.InvariantCulture)||source.LostAtOpen!=ready.Lost.ToString(CultureInfo.InvariantCulture))throw new InvalidDataException("Controlled ready does not belong to this open source");
            RequireControlledLinkReady(id);
            if(ReadSourceControl(id)!=null)throw new InvalidOperationException("Controlled source already linked; activation cannot be silently replayed");
            using var c=Open();using var t=c.BeginTransaction();
            Execute(c,t,"INSERT INTO source_control(session_id,ready,linked_utc) VALUES($id,$raw,$time)",("$id",id),("$raw",raw.ToArray()),("$time",linkedUtc.ToString("O")));
            RecordControlledLinked(c,t,id,linkedUtc);t.Commit();
        }
    }
    internal void MarkSourceControlWriteStarted(string id,DateTimeOffset startedUtc)
    {
        if(startedUtc==default)throw new ArgumentException("Actual attempted-write time required");
        lock(gate)
        {
            var source=ReadSource(id);var prior=ReadSourceControl(id)??throw new InvalidOperationException("Durable source link required before activation write");
            RequireControlledActivationReady(id);
            if(source.State!="OPEN"||prior.WriteStartedUtc!=null||prior.Completion!=null)throw new InvalidOperationException("Activation write unavailable or already attempted; no automatic retry");
            using var c=Open();using var t=c.BeginTransaction();
            Execute(c,t,"UPDATE source_control SET write_started_utc=$time WHERE session_id=$id",("$time",startedUtc.ToString("O")),("$id",id));t.Commit();
        }
    }
    internal void RecordSourceControlActivated(string id,ReadOnlyMemory<byte> raw)
    {
        lock(gate)
        {
            var source=ReadSource(id);var prior=ReadSourceControl(id)??throw new InvalidOperationException("Controlled source linkage missing");
            if(prior.WriteStartedUtc==null||prior.Completion!=null||source.State is "CLOSED" or "CLOSE_UNKNOWN_OPEN")throw new InvalidOperationException("Activation acknowledgment cannot authorize a new or closed source");
            LinuxControlledLoaderProtocol.ParseActivated(raw,LinuxControlledLoaderProtocol.ParseReady(prior.Ready),id);
            if(prior.Activated!=null){if(!raw.Span.SequenceEqual(prior.Activated))throw new InvalidDataException("Activation acknowledgment changed");return;}
            using var c=Open();using var t=c.BeginTransaction();Execute(c,t,"UPDATE source_control SET activated=$raw WHERE session_id=$id",("$raw",raw.ToArray()),("$id",id));t.Commit();
        }
    }
    internal void RecordSourceControlCompletion(string id,ReadOnlyMemory<byte> raw)
    {
        lock(gate)
        {
            var prior=ReadSourceControl(id)??throw new InvalidOperationException("Controlled source linkage missing");
            var complete=LinuxControlledLoaderProtocol.ParseCompletion(raw,LinuxControlledLoaderProtocol.ParseReady(prior.Ready).ControlVersion);
            if(complete.ObserverAttempted&&prior.WriteStartedUtc==null)throw new InvalidDataException("Observer attempted before linked source activation write");
            // A missing success acknowledgment can coexist with an activated
            // final frame. Keep the two observations separate, never synthesize it.
            if(prior.Activated!=null&&!complete.Activated)throw new InvalidDataException("Completion contradicts activation acknowledgment");
            if(prior.Completion!=null){if(!raw.Span.SequenceEqual(prior.Completion))throw new InvalidDataException("Controlled completion changed");return;}
            using var c=Open();using var t=c.BeginTransaction();Execute(c,t,"UPDATE source_control SET completion=$raw WHERE session_id=$id",("$raw",raw.ToArray()),("$id",id));t.Commit();
        }
    }
}
