using RansomFree.Contracts;
using System.Globalization;
using System.Security.Cryptography;
using System.Text.Json;
using Microsoft.Data.Sqlite;

namespace RansomFree.Client.Forensics;

// Receipt-only activation evidence. A saved map ID, successful pipe write, or
// ACK alone is not a live controller capability. The private owner retains the
// actual child/map/controller and must also pass its current in-memory barrier.
internal sealed partial class LinuxForensicJournal
{
    internal sealed record ActivationSample(int Version,string SampleId,string SourceSessionId,string ProviderEpoch,
        LinuxBpfLostMap.MapIdentity Map,string ReadySha256,string CommandSha256,int CommandBytes,
        string? Lost,string? Error,DateTimeOffset SampledUtc,
        [property:System.Text.Json.Serialization.JsonIgnore(Condition=System.Text.Json.Serialization.JsonIgnoreCondition.WhenWritingNull)] long? SampledMonotonic=null,
        [property:System.Text.Json.Serialization.JsonIgnore(Condition=System.Text.Json.Serialization.JsonIgnoreCondition.WhenWritingNull)] long? MonotonicFrequency=null);
    internal sealed record SourceActivation(ActivationSample Sample,LinuxOwnedLoaderProcess.PipeWrite? Write);
    private static void MigrateSourceActivation(SqliteConnection c,Action<string>? checkpoint)
    {
        using var t=c.BeginTransaction();Execute(c,t,"""
            CREATE TABLE source_activation(session_id TEXT PRIMARY KEY REFERENCES source_control(session_id),
              sample BLOB NOT NULL CHECK(typeof(sample)='blob' AND length(sample)<=4096),
              write_receipt BLOB CHECK(write_receipt IS NULL OR (typeof(write_receipt)='blob' AND length(write_receipt)<=4096)));
            PRAGMA user_version=11;
            """);checkpoint?.Invoke("activation-migration-before-commit");t.Commit();checkpoint?.Invoke("activation-migration-after-commit");
    }
    private static void ValidateActivationSample(string id,SourceControl control,ActivationSample sample)
    {
        var ready=LinuxControlledLoaderProtocol.ParseReady(control.Ready);var command=LinuxControlledLoaderProtocol.ActivationFrame(ready,id);
        if(sample.Version is not (1 or 2)||sample.Version==1&&(sample.SampledMonotonic!=null||sample.MonotonicFrequency!=null)||sample.Version==2&&(sample.SampledMonotonic is null or <=0||sample.MonotonicFrequency is null or <=0)||
            !Guid.TryParseExact(sample.SampleId,"N",out _)||sample.SourceSessionId!=id||
            sample.ProviderEpoch!=ready.Epoch.ToString(CultureInfo.InvariantCulture)||sample.SampledUtc==default||sample.Map==null||
            sample.Map!=new LinuxBpfLostMap.MapIdentity(2,ready.Maps[3],4,8,ready.ControlVersion is 3 or 4?6u:1u,0,ready.ControlVersion is 3 or 4?"op_health":"lost")||
            sample.ReadySha256!=Convert.ToHexString(SHA256.HashData(control.Ready))||sample.CommandSha256!=Convert.ToHexString(SHA256.HashData(command))||sample.CommandBytes!=command.Length||
            (sample.Lost==null?string.IsNullOrWhiteSpace(sample.Error)||sample.Error.Length>256:!Counter(sample.Lost)||sample.Error!=null))
            throw new InvalidDataException("Preactivation sample differs from linked source, map or exact command");
    }
    private static void ValidateActivationWrite(ActivationSample sample,LinuxOwnedLoaderProcess.PipeWrite write)
    {
        if(sample.Version==2&&(write.CommandSha256!=sample.CommandSha256||write.AttemptedMonotonic is null or <=0||
            write.ReturnedMonotonic is null or <=0||write.AttemptedMonotonic<sample.SampledMonotonic||write.ReturnedMonotonic<write.AttemptedMonotonic||write.MonotonicFrequency!=sample.MonotonicFrequency))
            throw new InvalidDataException("Actual activation buffer digest or monotonic call order differs from prewrite sample");
        if(write.AttemptedUtc==default||write.ReturnedUtc==default||write.Requested!=sample.CommandBytes||write.Written< -1||write.Written>write.Requested||
            (write.Written<0?write.WriteError<=0:write.WriteError!=0)||
            (write.CloseFailure==null?write.CloseResult is not (0 or -1)||(write.CloseResult==0?write.CloseError!=0:write.CloseError is null or <=0):
                string.IsNullOrWhiteSpace(write.CloseFailure)||write.CloseFailure.Length>256||write.CloseResult!=null||write.CloseError!=null))
            throw new InvalidDataException("Invalid bounded single-write/EOF receipt");
    }
    internal SourceActivation? ReadSourceActivation(string id)
    {lock(gate){using var c=Open();return ReadSourceActivation(c,id);}}
    private SourceActivation? ReadSourceActivation(SqliteConnection c,string id,SourceControl? knownControl=null)
    {
            using var q=Command(c,null,"SELECT sample,write_receipt FROM source_activation WHERE session_id=$id",("$id",id));using var r=q.ExecuteReader();
            if(!r.Read())return null;
            var sample=JsonSerializer.Deserialize<ActivationSample>((byte[])r[0])??throw new InvalidDataException("Activation sample missing");
            var write=r.IsDBNull(1)?null:JsonSerializer.Deserialize<LinuxOwnedLoaderProcess.PipeWrite>((byte[])r[1])??throw new InvalidDataException("Activation write receipt missing");
            var control=knownControl??ReadSourceControl(c,id)??throw new InvalidDataException("Activation linkage missing");ValidateActivationSample(id,control,sample);
            if(write!=null){if(control.WriteStartedUtc==null)throw new InvalidDataException("Write receipt without durable write intent");ValidateActivationWrite(sample,write);}
            return new(sample,write);
    }
    // One fresh connection for health evidence; no readiness or receipt cache.
    // Reuse exactly the existing linkage, activation and write validators.
    internal (SourceControl? Control,bool ActivationWriteConfirmed) ReadSourceHealthControl(string id)
    {
        lock(gate)
        {
            using var c=Open();var control=ReadSourceControl(c,id);
            var receipt=ReadSourceActivation(c,id,control);
            if(receipt==null)return (control,false);
            RequireActivationSample(control!,receipt.Sample);
            return (control,ActivationWriteConfirmed(receipt));
        }
    }
    internal void CommitSourceActivationSample(string id,ActivationSample sample)
    {
        lock(gate)
        {
            var control=ReadSourceControl(id)??throw new InvalidOperationException("Linked source required");ValidateActivationSample(id,control,sample);
            var bytes=JsonSerializer.SerializeToUtf8Bytes(sample);if(bytes.Length>4096)throw new InvalidDataException("Activation sample too large");
            var prior=ReadSourceActivation(id);
            if(prior!=null)
            {
                if(!JsonSerializer.SerializeToUtf8Bytes(prior.Sample).AsSpan().SequenceEqual(bytes))throw new InvalidDataException("First preactivation sample cannot be replaced");return;
            }
            if(ReadSource(id).State!="OPEN"||!IsControlledRawFormat(ReadSourceBankFormat(id))||ReadSourceOwnership(id)?.Phase!="LINKED_OWNER"||control.WriteStartedUtc!=null||control.Activated!=null||control.Completion!=null)
                throw new InvalidOperationException("Preactivation sample must precede the one write attempt");
            using var c=Open();using var t=c.BeginTransaction();Execute(c,t,"INSERT INTO source_activation(session_id,sample) VALUES($id,$sample)",("$id",id),("$sample",bytes));t.Commit();
        }
    }
    internal void RecordSourceActivationWrite(string id,LinuxOwnedLoaderProcess.PipeWrite write,Action<string>? checkpoint=null)
    {
        lock(gate)
        {
            var prior=ReadSourceActivation(id)??throw new InvalidOperationException("Original preactivation sample required");
            if(ReadSourceControl(id)?.WriteStartedUtc==null)throw new InvalidOperationException("Original durable write intent required");
            ValidateActivationWrite(prior.Sample,write);var bytes=JsonSerializer.SerializeToUtf8Bytes(write);
            if(bytes.Length>4096)throw new InvalidDataException("Activation write receipt too large");
            if(prior.Write!=null)
            {
                if(!JsonSerializer.SerializeToUtf8Bytes(prior.Write).AsSpan().SequenceEqual(bytes))throw new InvalidDataException("Original write receipt cannot be replaced");return;
            }
            // May finish after a concurrent fault: this records what returned,
            // without reopening the source or granting another write attempt.
            checkpoint?.Invoke("activation-write-before-transaction");
            using var c=Open();using var t=c.BeginTransaction();
            using(var q=Command(c,t,"UPDATE source_activation SET write_receipt=$write WHERE session_id=$id AND write_receipt IS NULL",("$id",id),("$write",bytes)))
                if(q.ExecuteNonQuery()!=1)
                {
                    using var priorBytes=Command(c,t,"SELECT write_receipt FROM source_activation WHERE session_id=$id",("$id",id));
                    if(priorBytes.ExecuteScalar() is not byte[] existing||!existing.AsSpan().SequenceEqual(bytes))throw new InvalidDataException("Activation receipt changed at transaction boundary; original must not be overwritten");
                }
            t.Commit();checkpoint?.Invoke("activation-write-committed");
        }
    }
    private void RequireActivationSample(string id)
    {
        var sample=ReadSourceActivation(id)?.Sample??throw new InvalidOperationException("Durable preactivation loss sample required before write");
        RequireActivationSample(ReadSourceControl(id)!,sample);
    }
    private static void RequireActivationSample(SourceControl control,ActivationSample sample)
    {
        var ready=LinuxControlledLoaderProtocol.ParseReady(control.Ready);
        if(sample.Version!=2||sample.Error!=null||sample.Lost!=ready.Lost.ToString(CultureInfo.InvariantCulture))throw new InvalidDataException("Current activation proof requires unchanged loss and monotonic sample evidence");
    }
    internal bool SourceActivationWriteConfirmed(string id)
    {
        var receipt=ReadSourceActivation(id);if(receipt==null)return false;
        RequireActivationSample(id);
        return ActivationWriteConfirmed(receipt);
    }
    private static bool ActivationWriteConfirmed(SourceActivation receipt)
        =>receipt.Write is {} write&&write.Written==write.Requested&&write.WriteError==0&&write.CloseResult==0&&write.CloseError==0&&write.CloseFailure==null;
}
