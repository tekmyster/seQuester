using System.Text.Json;
using Microsoft.Data.Sqlite;

namespace RansomFree.Client.Forensics;

// Latest native acquisition progress, not a completion or reconstructed I/O
// timeline. EXPIRED_DRAINING may still hold a source reference and write lease.
internal sealed partial class LinuxForensicJournal
{
    internal sealed record NativeProgress(LinuxActorLeaseStatus Status,string Disposition,DateTimeOffset ObservedUtc);
    private static void MigrateNativeProgress(SqliteConnection c,Action<string>? checkpoint)
    {
        using var t=c.BeginTransaction();Execute(c,t,"""
            CREATE TABLE native_progress(event_id TEXT PRIMARY KEY REFERENCES work(event_id),
              progress BLOB NOT NULL CHECK(length(progress)<=8192));
            PRAGMA user_version=5;
            """);checkpoint?.Invoke("native-progress-migration-before-commit");t.Commit();checkpoint?.Invoke("native-progress-migration-after-commit");
    }
    internal void RecordNativeProgress(string id,LinuxActorLeaseStatus status)
    {
        lock(gate)
        {
            if(!status.ToEvidence().Matches(Read(id).Observation.Attribution!.LinuxKernel!))throw new InvalidDataException("Native progress differs from raw operation identity");
            var disposition=LinuxNativeDisposition.Classify(status);var previous=ReadNativeProgress(id);
            if(previous?.Status==status&&previous.Disposition==disposition)return;
            var bytes=JsonSerializer.SerializeToUtf8Bytes(new NativeProgress(status,disposition,DateTimeOffset.UtcNow));
            if(bytes.Length>8192)throw new InvalidDataException("Native progress exceeds bound");
            using var c=Open();using var t=c.BeginTransaction();
            Execute(c,t,"INSERT INTO native_progress VALUES($id,$value) ON CONFLICT(event_id) DO UPDATE SET progress=excluded.progress",("$id",id),("$value",bytes));t.Commit();
        }
    }
    internal NativeProgress? ReadNativeProgress(string id)
    {
        lock(gate)
        {
            using var c=Open();using var q=Command(c,null,"SELECT progress FROM native_progress WHERE event_id=$id",("$id",id));var raw=q.ExecuteScalar();
            if(raw==null)return null;
            var value=JsonSerializer.Deserialize<NativeProgress>((byte[])raw)??throw new InvalidDataException("Native progress is null");
            if(value.Disposition!=LinuxNativeDisposition.Classify(value.Status)||!value.Status.ToEvidence().Matches(Read(id).Observation.Attribution!.LinuxKernel!)||value.ObservedUtc==default)
                throw new InvalidDataException("Native progress identity/state corrupted");return value;
        }
    }
}
internal static class LinuxNativeDisposition
{
    internal static string Classify(LinuxActorLeaseStatus status)
    {
        // ToEvidence validates exact ABI/ranges; Matches must additionally bind
        // the full tuple to the current session's canonical raw observation.
        status.ToEvidence();
        if(status.Ready)return "NATIVE_COMPLETE_READABLE";
        if(status.State==5)return "NATIVE_EXPIRED_DRAINING_UNRELEASED";
        if(status.State is 1 or 2 or 6)return "NATIVE_PENDING_UNRELEASED";
        var released=status.WriteLease==0&&status.StartedNs>0&&status.FinishedNs>=status.StartedNs&&status.DeadlineNs>status.StartedNs;
        if(status.State==4&&released&&status.Error<0)return "ACTOR_COPY_UNAVAILABLE_NATIVE_FAILED";
        if(status.State==3&&released)return "ACTOR_COPY_UNAVAILABLE_INVALID_NATIVE_STATUS";
        return "NATIVE_INVALID_STATUS_UNRELEASED";
    }
    internal static bool MayRelease(LinuxActorLeaseStatus status)=>Classify(status) is "NATIVE_COMPLETE_READABLE" or "ACTOR_COPY_UNAVAILABLE_NATIVE_FAILED" or "ACTOR_COPY_UNAVAILABLE_INVALID_NATIVE_STATUS";
}
