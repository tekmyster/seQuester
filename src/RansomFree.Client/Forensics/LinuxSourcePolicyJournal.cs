using System.Globalization;
using System.Security.Cryptography;
using Microsoft.Data.Sqlite;
using RansomFree.Contracts;

namespace RansomFree.Client.Forensics;

// Logical source lifecycle is retained for legacy format2 sources. This
// separate ownership phase states whether native opening was even attempted;
// OPEN in source_lifecycle alone never establishes an actual native owner.
internal sealed partial class LinuxForensicJournal
{
    internal sealed record SourcePolicy(int CodecVersion,ForensicPolicy Policy,string Sha256,DateTimeOffset RecordedUtc);
    internal sealed record SourceOwnership(string Phase,DateTimeOffset RecordedUtc);
    private static void MigrateSourcePolicy(SqliteConnection c,Action<string>? checkpoint)
    {
        using var t=c.BeginTransaction();Execute(c,t,"""
            CREATE TABLE source_bank_formats(bank_id TEXT PRIMARY KEY REFERENCES source_banks(bank_id),
              format TEXT NOT NULL CHECK(format IN ('raw-reserve-v2','raw-ingress-v3')));
            INSERT INTO source_bank_formats SELECT bank_id,'raw-reserve-v2' FROM source_banks;
            CREATE TABLE source_policy(session_id TEXT PRIMARY KEY REFERENCES source_lifecycle(session_id),
              codec_version INTEGER NOT NULL CHECK(codec_version=1),
              policy BLOB NOT NULL CHECK(typeof(policy)='blob' AND length(policy)<=4096),
              sha256 TEXT NOT NULL CHECK(length(sha256)=64),recorded_utc TEXT NOT NULL,
              UNIQUE(session_id,sha256));
            CREATE TABLE source_ownership(session_id TEXT PRIMARY KEY REFERENCES source_lifecycle(session_id),
              phase TEXT NOT NULL CHECK(phase IN ('PREPARED_NO_OWNER','OWNER_OPEN_ATTEMPTED','LINKED_OWNER','CLOSED')),
              recorded_utc TEXT NOT NULL);
            PRAGMA user_version=8;
            """);checkpoint?.Invoke("source-policy-migration-before-commit");t.Commit();checkpoint?.Invoke("source-policy-migration-after-commit");
    }
    private static string ReadSourceBankFormat(SqliteConnection c,SqliteTransaction? t,string bankId)
    {
        using var q=Command(c,t,"SELECT format FROM source_bank_formats WHERE bank_id=$id",("$id",bankId));
        return q.ExecuteScalar() as string??throw new InvalidDataException("Source bank format evidence missing");
    }
    internal string ReadSourceBankFormat(string sessionId)
    {lock(gate){var s=ReadSource(sessionId);using var c=Open();return ReadSourceBankFormat(c,null,s.BankId);}}
    private static void InsertPreparedSource(SqliteConnection c,SqliteTransaction t,string id,byte[] policy,DateTimeOffset time)
    {
        LinuxRawPolicyCodec.Decode(policy);
        Execute(c,t,"INSERT INTO source_policy VALUES($id,1,$policy,$hash,$time)",("$id",id),("$policy",policy),("$hash",Convert.ToHexString(SHA256.HashData(policy))),("$time",time.ToString("O")));
        Execute(c,t,"INSERT INTO source_ownership VALUES($id,'PREPARED_NO_OWNER',$time)",("$id",id),("$time",time.ToString("O")));
    }
    internal SourcePolicy? ReadSourcePolicy(string id)
    {
        lock(gate)
        {
            using var c=Open();using var q=Command(c,null,"SELECT codec_version,policy,sha256,recorded_utc FROM source_policy WHERE session_id=$id",("$id",id));using var r=q.ExecuteReader();
            if(!r.Read())return null;
            if(r.GetInt32(0)!=1||r[1] is not byte[] raw||raw.Length>4096||Convert.ToHexString(SHA256.HashData(raw))!=r.GetString(2))throw new InvalidDataException("POLICY_EVIDENCE_INVALID: exact frozen policy digest unavailable");
            var time=DateTimeOffset.Parse(r.GetString(3),CultureInfo.InvariantCulture);if(time==default)throw new InvalidDataException("Frozen source policy timestamp missing");
            return new(1,LinuxRawPolicyCodec.Decode(raw),r.GetString(2),time);
        }
    }
    internal SourceOwnership? ReadSourceOwnership(string id)
    {
        lock(gate)
        {
            using var c=Open();using var q=Command(c,null,"SELECT phase,recorded_utc FROM source_ownership WHERE session_id=$id",("$id",id));using var r=q.ExecuteReader();
            if(!r.Read())return null;
            var phase=r.GetString(0);var time=DateTimeOffset.Parse(r.GetString(1),CultureInfo.InvariantCulture);
            if(phase is not ("PREPARED_NO_OWNER" or "OWNER_OPEN_ATTEMPTED" or "LINKED_OWNER" or "CLOSED")||time==default)throw new InvalidDataException("Controlled source ownership phase invalid");return new(phase,time);
        }
    }
    // Durable one-use marker only. The owned runtime must commit this before
    // its actual open and then retain the returned descriptor. This grants no
    // native authority by itself and never retries an interrupted open.
    internal void RecordSourceOwnerOpenAttempt(string id,DateTimeOffset time)
    {
        if(time==default)throw new ArgumentException("Actual open-attempt time required");
        lock(gate)
        {
            if(ReadSource(id).State!="OPEN"||!IsControlledRawFormat(ReadSourceBankFormat(id))||ReadSourceOwnership(id)?.Phase!="PREPARED_NO_OWNER")throw new InvalidOperationException("Controlled open unavailable or already attempted");
            if(ReadSourcePolicy(id)==null)throw new InvalidDataException("POLICY_EVIDENCE_MISSING: no opening without frozen policy");
            using var c=Open();using var t=c.BeginTransaction();Execute(c,t,"UPDATE source_ownership SET phase='OWNER_OPEN_ATTEMPTED',recorded_utc=$time WHERE session_id=$id",("$id",id),("$time",time.ToString("O")));t.Commit();
        }
    }
    private void RequireControlledLinkReady(string id)
    {
        if(ReadSourceBankFormat(id)=="raw-reserve-v2")return;
        if(ReadSourceOwnership(id)?.Phase!="OWNER_OPEN_ATTEMPTED")throw new InvalidOperationException("Owned controller opening must precede controlled linkage");
        if(ReadOwnerMethodReturn(id,"OPEN")?.Outcome!="returned")throw new InvalidOperationException("Exact successful owned controller opening return required before linkage");
        if(ReadSourcePolicy(id)==null)throw new InvalidDataException("POLICY_EVIDENCE_MISSING: controlled linkage unavailable");
    }
    private static void RecordControlledLinked(SqliteConnection c,SqliteTransaction t,string id,DateTimeOffset time)
        =>Execute(c,t,"UPDATE source_ownership SET phase='LINKED_OWNER',recorded_utc=$time WHERE session_id=$id AND phase='OWNER_OPEN_ATTEMPTED'",("$id",id),("$time",time.ToString("O")));
    private void RequireControlledActivationReady(string id)
    {
        if(ReadSourceBankFormat(id)=="raw-reserve-v2")return;
        if(ReadSourceOwnership(id)?.Phase!="LINKED_OWNER"||ReadSourcePolicy(id)==null)throw new InvalidDataException("Controlled activation requires linked ownership and exact frozen policy");
        RequireActivationSample(id);
    }
}
