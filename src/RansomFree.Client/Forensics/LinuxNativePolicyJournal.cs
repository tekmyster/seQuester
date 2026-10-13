using System.Security.Cryptography;
using System.Text.Json;
using RansomFree.Contracts;

namespace RansomFree.Client.Forensics;

// Optional versioned component inside the existing root intake journal. This
// retains anti-rollback state only; rows never recreate a live challenge/owner.
internal sealed partial class LinuxForensicJournal
{
    private object? nativePolicyOwner;
    internal object AcquireNativePolicyOwner(string server,string keyId)
    {
        lock(gate)
        {
            ObjectDisposedException.ThrowIf(disposed,this);
            if(nativePolicyOwner!=null)throw new InvalidOperationException("Root policy admission already has an owner");
            ConfigureNativePolicy(server,keyId);
            return nativePolicyOwner=new object();
        }
    }
    internal void ReleaseNativePolicyOwner(object lease)
    {
        lock(gate)
        {
            ObjectDisposedException.ThrowIf(disposed,this);
            if(!ReferenceEquals(lease,nativePolicyOwner))throw new InvalidOperationException("Root policy admission owner differs");
            using var c=Open();
            if(runtimeOwner||admissionChecking||activeNativePins.Count!=0||privateWork.Count!=0||stoppedRecoveries.Count!=0||
                Scalar(c,null,"SELECT COUNT(*) FROM source_lifecycle WHERE state<>'CLOSED'")!=0)
                throw new InvalidOperationException("Root policy owner must remain through actual source close and recovery");
            nativePolicyOwner=null;
        }
    }
    internal void ConfigureNativePolicy(string server,string keyId)
    {
        if(!NativePolicySnapshot.ValidOrigin(server)||keyId.Length!=64||!keyId.All(Uri.IsHexDigit))throw new ArgumentException("Invalid root policy pin");
        lock(gate)
        {
            using var c=Open();using var t=c.BeginTransaction();
            Execute(c,t,"""
                CREATE TABLE IF NOT EXISTS native_policy_pin(id INTEGER PRIMARY KEY CHECK(id=1),version INTEGER NOT NULL,
                  server TEXT NOT NULL,key_id TEXT NOT NULL);
                CREATE TABLE IF NOT EXISTS native_policy_current(id INTEGER PRIMARY KEY CHECK(id=1),sequence INTEGER NOT NULL,
                  challenge TEXT NOT NULL,trust_revision INTEGER NOT NULL,trust_digest TEXT NOT NULL,issued_ticks INTEGER NOT NULL,
                  envelope BLOB NOT NULL CHECK(length(envelope)<=710000),envelope_sha256 TEXT NOT NULL);
                CREATE TABLE IF NOT EXISTS native_policy_monitoring(group_id TEXT PRIMARY KEY,revision INTEGER NOT NULL,digest TEXT NOT NULL);
                """);
            using(var q=Command(c,t,"SELECT version,server,key_id FROM native_policy_pin WHERE id=1"))
            using(var r=q.ExecuteReader())
            {
                if(r.Read())
                {if(r.GetInt32(0)!=1||r.GetString(1)!=server||r.GetString(2)!=keyId)throw new InvalidDataException("Root native policy pin changed; explicit migration required");t.Commit();return;}
            }
            if(Scalar(c,t,"SELECT COUNT(*) FROM native_policy_current")!=0||Scalar(c,t,"SELECT COUNT(*) FROM native_policy_monitoring")!=0)
                throw new InvalidDataException("Root policy pin missing from existing history");
            Execute(c,t,"INSERT INTO native_policy_pin VALUES(1,1,$server,$key)",("$server",server),("$key",keyId));t.Commit();
        }
    }
    internal void CommitNativePolicy(SignedNativePolicy envelope,NativePolicySnapshot snapshot,Action<string>? checkpoint=null)
    {
        var bytes=JsonSerializer.SerializeToUtf8Bytes(envelope);if(bytes.Length>710000)throw new InvalidDataException("Root policy envelope exceeds journal bound");
        var digest=Convert.ToHexString(SHA256.HashData(bytes));var group=snapshot.Monitoring.GroupId??"";
        var monitorDigest=Convert.ToHexString(SHA256.HashData(JsonSerializer.SerializeToUtf8Bytes(snapshot.Monitoring)));
        if(snapshot.SensorId!=sensor)throw new InvalidDataException("Root policy belongs to another sensor");
        lock(gate)
        {
            CheckQuota(bytes.Length*2L+65536);using var c=Open();using var t=c.BeginTransaction();
            using(var q=Command(c,t,"SELECT server,key_id FROM native_policy_pin WHERE id=1"))using(var r=q.ExecuteReader())
                if(!r.Read()||r.GetString(0)!=snapshot.Server||r.GetString(1)!=envelope.KeyId)throw new InvalidDataException("Root policy pin not established");
            long sequence=0;
            using(var q=Command(c,t,"SELECT sequence,challenge,trust_revision,trust_digest,issued_ticks FROM native_policy_current WHERE id=1"))using(var r=q.ExecuteReader())
            {
                if(r.Read())
                {
                    sequence=r.GetInt64(0);
                    if(sequence<1||r.GetString(1)==snapshot.Challenge||snapshot.Trust.Policy.Revision<r.GetInt64(2)||
                        snapshot.Trust.Policy.Revision==r.GetInt64(2)&&snapshot.Trust.Digest!=r.GetString(3)||snapshot.IssuedUtc.UtcTicks<r.GetInt64(4))
                        throw new InvalidDataException("Root policy challenge consumed or trust history regressed/conflicted");
                }
            }
            bool knownGroup;
            using(var q=Command(c,t,"SELECT revision,digest FROM native_policy_monitoring WHERE group_id=$group",("$group",group)))using(var r=q.ExecuteReader())
            {
                knownGroup=r.Read();if(knownGroup&&(snapshot.Monitoring.Revision<r.GetInt64(0)||snapshot.Monitoring.Revision==r.GetInt64(0)&&monitorDigest!=r.GetString(1)))
                    throw new InvalidDataException("Root monitoring policy regressed/conflicted within its group");
            }
            if(!knownGroup&&Scalar(c,t,"SELECT COUNT(*) FROM native_policy_monitoring")>=1024)throw new IOException("Root policy group-history bound reached; retained");
            Execute(c,t,"INSERT INTO native_policy_monitoring VALUES($group,$revision,$digest) ON CONFLICT(group_id) DO UPDATE SET revision=excluded.revision,digest=excluded.digest",
                ("$group",group),("$revision",snapshot.Monitoring.Revision),("$digest",monitorDigest));
            Execute(c,t,"""
                INSERT INTO native_policy_current VALUES(1,$sequence,$challenge,$revision,$digest,$issued,$envelope,$sha)
                  ON CONFLICT(id) DO UPDATE SET sequence=excluded.sequence,challenge=excluded.challenge,trust_revision=excluded.trust_revision,
                    trust_digest=excluded.trust_digest,issued_ticks=excluded.issued_ticks,envelope=excluded.envelope,envelope_sha256=excluded.envelope_sha256
                """,("$sequence",checked(sequence+1)),("$challenge",snapshot.Challenge),("$revision",snapshot.Trust.Policy.Revision),
                ("$digest",snapshot.Trust.Digest),("$issued",snapshot.IssuedUtc.UtcTicks),("$envelope",bytes),("$sha",digest));
            checkpoint?.Invoke("native-policy-before-commit");t.Commit();checkpoint?.Invoke("native-policy-after-commit");
        }
    }
}
