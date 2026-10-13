using RansomFree.Contracts;

namespace RansomFree.Server;

public sealed record TrustCapabilityStatus(string EndpointId,string Machine,string OperatingSystem,int PolicyVersion,int LinuxKernelTrustVersion,DateTimeOffset? ReportedUtc)
{public int LinuxNativeHashTrustVersion {get;init;} public DateTimeOffset? LinuxNativeHashReportedUtc {get;init;}}
public sealed class TrustCapabilityException(string code,string message):ArgumentException(message)
{ public string Code {get;}=code; }
public sealed partial class Store
{
    public const int LinuxTrustSourceMaximumAgeSeconds=120;
    public void InitializeTrustCapabilities()
    {
        if(sqlServer){RansomFree.Persistence.SqlServerSchema.Require(connectionString,"trust-capabilities",1);return;}
        using var c=Open();using var command=Command(c,null,"""
            CREATE TABLE IF NOT EXISTS trust_capabilities(endpoint TEXT PRIMARY KEY REFERENCES endpoints(id),
              policy_version INTEGER NOT NULL,kernel_trust_version INTEGER NOT NULL,os TEXT NOT NULL,reported INTEGER NOT NULL);
            """);command.ExecuteNonQuery();
    }
    public bool RecordTrustCapabilities(string endpoint,TrustCapabilitiesReport report)
    {
        if(!report.IsValid())throw new ArgumentException("Invalid trust capability report");
        InitializeTrustCapabilities();using var c=Open();using var transaction=c.BeginTransaction();
        using(var exists=Command(c,transaction,"SELECT COUNT(*) FROM endpoints WHERE id=$id AND revoked=0",("$id",endpoint)))
            if(Convert.ToInt64(exists.ExecuteScalar())!=1)return false;
        using(var update=Command(c,transaction,"UPDATE trust_capabilities SET policy_version=$policy,kernel_trust_version=$kernel,os=$os,reported=$now WHERE endpoint=$id",
            ("$id",endpoint),("$policy",report.PolicyVersion),("$kernel",report.LinuxKernelTrustVersion),("$os",report.OperatingSystem),("$now",Now())))
        if(update.ExecuteNonQuery()==0)
        {
            using var insert=Command(c,transaction,"INSERT INTO trust_capabilities(endpoint,policy_version,kernel_trust_version,os,reported) VALUES($id,$policy,$kernel,$os,$now)",
                ("$id",endpoint),("$policy",report.PolicyVersion),("$kernel",report.LinuxKernelTrustVersion),("$os",report.OperatingSystem),("$now",Now()));insert.ExecuteNonQuery();
        }
        transaction.Commit();return true;
    }
    private void InitializeNativeHashTrustCapabilities()
    {
        if(sqlServer){RansomFree.Persistence.SqlServerSchema.Require(connectionString,"trust-native-hash-capabilities",1);return;}
        using var c=Open();using var command=Command(c,null,"CREATE TABLE IF NOT EXISTS trust_native_hash_capabilities(endpoint TEXT PRIMARY KEY REFERENCES endpoints(id),version INTEGER NOT NULL,reported INTEGER NOT NULL)");command.ExecuteNonQuery();
    }
    public bool RecordNativeHashTrustCapabilities(string endpoint,TrustCapabilitiesReport report)
    {
        if(!report.IsValid())throw new ArgumentException("Invalid trust capability report");InitializeNativeHashTrustCapabilities();using var c=Open();using var t=c.BeginTransaction();
        using(var exists=Command(c,t,"SELECT COUNT(*) FROM endpoints WHERE id=$id AND revoked=0",("$id",endpoint)))if(Convert.ToInt64(exists.ExecuteScalar())!=1)return false;
        using(var update=Command(c,t,"UPDATE trust_native_hash_capabilities SET version=$version,reported=$now WHERE endpoint=$id",("$id",endpoint),("$version",report.LinuxNativeHashTrustVersion),("$now",Now())))
        if(update.ExecuteNonQuery()==0){using var insert=Command(c,t,"INSERT INTO trust_native_hash_capabilities(endpoint,version,reported) VALUES($id,$version,$now)",("$id",endpoint),("$version",report.LinuxNativeHashTrustVersion),("$now",Now()));insert.ExecuteNonQuery();}
        t.Commit();return true;
    }
    private static void RequireNativeHashTrustCapabilities(System.Data.Common.DbConnection c,System.Data.Common.DbTransaction t,TrustRule[] rules,DateTimeOffset now)
    {
        using var cmd=Command(c,t,"SELECT e.id,b.group_id,k.os,n.version,n.reported FROM endpoints e LEFT JOIN endpoint_groups_binding b ON b.endpoint=e.id LEFT JOIN trust_capabilities k ON k.endpoint=e.id LEFT JOIN trust_native_hash_capabilities n ON n.endpoint=e.id WHERE e.revoked=0");using var rows=cmd.ExecuteReader();
        while(rows.Read()){
            var id=rows.GetString(0);var group=rows.IsDBNull(1)?null:rows.GetString(1);var os=rows.IsDBNull(2)?"unknown":rows.GetString(2);
            if(os is "linux" or "unknown"&&rules.Any(r=>r.Enabled&&r.ExpiresUtc>now&&r.ProcessMatch==TrustEvaluation.LinuxNativeHashProcessMatch&&(r.Scope=="organization"||r.Scope=="group"&&r.ScopeId==group||r.Scope=="host"&&r.ScopeId==id))&&
                (rows.IsDBNull(3)||Convert.ToInt32(rows.GetValue(3))!=1||DateTimeOffset.FromUnixTimeMilliseconds(rows.GetInt64(4))<=now.AddSeconds(-LinuxTrustSourceMaximumAgeSeconds)))throw new TrustCapabilityException("TRUST_NATIVE_SOURCE_REQUIRED","A selected Linux sensor has no current qualified native hash source. Restore its source and retry.");
        }
    }
    private static void RequireLinuxTrustCapabilities(System.Data.Common.DbConnection c,System.Data.Common.DbTransaction transaction,TrustRule[] rules,DateTimeOffset now)
    {
        // Policy is distributed as one exact revision/digest. Never filter new
        // rules out for old clients or claim that an older parser enforced v3.
        using var command=Command(c,transaction,"""
            SELECT e.id,b.group_id,k.policy_version,k.kernel_trust_version,k.os,k.reported
              FROM endpoints e LEFT JOIN endpoint_groups_binding b ON b.endpoint=e.id
              LEFT JOIN trust_capabilities k ON k.endpoint=e.id WHERE e.revoked=0
            """);using var rows=command.ExecuteReader();
        while(rows.Read())
        {
            var endpoint=rows.GetString(0);var group=rows.IsDBNull(1)?null:rows.GetString(1);
            if(rows.IsDBNull(2)||Convert.ToInt32(rows.GetValue(2))<3||DateTimeOffset.FromUnixTimeMilliseconds(rows.GetInt64(5))<=now.AddHours(-24))
                throw new TrustCapabilityException("TRUST_PARSER_UPGRADE_REQUIRED","Update all enrolled sensors before publishing Linux kernel hash rules. A current policy v3 capability report is missing.");
            var os=rows.GetString(4);
            if(os is "linux" or "unknown"&&rules.Any(r=>r.ProcessMatch==TrustEvaluation.LinuxKernelProcessMatch&&r.Enabled&&r.ExpiresUtc>now&&
                (r.Scope=="organization"||r.Scope=="group"&&r.ScopeId==group||r.Scope=="host"&&r.ScopeId==endpoint))&&
                (Convert.ToInt32(rows.GetValue(3))!=1||DateTimeOffset.FromUnixTimeMilliseconds(rows.GetInt64(5))<=now.AddSeconds(-LinuxTrustSourceMaximumAgeSeconds)))
                throw new TrustCapabilityException("TRUST_NATIVE_SOURCE_REQUIRED","An applicable Linux sensor has not reported an active qualified kernel source. Review sensor readiness before publishing this rule.");
        }
    }
    public IReadOnlyList<TrustCapabilityStatus> TrustCapabilityStatuses()
    {
        InitializeTrustCapabilities();InitializeNativeHashTrustCapabilities();using var c=Open();using var command=Command(c,null,"""
            SELECT e.id,e.machine,k.os,k.policy_version,k.kernel_trust_version,k.reported,n.version,n.reported FROM endpoints e
              LEFT JOIN trust_capabilities k ON k.endpoint=e.id LEFT JOIN trust_native_hash_capabilities n ON n.endpoint=e.id WHERE e.revoked=0 ORDER BY e.machine,e.id
            """);using var rows=command.ExecuteReader();var result=new List<TrustCapabilityStatus>();
        while(rows.Read())result.Add(new(rows.GetString(0),rows.GetString(1),rows.IsDBNull(2)?"unknown":rows.GetString(2),
            rows.IsDBNull(3)?0:Convert.ToInt32(rows.GetValue(3)),rows.IsDBNull(4)?0:Convert.ToInt32(rows.GetValue(4)),rows.IsDBNull(5)?null:DateTimeOffset.FromUnixTimeMilliseconds(rows.GetInt64(5))){LinuxNativeHashTrustVersion=rows.IsDBNull(6)?0:Convert.ToInt32(rows.GetValue(6)),LinuxNativeHashReportedUtc=rows.IsDBNull(7)?null:DateTimeOffset.FromUnixTimeMilliseconds(rows.GetInt64(7))});
        return result;
    }
    private static void RequireAdvancedTrustCapabilities(System.Data.Common.DbConnection c,System.Data.Common.DbTransaction transaction,DateTimeOffset now)
    {
        using var command=Command(c,transaction,"SELECT e.id,k.policy_version,k.reported FROM endpoints e LEFT JOIN trust_capabilities k ON k.endpoint=e.id WHERE e.revoked=0");using var rows=command.ExecuteReader();
        while(rows.Read())if(rows.IsDBNull(1)||Convert.ToInt32(rows.GetValue(1))<4||DateTimeOffset.FromUnixTimeMilliseconds(rows.GetInt64(2))<=now.AddHours(-24))
            throw new TrustCapabilityException("TRUST_PARSER_UPGRADE_REQUIRED","Update all enrolled sensors before publishing advanced whitelist controls. A current policy v4 capability report is required.");
    }
}
