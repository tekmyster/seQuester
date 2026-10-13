using System.Security.Claims;
using System.Text.Json;
using Microsoft.AspNetCore.Antiforgery;
using Microsoft.AspNetCore.Identity;
using RansomFree.Contracts;
namespace RansomFree.Server;

public sealed record PublishTrustBody(long ExpectedRevision,string Mode,TrustRule[] Rules,string[] ApproveBroadening,string AdministratorPassword,string? Code=null,string? RecoveryCode=null);
public sealed class TrustPolicyConflictException:Exception;
public sealed record TrustEndpointStatus(string EndpointId,string Machine,string? GroupId,long Revision,string Status,DateTimeOffset? ReportedUtc);
public enum TrustEventClassification { PolicyUnknown,NonWhitelisted,Informational,LogOnly }
public sealed partial class Store
{
    public bool HasTrustStorage()
    {
        using var c=Open();using var command=Command(c,null,sqlServer?"SELECT CASE WHEN OBJECT_ID(N'dbo.trust_revisions',N'U') IS NULL THEN 0 ELSE 1 END":"SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='trust_revisions'");
        var exists=Convert.ToInt64(command.ExecuteScalar())==1;if(exists&&sqlServer)RansomFree.Persistence.SqlServerSchema.Require(connectionString,"trust",1);return exists;
    }
    // Separate additive component. Existing event/identity tables and their migration remain unchanged.
    public void InitializeTrustStorage()
    {
        if(sqlServer){RansomFree.Persistence.SqlServerSchema.Require(connectionString,"trust",1);return;}
        using var c=Open();using var command=Command(c,null,"""
            CREATE TABLE IF NOT EXISTS trust_revisions(revision INTEGER PRIMARY KEY AUTOINCREMENT,created INTEGER NOT NULL,actor TEXT NOT NULL,payload TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS trust_current(id INTEGER PRIMARY KEY CHECK(id=1),revision INTEGER NOT NULL REFERENCES trust_revisions(revision));
            CREATE TABLE IF NOT EXISTS trust_receipts(endpoint TEXT PRIMARY KEY REFERENCES endpoints(id),revision INTEGER NOT NULL,digest TEXT NOT NULL,group_id TEXT,mode TEXT NOT NULL,reported INTEGER NOT NULL);
            """);command.ExecuteNonQuery();
    }
    private static TrustPolicy ReadTrust(System.Data.Common.DbConnection c,System.Data.Common.DbTransaction? transaction)
    {
        using var cmd=Command(c,transaction,"SELECT r.payload FROM trust_current a JOIN trust_revisions r ON r.revision=a.revision WHERE a.id=1");
        var value=cmd.ExecuteScalar() as string;var policy=value==null?TrustPolicy.Default:JsonSerializer.Deserialize<TrustPolicy>(value)??throw new InvalidDataException("Invalid trust policy.");policy.Validate();return policy;
    }
    public TrustPolicy ReadTrustPolicy(){if(!HasTrustStorage())return TrustPolicy.Default;using var c=Open();return ReadTrust(c,null);}
    public TrustPolicy PublishTrustPolicy(PublishTrustBody body,string actor)
    {
        if(body.Rules==null||body.ApproveBroadening==null||body.ExpectedRevision<0||body.ApproveBroadening.Length>1000||body.ApproveBroadening.Distinct().Count()!=body.ApproveBroadening.Length)throw new ArgumentException("Invalid trust publication.");
        TrustEvaluation.Validate(body.Rules);
        var nativeRules=body.Rules.Any(r=>r.ProcessMatch==TrustEvaluation.LinuxKernelProcessMatch);
        var nativeHashRules=body.Rules.Any(r=>r.ProcessMatch==TrustEvaluation.LinuxNativeHashProcessMatch);
        var advancedRules=body.Rules.Any(r=>r.PathMatch!=null||r.AccountPrincipal!=null||r.ProcessInstance!=null||r.Subject=="account-or-process")||nativeHashRules;
        if(nativeRules||advancedRules)InitializeTrustCapabilities();
        if(nativeHashRules)InitializeNativeHashTrustCapabilities();
        if(body.Rules.Any(r=>r.Disposition is not ("normal" or "informational" or "log-only")))throw new ArgumentException("Choose normal alerts, informational alerts, or log only.");
        using var c=Open();using var transaction=c.BeginTransaction(System.Data.IsolationLevel.Serializable);var old=ReadTrust(c,transaction);
        if(old.Revision!=body.ExpectedRevision)throw new TrustPolicyConflictException();
        var approvals=new List<TrustApproval>();var now=DateTimeOffset.UtcNow;
        if(nativeRules)RequireLinuxTrustCapabilities(c,transaction,body.Rules,now);
        if(advancedRules)RequireAdvancedTrustCapabilities(c,transaction,now);
        if(nativeHashRules)RequireNativeHashTrustCapabilities(c,transaction,body.Rules,now);
        foreach(var rule in body.Rules)
        {
            if(rule.Scope=="organization"&&rule.ScopeId!="server")throw new ArgumentException("Organization scope must be this server.");
            if(rule.Scope is "group" or "host")
            {
                if(!Guid.TryParseExact(rule.ScopeId,"N",out _))throw new ArgumentException("Invalid target identity.");
                using var exists=Command(c,transaction,rule.Scope=="group"?"SELECT COUNT(*) FROM endpoint_groups WHERE id=$id":"SELECT COUNT(*) FROM endpoints WHERE id=$id AND revoked=0",("$id",rule.ScopeId));
                if(Convert.ToInt64(exists.ExecuteScalar())!=1)throw new ArgumentException("Target no longer exists.");
            }
            var parent=body.Rules.SingleOrDefault(x=>x.Id==rule.ParentRuleId);
            var broad=rule.Scope!="organization"&&rule.Disposition!="normal"&&(parent==null||!TrustEvaluation.Narrows(rule,parent));
            if(!broad)continue;
            var digest=TrustPolicy.RuleHash(rule);var existing=old.Approvals.SingleOrDefault(a=>a.RuleId==rule.Id&&a.RuleHash==digest);
            if(existing!=null)approvals.Add(existing);
            else if(body.ApproveBroadening.Contains(rule.Id))approvals.Add(new(rule.Id,digest,actor,now));
            else throw new ArgumentException("Broader scoped exception requires explicit administrator approval.");
        }
        if(body.ApproveBroadening.Any(id=>!approvals.Any(a=>a.RuleId==id)))throw new ArgumentException("Unexpected broadening approval.");
        var draft=new TrustPolicy(0,body.Mode,body.Rules,approvals.ToArray(),actor,now){Version=advancedRules?4:nativeRules?3:body.Rules.Any(r=>r.Disposition=="log-only"||r.ProcessMatch!=null||r.Name!=null)?2:1};draft.Validate();
        using var insert=Command(c,transaction,"INSERT INTO trust_revisions(created,actor,payload) VALUES($time,$actor,$payload) RETURNING revision",("$time",now.ToUnixTimeMilliseconds()),("$actor",actor),("$payload",JsonSerializer.Serialize(draft)));
        var revision=Convert.ToInt64(insert.ExecuteScalar());var next=draft with{Revision=revision};next.Validate();
        using(var fill=Command(c,transaction,"UPDATE trust_revisions SET payload=$payload WHERE revision=$revision",("$payload",JsonSerializer.Serialize(next)),("$revision",revision)))fill.ExecuteNonQuery();
        using(var current=Command(c,transaction,"UPDATE trust_current SET revision=$revision WHERE id=1",("$revision",revision)))if(current.ExecuteNonQuery()==0){using var add=Command(c,transaction,"INSERT INTO trust_current(id,revision) VALUES(1,$revision)",("$revision",revision));add.ExecuteNonQuery();}
        Audit(c,transaction,"Trust policy published",JsonSerializer.Serialize(new{Actor=actor,Previous=old.Revision,Revision=revision,PreviousDigest=old.Digest(),Digest=next.Digest(),ApprovedCount=approvals.Count}));
        transaction.Commit();return next;
    }
    public IReadOnlyList<TrustPolicy> TrustHistory()
    {
        if(!HasTrustStorage())return [];
        using var c=Open();using var command=Command(c,null,"SELECT payload FROM trust_revisions ORDER BY revision DESC LIMIT 100");using var reader=command.ExecuteReader();var results=new List<TrustPolicy>();while(reader.Read())results.Add(JsonSerializer.Deserialize<TrustPolicy>(reader.GetString(0))!);return results;
    }
    // Retain the reported decision verbatim. Only this authoritative policy replay
    // may classify it; structural validation of an endpoint claim is insufficient.
    public TrustEventClassification ClassifyTrust(StoredEvent stored)
    {
        var e=stored.Event;var claim=e.Trust;
        if(e.Source is "Forensic enrichment" or "Evidence transfer"&&e.Forensics is {RelatedEventId:not null} forensic&&forensic.IsValid())
        {
            // Resolve only within this sensor, never trust its claimed whitelist outcome or recurse through completions.
            using var originalConnection=Open();using var originalCommand=Command(originalConnection,null,"SELECT sequence,received,payload FROM events WHERE endpoint=$endpoint AND event_id=$event",("$endpoint",stored.EndpointId),("$event",forensic.RelatedEventId));
            using var row=originalCommand.ExecuteReader();
            if(row.Read()&&JsonSerializer.Deserialize<AgentEvent>(row.GetString(2)) is {} original&&original.Source!="Forensic enrichment")
            {
                var classification=ClassifyTrust(new(row.GetInt64(0),stored.EndpointId,DateTimeOffset.FromUnixTimeMilliseconds(row.GetInt64(1)),original));
                return classification==TrustEventClassification.LogOnly?TrustEventClassification.LogOnly:TrustEventClassification.Informational;
            }
            return TrustEventClassification.PolicyUnknown;
        }
        if(claim==null||!claim.IsValid()||claim.Result.Mode!="enforce"||claim.EvaluatedUtc>stored.ReceivedUtc.AddMinutes(1)||claim.EvaluatedUtc<e.ObservedUtc.AddMinutes(-1)||!HasTrustStorage())return TrustEventClassification.PolicyUnknown;
        if(claim.Group!=Assigned(stored.EndpointId).GroupId)return TrustEventClassification.PolicyUnknown;
        using var c=Open();using var command=Command(c,null,"SELECT payload FROM trust_revisions WHERE revision=$revision",("$revision",claim.Result.Revision!.Value));
        if(command.ExecuteScalar() is not string payload)return TrustEventClassification.PolicyUnknown;
        var policy=JsonSerializer.Deserialize<TrustPolicy>(payload);if(policy==null)return TrustEventClassification.PolicyUnknown;policy.Validate();
        if(policy.Mode!="enforce"||policy.Digest()!=claim.Result.Digest||policy.PublishedUtc>claim.EvaluatedUtc)return TrustEventClassification.PolicyUnknown;
        if(claim.Actor.Signer!=null||claim.Actor.Publisher!=null||claim.Actor.ParentExecutable!=null||claim.Actor.SignatureVerified)return TrustEventClassification.PolicyUnknown;
        if(claim.Version==4)
        {
            if(policy.Version!=4||claim.LinuxNativeHashBinding is not {} binding||binding.SensorId!=stored.EndpointId||!binding.Matches(e)||
                claim.Actor!=LinuxNativeHashBinding.ActorFor(stored.EndpointId,e,binding.ActorSha256))return TrustEventClassification.PolicyUnknown;
            if(binding.EntryEvent is {} entry)
            {
                using var entryCommand=Command(c,null,"SELECT payload FROM events WHERE endpoint=$endpoint AND event_id=$event",("$endpoint",stored.EndpointId),("$event",entry.EventId));
                if(entryCommand.ExecuteScalar() is not string entryPayload||JsonSerializer.Deserialize<AgentEvent>(entryPayload) is not {} savedEntry||
                    LinuxKernelTrustBinding.InputDigest(savedEntry)!=LinuxKernelTrustBinding.InputDigest(entry))return TrustEventClassification.PolicyUnknown;
            }
        }
        else if(claim.Version==3)
        {
            if(claim.LinuxKernelBinding?.SensorId!=stored.EndpointId||claim.LinuxKernelBinding.Matches(e)!=true||
                claim.Result.Decision.LogOnly&&policy.Version<3)return TrustEventClassification.PolicyUnknown;
        }
        else if(claim.OperatingSystem=="linux")
        {
            var a=e.Attribution;
            if(claim.Actor.Sha256!=null||claim.Actor.Executable!=null&&(claim.Version!=2||claim.ProcessBasis!="audit-executable-path-v1"||!string.Equals(e.Process,claim.Actor.Executable,StringComparison.Ordinal)))return TrustEventClassification.PolicyUnknown;
            if(e.Source!="Linux Audit"||a is not {Provider:"Linux Audit",EventTimeCredentials:true,CompleteRecordSet:true,UserId:not null}||claim.Actor.AccountKind!="uid"||claim.Actor.Authority!=stored.EndpointId||claim.Actor.AccountId!=(claim.Version==2?a.FileSystemUserId??a.UserId.Value:a.UserId.Value).ToString(System.Globalization.CultureInfo.InvariantCulture))return TrustEventClassification.PolicyUnknown;
        }
        else if(claim.OperatingSystem!="windows"||e.Source is not ("Windows audit 4656" or "Windows audit 4663" or "Windows minifilter"))return TrustEventClassification.PolicyUnknown;
        else if(e.Source=="Windows minifilter"&&(!WindowsKernelEvidence.Matches(e)||e.Attribution is not {CompleteRecordSet:true,WindowsKernel:{} kernel}||kernel.Subject.Captured!=31||claim.Actor.AccountId!=kernel.Subject.Sid))return TrustEventClassification.PolicyUnknown;
        else if(claim.Actor.Executable!=null||claim.Actor.Sha256!=null)
        {
            if(!string.Equals(e.Process,claim.Actor.Executable,StringComparison.OrdinalIgnoreCase))return TrustEventClassification.PolicyUnknown;
            if(claim.ProcessBasis=="windows-handle-locked-image-v1")
            {if(claim.ProcessCreatedUtc>e.ObservedUtc||claim.ImageCheckedUtc<e.ObservedUtc||claim.ImageCheckedUtc>e.ObservedUtc.AddSeconds(30))return TrustEventClassification.PolicyUnknown;}
            else if(claim.ProcessBasis=="windows-operation-bound-snapshot-v1")
            {
                if(e.Source!="Windows minifilter"||e.Forensics is not {} f||!f.IsValid()||f.ActorExecutable.Acquisition is not {Status.State:"captured",RecoveryStatus:null} a||
                    f.ActorExecutable.BindingStatus.State!="captured"||a.SourceEventId!=e.EventId||a.ProcessCreatedFileTime is not {} start||start is <=0 or >2650467743999999999||
                    claim.ProcessCreatedUtc!=DateTimeOffset.FromFileTime(start)||claim.ImageCheckedUtc!=a.PersistedUtc||
                    !string.Equals(claim.Actor.Sha256,a.SnapshotSha256,StringComparison.OrdinalIgnoreCase))return TrustEventClassification.PolicyUnknown;
            }
            else if(claim.Version!=2||claim.ProcessBasis!="audit-executable-path-v1"||claim.Actor.Sha256!=null)return TrustEventClassification.PolicyUnknown;
        }
        var decision=TrustEvaluation.Evaluate(policy.Rules,claim.Context(stored.EndpointId,e),claim.EvaluatedUtc,policy.ApprovedRules());
        if(JsonSerializer.Serialize(decision)!=JsonSerializer.Serialize(claim.Result.Decision))return TrustEventClassification.PolicyUnknown;
        return decision.LogOnly?TrustEventClassification.LogOnly:decision.Severity=="informational"?TrustEventClassification.Informational:TrustEventClassification.NonWhitelisted;
    }
    public int? TrustSyslogSeverity(StoredEvent stored)=>ClassifyTrust(stored)==TrustEventClassification.Informational?6:null;
    public AssignedTrustPolicy TrustAssignment(string endpoint)
    {
        if(!HasTrustStorage()){var issued=DateTimeOffset.UtcNow;return new(endpoint,Assigned(endpoint).GroupId,TrustPolicy.Default,TrustPolicy.Default.Digest(),issued,issued.AddHours(24));}
        using var c=Open();using var transaction=c.BeginTransaction(System.Data.IsolationLevel.Serializable);
        var policy=ReadTrust(c,transaction);var group=ReadAssigned(c,transaction,endpoint).GroupId;transaction.Commit();var now=DateTimeOffset.UtcNow;
        return new(endpoint,group,policy,policy.Digest(),now,now.AddHours(24));
    }
    public bool RecordTrustReceipt(string endpoint,TrustPolicyReceipt receipt)
    {
        if(!HasTrustStorage())InitializeTrustStorage();
        if(receipt.Version!=1)return false;
        using var c=Open();using var transaction=c.BeginTransaction(System.Data.IsolationLevel.Serializable);var current=ReadTrust(c,transaction);var group=ReadAssigned(c,transaction,endpoint).GroupId;
        if(receipt.Revision!=current.Revision||receipt.Digest!=current.Digest()||receipt.GroupId!=group||receipt.Mode!=current.Mode||current.Version>=3&&receipt.PolicyVersion<current.Version)return false;
        using(var update=Command(c,transaction,"UPDATE trust_receipts SET revision=$revision,digest=$digest,group_id=$group,mode=$mode,reported=$now WHERE endpoint=$endpoint",("$revision",receipt.Revision),("$digest",receipt.Digest),("$group",(object?)group??DBNull.Value),("$mode",receipt.Mode),("$now",Now()),("$endpoint",endpoint)))
        if(update.ExecuteNonQuery()==0){using var add=Command(c,transaction,"INSERT INTO trust_receipts(endpoint,revision,digest,group_id,mode,reported) VALUES($endpoint,$revision,$digest,$group,$mode,$now)",("$endpoint",endpoint),("$revision",receipt.Revision),("$digest",receipt.Digest),("$group",(object?)group??DBNull.Value),("$mode",receipt.Mode),("$now",Now()));add.ExecuteNonQuery();}
        transaction.Commit();return true;
    }
    public IReadOnlyList<TrustEndpointStatus> TrustEndpointStatuses()
    {
        var hasStorage=HasTrustStorage();var current=ReadTrustPolicy();using var c=Open();
        using var command=Command(c,null,hasStorage?"SELECT e.id,e.machine,b.group_id,r.revision,r.digest,r.group_id,r.mode,r.reported FROM endpoints e LEFT JOIN endpoint_groups_binding b ON b.endpoint=e.id LEFT JOIN trust_receipts r ON r.endpoint=e.id WHERE e.revoked=0 ORDER BY e.machine,e.id":"SELECT e.id,e.machine,b.group_id,NULL,NULL,NULL,NULL,NULL FROM endpoints e LEFT JOIN endpoint_groups_binding b ON b.endpoint=e.id WHERE e.revoked=0 ORDER BY e.machine,e.id");
        using var reader=command.ExecuteReader();var rows=new List<TrustEndpointStatus>();
        while(reader.Read())
        {
            var group=reader.IsDBNull(2)?null:reader.GetString(2);var reported=reader.IsDBNull(7)?(DateTimeOffset?)null:DateTimeOffset.FromUnixTimeMilliseconds(reader.GetInt64(7));
            var exact=!reader.IsDBNull(3)&&reader.GetInt64(3)==current.Revision&&reader.GetString(4)==current.Digest()&&(reader.IsDBNull(5)?null:reader.GetString(5))==group&&reader.GetString(6)==current.Mode;
            rows.Add(new(reader.GetString(0),reader.GetString(1),group,current.Revision,exact&&reported>DateTimeOffset.UtcNow.AddHours(-24)?"Received":"Pending",reported));
        }
        return rows;
    }
}

public static class TrustGovernanceApi
{
    public static void MapTrustGovernance(this WebApplication app,Func<HttpContext,string?> authenticate)
    {
        var read=app.MapGroup("/api/v1/console/trust-policy").RequireAuthorization(p=>p.RequireRole("Administrator","Operator","Reader"));
        read.MapGet("",(Store store)=>Results.Ok(store.ReadTrustPolicy()));
        read.MapGet("/history",(Store store)=>Results.Ok(store.TrustHistory()));
        read.MapGet("/endpoints",(Store store)=>Results.Ok(store.TrustEndpointStatuses()));
        read.MapGet("/capabilities",(Store store)=>Results.Ok(store.TrustCapabilityStatuses()));
        app.MapPost("/api/v1/console/trust-policy",async(HttpContext c,IAntiforgery csrf,PublishTrustBody body,Store store,UserManager<LocalUser> users,SignInManager<LocalUser> signIn,AuthDb db)=>
        {
            if(!await NotificationAuthorization.Check(c,csrf,body.AdministratorPassword,body.Code,body.RecoveryCode,users,signIn,db))return Results.Unauthorized();
            var actor=c.User.FindFirstValue(ClaimTypes.NameIdentifier)!;
            try
            {
                store.CallbackAudit("Trust publication requested",actor,body.ExpectedRevision.ToString());
                store.InitializeTrustStorage();return Results.Ok(store.PublishTrustPolicy(body,actor));
            }
            catch(TrustPolicyConflictException){store.CallbackAudit("Trust publication conflict",actor,body.ExpectedRevision.ToString());return Results.Conflict(new{error="Policy changed. Refresh before publishing."});}
            catch(TrustCapabilityException ex){store.CallbackAudit("Trust publication capability rejected",actor,body.ExpectedRevision.ToString());return Results.BadRequest(new{error=ex.Message,code=ex.Code});}
            catch(ArgumentException){store.CallbackAudit("Trust publication rejected",actor,body.ExpectedRevision.ToString());return Results.BadRequest(new{error="Invalid policy, target or approval. No policy published."});}
        }).RequireAuthorization(p=>p.RequireRole("Administrator"));
        app.MapPost("/api/v1/agent/trust-policy",(HttpContext c,TrustCapabilitiesReport report,Store store)=>
        {
            if(authenticate(c) is not {} endpoint)return Results.Unauthorized();
            if(!report.IsValid())return Results.BadRequest(new{error="Invalid trust capability report."});
            if(!store.RecordTrustCapabilities(endpoint,report)||!store.RecordNativeHashTrustCapabilities(endpoint,report))return Results.Unauthorized();
            var assignment=store.TrustAssignment(endpoint);
            return assignment.Policy.Version>=3&&report.PolicyVersion<assignment.Policy.Version?Results.Conflict(new{error="TRUST_POLICY_UPGRADE_REQUIRED"}):Results.Ok(assignment);
        });
        app.MapPost("/api/v1/agent/trust-policy/receipt",(HttpContext c,TrustPolicyReceipt receipt,Store store)=>authenticate(c) is {} endpoint?store.RecordTrustReceipt(endpoint,receipt)?Results.NoContent():Results.Conflict():Results.Unauthorized());
    }
}
