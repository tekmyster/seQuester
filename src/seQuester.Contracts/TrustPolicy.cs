using System.Security.Cryptography;
using System.Text.Json;
namespace RansomFree.Contracts;
public sealed record TrustApproval(string RuleId,string RuleHash,string Actor,DateTimeOffset ApprovedUtc);
public sealed record TrustPolicy(long Revision,string Mode,TrustRule[] Rules,TrustApproval[] Approvals,string Actor,DateTimeOffset PublishedUtc)
{
    public int Version {get;init;}=1;
    public static TrustPolicy Default=>new(0,"legacy",[],[],"system",DateTimeOffset.UnixEpoch);
    public static string RuleHash(TrustRule rule)=>Convert.ToHexString(SHA256.HashData(JsonSerializer.SerializeToUtf8Bytes(rule)));
    public string Digest()=>Convert.ToHexString(SHA256.HashData(JsonSerializer.SerializeToUtf8Bytes(this)));
    public HashSet<string> ApprovedRules()=>Approvals.Where(a=>Rules.Any(r=>r.Id==a.RuleId&&RuleHash(r)==a.RuleHash)).Select(a=>a.RuleId).ToHashSet(StringComparer.Ordinal);
    public void Validate()
    {
        if(Version is not (1 or 2 or 3 or 4)||Revision<0||Mode is not ("enforce" or "legacy")||Rules==null||Approvals==null||Approvals.Length>1000||Actor==null||Actor.Length>256||Actor.Any(char.IsControl))throw new ArgumentException("Invalid trust policy.");
        TrustEvaluation.Validate(Rules);
        if(Version<4&&Rules.Any(r=>r.PathMatch!=null||r.AccountPrincipal!=null||r.ProcessInstance!=null||r.Subject=="account-or-process"||r.ProcessMatch==TrustEvaluation.LinuxNativeHashProcessMatch))throw new ArgumentException("Advanced whitelist controls require policy version 4.");
        if(Version<3&&Rules.Any(r=>r.ProcessMatch==TrustEvaluation.LinuxKernelProcessMatch))throw new ArgumentException("Linux kernel hash rules require policy version 3.");
        if(Version==1&&Rules.Any(r=>r.Disposition=="log-only"||r.ProcessMatch!=null||r.Name!=null))throw new ArgumentException("Whitelist rules require policy version 2.");
        if(Mode=="legacy"&&(Rules.Length!=0||Approvals.Length!=0))throw new ArgumentException("Legacy mode cannot publish hierarchical exceptions.");
        if(Approvals.Any(a=>a==null||!Rules.Any(r=>r.Id==a.RuleId&&RuleHash(r)==a.RuleHash)||string.IsNullOrEmpty(a.Actor)||a.Actor.Length>256||a.Actor.Any(char.IsControl))||Approvals.Select(a=>a.RuleId).Distinct().Count()!=Approvals.Length)throw new ArgumentException("Invalid trust approval.");
        if(JsonSerializer.SerializeToUtf8Bytes(this).Length>400000)throw new ArgumentException("Trust policy exceeds distribution bound.");
    }
}
public sealed record AssignedTrustPolicy(string EndpointId,string? GroupId,TrustPolicy Policy,string Digest,DateTimeOffset IssuedUtc,DateTimeOffset ExpiresUtc)
{
    public string Organization=>"server";
    public void Validate()
    {
        if(!Guid.TryParseExact(EndpointId,"N",out _)||GroupId!=null&&!Guid.TryParseExact(GroupId,"N",out _)||Policy==null)throw new ArgumentException("Invalid trust assignment.");
        Policy.Validate();if(Digest!=Policy.Digest()||ExpiresUtc<=IssuedUtc||ExpiresUtc-IssuedUtc>TimeSpan.FromHours(24))throw new ArgumentException("Invalid trust assignment validity.");
    }
}
public sealed record TrustPolicyReceipt(int Version,long Revision,string Digest,string? GroupId,string Mode)
{
    [System.Text.Json.Serialization.JsonIgnore(Condition=System.Text.Json.Serialization.JsonIgnoreCondition.WhenWritingDefault)]
    public int PolicyVersion {get;init;}
}
public sealed record TrustCapabilitiesReport(int Version=1,int PolicyVersion=0,int LinuxKernelTrustVersion=0,string OperatingSystem="unknown")
{
    [System.Text.Json.Serialization.JsonIgnore(Condition=System.Text.Json.Serialization.JsonIgnoreCondition.WhenWritingDefault)]
    public int LinuxNativeHashTrustVersion {get;init;}
    public bool IsValid()=>Version==1&&PolicyVersion is >=0 and <=4&&LinuxKernelTrustVersion is 0 or 1&&
        OperatingSystem is "windows" or "linux" or "macos" or "unknown"&&
        (LinuxKernelTrustVersion==0||PolicyVersion>=3&&OperatingSystem=="linux")&&LinuxNativeHashTrustVersion is 0 or 1&&(LinuxNativeHashTrustVersion==0||PolicyVersion>=4&&OperatingSystem=="linux");
}
