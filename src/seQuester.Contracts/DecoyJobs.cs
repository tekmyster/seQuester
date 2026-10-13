using System.Security.Cryptography;
using System.Text.Json;
using System.Text.Json.Serialization;
namespace RansomFree.Contracts;

public sealed record ManagedDecoyJob(string EndpointId,long PolicyRevision,DateTimeOffset ApprovedUtc,DateTimeOffset ExpiresUtc,DecoySessionJob Job);
public sealed record DecoyJobReport(string JobId,long PolicyRevision,string UserSid,uint SessionId,string LogonId,DecoySessionReceipt Receipt,string Origin="User session");
public sealed record DecoyNativeReport(string JobId,string DecoyId,long PolicyRevision,string UserSid,uint SessionId,string LogonId,string Challenge,DateTimeOffset ObservedUtc,long? Revision,string State,string Scope="Endpoint and authenticated user session; not SYSTEM attestation");
public sealed record DecoyJobExchange(ManagedDecoyJob? Assignment);
public sealed record DecoyReportAcknowledgement(string State,string Challenge);
public sealed record DecoyJobSessionRequest(string Operation,DecoySessionReceipt? Receipt=null,DecoyNativeReport? Observation=null);
public sealed record DecoyJobSessionReply(string State,ManagedDecoyJob? Managed=null,DecoySessionAssignment? Assignment=null,string? Challenge=null,uint SessionId=0,string? LogonId=null);
public static class DecoyJobsProtocol
{
    public const string ObservationScope="Endpoint and authenticated user session; not SYSTEM attestation";
    public static readonly JsonSerializerOptions Json=new(){PropertyNameCaseInsensitive=true,UnmappedMemberHandling=JsonUnmappedMemberHandling.Disallow,AllowDuplicateProperties=false,RespectRequiredConstructorParameters=true,RespectNullableAnnotations=true,MaxDepth=12};
    public static T Read<T>(ReadOnlySpan<byte> bytes)=>bytes.Length is >1 and <=32768?JsonSerializer.Deserialize<T>(bytes,Json)??throw new InvalidDataException("Missing job message."):throw new InvalidDataException("Job message exceeds limit.");
    public static string Digest<T>(T value)=>Convert.ToHexString(SHA256.HashData(JsonSerializer.SerializeToUtf8Bytes(value)));
    public static bool Id(string value)=>Guid.TryParseExact(value,"N",out _);
    public static bool Nonce(string value)=>value is {Length:64}&&value.All(Uri.IsHexDigit);
    public static void Validate(ManagedDecoyJob value)
    {
        DecoySessionProtocol.Validate(value.Job);
        if(!Id(value.EndpointId)||value.PolicyRevision<1||value.ExpiresUtc<=value.ApprovedUtc||value.ExpiresUtc-value.ApprovedUtc>TimeSpan.FromDays(7))throw new ArgumentException("Invalid managed job.");
    }
    public static void Identity(string sid,uint session,string logon)
    {
        if(!TrayReaderIdentity.IsSupported(sid)||session==0||logon is not {Length:16}||!logon.All(Uri.IsHexDigit))throw new ArgumentException("Invalid authenticated session identity.");
    }
    public static void Validate(DecoyJobReport value)
    {
        Identity(value.UserSid,value.SessionId,value.LogonId);DecoySessionProtocol.Validate(value.Receipt);
        if(!Id(value.JobId)||value.PolicyRevision<1||value.JobId!=value.Receipt.JobId||value.Origin is not ("User session" or "Broker interruption")||value.Origin=="Broker interruption"&&value.Receipt.State!="Unconfirmed")throw new ArgumentException("Invalid job result binding.");
    }
    public static void Validate(DecoyNativeReport value)
    {
        Identity(value.UserSid,value.SessionId,value.LogonId);
        if(!Id(value.JobId)||!Id(value.DecoyId)||value.PolicyRevision<1||!Nonce(value.Challenge)||(value.State=="Unavailable"?value.Revision!=null:value.Revision is null or <1)||value.Scope!=ObservationScope||value.State is not ("Active" or "Disabled" or "Retired" or "Needs repair" or "Drive collision" or "Library changed" or "Ownership needs review" or "Different logon session" or "Unavailable"))throw new ArgumentException("Invalid native observation.");
    }
}
