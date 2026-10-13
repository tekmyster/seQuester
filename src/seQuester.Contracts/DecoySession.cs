using System.Text.Json;
using System.Text.Json.Serialization;

namespace RansomFree.Contracts;

public sealed record DecoySessionJob(string JobId,string UserSid,string StateDirectory,string ApprovedRoot,string Action,string DecoyId,string Kind,string Name,string? Drive=null,long? ExpectedRevision=null);
public sealed record DecoySessionPolicy(int Version,long Revision,DateTimeOffset ExpiresUtc,DecoySessionJob[] Jobs);
public sealed record DecoySessionReceipt(string JobId,string Nonce,string State,long? Revision=null,string? ResourceState=null);
public sealed record DecoySessionRequest(string Operation,DecoySessionReceipt? Receipt=null);
public sealed record DecoySessionAssignment(DecoySessionJob Job,string Nonce,DateTimeOffset ExpiresUtc);
public sealed record DecoySessionReply(string State,DecoySessionAssignment? Assignment=null);

public static class DecoySessionProtocol
{
    public const string PipeName="RansomFree.Agent.DecoySession.v1";
    private static readonly JsonSerializerOptions Json=new()
    {
        PropertyNameCaseInsensitive=true,UnmappedMemberHandling=JsonUnmappedMemberHandling.Disallow,
        AllowDuplicateProperties=false,RespectRequiredConstructorParameters=true,RespectNullableAnnotations=true,MaxDepth=8
    };
    private static T Read<T>(ReadOnlySpan<byte> data,int maximum) where T:class
    {
        if(data.Length<2||data.Length>maximum)throw new InvalidDataException("Session message exceeds its limit.");
        return JsonSerializer.Deserialize<T>(data,Json)??throw new InvalidDataException("Session message missing.");
    }
    public static DecoySessionPolicy ReadPolicy(ReadOnlySpan<byte> data){var value=Read<DecoySessionPolicy>(data,131072);Validate(value);return value;}
    public static DecoySessionJob ReadJob(ReadOnlySpan<byte> data){var value=Read<DecoySessionJob>(data,4096);Validate(value);return value;}
    public static DecoySessionRequest ReadRequest(ReadOnlySpan<byte> data){var value=Read<DecoySessionRequest>(data,4096);Validate(value);return value;}
    public static DecoySessionReceipt ReadReceipt(ReadOnlySpan<byte> data){var value=Read<DecoySessionReceipt>(data,4096);Validate(value);return value;}
    public static DecoySessionReply ReadReply(ReadOnlySpan<byte> data)
    {
        var value=Read<DecoySessionReply>(data,16384);
        if(value.State is "Assignment" or "Unconfirmed action needs review")
        {
            if(value.Assignment is not {} assignment)throw new InvalidDataException("Assignment missing.");
            Validate(assignment.Job);if(!ValidNonce(assignment.Nonce))throw new InvalidDataException("Assignment nonce invalid.");
        }
        else if(value.Assignment!=null||value.State is not ("No assignments" or "Session result recorded" or "Receipt refused" or "Receipt conflict" or "Request refused" or "Policy expired" or "Session result needs review" or "Prior session needs review"))throw new InvalidDataException("Invalid session reply.");
        return value;
    }
    private static bool ValidNonce(string? value)=>value is {Length:64}&&value.All(Uri.IsHexDigit);
    public static void Validate(DecoySessionRequest request)
    {
        if(request is {Operation:"poll",Receipt:null})return;
        if(request is {Operation:"receipt",Receipt:{} receipt}){Validate(receipt);return;}
        throw new ArgumentException("Invalid session request.");
    }
    public static void Validate(DecoySessionPolicy policy)
    {
        if(policy.Version!=1||policy.Revision<1||policy.Jobs is not {Length:<=64}||policy.Jobs.Any(j=>j==null)||policy.Jobs.Select(j=>j.JobId).Distinct(StringComparer.Ordinal).Count()!=policy.Jobs.Length)throw new ArgumentException("Invalid session policy.");
        foreach(var job in policy.Jobs)Validate(job);
    }
    public static void Validate(DecoySessionJob job)
    {
        if(!Guid.TryParseExact(job.JobId,"N",out _)||!Guid.TryParseExact(job.DecoyId,"N",out _)||!TrayReaderIdentity.IsSupported(job.UserSid)||job.Kind is not ("V02" or "V03")||job.Action is not ("create" or "observe" or "activate" or "disable" or "repair" or "retire"))throw new ArgumentException("Invalid session assignment.");
        if(job.Name is not {Length:>0 and <=60}||string.IsNullOrWhiteSpace(job.Name)||job.Name.Any(c=>!char.IsAsciiLetterOrDigit(c)&&c is not (' ' or '-' or '_')))throw new ArgumentException("Invalid decoy name.");
        if(job.Kind=="V02"&&(job.Drive is not {Length:2}||job.Drive[0] is <'E' or >'Z'||job.Drive[1]!=':')||job.Kind=="V03"&&job.Drive!=null)throw new ArgumentException("Invalid decoy drive.");
        if(job.Action is "create" or "observe" ? job.ExpectedRevision!=null : job.ExpectedRevision is not >0)throw new ArgumentException("Invalid expected revision.");
        foreach(var path in new[]{job.StateDirectory,job.ApprovedRoot})
        {
            if(path is not {Length:>3 and <=180}||!char.IsAsciiLetter(path[0])||path[1]!=':'||path[2]!='\\'||path[3..].IndexOfAny([':', '/', '*', '?', '"', '<', '>', '|'])>=0||path.Any(char.IsControl))throw new ArgumentException("Use explicit local Windows folders.");
            var folder=path.TrimEnd('\\');if(folder.Length<=3)throw new ArgumentException("A volume root is not an approved folder.");
            foreach(var part in folder[3..].Split('\\'))
            {
                var stem=part.Split('.')[0].ToUpperInvariant();
                if(part.Length==0||part.EndsWith(' ')||part.EndsWith('.')||stem is "CON" or "PRN" or "AUX" or "NUL"||stem.Length==4&&(stem.StartsWith("COM",StringComparison.Ordinal)||stem.StartsWith("LPT",StringComparison.Ordinal))&&stem[3] is >='1' and <='9')throw new ArgumentException("Ambiguous Windows folder name.");
            }
        }
        var state=job.StateDirectory.TrimEnd('\\');var root=job.ApprovedRoot.TrimEnd('\\');
        if(state.Equals(root,StringComparison.OrdinalIgnoreCase)||state.StartsWith(root+"\\",StringComparison.OrdinalIgnoreCase)||root.StartsWith(state+"\\",StringComparison.OrdinalIgnoreCase))throw new ArgumentException("State and deployment folders must be separate and non-nested.");
    }
    public static void Validate(DecoySessionReceipt receipt)
    {
        if(!Guid.TryParseExact(receipt.JobId,"N",out _)||!ValidNonce(receipt.Nonce)||receipt.State is not ("Applied" or "Observed" or "Failed" or "Unconfirmed")||receipt.Revision is <1)throw new ArgumentException("Invalid session receipt.");
        if(receipt.State is "Applied" or "Observed"&&(receipt.Revision==null||string.IsNullOrWhiteSpace(receipt.ResourceState)))throw new ArgumentException("A completed session report requires resource state and revision.");
        if(receipt.ResourceState?.Length>80||receipt.ResourceState?.Any(char.IsControl)==true)throw new ArgumentException("Invalid reported resource state.");
    }
}
