using System.Security.Cryptography;
using System.Text.Json;
using RansomFree.Contracts;

internal sealed class ResponseJournal
{
    private sealed record Entry(string Digest,ResponseReceipt Receipt,bool Acknowledged=false,DateTimeOffset? RecordedUtc=null);
    private readonly string path,directory;
    private readonly Dictionary<string,Entry> entries;
    public ResponseJournal(string directory,string fileName="response-journal.json")
    {
        if(fileName is not ("response-journal.json" or "automatic-response-journal.json"))throw new ArgumentException("Invalid journal name.");
        this.directory=directory;path=Path.Combine(directory,fileName);
        if(File.Exists(path)&&new FileInfo(path).Length>2097152)throw new InvalidDataException("Response journal exceeds its limit.");
        entries=File.Exists(path)?JsonSerializer.Deserialize<Dictionary<string,Entry>>(File.ReadAllText(path))??throw new InvalidDataException("Invalid response journal."):[];
        if(entries.Count>2000)throw new InvalidDataException("Response journal capacity reached.");
    }
    public ResponseReceipt Execute(ResponseCommand command,AgentConsoleState state,string approvalKey="AllowRemoteProcessStop",AssignedPolicy? policy=null,string? sensor=null)
    {
        if(approvalKey is not ("AllowRemoteProcessStop" or "AllowAutomaticProcessStop"))throw new ArgumentException("Invalid response permission.");
        if(!Guid.TryParseExact(command.Id,"N",out _) || !Guid.TryParseExact(command.EventId,"N",out _) || command.Action!="end-process" || command.RequestedBy is not {Length:>0 and <=256} || command.Reason is not {Length:>0 and <=500})throw new InvalidDataException("Unsupported response command.");
        if(command.Target!=null&&(!command.Target.IsValid()||command.Target.EventId!=command.EventId||command.Target.OperatingSystem!="windows"||command.PolicyRevision is null or <0||!EvidenceTransferLimits.Hash(command.PolicyDigest)))throw new InvalidDataException("Invalid process response evidence.");
        var digest=Convert.ToHexString(SHA256.HashData(JsonSerializer.SerializeToUtf8Bytes(command)));
        if(entries.TryGetValue(command.Id,out var prior)){if(prior.Digest!=digest)throw new InvalidDataException("Response ID content changed.");return prior.Receipt;}
        if(entries.Count>=2000)throw new InvalidDataException("Response journal is full; existing evidence preserved.");
        ResponseReceipt Complete(string outcome,string message){var receipt=new ResponseReceipt(command.Id,outcome,message);entries[command.Id]=new(digest,receipt,RecordedUtc:DateTimeOffset.UtcNow);Save();return receipt;}
        var now=DateTimeOffset.UtcNow;
        if(command.ExpiresUtc<=now || command.CreatedUtc>now.AddMinutes(1) || command.ExpiresUtc-command.CreatedUtc>TimeSpan.FromMinutes(2) || command.ExpiresUtc<=command.CreatedUtc)return Complete("Rejected","Command expired or its time bounds are invalid.");
        if(command.Target!=null&&!ResponseCommandPolicy.Permits(command,policy,sensor,approvalKey=="AllowAutomaticProcessStop"))return Complete("Rejected","The response does not match the current assigned policy.");
        if(command.Target!=null&&entries.Values.Count(e=>(e.Receipt.Outcome is "Succeeded" or "Failed" or "Indeterminate")&&e.RecordedUtc>now.AddMinutes(-1))>=policy!.Settings.ActiveResponse!.MaximumActionsPerMinute)return Complete("Rejected","The response rate limit was reached.");
        var approval=Path.Combine(directory,"response-permissions.json");
        if(!File.Exists(approval) || new FileInfo(approval).Length>4096)return Complete("Rejected","Remote process response is not approved locally.");
        using(var configuration=JsonDocument.Parse(File.ReadAllText(approval)))
            if(!configuration.RootElement.TryGetProperty(approvalKey,out var allow) || allow.ValueKind!=JsonValueKind.True)return Complete("Rejected","This process response mode is not approved locally.");
        // Persist intent BEFORE the irreversible action. After a crash, do not repeat an uncertain action.
        Complete("Indeterminate","Execution intent recorded; outcome was not confirmed. Inspect the endpoint before another request.");
        var result=state.Respond(command.EventId,"Management administrator "+command.RequestedBy,command.Target,policy?.Settings.ActiveResponse);
        return Complete(result.Success?"Succeeded":"Failed",result.Message);
    }
    public ResponseReceipt[] PendingReceipts()=>entries.Values.Where(x=>!x.Acknowledged).Take(10).Select(x=>x.Receipt).ToArray();
    public void Acknowledge(string id)
    {
        if(!entries.TryGetValue(id,out var entry))throw new InvalidDataException("Unknown response receipt.");
        entries[id]=entry with{Acknowledged=true};Save();
    }
    private void Save()
    {
        var temporary=path+".tmp";
        using(var stream=new FileStream(temporary,FileMode.Create,FileAccess.Write,FileShare.None)){JsonSerializer.Serialize(stream,entries);stream.Flush(true);}
        File.Move(temporary,path,true);
    }
}
