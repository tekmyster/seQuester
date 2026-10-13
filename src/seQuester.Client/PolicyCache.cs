using System.Text.Json;
using RansomFree.Contracts;

namespace RansomFree.Client;

public sealed class PolicyCache
{
    private readonly string path,endpoint;
    private bool validOnDisk;
    public AssignedPolicy Current {get;private set;}=new(null,0,MonitoringPolicy.Default);
    private sealed record Saved(string EndpointId,AssignedPolicy Policy);
    public PolicyCache(string directory,string endpointId)
    {
        if(!Guid.TryParseExact(endpointId,"N",out _))throw new ArgumentException("Invalid endpoint ID.");
        path=Path.Combine(directory,"managed-policy.json");endpoint=endpointId;
    }
    public void Load()
    {
        if(!File.Exists(path))return;
        if(new FileInfo(path).Length>1048576)throw new InvalidDataException("Policy cache exceeds its size limit.");
        using var stream=File.OpenRead(path);var saved=JsonSerializer.Deserialize<Saved>(stream)??throw new InvalidDataException("Invalid policy cache.");
        if(saved.EndpointId!=endpoint)throw new InvalidDataException("Policy cache belongs to a different enrollment.");
        Validate(saved.Policy);Current=saved.Policy;validOnDisk=true;
    }
    public static void Validate(AssignedPolicy policy)
    {
        if(policy is null || policy.Settings is null || !policy.Settings.IsValid() || policy.Revision<0 || policy.GroupId!=null && !Guid.TryParseExact(policy.GroupId,"N",out _) || policy.GroupId==null && (policy.Revision!=0 || !policy.Settings.SameContent(MonitoringPolicy.Default)))throw new InvalidDataException("Unsupported monitoring policy.");
    }
    public void Save(AssignedPolicy policy)
    {
        Validate(policy);
        if(validOnDisk && policy.GroupId==Current.GroupId && (policy.Revision<Current.Revision || policy.Revision==Current.Revision && !policy.Settings.SameContent(Current.Settings)))throw new InvalidDataException("Policy revision moved backwards or changed content.");
        if(policy.GroupId==Current.GroupId && policy.Revision==Current.Revision && policy.Settings.SameContent(Current.Settings) && validOnDisk && File.Exists(path))return;
        var temporary=path+"."+Guid.NewGuid().ToString("N")+".tmp";
        try
        {
            using(var stream=new FileStream(temporary,FileMode.CreateNew,FileAccess.Write,FileShare.None))
            {JsonSerializer.Serialize(stream,new Saved(endpoint,policy));stream.Flush(true);}
            if(!validOnDisk && File.Exists(path))File.Copy(path,path+".rejected-"+Guid.NewGuid().ToString("N"),false);
            File.Move(temporary,path,true);Current=policy;validOnDisk=true;
        }
        finally{if(File.Exists(temporary))File.Delete(temporary);}
    }
}
