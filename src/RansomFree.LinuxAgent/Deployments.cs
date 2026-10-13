using System.Security.Cryptography;
using System.Text.Json;
using RansomFree;
using RansomFree.Contracts;

namespace RansomFree.LinuxAgent;

internal sealed class Deployments(PrivateState state,ClientConfiguration config)
{
    public List<Canary> Items {get;}=state.Read<List<Canary>>("canaries.json")??[];
    public DeploymentProtectionEvidence? ProtectionEvidence {get;private set;}
    public void ValidateInventory()
    {
        if(Items.Count>1000||Items.Select(x=>x.Id).Distinct().Count()!=Items.Count||Items.Select(x=>x.Path).Distinct().Count()!=Items.Count)throw new InvalidDataException("Invalid canary inventory.");
        foreach(var item in Items)
        {
            if(!Guid.TryParseExact(item.Id,"N",out _)||item.Digest.Length!=64||!item.Digest.All(Uri.IsHexDigit)||!item.Active)throw new InvalidDataException("Canary inventory has incomplete deployment intent; inspect preserved files before recovery.");
            Paths.TargetFolder(Path.GetDirectoryName(item.Path)!,state.Directory);Paths.NoLinks(item.Path);
        }
    }
    public void Apply(MonitoringPolicy policy)
    {
        ValidatePolicy(policy);
        var plan=new List<(CanaryDeployment Item,string Path,string Signature,byte[] Bytes)>();
        foreach(var item in policy.Deployments)
        {
            if(!config.Folders.TryGetValue(item.FolderAlias,out var folder))throw new InvalidDataException("Folder alias is not locally approved: "+item.FolderAlias);
            folder=Paths.TargetFolder(folder,state.Directory);
            if(item.CallbackTokenId!=null&&item.CallbackUrl==null)throw new InvalidDataException("Token URL unresolved.");
            var spec=new CanarySpec(item.FileName,item.FileType,item.CallbackUrl);CanaryTemplates.Validate(spec);
            var path=Path.Combine(folder,CanaryTemplates.FileName(spec));var signature=PrivateState.Hash(JsonSerializer.SerializeToUtf8Bytes(item));
            var existing=Items.SingleOrDefault(x=>x.Id==item.Id);
            if(existing!=null)
            {
                if(!existing.Active||existing.Path!=path||existing.PlanDigest!=signature)throw new InvalidDataException("Deployment identities are immutable; incomplete/changed state preserved.");
                continue;
            }
            if(Path.Exists(path)||File.Exists(path))throw new IOException("Canary deployment would overwrite an existing object.");
            plan.Add((item,path,signature,CanaryTemplates.Render(spec)));
        }
        if(Items.Count+plan.Count>1000)throw new InvalidDataException("Local canary limit exceeded.");
        foreach(var entry in plan)
        {
            var pending=new Canary(entry.Item.Id,entry.Path,PrivateState.Hash(entry.Bytes),entry.Signature,false,entry.Bytes.Length,0);
            Items.Add(pending);state.Save("canaries.json",Items);
            using(var output=Native.FileAt(entry.Path,true)){output.Write(entry.Bytes);output.Flush(true);}
            var info=new FileInfo(entry.Path);
            Items[^1]=pending with{Active=true,ModifiedTicks=info.LastWriteTimeUtc.Ticks};state.Save("canaries.json",Items);
        }
        // Removing a policy row never removes a file or its monitoring inventory.
    }
    public IEnumerable<(string Path,string Operation)> CheckStartup()
    {
        foreach(var item in Items)
        {
            string? issue=null;
            try{using var stream=Native.FileAt(item.Path,false);if(Native.HashBounded(stream,16*1024*1024)!=item.Digest)issue="Canary content differs from baseline";}
            catch(Exception ex){issue="Canary unavailable: "+ex.GetType().Name;}
            if(issue!=null)yield return(item.Path,issue);
        }
    }
    public void ValidatePolicy(MonitoringPolicy policy)
    {
        if(!policy.IsValid())throw new InvalidDataException("Invalid managed policy.");
        if(policy.AutomaticResponse.Enabled&&(!config.AllowAutomaticProcessStop||!Platform.SupportsAutomatic(policy.AutomaticResponse)))
            throw new InvalidDataException(Platform.Name+" automatic response requires local approval and supported attributed triggers. Linux excludes delete/permissions; macOS excludes read intent.");
    }
    private readonly Dictionary<string,string> lastMetadata=[];
    public IEnumerable<(string Path,string Operation)> CheckMetadata()
    {
        var verification=new List<BaitVerification>(Items.Count);
        foreach(var item in Items)
        {
            string status;
            try
            {
                var path=Paths.NoLinks(item.Path);var attributes=File.GetAttributes(path);
                if((attributes&(FileAttributes.Directory|FileAttributes.ReparsePoint))!=0){status="Canary replaced by unsupported object";verification.Add(BaitVerification.Missing);}
                else{var file=new FileInfo(path);status=file.Length!=item.Length||file.LastWriteTimeUtc.Ticks!=item.ModifiedTicks?"Canary metadata differs from baseline":"Baseline";verification.Add(status=="Baseline"?BaitVerification.Healthy:BaitVerification.Changed);}
            }
            catch(FileNotFoundException){status="Canary missing";verification.Add(BaitVerification.Missing);}
            catch(DirectoryNotFoundException){status="Canary missing";verification.Add(BaitVerification.Missing);}
            catch(Exception ex){status="Canary inaccessible: "+ex.GetType().Name;verification.Add(BaitVerification.Unknown);}
            var previous=lastMetadata.GetValueOrDefault(item.Path,"Baseline");lastMetadata[item.Path]=status;
            if(status!=previous)yield return(item.Path,status=="Baseline"?"Canary metadata returned to baseline (content not reverified)":status);
        }
        ProtectionEvidence=LinuxProtectionStatus.Summarize(verification,DateTimeOffset.UtcNow);
    }
}
