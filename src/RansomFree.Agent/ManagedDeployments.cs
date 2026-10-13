using System.Security.Cryptography;
using System.Text.Json;
using RansomFree;
using RansomFree.Contracts;

// Folder authorization is local, never supplied by the management policy.
internal static class ManagedDeployments
{
    public static void Apply(string dataDirectory,CanaryMonitor monitor,MonitoringPolicy policy)
    {
        if(policy.Deployments.Length==0)return;
        var config=Path.Combine(dataDirectory,"deployment-folders.json");
        if(!File.Exists(config) || new FileInfo(config).Length>32768)
            throw new InvalidDataException("Local deployment folder approvals are missing or too large.");
        var folders=JsonSerializer.Deserialize<Dictionary<string,string>>(File.ReadAllText(config))??throw new InvalidDataException("Invalid folder approvals.");
        if(folders.Count>100)throw new InvalidDataException("Too many folder approvals.");
        var plan=new List<(string Path,CanarySpec Spec,Canary? Existing)>();
        foreach(var item in policy.Deployments)
        {
            if(!folders.TryGetValue(item.FolderAlias,out var folder))throw new InvalidDataException("Deployment folder alias has not been approved locally: "+item.FolderAlias);
            folder=ValidateFolder(folder,dataDirectory);
            var signature=Convert.ToHexString(SHA256.HashData(JsonSerializer.SerializeToUtf8Bytes(item)));
            if(item.CallbackTokenId!=null && item.CallbackUrl==null)throw new InvalidDataException("Tokenized deployment is missing its resolved receiver URL.");
            var spec=new CanarySpec(item.FileName,item.FileType,item.CallbackUrl){ManagedId=item.Id,ManagedSignature=signature};
            CanaryTemplates.Validate(spec);
            var path=Path.Combine(folder,CanaryTemplates.FileName(spec));
            var existing=monitor.Settings.Canaries.SingleOrDefault(x=>x.ManagedId==item.Id);
            if(existing!=null)
            {
                if(existing.ManagedSignature!=signature || !existing.Path.Equals(path,StringComparison.OrdinalIgnoreCase))throw new InvalidDataException("Deployment IDs are immutable. Create a new deployment for changed content or location.");
                if(!File.Exists(path) || (File.GetAttributes(path)&FileAttributes.ReparsePoint)!=0 || CanaryMonitor.Hash(path)!=existing.Hash)
                    throw new IOException("Managed canary is missing or changed; evidence is preserved and automatic replacement is disabled.");
            }
            else if(File.Exists(path) || Directory.Exists(path))throw new IOException("Deployment would overwrite an existing path; no file was replaced.");
            plan.Add((path,spec,existing));
        }
        if(plan.Select(x=>x.Path).Distinct(StringComparer.OrdinalIgnoreCase).Count()!=plan.Count)throw new InvalidDataException("Deployment paths overlap.");
        if(monitor.Settings.Canaries.Count+plan.Count(x=>x.Existing==null)>1000)throw new InvalidDataException("Endpoint canary capacity reached.");
        // Validate the full plan first. Persist each successful file; a later failure is retried without overwriting it.
        var changed=false;
        try
        {
            foreach(var item in plan)
            {
                using var lease=DeploymentPathLease.Acquire(Path.GetDirectoryName(item.Path)!,item.Existing==null?null:item.Path);
                ValidateFolder(Path.GetDirectoryName(item.Path)!,dataDirectory);
                if(item.Existing==null){changed=true;monitor.Deploy(Path.GetDirectoryName(item.Path)!,[item.Spec]);}
                else
                {
                    if(CanaryMonitor.Hash(item.Path)!=item.Existing.Hash)throw new IOException("Managed canary changed while applying the plan; preserved for investigation.");
                    if(!AuditPolicy.IsAttached(item.Path)){monitor.EnableAuditing();AuditPolicy.Attach(item.Path);}
                }
            }
        }
        finally{if(changed)monitor.Start();}
    }
    private static string ValidateFolder(string folder,string dataDirectory)
    {
        if(string.IsNullOrWhiteSpace(folder) || !Path.IsPathFullyQualified(folder) || folder.StartsWith(@"\\") || folder.Contains('%'))throw new InvalidDataException("Approve an explicit local absolute data folder.");
        folder=Path.GetFullPath(folder).TrimEnd(Path.DirectorySeparatorChar);
        if(!Directory.Exists(folder) || Path.GetPathRoot(folder)?.TrimEnd('\\')==folder)throw new IOException("Deployment requires an existing non-root data folder.");
        foreach(var protectedFolder in new[]{Environment.GetFolderPath(Environment.SpecialFolder.Windows),Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles),Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86),dataDirectory})
            if(!string.IsNullOrEmpty(protectedFolder) && (folder.Equals(protectedFolder.TrimEnd('\\'),StringComparison.OrdinalIgnoreCase) || folder.StartsWith(protectedFolder.TrimEnd('\\')+"\\",StringComparison.OrdinalIgnoreCase)))throw new IOException("System, installation, and agent-state folders cannot be deployment targets.");
        for(string? ancestor=folder;ancestor!=null;ancestor=Path.GetDirectoryName(ancestor))
            if((File.GetAttributes(ancestor)&FileAttributes.ReparsePoint)!=0)throw new IOException("Deployment path traverses a link or junction.");
        return folder;
    }
}
