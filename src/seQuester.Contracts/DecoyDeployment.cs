namespace RansomFree.Contracts;

public sealed record DecoyDeploymentType(string Id,string Name,string[] Platforms,string Provider,string Status);
public static class DecoyDeploymentCatalog
{
    public static IReadOnlyList<DecoyDeploymentType> Types=>[
        new("V01","Virtual disk",["windows"],"Windows virtual disk","Provider required"),
        new("V02","Directory-backed drive",["windows"],"Windows DOS device lifecycle","Provider required"),
        new("V03","Library link",["windows"],"Windows shell namespace","Provider required"),
        new("V04","Loopback volume",["linux"],"Linux loop and mount broker","Provider required"),
        new("V05","Bind mount",["linux"],"Linux namespace mount broker","Provider required"),
        new("V06","Decoy filesystem",["linux","macos"],"Restricted FUSE adapter","Provider required"),
        new("V07","Disk image",["macos"],"macOS disk image lifecycle","Provider required"),
        new("V08","Labeled virtual volume",["windows","linux","macos"],"Platform volume adapter","Provider required"),
        new("V09","Network share",["windows","linux","macos"],"SMB/NFS/WebDAV service","Provider required"),
        new("V10","Cloud-synced folder",["windows","linux","macos"],"Approved sync-provider adapter","Provider required"),
        new("V11","Container volume",["linux"],"Container/orchestrator adapter","Provider required"),
        new("N01","Registry decoy",["windows"],"Registry lifecycle and sensor","Provider required"),
        new("N02","Named pipe",["windows"],"Restricted pipe service","Provider required"),
        new("N03","FIFO or socket",["linux","macos"],"Restricted IPC service","Provider required"),
        new("N04","Database decoy",["windows","linux"],"Database adapter","Provider required"),
        new("N05","Service endpoint",["windows","linux"],"Restricted protocol listener","Provider required"),
        new("N06","Synthetic credential entry",["windows","linux","macos"],"Synthetic-only config adapter","Provider required"),
        new("N07","Bookmark or shortcut",["windows","linux","macos"],"Approved profile integration","Provider required"),
        new("N08","Object-storage token",["windows","linux"],"Scoped object-storage adapter","Provider required")
    ];
}
public sealed record DecoyDeploymentRequest(string Id,string Type,string Platform,string Target,string Description)
{
    public bool Enabled {get;init;}
}
public sealed record DecoyDeploymentPreview(string Id,string State,bool CanDeploy,string Reason);
public static class DecoyDeploymentPlanner
{
    // Planning cannot create a device, directory, mount, listener or cloud resource.
    // A catalog entry is never treated as an installed provider.
    public static DecoyDeploymentPreview Preview(DecoyDeploymentRequest request)
    {
        if(request==null||!Guid.TryParseExact(request.Id,"N",out _)||request.Target is not {Length:>0 and <=2048}||request.Target.Any(char.IsControl)||request.Description==null||request.Description.Length>1024||request.Description.Any(char.IsControl))throw new ArgumentException("Invalid decoy deployment request.");
        var type=DecoyDeploymentCatalog.Types.SingleOrDefault(x=>x.Id==request.Type);
        if(type==null||!type.Platforms.Contains(request.Platform))throw new ArgumentException("Unsupported decoy type or platform.");
        if(!request.Enabled)return new(request.Id,"Disabled",false,"Deployment is disabled.");
        return new(request.Id,"Provider required",false,"An approved lifecycle provider is required. No resources were created.");
    }
}
