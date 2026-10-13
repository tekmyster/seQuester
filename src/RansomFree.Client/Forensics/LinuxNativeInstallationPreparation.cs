using System.Security.Cryptography;
using System.Text.Json;

namespace RansomFree.Client.Forensics;

// Explicit root installation only. The request contains a public policy key
// and approved target names, never the ordinary sensor's network credential.
// Directories and package bytes are staged by the installer before this call.
internal static class LinuxNativeInstallationPreparation
{
    private sealed record Request(int Version,string SensorId,string Server,string PublicKeyBase64,uint ServiceUid,uint ServiceGroup,
        string PackageDirectory,LinuxNativeInstallation.Member[] Members,string[] TargetPaths);
    internal static string Prepare(string requestPath)
    {
        if(!LinuxNativeInstallation.CanonicalPath(requestPath))throw new ArgumentException("Canonical root-owned request required");
        using var input=LinuxProtectedDirectory.OpenRoot(Path.GetDirectoryName(requestPath)!);input.RequirePrivate();
        var bytes=input.Read(Path.GetFileName(requestPath),65536).Bytes;
        using(var document=JsonDocument.Parse(bytes))
        {
            static void Unique(JsonElement node)
            {
                if(node.ValueKind==JsonValueKind.Object)
                {var names=new HashSet<string>(StringComparer.Ordinal);foreach(var property in node.EnumerateObject()){if(!names.Add(property.Name))throw new InvalidDataException("Duplicate installation request field");Unique(property.Value);}}
                else if(node.ValueKind==JsonValueKind.Array)foreach(var child in node.EnumerateArray())Unique(child);
            }
            Unique(document.RootElement);
        }
        var request=JsonSerializer.Deserialize<Request>(bytes,new JsonSerializerOptions{UnmappedMemberHandling=System.Text.Json.Serialization.JsonUnmappedMemberHandling.Disallow})??throw new InvalidDataException("Missing installation request");
        if(request.Version is not (1 or 2 or 3 or 4 or 5)||request.TargetPaths is not {Length:>=1 and <=32}||request.TargetPaths.Distinct(StringComparer.Ordinal).Count()!=request.TargetPaths.Length)
            throw new InvalidDataException("Explicit bounded unique native target paths required");
        const string privatePath="/var/lib/sequester-native",channelPath="/run/sequester-native",exportPath="/var/lib/sequester-native-export";
        var config=new LinuxNativeInstallation.Configuration(1,true,request.SensorId,request.Server,request.PublicKeyBase64,request.ServiceUid,request.ServiceGroup,
            request.PackageDirectory,new string('0',64),privatePath,channelPath,exportPath);
        LinuxNativeInstallation.Validate(config);
        if(!request.PackageDirectory.StartsWith("/opt/sequester-native/releases/",StringComparison.Ordinal))throw new InvalidDataException("Native package must belong to a staged release");
        var runningKernel=File.ReadAllText("/proc/sys/kernel/osrelease").Trim();string runningBtf;
        using(var btf=File.OpenRead("/sys/kernel/btf/vmlinux"))runningBtf=Convert.ToHexString(SHA256.HashData(btf));
        var profile=LinuxNativeInstallation.RequireProfile(runningKernel,runningBtf,request.Version);
        using var configuration=LinuxProtectedDirectory.OpenRoot(LinuxNativeCompanionService.ConfigurationDirectory);configuration.RequirePrivate();configuration.RequireQualifiedLocalExt4();
        using var package=LinuxProtectedDirectory.OpenRoot(request.PackageDirectory);package.RequirePrivate();var mount=package.RequireQualifiedLocalExt4();
        using var state=LinuxProtectedDirectory.OpenRoot(privatePath);state.RequirePrivate();state.RequireQualifiedLocalExt4();
        using var channel=LinuxProtectedDirectory.OpenRoot(channelPath,request.ServiceGroup);
        using var export=LinuxProtectedDirectory.OpenRoot(exportPath,request.ServiceGroup);
        if(configuration.Names(256).Length!=0||package.Names(256).Any(n=>n is "manifest.json" or "package-update.lock"))
            throw new InvalidOperationException("Existing installation/package metadata retained; preparation never overwrites an installation");
        var targets=new List<LinuxProtectedDirectory.MonitoredTarget>();var members=new List<LinuxProtectedDirectory.RetainedPackageFile>();
        try
        {
            foreach(var target in request.TargetPaths)targets.Add(LinuxProtectedDirectory.OpenMonitoredTarget(target));
            var manifest=new LinuxNativeInstallation.Manifest(request.Version,profile.Kernel,"x64",profile.BtfSha256,"sq_actor_lease",2,160,request.Version switch{3 or 4 or 5=>4u,2=>3u,_=>2u},request.Version switch{3 or 4 or 5=>8u,2=>7u,_=>6u},4194304,4,request.Members,
                targets.Select(t=>new LinuxNativeInstallation.Target(t.Path,t.Target.Device,t.Target.Inode)).ToArray());
            LinuxNativeInstallation.Validate(manifest);
            LinuxNativeInstallation.RequireModule(manifest);
            foreach(var entry in manifest.Members)
            {
                var file=package.OpenPackageFile(entry.Name,checked((int)entry.Size),entry.Role=="loader");members.Add(file);file.RequireMount(mount);
                if(file.File.Size!=(ulong)entry.Size||file.Sha256()!=entry.Sha256)throw new InvalidDataException("Held native package member differs from approved size/hash");package.RequirePackagePath(entry.Name,file);
            }
            foreach(var target in targets)target.RequireCurrent();
            var manifestBytes=JsonSerializer.SerializeToUtf8Bytes(manifest);config=config with{ManifestSha256=Convert.ToHexString(SHA256.HashData(manifestBytes))};
            // Root-only parents have been held/verified. These create-new,
            // fsynced writes preserve partial failure evidence and never replace.
            EvidenceDurability.SaveNew(Path.Combine(request.PackageDirectory,"package-update.lock"),[]);
            EvidenceDurability.SaveNew(Path.Combine(request.PackageDirectory,"manifest.json"),manifestBytes);
            EvidenceDurability.SaveNew(Path.Combine(LinuxNativeCompanionService.ConfigurationDirectory,"installation-update.lock"),[]);
            EvidenceDurability.SaveNew(Path.Combine(LinuxNativeCompanionService.ConfigurationDirectory,"installation.json"),JsonSerializer.SerializeToUtf8Bytes(config));
            using var admitted=LinuxNativePackageAdmission.Open(LinuxNativeCompanionService.ConfigurationDirectory);
            using var admittedTargets=LinuxNativeTargetAdmission.Open(manifest.Targets);
            return JsonSerializer.Serialize(new{Prepared=true,NativeActivation=false,ConfigurationDirectory=LinuxNativeCompanionService.ConfigurationDirectory,config.SensorId,config.Server,config.ManifestSha256,TargetCount=targets.Count,
                Scope="New root installation admitted; no service start, module load, target hashing or evidence deletion"});
        }
        finally{foreach(var member in members)member.Dispose();foreach(var target in targets)target.Dispose();}
    }
}
