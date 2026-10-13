using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text.Json;
using Microsoft.Win32.SafeHandles;

namespace RansomFree.Client.Forensics;

// Only admits package/configuration bytes. This does not admit targets, load a
// module, create a controller, or start a source. The installed owner must hold
// this object until its actual loader and native lifetime have finished.
internal sealed class LinuxNativePackageAdmission:IDisposable
{
    private readonly object gate=new();
    private readonly string configurationPath;
    private readonly LinuxProtectedDirectory configuration,package;
    private readonly LinuxProtectedDirectory.RetainedPackageFile configurationLock,packageLock;
    private readonly Dictionary<string,LinuxProtectedDirectory.RetainedPackageFile> members;
    private readonly LinuxNativeInstallation.Definition definition;
    private readonly LinuxNativeDefinitionPin definitionPin;
    internal LinuxProtectedDirectory.MountIdentity ConfigurationMount {get;}
    internal LinuxProtectedDirectory.MountIdentity PackageMount {get;}
    private bool disposed;
    private LinuxNativeAdmissionHold? nativeHold;
    private LinuxNativePackageAdmission(string path,LinuxProtectedDirectory configuration,LinuxProtectedDirectory package,
        LinuxProtectedDirectory.RetainedPackageFile configurationLock,LinuxProtectedDirectory.RetainedPackageFile packageLock,
        Dictionary<string,LinuxProtectedDirectory.RetainedPackageFile> members,LinuxNativeInstallation.Definition definition,
        LinuxProtectedDirectory.MountIdentity configurationMount,LinuxProtectedDirectory.MountIdentity packageMount)
    {configurationPath=path;this.configuration=configuration;this.package=package;this.configurationLock=configurationLock;this.packageLock=packageLock;this.members=members;this.definition=definition;definitionPin=new(definition);ConfigurationMount=configurationMount;PackageMount=packageMount;}
    internal static LinuxNativePackageAdmission Open(string configurationPath)
    {
        if(!OperatingSystem.IsLinux()||RuntimeInformation.ProcessArchitecture!=Architecture.X64)throw new PlatformNotSupportedException("Native package profile requires qualified Linux x64");
        LinuxProtectedDirectory? root=null,package=null;LinuxProtectedDirectory.RetainedPackageFile? rootLock=null,packageLock=null;
        var members=new Dictionary<string,LinuxProtectedDirectory.RetainedPackageFile>(StringComparer.Ordinal);
        try
        {
            root=LinuxProtectedDirectory.OpenRoot(configurationPath);root.RequirePrivate();
            var rootMount=root.RequireQualifiedLocalExt4();
            rootLock=root.OpenPackageFile("installation-update.lock",1);rootLock.RequireMount(rootMount);rootLock.AcquireUpdateLease();
            var definition=LinuxNativeInstallation.ReadDefinition(configurationPath);
            if(!definition.Configuration.Enabled)throw new InvalidOperationException("Native installation is disabled");
            package=LinuxProtectedDirectory.OpenRoot(definition.Configuration.PackageDirectory);package.RequirePrivate();
            var packageMount=package.RequireQualifiedLocalExt4();
            packageLock=package.OpenPackageFile("package-update.lock",1);packageLock.RequireMount(packageMount);packageLock.AcquireUpdateLease();
            var reread=LinuxNativeInstallation.ReadDefinition(configurationPath);
            if(definition.ConfigurationSha256!=reread.ConfigurationSha256||definition.ConfigurationFile!=reread.ConfigurationFile||definition.ManifestFile!=reread.ManifestFile)
                throw new IOException("Installation changed during package lease acquisition");
            if(File.ReadAllText("/proc/sys/kernel/osrelease").Trim()!=definition.Manifest.Kernel)throw new PlatformNotSupportedException("Running kernel differs from admitted package");
            using(var btf=File.OpenRead("/sys/kernel/btf/vmlinux"))
                if(Convert.ToHexString(SHA256.HashData(btf))!=definition.Manifest.BtfSha256)throw new PlatformNotSupportedException("Running BTF differs from admitted package");
            foreach(var entry in definition.Manifest.Members)
            {
                var file=package.OpenPackageFile(entry.Name,checked((int)entry.Size),entry.Role=="loader");members.Add(entry.Name,file);
                file.RequireMount(packageMount);
                if(file.File.Size!=(ulong)entry.Size||file.Sha256()!=entry.Sha256)throw new IOException("Opened native member differs from pinned size/hash");
                package.RequirePackagePath(entry.Name,file);
            }
            root.RequirePackagePath("installation-update.lock",rootLock);package.RequirePackagePath("package-update.lock",packageLock);
            return new(configurationPath,root,package,rootLock,packageLock,members,definition,rootMount,packageMount);
        }
        catch
        {
            foreach(var member in members.Values)member.Dispose();packageLock?.Dispose();rootLock?.Dispose();package?.Dispose();root?.Dispose();throw;
        }
    }
    internal LinuxNativeInstallation.Definition Definition
    {get{lock(gate){ObjectDisposedException.ThrowIf(disposed,this);return JsonSerializer.Deserialize<LinuxNativeInstallation.Definition>(JsonSerializer.SerializeToUtf8Bytes(definition))!;}}}
    internal void RequireCurrent()
    {
        lock(gate)
        {
            ObjectDisposedException.ThrowIf(disposed,this);
            using var mounts=LinuxProtectedDirectory.BeginMountValidation();
            if(configuration.RequireQualifiedLocalExt4()!=ConfigurationMount||package.RequireQualifiedLocalExt4()!=PackageMount)
                throw new IOException("Native installation filesystem changed");
            configurationLock.RequireMount(ConfigurationMount);packageLock.RequireMount(PackageMount);
            configuration.RequirePackagePath("installation-update.lock",configurationLock);package.RequirePackagePath("package-update.lock",packageLock);
            definitionPin.RequireCurrent(configurationPath,ConfigurationMount,PackageMount);
            foreach(var (name,member) in members){package.RequirePackagePath(name,member);member.RequireMount(PackageMount);}
            mounts.Complete();
        }
    }
    internal LinuxNativeAdmissionHold HoldNativeLifetime()
    {
        lock(gate)
        {
            RequireCurrent();if(nativeHold!=null)throw new InvalidOperationException("Native package lifetime already owned");
            return nativeHold=new(hold=>{lock(gate){if(!ReferenceEquals(nativeHold,hold))throw new InvalidOperationException("Foreign native package hold");nativeHold=null;}});
        }
    }
    internal T WithOwnedModuleDescriptor<T>(Func<SafeFileHandle,T> operation)
    {
        lock(gate)
        {
            RequireCurrent();if(nativeHold==null)throw new InvalidOperationException("Explicit native package lifetime required");
            var entry=definition.Manifest.Members.Single(x=>x.Role=="module");
            return members[entry.Name].WithDescriptor(operation);
        }
    }
    public void Dispose()
    {
        lock(gate)
        {
            if(disposed)return;if(nativeHold!=null)throw new InvalidOperationException("Native module/source must actually close before package admission release");disposed=true;
            foreach(var member in members.Values)member.Dispose();packageLock.Dispose();configurationLock.Dispose();package.Dispose();configuration.Dispose();
        }
    }
}
