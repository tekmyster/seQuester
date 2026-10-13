using System.Security.Cryptography;
using System.Text.Json;

namespace RansomFree.Client.Forensics;

// Reuses only the already validated canonical definition. Every check still
// reads protected configuration/manifest bytes from fresh descriptors. This
// contains no policy, activation, readiness, target or map observations.
internal sealed class LinuxNativeDefinitionPin
{
    private readonly string packagePath,configurationSha256,manifestSha256;
    private readonly byte[] configurationBytes,manifestBytes;
    private readonly LinuxProtectedDirectory.Identity configurationIdentity,manifestIdentity;
    internal LinuxNativeDefinitionPin(LinuxNativeInstallation.Definition definition)
    {
        LinuxNativeInstallation.Validate(definition.Configuration);
        LinuxNativeInstallation.Validate(definition.Manifest);
        configurationBytes=JsonSerializer.SerializeToUtf8Bytes(definition.Configuration);
        manifestBytes=JsonSerializer.SerializeToUtf8Bytes(definition.Manifest);
        configurationSha256=definition.ConfigurationSha256;
        manifestSha256=definition.Configuration.ManifestSha256;
        if(Convert.ToHexString(SHA256.HashData(configurationBytes))!=configurationSha256||
            Convert.ToHexString(SHA256.HashData(manifestBytes))!=manifestSha256)
            throw new InvalidDataException("Validated definition does not match its exact admitted canonical bytes");
        packagePath=definition.Configuration.PackageDirectory;
        configurationIdentity=definition.ConfigurationFile;manifestIdentity=definition.ManifestFile;
    }
    internal void RequireCurrent(string configurationPath,LinuxProtectedDirectory.MountIdentity configurationMount,
        LinuxProtectedDirectory.MountIdentity packageMount)
    {
        using var configuration=LinuxProtectedDirectory.OpenRoot(configurationPath);configuration.RequirePrivate();
        if(configuration.RequireQualifiedLocalExt4()!=configurationMount)throw new IOException("Configuration mount differs from admission");
        var config=configuration.Read("installation.json",65536);
        // Refuse changed configuration before using its prior package path.
        RequireConfiguration(config);
        using var package=LinuxProtectedDirectory.OpenRoot(packagePath);package.RequirePrivate();
        if(package.RequireQualifiedLocalExt4()!=packageMount)throw new IOException("Package mount differs from admission");
        RequireObserved(config,package.Read("manifest.json",65536));
    }
    private void RequireConfiguration(LinuxProtectedDirectory.Captured config)
    {
        if(config.File!=configurationIdentity||(config.File.Mode&0x3f)!=0||
            Convert.ToHexString(SHA256.HashData(config.Bytes))!=configurationSha256||
            !config.Bytes.AsSpan().SequenceEqual(configurationBytes))
            throw new IOException("Admitted configuration bytes or identity changed; source must stop and revalidate");
    }
    // Also exercised without native descriptors to validate substitution and
    // mutation refusal. Production callers obtain both values through Read.
    internal void RequireObserved(LinuxProtectedDirectory.Captured config,LinuxProtectedDirectory.Captured manifest)
    {
        RequireConfiguration(config);
        if(manifest.File!=manifestIdentity||(manifest.File.Mode&0x3f)!=0||
            Convert.ToHexString(SHA256.HashData(manifest.Bytes))!=manifestSha256||
            !manifest.Bytes.AsSpan().SequenceEqual(manifestBytes))
            throw new IOException("Admitted manifest bytes or identity changed; source must stop and revalidate");
    }
}
