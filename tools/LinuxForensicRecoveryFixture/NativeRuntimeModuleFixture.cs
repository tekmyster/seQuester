using System.Security.Cryptography;
using System.Diagnostics;
using System.Text.Json;
using RansomFree.Client.Forensics;

// Test installer only: it stages independently supplied qualification artifacts
// and the ephemeral fixture public key. The product never creates that key.
internal sealed class NativeRuntimeModuleFixture:IDisposable
{
    internal LinuxNativeModuleOwner Owner {get;}
    private readonly LinuxNativePackageAdmission package;
    private readonly LinuxNativeTargetAdmission targets;
    internal static string Stage(OwnedRuntimeNativeChecks.Config input,byte[] publicKey)
    {
        if(!OperatingSystem.IsLinux())throw new PlatformNotSupportedException("Actual Linux qualification only");
        const UnixFileMode priv=UnixFileMode.UserRead|UnixFileMode.UserWrite;
        var parent=Path.GetDirectoryName(input.Root)!;var configuration=Path.Combine(parent,"installation");var packageDirectory=Path.Combine(parent,"native-package");
        if(Directory.Exists(configuration)||Directory.Exists(packageDirectory))throw new IOException("Fresh fixture installation required");
        foreach(var p in new[]{configuration,packageDirectory})Directory.CreateDirectory(p,priv|UnixFileMode.UserExecute);
        void Save(string path,byte[] bytes,UnixFileMode mode=priv){File.WriteAllBytes(path,bytes);File.SetUnixFileMode(path,mode);}
        var members=new List<LinuxNativeInstallation.Member>();
        // Resolve dependencies of the exact previously qualified executable.
        // The old LD_LIBRARY_PATH may be absent; do not guess a staging path.
        if(Convert.ToHexString(SHA256.HashData(File.ReadAllBytes(input.Runtime.Launch.Loader)))!="1F59CCC5D7F6899F3588C45E2E673FACD519FA2E9A99DDCEE9E865D264E15374")throw new InvalidDataException("Exact qualified loader required before dependency inspection");
        var start=new ProcessStartInfo("/usr/bin/ldd"){UseShellExecute=false,RedirectStandardOutput=true,RedirectStandardError=true};
        start.Environment.Clear();start.Environment["PATH"]="/usr/bin:/bin";start.Environment["LANG"]="C";start.Environment["LD_LIBRARY_PATH"]=input.Runtime.Launch.LibraryDirectory;
        start.ArgumentList.Add(input.Runtime.Launch.Loader);using var dependency=Process.Start(start)??throw new IOException("Dependency inspection failed");
        var output=dependency.StandardOutput.ReadToEnd();var errors=dependency.StandardError.ReadToEnd();dependency.WaitForExit();
        Save(Path.Combine(parent,"loader-dependencies.txt"),System.Text.Encoding.UTF8.GetBytes(output+errors));
        if(dependency.ExitCode!=0||output.Contains("not found",StringComparison.Ordinal))throw new IOException("Qualified loader dependency unavailable");
        var libraries=output.Split('\n').Select(line=>line.Split(' ',StringSplitOptions.RemoveEmptyEntries|StringSplitOptions.TrimEntries)).Where(parts=>parts.Length>=3&&parts[1]=="=>").ToArray();
        if(!libraries.Any(parts=>parts[0]=="libbpf.so.1")||libraries.Any(parts=>!Path.IsPathFullyQualified(parts[2])))throw new IOException("Explicit resolved loader dependency set required");
        var inputs=new[]{(input.Runtime.Launch.Loader,"loader",Path.GetFileName(input.Runtime.Launch.Loader)),(input.Runtime.Launch.ObjectFile,"object",Path.GetFileName(input.Runtime.Launch.ObjectFile)),
            (Path.Combine(Path.GetDirectoryName(input.Runtime.Launch.Loader)!,"sq_actor_lease.ko"),"module","sq_actor_lease.ko")}.Concat(libraries.Select(parts=>(parts[2],"library",parts[0])));
        foreach(var (path,role,name) in inputs)
        {
            var bytes=File.ReadAllBytes(path);Save(Path.Combine(packageDirectory,name),bytes,priv|(role=="loader"?UnixFileMode.UserExecute:0));
            members.Add(new(name,role,bytes.Length,Convert.ToHexString(SHA256.HashData(bytes))));
        }
        var definitions=input.Runtime.Launch.Targets.Select((path,n)=>new LinuxNativeInstallation.Target(path,input.Runtime.ExpectedTargets[n].Device,input.Runtime.ExpectedTargets[n].Inode)).ToArray();
        var manifest=new LinuxNativeInstallation.Manifest(1,LinuxNativeInstallation.QualifiedKernel,"x64",LinuxNativeInstallation.QualifiedBtfSha256,"sq_actor_lease",2,160,2,6,4194304,4,members.ToArray(),definitions);
        var manifestBytes=JsonSerializer.SerializeToUtf8Bytes(manifest);Save(Path.Combine(packageDirectory,"manifest.json"),manifestBytes);
        Save(Path.Combine(packageDirectory,"package-update.lock"),[]);Save(Path.Combine(configuration,"installation-update.lock"),[]);
        var config=new LinuxNativeInstallation.Configuration(1,true,"11111111111111111111111111111111","https://qualification.invalid/",Convert.ToBase64String(publicKey),65534,65534,packageDirectory,Convert.ToHexString(SHA256.HashData(manifestBytes)),input.Root,Path.Combine(parent,"channel"),Path.Combine(parent,"exports"));
        Save(Path.Combine(configuration,"installation.json"),JsonSerializer.SerializeToUtf8Bytes(config));
        return configuration;
    }
    internal NativeRuntimeModuleFixture(OwnedRuntimeNativeChecks.Config input,byte[] publicKey,Action<string>? checkpoint=null)
    {
        var configuration=Stage(input,publicKey);
        package=LinuxNativePackageAdmission.Open(configuration);
        try
        {
            targets=LinuxNativeTargetAdmission.Open(package.Definition.Manifest.Targets);
            try{Owner=checkpoint==null?LinuxNativeModuleOwner.Prepare(package,targets):LinuxNativeModuleOwner.PrepareForQualification(package,targets,checkpoint);}
            catch{targets.Dispose();throw;}
        }
        catch{package.Dispose();throw;}
        Owner.Load();if(Owner.State!="LoadedOwned")throw new IOException("Fixture module did not load");
    }
    internal async Task Close()
    {
        // Busy unload may be retried after the kernel releases final references.
        // It never permits force, a substituted task or presumed process exit.
        while(Owner.State!="UnloadVerifiedAbsent")
        {
            await Owner.StopSourceAndUnloadAsync();
            if(Owner.State!="UnloadVerifiedAbsent")await Task.Delay(100);
        }
        File.WriteAllBytes(Path.Combine(Path.GetDirectoryName(package.Definition.Configuration.PrivateDirectory)!,"module-owner-final.json"),
            JsonSerializer.SerializeToUtf8Bytes(new{Owner.OwnerId,Owner.State,Owner.EvidenceDirectory,Owner.LoadReturn,Owner.UnloadReturn,RuntimeId=Owner.RegisteredSource!.RuntimeId}));
    }
    public void Dispose(){Owner.Dispose();targets.Dispose();package.Dispose();}
}
