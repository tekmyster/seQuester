using System.ComponentModel;
using System.Security.Cryptography;
using System.Text.Json;
using RansomFree.Client.Forensics;

internal static class NativePackageAdmissionChecks
{
    private const UnixFileMode Private=UnixFileMode.UserRead|UnixFileMode.UserWrite;
    internal static void Run(string root)
    {
        if(!OperatingSystem.IsLinux()||Directory.Exists(root))throw new ArgumentException("Fresh Linux package admission fixture required");
        Directory.CreateDirectory(root,Private|UnixFileMode.UserExecute);using var key=RSA.Create(3072);
        var checks=new List<string>();void Check(bool ok,string label){if(!ok)throw new Exception(label);checks.Add(label);}
        void Reject(Action action,string label){try{action();}catch(Exception e)when(e is IOException or InvalidDataException or Win32Exception or InvalidOperationException){Check(true,label);return;}throw new Exception("Accepted: "+label);}
        void Save(string path,byte[] bytes,UnixFileMode mode=Private){File.WriteAllBytes(path,bytes);File.SetUnixFileMode(path,mode);}
        (string Config,string Package,LinuxNativeInstallation.Configuration Definition,LinuxNativeInstallation.Manifest Manifest) Create(string name)
        {
            var b=Path.Combine(root,name);var config=Path.Combine(b,"config");var package=Path.Combine(b,"package");
            Directory.CreateDirectory(b,Private|UnixFileMode.UserExecute);Directory.CreateDirectory(config,Private|UnixFileMode.UserExecute);Directory.CreateDirectory(package,Private|UnixFileMode.UserExecute);
            var bytes=new byte[]{1,3,5,7};var hash=Convert.ToHexString(SHA256.HashData(bytes));
            var members=new[]{new LinuxNativeInstallation.Member("loader","loader",4,hash),new("lease.bpf.o","object",4,hash),new("sq_actor_lease.ko","module",4,hash),new("libqualified.so.1","library",4,hash)};
            var manifest=new LinuxNativeInstallation.Manifest(1,LinuxNativeInstallation.QualifiedKernel,"x64",LinuxNativeInstallation.QualifiedBtfSha256,"sq_actor_lease",2,160,2,6,4194304,4,members,[new("/srv/definition-only-target.txt",2049,42)]);
            var manifestBytes=JsonSerializer.SerializeToUtf8Bytes(manifest);Save(Path.Combine(package,"manifest.json"),manifestBytes);
            foreach(var member in members)Save(Path.Combine(package,member.Name),bytes,Private|(member.Role=="loader"?UnixFileMode.UserExecute:0));
            Save(Path.Combine(package,"package-update.lock"),[]);Save(Path.Combine(config,"installation-update.lock"),[]);
            var definition=new LinuxNativeInstallation.Configuration(1,true,"11111111111111111111111111111111","https://qualification.invalid/",Convert.ToBase64String(key.ExportSubjectPublicKeyInfo()),65534,65534,package,Convert.ToHexString(SHA256.HashData(manifestBytes)),Path.Combine(b,"private"),Path.Combine(b,"channel"),Path.Combine(b,"exports"));
            Save(Path.Combine(config,"installation.json"),JsonSerializer.SerializeToUtf8Bytes(definition));return(config,package,definition,manifest);
        }
        var valid=Create("valid");
        var read=LinuxNativeInstallation.ReadDefinition(valid.Config);Check(read.Configuration==valid.Definition&&read.ConfigurationFile.Uid==0&&read.ManifestFile.Uid==0,"same-descriptor root definition matches exact sensor, server and manifest pin");
        LinuxProtectedDirectory.MountIdentity? configurationMount=null,packageMount=null;
        using(var admitted=LinuxNativePackageAdmission.Open(valid.Config))
        {
            admitted.RequireCurrent();Check(admitted.Definition.Manifest.Members.Length==4,"actual kernel/BTF and four retained member hashes admitted without native activation");
            configurationMount=admitted.ConfigurationMount;packageMount=admitted.PackageMount;
            Check(configurationMount.Type=="ext4"&&configurationMount==packageMount&&configurationMount.MountId>0&&configurationMount.DeviceMajor>0,"admitted configuration and package leases retain exact actual local ext4 mount identity");
            var copy=admitted.Definition;copy.Manifest.Members[0]=copy.Manifest.Members[0] with{Sha256=new string('0',64)};
            Check(admitted.Definition.Manifest.Members[0].Sha256==valid.Manifest.Members[0].Sha256,"returned definition cannot mutate held package authority");
            Reject(()=>{using var second=LinuxNativePackageAdmission.Open(valid.Config);},"second package/config owner refused while lifetime lease held");
            admitted.RequireCurrent();Check(true,"failed second admission leaves original owner current");
            using var lifetime=admitted.HoldNativeLifetime();
            Reject(admitted.Dispose,"live native hold prevents package admission disposal");
            Reject(()=>{using var secondHold=admitted.HoldNativeLifetime();},"one native owner per admitted package lifetime");
            admitted.RequireCurrent();Check(true,"refused disposal retains package handles and update leases");
            lifetime.Dispose();using var nextHold=admitted.HoldNativeLifetime();
            Check(true,"a returned volatile hold permits a new explicit owner without restoring authority from disk");
        }
        using(var unsupported=LinuxProtectedDirectory.OpenRoot("/proc"))
            Reject(()=>unsupported.RequireQualifiedLocalExt4(),"actual unsupported procfs mount cannot supply native package lease authority");
        using(var next=LinuxNativePackageAdmission.Open(valid.Config)){next.RequireCurrent();Check(true,"package can be admitted after first owner actually closes its leases");}
        var mutation=Create("mutation");
        using(var admitted=LinuxNativePackageAdmission.Open(mutation.Config))
        {
            File.Move(Path.Combine(mutation.Package,"loader"),Path.Combine(mutation.Package,"original-loader-retained"));Save(Path.Combine(mutation.Package,"loader"),[2,4,6,8],Private|UnixFileMode.UserExecute);
            Reject(admitted.RequireCurrent,"path replacement after hashing invalidates package before any loader/module action");
            Check(File.ReadAllBytes(Path.Combine(mutation.Package,"original-loader-retained")).SequenceEqual(new byte[]{1,3,5,7}),"invalidated package retains original executable bytes in fixture evidence");
        }
        var disabled=Create("disabled");Save(Path.Combine(disabled.Config,"installation.json"),JsonSerializer.SerializeToUtf8Bytes(disabled.Definition with{Enabled=false}));
        Reject(()=>{using var _=LinuxNativePackageAdmission.Open(disabled.Config);},"default-disabled installation cannot admit package lifetime");
        var wrongBytes=Create("wrong-bytes");Save(Path.Combine(wrongBytes.Package,"lease.bpf.o"),[8,6,4,2]);
        Reject(()=>{using var _=LinuxNativePackageAdmission.Open(wrongBytes.Config);},"same-sized different package bytes fail SHA256 admission");
        var wrongManifest=Create("wrong-manifest");Save(Path.Combine(wrongManifest.Package,"manifest.json"),JsonSerializer.SerializeToUtf8Bytes(wrongManifest.Manifest with{NativeLeases=5}));
        Reject(()=>{using var _=LinuxNativePackageAdmission.Open(wrongManifest.Config);},"changed package manifest fails configuration hash pin");
        var wrongSize=Create("wrong-size");Save(Path.Combine(wrongSize.Package,"lease.bpf.o"),[1,3,5]);
        Reject(()=>{using var _=LinuxNativePackageAdmission.Open(wrongSize.Config);},"shorter package file fails declared size before execution");
        var readable=Create("public-package");File.SetUnixFileMode(readable.Package,Private|UnixFileMode.UserExecute|UnixFileMode.GroupRead|UnixFileMode.GroupExecute);
        Reject(()=>{using var _=LinuxNativePackageAdmission.Open(readable.Config);},"group-visible privileged package root refused");
        var executable=Create("executable-library");File.SetUnixFileMode(Path.Combine(executable.Package,"libqualified.so.1"),Private|UnixFileMode.UserExecute);
        Reject(()=>{using var _=LinuxNativePackageAdmission.Open(executable.Config);},"library role cannot silently accept executable mode");
        var configChanged=Create("config-changed");using(var admitted=LinuxNativePackageAdmission.Open(configChanged.Config))
        {
            Save(Path.Combine(configChanged.Config,"installation.json"),JsonSerializer.SerializeToUtf8Bytes(configChanged.Definition with{ServiceUid=65533}));
            Reject(admitted.RequireCurrent,"service-identity configuration change invalidates existing admission");
        }
        foreach(var name in new[]{"manifest-rewrite","manifest-replace","manifest-public","config-replace","config-public"})
        {
            var item=Create(name);using var admitted=LinuxNativePackageAdmission.Open(item.Config);
            admitted.RequireCurrent();
            if(name=="manifest-rewrite")Save(Path.Combine(item.Package,"manifest.json"),JsonSerializer.SerializeToUtf8Bytes(item.Manifest with{NativeLeases=5}));
            if(name=="manifest-replace"){File.Move(Path.Combine(item.Package,"manifest.json"),Path.Combine(item.Package,"manifest-original.json"));Save(Path.Combine(item.Package,"manifest.json"),JsonSerializer.SerializeToUtf8Bytes(item.Manifest));}
            if(name=="manifest-public")File.SetUnixFileMode(Path.Combine(item.Package,"manifest.json"),Private|UnixFileMode.GroupRead);
            if(name=="config-replace"){File.Move(Path.Combine(item.Config,"installation.json"),Path.Combine(item.Config,"installation-original.json"));Save(Path.Combine(item.Config,"installation.json"),JsonSerializer.SerializeToUtf8Bytes(item.Definition));}
            if(name=="config-public")File.SetUnixFileMode(Path.Combine(item.Config,"installation.json"),Private|UnixFileMode.GroupRead);
            Reject(admitted.RequireCurrent,"fresh protected definition pin refuses actual "+name+" without parse or stale fallback");
        }
        File.WriteAllText(Path.Combine(root,"RESULTS.json"),JsonSerializer.Serialize(new{Passed=true,Checks=checks.Count,Details=checks,Root=root,ConfigurationMount=configurationMount,PackageMount=packageMount,Scope="Actual Linux root config/package admission and qualified local ext4, kernel/BTF with harmless fixture bytes; targets, ELF execution, module load/unload and installed source remain untested and inactive"}));
        Console.WriteLine(JsonSerializer.Serialize(new{Passed=true,Checks=checks.Count,Root=root}));
    }
}
