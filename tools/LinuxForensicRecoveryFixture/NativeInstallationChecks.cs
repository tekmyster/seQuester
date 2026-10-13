using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using RansomFree.Client.Forensics;

internal static class NativeInstallationChecks
{
    internal static void Run(string root)
    {
        if(Directory.Exists(root))throw new ArgumentException("Fresh definition fixture directory required");Directory.CreateDirectory(root);
        var checks=new List<string>();void Check(bool ok,string label){if(!ok)throw new Exception(label);checks.Add(label);}
        void Reject(Action action,string label){try{action();}catch(Exception e)when(e is InvalidDataException or CryptographicException){Check(true,label);return;}throw new Exception("Accepted: "+label);}
        using var key=RSA.Create(3072);var hash=new string('A',64);
        var config=new LinuxNativeInstallation.Configuration(1,false,"11111111111111111111111111111111","https://qualification.invalid/",Convert.ToBase64String(key.ExportSubjectPublicKeyInfo()),65534,65534,"/opt/sequester/native",hash,"/var/lib/sequester/private","/run/sequester/channel","/var/lib/sequester/exports");
        LinuxNativeInstallation.Validate(config);Check(!config.Enabled,"configuration explicitly defaults to disabled without changing installed services");
        var encoded=JsonSerializer.SerializeToUtf8Bytes(config);Check(LinuxNativeInstallation.Parse<LinuxNativeInstallation.Configuration>(encoded)==config,"all explicit configuration fields survive exact canonical JSON");
        foreach(var candidate in new[]{config with{Version=2},config with{SensorId="sensor"},config with{Server="http://qualification.invalid/"},config with{ServiceUid=0},config with{ServiceGroup=0},config with{ManifestSha256=hash.ToLowerInvariant()},config with{PackageDirectory="/opt/../etc"},config with{PackageDirectory="/opt//native"},config with{PrivateDirectory=config.PackageDirectory},config with{PrivateDirectory=config.PackageDirectory+"/state"}})
            Reject(()=>LinuxNativeInstallation.Validate(candidate),"configuration refuses unsupported identity/context/pin/root: "+checks.Count);
        using(var weak=RSA.Create(2048))Reject(()=>LinuxNativeInstallation.Validate(config with{PublicKeyBase64=Convert.ToBase64String(weak.ExportSubjectPublicKeyInfo())}),"verification pin refuses weaker RSA key");
        Reject(()=>LinuxNativeInstallation.Validate(config with{PublicKeyBase64=config.PublicKeyBase64+"AA=="}),"verification pin refuses trailing encoded bytes");
        foreach(var suffix in new[]{",\"Version\":1}",",\"Unknown\":true}"})
            Reject(()=>LinuxNativeInstallation.Parse<LinuxNativeInstallation.Configuration>(Encoding.UTF8.GetBytes(Encoding.UTF8.GetString(encoded)[..^1]+suffix)),"canonical configuration rejects duplicate/unknown fields");
        var members=new[]{new LinuxNativeInstallation.Member("loader","loader",1000,hash),new("lease.bpf.o","object",1000,hash),new("sq_actor_lease.ko","module",1000,hash)};
        var manifest=new LinuxNativeInstallation.Manifest(1,LinuxNativeInstallation.QualifiedKernel,"x64",LinuxNativeInstallation.QualifiedBtfSha256,"sq_actor_lease",2,160,2,6,4194304,4,members,[new("/srv/decoys/a.txt",2049,42)]);
        LinuxNativeInstallation.Validate(manifest);Check(true,"exact current device status2/160-byte and controlled-v2/native6 profile accepted as definition only");
        var debian=LinuxNativeInstallation.RequireProfile(manifest.Kernel,manifest.BtfSha256);
        var ubuntu=LinuxNativeInstallation.RequireProfile("6.8.0-134-generic","4A07F657AC332A73329EB46DA423C84EC37525330EA5595CF6FAA01FBBDCB45C");
        Check(debian.ModuleSha256==LinuxNativeModuleOwner.QualifiedModuleSha256&&ubuntu.ModuleSha256!=debian.ModuleSha256,"separate exact kernel/BTF pairs bind distinct benchmarked modules");
        var debianModule=members[2] with{Sha256=debian.ModuleSha256};
        var ubuntuModule=members[2] with{Sha256=ubuntu.ModuleSha256};
        var qualifiedDebian=manifest with{Members=[members[0],members[1],debianModule]};
        var qualifiedUbuntu=manifest with{Kernel=ubuntu.Kernel,BtfSha256=ubuntu.BtfSha256,Members=[members[0],members[1],ubuntuModule]};
        LinuxNativeInstallation.Validate(qualifiedUbuntu);LinuxNativeInstallation.RequireModule(qualifiedUbuntu);
        Check(true,"exact Ubuntu benchmark profile and associated module accepted for installed qualification");
        LinuxNativeInstallation.RequireModule(qualifiedDebian);Check(true,"existing Debian module binding preserved");
        var retentionProfile=LinuxNativeInstallation.RequireProfile(debian.Kernel,debian.BtfSha256,4);
        var retention=qualifiedDebian with{Version=4,ControlVersion=4,NativeSchema=8,Members=[members[0] with{Sha256=retentionProfile.LoaderSha256!},members[1] with{Sha256=retentionProfile.ObjectSha256!},members[2] with{Sha256=retentionProfile.ModuleSha256}]};
        LinuxNativeInstallation.Validate(retention);LinuxNativeInstallation.RequireModule(retention);
        Check(retentionProfile.ModuleSha256!=debian.ModuleSha256,"retention manifest4 binds the exact separately qualified module/BPF bundle");
        Reject(()=>LinuxNativeInstallation.RequireModule(retention with{Members=[retention.Members[0],retention.Members[1],debianModule]}),"retention manifest refuses former module bytes");
        Reject(()=>LinuxNativeInstallation.RequireModule(retention with{Members=[retention.Members[0],members[1],retention.Members[2]]}),"retention manifest refuses unrelated BPF bytes");
        Reject(()=>LinuxNativeInstallation.Validate(retention with{ControlVersion=3}),"retention manifest refuses protocol downgrade");
        Check(JsonSerializer.SerializeToUtf8Bytes(LinuxNativeInstallation.Parse<LinuxNativeInstallation.Manifest>(JsonSerializer.SerializeToUtf8Bytes(retention))).AsSpan().SequenceEqual(JsonSerializer.SerializeToUtf8Bytes(retention)),"retention manifest canonical bytes round trip without protocol fallback");
        var watchProfile=LinuxNativeInstallation.RequireProfile(debian.Kernel,debian.BtfSha256,5);
        var watch=retention with{Version=5,Members=[retention.Members[0] with{Sha256=watchProfile.LoaderSha256!},retention.Members[1] with{Sha256=watchProfile.ObjectSha256!},retention.Members[2] with{Sha256=watchProfile.ModuleSha256}]};
        LinuxNativeInstallation.Validate(watch);LinuxNativeInstallation.RequireModule(watch);
        Check(watchProfile.ObjectSha256!=retentionProfile.ObjectSha256,"watch-first manifest5 binds new separately qualified BPF bytes");
        Reject(()=>LinuxNativeInstallation.RequireModule(watch with{Members=retention.Members}),"watch-first manifest refuses old bundle under new version");
        Reject(()=>LinuxNativeInstallation.RequireModule(watch with{Members=[watch.Members[0],retention.Members[1],watch.Members[2]]}),"watch-first manifest refuses former BPF");
        Reject(()=>LinuxNativeInstallation.RequireModule(watch with{Members=[watch.Members[0],watch.Members[1],retention.Members[2]]}),"watch-first manifest refuses former module");
        Reject(()=>LinuxNativeInstallation.RequireModule(watch with{Version=4}),"new native artifacts cannot substitute into retained manifest4");
        Reject(()=>LinuxNativeInstallation.Validate(watch with{ControlVersion=3}),"watch-first manifest refuses protocol downgrade");
        Reject(()=>LinuxNativeInstallation.RequireModule(watch with{Kernel=ubuntu.Kernel,BtfSha256=ubuntu.BtfSha256}),"watch-first manifest refuses native artifact substitution across platforms");
        Check(JsonSerializer.SerializeToUtf8Bytes(LinuxNativeInstallation.Parse<LinuxNativeInstallation.Manifest>(JsonSerializer.SerializeToUtf8Bytes(watch))).AsSpan().SequenceEqual(JsonSerializer.SerializeToUtf8Bytes(watch)),"watch-first manifest canonical bytes retain exact profile");
        var ubuntuIoProfile=LinuxNativeInstallation.RequireProfile(ubuntu.Kernel,ubuntu.BtfSha256,5);
        var ubuntuIo=watch with{Kernel=ubuntu.Kernel,BtfSha256=ubuntu.BtfSha256,Members=[watch.Members[0] with{Sha256=ubuntuIoProfile.LoaderSha256!},watch.Members[1] with{Sha256=ubuntuIoProfile.ObjectSha256!},watch.Members[2] with{Sha256=ubuntuIoProfile.ModuleSha256}]};
        LinuxNativeInstallation.Validate(ubuntuIo);LinuxNativeInstallation.RequireModule(ubuntuIo);
        Check(ubuntuIoProfile.ModuleSha256!=watchProfile.ModuleSha256,"UbuntuIO manifest5 binds its exact separately qualified6.8 module");
        Reject(()=>LinuxNativeInstallation.RequireModule(ubuntuIo with{Members=watch.Members}),"UbuntuIO refuses Debian native bundle");
        Reject(()=>LinuxNativeInstallation.RequireModule(watch with{Members=ubuntuIo.Members}),"DebianIO refuses Ubuntu native bundle");
        Reject(()=>LinuxNativeInstallation.Validate(ubuntuIo with{ControlVersion=3}),"UbuntuIO refuses protocol downgrade");
        Reject(()=>LinuxNativeInstallation.Validate(ubuntuIo with{BtfSha256=debian.BtfSha256}),"UbuntuIO refuses another kernel BTF");
        Check(LinuxNativeInstallation.Parse<LinuxNativeInstallation.Manifest>(JsonSerializer.SerializeToUtf8Bytes(ubuntuIo)).NativeSchema==8,"UbuntuIO preserves explicit schema8 canonical definition");
        foreach(var historical in new[]{
            (Kernel:"6.12.95+deb13-amd64",Btf:"8C82D3E61CD10679F25E6C3F46D14C839CC346AF90465F49F580E26430085397",RejectedModule:"04144A97486F69886ADD6BCC29CECCD805113DD38E88262E0598696933B7988C"),
            (Kernel:"6.12.86+deb13-amd64",Btf:"23FEC9F8D759721489BA879C5383B23732E44B2E52389DCDC7FC77A8A9A09A83",RejectedModule:"6A3054183C0E66C655C560CB1391A4C8E2338FFBB23B30C00B1CD35D375668AD")})
        {
            var profile=LinuxNativeInstallation.RequireProfile(historical.Kernel,historical.Btf,5);
            var exact=watch with{Kernel=historical.Kernel,BtfSha256=historical.Btf,Members=[watch.Members[0] with{Sha256=profile.LoaderSha256!},watch.Members[1] with{Sha256=profile.ObjectSha256!},watch.Members[2] with{Sha256=profile.ModuleSha256}]};
            LinuxNativeInstallation.Validate(exact);LinuxNativeInstallation.RequireModule(exact);
            Check(profile.ModuleSha256!=historical.RejectedModule,"exact historical kernel refuses formerly rejected BTF-base module: "+historical.Kernel);
            Reject(()=>LinuxNativeInstallation.RequireModule(exact with{Members=[exact.Members[0],exact.Members[1],exact.Members[2] with{Sha256=historical.RejectedModule}]}),"rejected BTF-base artifact cannot substitute into qualified manifest");
            Reject(()=>LinuxNativeInstallation.RequireModule(exact with{Members=watch.Members}),"historical profile refuses Debian94 native substitution");
            Reject(()=>LinuxNativeInstallation.RequireModule(watch with{Members=exact.Members}),"Debian94 refuses historical native substitution");
            Reject(()=>LinuxNativeInstallation.Validate(exact with{BtfSha256=watch.BtfSha256}),"historical profile refuses another BTF");
            Reject(()=>LinuxNativeInstallation.Validate(exact with{Version=4}),"historical IO cannot enter previous manifest profile");
            Reject(()=>LinuxNativeInstallation.Validate(exact with{ControlVersion=3}),"historical IO refuses protocol downgrade");
            Check(LinuxNativeInstallation.Parse<LinuxNativeInstallation.Manifest>(JsonSerializer.SerializeToUtf8Bytes(exact)).NativeSchema==8,"historical IO preserves explicit canonical schema8");
        }
        var kernel61=LinuxNativeInstallation.RequireProfile("6.1.0-50-amd64","ECF4E48FCBED6D520B857BAF9FD06621B734094CE76FE41B0B0BC5E159AE6EFD",5);
        var exact61=watch with{Kernel=kernel61.Kernel,BtfSha256=kernel61.BtfSha256,Members=[watch.Members[0] with{Sha256=kernel61.LoaderSha256!},watch.Members[1] with{Sha256=kernel61.ObjectSha256!},watch.Members[2] with{Sha256=kernel61.ModuleSha256}]};
        LinuxNativeInstallation.Validate(exact61);LinuxNativeInstallation.RequireModule(exact61);
        Check(kernel61.LoaderSha256=="089F097CB3F1BA533D3CBCA65C02FB605DA7BA028120A2F29CF3C0E3D67ECC5B","kernel61 pins Debian12 runtime-qualified loader");
        Reject(()=>LinuxNativeInstallation.RequireModule(exact61 with{Members=[exact61.Members[0],exact61.Members[1] with{Sha256="9B41C2044F485377CFB8C5CC4EDF9E51F7574B5F6F7EDAF12E370F3D0961274B"},exact61.Members[2]]}),"kernel61 rejects sleepable task_alloc verifier-failed object");
        Reject(()=>LinuxNativeInstallation.RequireModule(exact61 with{Members=watch.Members}),"kernel61 rejects Debian94 bundle");
        Reject(()=>LinuxNativeInstallation.RequireModule(watch with{Members=exact61.Members}),"Debian94 rejects kernel61 bundle");
        Reject(()=>LinuxNativeInstallation.Validate(exact61 with{BtfSha256=watch.BtfSha256}),"kernel61 rejects wrong BTF");
        Reject(()=>LinuxNativeInstallation.Validate(exact61 with{Version=4}),"kernel61 rejects manifest downgrade");
        Reject(()=>LinuxNativeInstallation.Validate(exact61 with{ControlVersion=3}),"kernel61 rejects protocol downgrade");
        Check(LinuxNativeInstallation.Parse<LinuxNativeInstallation.Manifest>(JsonSerializer.SerializeToUtf8Bytes(exact61)).NativeSchema==8,"kernel61 preserves canonical schema8");
        var hwe=LinuxNativeInstallation.RequireProfile("6.8.0-138-generic","3EAB61C9C1FDE515C548552AD83DB2007C79F11F77597EC495DE6AE85E589773",5);
        var exactHwe=watch with{Kernel=hwe.Kernel,BtfSha256=hwe.BtfSha256,Members=[watch.Members[0] with{Sha256=hwe.LoaderSha256!},watch.Members[1] with{Sha256=hwe.ObjectSha256!},watch.Members[2] with{Sha256=hwe.ModuleSha256}]};
        LinuxNativeInstallation.Validate(exactHwe);LinuxNativeInstallation.RequireModule(exactHwe);
        Check(hwe.LoaderSha256==kernel61.LoaderSha256,"HWE pins the older-userspace compatible qualified loader");
        Reject(()=>LinuxNativeInstallation.RequireModule(exactHwe with{Members=[exactHwe.Members[0] with{Sha256=watchProfile.LoaderSha256!},exactHwe.Members[1],exactHwe.Members[2]]}),"HWE rejects Debian13 loader substitution");
        Reject(()=>LinuxNativeInstallation.RequireModule(exactHwe with{Members=ubuntuIo.Members}),"HWE rejects Noble134 bundle substitution");
        Reject(()=>LinuxNativeInstallation.RequireModule(ubuntuIo with{Members=exactHwe.Members}),"Noble134 rejects HWE138 bundle substitution");
        Reject(()=>LinuxNativeInstallation.Validate(exactHwe with{BtfSha256=ubuntuIo.BtfSha256}),"HWE rejects wrong BTF");
        Reject(()=>LinuxNativeInstallation.Validate(exactHwe with{Version=4}),"HWE rejects manifest downgrade");
        Reject(()=>LinuxNativeInstallation.Validate(exactHwe with{ControlVersion=3}),"HWE rejects protocol downgrade");
        Check(LinuxNativeInstallation.Parse<LinuxNativeInstallation.Manifest>(JsonSerializer.SerializeToUtf8Bytes(exactHwe)).NativeSchema==8,"HWE preserves canonical schema8");
        var atomicProfile=LinuxNativeInstallation.RequireProfile(ubuntu.Kernel,ubuntu.BtfSha256,2);
        var atomicModule=members[2] with{Sha256=atomicProfile.ModuleSha256};
        var atomicLoader=members[0] with{Sha256=atomicProfile.LoaderSha256!};var atomicObject=members[1] with{Sha256=atomicProfile.ObjectSha256!};
        var atomic=qualifiedUbuntu with{Version=2,ControlVersion=3,NativeSchema=7,Members=[atomicLoader,atomicObject,atomicModule]};
        LinuxNativeInstallation.Validate(atomic);LinuxNativeInstallation.RequireModule(atomic);
        Check(atomicProfile.ModuleSha256!=ubuntu.ModuleSha256,"atomic manifest2 selects exact separately tested module and control3/schema7");
        foreach(var candidate in new[]{atomic with{Version=1},atomic with{Version=3},atomic with{ControlVersion=2},atomic with{NativeSchema=6},atomic with{Kernel=debian.Kernel,BtfSha256=debian.BtfSha256}})
            Reject(()=>LinuxNativeInstallation.Validate(candidate),"atomic manifest rejects version/protocol/platform substitution: "+checks.Count);
        Reject(()=>LinuxNativeInstallation.RequireModule(atomic with{Members=[atomicLoader,atomicObject,ubuntuModule]}),"atomic manifest refuses former Ubuntu module");
        Reject(()=>LinuxNativeInstallation.RequireModule(atomic with{Members=[members[0],atomicObject,atomicModule]}),"atomic manifest refuses substituted loader");
        Reject(()=>LinuxNativeInstallation.RequireModule(atomic with{Members=[atomicLoader,members[1],atomicModule]}),"atomic manifest refuses substituted BPF object");
        Reject(()=>LinuxNativeInstallation.RequireModule(qualifiedUbuntu with{Members=[members[0],members[1],atomicModule]}),"legacy manifest refuses new atomic module");
        Check(LinuxNativeInstallation.Parse<LinuxNativeInstallation.Manifest>(JsonSerializer.SerializeToUtf8Bytes(atomic)).ControlVersion==3,"explicit atomic manifest survives canonical JSON without protocol fallback");
        Reject(()=>LinuxNativeInstallation.RequireModule(qualifiedUbuntu with{Members=[members[0],members[1],debianModule]}),"Ubuntu profile refuses Debian module bytes");
        Reject(()=>LinuxNativeInstallation.RequireModule(qualifiedDebian with{Members=[members[0],members[1],ubuntuModule]}),"Debian profile refuses Ubuntu module bytes");
        Reject(()=>LinuxNativeInstallation.Validate(qualifiedUbuntu with{BtfSha256=debian.BtfSha256}),"Ubuntu kernel refuses substituted Debian BTF");
        Reject(()=>LinuxNativeInstallation.Validate(qualifiedDebian with{BtfSha256=ubuntu.BtfSha256}),"Debian kernel refuses substituted Ubuntu BTF");
        Reject(()=>LinuxNativeInstallation.Validate(qualifiedUbuntu with{Kernel="6.8.0-135-generic"}),"unbenchmarked adjacent Ubuntu kernel refused");
        Reject(()=>LinuxNativeInstallation.RequireModule(qualifiedUbuntu with{Members=[members[0],members[1],members[2]]}),"familiar module name with unknown bytes refused");
        foreach(var candidate in new[]{manifest with{Kernel="6.12.0"},manifest with{Architecture="arm64"},manifest with{BtfSha256=hash},manifest with{ModuleStatusSchema=1},manifest with{ModuleStatusBytes=152},manifest with{ControlVersion=1},manifest with{NativeSchema=5},manifest with{MaximumActorBytes=8388608},manifest with{NativeLeases=5}})
            Reject(()=>LinuxNativeInstallation.Validate(candidate),"manifest refuses unqualified kernel/BTF/protocol/bounds: "+checks.Count);
        Reject(()=>LinuxNativeInstallation.Validate(manifest with{Members=[members[0],members[1],members[1]]}),"member names and exact loader/object/module roles cannot alias");
        Reject(()=>LinuxNativeInstallation.Validate(manifest with{Members=[members[0] with{Name="../loader"},members[1],members[2]]}),"package members cannot traverse directories");
        Reject(()=>LinuxNativeInstallation.Validate(manifest with{Members=[members[0] with{Name="package-update.lock"},members[1],members[2]]}),"package binary cannot alias update-lock file");
        Reject(()=>LinuxNativeInstallation.Validate(manifest with{Members=[members[0] with{Size=8388609},members[1],members[2]]}),"member read size is bounded before file allocation");
        Reject(()=>LinuxNativeInstallation.Validate(manifest with{Targets=[]}),"empty target set rejected");
        var full=manifest with{Targets=Enumerable.Range(1,32).Select(i=>new LinuxNativeInstallation.Target("/srv/decoys/"+i+".txt",2049,(ulong)i)).ToArray()};
        LinuxNativeInstallation.Validate(full);Check(true,"thirty-two distinct frozen target definitions accepted");
        Reject(()=>LinuxNativeInstallation.Validate(full with{Targets=[..full.Targets,new("/srv/decoys/33.txt",2049,33)]}),"thirty-third target rejected");
        Reject(()=>LinuxNativeInstallation.Validate(manifest with{Targets=[manifest.Targets[0],manifest.Targets[0] with{Path="/srv/decoys/alias.txt"}]}),"same device/inode cannot be configured through two target paths");
        Reject(()=>LinuxNativeInstallation.Validate(manifest with{Targets=[manifest.Targets[0],manifest.Targets[0] with{Inode=43}]}),"same path cannot be assigned two file identities");
        var bad=JsonSerializer.SerializeToUtf8Bytes(manifest with{Members=null!});Reject(()=>LinuxNativeInstallation.Validate(LinuxNativeInstallation.Parse<LinuxNativeInstallation.Manifest>(bad)),"null package inventory is explicit refusal");
        // Definition reuse is bound to independently observed exact bytes and
        // full stat identity, never only a pathname or remembered hash.
        void RefusePin(Action action,string label){try{action();}catch(IOException){Check(true,label);return;}throw new Exception("Accepted: "+label);}
        var manifestBytes=JsonSerializer.SerializeToUtf8Bytes(manifest);
        var pinConfig=config with{ManifestSha256=Convert.ToHexString(SHA256.HashData(manifestBytes))};
        var configBytes=JsonSerializer.SerializeToUtf8Bytes(pinConfig);
        var configIdentity=new LinuxProtectedDirectory.Identity(0,0,0x8180,1,100,(ulong)configBytes.Length,8,1,10,11,12,13);
        var manifestIdentity=new LinuxProtectedDirectory.Identity(0,0,0x8180,1,101,(ulong)manifestBytes.Length,8,1,10,11,12,13);
        var definition=new LinuxNativeInstallation.Definition(pinConfig,manifest,Convert.ToHexString(SHA256.HashData(configBytes)),configIdentity,manifestIdentity);
        var pin=new LinuxNativeDefinitionPin(definition);
        var configObserved=new LinuxProtectedDirectory.Captured(configBytes,configIdentity);
        var manifestObserved=new LinuxProtectedDirectory.Captured(manifestBytes,manifestIdentity);
        pin.RequireObserved(configObserved,manifestObserved);Check(true,"validated definition reuse accepts exact fresh bytes and complete identities");
        foreach(var changed in new[]{configIdentity with{Uid=1},configIdentity with{Gid=1},configIdentity with{Mode=0x81a0},configIdentity with{Links=2},configIdentity with{Inode=102},configIdentity with{DeviceMajor=9},configIdentity with{DeviceMinor=2},configIdentity with{Size=configIdentity.Size+1},configIdentity with{ModifiedSeconds=20},configIdentity with{ModifiedNanoseconds=20},configIdentity with{ChangedSeconds=20},configIdentity with{ChangedNanoseconds=20}})
            RefusePin(()=>pin.RequireObserved(configObserved with{File=changed},manifestObserved),"fresh configuration identity substitution refused: "+checks.Count);
        foreach(var changed in new[]{manifestIdentity with{Uid=1},manifestIdentity with{Gid=1},manifestIdentity with{Mode=0x81a0},manifestIdentity with{Links=2},manifestIdentity with{Inode=103},manifestIdentity with{DeviceMajor=9},manifestIdentity with{DeviceMinor=2},manifestIdentity with{Size=manifestIdentity.Size+1},manifestIdentity with{ModifiedSeconds=20},manifestIdentity with{ModifiedNanoseconds=20},manifestIdentity with{ChangedSeconds=20},manifestIdentity with{ChangedNanoseconds=20}})
            RefusePin(()=>pin.RequireObserved(configObserved,manifestObserved with{File=changed}),"fresh manifest identity substitution refused: "+checks.Count);
        var changedConfig=(byte[])configBytes.Clone();changedConfig[^2]^=1;
        var changedManifest=(byte[])manifestBytes.Clone();changedManifest[^2]^=1;
        RefusePin(()=>pin.RequireObserved(configObserved with{Bytes=changedConfig},manifestObserved),"same-size configuration byte mutation refused without stale fallback");
        RefusePin(()=>pin.RequireObserved(configObserved,manifestObserved with{Bytes=changedManifest}),"same-size manifest byte mutation refused without stale fallback");
        RefusePin(()=>pin.RequireObserved(configObserved with{Bytes=[]},manifestObserved),"unavailable fresh configuration never uses prior pin as readiness");
        RefusePin(()=>pin.RequireObserved(configObserved,manifestObserved with{Bytes=[]}),"unavailable fresh manifest never uses prior pin as readiness");
        RefusePin(()=>pin.RequireObserved(configObserved with{Bytes=Encoding.UTF8.GetBytes(Encoding.UTF8.GetString(configBytes)+" ")},manifestObserved),"noncanonical fresh configuration is refused");
        Reject(()=>_ =new LinuxNativeDefinitionPin(definition with{ConfigurationSha256=new string('B',64)}),"pin requires exact canonical configuration digest");
        Reject(()=>_ =new LinuxNativeDefinitionPin(definition with{Configuration=pinConfig with{PublicKeyBase64="AA=="}}),"pin validates DER key without sharing an RSA instance");
        var originalMember=manifest.Members[0];manifest.Members[0]=originalMember with{Sha256=new string('B',64)};
        pin.RequireObserved(configObserved,manifestObserved);Check(true,"pin owns canonical byte copies independently of later mutable caller arrays");manifest.Members[0]=originalMember;
        var elapsed=System.Diagnostics.Stopwatch.StartNew();for(var i=0;i<1000;i++)pin.RequireObserved(configObserved,manifestObserved);elapsed.Stop();
        Check(true,"one thousand checks still compare actual provided bytes and identities");
        pin.RequireObserved(configObserved,manifestObserved);Check(true,"prior rejection neither adopts changed bytes nor poisons unchanged admitted pin");
        File.WriteAllText(Path.Combine(root,"RESULTS.json"),JsonSerializer.Serialize(new{Passed=true,Checks=checks.Count,Details=checks,PinChecksElapsedMs=elapsed.ElapsedMilliseconds,Root=root,Scope="Definition syntax, fixed profile bounds and exact-byte/identity reuse only; actual protected descriptors, filesystem mutation, native ownership and installed activation remain separate gates"}));
        Console.WriteLine(JsonSerializer.Serialize(new{Passed=true,Checks=checks.Count,Root=root}));
    }
}
