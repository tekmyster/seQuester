using System.Security.Cryptography;
using System.Text.Json;
using RansomFree.Contracts;

namespace RansomFree.Client.Forensics;

// Definition validation only. This object grants no loader/module capability.
// Installed startup must additionally hold the package update lease, verify
// opened member/target descriptors and own the module/source lifetimes.
internal static class LinuxNativeInstallation
{
    internal sealed record Configuration(int Version,bool Enabled,string SensorId,string Server,string PublicKeyBase64,
        uint ServiceUid,uint ServiceGroup,string PackageDirectory,string ManifestSha256,string PrivateDirectory,string ChannelDirectory,string ExportDirectory);
    internal sealed record Member(string Name,string Role,long Size,string Sha256);
    internal sealed record Target(string Path,uint Device,ulong Inode);
    internal sealed record Manifest(int Version,string Kernel,string Architecture,string BtfSha256,string ModuleName,
        int ModuleStatusSchema,int ModuleStatusBytes,uint ControlVersion,uint NativeSchema,int MaximumActorBytes,int NativeLeases,Member[] Members,Target[] Targets);
    internal sealed record Definition(Configuration Configuration,Manifest Manifest,string ConfigurationSha256,
        LinuxProtectedDirectory.Identity ConfigurationFile,LinuxProtectedDirectory.Identity ManifestFile);
    internal const string QualifiedKernel="6.12.94+deb13-amd64";
    internal const string QualifiedBtfSha256="1F985FB42AB930EF42FF4C228990EC085D89FAF589B115EE256DDD717624DC8E";
    internal sealed record QualifiedProfile(string Kernel,string BtfSha256,string ModuleSha256,string? LoaderSha256=null,string? ObjectSha256=null);
    // Exact native benchmarks qualify these bytes only. Installed/server acceptance
    // remains a separate release gate; a kernel family or filename is insufficient.
    internal static QualifiedProfile RequireProfile(string kernel,string btfSha256,int manifestVersion=1)=> (kernel,btfSha256,manifestVersion) switch
    {
        (QualifiedKernel,QualifiedBtfSha256,1)=>new(kernel,btfSha256,LinuxNativeModuleOwner.QualifiedModuleSha256),
        // Control 4 scalar/vector write and append capture: Ops native R7,
        // owned managed runtime R2 and 501-check central transport R2.
        (QualifiedKernel,QualifiedBtfSha256,3)=>new(kernel,btfSha256,
            "8D5DA8BCF775BF6C353C0436E0167B7A9C3D505B595799D44AA7352CB44E22B3",
            "37A10FC7A3E9F733FE3D5F217F9C6FDF5E2986C4DD692D76FCACE2BE3430DE7A",
            "39F929AD9A407492EB13B25420628B5D75DC5A7A13ACABA67985E51D5964793E"),
        // Manifest 4 retains the entry-observed image for sixty seconds before
        // durable START, with a separate ten-second copy budget. Actual Ops
        // qualification R2 verified 14 operations, 35 hashes and normal unload.
        (QualifiedKernel,QualifiedBtfSha256,4)=>new(kernel,btfSha256,
            "79257F11E62AB29FF08CE5F6EDF53B17851141A47875C2572BE4683F9E861896",
            "37A10FC7A3E9F733FE3D5F217F9C6FDF5E2986C4DD692D76FCACE2BE3430DE7A",
            "E2D4AADDF752E69430584E02B13F19A992D8FC55451BF8AC57C84A57A494F63E"),
        // Watch-first allocation and zero-inode handling: exact native
        // qualification 20261010 R1; installed acceptance remains separate.
        (QualifiedKernel,QualifiedBtfSha256,5)=>new(kernel,btfSha256,
            "B4ADDE83C9CE468DDD211847FD5C26FDBEDE8F12A12A8D5792DA1CC2C4002E3A",
            "37A10FC7A3E9F733FE3D5F217F9C6FDF5E2986C4DD692D76FCACE2BE3430DE7A",
            "6B3CB7B88067E430B35FCCE5EDB19B9685A67E23AA5BA8134530EF2C425F57F8"),
        ("6.8.0-134-generic","4A07F657AC332A73329EB46DA423C84EC37525330EA5595CF6FAA01FBBDCB45C",1)=>
            new(kernel,btfSha256,"57A1BB56FEFE2BF797762633ABF0D12867B62CDAA8D7CA18E2874062024C83D3"),
        // Exact v27/build R18 module: native and sensor runtime read/denied-open
        // tests, recorded artifact hashes, and normal close/unload verified.
        // Installed companion acceptance and production rollout remain separate.
        ("6.8.0-134-generic","4A07F657AC332A73329EB46DA423C84EC37525330EA5595CF6FAA01FBBDCB45C",2)=>
            new(kernel,btfSha256,"1D76A89AC68AFF68CD12ECEA1FBC28DE37B9B0F24C9E06C42A4F8232D0541D67",
                "D7F90CA0DDEC68962AB29CBB1274EB3681CDEF1B2DA1BD50F753CC2968CF6088",
                "99B1B10B551DA394F732A51D1EBF1E69C5FFDEC2156726A3CF3D830FA67548C7"),
        // Ubuntu6.8 write/append and first-use capture: actual qualification
        // 20261010 R4; fourteen operations, seventy records and thirty-five copies.
        ("6.8.0-134-generic","4A07F657AC332A73329EB46DA423C84EC37525330EA5595CF6FAA01FBBDCB45C",5)=>
            new(kernel,btfSha256,"211E31248C1C4247C2BB3362920E257588ACA60CA4FED21919DE0F2E8C316024",
                "550E96E3F474D8BC4BA07D603493D7957DCE8B8868921F1FC2C80545140EDB98",
                "5C595A819CB549F3E9344521E86C6EDFB34E044A7CB1508A76E188BA305D6DE9"),
        // Exact live private-fixture qualification 20261010 R3 on both hosts:
        // fourteen operations, actor copies, zero loss and normal unload.
        // MODULE_PAHOLE_FLAGS is empty: these exact-BTF artifacts must not
        // relocate the IDs used by their per-program kfunc filter.
        ("6.12.95+deb13-amd64","8C82D3E61CD10679F25E6C3F46D14C839CC346AF90465F49F580E26430085397",5)=>
            new(kernel,btfSha256,"99A14E6B6D7C8F7E0A50E9A3C296244F1CDBCF0B3291ED4550AF58BB4D9B00B4",
                "37A10FC7A3E9F733FE3D5F217F9C6FDF5E2986C4DD692D76FCACE2BE3430DE7A",
                "C9405ED214F5FF4689854A6D41EFA684AD9074137BFE532C19C3C0ECC51C858D"),
        ("6.12.86+deb13-amd64","23FEC9F8D759721489BA879C5383B23732E44B2E52389DCDC7FC77A8A9A09A83",5)=>
            new(kernel,btfSha256,"5352511B87A0C268CC1A66CD704F518064C742FFBB7027C0A523706DEB7A343E",
                "37A10FC7A3E9F733FE3D5F217F9C6FDF5E2986C4DD692D76FCACE2BE3430DE7A",
                "C05C287059FB44A9CD41245A41D78E3BF659BBCAE3A450FF67DB4256664CDAD9"),
        // Isolated exact-kernel qualification 20261010 R4: fourteen operations,
        // 35 verified copies after immediate exit/unlink, zero loss, normal unload.
        // Explicit 6.1 atomic-only helpers and non-sleepable task_alloc; Debian12 loader.
        ("6.1.0-50-amd64","ECF4E48FCBED6D520B857BAF9FD06621B734094CE76FE41B0B0BC5E159AE6EFD",5)=>
            new(kernel,btfSha256,"05E9E1559573EA8A897040D0C73EBC31A23A2FE1FE63F865641870CC2F57DAA3",
                "089F097CB3F1BA533D3CBCA65C02FB605DA7BA028120A2F29CF3C0E3D67ECC5B",
                "BD60C4EAEE76C4DB88ED21623E45BCA1C5E0A72625245FD3AAB464ECCBD02068"),
        // Exact isolated HWE qualification 20261010 R5: fourteen operations,
        // 35 hash-verified captures after exit/unlink, zero loss, normal unload.
        ("6.8.0-138-generic","3EAB61C9C1FDE515C548552AD83DB2007C79F11F77597EC495DE6AE85E589773",5)=>
            new(kernel,btfSha256,"1A834328252E117941313CB19619FB2A6196EA0D900E89FCA3755F9E016E5DF5",
                "089F097CB3F1BA533D3CBCA65C02FB605DA7BA028120A2F29CF3C0E3D67ECC5B",
                "16AD7CE3C2AA98B8B73D6C185CFABD6BB462ED6FB2444D86C134256EE4820ECF"),
        _=>throw new InvalidDataException("Native kernel and BTF pair has not been qualified")
    };
    internal static void RequireModule(Manifest manifest)
    {
        var profile=RequireProfile(manifest.Kernel,manifest.BtfSha256,manifest.Version);
        if(manifest.Members.Single(x=>x.Role=="module").Sha256!=profile.ModuleSha256)
            throw new InvalidDataException("Native module differs from the exact qualified kernel/BTF artifact");
        if(profile.LoaderSha256!=null&&manifest.Members.Single(x=>x.Role=="loader").Sha256!=profile.LoaderSha256||
            profile.ObjectSha256!=null&&manifest.Members.Single(x=>x.Role=="object").Sha256!=profile.ObjectSha256)
            throw new InvalidDataException("Native loader or BPF object differs from the exact tested protocol package");
    }
    internal static bool CanonicalPath(string? path)=>path is {Length:>1 and <=2048}&&path[0]=='/'&&
        !path.Any(char.IsControl)&&!path.Contains('\\')&&!path.Split('/').Skip(1).Any(p=>p.Length==0||p is "." or "..");
    private static bool Hex(string? value)=>value is {Length:64}&&value.All(c=>c is >= '0' and <= '9' or >= 'A' and <= 'F');
    private static bool Name(string? value)=>value is {Length:>=1 and <=128}&&value is not ("." or "..")&&
        value.All(c=>char.IsAsciiLetterOrDigit(c)||c is '.' or '-' or '_');
    internal static T Parse<T>(ReadOnlySpan<byte> bytes)where T:class
    {
        if(bytes.Length is <1 or >65536)throw new InvalidDataException("Native installation definition exceeds bound");
        T value;try{value=JsonSerializer.Deserialize<T>(bytes)??throw new InvalidDataException("Missing native installation definition");}
        catch(JsonException e){throw new InvalidDataException("Invalid native installation JSON",e);}
        if(!JsonSerializer.SerializeToUtf8Bytes(value).AsSpan().SequenceEqual(bytes))throw new InvalidDataException("Native installation fields must be explicit, canonical and unique");
        return value;
    }
    internal static void Validate(Configuration c)
    {
        if(c.Version!=1||!Guid.TryParseExact(c.SensorId,"N",out _)||!NativePolicySnapshot.ValidOrigin(c.Server)||
            c.ServiceUid is 0 or uint.MaxValue||c.ServiceGroup is 0 or uint.MaxValue||!Hex(c.ManifestSha256))
            throw new InvalidDataException("Unsupported native installation identity, service account or manifest pin");
        var paths=new[]{c.PackageDirectory,c.PrivateDirectory,c.ChannelDirectory,c.ExportDirectory};
        if(paths.Any(p=>!CanonicalPath(p))||paths.Distinct(StringComparer.Ordinal).Count()!=paths.Length||
            paths.Any(p=>paths.Any(q=>p!=q&&p.StartsWith(q+"/",StringComparison.Ordinal))))
            throw new InvalidDataException("Separate canonical package, private, channel and export roots required");
        if(c.PublicKeyBase64 is not {Length:>=1 and <=1024})throw new InvalidDataException("Native public verification pin missing or too large");
        byte[] key;try{key=Convert.FromBase64String(c.PublicKeyBase64);}catch(FormatException e){throw new InvalidDataException("Native public verification pin invalid",e);}
        using var rsa=RSA.Create();rsa.ImportSubjectPublicKeyInfo(key,out var used);
        if(used!=key.Length||rsa.KeySize is not (3072 or 4096)||Convert.ToBase64String(key)!=c.PublicKeyBase64)
            throw new InvalidDataException("Exact supported native public verification pin required");
    }
    internal static void Validate(Manifest m)
    {
        _=RequireProfile(m.Kernel,m.BtfSha256,m.Version);
        var supportedProtocol=m.Version switch{1=>m.ControlVersion==2&&m.NativeSchema==6,2=>m.ControlVersion==3&&m.NativeSchema==7,3 or 4 or 5=>m.ControlVersion==4&&m.NativeSchema==8,_=>false};
        if(!supportedProtocol||m.Architecture!="x64"||m.ModuleName!="sq_actor_lease"||
            m.ModuleStatusSchema!=2||m.ModuleStatusBytes!=160||m.MaximumActorBytes!=4*1024*1024||m.NativeLeases!=4)
            throw new InvalidDataException("Native profile differs from the qualified kernel, BTF, module and bounded protocol");
        if(m.Members is not {Length:>=3 and <=32}||m.Members.Any(x=>x==null||!Name(x.Name)||x.Name=="package-update.lock"||x.Name=="manifest.json"||
            x.Role is not ("loader" or "object" or "module" or "library")||x.Size is <1 or >8*1024*1024||!Hex(x.Sha256))||
            m.Members.Select(x=>x.Name).Distinct(StringComparer.Ordinal).Count()!=m.Members.Length||
            new[]{"loader","object","module"}.Any(role=>m.Members.Count(x=>x.Role==role)!=1)||m.Members.Sum(x=>x.Size)>64L*1024*1024)
            throw new InvalidDataException("Bounded unique native package members and exact role hashes required");
        if(m.Targets is not {Length:>=1 and <=32}||m.Targets.Any(x=>x==null||!CanonicalPath(x.Path)||x.Inode==0)||
            m.Targets.Select(x=>x.Path).Distinct(StringComparer.Ordinal).Count()!=m.Targets.Length||
            m.Targets.Select(x=>(x.Device,x.Inode)).Distinct().Count()!=m.Targets.Length)
            throw new InvalidDataException("One to thirty-two distinct frozen target paths and file identities required");
    }
    internal static Definition ReadDefinition(string configurationDirectory)
    {
        if(!CanonicalPath(configurationDirectory))throw new ArgumentException("Root installation configuration directory required");
        using var directory=LinuxProtectedDirectory.OpenRoot(configurationDirectory);
        directory.RequirePrivate();
        var configFile=directory.Read("installation.json",65536);var c=Parse<Configuration>(configFile.Bytes);Validate(c);
        if((configFile.File.Mode&0x3f)!=0)throw new InvalidDataException("Installation configuration must be root-private");
        using var package=LinuxProtectedDirectory.OpenRoot(c.PackageDirectory);package.RequirePrivate();var manifestFile=package.Read("manifest.json",65536);
        if((manifestFile.File.Mode&0x3f)!=0||Convert.ToHexString(SHA256.HashData(manifestFile.Bytes))!=c.ManifestSha256)
            throw new InvalidDataException("Root-private package manifest differs from installation pin");
        var manifest=Parse<Manifest>(manifestFile.Bytes);Validate(manifest);
        return new(c,manifest,Convert.ToHexString(SHA256.HashData(configFile.Bytes)),configFile.File,manifestFile.File);
    }
}
