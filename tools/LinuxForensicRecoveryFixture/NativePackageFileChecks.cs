using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text.Json;
using RansomFree.Client.Forensics;

internal static class NativePackageFileChecks
{
    [DllImport("libc")]private static extern uint geteuid();
    [DllImport("libc",SetLastError=true)]private static extern int link(string source,string destination);
    [DllImport("libc",SetLastError=true)]private static extern int mkfifo(string path,uint mode);
    [DllImport("libc",SetLastError=true)]private static extern int chown(string path,uint uid,uint gid);
    private const UnixFileMode Private=UnixFileMode.UserRead|UnixFileMode.UserWrite;
    internal static void Run(string root)
    {
        if(!OperatingSystem.IsLinux()||geteuid()!=0||Directory.Exists(root))throw new ArgumentException("Fresh root Linux package fixture required");
        Directory.CreateDirectory(root,Private|UnixFileMode.UserExecute);
        var checks=new List<string>();void Check(bool ok,string label){if(!ok)throw new Exception(label);checks.Add(label);}
        void Reject(Action action,string label)
        {try{action();}catch(Exception e)when(e is IOException or Win32Exception or ArgumentException or ObjectDisposedException){Check(true,label);return;}throw new Exception("Accepted: "+label);}
        string Save(string name,byte[] bytes,UnixFileMode mode=Private)
        {var path=Path.Combine(root,name);File.WriteAllBytes(path,bytes);File.SetUnixFileMode(path,mode);return path;}
        using var directory=LinuxProtectedDirectory.OpenRoot(root);directory.RequirePrivate();Check(true,"root-private directory opened without unprivileged-writable ancestors");
        var original=new byte[]{1,3,5,7};var digest=Convert.ToHexString(SHA256.HashData(original));Save("member.bin",original);
        using(var member=directory.OpenPackageFile("member.bin",16))
        {
            Check(member.Sha256()==digest&&member.Sha256()==digest,"repeat SHA256 reads exact retained descriptor without moving a stream cursor");
            directory.RequirePackagePath("member.bin",member);Check(member.File.Size==4&&member.File.Uid==0,"current pathname equals retained owner/size/stable file identity");
            var actual=new byte[4];Check(member.WithDescriptor(fd=>RandomAccess.Read(fd,actual,0))==4&&actual.SequenceEqual(original),"hashing leaves original readable descriptor valid for a later owner");
            File.Move(Path.Combine(root,"member.bin"),Path.Combine(root,"original-retained.bin"));Save("member.bin",[2,4,6,8]);
            Reject(()=>directory.RequirePackagePath("member.bin",member),"same pathname replacement cannot validate as retained package member");
            Check(File.ReadAllBytes(Path.Combine(root,"original-retained.bin")).SequenceEqual(original),"replacement leaves original backing bytes preserved");
        }
        Save("changing.bin",original);using(var member=directory.OpenPackageFile("changing.bin",16))
        {File.WriteAllBytes(Path.Combine(root,"changing.bin"),[1,2,3,4,5]);Reject(()=>member.Sha256(),"in-place modification invalidates retained identity before hashing");}
        var closed=directory.OpenPackageFile("member.bin",16);closed.Dispose();Reject(()=>closed.Sha256(),"disposed member cannot create a hash result");
        Save("loader",original,Private|UnixFileMode.UserExecute);
        Reject(()=>{using var _=directory.OpenPackageFile("loader",16);},"executable cannot masquerade as non-executable data member");
        using(var loader=directory.OpenPackageFile("loader",16,true))Check(loader.Sha256()==digest,"declared executable mode accepted without executing the binary");
        Reject(()=>{using var _=directory.OpenPackageFile("member.bin",16,true);},"declared loader requires owner execute permission");
        Save("group-write.bin",original,Private|UnixFileMode.GroupWrite);Reject(()=>{using var _=directory.OpenPackageFile("group-write.bin",16);},"group-writable package bytes refused");
        Save("special.bin",original,Private|(UnixFileMode)0x800);Reject(()=>{using var _=directory.OpenPackageFile("special.bin",16);},"set-user-ID package member refused");
        var foreign=Save("foreign.bin",original);if(chown(foreign,65534,65534)!=0)throw new Win32Exception(Marshal.GetLastPInvokeError());Reject(()=>{using var _=directory.OpenPackageFile("foreign.bin",16);},"non-root package file refused");
        File.CreateSymbolicLink(Path.Combine(root,"symbolic.bin"),Path.Combine(root,"member.bin"));Reject(()=>{using var _=directory.OpenPackageFile("symbolic.bin",16);},"symbolic package member refused");
        Save("linked.bin",original);if(link(Path.Combine(root,"linked.bin"),Path.Combine(root,"second-link.bin"))!=0)throw new Win32Exception(Marshal.GetLastPInvokeError());Reject(()=>{using var _=directory.OpenPackageFile("linked.bin",16);},"hard-linked package member refused");
        if(mkfifo(Path.Combine(root,"fifo"),384)!=0)throw new Win32Exception(Marshal.GetLastPInvokeError());Reject(()=>{using var _=directory.OpenPackageFile("fifo",16);},"unexpected FIFO is rejected without blocking on open");
        Reject(()=>{using var _=directory.OpenPackageFile("member.bin",3);},"oversized member refused before allocation");
        Reject(()=>{using var _=directory.OpenPackageFile("../member.bin",16);},"package name cannot traverse retained parent");
        Save("package-update.lock",[]);
        using(var owner=directory.OpenPackageFile("package-update.lock",1))
        using(var other=directory.OpenPackageFile("package-update.lock",1))
        {
            owner.AcquireUpdateLease();Check(true,"root package update lease acquired without waiting");
            Reject(()=>other.AcquireUpdateLease(),"second independent open cannot overlap package update lease");
            owner.Dispose();other.AcquireUpdateLease();Check(true,"new owner acquires lease only after original descriptor closes");
        }
        Save("nonempty.lock",[1]);using(var member=directory.OpenPackageFile("nonempty.lock",1))Reject(member.AcquireUpdateLease,"update lock cannot alias package contents");
        File.SetUnixFileMode(root,Private|UnixFileMode.UserExecute|UnixFileMode.GroupRead|UnixFileMode.GroupExecute);
        try{Reject(directory.RequirePrivate,"group-visible package directory refused for privileged installation");}
        finally{File.SetUnixFileMode(root,Private|UnixFileMode.UserExecute);}
        File.WriteAllText(Path.Combine(root,"RESULTS.json"),JsonSerializer.Serialize(new{Passed=true,Checks=checks.Count,Details=checks,Root=root,Scope="Actual Linux retained descriptor hashing, package permission/identity checks and nonblocking update lease; no module, loader, source or installed service activated"}));
        Console.WriteLine(JsonSerializer.Serialize(new{Passed=true,Checks=checks.Count,Root=root}));
    }
}
