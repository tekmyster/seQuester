using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Text.Json;
using RansomFree.Client.Forensics;

internal static class NativeBindTargetChecks
{
    [DllImport("libc",EntryPoint="mount",SetLastError=true)]private static extern int Mount(string source,string target,string? type,nuint flags,nint data);
    [DllImport("libc",EntryPoint="umount2",SetLastError=true)]private static extern int Unmount(string target,int flags);
    internal static void Run(string root)
    {
        if(!OperatingSystem.IsLinux()||Directory.Exists(root)||!root.StartsWith("/root/sequester-protected-",StringComparison.Ordinal))throw new ArgumentException("Fresh owned bind fixture directory required");
        Directory.CreateDirectory(root,UnixFileMode.UserRead|UnixFileMode.UserWrite|UnixFileMode.UserExecute);
        var source=Path.Combine(root,"source.txt");var target=Path.Combine(root,"mount.txt");
        File.WriteAllText(source,"Owned source fixture");File.WriteAllText(target,"Owned underlying mountpoint fixture");
        var checks=new List<string>();void Check(bool ok,string label){if(!ok)throw new Exception(label);checks.Add(label);}
        void Reject(Action action,string label)
        {try{action();}catch(Exception e)when(e is IOException or InvalidDataException){Check(true,label);return;}throw new Exception("Accepted: "+label);}
        LinuxNativeTargetAdmission.TargetProof? proof=null;LinuxProtectedDirectory.MountIdentity originalMount;
        LinuxNativeInstallation.Target expected;
        using(var original=LinuxProtectedDirectory.OpenMonitoredTarget(source))
        {originalMount=original.Mount;expected=new(target,original.Target.Device,original.Target.Inode);}
        var mounted=false;var unloaded=false;
        try
        {
            if(Mount(source,target,null,4096,0)!=0)throw new Win32Exception(Marshal.GetLastPInvokeError());mounted=true;
            Check(true,"actual MS_BIND attached only the owned fixture file");
            File.WriteAllText(Path.Combine(root,"mountinfo-bound.txt"),File.ReadAllText("/proc/self/mountinfo"));
            using(var admitted=LinuxNativeTargetAdmission.Open([expected]))
            {
                admitted.RequireCurrent();proof=admitted.Proofs[0];
                Check(proof.Mount.Type=="ext4"&&proof.Mount.MountId!=originalMount.MountId&&proof.Identity.Device==expected.Device&&proof.Identity.Inode==expected.Inode,"held bind target has exact original inode with distinct actual ext4 mount identity");
                Reject(()=>{using var duplicate=LinuxNativeTargetAdmission.Open([expected,expected with{Path=source}]);},"bind alias cannot create duplicate ordinals for one target inode");
                Reject(()=>{using var wrong=LinuxNativeTargetAdmission.Open([expected with{Inode=ulong.MaxValue}]);},"bind location does not bypass expected target identity check");
                File.Move(source,source+".original");File.WriteAllText(source,"New underlying source pathname");admitted.RequireCurrent();
                Check(true,"source-path replacement leaves bind target monitoring the original exact held inode");
            }
        }
        finally
        {
            if(mounted)
            {
                var result=Unmount(target,0);var error=result<0?Marshal.GetLastPInvokeError():0;
                File.WriteAllText(Path.Combine(root,"unmount.json"),JsonSerializer.Serialize(new{Result=result,Error=error,Flags=0,Target=target}));
                if(result!=0)throw new Win32Exception(error,"Owned bind remains unresolved; no forced/lazy unmount");unloaded=true;
            }
        }
        Check(unloaded,"normal unmount returned only after all target admission descriptors closed");
        using(var restored=LinuxProtectedDirectory.OpenMonitoredTarget(target))
            Check(restored.Mount==originalMount&&restored.Target.Inode!=expected.Inode,"unmount exposes original underlying mountpoint file and mount identity");
        File.WriteAllText(Path.Combine(root,"RESULTS.json"),JsonSerializer.Serialize(new{Passed=true,Checks=checks.Count,Details=checks,Root=root,OriginalMount=originalMount,Proof=proof,Scope="Actual owned bind-mounted local ext4 target admission and normal unmount only; no source/module activation or target content hashing/preservation."}));
        Console.WriteLine(JsonSerializer.Serialize(new{Passed=true,Checks=checks.Count,Root=root}));
    }
}
