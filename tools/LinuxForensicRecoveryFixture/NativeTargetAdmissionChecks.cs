using System.ComponentModel;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Text.Json;
using RansomFree.Client.Forensics;
using RansomFree.Contracts;

internal static class NativeTargetAdmissionChecks
{
    [DllImport("libc",SetLastError=true)]private static extern int link(string source,string destination);
    [DllImport("libc",SetLastError=true)]private static extern int mkfifo(string path,uint mode);
    [DllImport("libc",SetLastError=true)]private static extern int chown(string path,uint uid,uint gid);
    private const UnixFileMode Private=UnixFileMode.UserRead|UnixFileMode.UserWrite|UnixFileMode.UserExecute;
    internal static void Run(string root)
    {
        if(!OperatingSystem.IsLinux()||Directory.Exists(root))throw new ArgumentException("Fresh Linux target fixture required");
        Directory.CreateDirectory(root,Private);var checks=new List<string>();
        void Check(bool ok,string label){if(!ok)throw new Exception(label);checks.Add(label);}
        void Reject(Action action,string label)
        {try{action();}catch(Exception e)when(e is IOException or InvalidDataException or Win32Exception or ArgumentException or InvalidOperationException){Check(true,label);return;}throw new Exception("Accepted: "+label);}
        var paths=Enumerable.Range(0,32).Select(n=>Path.Combine(root,"target-"+n+".txt")).ToArray();
        foreach(var path in paths)File.WriteAllText(path,"Owned target fixture; contents must not be preserved or hashed");
        var start=new ProcessStartInfo("/usr/bin/python3"){UseShellExecute=false,RedirectStandardOutput=true,RedirectStandardError=true};
        start.ArgumentList.Add("-c");start.ArgumentList.Add("import os,sys,json;print(json.dumps([dict(Path=p,Device=(os.major(os.stat(p).st_dev)<<20)|os.minor(os.stat(p).st_dev),Inode=os.stat(p).st_ino) for p in sys.argv[1:]]))");
        foreach(var path in paths)start.ArgumentList.Add(path);
        using var stat=Process.Start(start)??throw new IOException("Independent stat fixture failed to start");
        var prepared=stat.StandardOutput.ReadToEnd();var error=stat.StandardError.ReadToEnd();stat.WaitForExit();
        if(stat.ExitCode!=0)throw new IOException(error);
        var definitions=JsonSerializer.Deserialize<LinuxNativeInstallation.Target[]>(prepared)!;
        File.WriteAllText(Path.Combine(root,"independent-stat.json"),prepared);
        LinuxNativeTargetAdmission.TargetProof[] proof;
        using(var admitted=LinuxNativeTargetAdmission.Open(definitions.Reverse()))
        {
            admitted.RequireCurrent();proof=admitted.Proofs.ToArray();
            Check(proof.Length==32&&proof.All(x=>x.Mount.Type=="ext4"),"thirty-two independently statted actual local targets admitted with held O_PATH identities");
            Check(admitted.Prepared.Targets.SequenceEqual(definitions.Select(x=>new LinuxControlledTargetSet.Identity(x.Device,x.Inode)).OrderBy(x=>x.Device).ThenBy(x=>x.Inode)),"native target table uses canonical numeric device/inode order independent of input path order");
            File.AppendAllText(paths[0],"\nordinary target modification");admitted.RequireCurrent();
            Check(true,"size and timestamp changes retain monitoring of the same target identity");
            if(chown(paths[1],65534,65534)!=0)throw new Win32Exception(Marshal.GetLastPInvokeError());admitted.RequireCurrent();
            Check(true,"ordinary user ownership does not disqualify a monitored honeypot");
            using var lifetime=admitted.HoldNativeLifetime();
            Reject(admitted.Dispose,"live native hold prevents target descriptor disposal");
            Reject(()=>{using var secondHold=admitted.HoldNativeLifetime();},"one native owner per admitted target set");
            lifetime.Dispose();admitted.RequireCurrent();Check(true,"actual hold return preserves target admission until explicit disposal");
        }
        Reject(()=>{using var _=LinuxNativeTargetAdmission.Open([]);},"empty target list refused");
        Reject(()=>{using var _=LinuxNativeTargetAdmission.Open(definitions.Append(definitions[0]));},"thirty-third target refused before native activation");
        Reject(()=>{using var _=LinuxNativeTargetAdmission.Open([definitions[0],definitions[0]]);},"duplicate configured pathname refused");
        Reject(()=>{using var _=LinuxNativeTargetAdmission.Open([definitions[0],definitions[0] with{Path=paths[1]}]);},"same device/inode cannot acquire two target ordinals");
        Reject(()=>{using var _=LinuxNativeTargetAdmission.Open([definitions[0] with{Inode=ulong.MaxValue}]);},"root-configured expected inode mismatch refused");
        Reject(()=>{using var _=LinuxNativeTargetAdmission.Open([definitions[0] with{Path=root+"/../not-canonical"}]);},"noncanonical target traversal refused");
        var finalLink=Path.Combine(root,"link.txt");File.CreateSymbolicLink(finalLink,paths[0]);
        Reject(()=>{using var _=LinuxNativeTargetAdmission.Open([definitions[0] with{Path=finalLink}]);},"final target symlink refused without following its referent");
        var parentLink=Path.Combine(root,"parent-link");Directory.CreateSymbolicLink(parentLink,root);
        Reject(()=>{using var _=LinuxNativeTargetAdmission.Open([definitions[0] with{Path=Path.Combine(parentLink,Path.GetFileName(paths[0]))}]);},"symlink in target ancestry refused");
        if(link(paths[2],Path.Combine(root,"second-name.txt"))!=0)throw new Win32Exception(Marshal.GetLastPInvokeError());
        Reject(()=>{using var _=LinuxNativeTargetAdmission.Open([definitions[2]]);},"multiply linked target refused");
        Reject(()=>{using var _=LinuxNativeTargetAdmission.Open([definitions[0] with{Path=root}]);},"directory cannot be admitted as regular target");
        var fifo=Path.Combine(root,"fifo");if(mkfifo(fifo,384)!=0)throw new Win32Exception(Marshal.GetLastPInvokeError());
        Reject(()=>{using var _=LinuxNativeTargetAdmission.Open([definitions[0] with{Path=fifo}]);},"FIFO target refused without a blocking content open");
        Reject(()=>{using var _=LinuxNativeTargetAdmission.Open([definitions[0] with{Path="/proc/version"}]);},"actual nonlocal-profile procfs target refused");
        using(var admitted=LinuxNativeTargetAdmission.Open([definitions[3]]))
        {
            File.Move(paths[3],paths[3]+".original");File.WriteAllText(paths[3],"replacement");
            Reject(admitted.RequireCurrent,"same pathname replacement invalidates held session without updating target table");
            Check(admitted.Prepared.Targets[0].Inode==definitions[3].Inode,"replacement cannot silently change frozen monitoring identity");
        }
        using(var admitted=LinuxNativeTargetAdmission.Open([definitions[4]]))
        {
            File.Delete(paths[4]);Reject(admitted.RequireCurrent,"unlink of held target invalidates session even while descriptor retains inode");
        }
        using(var admitted=LinuxNativeTargetAdmission.Open([definitions[5]]))
        {
            if(link(paths[5],Path.Combine(root,"late-link.txt"))!=0)throw new Win32Exception(Marshal.GetLastPInvokeError());
            Reject(admitted.RequireCurrent,"added hard link invalidates previously admitted target");
        }
        var closed=LinuxNativeTargetAdmission.Open([definitions[6]]);closed.Dispose();Reject(closed.RequireCurrent,"closed target lifetime cannot revalidate or regain authority");
        using(var fresh=LinuxNativeTargetAdmission.Open([definitions[7]])){fresh.RequireCurrent();Check(true,"prior refused targets do not prevent independent valid admission");}
        File.WriteAllText(Path.Combine(root,"RESULTS.json"),JsonSerializer.Serialize(new{Passed=true,Checks=checks.Count,Details=checks,Root=root,Proofs=proof,Scope="Actual held target identity and local ext4 admission only. No target content hashes/copies, native module, loader, source or installed service activation."}));
        Console.WriteLine(JsonSerializer.Serialize(new{Passed=true,Checks=checks.Count,Root=root}));
    }
}
