using System.ComponentModel;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Text.Json;
using RansomFree.Client.Forensics;

internal static class TargetStatxChecks
{
    [DllImport("libc",EntryPoint="link",SetLastError=true)]private static extern int Link(string source,string target);
    internal static void Run(string root)
    {
        if(!OperatingSystem.IsLinux()||Directory.Exists(root))throw new IOException("Unique actual Linux fixture directory required");
        Directory.CreateDirectory(root,UnixFileMode.UserRead|UnixFileMode.UserWrite|UnixFileMode.UserExecute);
        var checks=new List<string>();void Check(bool ok,string label){if(!ok)throw new Exception(label);checks.Add(label);}
        void Refused(Action action,string label)
        {try{action();throw new Exception("Target mutation accepted: "+label);}catch(Exception e)when(e is IOException or Win32Exception){Check(true,label);}}
        var parent=Path.Combine(root,"parent");Directory.CreateDirectory(parent);var path=Path.Combine(parent,"target");File.WriteAllText(path,"original");
        using(var target=LinuxProtectedDirectory.OpenMonitoredTarget(path))
        {
            for(var i=0;i<100;i++)target.RequireCurrent();Check(true,"100 fresh current pathname/held descriptor/mount checks passed");
            File.AppendAllText(path," legitimate write");target.RequireCurrent();Check(true,"content/size change preserves original identity semantics; target not hashed");
            var original=Path.Combine(parent,"retained-original");File.Move(path,original);File.WriteAllText(path,"replacement");
            Refused(target.RequireCurrent,"same-path different inode refused");File.Delete(path);File.Move(original,path);target.RequireCurrent();
            File.Move(path,original);File.CreateSymbolicLink(path,original);
            Refused(target.RequireCurrent,"final symlink refused without following");File.Delete(path);File.Move(original,path);target.RequireCurrent();
            File.Move(path,original);Refused(target.RequireCurrent,"missing pathname refused");File.Move(original,path);target.RequireCurrent();
            var extra=Path.Combine(parent,"extra-link");if(Link(path,extra)!=0)throw new Win32Exception(Marshal.GetLastPInvokeError());
            Refused(target.RequireCurrent,"extra hard link refused");File.Delete(extra);target.RequireCurrent();
            var moved=Path.Combine(root,"moved-parent");Directory.Move(parent,moved);Directory.CreateSymbolicLink(parent,moved);
            Refused(target.RequireCurrent,"symlink ancestor refused");Directory.Delete(parent);Directory.Move(moved,parent);target.RequireCurrent();
            File.SetUnixFileMode(path,UnixFileMode.UserRead|UnixFileMode.UserWrite);target.RequireCurrent();Check(true,"existing target permission-change semantics preserved");
            if(Environment.GetEnvironmentVariable("SEQUESTER_TARGET_FIXTURE_PRIVATE_MOUNT_NS")!="1")throw new InvalidOperationException("Bind-mount check requires verified private mount namespace");
            void Command(string name,params string[] arguments)
            {
                var start=new ProcessStartInfo(name){RedirectStandardOutput=true,RedirectStandardError=true};foreach(var a in arguments)start.ArgumentList.Add(a);
                using var process=Process.Start(start)??throw new IOException("Fixture command failed");var error=process.StandardError.ReadToEnd();process.StandardOutput.ReadToEnd();
                if(!process.WaitForExit(10000)||process.ExitCode!=0)throw new IOException("Fixture command failed: "+name+" "+error);
            }
            Command("mount","--bind",path,path);
            try{Refused(target.RequireCurrent,"same device/inode on substituted bind mount refused");}
            finally{Command("umount",path);}
            target.RequireCurrent();Check(true,"normal unmount restores original target admission");
        }
        File.Delete(path);File.WriteAllText(path,"replacement after close");
        using(var newTarget=LinuxProtectedDirectory.OpenMonitoredTarget(path)){newTarget.RequireCurrent();Check(true,"new admission can validate a newly installed target");}
        Console.WriteLine(JsonSerializer.Serialize(new{Passed=true,Checks=checks.Count,ChecksPassed=checks,Root=root,BindMountTestPassed=true,NoNativeActivation=true,NoServiceChanged=true,Scope="Actual Linux statx target mutation/refusal tests; bind mount confined to independently verified temporary mount namespace"}));
    }
}
