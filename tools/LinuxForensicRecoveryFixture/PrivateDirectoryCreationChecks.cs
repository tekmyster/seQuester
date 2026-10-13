using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Text.Json;
using RansomFree.Client.Forensics;

internal static class PrivateDirectoryCreationChecks
{
    [DllImport("libc")]private static extern uint geteuid();
    [DllImport("libc")]private static extern uint getegid();
    internal static void Run(string root)
    {
        if(!OperatingSystem.IsLinux()||geteuid()!=0||getegid()==0||Directory.Exists(root))
            throw new ArgumentException("Fresh owned directory and root process with non-root service GID required");
        Directory.CreateDirectory(root,UnixFileMode.UserRead|UnixFileMode.UserWrite|UnixFileMode.UserExecute);
        using var parent=LinuxProtectedDirectory.OpenRoot(root);parent.RequirePrivate();
        var checks=new List<string>();void Check(bool ok,string label){if(!ok)throw new Exception(label);checks.Add(label);}
        void Reject(Action action,string label)
        {try{action();}catch(Exception e)when(e is IOException or Win32Exception or ArgumentException){Check(true,label);return;}throw new Exception("Accepted: "+label);}
        using(var child=parent.CreatePrivateChild("module-journal"))
        {
            child.RequirePrivate();using var reopened=LinuxProtectedDirectory.OpenRoot(root+"/module-journal",0);reopened.RequirePrivate();
            Check(true,"new journal is root:root mode0700 despite non-root effective service GID");
            child.PublishNew("receipt.json",[1,2,3]);var receipt=child.Read("receipt.json",16);
            Check(receipt.File.Uid==0&&receipt.File.Gid==0&&receipt.Bytes.SequenceEqual(new byte[]{1,2,3}),"root:root receipt published and read through created descriptor");
            Reject(()=>parent.CreatePrivateChild("module-journal"),"duplicate directory creation refuses existing journal");
            Check(child.Read("receipt.json",16).Bytes.SequenceEqual(receipt.Bytes),"duplicate refusal preserves original receipt bytes");
        }
        Directory.CreateSymbolicLink(root+"/alias",root+"/module-journal");Reject(()=>parent.CreatePrivateChild("alias"),"existing symlink is never adopted");
        File.WriteAllText(root+"/existing-file","retained");Reject(()=>parent.CreatePrivateChild("existing-file"),"existing file is never adopted");
        foreach(var name in new[]{"", ".", "..", "../escape", "/absolute", "nested/child", "back\\slash", "control\n"})
            Reject(()=>parent.CreatePrivateChild(name),"invalid directory component refused: "+checks.Count);
        var moved=root+"-retained";Directory.Move(root,moved);Directory.CreateDirectory(root);
        using(var child=parent.CreatePrivateChild("after-parent-move")){child.RequirePrivate();}
        Check(Directory.Exists(moved+"/after-parent-move")&&!Directory.Exists(root+"/after-parent-move"),"creation uses held parent descriptor after pathname substitution");
        var result=new{Passed=true,Checks=checks.Count,Details=checks,EffectiveUid=geteuid(),EffectiveGid=getegid(),Root=moved,Scope="Actual mkdirat/fchown/fchmod/fsync under non-root service GID; no native activation"};
        File.WriteAllText(moved+"/RESULTS.json",JsonSerializer.Serialize(result));Console.WriteLine(JsonSerializer.Serialize(result));
    }
}
