using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Text;
using System.Text.Json;
using RansomFree.Client.Forensics;

internal static class ProtectedDirectoryChecks
{
    [DllImport("libc",SetLastError=true)]private static extern uint geteuid();
    [DllImport("libc",SetLastError=true)]private static extern int chown(string path,uint owner,uint group);
    [DllImport("libc",SetLastError=true)]private static extern int link(string oldpath,string newpath);
    [DllImport("libc",SetLastError=true)]private static extern int mkfifo(string path,uint mode);
    internal static void Run(string root)
    {
        if(!OperatingSystem.IsLinux()||geteuid()!=0||Directory.Exists(root))throw new ArgumentException("Fresh root-owned Linux fixture required");
        Directory.CreateDirectory(root,UnixFileMode.UserRead|UnixFileMode.UserWrite|UnixFileMode.UserExecute);
        var checks=new List<string>();void Check(bool ok,string label){if(!ok)throw new Exception(label);checks.Add(label);}
        void Reject(Action action,string label){try{action();}catch(Exception e)when(e is IOException or Win32Exception or ArgumentException or ObjectDisposedException){Check(true,label);return;}throw new Exception("Accepted: "+label);}
        void FileAt(string name,string text="trusted")
        {File.WriteAllText(Path.Combine(root,name),text);File.SetUnixFileMode(Path.Combine(root,name),UnixFileMode.UserRead|UnixFileMode.UserWrite);}
        FileAt("input.json");using var directory=LinuxProtectedDirectory.OpenRoot(root,0);
        var first=directory.Read("input.json",64);Check(Encoding.UTF8.GetString(first.Bytes)=="trusted"&&first.File.Uid==0&&first.File.Links==1,"validated descriptor yields exact root-owned bytes and identity");
        Reject(()=>directory.Read("../input.json",64),"parent path traversal refused");
        Reject(()=>directory.Read("/input.json",64),"absolute child path refused");
        Reject(()=>directory.Read("input.json",1),"oversized regular file refused before allocation");
        Reject(()=>LinuxProtectedDirectory.OpenRoot(root+"/../"+Path.GetFileName(root)),"noncanonical directory path refused");
        Reject(()=>LinuxProtectedDirectory.OpenRoot(root,65534),"unexpected bridge directory group refused");
        File.CreateSymbolicLink(Path.Combine(root,"file-link"),"input.json");Reject(()=>directory.Read("file-link",64),"final symlink refused");
        Directory.CreateSymbolicLink(Path.Combine(root,"dir-link"),root);Reject(()=>LinuxProtectedDirectory.OpenRoot(root+"/dir-link"),"ancestor symlink refused");
        FileAt("hard-link-source");if(link(root+"/hard-link-source",root+"/hard-link")!=0)throw new Win32Exception(Marshal.GetLastPInvokeError());
        Reject(()=>directory.Read("hard-link",64),"hard-linked root file refused");
        FileAt("owner");if(chown(root+"/owner",65534,0)!=0)throw new Win32Exception(Marshal.GetLastPInvokeError());Reject(()=>directory.Read("owner",64),"non-root-owned file refused");
        FileAt("group");if(chown(root+"/group",0,65534)!=0)throw new Win32Exception(Marshal.GetLastPInvokeError());Reject(()=>directory.Read("group",64),"unexpected root file group refused");
        foreach(var mode in new[]{UnixFileMode.GroupWrite,UnixFileMode.OtherRead,UnixFileMode.UserExecute,UnixFileMode.SetUser,UnixFileMode.SetGroup,UnixFileMode.StickyBit})
        {var name="mode-"+(int)mode;FileAt(name);File.SetUnixFileMode(root+"/"+name,UnixFileMode.UserRead|UnixFileMode.UserWrite|mode);Reject(()=>directory.Read(name,64),"unsafe file permission refused: "+mode);}
        if(mkfifo(root+"/fifo",384)!=0)throw new Win32Exception(Marshal.GetLastPInvokeError());Reject(()=>directory.Read("fifo",64),"FIFO rejected without blocking for a writer");
        var writable=root+"/writable";Directory.CreateDirectory(writable);File.SetUnixFileMode(writable,UnixFileMode.UserRead|UnixFileMode.UserWrite|UnixFileMode.UserExecute|UnixFileMode.GroupWrite);
        Reject(()=>LinuxProtectedDirectory.OpenRoot(writable),"group-writable ancestor refused");
        FileAt("mutated");Reject(()=>directory.Read("mutated",64,()=>File.AppendAllText(root+"/mutated","changed")),"same open inode modification refused");
        FileAt("replaced");bool replacementSafe;
        try{replacementSafe=Encoding.UTF8.GetString(directory.Read("replaced",64,()=>{File.Move(root+"/replaced",root+"/retained-replaced");FileAt("replaced","untrusted");}).Bytes)=="trusted";}
        catch(IOException){replacementSafe=true;}
        Check(replacementSafe,"file pathname replacement yields held original bytes or explicit metadata-change failure");
        var moved=root+"-retained";var pinned=directory.Read("input.json",64,()=>{Directory.Move(root,moved);Directory.CreateDirectory(root);FileAt("input.json","untrusted");});
        Check(Encoding.UTF8.GetString(pinned.Bytes)=="trusted","held directory descriptor is unaffected by ancestor pathname substitution");
        directory.Dispose();Reject(()=>directory.Read("input.json",64),"disposed descriptor reader refuses access");
        File.WriteAllText(Path.Combine(moved,"RESULTS.json"),JsonSerializer.Serialize(new{Passed=true,Checks=checks.Count,Details=checks,Root=moved,ReplacementRoot=root,Scope="Actual Linux openat/statx descriptor reads and permission/race cases; no native source activation"}));
        Console.WriteLine(JsonSerializer.Serialize(new{Passed=true,Checks=checks.Count,Root=moved,ReplacementRoot=root}));
    }
}
