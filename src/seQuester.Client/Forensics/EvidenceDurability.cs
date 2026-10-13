using System.ComponentModel;
using System.Runtime.InteropServices;

namespace RansomFree.Client.Forensics;

// File Flush(true) alone does not make a new Linux directory entry durable.
internal static class EvidenceDurability
{
    [DllImport("libc",SetLastError=true,EntryPoint="open")] private static extern int Open(string path,int flags);
    [DllImport("libc",SetLastError=true,EntryPoint="fsync")] private static extern int Sync(int fd);
    [DllImport("libc",EntryPoint="close")] private static extern int Close(int fd);
    [DllImport("kernel32.dll",CharSet=CharSet.Unicode,SetLastError=true,EntryPoint="MoveFileExW")]
    [return:MarshalAs(UnmanagedType.Bool)] private static extern bool Move(string from,string to,uint flags);
    internal static void NoLinks(string path)
    {
        for(string? p=Path.GetFullPath(path);p!=null;p=Path.GetDirectoryName(p))
            if(Path.Exists(p)&&(File.GetAttributes(p)&FileAttributes.ReparsePoint)!=0)throw new IOException("Evidence path contains a link.");
    }
    internal static void DirectoryCommitted(string directory)
    {
        if(!OperatingSystem.IsLinux())return;
        NoLinks(directory);
        var fd=Open(directory,0x10000|0x20000|0x80000); // O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC
        if(fd<0)throw new Win32Exception(Marshal.GetLastPInvokeError());
        try{if(Sync(fd)!=0)throw new Win32Exception(Marshal.GetLastPInvokeError());}finally{Close(fd);}
    }
    internal static void SaveNew(string path,ReadOnlySpan<byte> bytes)
    {
        NoLinks(path);
        var temporary=path+"."+Guid.NewGuid().ToString("N")+".tmp";
        var options=new FileStreamOptions{Mode=FileMode.CreateNew,Access=FileAccess.Write,Share=FileShare.None};
        if(!OperatingSystem.IsWindows())options.UnixCreateMode=UnixFileMode.UserRead|UnixFileMode.UserWrite;
        using(var file=new FileStream(temporary,options)){file.Write(bytes);file.Flush(true);}
        if(OperatingSystem.IsWindows())
        {
            static string Extended(string p)=>p.StartsWith(@"\\?\",StringComparison.Ordinal)?p:p.StartsWith(@"\\",StringComparison.Ordinal)?@"\\?\UNC\"+p[2..]:@"\\?\"+p;
            if(!Move(Extended(temporary),Extended(path),8))throw new Win32Exception(Marshal.GetLastPInvokeError());
        }
        else File.Move(temporary,path,false);
        DirectoryCommitted(Path.GetDirectoryName(path)!);
    }
}
