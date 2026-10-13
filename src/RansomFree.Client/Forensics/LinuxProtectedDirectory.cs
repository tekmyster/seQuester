using System.ComponentModel;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;

namespace RansomFree.Client.Forensics;

// Root configuration/bridge reads validate and use the same descriptors. No
// unprivileged pathname is reopened after its owner/mode check. Linux only.
internal sealed partial class LinuxProtectedDirectory:IDisposable
{
    private const int PathOnly=0x200000,DirectoryOnly=0x10000,NoFollow=0x20000,CloseOnExec=0x80000,NonBlocking=0x800;
    [DllImport("libc",SetLastError=true,EntryPoint="open")]private static extern int Open(string path,int flags);
    [DllImport("libc",SetLastError=true,EntryPoint="openat")]private static extern int OpenAt(SafeFileHandle directory,string name,int flags);
    [DllImport("libc",SetLastError=true,EntryPoint="statx")]private static extern int Statx(SafeFileHandle file,string path,int flags,uint mask,[Out] byte[] value);
    [DllImport("libc",SetLastError=true,EntryPoint="openat")]private static extern int CreateAt(SafeFileHandle directory,string name,int flags,uint mode);
    [DllImport("libc",SetLastError=true,EntryPoint="mkdirat")]private static extern int MakeDirectoryAt(SafeFileHandle directory,string name,uint mode);
    [DllImport("libc",SetLastError=true,EntryPoint="fchown")]private static extern int ChangeOwner(SafeFileHandle file,uint owner,uint group);
    [DllImport("libc",SetLastError=true,EntryPoint="fchmod")]private static extern int ChangeMode(SafeFileHandle file,uint mode);
    [DllImport("libc",SetLastError=true,EntryPoint="renameat2")]private static extern int RenameNew(SafeFileHandle from,string oldname,SafeFileHandle to,string newname,uint flags);
    [DllImport("libc",SetLastError=true,EntryPoint="fsync")]private static extern int Sync(SafeFileHandle file);
    [DllImport("libc",SetLastError=true,EntryPoint="unlinkat")]private static extern int Unlink(SafeFileHandle directory,string name,int flags);
    [DllImport("libc",SetLastError=true,EntryPoint="fchownat")]private static extern int ChangeOwnerAt(SafeFileHandle directory,string name,uint owner,uint group,int flags);
    [DllImport("libc",SetLastError=true,EntryPoint="fchmodat")]private static extern int ChangeModeAt(SafeFileHandle directory,string name,uint mode,int flags);
    [DllImport("libc",EntryPoint="geteuid")]private static extern uint UserId();
    private readonly SafeFileHandle handle;
    private readonly uint? group;
    private readonly object gate=new();
    private bool disposed;
    internal sealed record Identity(uint Uid,uint Gid,ushort Mode,uint Links,ulong Inode,ulong Size,uint DeviceMajor,uint DeviceMinor,
        long ModifiedSeconds,uint ModifiedNanoseconds,long ChangedSeconds,uint ChangedNanoseconds);
    internal sealed record Captured(byte[] Bytes,Identity File);
    private LinuxProtectedDirectory(SafeFileHandle handle,uint? group){this.handle=handle;this.group=group;}
    private static SafeFileHandle Handle(int fd)=>fd<0?throw new Win32Exception(Marshal.GetLastPInvokeError()):new((nint)fd,true);
    private static Identity Describe(SafeFileHandle fd)
    {
        var b=new byte[256];if(Statx(fd,"",0x1000,0x7ff,b)!=0)throw new Win32Exception(Marshal.GetLastPInvokeError());
        if((BitConverter.ToUInt32(b,0)&0x7df)!=0x7df)throw new IOException("Root file ownership and identity metadata unavailable");
        return Description(b);
    }
    private static Identity Description(byte[] b)
    {
        return new(BitConverter.ToUInt32(b,20),BitConverter.ToUInt32(b,24),BitConverter.ToUInt16(b,28),BitConverter.ToUInt32(b,16),
            BitConverter.ToUInt64(b,32),BitConverter.ToUInt64(b,40),BitConverter.ToUInt32(b,136),BitConverter.ToUInt32(b,140),
            BitConverter.ToInt64(b,112),BitConverter.ToUInt32(b,120),BitConverter.ToInt64(b,96),BitConverter.ToUInt32(b,104));
    }
    private static void RequireDirectory(Identity d,uint? group=null)
    {
        if(d.Uid!=0||(d.Mode&0xf000)!=0x4000||(d.Mode&0x12)!=0||group!=null&&(d.Gid!=group||(d.Mode&7)!=0))
            throw new IOException("Root directory has unsafe ownership, permissions or type");
    }
    private static void RequireFile(Identity f,uint? group)
    {
        if(f.Uid!=0||(f.Mode&0xf000)!=0x8000||f.Links!=1||(f.Mode&0xe4f)!=0|| // no special bits, execute, or other access
            (f.Mode&0x12)!=0||group!=null&&f.Gid!=group)
            throw new IOException("Root file has unsafe ownership, permissions, links or type");
    }
    internal static LinuxProtectedDirectory OpenRoot(string path,uint? group=null)
    {
        if(!OperatingSystem.IsLinux())throw new PlatformNotSupportedException();
        if(!path.StartsWith('/')||path.Length>4096||path.Any(char.IsControl)||path.Contains('\\'))throw new ArgumentException("Absolute canonical Linux directory required");
        var parts=path.Split('/');if(path!="/"&&parts.Skip(1).Any(x=>x.Length==0||x is "." or ".."))throw new ArgumentException("Noncanonical root directory path");
        var current=Handle(Open("/",PathOnly|DirectoryOnly|NoFollow|CloseOnExec));
        try
        {
            RequireDirectory(Describe(current));
            foreach(var part in parts.Skip(1).Where(x=>x.Length!=0))
            {
                var next=Handle(OpenAt(current,part,PathOnly|DirectoryOnly|NoFollow|CloseOnExec));
                try{RequireDirectory(Describe(next));}catch{next.Dispose();throw;}
                current.Dispose();current=next;
            }
            RequireDirectory(Describe(current),group);return new(current,group);
        }
        catch{current.Dispose();throw;}
    }
    internal LinuxProtectedDirectory CreatePrivateChild(string name)
    {
        if(name.Length is <1 or >255||name is "." or ".."||name.Any(char.IsControl)||name.Contains('/')||name.Contains('\\'))
            throw new ArgumentException("Single-component new private directory required");
        lock(gate)
        {
            ObjectDisposedException.ThrowIf(disposed,this);
            if(UserId()!=0)throw new UnauthorizedAccessException("Root directory creator required");
            RequirePrivate();
            // mkdirat must create a new node; an existing directory or symlink
            // is never adopted or repaired. Use the held parent and child FDs.
            if(MakeDirectoryAt(handle,name,448)!=0)throw new Win32Exception(Marshal.GetLastPInvokeError()); // 0700
            var child=Handle(OpenAt(handle,name,DirectoryOnly|NoFollow|CloseOnExec));
            try
            {
                var before=Describe(child);RequireDirectory(before);
                if((before.Mode&0xfff)!=448)throw new IOException("New private directory permissions changed");
                // The installed root service has a dedicated non-root GID.
                // Private module receipts still require explicit root:root.
                if(ChangeOwner(child,0,0)!=0||ChangeMode(child,448)!=0)throw new Win32Exception(Marshal.GetLastPInvokeError());
                RequireDirectory(Describe(child),0);
                if(Sync(child)!=0)throw new Win32Exception(Marshal.GetLastPInvokeError());
                CommitDirectory();return new(child,0);
            }
            catch{child.Dispose();throw;} // Retain incomplete nodes for diagnosis.
        }
    }
    internal Captured Read(string name,int maximumBytes,Action? afterOpen=null)
    {
        if(name.Length is <1 or >255||name is "." or ".."||name.Any(char.IsControl)||name.Contains('/')||name.Contains('\\')||maximumBytes is <1 or >8*1024*1024)
            throw new ArgumentException("Bounded single-component root file required");
        lock(gate)
        {
            ObjectDisposedException.ThrowIf(disposed,this);RequireDirectory(Describe(handle),group);
            // O_NONBLOCK prevents an unexpected FIFO from hanging before its
            // type can be rejected. Every file is then read from this handle.
            using var file=Handle(OpenAt(handle,name,NoFollow|CloseOnExec|NonBlocking));
            var before=Describe(file);RequireFile(before,group);
            if(before.Size>(ulong)maximumBytes)throw new IOException("Root file exceeds read bound");
            afterOpen?.Invoke();
            var bytes=new byte[checked((int)before.Size)];using var stream=new FileStream(file,FileAccess.Read);
            stream.ReadExactly(bytes);if(stream.ReadByte()!=-1||Describe(file)!=before)throw new IOException("Root file changed while being read");
            return new(bytes,before);
        }
    }
    internal string[] Names(int maximumEntries)
    {
        if(maximumEntries is <1 or >16384)throw new ArgumentException("Bounded directory inventory required");
        lock(gate)
        {
            ObjectDisposedException.ThrowIf(disposed,this);RequireDirectory(Describe(handle),group);
            // This path refers to this held descriptor, not the original mutable
            // installation path. It is never supplied by a bridge packet.
            var names=System.IO.Directory.EnumerateFileSystemEntries("/proc/self/fd/"+handle.DangerousGetHandle().ToInt32()).Take(maximumEntries+1).Select(Path.GetFileName).ToArray();
            if(names.Length>maximumEntries)throw new IOException("Root inbox inventory bound exceeded; retained");return names!;
        }
    }
    // The caller retains this directory for the entire socket lifetime. Its
    // parent is root-owned and nonwritable by the connecting service account.
    internal string SocketPath(string name)
    {
        if(name.Length is <1 or >64||name is "." or ".."||name.Any(c=>!char.IsAsciiLetterOrDigit(c)&&c is not ('.' or '-' or '_')))
            throw new ArgumentException("Bounded socket name required");
        lock(gate)
        {
            ObjectDisposedException.ThrowIf(disposed,this);RequireDirectory(Describe(handle),group);
            if(group==null)throw new InvalidOperationException("Explicit socket service group required");
            return "/proc/self/fd/"+handle.DangerousGetHandle().ToInt32()+"/"+name;
        }
    }
    internal void ConfigureSocket(string name)
    {
        lock(gate)
        {
            _=SocketPath(name);if(UserId()!=0)throw new UnauthorizedAccessException("Root socket owner required");
            using var node=Handle(OpenAt(handle,name,PathOnly|NoFollow|CloseOnExec));var before=Describe(node);
            if(before.Uid!=0||before.Links!=1||(before.Mode&0xf000)!=0xc000)throw new IOException("Root socket node required");
            // No unprivileged writer can change the validated parent. Refuse
            // preexisting nodes at bind; these operations only configure ours.
            if(ChangeOwnerAt(handle,name,0,group!.Value,0x100)!=0||ChangeModeAt(handle,name,432,0)!=0)throw new Win32Exception(Marshal.GetLastPInvokeError()); // 0660
            RequireSocket(name);
        }
    }
    internal Identity RequireSocket(string name)
    {
        lock(gate)
        {
            _=SocketPath(name);using var node=Handle(OpenAt(handle,name,PathOnly|NoFollow|CloseOnExec));var value=Describe(node);
            if(value.Uid!=0||value.Gid!=group||value.Links!=1||value.Mode!=(0xc000|432))throw new IOException("Unsafe root policy socket");
            return value;
        }
    }
    internal void RetireOwnedSocket(string name,Identity expected)
    {
        lock(gate)
        {
            _=SocketPath(name);if(UserId()!=0)throw new UnauthorizedAccessException("Root socket owner required");
            Identity actual;
            try{actual=RequireSocket(name);}catch(Win32Exception ex)when(ex.NativeErrorCode==2){CommitDirectory();return;}
            if(actual!=expected)throw new IOException("Socket node differs from the closed listener; retained");
            if(Unlink(handle,name,0)!=0)throw new Win32Exception(Marshal.GetLastPInvokeError());CommitDirectory();
        }
    }
    internal Identity Inspect(string name)
    {
        if(name.Length is <1 or >255||name is "." or ".."||name.Any(char.IsControl)||name.Contains('/')||name.Contains('\\'))throw new ArgumentException("Single-component root file required");
        lock(gate)
        {
            ObjectDisposedException.ThrowIf(disposed,this);RequireDirectory(Describe(handle),group);
            using var file=Handle(OpenAt(handle,name,PathOnly|NoFollow|CloseOnExec));var info=Describe(file);RequireFile(info,group);return info;
        }
    }
    internal void PublishNew(string name,byte[] bytes,Action<string>? checkpoint=null)
    {
        if(name.Length is <1 or >255||name is "." or ".."||name.Any(char.IsControl)||name.Contains('/')||name.Contains('\\')||bytes.Length is <1 or >8*1024*1024)
            throw new ArgumentException("Bounded root publication required");
        lock(gate)
        {
            ObjectDisposedException.ThrowIf(disposed,this);
            if(UserId()!=0||group==null)throw new UnauthorizedAccessException("Only root may publish to an explicitly grouped inbox");
            RequireDirectory(Describe(handle),group);
            // Old incomplete temporaries remain visible for explicit recovery;
            // no request-controlled pathname or existing artifact is overwritten.
            var temporary="pending-"+Guid.NewGuid().ToString("N")+".tmp";
            using(var file=Handle(CreateAt(handle,temporary,1|0x40|0x80|NoFollow|CloseOnExec,384)))
            {
                if(ChangeOwner(file,0,group.Value)!=0||ChangeMode(file,416)!=0)throw new Win32Exception(Marshal.GetLastPInvokeError()); // 0640
                using var output=new FileStream(file,FileAccess.Write);output.Write(bytes);output.Flush(true);RequireFile(Describe(file),group);
            }
            checkpoint?.Invoke("bridge-export-written");
            if(RenameNew(handle,temporary,handle,name,1)!=0)throw new Win32Exception(Marshal.GetLastPInvokeError()); // RENAME_NOREPLACE
            checkpoint?.Invoke("bridge-export-renamed");CommitDirectory();checkpoint?.Invoke("bridge-export-committed");
        }
    }
    internal void CommitDirectory()
    {
        lock(gate)
        {
            ObjectDisposedException.ThrowIf(disposed,this);
            using var directory=Handle(OpenAt(handle,".",DirectoryOnly|NoFollow|CloseOnExec));RequireDirectory(Describe(directory),group);
            if(Sync(directory)!=0)throw new Win32Exception(Marshal.GetLastPInvokeError());
        }
    }
    internal void RetireExportDuplicate(string eventId,string expectedHash)
    {
        if(!RansomFree.Contracts.EvidenceTransferLimits.Id(eventId)||!RansomFree.Contracts.EvidenceTransferLimits.Hash(expectedHash))throw new ArgumentException("Exact exported event identity required");
        lock(gate)
        {
            ObjectDisposedException.ThrowIf(disposed,this);
            if(UserId()!=0||group==null)throw new UnauthorizedAccessException("Only root retires an acknowledged export duplicate");
            RequireDirectory(Describe(handle),group);var name=eventId+".json";
            try
            {
                var existing=Read(name,LinuxNativeBridgePacket.MaximumBytes);
                if(LinuxNativeBridgePacket.Hash(existing.Bytes)!=expectedHash)throw new InvalidDataException("Native export changed before duplicate retirement; retained");
            }
            catch(Win32Exception e)when(e.NativeErrorCode==2){CommitDirectory();return;}
            if(Unlink(handle,name,0)!=0)throw new Win32Exception(Marshal.GetLastPInvokeError());CommitDirectory();
        }
    }
    public void Dispose(){lock(gate){if(disposed)return;handle.Dispose();disposed=true;}}
}
