using Microsoft.Win32.SafeHandles;
using System.ComponentModel;
using System.Runtime.InteropServices;
using RansomFree.Contracts;

namespace RansomFree.Client.Forensics;

internal sealed partial class LinuxProtectedDirectory
{
    // Honeypot parents may be user-owned. Traverse without following any link;
    // the authority is the root-installed expected tuple, not parent ownership.
    // O_PATH retains only identity: target contents are never read or hashed.
    internal static MonitoredTarget OpenMonitoredTarget(string path)
    {
        if(!OperatingSystem.IsLinux()||!LinuxNativeInstallation.CanonicalPath(path))throw new ArgumentException("Canonical Linux target path required");
        var parts=path.Split('/').Skip(1).ToArray();
        using var root=Handle(Open("/",PathOnly|DirectoryOnly|NoFollow|CloseOnExec));
        SafeFileHandle current=root;
        try
        {
            for(var n=0;n<parts.Length-1;n++)
            {
                var next=Handle(OpenAt(current,parts[n],PathOnly|DirectoryOnly|NoFollow|CloseOnExec));
                if(current!=root)current.Dispose();current=next;
            }
            var file=Handle(OpenAt(current,parts[^1],PathOnly|NoFollow|CloseOnExec));
            try
            {
                var identity=Describe(file);var tuple=MonitoredTarget.Tuple(identity);var mount=QualifiedMount(file);
                return new(path,file,identity,tuple,mount);
            }
            catch{file.Dispose();throw;}
        }
        finally{if(current!=root)current.Dispose();}
    }
    // Reopening the final target with O_PATH still emits Linux Audit open
    // records. Sample its current identity/mount atomically through statx
    // instead. Ancestors retain the original no-follow directory traversal.
    // The original target descriptor remains held and independently qualified.
    private static void RequireMonitoredPath(string path,LinuxControlledTargetSet.Identity expected,MountIdentity mount)
    {
        var parts=path.Split('/').Skip(1).ToArray();
        using var root=Handle(Open("/",PathOnly|DirectoryOnly|NoFollow|CloseOnExec));
        SafeFileHandle current=root;
        try
        {
            for(var n=0;n<parts.Length-1;n++)
            {
                var next=Handle(OpenAt(current,parts[n],PathOnly|DirectoryOnly|NoFollow|CloseOnExec));
                if(current!=root)current.Dispose();current=next;
            }
            var b=new byte[256];
            if(Statx(current,parts[^1],0x100,0x17ff,b)!=0)throw new Win32Exception(Marshal.GetLastPInvokeError()); // AT_SYMLINK_NOFOLLOW
            if((BitConverter.ToUInt32(b,0)&0x17df)!=0x17df)throw new IOException("Current target identity or mount unavailable");
            var identity=Description(b);
            if(MonitoredTarget.Tuple(identity)!=expected||BitConverter.ToUInt64(b,144)!=mount.MountId||
                identity.DeviceMajor!=mount.DeviceMajor||identity.DeviceMinor!=mount.DeviceMinor)
                throw new IOException("Monitored pathname no longer names the admitted target/mount; stop and revalidate");
        }
        finally{if(current!=root)current.Dispose();}
    }
    internal sealed class MonitoredTarget:IDisposable
    {
        private readonly object gate=new();private readonly SafeFileHandle file;private bool disposed;
        internal string Path {get;}
        internal Identity Metadata {get;}
        internal LinuxControlledTargetSet.Identity Target {get;}
        internal MountIdentity Mount {get;}
        internal MonitoredTarget(string path,SafeFileHandle file,Identity metadata,LinuxControlledTargetSet.Identity target,MountIdentity mount)
        {Path=path;this.file=file;Metadata=metadata;Target=target;Mount=mount;}
        internal static LinuxControlledTargetSet.Identity Tuple(Identity value)
        {
            if((value.Mode&0xf000)!=0x8000||value.Links!=1||value.Inode==0||value.DeviceMajor>4095||value.DeviceMinor>1048575)
                throw new IOException("Monitored target must be a single-linked regular file with a supported device identity");
            // Same explicit device encoding as controlled_v2_targets.h.
            var device=(value.DeviceMajor<<20)|value.DeviceMinor;if(device==0)throw new IOException("Monitored target device unavailable");
            return new(device,value.Inode);
        }
        internal void RequireCurrent()
        {
            lock(gate)
            {
                ObjectDisposedException.ThrowIf(disposed,this);
                if(Tuple(Describe(file))!=Target||QualifiedMount(file)!=Mount)throw new IOException("Held monitored target identity changed");
                RequireMonitoredPath(Path,Target,Mount);
            }
        }
        public void Dispose(){lock(gate){if(disposed)return;disposed=true;file.Dispose();}}
    }
}
