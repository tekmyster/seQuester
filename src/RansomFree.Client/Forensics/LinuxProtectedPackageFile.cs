using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using Microsoft.Win32.SafeHandles;

namespace RansomFree.Client.Forensics;

internal sealed partial class LinuxProtectedDirectory
{
    [DllImport("libc",EntryPoint="flock",SetLastError=true)]private static extern int Flock(SafeFileHandle file,int operation);
    internal void RequirePrivate()
    {
        lock(gate)
        {
            ObjectDisposedException.ThrowIf(disposed,this);var current=Describe(handle);RequireDirectory(current);
            if((current.Mode&0x3f)!=0)throw new IOException("Native configuration/package directory must be root-private");
        }
    }
    private static void PackageName(string name)
    {if(name.Length is <1 or >128||name is "." or ".."||name.Any(c=>!char.IsAsciiLetterOrDigit(c)&&c is not ('.' or '-' or '_')))throw new ArgumentException("Single-component native package member required");}
    private static void RequirePackageFile(Identity f,int maximumBytes,bool executable)
    {
        if(f.Uid!=0||(f.Mode&0xf000)!=0x8000||f.Links!=1||(f.Mode&0xe12)!=0||f.Size>(ulong)maximumBytes||
            (executable?(f.Mode&0x40)==0:(f.Mode&0x49)!=0))
            throw new IOException("Native package member has unsafe owner, mode, links, type or size");
    }
    internal RetainedPackageFile OpenPackageFile(string name,int maximumBytes,bool executable=false)
    {
        PackageName(name);if(maximumBytes is <1 or >8*1024*1024)throw new ArgumentException("Bounded native package member required");
        lock(gate)
        {
            RequirePrivate();var file=Handle(OpenAt(handle,name,NoFollow|CloseOnExec|NonBlocking));
            try{var identity=Describe(file);RequirePackageFile(identity,maximumBytes,executable);return new(file,identity,maximumBytes,executable);}
            catch{file.Dispose();throw;}
        }
    }
    internal void RequirePackagePath(string name,RetainedPackageFile retained)
    {
        PackageName(name);
        lock(gate)
        {
            RequirePrivate();using var current=Handle(OpenAt(handle,name,PathOnly|NoFollow|CloseOnExec));
            retained.RequireIdentity(Describe(current));
        }
    }
    // Holding this descriptor preserves identity. The serialized root updater
    // must also honor the separate update lease for the entire loader lifetime;
    // a descriptor does not make in-place file bytes immutable by itself.
    internal sealed class RetainedPackageFile:IDisposable
    {
        private readonly SafeFileHandle file;
        private readonly object gate=new();
        private readonly int maximum;
        private readonly bool executable;
        private bool disposed,locked;
        internal Identity File {get;}
        internal RetainedPackageFile(SafeFileHandle file,Identity identity,int maximum,bool executable)
        {this.file=file;File=identity;this.maximum=maximum;this.executable=executable;}
        private void RequireCurrent()
        {
            ObjectDisposedException.ThrowIf(disposed,this);var current=Describe(file);RequirePackageFile(current,maximum,executable);
            if(current!=File)throw new IOException("Retained native package member changed");
        }
        internal void RequireIdentity(Identity expected){lock(gate){RequireCurrent();if(expected!=File)throw new IOException("Native package pathname no longer names the retained file");}}
        internal void RequireMount(MountIdentity expected)
        {lock(gate){RequireCurrent();if(QualifiedMount(file)!=expected)throw new IOException("Package member or update lease crosses the admitted local mount");}}
        internal string Sha256()
        {
            lock(gate)
            {
                RequireCurrent();using var hash=IncrementalHash.CreateHash(HashAlgorithmName.SHA256);var buffer=new byte[65536];long offset=0;
                while(offset<(long)File.Size)
                {
                    var length=(int)Math.Min(buffer.Length,(long)File.Size-offset);var count=RandomAccess.Read(file,buffer.AsSpan(0,length),offset);
                    if(count<=0||count>length)throw new IOException("Native package member shortened during hash");
                    hash.AppendData(buffer,0,count);offset+=count;
                }
                if(RandomAccess.Read(file,buffer.AsSpan(0,1),offset)!=0)throw new IOException("Native package member grew during hash");
                RequireCurrent();return Convert.ToHexString(hash.GetHashAndReset());
            }
        }
        internal void AcquireUpdateLease()
        {
            lock(gate)
            {
                RequireCurrent();if(locked)throw new InvalidOperationException("Update lease already acquired");
                if(File.Size!=0||executable||(File.Mode&0x3f)!=0)throw new IOException("Root-private empty update lease file required");
                if(Flock(file,2|4)!=0)throw new Win32Exception(Marshal.GetLastPInvokeError()); // LOCK_EX | LOCK_NB
                locked=true;RequireCurrent();
            }
        }
        // A future module owner can use the same already-hashed readable FD.
        // This primitive neither loads a module nor executes a package member.
        internal T WithDescriptor<T>(Func<SafeFileHandle,T> operation)
        {lock(gate){RequireCurrent();return operation(file);}}
        public void Dispose(){lock(gate){if(disposed)return;disposed=true;file.Dispose();}}
    }
}
