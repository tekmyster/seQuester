using System.Collections.Immutable;
using RansomFree.Contracts;

namespace RansomFree.Client.Forensics;

// Freezes target identities independently of the loader. The installed owner
// retains this admission until its actual source/loader detach has returned.
// A pathname replacement invalidates the session; it never edits a live map.
internal sealed class LinuxNativeTargetAdmission:IDisposable
{
    internal sealed record TargetProof(string Path,LinuxControlledTargetSet.Identity Identity,
        LinuxProtectedDirectory.Identity Metadata,LinuxProtectedDirectory.MountIdentity Mount);
    private readonly object gate=new();
    private readonly List<LinuxProtectedDirectory.MonitoredTarget> files;
    internal ImmutableArray<TargetProof> Proofs {get;}
    internal LinuxControlledTargetSet Prepared {get;}
    private bool disposed;
    private LinuxNativeAdmissionHold? nativeHold;
    private LinuxNativeTargetAdmission(List<LinuxProtectedDirectory.MonitoredTarget> files)
    {
        this.files=files;Prepared=LinuxControlledTargetSet.Prepare(files.Select(f=>f.Target));
        Proofs=files.Select(f=>new TargetProof(f.Path,f.Target,f.Metadata,f.Mount)).ToImmutableArray();
    }
    internal static LinuxNativeTargetAdmission Open(IEnumerable<LinuxNativeInstallation.Target> configured)
    {
        ArgumentNullException.ThrowIfNull(configured);var definitions=configured.Take(33).ToArray();
        if(definitions.Length is <1 or >32||definitions.Any(x=>x==null||!LinuxNativeInstallation.CanonicalPath(x.Path))||
            definitions.Select(x=>x.Path).Distinct(StringComparer.Ordinal).Count()!=definitions.Length)
            throw new InvalidDataException("One to thirty-two distinct configured target paths required");
        _=LinuxControlledTargetSet.Prepare(definitions.Select(x=>new LinuxControlledTargetSet.Identity(x.Device,x.Inode)));
        var files=new List<LinuxProtectedDirectory.MonitoredTarget>();
        try
        {
            foreach(var expected in definitions)
            {
                var file=LinuxProtectedDirectory.OpenMonitoredTarget(expected.Path);files.Add(file);
                if(file.Target!=new LinuxControlledTargetSet.Identity(expected.Device,expected.Inode))
                    throw new IOException("Observed target differs from the root-installed identity");
            }
            foreach(var file in files)file.RequireCurrent();
            return new(files);
        }
        catch{foreach(var file in files)file.Dispose();throw;}
    }
    internal void RequireCurrent()
    {lock(gate){ObjectDisposedException.ThrowIf(disposed,this);using var mounts=LinuxProtectedDirectory.BeginMountValidation();foreach(var file in files)file.RequireCurrent();mounts.Complete();}}
    internal LinuxNativeAdmissionHold HoldNativeLifetime()
    {
        lock(gate)
        {
            RequireCurrent();if(nativeHold!=null)throw new InvalidOperationException("Native target lifetime already owned");
            return nativeHold=new(hold=>{lock(gate){if(!ReferenceEquals(nativeHold,hold))throw new InvalidOperationException("Foreign native target hold");nativeHold=null;}});
        }
    }
    public void Dispose(){lock(gate){if(disposed)return;if(nativeHold!=null)throw new InvalidOperationException("Native source must actually detach before target admission release");disposed=true;foreach(var file in files)file.Dispose();}}
}
