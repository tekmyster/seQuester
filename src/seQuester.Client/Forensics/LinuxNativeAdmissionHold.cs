namespace RansomFree.Client.Forensics;

// Volatile managed ownership only. It never authorizes native I/O or recreates
// a module/source from persisted metadata. The eventual module owner retains
// the hold privately until its actual native lifetime has closed.
internal sealed class LinuxNativeAdmissionHold:IDisposable
{
    private readonly object gate=new();private Action<LinuxNativeAdmissionHold>? release;
    internal LinuxNativeAdmissionHold(Action<LinuxNativeAdmissionHold> release){this.release=release;}
    public void Dispose(){lock(gate){if(release==null)return;release(this);release=null;}}
}
