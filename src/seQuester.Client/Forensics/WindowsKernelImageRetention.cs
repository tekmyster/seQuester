using System.ComponentModel;
using System.Diagnostics;
using System.Globalization;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;
using RansomFree.Contracts;
namespace RansomFree.Client.Forensics;

// Retains file objects, never executable path lookups or token snapshots. An exact
// kernel process instance can outlive its user-mode process and pending I/O.
[System.Runtime.Versioning.SupportedOSPlatform("windows")]
internal sealed class WindowsKernelImageRetention:IDisposable
{
    private sealed record Entry(FileStream Image,FileIdentityEvidence File,string EventId,DateTimeOffset CapturedUtc,long Timestamp);
    private readonly Dictionary<string,Entry> entries=new(StringComparer.Ordinal);
    private readonly object gate=new();
    private readonly int capacity;
    private readonly long lifetimeTicks;
    private readonly Func<long> timestamp;
    private bool disposed;
    internal WindowsKernelImageRetention(int capacity=64,TimeSpan? lifetime=null,Func<long>? timestamp=null)
    {
        var duration=lifetime??TimeSpan.FromSeconds(30);
        if(capacity is <1 or >256||duration<=TimeSpan.Zero||duration>TimeSpan.FromMinutes(1))throw new ArgumentOutOfRangeException(nameof(capacity));
        this.capacity=capacity;this.timestamp=timestamp??Stopwatch.GetTimestamp;lifetimeTicks=checked((long)(duration.TotalSeconds*Stopwatch.Frequency));
    }
    [DllImport("kernel32.dll",SetLastError=true)]private static extern SafeFileHandle ReOpenFile(SafeFileHandle file,uint access,uint share,uint flags);
    internal static FileStream Reopen(FileStream source,FileIdentityEvidence expected)
    {
        if(!NativeFileIdentity.Same(expected,NativeFileIdentity.Read(source)))throw new IOException("Retained actor file identity changed.");
        var handle=ReOpenFile(source.SafeFileHandle,0x80000000,5,0); // GENERIC_READ, share READ|DELETE; separate file position.
        if(handle.IsInvalid){var error=Marshal.GetLastWin32Error();handle.Dispose();throw new Win32Exception(error);}
        FileStream? copy=null;
        try
        {
            copy=new FileStream(handle,FileAccess.Read);
            if(!NativeFileIdentity.Same(expected,NativeFileIdentity.Read(copy))||!NativeFileIdentity.Same(expected,NativeFileIdentity.Read(source)))throw new IOException("Retained actor file changed while reopening.");
            return copy;
        }
        catch{if(copy!=null)copy.Dispose();else handle.Dispose();throw;}
    }
    private static string? Key(AgentEvent value,string sensor)
    {
        var k=value.Attribution?.WindowsKernel;
        if(value.Source!="Windows minifilter"||k?.IsValid()!=true||k.ProcessId!=value.ProcessId||k.ProcessCreatedFileTime is not >0||string.IsNullOrWhiteSpace(value.Process)||!Guid.TryParseExact(sensor,"N",out _))return null;
        return sensor+":"+k.Instance+":"+k.ProcessId+":"+k.ProcessCreatedFileTime.Value.ToString(CultureInfo.InvariantCulture)+":"+value.Process.ToUpperInvariant();
    }
    internal ActorLease Capture(AgentEvent value,string sensor,Action<string> health)
    {
        lock(gate)
        {
            ObjectDisposedException.ThrowIf(disposed,this);Prune();
            var key=Key(value,sensor);
            var captured=ActorLease.Capture(value,sensor,true);
            if(key!=null&&entries.TryGetValue(key,out var saved)&&(captured.Image==null||!NativeFileIdentity.Same(saved.File,captured.File)))
            {
                captured.Dispose();
                try
                {
                    var result=ActorLease.Unavailable(value,"retained-image-pending");
                    result.Image=Reopen(saved.Image,saved.File);result.File=saved.File;
                    result.Binding=EvidenceStatus.Captured("retained-file-object; exact-kernel-process-instance; not-loaded-memory-verification");
                    result.BindingSourceEventId=saved.EventId;result.BindingCapturedUtc=saved.CapturedUtc;
                    // Optional process metadata is not synthesized from a previous event.
                    result.Process=result.Process with{CommandLineStatus=EvidenceStatus.Unavailable("retained-image-only; process-metadata-not-requeried"),ParentStatus=EvidenceStatus.Unavailable("retained-image-only; parent-not-requeried"),SessionStatus=EvidenceStatus.Unavailable("retained-image-only; process-session-not-requeried")};
                    result.ApplyKernel(value,sensor);return result;
                }
                catch(Exception ex)when(ActorLease.OptionalFailure(ex))
                {
                    saved.Image.Dispose();entries.Remove(key);
                    var result=ActorLease.Unavailable(value,"retained-actor-image-unavailable");result.Binding=ActorLease.FailedField("retained-actor-image-unavailable",ex);result.ApplyKernel(value,sensor);
                    health("Windows kernel retained actor unavailable: "+result.Binding.NativeCode);return result;
                }
            }
            if(key==null||captured.Image==null||captured.Binding.State!="captured"||captured.Process.StartKey!=value.Attribution!.WindowsKernel!.ProcessCreatedFileTime!.Value.ToString(CultureInfo.InvariantCulture))return captured;
            if(entries.ContainsKey(key))return captured; // Fixed lifetime, never prolonged by more events.
            try
            {
                var retained=Reopen(captured.Image,captured.File);
                if(entries.Count>=capacity){var oldest=entries.MinBy(x=>x.Value.Timestamp);oldest.Value.Image.Dispose();entries.Remove(oldest.Key);health("Windows kernel actor retention capacity reached; oldest process image released");}
                entries.Add(key,new(retained,captured.File,value.EventId,captured.CapturedUtc,timestamp()));
            }
            catch(Exception ex)when(ActorLease.OptionalFailure(ex)){health("Windows kernel actor retention unavailable: "+ActorLease.FailedField("retention-failed",ex).NativeCode);}
            return captured;
        }
    }
    private void Prune()
    {
        var now=timestamp();foreach(var pair in entries.Where(x=>now-x.Value.Timestamp>=lifetimeTicks).ToArray()){pair.Value.Image.Dispose();entries.Remove(pair.Key);}
    }
    internal void Expire(){lock(gate){if(!disposed)Prune();}}
    internal int Count{get{lock(gate)return entries.Count;}}
    public void Dispose(){lock(gate){if(disposed)return;disposed=true;foreach(var value in entries.Values)value.Image.Dispose();entries.Clear();}}
}
