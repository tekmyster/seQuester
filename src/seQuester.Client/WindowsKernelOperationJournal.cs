using System.Runtime.InteropServices;

namespace RansomFree.Client;

// Raw evidence is committed before executable collection. The short gate only
// coordinates inbox files and delivery ownership, never actor I/O or publication.
// Restart may deliver a raw record with explicitly unavailable actor evidence.
// This is at-least-once intake, not a multi-file transaction or power-loss proof.
internal sealed class WindowsKernelOperationJournal
{
    private readonly string directory;
    private readonly int capacity;
    private readonly object gate=new();
    private readonly HashSet<string> scheduled=new(StringComparer.OrdinalIgnoreCase);
    internal WindowsKernelOperationJournal(string directory,int capacity=8192)
    {
        if(capacity<1)throw new ArgumentOutOfRangeException(nameof(capacity));
        this.directory=Path.GetFullPath(directory);this.capacity=capacity;Directory.CreateDirectory(this.directory);
    }
    internal string RecordPath(string eventId)
    {
        if(!Guid.TryParseExact(eventId,"N",out _))throw new InvalidDataException("Invalid kernel event ID");
        return Path.Combine(directory,eventId+".record");
    }
    private string ValidatePath(string path)
    {
        var full=Path.GetFullPath(path);
        if(!full.Equals(RecordPath(Path.GetFileNameWithoutExtension(full)),StringComparison.OrdinalIgnoreCase))throw new InvalidDataException("Invalid kernel journal path");
        return full;
    }
    // The caller has already decoded/validated the native packet. False means a
    // durable record belongs to recovery/delivery; do not collect or enqueue it again.
    internal bool Prepare(string eventId,byte[] bytes)
    {
        if(!WindowsKernelDecoder.ValidRecordLength(bytes.Length))throw new InvalidDataException("Kernel event length mismatch");
        var target=RecordPath(eventId);
        lock(gate)
        {
            if(File.Exists(target))
            {
                if(!File.ReadAllBytes(target).AsSpan().SequenceEqual(bytes))throw new IOException("Kernel journal identity collision");
            }
            else
            {
                if(scheduled.Contains(target))throw new IOException("Scheduled kernel journal missing; acknowledgement withheld");
                if(Directory.EnumerateFiles(directory,"*.record").Take(capacity).Count()>=capacity)throw new IOException("Kernel journal capacity exceeded; driver acknowledgement withheld");
                var temporary=target+"."+Guid.NewGuid().ToString("N")+".tmp";
                using(var file=new FileStream(temporary,FileMode.CreateNew,FileAccess.Write,FileShare.None,4096,FileOptions.WriteThrough)){file.Write(bytes);file.Flush(true);}
                if(OperatingSystem.IsWindows())
                {
                    // Same-directory commit, without REPLACE_EXISTING. Retain a
                    // failed temporary file for diagnosis; never overwrite evidence.
                    if(!MoveFileEx(temporary,target,8))throw new IOException("Kernel journal commit failed: "+Marshal.GetLastPInvokeError());
                }
                else File.Move(temporary,target,false);
                if(!File.ReadAllBytes(target).AsSpan().SequenceEqual(bytes))throw new IOException("Committed kernel journal failed byte verification; acknowledgement withheld");
            }
            return !scheduled.Contains(target);
        }
    }
    internal bool Schedule(string path)
    {
        path=ValidatePath(path);
        lock(gate)
        {
            if(!File.Exists(path))throw new IOException("Cannot schedule missing kernel journal");
            if(!WindowsKernelAcquisitionJournal.Ready(path))return false;
            return scheduled.Add(path);
        }
    }
    internal void Complete(string path)
    {
        path=ValidatePath(path);
        lock(gate)
        {
            if(!scheduled.Contains(path))throw new InvalidOperationException("Kernel journal has no delivery owner");
            File.Delete(path); // only after the caller's successful durable publication
            scheduled.Remove(path);
        }
    }
    [DllImport("kernel32.dll",CharSet=CharSet.Unicode,SetLastError=true)]
    [return:MarshalAs(UnmanagedType.Bool)]private static extern bool MoveFileEx(string source,string destination,uint flags);
}
