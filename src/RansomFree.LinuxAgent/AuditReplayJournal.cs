using System.Buffers.Binary;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace RansomFree.LinuxAgent;

// Collector-side durable ownership for protocol-v2 frames. Admission and parser
// retirement are separate: never acknowledge channel admission as persistence.
// Integration must retire only at an empty parser boundary after its emitted
// packets/status are durable. Interrupted partial records remain for replay.
internal sealed record AuditReplayFrame(Guid RelayInstance,long Sequence,long LossTotal,byte[] Bytes)
{
    public byte[] Encode()
    {
        Validate();var result=new byte[32+Bytes.Length];RelayInstance.TryWriteBytes(result);
        BinaryPrimitives.WriteInt64LittleEndian(result.AsSpan(16),Sequence);
        BinaryPrimitives.WriteInt64LittleEndian(result.AsSpan(24),LossTotal);Bytes.CopyTo(result,32);return result;
    }
    public static AuditReplayFrame Decode(byte[] bytes)
    {
        if(bytes.Length is <32 or >8224)throw new InvalidDataException("Invalid audit replay frame length.");
        var result=new AuditReplayFrame(new Guid(bytes.AsSpan(0,16)),BinaryPrimitives.ReadInt64LittleEndian(bytes.AsSpan(16)),BinaryPrimitives.ReadInt64LittleEndian(bytes.AsSpan(24)),bytes[32..]);result.Validate();return result;
    }
    public void Validate()
    {
        if(RelayInstance==Guid.Empty||Sequence<=0||LossTotal<0||Bytes==null||Bytes.Length>8192)throw new InvalidDataException("Invalid audit replay identity or payload.");
    }
}
internal sealed record AuditReplayEntry(long Order,AuditReplayFrame Frame,long LossDelta);
internal sealed record AuditReplayAdmission(AuditReplayEntry? Entry,bool Duplicate);
internal sealed record AuditReplayPeer(long Sequence,long LossTotal,string Digest);
internal sealed record AuditReplayCheckpoint(int Version,long LastOrder,long RetiredOrder,Dictionary<Guid,AuditReplayPeer> Peers);
internal sealed class AuditReplayCapacityException:IOException
{
    public AuditReplayCapacityException():base("Audit replay storage full; admission refused, retained input not overwritten."){}
}
[JsonSerializable(typeof(AuditReplayCheckpoint))]
internal partial class AuditReplayJsonContext:JsonSerializerContext {}

[System.Runtime.Versioning.SupportedOSPlatform("linux")]
internal sealed class AuditReplayJournal:IDisposable
{
    const int MaxEntries=4096,MaxPeers=256;
    const long MaxBytes=64L*1024*1024;
    readonly string root;
    readonly Action<string,bool> validate;
    readonly FileStream lease;
    readonly object gate=new();
    readonly SortedDictionary<long,AuditReplayEntry> entries=[];
    readonly Dictionary<(Guid,long),AuditReplayEntry> identities=[];
    AuditReplayCheckpoint checkpoint;
    long bytes;
    bool disposed;
    [DllImport("libc",SetLastError=true)] static extern int open(string path,int flags);
    [DllImport("libc",SetLastError=true)] static extern int fsync(int descriptor);
    [DllImport("libc",SetLastError=true)] static extern int close(int descriptor);

    public AuditReplayJournal(string root,Action<string,bool> validate)
    {
        if(!OperatingSystem.IsLinux())throw new PlatformNotSupportedException("Durable audit replay requires Linux directory fsync.");
        this.root=Path.GetFullPath(root);this.validate=validate;
        validate(Path.GetDirectoryName(this.root)!,true);
        if(!Directory.Exists(this.root))
        {
            Directory.CreateDirectory(this.root,UnixFileMode.UserRead|UnixFileMode.UserWrite|UnixFileMode.UserExecute);
            SyncDirectory(Path.GetDirectoryName(this.root)!);
        }
        validate(this.root,true);
        if((File.GetUnixFileMode(this.root)&(UnixFileMode.GroupRead|UnixFileMode.GroupWrite|UnixFileMode.GroupExecute|UnixFileMode.OtherRead|UnixFileMode.OtherWrite|UnixFileMode.OtherExecute))!=0)throw new UnauthorizedAccessException("Replay journal must be root-private.");
        var leasePath=Path.Combine(this.root,"owner.lock");if(File.Exists(leasePath))validate(leasePath,false);
        lease=new FileStream(leasePath,new FileStreamOptions{Mode=FileMode.OpenOrCreate,Access=FileAccess.ReadWrite,Share=FileShare.None,UnixCreateMode=UnixFileMode.UserRead|UnixFileMode.UserWrite});
        try
        {
            var state=Path.Combine(this.root,"checkpoint.json");
            if(File.Exists(state))
            {
                validate(state,false);if(new FileInfo(state).Length>131072)throw new InvalidDataException("Replay checkpoint too large.");
                checkpoint=JsonSerializer.Deserialize(File.ReadAllBytes(state),AuditReplayJsonContext.Default.AuditReplayCheckpoint)??throw new InvalidDataException("Missing replay checkpoint.");
            }
            else checkpoint=new(2,0,0,[]);
            if(checkpoint.Version!=2||checkpoint.LastOrder<0||checkpoint.RetiredOrder<0||checkpoint.RetiredOrder>checkpoint.LastOrder||checkpoint.Peers==null||checkpoint.Peers.Count>MaxPeers)throw new InvalidDataException("Invalid replay checkpoint.");
            foreach(var peer in checkpoint.Peers)
                if(peer.Key==Guid.Empty||peer.Value.Sequence<=0||peer.Value.LossTotal<0||peer.Value.Digest.Length!=64||!peer.Value.Digest.All(Uri.IsHexDigit))throw new InvalidDataException("Invalid replay peer checkpoint.");
            var inventory=Directory.EnumerateFiles(this.root,"*.frame").Take(MaxEntries+1).OrderBy(Path.GetFileName,StringComparer.Ordinal).ToArray();
            if(inventory.Length>MaxEntries)throw new IOException("Replay inventory capacity exceeded; files retained.");
            foreach(var path in inventory)
            {
                validate(path,false);var name=Path.GetFileNameWithoutExtension(path);
                if(name.Length!=20||!name.All(char.IsAsciiDigit)||!long.TryParse(name,out var order)||order<=0)throw new InvalidDataException("Invalid replay record name.");
                if(new FileInfo(path).Length is <80 or >8272)throw new InvalidDataException("Invalid replay record size.");
                var raw=File.ReadAllBytes(path);var frameBytes=raw[48..];var delta=BinaryPrimitives.ReadInt64LittleEndian(raw.AsSpan(40));
                if(BinaryPrimitives.ReadInt64LittleEndian(raw.AsSpan(32))!=order||!CryptographicOperations.FixedTimeEquals(raw.AsSpan(0,32),SHA256.HashData(raw.AsSpan(32))))throw new InvalidDataException("Replay record integrity failed.");
                var frame=AuditReplayFrame.Decode(frameBytes);
                if(delta<0||delta>frame.LossTotal)throw new InvalidDataException("Invalid retained loss delta.");
                if(order<=checkpoint.RetiredOrder)continue; // Previously committed unlink interrupted; retain until maintenance.
                if(order>checkpoint.LastOrder)
                {
                    if(order!=checkpoint.LastOrder+1)throw new InvalidDataException("Replay global sequence gap.");
                    var prior=checkpoint.Peers.GetValueOrDefault(frame.RelayInstance);
                    ValidateNext(frame,prior);Remember(order,frame,frameBytes);
                }
                var entry=new AuditReplayEntry(order,frame,delta);entries.Add(order,entry);identities.Add((frame.RelayInstance,frame.Sequence),entry);bytes+=raw.Length;
            }
            if(bytes>MaxBytes||checkpoint.Peers.Count>MaxPeers)throw new IOException("Replay capacity exceeded; files retained.");
            var expected=checkpoint.RetiredOrder;
            foreach(var order in entries.Keys)if(order!=++expected)throw new InvalidDataException("Missing retained replay record.");
            if(expected!=checkpoint.LastOrder)throw new InvalidDataException("Replay checkpoint references missing retained input.");
            // Recover a raw record written before its admission checkpoint. A
            // duplicate may be acknowledged only after this checkpoint is durable.
            SaveCheckpoint();
        }
        catch{lease.Dispose();throw;}
    }
    static void ValidateNext(AuditReplayFrame frame,AuditReplayPeer? prior)
    {
        if(frame.Sequence!=(prior?.Sequence??0)+1||frame.LossTotal<(prior?.LossTotal??0))throw new InvalidDataException("Replay sequence gap or decreasing loss counter.");
    }
    void Remember(long order,AuditReplayFrame frame,byte[] frameBytes)
    {
        checkpoint.Peers[frame.RelayInstance]=new(frame.Sequence,frame.LossTotal,Convert.ToHexString(SHA256.HashData(frameBytes)));
        checkpoint=checkpoint with{LastOrder=order};
    }
    string FramePath(long order)=>Path.Combine(root,order.ToString("D20")+".frame");
    void SyncDirectory()=>SyncDirectory(root);
    static void SyncDirectory(string directory)
    {
        // Linux O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC. Root ancestry is validated.
        var descriptor=open(directory,0x10000|0x20000|0x80000);
        if(descriptor<0)throw new System.ComponentModel.Win32Exception(Marshal.GetLastPInvokeError());
        try{if(fsync(descriptor)!=0)throw new System.ComponentModel.Win32Exception(Marshal.GetLastPInvokeError());}finally{close(descriptor);}
    }
    void SaveCheckpoint()
    {
        var target=Path.Combine(root,"checkpoint.json");var temporary=Path.Combine(root,Guid.NewGuid().ToString("N")+".tmp");
        using(var file=new FileStream(temporary,new FileStreamOptions{Mode=FileMode.CreateNew,Access=FileAccess.Write,Share=FileShare.None,UnixCreateMode=UnixFileMode.UserRead|UnixFileMode.UserWrite}))
        {JsonSerializer.Serialize(file,checkpoint,AuditReplayJsonContext.Default.AuditReplayCheckpoint);file.Flush(true);}
        if(File.Exists(target))validate(target,false);
        File.Move(temporary,target,true);SyncDirectory();
    }
    public AuditReplayEntry[] Pending(){lock(gate){ObjectDisposedException.ThrowIf(disposed,this);return entries.Values.ToArray();}}
    public long TotalLoss {get{lock(gate){ObjectDisposedException.ThrowIf(disposed,this);return checkpoint.Peers.Values.Sum(x=>x.LossTotal);}}}
    public long RetiredOrder {get{lock(gate)return checkpoint.RetiredOrder;}}
    public int PendingCount {get{lock(gate)return entries.Count;}}
    public long PendingBytes {get{lock(gate)return bytes;}}
    public bool IsFaulted {get{lock(gate)return disposed;}}
    public long NextSequence(Guid instance){lock(gate){ObjectDisposedException.ThrowIf(disposed,this);return checked((checkpoint.Peers.GetValueOrDefault(instance)?.Sequence??0)+1);}}
    public long ReportedLoss(Guid instance){lock(gate){ObjectDisposedException.ThrowIf(disposed,this);return checkpoint.Peers.GetValueOrDefault(instance)?.LossTotal??0;}}
    public AuditReplayEntry? FirstPending(){lock(gate){ObjectDisposedException.ThrowIf(disposed,this);return entries.Count==0?null:entries.First().Value;}}
    public AuditReplayAdmission Admit(AuditReplayFrame frame)
    {
        lock(gate)
        {
            ObjectDisposedException.ThrowIf(disposed,this);var payload=frame.Encode();frame=AuditReplayFrame.Decode(payload);var prior=checkpoint.Peers.GetValueOrDefault(frame.RelayInstance);
            if(identities.TryGetValue((frame.RelayInstance,frame.Sequence),out var retained))
            {
                if(!retained.Frame.Encode().AsSpan().SequenceEqual(payload))throw new InvalidDataException("Replay duplicate bytes differ.");
                return new(null,true);
            }
            if(prior!=null&&frame.Sequence==prior.Sequence)
            {
                if(prior.Digest!=Convert.ToHexString(SHA256.HashData(payload)))throw new InvalidDataException("Retired replay duplicate bytes differ.");
                return new(null,true);
            }
            ValidateNext(frame,prior);
            if(prior==null&&checkpoint.Peers.Count>=MaxPeers||entries.Count>=MaxEntries||bytes+payload.Length+48>MaxBytes)throw new AuditReplayCapacityException();
            var delta=AuditLossCounter.Delta(frame.LossTotal,prior?.LossTotal??0);
            var order=checked(checkpoint.LastOrder+1);var record=new byte[48+payload.Length];BinaryPrimitives.WriteInt64LittleEndian(record.AsSpan(32),order);BinaryPrimitives.WriteInt64LittleEndian(record.AsSpan(40),delta);payload.CopyTo(record,48);SHA256.HashData(record.AsSpan(32)).CopyTo(record,0);
            // If either durable write fails, fail closed. Reopening recovers the
            // complete raw file; this object cannot accept additional frames.
            try
            {
                using(var file=new FileStream(FramePath(order),new FileStreamOptions{Mode=FileMode.CreateNew,Access=FileAccess.Write,Share=FileShare.None,UnixCreateMode=UnixFileMode.UserRead|UnixFileMode.UserWrite}))
                {file.Write(record);file.Flush(true);}
                SyncDirectory();Remember(order,frame,payload);SaveCheckpoint();
            }
            catch{disposed=true;lease.Dispose();throw;}
            var entry=new AuditReplayEntry(order,frame,delta);
            entries.Add(order,entry);identities.Add((frame.RelayInstance,frame.Sequence),entry);bytes+=record.Length;return new(entry,false);
        }
    }
    // Caller establishes durable output and an empty parser boundary first.
    public void RetireThrough(long order)
    {
        lock(gate)
        {
            ObjectDisposedException.ThrowIf(disposed,this);
            if(order<checkpoint.RetiredOrder||order>checkpoint.LastOrder)throw new InvalidDataException("Invalid parser replay retirement.");
            checkpoint=checkpoint with{RetiredOrder=order};
            try{SaveCheckpoint();}catch{disposed=true;lease.Dispose();throw;}
            foreach(var entry in entries.Values.TakeWhile(x=>x.Order<=order).ToArray())
            {
                var path=FramePath(entry.Order);validate(path,false);File.Delete(path);entries.Remove(entry.Order);identities.Remove((entry.Frame.RelayInstance,entry.Frame.Sequence));bytes-=entry.Frame.Bytes.Length+80;
            }
            SyncDirectory();
        }
    }
    public void Dispose(){lock(gate){if(disposed)return;disposed=true;lease.Dispose();}}
}
