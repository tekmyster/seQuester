using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using Microsoft.Win32.SafeHandles;
using RansomFree.Contracts;

namespace RansomFree.Client.Forensics;

// One private destination and one exact terminal native tuple. No actor source
// pathname/PID is opened. The journal must persist this admission before SELECT.
internal sealed class LinuxSnapshotAdmission:IDisposable
{
    [DllImport("libc",SetLastError=true,EntryPoint="fallocate")]
    private static extern int Allocate(SafeFileHandle file,int mode,long offset,long length);
    private readonly FileStream stream;
    private readonly IncrementalHash digest=IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
    private long written;
    private bool started,disposed,failed;
    private readonly object gate=new();
    private LinuxSnapshotWriteReceipt? receipt;
    internal string SourceEventId {get;}
    internal string SnapshotId {get;}
    internal string PrivatePath {get;}
    internal string RawSha256 {get;}
    internal LinuxActorLeaseStatus ExpectedStatus {get;}
    internal FileIdentityEvidence ReservedFile {get;}
    internal bool PhysicalAllocationEstablished {get;}
    internal FileIdentityEvidence? VerifiedFile {get;private set;}
    internal string? VerifiedSha256 {get;private set;}
    internal bool IntentCommitted {get{lock(gate)return receipt!=null;}}
    internal LinuxSnapshotWriteReceipt RequireWriteReceipt()
    {lock(gate){if(receipt==null||!receipt.Matches(this))throw new InvalidDataException("Matching immutable snapshot write receipt required");return receipt;}}
    internal void BindReceipt(LinuxSnapshotWriteReceipt value)
    {lock(gate){if(disposed||failed||started||receipt!=null||!value.Matches(this))throw new InvalidDataException("Snapshot write receipt cannot be bound");receipt=value;}}
    internal LinuxSnapshotAdmission(string path,string id,AgentEvent observation,LinuxActorLeaseStatus expected)
    {
        var kernel=observation.Attribution?.LinuxKernel??throw new InvalidDataException("Native observation required for snapshot admission");
        if(!expected.Ready||!expected.Matches(kernel))throw new InvalidDataException("Snapshot admission requires a matching terminal native status");
        SourceEventId=observation.EventId;RawSha256=kernel.NativeObservationSha256;
        SnapshotId=id;PrivatePath=path;ExpectedStatus=expected;EvidenceDurability.NoLinks(path);
        var options=new FileStreamOptions{Mode=FileMode.CreateNew,Access=FileAccess.ReadWrite,Share=FileShare.None};
        if(!OperatingSystem.IsWindows())options.UnixCreateMode=UnixFileMode.UserRead|UnixFileMode.UserWrite;
        stream=new FileStream(path,options);
        try
        {
            if(OperatingSystem.IsLinux())
            {
                if(Allocate(stream.SafeFileHandle,0,0,checked((long)expected.Size))!=0)throw new Win32Exception(Marshal.GetLastPInvokeError());
                PhysicalAllocationEstablished=true;
            }
            else stream.SetLength(checked((long)expected.Size)); // Isolated transport replay only.
            stream.Flush(true);EvidenceDurability.DirectoryCommitted(Path.GetDirectoryName(path)!);
            ReservedFile=NativeFileIdentity.Read(stream);
            if(ReservedFile.Size!=(long)expected.Size||ReservedFile.StableId==null)throw new IOException("Snapshot allocation identity unavailable");
        }
        catch{stream.Dispose();digest.Dispose();throw;}
    }
    internal void BeginRead(AgentEvent observation,LinuxActorLeaseStatus status)
    {
      lock(gate)
      {
        ObjectDisposedException.ThrowIf(disposed,this);
        RequireWriteReceipt();
        if(failed||started||SourceEventId!=observation.EventId||RawSha256!=observation.Attribution?.LinuxKernel?.NativeObservationSha256||status!=ExpectedStatus||!status.Ready||!status.Matches(observation.Attribution!.LinuxKernel!))throw new InvalidDataException("Snapshot admission or pre-select native identity differs");
        var actual=NativeFileIdentity.Read(stream);
        if(!NativeFileIdentity.Same(actual,ReservedFile))throw new InvalidDataException("Reserved private file changed before select");
        started=true;stream.Position=0;
      }
    }
    internal void Append(ReadOnlySpan<byte> bytes)
    {
      lock(gate)
      {
        if(disposed||failed||!started||VerifiedFile!=null||bytes.Length==0||written+bytes.Length>(long)ExpectedStatus.Size)throw new InvalidOperationException("Snapshot write outside admitted bounds");
        stream.Write(bytes);digest.AppendData(bytes);written+=bytes.Length;
      }
    }
    internal void Finish(LinuxActorLeaseStatus status)
    {
      lock(gate)
      {
        if(disposed||failed||!started||VerifiedFile!=null||written!=(long)ExpectedStatus.Size||status!=ExpectedStatus||!status.Ready)throw new InvalidDataException("Snapshot read did not complete against admitted status");
        stream.Flush(true);var before=NativeFileIdentity.Read(stream);
        if(before.StableId!=ReservedFile.StableId||before.Size!=ReservedFile.Size)throw new InvalidDataException("Private destination identity changed during read");
        stream.Position=0;var hash=Convert.ToHexString(SHA256.HashData(stream));var after=NativeFileIdentity.Read(stream);
        if(hash!=Convert.ToHexString(digest.GetHashAndReset())||!NativeFileIdentity.Same(before,after))throw new IOException("Private snapshot readback hash or metadata differs");
        VerifiedFile=after;VerifiedSha256=hash;
      }
    }
    internal void MarkFailed(){lock(gate){failed=true;VerifiedFile=null;VerifiedSha256=null;}}
    public void Dispose(){lock(gate){if(disposed)return;disposed=true;stream.Dispose();digest.Dispose();}}
}
