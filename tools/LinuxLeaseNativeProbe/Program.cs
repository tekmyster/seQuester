using System.ComponentModel;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using RansomFree.Client;
using RansomFree.Client.Forensics;
using RansomFree.Contracts;

// Isolated native qualification runner, never an installed sensor entry point.
if(args.Length is <1 or >2||args.Length==2&&args[1]!="--admitted"||!OperatingSystem.IsLinux())throw new ArgumentException("Pass a new private output directory on the owned Linux qualification VM and optional --admitted");
var admitted=args.Length==2;
var root=Path.GetFullPath(args[0]);
if(!root.StartsWith("/var/tmp/sequester-managed-lease-native-",StringComparison.Ordinal)||Directory.Exists(root))throw new InvalidOperationException("Fresh owned lab directory required");
for(string? p=Path.GetDirectoryName(root);p!=null;p=Path.GetDirectoryName(p))if(Path.Exists(p)&&(File.GetAttributes(p)&FileAttributes.ReparsePoint)!=0)throw new IOException("Lab directory must not follow links");
Directory.CreateDirectory(root,UnixFileMode.UserRead|UnixFileMode.UserWrite|UnixFileMode.UserExecute);
DirectorySync.Flush(Path.GetDirectoryName(root)!);
using var device=new LinuxActorLeaseDevice();var sensor=Guid.NewGuid().ToString("N");var collector=Guid.NewGuid().ToString("N");long sequence=0;
Console.WriteLine(JsonSerializer.Serialize(new{Ready=true,Sensor=sensor,Collector=collector,Root=root}));
void Save(string path,ReadOnlySpan<byte> bytes){if(!OperatingSystem.IsLinux())throw new PlatformNotSupportedException();using(var stream=new FileStream(path,new FileStreamOptions{Mode=FileMode.CreateNew,Access=FileAccess.Write,Share=FileShare.None,UnixCreateMode=UnixFileMode.UserRead|UnixFileMode.UserWrite})){stream.Write(bytes);stream.Flush(true);}DirectorySync.Flush(root);}
while(await Console.In.ReadLineAsync() is {} line)
{
    if(line=="stop")break;
    var raw=Encoding.UTF8.GetBytes(line);var e=LinuxKernelDecoder.Decode(raw,sensor,collector,++sequence,DateTimeOffset.UtcNow);var k=e.Attribution!.LinuxKernel!;
    // Persist before any native status/select/read; failures leave the record.
    Save(Path.Combine(root,e.EventId+".native.json"),raw);Save(Path.Combine(root,e.EventId+".event.json"),JsonSerializer.SerializeToUtf8Bytes(e));
    using var journal=admitted?new LinuxForensicJournal(Path.Combine(root,e.EventId),sensor):null;
    journal?.CommitObservation(raw,e,new());
    string? failure=null;LinuxActorSnapshot? snapshot=null;LinuxActorLeaseStatus? lastStatus=null;string? manifestName=null;var dropped=false;var badEpochRejected=false;
    try
    {
        try{device.Status(k with{ProviderEpoch=(ulong.Parse(k.ProviderEpoch)^1UL).ToString(System.Globalization.CultureInfo.InvariantCulture)});throw new Exception("Mismatched provider epoch accepted");}catch(InvalidDataException){badEpochRejected=true;}
        var until=Stopwatch.StartNew();LinuxActorLeaseStatus status;
        do{status=device.Status(k);lastStatus=status;if(status.Ready||status.State is 4 or 5)break;if(until.Elapsed>TimeSpan.FromSeconds(4))throw new TimeoutException("Native actor copy has not reached a readable terminal state");await Task.Delay(20);}while(true);
        if(journal==null)snapshot=device.ReadReadySnapshot(k);
        else
        {
            if(!status.Ready)throw new InvalidDataException("Native actor did not reach a readable terminal status");
            journal.AcquireAdmittedSnapshot(device,e.EventId,status);
            var a=journal.Read(e.EventId).Acquisition??throw new IOException("Admitted acquisition outcome uncommitted");
            if(a.Status.State!="captured")throw new IOException("Admitted acquisition unavailable: "+a.Status.Reason);
            using var restored=journal.RestoreActor(e.EventId);
            if(restored.Image==null)throw new IOException("Admitted private artifact recovery failed");
            restored.Image.Position=0;using var buffer=new MemoryStream();restored.Image.CopyTo(buffer);var retained=buffer.ToArray();
            if(Convert.ToHexString(SHA256.HashData(retained))!=a.SnapshotSha256)throw new IOException("Admitted private artifact hash changed");
            snapshot=new(status,retained,a.SnapshotSha256!,a.SizeMatchesEarlierObservation==true);
        }
        var artifact=e.EventId+".bin";var path=Path.Combine(root,artifact);Save(path,snapshot.Bytes.Span);
        FileIdentityEvidence file;using(var saved=new FileStream(path,FileMode.Open,FileAccess.Read,FileShare.Read))
        {
            file=NativeFileIdentity.Read(saved);
            if(saved.Length!=snapshot.Bytes.Length||Convert.ToHexString(SHA256.HashData(saved))!=snapshot.Sha256)throw new IOException("Private snapshot readback differs");
        }
        manifestName=e.EventId+".manifest.json";
        var manifest=new{Schema="sequester.linux-managed-lease-native/v1",SourceEventId=e.EventId,NativeObservationSha256=k.NativeObservationSha256,NativeStatus=snapshot.NativeStatus,SnapshotSha256=snapshot.Sha256,snapshot.SizeMatchesEarlierObservation,SnapshotFile=file,Artifact=artifact,PreservedUtc=DateTimeOffset.UtcNow,WhitelistEligible=false,Admitted=admitted,Acquisition=journal?.Read(e.EventId).Acquisition,SnapshotIntent=journal?.ReadSnapshotIntent(e.EventId),Scope="Owned native protocol qualification; backing-file bytes, not process memory"};
        var encoded=JsonSerializer.SerializeToUtf8Bytes(manifest);Save(Path.Combine(root,manifestName),encoded);
        if(!File.ReadAllBytes(Path.Combine(root,manifestName)).AsSpan().SequenceEqual(encoded))throw new IOException("Private manifest readback differs");
        if(journal!=null&&device.Status(k)!=snapshot.NativeStatus)throw new InvalidDataException("Native status changed before terminal release");
        device.Drop(k);dropped=true;journal?.RecordDrop(e.EventId,"returned");
        try{device.Status(k);throw new Exception("Dropped native lease remained readable");}catch(Win32Exception ex)when(ex.NativeErrorCode==2){}
    }
    catch(Exception ex)
    {
        failure=ex.GetType().Name+": "+ex.Message;
        if(journal!=null&&journal.Read(e.EventId).Acquisition==null)
        {
            try{journal.CommitUnavailable(e.EventId,"ACTOR_COPY_UNAVAILABLE_NATIVE_QUALIFICATION",lastStatus,ex is Win32Exception native?native.NativeErrorCode.ToString():ex.GetType().Name);}
            catch(Exception persistence){failure+="; ACQUISITION_OUTCOME_UNCOMMITTED: "+persistence.GetType().Name;}
        }
    }
    var result=new{EventId=e.EventId,Passed=failure==null,Error=failure,SnapshotSha256=snapshot?.Sha256,Bytes=snapshot?.Bytes.Length,NativeStatus=snapshot?.NativeStatus??lastStatus,Manifest=manifestName,Dropped=dropped,BadEpochRejected=badEpochRejected,WhitelistEligible=false,Admitted=admitted,Acquisition=journal?.Read(e.EventId).Acquisition,SnapshotIntent=journal?.ReadSnapshotIntent(e.EventId)};
    Save(Path.Combine(root,e.EventId+".result.json"),JsonSerializer.SerializeToUtf8Bytes(result));Console.WriteLine(JsonSerializer.Serialize(result));
}
// This can wait on an actual kernel read; this runner never reports an early
// timeout as native close completion or kills a kernel worker.
device.Dispose();Console.WriteLine(JsonSerializer.Serialize(new{Closed=true,Observations=sequence}));

static class DirectorySync
{
    [DllImport("libc",SetLastError=true,EntryPoint="open")]private static extern int Open(string path,int flags);
    [DllImport("libc",SetLastError=true,EntryPoint="fsync")]private static extern int Sync(int fd);
    [DllImport("libc",EntryPoint="close")]private static extern int Close(int fd);
    public static void Flush(string path)
    {
        var fd=Open(path,0x10000|0x20000|0x80000);if(fd<0)throw new Win32Exception(Marshal.GetLastPInvokeError());
        try{if(Sync(fd)!=0)throw new Win32Exception(Marshal.GetLastPInvokeError());}finally{Close(fd);}
    }
}
