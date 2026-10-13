using System.Security.Cryptography;
using System.Text.Json;
using RansomFree.Client;
using RansomFree.Client.Forensics;
using RansomFree.Contracts;

// Controller fills only an owned loop-mounted filesystem between the ready
// and capture handshakes, then removes its own filler before recovery. This
// path never loads a driver or opens an actor pathname/native device.
static class NativeDiskPressureChecks
{
    internal static async Task Run(string mode,string root,string sensor,byte[] raw,AgentEvent observation,LinuxActorSnapshot snapshot)
    {
        if(!OperatingSystem.IsLinux()||Directory.Exists(root)||!root.StartsWith("/var/tmp/sequester-linux-recovery-",StringComparison.Ordinal))throw new ArgumentException("Fresh owned Linux filesystem path required");
        var preallocate=mode=="snapshot-enospc-admitted";
        var port=new SnapshotAdmissionChecks.Port(snapshot.NativeStatus,snapshot.Bytes.ToArray());
        string? acquisitionError=null,readError=null,observedState=null,verifiedHash=null,privatePath=null;bool allocated=false;
        using(var journal=new LinuxForensicJournal(root,sensor))
        {
            journal.CommitObservation(raw,observation,new());
            LinuxSnapshotAdmission? admission=null;
            if(preallocate)
            {
                admission=journal.AdmitSnapshot(observation.EventId,snapshot.NativeStatus);
                allocated=admission.PhysicalAllocationEstablished;privatePath=admission.PrivatePath;
                if(!allocated)throw new IOException("Native private snapshot was not physically preallocated");
            }
            Console.WriteLine(JsonSerializer.Serialize(new{Ready=true,Mode=mode,PhysicalSnapshotAllocation=allocated,SourceEventId=observation.EventId,ExpectedBytes=snapshot.Bytes.Length}));
            if(await Console.In.ReadLineAsync()!="capture")throw new InvalidDataException("Owned filesystem pressure handshake failed");
            using var device=new LinuxActorLeaseDevice(port);
            try
            {
                if(admission!=null)
                {
                    device.ReadReadySnapshotInto(observation,admission);verifiedHash=admission.VerifiedSha256;
                    journal.CommitAdmittedSnapshot(admission);
                }
                else journal.AcquireAdmittedSnapshot(device,observation.EventId,snapshot.NativeStatus);
            }
            catch(Exception ex)when(ex is IOException or InvalidDataException or System.ComponentModel.Win32Exception or Microsoft.Data.Sqlite.SqliteException)
            {acquisitionError=ex.GetType().Name+":"+(ex is System.ComponentModel.Win32Exception native?native.NativeErrorCode.ToString():ex.HResult.ToString());}
            finally{admission?.Dispose();}
            try{observedState=journal.Read(observation.EventId).Acquisition?.Status.State;}
            catch(Exception ex){readError=ex.GetType().Name;}
            if(port.Drops!=0||port.Selects!=(preallocate?1:0))throw new InvalidDataException("Disk pressure allowed unexpected SELECT or DROP");
            if(preallocate&&!string.Equals(verifiedHash,snapshot.Sha256,StringComparison.OrdinalIgnoreCase))throw new InvalidDataException("Preallocated private copy did not retain the exact actor bytes under actual disk pressure");
            if(!preallocate&&observedState=="captured")throw new InvalidDataException("Unallocated full-filesystem capture was falsely successful");
            Console.WriteLine(JsonSerializer.Serialize(new{CaptureComplete=true,Mode=mode,port.Selects,port.Drops,VerifiedSha256=verifiedHash,AcquisitionState=observedState,AcquisitionError=acquisitionError,ReadError=readError}));
        }
        if(await Console.In.ReadLineAsync()!="recover")throw new InvalidDataException("Owned filler release handshake failed");
        using(var journal=new LinuxForensicJournal(root,sensor))
        {
            var intent=journal.ReadSnapshotIntent(observation.EventId);
            if(intent!=null)journal.RecoverAdmittedSnapshot(observation.EventId);
            else if(journal.Read(observation.EventId).Acquisition==null)journal.CommitUnavailable(observation.EventId,"ACTOR_COPY_UNAVAILABLE_PRESSURE_CAPTURE_UNCOMMITTED");
            var work=journal.Read(observation.EventId);var a=work.Acquisition!;
            if(a.Status.State=="captured")
            {
                using var actor=journal.RestoreActor(observation.EventId);
                if(!preallocate||actor.Image==null||!string.Equals(a.SnapshotSha256,snapshot.Sha256,StringComparison.OrdinalIgnoreCase))throw new InvalidDataException("Invalid recovered pressure capture");
            }
            if(privatePath!=null)
            {
                using var file=File.OpenRead(privatePath);
                if(!Convert.ToHexString(SHA256.HashData(file)).Equals(snapshot.Sha256,StringComparison.OrdinalIgnoreCase))throw new InvalidDataException("Pressure recovery changed private actor bytes");
            }
            Console.WriteLine(JsonSerializer.Serialize(new{Passed=true,Mode=mode,RecoveredState=a.Status.State,RecoveredReason=a.Status.Reason,SnapshotSha256=a.SnapshotSha256,PrivateBytesRetained=privatePath!=null,port.Selects,port.Drops,RawRetained=work.Observation==observation,Scope="Actual owned filesystem pressure; simulated native byte transport; no kernel controller/resource-release qualification"}));
        }
    }
}
