using RansomFree.Contracts;

namespace RansomFree.Client.Forensics;

internal sealed class LinuxSnapshotWriteReceipt
{
    private readonly string eventId,snapshotId,rawHash;
    private readonly LinuxActorLeaseStatus status;
    private readonly FileIdentityEvidence file;
    private LinuxSnapshotWriteReceipt(LinuxSnapshotAdmission a)
    {eventId=a.SourceEventId;snapshotId=a.SnapshotId;rawHash=a.RawSha256;status=a.ExpectedStatus;file=a.ReservedFile;}
    internal static LinuxSnapshotWriteReceipt ReadCommitted(LinuxForensicJournal journal,LinuxSnapshotAdmission a)
    {
        var intent=journal.ReadSnapshotIntent(a.SourceEventId);var work=journal.Read(a.SourceEventId);
        if(intent?.State!="write-intent"||intent.SnapshotId!=a.SnapshotId||intent.ExpectedStatus!=a.ExpectedStatus||intent.ReservedFile!=a.ReservedFile||work.Acquisition!=null||work.Observation.Attribution!.LinuxKernel!.NativeObservationSha256!=a.RawSha256)throw new InvalidDataException("No matching committed snapshot write intent");
        return new(a);
    }
    internal bool Matches(LinuxSnapshotAdmission a)=>eventId==a.SourceEventId&&snapshotId==a.SnapshotId&&rawHash==a.RawSha256&&status==a.ExpectedStatus&&file==a.ReservedFile;
}
