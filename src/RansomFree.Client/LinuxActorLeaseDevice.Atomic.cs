using System.Buffers.Binary;

namespace RansomFree.Client;

public sealed partial class LinuxActorLeaseDevice
{
    internal const uint AtomicStatusCommand=0xc0c05110,AtomicStartCommand=0x40885111,
        AtomicDropCommand=0x40885112,AtomicSelectCommand=0x40885113,AtomicRegisterCommand=0x40885115;
    private ulong atomicEpoch;
    // These exact requests exist only on this retained, exclusive controller.
    // Persisted receipts alone never reconstruct execution capabilities.
    private readonly Dictionary<ulong,LinuxAtomicLeaseRequest> atomicRequests=[];
    internal void RegisterAtomicSource(ulong epoch)
    {
        lock(gate)
        {
            ObjectDisposedException.ThrowIf(disposed,this);
            if(epoch==0||atomicEpoch!=0)throw new InvalidOperationException("Atomic source epoch must be pinned once on its owned controller");
            var request=new byte[136];BinaryPrimitives.WriteUInt32LittleEndian(request,1);BinaryPrimitives.WriteUInt32LittleEndian(request.AsSpan(4),136);
            BinaryPrimitives.WriteUInt64LittleEndian(request.AsSpan(72),epoch);transport.Control(AtomicRegisterCommand,request);atomicEpoch=epoch;
        }
    }
    private LinuxAtomicLeaseStatus AtomicStatusCore(LinuxAtomicLeaseKey expected)
    {
        if(!expected.Valid||atomicEpoch==0||expected.ProviderEpoch!=atomicEpoch)throw new InvalidDataException("Atomic operation does not belong to this admitted source epoch");
        var bytes=new byte[192];BinaryPrimitives.WriteUInt32LittleEndian(bytes,1);BinaryPrimitives.WriteUInt32LittleEndian(bytes.AsSpan(4),136);expected.Encode().CopyTo(bytes,8);
        transport.Control(AtomicStatusCommand,bytes);var status=LinuxAtomicLeaseStatus.Decode(bytes);
        if(status.Key!=expected)throw new InvalidDataException("Native actor/target/process/operation key differs from committed raw observation");
        if(atomicRequests.TryGetValue(expected.LeaseId,out var request)&&(status.ReceiptLow!=request.ReceiptLow||status.ReceiptHigh!=request.ReceiptHigh))
            throw new InvalidDataException("Native copy receipt differs from this controller's original durable authorization");
        return status;
    }
    internal LinuxAtomicLeaseStatus AtomicStatus(LinuxAtomicLeaseKey key)
    {lock(gate){ObjectDisposedException.ThrowIf(disposed,this);return AtomicStatusCore(key);}}
    internal void StartAtomicAuthorizedCopy(LinuxAtomicLeaseKey key,string committedAuthorizationId)
    {
        lock(gate)
        {
            ObjectDisposedException.ThrowIf(disposed,this);var request=LinuxAtomicLeaseRequest.Authorized(key,committedAuthorizationId);
            if(atomicRequests.ContainsKey(key.LeaseId))throw new InvalidOperationException("This controller already attempted START for this exact lease");
            var before=AtomicStatusCore(key);
            if(before.State!=3||before.Error!=0||before.Bytes!=0||before.ReceiptLow!=0||before.ReceiptHigh!=0||before.ActorReferenceOwned!=1||before.WriteExclusionOwned!=1)
                throw new InvalidDataException("Actor is not finalized and awaiting its first durable raw START");
            // Retain attempted identity even if the transport returns ambiguously.
            atomicRequests.Add(key.LeaseId,request);transport.Control(AtomicStartCommand,request.Encode());
        }
    }
    internal void SelectAtomic(LinuxAtomicLeaseKey key)
    {
        lock(gate)
        {
            ObjectDisposedException.ThrowIf(disposed,this);var status=AtomicStatusCore(key);
            if(status.State!=7||status.Error!=0||status.Size is 0 or >4194304||status.Bytes!=status.Size||status.ActorReferenceOwned!=0||status.WriteExclusionOwned!=0)
                throw new InvalidDataException("Atomic bytes have not completed and drained their source reference");
            transport.Control(AtomicSelectCommand,RequireAtomicRequest(key).Encode());
        }
    }
    internal void DropAtomic(LinuxAtomicLeaseKey key)
    {
        lock(gate)
        {
            ObjectDisposedException.ThrowIf(disposed,this);var status=AtomicStatusCore(key);
            if(status.State is not (7 or 8)||status.ActorReferenceOwned!=0||status.WriteExclusionOwned!=0)
                throw new InvalidDataException("Atomic release refused while native ownership remains outstanding");
            transport.Control(AtomicDropCommand,RequireAtomicRequest(key).Encode());
            // Keep attempted request until controller closes; never issue again
            // if receipt persistence after returned DROP later fails.
        }
    }
    private LinuxAtomicLeaseRequest RequireAtomicRequest(LinuxAtomicLeaseKey key)
        =>atomicRequests.TryGetValue(key.LeaseId,out var request)&&request.Key==key?request:throw new InvalidOperationException("No original in-process atomic authorization for this lease");
}
