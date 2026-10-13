using System.Buffers.Binary;
using RansomFree.Contracts;

namespace RansomFree.Client;

// Separately negotiated protocol. Never reinterpret the 160-byte legacy status.
internal sealed record LinuxAtomicLeaseKey(ulong LeaseId,ulong Cookie,ulong ProcessId,ulong ThreadId,
    ulong ProcessStartNs,ulong TaskStartNs,ulong SelfExecId,ulong AssociationGeneration,ulong ProviderEpoch,
    ulong ActorDevice,ulong ActorInode,ulong TargetDevice,ulong TargetInode,ulong OperationNonce)
{
    internal bool Valid=>LeaseId is >0 and <=long.MaxValue&&Cookie>0&&ProcessId is >0 and <=int.MaxValue&&ThreadId is >0 and <=uint.MaxValue&&
        ProcessStartNs>0&&TaskStartNs>0&&SelfExecId>0&&AssociationGeneration>0&&(AssociationGeneration&1)==0&&
        ProviderEpoch>0&&ActorDevice is >0 and <=uint.MaxValue&&ActorInode>0&&TargetDevice is >0 and <=uint.MaxValue&&TargetInode>0&&OperationNonce>0;
    internal static LinuxAtomicLeaseKey Decode(ReadOnlySpan<byte> bytes)
    {
        if(bytes.Length!=112)throw new InvalidDataException("Atomic key size differs from native ABI");
        var n=new ulong[14];for(int i=0;i<14;i++)n[i]=BinaryPrimitives.ReadUInt64LittleEndian(bytes[(i*8)..]);
        return new(n[0],n[1],n[2],n[3],n[4],n[5],n[6],n[7],n[8],n[9],n[10],n[11],n[12],n[13]);
    }
    internal bool Matches(LinuxKernelEvidence k)
    {
        string D(ulong n)=>n.ToString(System.Globalization.CultureInfo.InvariantCulture);
        var nonce=k.PermissionObservation is {Stage:1,Schema:1} p?p.OperationNonce:k.IoObservation is {Stage:1,Schema:3} io?io.OperationNonce:null;
        return k.IsValid()&&k.NativeSchemaVersion is 7 or 8&&nonce!=null&&
            LeaseId==(ulong)k.Lease&&D(Cookie)==k.Cookie&&ProcessId==(ulong?)k.ProcessId&&ThreadId==k.ThreadId&&
            D(ProcessStartNs)==k.ProcessStartNs&&D(TaskStartNs)==k.TaskStartNs&&D(SelfExecId)==k.SelfExecId&&
            D(AssociationGeneration)==k.AssociationAfter&&D(ProviderEpoch)==k.ProviderEpoch&&ActorDevice==k.ActorDevice&&D(ActorInode)==k.ActorInode&&
            TargetDevice==k.TargetIdentity?.Device&&D(TargetInode)==k.TargetIdentity?.Inode&&D(OperationNonce)==nonce;
    }
    internal byte[] Encode()
    {
        ulong[] n=[LeaseId,Cookie,ProcessId,ThreadId,ProcessStartNs,TaskStartNs,SelfExecId,AssociationGeneration,ProviderEpoch,ActorDevice,ActorInode,TargetDevice,TargetInode,OperationNonce];
        var bytes=new byte[112];for(int i=0;i<n.Length;i++)BinaryPrimitives.WriteUInt64LittleEndian(bytes.AsSpan(i*8),n[i]);return bytes;
    }
}
internal sealed record LinuxAtomicLeaseRequest(LinuxAtomicLeaseKey Key,ulong ReceiptLow,ulong ReceiptHigh)
{
    internal byte[] Encode()
    {
        if(!Key.Valid||ReceiptLow==0&&ReceiptHigh==0)throw new InvalidDataException("Atomic copy requires full observed key and committed receipt");
        var bytes=new byte[136];BinaryPrimitives.WriteUInt32LittleEndian(bytes,1);BinaryPrimitives.WriteUInt32LittleEndian(bytes.AsSpan(4),136);
        Key.Encode().CopyTo(bytes,8);BinaryPrimitives.WriteUInt64LittleEndian(bytes.AsSpan(120),ReceiptLow);BinaryPrimitives.WriteUInt64LittleEndian(bytes.AsSpan(128),ReceiptHigh);return bytes;
    }
    internal static LinuxAtomicLeaseRequest Authorized(LinuxAtomicLeaseKey key,string durableAuthorizationId)
    {
        if(!Guid.TryParseExact(durableAuthorizationId,"N",out var id)||id==Guid.Empty)throw new InvalidDataException("Durable raw authorization identity missing");
        var bytes=id.ToByteArray();return new(key,BinaryPrimitives.ReadUInt64LittleEndian(bytes),BinaryPrimitives.ReadUInt64LittleEndian(bytes.AsSpan(8)));
    }
}
internal sealed record LinuxAtomicLeaseStatus(LinuxAtomicLeaseKey Key,ulong ReceiptLow,ulong ReceiptHigh,uint State,int Error,
    ulong StartedNs,ulong DeadlineNs,ulong FinishedNs,ulong Size,ulong Bytes,uint ActorReferenceOwned,uint WriteExclusionOwned)
{
    internal static LinuxAtomicLeaseStatus Decode(ReadOnlySpan<byte> data)
    {
        if(data.Length!=192||BinaryPrimitives.ReadUInt32LittleEndian(data)!=1||BinaryPrimitives.ReadUInt32LittleEndian(data[4..])!=136)
            throw new InvalidDataException("Atomic status ABI unavailable or malformed");
        var bytes=data.ToArray();ulong U(int offset)=>BinaryPrimitives.ReadUInt64LittleEndian(bytes.AsSpan(offset));
        var value=new LinuxAtomicLeaseStatus(LinuxAtomicLeaseKey.Decode(data.Slice(8,112)),U(120),U(128),BinaryPrimitives.ReadUInt32LittleEndian(data[136..]),BinaryPrimitives.ReadInt32LittleEndian(data[140..]),U(144),U(152),U(160),U(168),U(176),BinaryPrimitives.ReadUInt32LittleEndian(data[184..]),BinaryPrimitives.ReadUInt32LittleEndian(data[188..]));
        if(value.State is <1 or >8||value.Error is >0 or <-4095||value.Bytes>value.Size||value.ActorReferenceOwned>1||value.WriteExclusionOwned>1)
            throw new InvalidDataException("Invalid atomic native state");
        return value;
    }
}
