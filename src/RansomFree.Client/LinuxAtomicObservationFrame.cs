using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using RansomFree.Contracts;

namespace RansomFree.Client;

// Exact non-sleepable native observation. Diagnostic records are retained,
// but never become an actor-copy key or a permission-entry/result pair.
internal sealed record LinuxAtomicObservationFrame(uint Schema,uint Hook,uint Stage,LinuxAtomicLeaseKey ObservedKey,
    ulong ObservedNs,ulong EntryNs,ulong ActorSize,long Reservation,long FinalizeError,int? PermissionResult,int AccessMask,
    int IdentityError,int CredentialError,int ActorMetadataError,int AssociationError,uint TargetOrdinal,uint CredentialFields,
    uint? Uid,uint? EffectiveUid,uint? FileSystemUid,uint? Gid,uint? EffectiveGid,uint? FileSystemGid,uint IdentityFields,LinuxIoObservation? Io=null)
{
    internal bool IsDiagnostic=>Schema is 2 or 4&&Stage==3;
    internal bool CanAuthorizeCopy=>!IsDiagnostic&&Stage==1&&ObservedKey.Valid&&Reservation==(long)ObservedKey.LeaseId&&FinalizeError==0&&
        IdentityFields==7&&IdentityError==0&&ActorMetadataError==0&&AssociationError==0;
    internal static LinuxAtomicObservationFrame Decode(ReadOnlySpan<byte> raw)
    {
        if(raw.Length is not (232 or 304))throw new InvalidDataException("Atomic observation has wrong native size");
        var bytes=raw.ToArray();uint U(int n)=>BinaryPrimitives.ReadUInt32LittleEndian(bytes.AsSpan(n));
        int I(int n)=>BinaryPrimitives.ReadInt32LittleEndian(bytes.AsSpan(n));ulong Q(int n)=>BinaryPrimitives.ReadUInt64LittleEndian(bytes.AsSpan(n));
        var schema=U(0);var hook=U(8);var stage=U(12);var key=LinuxAtomicLeaseKey.Decode(raw.Slice(16,112));
        var io=raw.Length==304;
        if(U(4)!=raw.Length||!(io?hook is 3 or 4&& (schema==3&&stage is 1 or 2||schema==4&&stage==3):hook is 1 or 2&&(schema==1&&stage is 1 or 2||schema==2&&stage==3))||U(228)!=0||U(192)>=32||U(196)>63||U(224)>7)
            throw new InvalidDataException("Atomic native schema, stage, hook or availability mask invalid");
        if(schema is 2 or 4&&(key.LeaseId!=0||key.Cookie!=0||key.OperationNonce!=0||key.AssociationGeneration!=0)||
            schema is 1 or 3&&(key.Cookie==0||key.OperationNonce==0)||key.ProviderEpoch==0||key.ProcessId is 0 or >int.MaxValue||key.ThreadId is 0 or >uint.MaxValue||
            key.TargetInode==0||key.TargetDevice is 0 or >uint.MaxValue||key.ActorDevice>uint.MaxValue||Q(128)==0||Q(136)==0||Q(128)<Q(136))
            throw new InvalidDataException("Atomic observation correlation or lifetime context invalid");
        uint? Credential(int index)=> (U(196)&(1u<<index))!=0?U(200+index*4):null;
        for(int i=0;i<6;i++)if(Credential(i)==uint.MaxValue)throw new InvalidDataException("Invalid kernel ID was marked available");
        if((stage!=2||io)&&I(168)!=0)throw new InvalidDataException("Frame asserted an unavailable permission outcome");
        LinuxIoObservation? operation=null;
        if(io)
        {
            string D(ulong v)=>v.ToString(System.Globalization.CultureInfo.InvariantCulture);
            string S(int offset)=>BinaryPrimitives.ReadInt64LittleEndian(bytes.AsSpan(offset)).ToString(System.Globalization.CultureInfo.InvariantCulture);
            var fields=U(288);
            if(Q(296)!=0||fields>127||stage!=2&&BinaryPrimitives.ReadInt64LittleEndian(bytes.AsSpan(240))!=0)throw new InvalidDataException("I/O reserved fields, availability or result invalid");
            operation=new(){Schema=schema,Stage=stage,OperationNonce=D(key.OperationNonce),ObservedLease=D(key.LeaseId),EntryNs=D(Q(136)),ObservedNs=D(Q(128)),
                RequestedBytes=(fields&1)!=0?D(Q(232)):null,ReturnValue=stage==2?S(240):null,OffsetBefore=(fields&2)!=0?S(248):null,OffsetAfter=(fields&4)!=0?S(256):null,
                SizeBefore=(fields&8)!=0?D(Q(264)):null,SizeAfter=(fields&16)!=0?D(Q(272)):null,FileFlags=(fields&32)!=0?U(280):null,RwFlags=(fields&64)!=0?U(284):null,
                AvailabilityFields=fields,CollectionError=I(292),IdentityFields=U(224),IdentityError=I(176),ActorMetadataError=I(184)};
            if(!operation.IsValid())throw new InvalidDataException("Invalid I/O observation");
        }
        return new(schema,hook,stage,key,Q(128),Q(136),Q(144),BinaryPrimitives.ReadInt64LittleEndian(raw[152..]),BinaryPrimitives.ReadInt64LittleEndian(raw[160..]),
            stage==2&&!io?I(168):null,I(172),I(176),I(180),I(184),I(188),U(192),U(196),Credential(0),Credential(1),Credential(2),Credential(3),Credential(4),Credential(5),U(224),operation);
    }
    internal static LinuxAtomicObservationFrame DecodeEnvelope(ReadOnlyMemory<byte> raw)
    {
        using var json=JsonDocument.Parse(raw);var obj=json.RootElement;
        if(obj.ValueKind!=JsonValueKind.Object||obj.EnumerateObject().Count()!=2||obj.GetProperty("schemaVersion").GetInt32() is not (7 or 8))
            throw new InvalidDataException("Atomic loader envelope unavailable or malformed");
        var text=obj.GetProperty("atomicObservation").GetString();
        var version=obj.GetProperty("schemaVersion").GetInt32();
        if(text==null||text.Length!=(version==7?312:408))throw new InvalidDataException("Atomic frame base64 size invalid");
        var bytes=Convert.FromBase64String(text);if(Convert.ToBase64String(bytes)!=text)throw new InvalidDataException("Atomic frame base64 is not canonical");var frame=Decode(bytes);
        if((version==8)!=(frame.Io!=null))throw new InvalidDataException("Envelope and native operation schemas disagree");return frame;
    }
    // Raw-bank positions and their digest survive restart. Never identify a
    // diagnostic by its intentionally zero operation cookie/nonce.
    internal static string DeliveryIdentity(string sensor,string sourceSession,long rawPosition,ReadOnlySpan<byte> raw)
    {
        if(!Guid.TryParseExact(sensor,"N",out _)||!Guid.TryParseExact(sourceSession,"N",out _)||rawPosition<=0)throw new InvalidDataException("Durable raw delivery context required");
        var context=Encoding.UTF8.GetBytes(sensor+":"+sourceSession+":"+rawPosition.ToString(System.Globalization.CultureInfo.InvariantCulture)+":"+Convert.ToHexString(SHA256.HashData(raw)));
        return Convert.ToHexString(SHA256.HashData(context).AsSpan(0,16)).ToLowerInvariant();
    }
}
