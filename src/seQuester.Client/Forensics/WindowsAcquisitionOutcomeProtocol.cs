using System.Buffers.Binary;
using System.Security.Cryptography;
using RansomFree.Contracts;
namespace RansomFree.Client.Forensics;

// Contract/codec preparation only: no active driver advertises these commands
// yet. Receiver integration must commit the exact reply before native ACK.
internal enum WindowsAcquisitionState:uint
{NoExactAssociation,ExactPrebindRefusal,CopyPending,ExactBoundCopyFailure,BoundBytesUnavailable,BlobPinned}
internal enum WindowsAcquisitionStage:uint
{None,MetadataSlot,HeaderCapacity,FullCopyCapacity,ByteCredit,CopyRead,CopyAllocation,SourceStandardQuery,SourceBasicQuery,SourceInternalQuery}
internal sealed record WindowsAcquisitionOutcome(
    string Provider,ulong Epoch,ulong Instance,ulong Sequence,ulong ProcessGeneration,
    ulong NegativeAssociation,ulong OriginCandidate,ulong OriginGeneration,ulong ObservedQpc,
    uint NativeStatus,WindowsAcquisitionState State,WindowsAcquisitionStage Stage,uint Certainty,uint Flags,string RawSha256);
internal sealed record WindowsNegativeAcquisitionHealth(uint Live,ulong ReferencesTaken,ulong ReferencesReleased,ulong GapCount,ulong GapQpc,ulong BindAttempted);
internal static class WindowsAcquisitionOutcomeProtocol
{
    internal const uint OutcomeCommand=34,CapabilityCommand=35;
    private static uint U32(ReadOnlySpan<byte> b,int o)=>BinaryPrimitives.ReadUInt32LittleEndian(b[o..]);
    private static ulong U64(ReadOnlySpan<byte> b,int o)=>BinaryPrimitives.ReadUInt64LittleEndian(b[o..]);
    private static void Put32(Span<byte> b,int o,uint n)=>BinaryPrimitives.WriteUInt32LittleEndian(b[o..],n);
    private static void Put(Span<byte> b,int o,ulong n)=>BinaryPrimitives.WriteUInt64LittleEndian(b[o..],n);
    private static byte[] ProviderBytes(string provider)
    {
        if(provider.Length!=32||!provider.All(Uri.IsHexDigit))throw new ArgumentException("Exact provider wire UUID required");
        var bytes=Convert.FromHexString(provider);if(bytes.All(x=>x==0))throw new ArgumentException("Zero provider UUID");return bytes;
    }
    internal static byte[] CapabilitiesRequest(){var b=new byte[8];Put32(b,0,4);Put32(b,4,CapabilityCommand);return b;}
    internal static bool Capabilities(ReadOnlySpan<byte> b,string provider,ulong epoch)
    {
        var uuid=ProviderBytes(provider);
        if(epoch==0||b.Length!=48||U32(b,0)!=1||U32(b,4)!=48||!b.Slice(8,16).SequenceEqual(uuid)||U64(b,24)!=epoch||U64(b,32)>1||U32(b,40)!=1||U32(b,44)!=128)
            throw new InvalidDataException("Acquisition capability does not match provider/epoch or fixed reply layout");
        return U64(b,32)==1;
    }
    internal static WindowsNegativeAcquisitionHealth NegativeHealth(ReadOnlySpan<byte> b,string provider,ulong epoch)
    {
        var uuid=ProviderBytes(provider);
        if(epoch==0||b.Length!=88||U32(b,0)!=1||U32(b,4)!=88||!b.Slice(8,16).SequenceEqual(uuid)||U64(b,24)!=epoch||U32(b,32)!=128||U32(b,36)>128||
            U64(b,56)>U64(b,48)||U64(b,48)-U64(b,56)!=U32(b,36)||U64(b,80)>U32(b,36)||U64(b,40)!=U64(b,48)||(U64(b,64)==0)!=(U64(b,72)==0))
            throw new InvalidDataException("Negative acquisition health provider/epoch/layout/reference invariant failed");
        return new(U32(b,36),U64(b,48),U64(b,56),U64(b,64),U64(b,72),U64(b,80));
    }
    internal static byte[] Request(string provider,ulong epoch,ulong instance,ulong sequence)
    {
        if(epoch==0||instance==0||sequence==0)throw new ArgumentException("Exact nonzero operation key required");
        var b=new byte[48];Put32(b,0,4);Put32(b,4,OutcomeCommand);ProviderBytes(provider).CopyTo(b,8);Put(b,24,epoch);Put(b,32,instance);Put(b,40,sequence);return b;
    }
    internal static WindowsAcquisitionOutcome Decode(ReadOnlySpan<byte> b,string provider,ulong epoch,ulong instance,ulong sequence)
    {
        var uuid=ProviderBytes(provider);
        if(epoch==0||instance==0||sequence==0||b.Length!=128||U32(b,0)!=1||U32(b,4)!=128||!b.Slice(8,16).SequenceEqual(uuid)||U64(b,24)!=epoch||U64(b,32)!=instance||U64(b,40)!=sequence||U32(b,108)!=0||U64(b,112)!=0||U64(b,120)!=0)
            throw new InvalidDataException("Acquisition outcome does not match exact operation or reserved layout");
        var gen=U64(b,48);var negative=U64(b,56);var candidate=U64(b,64);var originGen=U64(b,72);
        var qpc=U64(b,80);var status=U32(b,88);var state=U32(b,92);var stage=U32(b,96);var certainty=U32(b,100);var flags=U32(b,104);
        if(qpc==0||state>5||stage>9||certainty>2||(flags&~15u)!=0||candidate==0&&originGen!=0||state!=1&&negative!=0)
            throw new InvalidDataException("Unknown or contradictory acquisition state");
        var terminal=status!=0&&status!=0x103;
        var valid=state switch
        {
            0=>gen==0&&negative==0&&candidate==0&&originGen==0&&status==0xC0000225&&stage==0&&certainty==0&&flags==0,
            1=>gen!=0&&negative!=0&&terminal&&stage is >=1 and <=9&&certainty==1&&originGen==0&&(stage<7||candidate==0),
            2=>gen!=0&&candidate!=0&&originGen==gen&&status==0x103&&stage==0&&certainty==1,
            3=>gen!=0&&candidate!=0&&originGen==gen&&terminal&&stage is >=3 and <=6&&certainty==1,
            4=>gen!=0&&status==0xC0000225&&stage==0&&certainty==1&&(candidate==0||originGen==gen),
            5=>gen!=0&&candidate!=0&&originGen==gen&&status==0&&stage==0&&certainty==2,
            _=>false
        };
        if(!valid)throw new InvalidDataException("Acquisition status/stage/identity invariant failed");
        return new(Convert.ToHexString(uuid),epoch,instance,sequence,gen,negative,candidate,originGen,qpc,status,(WindowsAcquisitionState)state,(WindowsAcquisitionStage)stage,certainty,flags,Convert.ToHexString(SHA256.HashData(b)));
    }
    internal static WindowsAcquisitionObservation Evidence(WindowsAcquisitionOutcome outcome,string operationHash)=>new(){
        Version=1,Status=EvidenceStatus.Captured("immutable-operation-acquisition"),QueryAttempted=true,
        Provider=outcome.Provider,Epoch=outcome.Epoch,Instance=outcome.Instance,Sequence=outcome.Sequence,
        ProcessGeneration=outcome.ProcessGeneration,NegativeAssociation=outcome.NegativeAssociation,OriginCandidate=outcome.OriginCandidate,
        OriginGeneration=outcome.OriginGeneration,ObservedQpc=outcome.ObservedQpc,NativeStatus="0x"+outcome.NativeStatus.ToString("X8"),
        State=(uint)outcome.State,Stage=(uint)outcome.Stage,Certainty=outcome.Certainty,Flags=outcome.Flags,
        RawSha256=outcome.RawSha256,OperationRecordSha256=operationHash};
}
