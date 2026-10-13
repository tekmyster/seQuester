using System.Buffers.Binary;
using System.Security.Cryptography;
using RansomFree.Contracts;

namespace RansomFree.Client;

// Decoder only. No production driver installation, event publication or trust
// promotion is enabled by adding this class. Wire layout is independently tested
// against the raw native records, not reconstructed from the JSON test report.
public static class WindowsSyscallDecoder
{
    public const int RecordBytes=408;
    public static WindowsSyscallEvidence Decode(byte[] record)
    {
        if(record.Length!=RecordBytes||U32(record,0)!=1||U32(record,4)!=RecordBytes||U32(record,116)!=0)
            throw new InvalidDataException("Unsupported Windows syscall record header");
        var result=new WindowsSyscallEvidence
        {
            Sequence=checked((long)U64(record,8)),
            EntryUtc=DateTimeOffset.FromFileTime(checked((long)U64(record,16))),
            EntryMonotonic=checked((long)U64(record,24)),
            ReturnUtc=DateTimeOffset.FromFileTime(checked((long)U64(record,32))),
            ReturnMonotonic=checked((long)U64(record,40)),
            ProcessId=checked((uint)U64(record,48)),ThreadId=checked((uint)U64(record,56)),
            ProcessCreatedFileTime=checked((long)U64(record,64)),TargetHandle=U64(record,72).ToString("X16"),
            Operation=U32(record,80),InformationClass=U32(record,84),RequestedLength=U32(record,88),
            ReturnStatus=Status(record,92),AttributionStatus=Status(record,96),FileObjectStatus=Status(record,100),
            ThreadImpersonating=U32(record,104) switch {1=>false,2=>true,_=>null},
            CaptureIrql=U32(record,108),RequestorMode=U32(record,112),
            ProcessOwner=WindowsKernelDecoder.Token(record,120),ThreadEffective=WindowsKernelDecoder.Token(record,264),
            RawRecordSha256=Convert.ToHexString(SHA256.HashData(record))
        };
        // Record equality does not compare the QueryStatus arrays by contents.
        if(result.ThreadImpersonating==false&&!record.AsSpan(120,144).SequenceEqual(record.AsSpan(264,144)))
            throw new InvalidDataException("Non-impersonating native token records disagree");
        if(result.ThreadImpersonating==false)result=result with {ThreadEffective=result.ProcessOwner};
        if(!result.IsValid())throw new InvalidDataException("Invalid Windows syscall observation");
        return result;
    }
    private static uint U32(byte[] b,int o)=>BinaryPrimitives.ReadUInt32LittleEndian(b.AsSpan(o,4));
    private static ulong U64(byte[] b,int o)=>BinaryPrimitives.ReadUInt64LittleEndian(b.AsSpan(o,8));
    private static string Status(byte[] b,int o)=>"0x"+U32(b,o).ToString("X8");
}
