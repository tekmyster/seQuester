using System.Globalization;
using System.Text.Json.Serialization;

namespace RansomFree.Contracts;

// Completed synchronous VFS I/O is separate from permission/open intent.
// Decimal strings preserve exact native 64-bit values in SIEM/JavaScript.
public sealed record LinuxIoObservation
{
    public uint Schema {get;init;}=3;
    public uint Stage {get;init;}
    public string OperationNonce {get;init;}="";
    public string ObservedLease {get;init;}="";
    public string EntryNs {get;init;}="";
    public string ObservedNs {get;init;}="";
    public string? RequestedBytes {get;init;}
    public string? ReturnValue {get;init;}
    public string? OffsetBefore {get;init;}
    public string? OffsetAfter {get;init;}
    public string? SizeBefore {get;init;}
    public string? SizeAfter {get;init;}
    public uint? FileFlags {get;init;}
    public uint? RwFlags {get;init;}
    public uint AvailabilityFields {get;init;}
    public int CollectionError {get;init;}
    public uint IdentityFields {get;init;}
    public int IdentityError {get;init;}
    public int ActorMetadataError {get;init;}
    public string ResultMeaning {get;init;}="SYNCHRONOUS_VFS_RETURN_NOT_DURABILITY_OR_ASYNC_COMPLETION";
    public string SizeMeaning {get;init;}="NONEXCLUSIVE_INODE_SIZE_SAMPLES";
    public string PairingStatus {get;init;}="NOT_YET_CORRELATED";
    [JsonIgnore] public bool Diagnostic=>Schema==4&&Stage==3;
    [JsonIgnore] public long? Result=>ReturnValue!=null&&Signed(ReturnValue)?long.Parse(ReturnValue,CultureInfo.InvariantCulture):null;
    [JsonIgnore] public string Outcome=>Stage!=2?"not-observed":Result==-529?"pending":Result>=0?"success":"failure";
    [JsonIgnore] public string? TransferredBytes=>Stage==2&&Result is >=0?ReturnValue:null;
    [JsonIgnore] public bool? AppendRequested=>FileFlags.HasValue&&RwFlags.HasValue?(RwFlags.Value&0x10)!=0||(FileFlags.Value&0x400)!=0&&(RwFlags.Value&0x20)==0:null;
    [JsonIgnore] public int? Errno=>Stage==2&&Result is >=-4095 and <0&&Result!=-529?checked((int)-Result.Value):null;
    private static bool Signed(string? value)=>value is {Length:>0 and <=20}&&long.TryParse(value,NumberStyles.AllowLeadingSign,CultureInfo.InvariantCulture,out var n)&&n.ToString(CultureInfo.InvariantCulture)==value;
    public bool IsValid()
    {
        if(!(Schema==3&&Stage is 1 or 2||Diagnostic)||!LinuxKernelEvidence.Decimal(OperationNonce)||
            (Diagnostic?OperationNonce!="0":OperationNonce=="0")||!LinuxKernelEvidence.Decimal(ObservedLease)||Diagnostic&&ObservedLease!="0"||
            !LinuxKernelEvidence.Decimal(EntryNs)||EntryNs=="0"||!LinuxKernelEvidence.Decimal(ObservedNs)||
            ulong.Parse(ObservedNs,CultureInfo.InvariantCulture)<ulong.Parse(EntryNs,CultureInfo.InvariantCulture)||
            AvailabilityFields>127||IdentityFields>7||CollectionError>0||
            (Stage==2?!Signed(ReturnValue):ReturnValue!=null)||
            ResultMeaning!="SYNCHRONOUS_VFS_RETURN_NOT_DURABILITY_OR_ASYNC_COMPLETION"||SizeMeaning!="NONEXCLUSIVE_INODE_SIZE_SAMPLES"||PairingStatus!="NOT_YET_CORRELATED")return false;
        string?[] values=[RequestedBytes,OffsetBefore,OffsetAfter,SizeBefore,SizeAfter];
        uint[] bits=[1,2,4,8,16];
        for(int i=0;i<values.Length;i++)if(((AvailabilityFields&bits[i])!=0)!=(values[i]!=null)||values[i]!=null&&!(i is 1 or 2?Signed(values[i]):LinuxKernelEvidence.Decimal(values[i])))return false;
        if(((AvailabilityFields&32)!=0)!=FileFlags.HasValue||((AvailabilityFields&64)!=0)!=RwFlags.HasValue||Stage!=2&&(OffsetAfter!=null||SizeAfter!=null))return false;
        if(Stage==2&&Result is >=0&&RequestedBytes!=null&&(ulong)Result.Value>ulong.Parse(RequestedBytes,CultureInfo.InvariantCulture))return false;
        return true;
    }
}
