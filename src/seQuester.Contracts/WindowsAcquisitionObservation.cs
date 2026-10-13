using System.Buffers.Binary;
using System.Security.Cryptography;
namespace RansomFree.Contracts;

// Acquisition diagnostics are observations, never selectors for executable
// bytes, hash verdicts, preservation receipts, or replacement process identities.
public sealed record WindowsAcquisitionObservation
{
    public int Version {get;init;}
    public EvidenceStatus Status {get;init;}=EvidenceStatus.Unavailable("legacy-provider");
    public bool? QueryAttempted {get;init;}=false;
    public string? Provider {get;init;}
    public ulong? Epoch {get;init;}
    public ulong? Instance {get;init;}
    public ulong? Sequence {get;init;}
    public ulong? ProcessGeneration {get;init;}
    public ulong? NegativeAssociation {get;init;}
    public ulong? OriginCandidate {get;init;}
    public ulong? OriginGeneration {get;init;}
    public ulong? ObservedQpc {get;init;}
    public string? NativeStatus {get;init;}
    public uint? State {get;init;}
    public uint? Stage {get;init;}
    public uint? Certainty {get;init;}
    public uint? Flags {get;init;}
    public string? RawSha256 {get;init;}
    public string? OperationRecordSha256 {get;init;}
    [System.Text.Json.Serialization.JsonIgnore(Condition=System.Text.Json.Serialization.JsonIgnoreCondition.WhenWritingNull)]
    public string? RecoveryProvider {get;init;}
    [System.Text.Json.Serialization.JsonIgnore(Condition=System.Text.Json.Serialization.JsonIgnoreCondition.WhenWritingNull)]
    public ulong? RecoveryEpoch {get;init;}
    [System.Text.Json.Serialization.JsonIgnore(Condition=System.Text.Json.Serialization.JsonIgnoreCondition.WhenWritingNull)]
    public DateTimeOffset? RecoveryObservedUtc {get;init;}
    public string? ReasonCode=>Status.Reason=="provider-retired-before-companion-commit"?"ACTOR_ACQ_COMPANION_UNAVAILABLE_PROVIDER_RETIRED":State switch{0=>"ACTOR_ACQ_NO_EXACT_ASSOCIATION",1=>"ACTOR_ACQ_EXACT_PREBIND_FAILURE",2=>"ACTOR_ACQ_COPY_PENDING",3=>"ACTOR_ACQ_EXACT_BOUND_FAILURE",4=>"ACTOR_ACQ_BOUND_BYTES_UNAVAILABLE",5=>"ACTOR_ACQ_BLOB_PINNED",_=>null};
    public string? FailureStage=>Stage switch{0=>"none",1=>"metadata-slot",2=>"header-capacity",3=>"full-copy-capacity",4=>"byte-credit",5=>"copy-read",6=>"copy-allocation",7=>"source-standard-query",8=>"source-basic-query",9=>"source-internal-query",_=>null};
    static bool Hash(string? value)=>value is {Length:64}&&value.All(Uri.IsHexDigit);
    static bool ProviderId(string? value)=>value is {Length:32}&&value.All(Uri.IsHexDigit)&&value.Any(x=>x!='0');
    public bool IsValid(WindowsKernelEvidence kernel)
    {
        if(Version==2&&Status is {State:"unavailable",Reason:"provider-retired-before-companion-commit",NativeCode:null})
            return QueryAttempted==null&&ProviderId(Provider)&&Epoch is >0&&Epoch==Instance&&Instance?.ToString("X16")==kernel.Instance&&Sequence==(ulong)kernel.Sequence&&
                ProcessGeneration==null&&NegativeAssociation==null&&OriginCandidate==null&&OriginGeneration==null&&ObservedQpc==null&&NativeStatus==null&&State==null&&Stage==null&&Certainty==null&&Flags==null&&RawSha256==null&&Hash(OperationRecordSha256)&&
                ProviderId(RecoveryProvider)&&RecoveryEpoch is >0&&(RecoveryProvider!=Provider||RecoveryEpoch!=Epoch)&&RecoveryObservedUtc is {} recovered&&recovered!=default;
        if(RecoveryProvider!=null||RecoveryEpoch!=null||RecoveryObservedUtc!=null)return false;
        if(Version==0)return QueryAttempted==false&&Status is {State:"unavailable",Reason:"legacy-provider" or "pre-companion-record",NativeCode:null}&&
            Provider==null&&Epoch==null&&Instance==null&&Sequence==null&&ProcessGeneration==null&&NegativeAssociation==null&&OriginCandidate==null&&OriginGeneration==null&&ObservedQpc==null&&NativeStatus==null&&State==null&&Stage==null&&Certainty==null&&Flags==null&&RawSha256==null&&OperationRecordSha256==null;
        if(Version!=1||QueryAttempted!=true||Status is not {State:"captured",Reason:"immutable-operation-acquisition",NativeCode:null}||
            Provider is not {Length:32}||!Provider.All(Uri.IsHexDigit)||Provider.All(x=>x=='0')||Epoch is null or 0||Epoch!=Instance||
            Instance?.ToString("X16")!=kernel.Instance||Sequence!=(ulong)kernel.Sequence||ObservedQpc is null or 0||
            ProcessGeneration==null||NegativeAssociation==null||OriginCandidate==null||OriginGeneration==null||State is null or >5||Stage is null or >9||Certainty is null or >2||Flags is null or >15||
            !Hash(RawSha256)||!Hash(OperationRecordSha256)||NativeStatus is not {Length:10}||!NativeStatus.StartsWith("0x")||!NativeStatus[2..].All(Uri.IsHexDigit))return false;
        var terminal=NativeStatus is not ("0x00000000" or "0x00000103");
        if(OriginCandidate==0&&OriginGeneration!=0||State!=1&&NegativeAssociation!=0)return false;
        // All 128 native bytes are reconstructible: fixed header and reserved
        // zeros plus copied scalar fields. Reject a hash inconsistent with them.
        var raw=new byte[128];BinaryPrimitives.WriteUInt32LittleEndian(raw,1);BinaryPrimitives.WriteUInt32LittleEndian(raw.AsSpan(4),128);
        Convert.FromHexString(Provider).CopyTo(raw,8);
        foreach(var pair in new[]{(24,Epoch.Value),(32,Instance!.Value),(40,Sequence!.Value),(48,ProcessGeneration.Value),(56,NegativeAssociation.Value),(64,OriginCandidate.Value),(72,OriginGeneration.Value),(80,ObservedQpc.Value)})BinaryPrimitives.WriteUInt64LittleEndian(raw.AsSpan(pair.Item1),pair.Item2);
        BinaryPrimitives.WriteUInt32LittleEndian(raw.AsSpan(88),Convert.ToUInt32(NativeStatus[2..],16));
        foreach(var pair in new[]{(92,State.Value),(96,Stage.Value),(100,Certainty.Value),(104,Flags.Value)})BinaryPrimitives.WriteUInt32LittleEndian(raw.AsSpan(pair.Item1),pair.Item2);
        if(!Convert.ToHexString(SHA256.HashData(raw)).Equals(RawSha256,StringComparison.OrdinalIgnoreCase))return false;
        return State switch{
            0=>ProcessGeneration==0&&NegativeAssociation==0&&OriginCandidate==0&&OriginGeneration==0&&NativeStatus=="0xC0000225"&&Stage==0&&Certainty==0&&Flags==0,
            1=>ProcessGeneration>0&&NegativeAssociation>0&&terminal&&Stage is >=1 and <=9&&Certainty==1&&OriginGeneration==0&&(Stage<7||OriginCandidate==0),
            2=>ProcessGeneration>0&&OriginCandidate>0&&OriginGeneration==ProcessGeneration&&NativeStatus=="0x00000103"&&Stage==0&&Certainty==1,
            3=>ProcessGeneration>0&&OriginCandidate>0&&OriginGeneration==ProcessGeneration&&terminal&&Stage is >=3 and <=6&&Certainty==1,
            4=>ProcessGeneration>0&&NativeStatus=="0xC0000225"&&Stage==0&&Certainty==1&&(OriginCandidate==0||OriginGeneration==ProcessGeneration),
            5=>ProcessGeneration>0&&OriginCandidate>0&&OriginGeneration==ProcessGeneration&&NativeStatus=="0x00000000"&&Stage==0&&Certainty==2,
            _=>false};
    }
}
