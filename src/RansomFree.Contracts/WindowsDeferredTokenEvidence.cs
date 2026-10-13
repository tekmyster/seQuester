namespace RansomFree.Contracts;

// Additive evidence from the private PASSIVE-worker qualification build.
// A reference identifies a token object; it does not freeze mutable token fields.
public sealed record WindowsDeferredTokenEvidence
{
    public int SchemaVersion {get;init;}=1;
    public string Instance {get;init;}="";
    public long Sequence {get;init;}
    public DateTimeOffset ReferencedUtc {get;init;}
    public DateTimeOffset QueryStartedUtc {get;init;}
    public uint ReferenceIrql {get;init;}
    public bool? ThreadImpersonating {get;init;}
    public bool? CopyOnOpen {get;init;}
    public bool? EffectiveOnly {get;init;}
    public uint? EntryImpersonationLevel {get;init;}
    public string CollectionStatus {get;init;}="";
    public string ImpersonationMetadataTiming {get;init;}="later-query-of-callback-referenced-token";
    public string PrimaryMetadataTiming {get;init;}="later-query-of-referenced-process; not-entry-token-snapshot";
    public string ImageMetadataTiming {get;init;}="later-query-of-referenced-process";
    public WindowsTokenSnapshot ThreadEffective {get;init;}=new();
    public WindowsTokenSnapshot ThreadOwnerPrimary {get;init;}=new();
    public WindowsTokenSnapshot RequestorPrimary {get;init;}=new();
    public long? ThreadProcessCreatedFileTime {get;init;}
    public string NativeImage {get;init;}="";
    public string RawSha256 {get;init;}="";
    public bool IsValid(WindowsKernelEvidence operation)=>SchemaVersion==1&&
        Instance==operation.Instance&&Sequence==operation.Sequence&&Sequence>0&&
        ReferencedUtc!=default&&QueryStartedUtc!=default&&ReferenceIrql==1&&operation.CaptureIrql==1&&
        CollectionStatus is "0x00000000" or "0x8000000D" or "0xC0000225"&&
        ImpersonationMetadataTiming=="later-query-of-callback-referenced-token"&&
        PrimaryMetadataTiming=="later-query-of-referenced-process; not-entry-token-snapshot"&&
        ImageMetadataTiming=="later-query-of-referenced-process"&&
        ThreadEffective?.IsValid()==true&&ThreadOwnerPrimary?.IsValid()==true&&RequestorPrimary?.IsValid()==true&&
        (ThreadImpersonating==true?operation.ThreadId!=null&&EntryImpersonationLevel is <=3&&CopyOnOpen!=null&&EffectiveOnly!=null:
            EntryImpersonationLevel==null&&CopyOnOpen==null&&EffectiveOnly==null&&ThreadEffective.Captured==0)&&
        ((ThreadImpersonating==null)==(operation.ThreadId==null))&&
        (operation.ThreadId!=null||ThreadOwnerPrimary.Captured==0&&ThreadProcessCreatedFileTime==null)&&
        ThreadProcessCreatedFileTime is null or >0&&NativeImage.Length<=1536&&
        RawSha256 is {Length:64}&&RawSha256.All(Uri.IsHexDigit)&&
        CollectionStatus==(ThreadImpersonating==null?"0xC0000225":
            ThreadImpersonating==true&&ThreadEffective.Captured!=31||ThreadOwnerPrimary.Captured!=31||RequestorPrimary.Captured!=31||NativeImage.Length==0?"0x8000000D":"0x00000000");
}
