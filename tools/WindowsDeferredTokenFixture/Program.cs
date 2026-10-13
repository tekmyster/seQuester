using System.Buffers.Binary;
using System.Security.Principal;
using System.Text;
using System.Text.Json;
using RansomFree.Client;
using RansomFree.Contracts;

if(args.Length==1){NativeRecordChecks.Run(args[0]);return;}
if(args.Length!=0)throw new ArgumentException("Pass a successful native raw-fixture directory or no arguments for managed contract tests");

var statuses=Enumerable.Repeat("0xC0000225",5).ToArray();
var missing=new WindowsTokenSnapshot{QueryStatus=statuses};
var op=new WindowsKernelEvidence{Version=5,Instance="000000000000000A",Sequence=7,ProcessId=100,ThreadId=101,ThreadProcessId=100,
 ProcessCreatedFileTime=DateTimeOffset.UtcNow.ToFileTime(),CompletedUtc=DateTimeOffset.UtcNow,MonotonicFrequency=10000000,
 CaptureIrql=1,Flags=28,NativePath="\\Device\\HarddiskVolume1\\owned.bin",NameSource="opened",NormalizedNameStatus="0xC01C0005",
 ThreadOwnerPrimary=missing,ThreadOwnerStatus="irql-not-passive",CallbackDataFlags=0,RequestorMode=0,
 BaseRecordSha256=new('0',64),ThreadContextSha256=new('0',64),CreateAuthorization=missing,ThreadEffective=missing,RequestorPrimary=missing};
if(!op.IsValid())throw new Exception("Invalid fixture base evidence");
void U32(byte[] b,int p,uint v)=>BinaryPrimitives.WriteUInt32LittleEndian(b.AsSpan(p),v);
void U64(byte[] b,int p,ulong v)=>BinaryPrimitives.WriteUInt64LittleEndian(b.AsSpan(p),v);
void Token(byte[] b,int p,string? sid){
 if(sid==null){for(var i=0;i<5;i++)U32(b,p+4+i*4,0xC0000225);return;}
 var principal=new SecurityIdentifier(sid);var raw=new byte[principal.BinaryLength];principal.GetBinaryForm(raw,0);
 U32(b,p,31);U32(b,p+24,(uint)raw.Length);U32(b,p+28,0);U32(b,p+32,0x4000);U32(b,p+36,1);
 U32(b,p+40,sid=="S-1-5-19"?2u:1u);U32(b,p+44,sid=="S-1-5-19"?2u:uint.MaxValue);
 U64(b,p+48,11);U64(b,p+56,12);U64(b,p+64,13);raw.CopyTo(b,p+72);
}
byte[] Make(bool impersonating){
 var b=new byte[2048];U32(b,0,1);U32(b,4,2048);U64(b,8,10);U64(b,16,7);
 U64(b,24,(ulong)DateTimeOffset.UtcNow.ToFileTime());U64(b,32,(ulong)DateTimeOffset.UtcNow.AddSeconds(-5).ToFileTime()); // clock steps must not discard evidence
 U32(b,40,1);U32(b,44,impersonating?2u:1u);U32(b,48,impersonating?1u:0u);U32(b,52,impersonating?1u:0u);
 U32(b,60,1);U32(b,64,impersonating?2u:uint.MaxValue);
 Token(b,72,impersonating?"S-1-5-19":null);Token(b,216,"S-1-5-18");Token(b,360,"S-1-5-18");
 U64(b,504,(ulong)op.ProcessCreatedFileTime!.Value);Encoding.Unicode.GetBytes("\\Device\\HarddiskVolume1\\actor.exe\0").CopyTo(b,512);return b;
}
var good=Make(true);var decoded=WindowsKernelDecoder.DecodeDeferredTokenContext(op,good);
if(decoded.ThreadEffective.Sid!="S-1-5-19"||decoded.ThreadOwnerPrimary.Sid!="S-1-5-18"||decoded.PrimaryMetadataTiming==decoded.ImpersonationMetadataTiming)throw new Exception("Security principals or timing collapsed");
var noImpersonation=WindowsKernelDecoder.DecodeDeferredTokenContext(op,Make(false));
if(noImpersonation.ThreadEffective.Captured!=0||noImpersonation.ThreadEffective.Sid!=null||noImpersonation.ThreadImpersonating!=false)throw new Exception("No-impersonation effective token fabricated");
var json=JsonSerializer.Serialize(decoded);if(JsonSerializer.Deserialize<WindowsDeferredTokenEvidence>(json)?.IsValid(op)!=true)throw new Exception("SIEM round-trip failed");
var absent=Make(false);U32(absent,44,0);U32(absent,56,0xC0000225);Array.Clear(absent,216,144);Token(absent,216,null);U64(absent,504,0);
var absentDecoded=WindowsKernelDecoder.DecodeDeferredTokenContext(op with{ThreadId=null,ThreadProcessId=null,Flags=29,ThreadOwnerStatus="thread-unavailable"},absent);
if(absentDecoded.ThreadImpersonating!=null||absentDecoded.ThreadOwnerPrimary.Captured!=0)throw new Exception("Unavailable callback thread fabricated");
var rejected=0;
void Reject(byte[] b,WindowsKernelEvidence? operation=null){try{WindowsKernelDecoder.DecodeDeferredTokenContext(operation??op,b);}catch(InvalidDataException){rejected++;return;}throw new Exception("Invalid deferred evidence accepted");}
foreach(var edit in new (int,uint)[]{(0,2),(4,2040),(8,11),(16,8),(40,0),(44,3),(48,3),(56,0x8000000D),(60,0),(64,4),(68,1)}){var bad=(byte[])good.Clone();U32(bad,edit.Item1,edit.Item2);Reject(bad);}
Reject(good[..2040]);Reject(good,op with{ThreadId=null,ThreadProcessId=null});
var fabricated=Make(false);Token(fabricated,72,"S-1-5-18");Reject(fabricated);
var falseComplete=(byte[])good.Clone();Token(falseComplete,72,null);U32(falseComplete,72,0);Array.Clear(falseComplete,72+24,120);Reject(falseComplete);
Console.WriteLine(JsonSerializer.Serialize(new{Passed=true,ManagedOnly=true,PositiveCases=4,NegativeCases=rejected,NativeQualificationClaim=false,ProductionIntegrated=false}));
