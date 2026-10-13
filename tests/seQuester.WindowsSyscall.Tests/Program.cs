using System.Buffers.Binary;
using System.Text.Json;
using RansomFree.Client;
using RansomFree.Contracts;

if(args.Length is not (1 or 2))throw new ArgumentException("Supply the actual nine-pair native raw file and optional native intake file");
var raw=File.ReadAllBytes(args[0]);
if(raw.Length!=9*696)throw new InvalidDataException("Expected nine native record/truth pairs");
var checks=0;
void Check(bool ok,string description){if(!ok)throw new Exception(description);checks++;}
void Reject(byte[] r,string description){try{WindowsSyscallDecoder.Decode(r);}catch(Exception e) when(e is InvalidDataException or OverflowException or ArgumentOutOfRangeException){checks++;return;}throw new Exception(description);}
var records=new List<WindowsSyscallEvidence>();
for(var i=0;i<9;i++)
{
    var bytes=raw.AsSpan(i*696,408).ToArray();var value=WindowsSyscallDecoder.Decode(bytes);records.Add(value);
    Check(value.IsValid(),"native evidence valid");
    Check(value.Sequence==i+1,"native ordering");
    Check(value.ReturnStatus==(i<6?"0xC0000022":i<8?"0xC0000054":"0x00000000"),"actual native result");
    Check(value.Outcome==(i<8?"failed":"success"),"status interpretation");
    Check(value.ProcessOwner.Sid=="S-1-5-18"&&value.ThreadEffective.Sid==(i<8?"S-1-5-19":"S-1-5-18"),"owner/effective separation");
    Check(value.ThreadImpersonating==(i<8),"impersonation state");
    Check(JsonSerializer.Serialize(value.ProcessOwner)==JsonSerializer.Serialize(WindowsKernelDecoder.Token(raw,(i*696)+408)),"independent owner token truth");
    Check(JsonSerializer.Serialize(value.ThreadEffective)==JsonSerializer.Serialize(WindowsKernelDecoder.Token(raw,(i*696)+552)),"independent effective token truth");
    Check(value.BytesTransferred==null&&value.MonotonicFrequency==null,"unavailable values stay null");
    var roundtrip=JsonSerializer.Deserialize<WindowsSyscallEvidence>(JsonSerializer.Serialize(value))!;
    Check(roundtrip.IsValid()&&roundtrip.ProcessInstanceKey==value.ProcessInstanceKey,"SIEM JSON round trip");
}
Check(records.Select(x=>x.ProcessInstanceKey).Distinct().Count()==1,"same actual process instance");
Check((records[0] with {ProcessCreatedFileTime=records[0].ProcessCreatedFileTime+1}).ProcessInstanceKey!=records[0].ProcessInstanceKey,"PID reuse separates instances");
var original=raw.AsSpan(0,408).ToArray();
void Mutate32(int o,uint v,string description){var r=(byte[])original.Clone();BinaryPrimitives.WriteUInt32LittleEndian(r.AsSpan(o),v);Reject(r,description);}
Mutate32(0,2,"unknown wire version accepted");Mutate32(4,409,"wrong size accepted");Mutate32(116,1,"reserved bits accepted");
Mutate32(104,0,"unknown impersonation accepted as complete");Mutate32(108,1,"unsupported capture IRQL accepted");
Mutate32(80,99,"unknown operation accepted");Mutate32(120,32,"unknown token capture mask accepted");
Mutate32(104,1,"contradictory non-impersonating identities accepted");
var pending=(byte[])original.Clone();BinaryPrimitives.WriteUInt32LittleEndian(pending.AsSpan(92),0x103);
Check(WindowsSyscallDecoder.Decode(pending).Outcome=="pending"&&WindowsSyscallDecoder.Decode(pending).BytesTransferred==null,"pending is not completed success");
Check(new WindowsSyscallEvidence().Outcome=="unknown","empty evidence outcome is unavailable");
Reject(original[..407],"truncated record accepted");
var reportingChecks=await ReportingChecks.Run(raw);
var actualIntakeChecks=args.Length==2?RealIntakeChecks.Run(raw,File.ReadAllBytes(args[1])):0;
Console.WriteLine(JsonSerializer.Serialize(new {Passed=true,Checks=checks,ReportingChecks=reportingChecks,ActualIntakeChecks=actualIntakeChecks,ActualNativeRecords=9,ProductionSourceEnabled=false,CentralIntegrationVerified=false}));
