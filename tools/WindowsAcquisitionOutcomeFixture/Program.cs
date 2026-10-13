using System.Buffers.Binary;
using System.Security.Cryptography;
using RansomFree.Client.Forensics;
using RansomFree.Contracts;
using System.Text.Json;

const string provider="1234567890ABCDEF1234567890ABCDEF";
var checks=0;
void Check(bool ok,string name){if(!ok)throw new Exception(name);checks++;}
void Reject(Action call,string name){try{call();}catch(InvalidDataException){checks++;return;}throw new Exception("Accepted "+name);}
void Put32(byte[] b,int offset,uint value)=>BinaryPrimitives.WriteUInt32LittleEndian(b.AsSpan(offset),value);
void Put(byte[] b,int offset,ulong value)=>BinaryPrimitives.WriteUInt64LittleEndian(b.AsSpan(offset),value);
byte[] Frame(uint state)
{
 var b=new byte[128];Put32(b,0,1);Put32(b,4,128);Convert.FromHexString(provider).CopyTo(b,8);Put(b,24,10);Put(b,32,10);Put(b,40,20);Put(b,80,100);
 Put32(b,92,state);Put32(b,88,state switch{0 or 4=>0xC0000225,2=>0x103,1 or 3=>0xC000009A,_=>0});
 if(state!=0){Put(b,48,9);Put32(b,100,state==5?2u:1u);}
 if(state==1){Put(b,56,8);Put32(b,96,1);}
 if(state is 2 or 3 or 4 or 5){Put(b,64,7);Put(b,72,9);}
 if(state==3)Put32(b,96,5);
 return b;
}
WindowsAcquisitionOutcome Decode(byte[] b)=>WindowsAcquisitionOutcomeProtocol.Decode(b,provider,10,10,20);
for(uint state=0;state<6;state++)
{
 var b=Frame(state);var decoded=Decode(b);
 Check((uint)decoded.State==state&&decoded.RawSha256==Convert.ToHexString(SHA256.HashData(b)),"six states and exact raw integrity");
 var kernel=new WindowsKernelEvidence{Instance=10UL.ToString("X16"),Sequence=20};
 var evidence=WindowsAcquisitionOutcomeProtocol.Evidence(decoded,new string('A',64));
 Check(evidence.IsValid(kernel)&&evidence.ReasonCode!=null&&evidence.FailureStage!=null,"six public SIEM observations preserve exact linkage and stable reason codes");
 Check(!evidence.IsValid(kernel with{Sequence=21}),"public observation cannot attach to another operation");
 Check(!(evidence with{RawSha256=new string('B',64)}).IsValid(kernel),"public observation hash must reconstruct the original native scalars");
 foreach(var field in new[]{0,4,8,24,32,40,108,112,120})
 {
  var changed=(byte[])b.Clone();changed[field]^=1;Reject(()=>Decode(changed),"wire/key/reserved mutation "+field);
 }
 Reject(()=>Decode(b[..127]),"short outcome");Reject(()=>Decode(b.Concat(new byte[1]).ToArray()),"oversized outcome");
 var unknown=(byte[])b.Clone();Put32(unknown,104,16);Reject(()=>Decode(unknown),"undefined flag");
 unknown=(byte[])b.Clone();Put32(unknown,92,6);Reject(()=>Decode(unknown),"unknown state");
 unknown=(byte[])b.Clone();Put32(unknown,96,10);Reject(()=>Decode(unknown),"undefined/health-only stage cannot explain an operation");
}
var pending=Frame(2);var immutable=Decode(pending);Put32(pending,92,3);Put32(pending,88,0xC0000001);Put32(pending,96,5);
Check(immutable.State==WindowsAcquisitionState.CopyPending&&Decode(pending).State==WindowsAcquisitionState.ExactBoundCopyFailure,"later failure cannot rewrite prior decoded snapshot");
var missing=Frame(0);Put(missing,56,1);Reject(()=>Decode(missing),"unbound overflow cannot acquire a causal negative ID");
var released=Frame(4);Put32(released,88,0x103);Reject(()=>Decode(released),"released bytes cannot be labelled pending");
var failed=Frame(3);Put32(failed,88,0);Reject(()=>Decode(failed),"successful status cannot support terminal copy failure");
var boundCapacity=Frame(3);Put32(boundCapacity,96,3);Check(Decode(boundCapacity).Stage==WindowsAcquisitionStage.FullCopyCapacity,"post-bind full-copy capacity retains actual stage 3");
Put(boundCapacity,64,0);Put(boundCapacity,72,0);Reject(()=>Decode(boundCapacity),"bound failure requires its real origin candidate");
for(uint stage=7;stage<=9;stage++){
 var sourceQuery=Frame(1);Put32(sourceQuery,96,stage);Put32(sourceQuery,88,0xC0000022);
 Check((uint)Decode(sourceQuery).Stage==stage,"pre-entry source query keeps actual metadata stage");
 Put(sourceQuery,64,7);Reject(()=>Decode(sourceQuery),"pre-entry source query cannot invent a candidate");
 sourceQuery=Frame(3);Put32(sourceQuery,96,stage);Reject(()=>Decode(sourceQuery),"source query before entry cannot be a bound copy failure");
}
foreach(uint stage in new uint[]{3,4,5,6}){var unbound=Frame(1);Put32(unbound,96,stage);Put(unbound,64,7);Check((uint)Decode(unbound).Stage==stage&&Decode(unbound).NegativeAssociation!=0,"unbound candidate failure later associates through exact negative record");}
var ready=Frame(5);Put(ready,64,0);Reject(()=>Decode(ready),"ready pin requires real candidate identity");
var prebind=Frame(1);Put(prebind,64,7);Check(Decode(prebind).OriginGeneration==0,"candidate allocated before process binding has no invented generation");
Put(prebind,72,9);Reject(()=>Decode(prebind),"unbound candidate cannot have a fabricated process generation");
var caps=new byte[48];Put32(caps,0,1);Put32(caps,4,48);Convert.FromHexString(provider).CopyTo(caps,8);Put(caps,24,10);Put(caps,32,1);Put32(caps,40,1);Put32(caps,44,128);
Check(WindowsAcquisitionOutcomeProtocol.Capabilities(caps,provider,10),"capability bound to active provider epoch and V1 layout");
foreach(var field in new[]{0,4,8,24,40,44}){var c=(byte[])caps.Clone();c[field]^=1;Reject(()=>WindowsAcquisitionOutcomeProtocol.Capabilities(c,provider,10),"malformed advertised capability "+field);}
Put(caps,32,2);Reject(()=>WindowsAcquisitionOutcomeProtocol.Capabilities(caps,provider,10),"unknown capability flags");
Put(caps,32,0);Check(!WindowsAcquisitionOutcomeProtocol.Capabilities(caps,provider,10),"absent capability is explicit and cannot claim V1 support");
var request=WindowsAcquisitionOutcomeProtocol.Request(provider,10,10,20);
Check(request.Length==48&&BinaryPrimitives.ReadUInt32LittleEndian(request)==4&&BinaryPrimitives.ReadUInt32LittleEndian(request.AsSpan(4))==34,"query retains protocol/command dispatch envelope");
Check(WindowsAcquisitionOutcomeProtocol.CapabilitiesRequest().SequenceEqual(new byte[]{4,0,0,0,35,0,0,0}),"capability command is exact 8-byte envelope");
var legacy=new WindowsAcquisitionObservation();Check(legacy.IsValid(new())&&legacy.ReasonCode==null&&legacy.NativeStatus==null&&legacy.QueryAttempted==false,"legacy source is explicit unavailable with no fabricated native state");
Check(!(legacy with{NativeStatus="0x00000000"}).IsValid(new()),"legacy observation cannot claim a successful native status");
var historical=new WindowsKernelEvidence();var historicalBytes=JsonSerializer.SerializeToUtf8Bytes(historical);
Check(!System.Text.Encoding.UTF8.GetString(historicalBytes).Contains("AcquisitionObservation")&&JsonSerializer.SerializeToUtf8Bytes(JsonSerializer.Deserialize<WindowsKernelEvidence>(historicalBytes)).SequenceEqual(historicalBytes),"additive nullable container preserves historical immutable serialization");
Console.WriteLine($"PASS {checks} acquisition-outcome codec checks; native dispatch, failure pool, durable intake and live qualification remain pending");
var health=new byte[88];Put32(health,0,1);Put32(health,4,88);Convert.FromHexString(provider).CopyTo(health,8);Put(health,24,10);Put32(health,32,128);Put32(health,36,2);Put(health,40,5);Put(health,48,5);Put(health,56,3);Put(health,64,1);Put(health,72,99);Put(health,80,1);
Check(WindowsAcquisitionOutcomeProtocol.NegativeHealth(health,provider,10) is {Live:2,ReferencesTaken:5,ReferencesReleased:3,GapCount:1,BindAttempted:1},"negative reference and coalesced loss counters are explicit");
foreach(var offset in new[]{0,4,8,24,32,36,40,48,56,80}){var bad=(byte[])health.Clone();bad[offset]^=0x80;Reject(()=>WindowsAcquisitionOutcomeProtocol.NegativeHealth(bad,provider,10),"contradictory negative health offset "+offset);}
var missingGapTime=(byte[])health.Clone();Put(missingGapTime,72,0);Reject(()=>WindowsAcquisitionOutcomeProtocol.NegativeHealth(missingGapTime,provider,10),"positive loss count requires observed monotonic gap time");
Console.WriteLine($"PASS {checks} total acquisition codec/health checks");
if(OperatingSystem.IsWindows())JournalChecks.Run();
await TransportChecks.Run(args.Length==1?args[0]:null);
