using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Security.Principal;
using System.Text.Json;
using Microsoft.Win32.SafeHandles;
using RansomFree.Client.Forensics;
using RansomFree.Contracts;

if(args.Length!=1||WindowsIdentity.GetCurrent().User?.Value!="S-1-5-18"||Environment.MachineName!="CPTNYC_DC01")throw new ArgumentException("Owned isolated DC clone and SYSTEM required");
var root=Path.GetFullPath(args[0]);if(Directory.Exists(root))throw new IOException("Output exists");Directory.CreateDirectory(root);
using var seed=JsonDocument.Parse(File.ReadAllBytes(Path.Combine(Path.GetDirectoryName(root)!,"ack-recovery-seed.json")));var s=seed.RootElement;
if(s.GetProperty("Schema").GetString()!="sequester.dc-r37-ack-recovery-seed/v1")throw new InvalidDataException("Unexpected recovery seed");
var directory=s.GetProperty("CaptureDirectory").GetString()!;var storePath=Path.Combine(directory,"kernel-actor-intake");
if(directory!=@"C:\SqKernelTest\image-diagnostic-4c051b13498d484db423c4dd9f33ae36\results\capture")throw new InvalidDataException("Recovery must use the exact prior owned lab outbox, preserving file identities");
var sensor=s.GetProperty("Sensor").GetString()!;var pending=s.GetProperty("PendingSnapshotId").GetString()!;if(!Guid.TryParseExact(sensor,"N",out _)||pending!="14cb6c38d5e74e5c8debaf8bdbe333e6")throw new InvalidDataException("Unexpected captured sensor/snapshot identity");
var checks=new List<string>();var health=new List<string>();var identities=new Dictionary<string,FileIdentityEvidence>();var before=new Dictionary<string,string>(StringComparer.Ordinal);var after=new Dictionary<string,string>(StringComparer.Ordinal);bool passed=false;string? error=null;var nativeRpcAcks=0;string? provider=null;ulong instance=0;object? nativeHealth=null;
void Check(bool value,string label){if(!value)throw new IOException(label);checks.Add(label);}
string Hash(string path){using var file=File.OpenRead(path);return Convert.ToHexString(SHA256.HashData(file));}
void Save(string name,object value)=>File.WriteAllText(Path.Combine(root,name),JsonSerializer.Serialize(value,new JsonSerializerOptions{WriteIndented=true}));
try
{
 // Copies below preserve original serialized evidence for comparison only. The
 // actual recovery uses the original private files: copying/rebasing their NTFS
 // identities would not establish recovery of the recorded snapshot identity.
 var beforeCopy=Path.Combine(root,"before");Directory.CreateDirectory(beforeCopy);
 foreach(var entry in s.GetProperty("Files").EnumerateArray())
 {
  var name=entry.GetProperty("Name").GetString()!;Check(Path.GetFileName(name)==name,"seed paths are basenames");var path=Path.Combine(storePath,name);var hash=Hash(path);Check(hash==entry.GetProperty("Sha256").GetString(),"original outbox file matches sealed failed-archive bytes: "+name);before.Add(name,hash);File.Copy(path,Path.Combine(beforeCopy,name),false);
 }
 Check(Directory.GetFiles(storePath).Select(Path.GetFileName).Order().SequenceEqual(before.Keys.Order()),"original outbox has no unrecorded files before recovery");
 foreach(var index in Directory.GetFiles(storePath,"*.process.json"))
 {
  using var record=JsonDocument.Parse(File.ReadAllBytes(index));var r=record.RootElement;if(r.GetProperty("State").GetString()!="captured")continue;
  var id=r.GetProperty("SnapshotId").GetString()!;var expected=r.GetProperty("SnapshotFile").Deserialize<FileIdentityEvidence>()!;var path=Path.Combine(storePath,id+".bin");
  using var file=File.OpenRead(path);var actual=NativeFileIdentity.Read(file);Check(NativeFileIdentity.Same(expected,actual)&&file.Length==r.GetProperty("Ready").GetProperty("ByteLength").GetInt64()&&Convert.ToHexString(SHA256.HashData(file))==r.GetProperty("Sha256").GetString()&&NativeFileIdentity.Same(actual,NativeFileIdentity.Read(file)),"original snapshot bytes and recorded NTFS identity survive service restart: "+id);identities.Add(id,actual);
 }
 Check(identities.Count==7,"all seven archived process snapshots verified before recovery");
 var outcomesBefore=Directory.GetFiles(storePath,"*.ack-outcome.json");Check(outcomesBefore.Length==6&&!File.Exists(Path.Combine(storePath,pending+".ack"))&&!File.Exists(Path.Combine(storePath,pending+".ack-outcome.json")),"only the recorded background intent is pending before recovery");
 Marshal.ThrowExceptionForHR(Native.FilterConnectCommunicationPort("\\SeQuesterActorPrototype",0,0,0,0,out var port));using(port)
 {
  byte[] Get(uint command,int length){var request=WindowsStagedActorProtocol.Message(command);var reply=new byte[length];Marshal.ThrowExceptionForHR(Native.FilterSendMessage(port,request,8,reply,(uint)length,out var n));if(n!=length)throw new IOException("Native reply size differs");return reply;}
  var binding=Get(20,88);var operations=Get(3,48);provider=Convert.ToHexString(binding.AsSpan(8,16));instance=WindowsStagedActorProtocol.U64(operations,8);
  Check(WindowsStagedActorProtocol.U32(binding,0)==1&&WindowsStagedActorProtocol.U32(binding,4)==88&&WindowsStagedActorProtocol.U32(operations,0)==4&&provider!=s.GetProperty("Provider").GetString()&&instance!=s.GetProperty("Instance").GetUInt64(),"actual reloaded native provider and operation epoch differ from saved outbox");
  byte[] NoAck(byte[] request,int size){nativeRpcAcks++;throw new IOException("Provider-changed recovery attempted a stale native RPC");}
  var recovered=new WindowsStagedActorStore(directory,sensor);recovered.RetryProcessAcknowledgements(provider,instance,NoAck,health.Add);
  var terminalPath=Path.Combine(storePath,pending+".ack-outcome.json");using var terminal=JsonDocument.Parse(File.ReadAllBytes(terminalPath));var t=terminal.RootElement;using var intent=JsonDocument.Parse(File.ReadAllBytes(Path.Combine(storePath,pending+".ack-intent.json")));var i=intent.RootElement;
  Check(t.GetProperty("Outcome").GetString()=="ACK_PROVIDER_CHANGED"&&t.GetProperty("Attempt").GetInt32()==0&&t.GetProperty("SnapshotId").GetString()==pending&&t.GetProperty("ClaimSha256").GetString()==i.GetProperty("ClaimSha256").GetString()&&t.GetProperty("NativeCode").ValueKind==JsonValueKind.Null,"provider change appends an explicit non-confirmed terminal with exact claim linkage");
  var terminalHash=Hash(terminalPath);new WindowsStagedActorStore(directory,sensor).RetryProcessAcknowledgements(provider,instance,NoAck,health.Add);
  Check(Hash(terminalPath)==terminalHash&&nativeRpcAcks==0&&!File.Exists(Path.Combine(storePath,pending+".ack")),"second service restart preserves the same terminal and sends zero ACK RPCs");
  foreach(var pair in before)Check(Hash(Path.Combine(storePath,pair.Key))==pair.Value,"prior outbox file remains byte-identical: "+pair.Key);
  foreach(var pair in identities){using var file=File.OpenRead(Path.Combine(storePath,pair.Key+".bin"));Check(NativeFileIdentity.Same(pair.Value,NativeFileIdentity.Read(file)),"recovery preserves snapshot NTFS identity: "+pair.Key);}
  foreach(var path in Directory.GetFiles(storePath))after.Add(Path.GetFileName(path),Hash(path));Check(after.Keys.Except(before.Keys).SequenceEqual(new[]{pending+".ack-outcome.json"}),"only one new terminal file is appended to the original lab outbox");
  Get(9,0);var b=Get(20,88);var st=Get(12,224);var pm=Get(28,48);var op=Get(3,48);
  Check(WindowsStagedActorProtocol.U64(b,40)==WindowsStagedActorProtocol.U64(b,48)&&WindowsStagedActorProtocol.U32(b,64)==0&&WindowsStagedActorProtocol.U64(b,72)==WindowsStagedActorProtocol.U64(b,80)&&WindowsStagedActorProtocol.U64(st,24)==0&&WindowsStagedActorProtocol.U32(st,212)==1&&WindowsStagedActorProtocol.U32(pm,12)==0&&WindowsStagedActorProtocol.U64(pm,16)==WindowsStagedActorProtocol.U64(pm,24)&&WindowsStagedActorProtocol.U64(op,24)==0,"new provider stops with balanced native resources and no raw loss");nativeHealth=new{Binding=Convert.ToHexString(b),Staging=Convert.ToHexString(st),ProcessCreation=Convert.ToHexString(pm),Operations=Convert.ToHexString(op)};
 }
 var afterCopy=Path.Combine(root,"after");Directory.CreateDirectory(afterCopy);foreach(var name in after.Keys)File.Copy(Path.Combine(storePath,name),Path.Combine(afterCopy,name),false);passed=true;
}
catch(Exception ex){error=ex.ToString();}
Save("RESULTS.json",new{Schema="sequester.windows-ack-recovery-native/v1",AccountingPassed=passed,AllChildrenObserved=passed,Children=0,Matches=passed?1:0,Sensor=sensor,OldArchiveSha256=s.GetProperty("ArchiveSha256").GetString(),OldProvider=s.GetProperty("Provider").GetString(),Provider=provider,Instance=instance,PendingSnapshotId=pending,NativeRpcAcks=nativeRpcAcks,BeforeHashes=before,AfterHashes=after,SnapshotIdentities=identities,Checks=checks,Health=health,NativeHealth=nativeHealth,ByteCaptureImplemented=true,ProductionReady=false,Error=error,Scope="Actual new provider plus original private NTFS outbox; append-only provider-change terminal, no confirmed ACK invented. Immutable failed archive remains unchanged."});Console.WriteLine(JsonSerializer.Serialize(new{passed,error}));if(!passed)Environment.ExitCode=2;
static class Native
{
 [DllImport("fltlib.dll",CharSet=CharSet.Unicode)]internal static extern int FilterConnectCommunicationPort(string name,uint options,nint context,ushort size,nint security,out SafeFileHandle port);
 [DllImport("fltlib.dll")]internal static extern int FilterSendMessage(SafeFileHandle port,byte[] input,uint size,[Out]byte[] output,uint outputSize,out uint returned);
}
