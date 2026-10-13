using System.Text.Json;
using RansomFree.Client;
using RansomFree.Contracts;
if(args.Length!=2)throw new ArgumentException("Captured candidate events and new private spool directory required");
var events=File.ReadLines(args[0]).Select(line=>JsonSerializer.Deserialize<AgentEvent>(line)!).Where(e=>e.Source=="Windows minifilter"&&e.Attribution?.WindowsKernel?.Version==6).ToArray();
if(events.Length==0)throw new Exception("Actual candidate records required");
var count=0;
void Check(bool condition,string message){if(!condition)throw new Exception(message);count++;Console.WriteLine("PASS: "+message);}
foreach(var e in events){
 var k=e.Attribution!.WindowsKernel!;
 Check(k.IsValid()&&WindowsKernelEvidence.Matches(e),"captured remote event validates with preserved thread context");
 Check(!(k with{Version=5}).IsValid(),"remote completion cannot be mislabeled as legacy local evidence");
 Check(!(k with{FileIoBoundary="server-ntfs"}).IsValid(),"client completion cannot assert remote server completion");
 Check(!(k with{RemoteProviderStatus="SMB verified"}).IsValid(),"uncollected provider identity cannot be manufactured");
 Check(!(k with{NativePath=@"\Device\HarddiskVolume1\file.bin"}).IsValid(),"remote flag requires the recorded MUP boundary");
 Check(!(k with{Flags=k.Flags&~1024u}).IsValid(),"remote schema requires native boundary flag");
 Check(JsonSerializer.Deserialize<AgentEvent>(JsonSerializer.Serialize(e))!.Attribution!.WindowsKernel!.IsValid(),"JSON retains explicit remote boundary semantics");
}
var directory=Path.GetFullPath(args[1]);if(Directory.Exists(directory))throw new IOException("Fresh spool directory required");
var spool=new EventSpool(directory,Guid.NewGuid().ToString("N"));spool.Enqueue(events[0]);var batch=spool.Peek();
var supported=new BatchReceipt(1,0){AttributionVersion=1,ForensicsVersion=1,ActorAcquisitionVersion=1,ProcessCreationVersion=1,WindowsKernelVersion=6};
var rejected=false;try{spool.Acknowledge(batch,supported with{WindowsKernelVersion=5});}catch(InvalidDataException ex){rejected=ex.Message.StartsWith("Windows kernel evidence not acknowledged",StringComparison.Ordinal);}
Check(rejected&&spool.Count==1,"older server acknowledgment retains remote evidence");
spool.Acknowledge(batch,supported);
Check(spool.Count==0,"version 6 acknowledgment permits durable queue removal");
Console.WriteLine($"PASS: {count} remote schema checks on {events.Length} captured operations");
