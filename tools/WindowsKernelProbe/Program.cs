using System.Text.Json;
using RansomFree.Client;
using RansomFree.Client.Forensics;
using RansomFree.Contracts;

if(args.Length==2&&args[0]=="--lifecycle"){LifecycleChecks.Run(args[1]);return;}
if(args.Length is not (3 or 4 or 5)||args.Length>=4&&args[3]!="--remote-filesystem")throw new ArgumentException("Arguments: watched directory, new output directory, duration seconds, optional --remote-filesystem and second watched directory");
var remoteFilesystem=args.Length>=4;
var watched=Path.GetFullPath(args[0]);var directory=Path.GetFullPath(args[1]);
if(Directory.Exists(directory))throw new IOException("Probe output must be a new directory");
Directory.CreateDirectory(directory);
var sensor=Guid.NewGuid().ToString("N");var gate=new object();
var spool=new EventSpool(directory,sensor);var output=Path.Combine(directory,"events.jsonl");
void Persist(AgentEvent e){lock(gate){spool.Enqueue(e);using var file=new FileStream(output,FileMode.Append,FileAccess.Write,FileShare.Read);file.Write(JsonSerializer.SerializeToUtf8Bytes(e));file.WriteByte(10);file.Flush(true);}}
void Health(string message){lock(gate)File.AppendAllText(Path.Combine(directory,"health.jsonl"),JsonSerializer.Serialize(new{Time=DateTimeOffset.UtcNow,Message=message})+Environment.NewLine);}
await using(var pipeline=new ForensicPipeline(sensor,directory,Health))
{
void Publish(AgentEvent e,ActorLease? early){
 var restored=WindowsKernelSource.RestorePrepared(directory,e.EventId);
 if(restored!=null){early?.Dispose();Persist(restored);return;}
 pipeline.Submit(e,new(),pending=>{WindowsKernelSource.SavePrepared(directory,pending);Persist(pending);},Persist,early);
}
await using(var source=new WindowsKernelSource(sensor,directory,()=>Directory.GetFiles(watched,"*.bin").Concat(args.Length==5?Directory.GetFiles(Path.GetFullPath(args[4]),"*.bin"):[]).ToArray(),e=>Publish(e,null),Health,Publish,captureStagedExecutables:remoteFilesystem,captureRemoteFilesystem:remoteFilesystem))
{await Task.Delay(TimeSpan.FromSeconds(int.Parse(args[2])));}
}
spool=new EventSpool(directory,sensor);
Console.WriteLine(JsonSerializer.Serialize(new{Sensor=sensor,DurableEvents=spool.Count,Output=output,Health=Path.Combine(directory,"health.jsonl")}));
