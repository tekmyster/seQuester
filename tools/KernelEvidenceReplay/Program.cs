using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using RansomFree.Client;
using RansomFree.Contracts;

if(args.Length is not (3 or 4)||args.Length==4&&args[3]!="--prepared-linux")throw new ArgumentException("Arguments: HTTPS server, private data directory, kernel JSONL, optional --prepared-linux");
var linux=args.Length==4;var reportedHost=linux?"plex01-kernel-lab":"SQ-KERNEL-TEST";
var directory=Path.GetFullPath(args[1]);Directory.CreateDirectory(directory);
var connectionFile=Path.Combine(directory,"lab-connection.json");
Connection connection;
if(File.Exists(connectionFile))connection=JsonSerializer.Deserialize<Connection>(File.ReadAllText(connectionFile))!;
else{
 using var enrolling=new ManagementClient(args[0]);
 var code=Console.ReadLine()??throw new ArgumentException("Enrollment code must be supplied on standard input");
 var enrollment=await enrolling.EnrollAsync(new(code,reportedHost,"0.0.1-kernel-lab"));
 connection=new(enrollment.EndpointId,Convert.ToBase64String(ProtectedData.Protect(Encoding.UTF8.GetBytes(enrollment.Credential),null,DataProtectionScope.LocalMachine)));
 using var stream=new FileStream(connectionFile,FileMode.CreateNew,FileAccess.Write,FileShare.None);JsonSerializer.Serialize(stream,connection);stream.Flush(true);
}
using var management=new ManagementClient(args[0],Encoding.UTF8.GetString(ProtectedData.Unprotect(Convert.FromBase64String(connection.ProtectedCredential),null,DataProtectionScope.LocalMachine)));
await management.HeartbeatAsync(new("0.0.1-kernel-lab","Isolated kernel test; captured evidence replayed through management spool") {OperatingSystem=linux?"linux":"windows"});
var spool=new EventSpool(directory,connection.EndpointId);var submitted=new List<AgentEvent>();
foreach(var line in File.ReadLines(args[2])){
 if(linux){var prepared=JsonSerializer.Deserialize<AgentEvent>(line)??throw new InvalidDataException("Missing prepared event");if(prepared.Source!="Linux eBPF prototype"||prepared.Attribution?.Provider!="Linux eBPF prototype")throw new InvalidDataException("Unexpected prepared provider");spool.Enqueue(prepared);submitted.Add(prepared);continue;}
 using var json=JsonDocument.Parse(line);var e=json.RootElement;
 if(e.GetProperty("Kind").GetString()!="File")continue;
 string S(string name)=>e.GetProperty(name).GetString()??"";
 var nativePid=e.GetProperty("ProcessId").GetUInt64();int? pid=nativePid is >0 and <=int.MaxValue?(int)nativePid:null;
 var major=e.GetProperty("Major").GetUInt32();var kind=e.GetProperty("OperationClass").GetUInt32();var flags=e.GetProperty("Flags").GetUInt32();var status=e.GetProperty("Status").GetInt32();
 var operation=major switch{0=>"File open",3=>"Content read (copy possible)",4=>"Content written",6 when kind is 10 or 65=>"File renamed",6 when kind is 13 or 64=>"Delete requested",6=>"File metadata changed",21=>"Permissions changed",255=>"Memory mapping requested",_=>"File operation"};
 var sid=S("UserSid");var image=S("Image");var user=S("User");if(user.Length==0)user=sid;
 var complete=pid.HasValue&&sid.Length>0&&image.Length>0&&(flags&31)==0;
 var identity=$"{S("Host")}|{e.GetProperty("Instance").GetUInt64()}|{e.GetProperty("Sequence").GetUInt64()}|{S("ObservedUtc")}";
 var id=Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(identity)).AsSpan(0,16)).ToLowerInvariant();
 var basis=$"Kernel event snapshot; effective SID={sid}; process owner SID={S("PrimaryUserSid")}; flags={flags}; NTSTATUS=0x{status:x8}; information={e.GetProperty("Information").GetUInt64()}. Test-VM evidence replay.";
 if(basis.Length>512)throw new InvalidDataException("Evidence basis exceeds server contract; native record retained");
 var item=new AgentEvent(id,e.GetProperty("ObservedUtc").GetDateTimeOffset(),operation,S("Path"),user.Length>0?user:null,image.Length>0?image:null,pid,"Windows minifilter prototype") {Attribution=new(){Provider="Windows minifilter prototype",Level=complete?"Full attribution":pid.HasValue||sid.Length>0||image.Length>0?"Partial attribution":"Detection only",Basis=basis,EvidenceId=$"{e.GetProperty("Instance").GetUInt64()}:{e.GetProperty("Sequence").GetUInt64()}",Syscall=$"IRP:{major}:{kind}",Outcome=status>=0?"Success":"Failed",UserName=user.Length>0?user:null,AccountNameSource="Kernel SID; account label resolved by the capture probe",ProcessName=image.Length>0?Path.GetFileName(image):null,ProcessStartTicks=e.GetProperty("ProcessCreatedUtcFileTime").GetInt64().ToString(System.Globalization.CultureInfo.InvariantCulture),EventTimeCredentials=sid.Length>0,CompleteRecordSet=complete}};
 spool.Enqueue(item);submitted.Add(item);
}
// Reopen the actual management spool before transmission to verify durable restoration.
spool=new EventSpool(directory,connection.EndpointId);var restored=spool.Count;var accepted=0;var duplicates=0;
while(spool.Count>0){var batch=spool.Peek();var receipt=await management.SendEventsAsync(batch);spool.Acknowledge(batch,receipt);accepted+=receipt.Accepted;duplicates+=receipt.Duplicates;}
File.WriteAllText(Path.Combine(directory,"submitted-events.json"),JsonSerializer.Serialize(submitted));
var result=new{EndpointId=connection.EndpointId,NativeEvents=submitted.Count,RestoredQueue=restored,Accepted=accepted,Duplicates=duplicates,Remaining=spool.Count,ObservedHost=linux?"plex01":"SQ-KERNEL-TEST",Transport="Host-relayed captured kernel evidence through the actual management client and durable spool"};
File.WriteAllText(Path.Combine(directory,"delivery-result.json"),JsonSerializer.Serialize(result));Console.WriteLine(JsonSerializer.Serialize(result));
record Connection(string EndpointId,string ProtectedCredential);
