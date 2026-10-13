using System.Text;
using System.Text.Json;
using RansomFree.Client.Forensics;

if(args.Length==2&&args[0]=="raw-capacity"){RawCapacityChecks.Run(Path.GetFullPath(args[1]));return;}

if(args.Length==1&&args[0]=="timer-spin"){await TimerSpinChecks.Run();return;}
if(args.Length==2&&args[0]=="target-statx"){TargetStatxChecks.Run(Path.GetFullPath(args[1]));return;}
if(args.Length is 2 or 3&&args[0]=="queue-lifetime"){
 QueueLifetimeChecks.Run(Path.GetFullPath(args[1]),args.Length==3&&args[2]=="baseline");return;
}

if(args.Length is 2 or 3&&args[0]=="journal-lifetime"){
 JournalLifetimeChecks.Run(Path.GetFullPath(args[1]),args.Length==3&&args[2]=="baseline");return;
}

var checks=new List<string>();
void Check(bool ok,string label){if(!ok)throw new Exception(label);checks.Add(label);}
var directKey=new LinuxProtectedDirectory.DirectMountKey(2147483678,29,8,2,0xef53);
byte[] DirectResponse(){var bytes=new byte[1024];BitConverter.TryWriteBytes(bytes.AsSpan(),518u);BitConverter.TryWriteBytes(bytes.AsSpan(8),0x23ul);BitConverter.TryWriteBytes(bytes.AsSpan(16),8u);BitConverter.TryWriteBytes(bytes.AsSpan(20),2u);BitConverter.TryWriteBytes(bytes.AsSpan(24),0xef53ul);BitConverter.TryWriteBytes(bytes.AsSpan(40),directKey.Unique);BitConverter.TryWriteBytes(bytes.AsSpan(56),29u);Encoding.ASCII.GetBytes("ext4\0").CopyTo(bytes,512);return bytes;}
Check(LinuxProtectedDirectory.ParseDirectMount(DirectResponse(),directKey)=="ext4","direct query exact unique and legacy identity matched");
foreach(var offset in new[]{0,8,16,20,24,36,40,56,516}){
 var bytes=DirectResponse();if(offset==0)BitConverter.TryWriteBytes(bytes.AsSpan(),uint.MaxValue);else bytes[offset]^=0xff;
 try{LinuxProtectedDirectory.ParseDirectMount(bytes,directKey);throw new Exception("malformed direct identity accepted");}catch(IOException){Check(true,"direct response invalid field refused at "+offset);}
}
try{LinuxProtectedDirectory.ParseDirectMount(new byte[511],directKey);throw new Exception("short direct response accepted");}catch(IOException){Check(true,"truncated direct response refused");}
string Read(byte[] bytes,int? chunk=null)=>LinuxProtectedDirectory.ReadMountInventory(chunk.HasValue?new FragmentedStream(bytes,chunk.Value):new MemoryStream(bytes));
Check(Read([])=="","empty inventory");
var small=Encoding.UTF8.GetBytes("42 1 8:2 / / rw - ext4 /dev/sda2 rw\n");
Check(Read(small)==Encoding.UTF8.GetString(small),"exact bytes retained");
Check(Read(small,3)==Encoding.UTF8.GetString(small),"fragmented reads preserved");
var large=Enumerable.Repeat((byte)'a',1024*1024).ToArray();
Check(Read(large,127).Length==large.Length,"original one MiB limit accepted");
try{Read(new byte[1024*1024+1]);throw new Exception("oversized accepted");}catch(IOException){Check(true,"one byte beyond bound rejected");}
try{LinuxProtectedDirectory.ReadMountInventory(new BrokenStream());throw new Exception("read failure hidden");}catch(IOException){Check(true,"stream failure remains visible");}
Check(Read(small)==Encoding.UTF8.GetString(small),"buffer usable after failed read");
string? Type(string text)=>LinuxProtectedDirectory.ReadMountType(text,42,8,2);
var mountLine=Encoding.UTF8.GetString(small);
Check(Type(mountLine)=="ext4","exact selected mount type");
Check(Type(mountLine.TrimEnd('\n'))=="ext4","last mount without newline");
Check(Type("\n"+mountLine+"\n")=="ext4","empty lines retained semantics");
Check(Type("142 1 8:2 / / rw - xfs /dev/sda2 rw\n")==null,"mount id prefix is not a match");
Check(Type(mountLine.Replace("ext4","xfs"))=="xfs","non ext4 type preserved for rejection by caller");
foreach(var invalid in new[]{mountLine+mountLine,mountLine.Replace("8:2","8:3"),"42",mountLine.Replace(" - "," "),mountLine.TrimEnd('\n')+" extra"}){
 try{Type(invalid);throw new Exception("invalid selected mount accepted");}catch(IOException){Check(true,"ambiguous or malformed selected mount rejected");}
}
var unrelated=string.Concat(Enumerable.Range(1000,1000).Select(n=>$"{n} 1 8:2 / / rw - ext4 /dev/sda2 rw\n"))+mountLine;
for(var n=0;n<20;n++)Type(unrelated);
var parseBefore=GC.GetAllocatedBytesForCurrentThread();var allSelected=true;
for(var n=0;n<1000;n++)allSelected&=Type(unrelated)=="ext4";
var parseAllocated=GC.GetAllocatedBytesForCurrentThread()-parseBefore;
Check(allSelected,"large inventory selected mount unchanged");
Check(parseAllocated<1024*1024,"1000 parses with 1000 unrelated mounts allocate under one MiB total");
var reads=0;
using(var pass=new LinuxProtectedDirectory.MountValidationPass(()=>{reads++;return mountLine;})){
 for(var n=0;n<1000;n++)if(pass.Observe(42,8,2)!="ext4")throw new Exception("mount validation changed");
 pass.Complete();Check(reads==2,"1000 observations use fresh before and after inventory, no retained cross-pass cache");
 try{pass.Observe(42,8,2);throw new Exception("completed pass reusable");}catch(InvalidOperationException){Check(true,"completed pass cannot supply further mount observations");}
}
foreach(var changed in new[]{"",mountLine.Replace("ext4","xfs"),mountLine+mountLine,mountLine.Replace("8:2","8:3")}){
 reads=0;using var pass=new LinuxProtectedDirectory.MountValidationPass(()=>++reads==1?mountLine:changed);
 Check(pass.Observe(42,8,2)=="ext4","initial mount observed before mutation");
 try{pass.Complete();throw new Exception("changed mount accepted");}catch(IOException){Check(true,"removed substituted duplicate or changed-device mount refused before validation completes");}
}
using(var pass=new LinuxProtectedDirectory.MountValidationPass(()=>mountLine+"777 1 8:2 / / rw - ext4 /dev/sda2 rw\n")){
 Check(pass.Observe(42,8,2)=="ext4","unrelated mounts do not replace selected mount");pass.Complete();
}
for(var n=0;n<20;n++)Read(small);
var before=GC.GetAllocatedBytesForCurrentThread();for(var n=0;n<1000;n++)Read(small);
var allocated=GC.GetAllocatedBytesForCurrentThread()-before;
Check(allocated<1024*1024,"1000 repeated small inventories allocate under one MiB total");
reads=0;
using(var pass=new LinuxProtectedDirectory.MountValidationPass(()=>{reads++;return mountLine;},eager:false)){
 Check(reads==0,"lazy production pass avoids full mount inventory until fallback is needed");
 Check(pass.Observe(42,8,2)=="ext4"&&reads==1,"unsupported direct API fallback reads fresh inventory");
 pass.Complete();Check(reads==2,"fallback completion rechecks fresh inventory");
}
if(OperatingSystem.IsLinux()){
 using var input=File.OpenRead("/proc/self/mountinfo");
 var current=LinuxProtectedDirectory.ReadMountInventory(input);
 Check(current.Length>0&&current.Split('\n').Any(x=>x.Contains(" - ext4 ")),"actual Linux mount inventory read with unchanged ext4 classification data");
 using var directory=LinuxProtectedDirectory.OpenRoot(AppContext.BaseDirectory.TrimEnd('/'));
 using var pass=LinuxProtectedDirectory.BeginMountValidation();
 var mount=directory.RequireQualifiedLocalExt4();pass.Complete();
 Check(mount.Type=="ext4"&&mount.MountId>0,"actual held Linux descriptor and fresh before/after mount inventory validation");
 var iterations=0;var cpu=System.Diagnostics.Process.GetCurrentProcess().TotalProcessorTime;
 var timer=System.Diagnostics.Stopwatch.StartNew();
 for(var n=0;n<100;n++){
  using var directPass=new LinuxProtectedDirectory.MountValidationPass(()=>throw new Exception("direct query unexpectedly read full mount inventory"),eager:false);
  Check(directory.RequireQualifiedLocalExt4()==mount,"live direct mount identity remains equal to admitted descriptor");
  directPass.Complete();iterations++;
 }
 Console.WriteLine(JsonSerializer.Serialize(new{DirectMountLive=true,Iterations=iterations,CpuMs=(System.Diagnostics.Process.GetCurrentProcess().TotalProcessorTime-cpu).TotalMilliseconds,ElapsedMs=timer.Elapsed.TotalMilliseconds}));
}
Console.WriteLine(JsonSerializer.Serialize(new{Passed=true,Checks=checks.Count,ChecksPassed=checks,SmallReadIterations=1000,AllocatedBytes=allocated,LargeInventoryParseIterations=1000,ParseAllocatedBytes=parseAllocated,Platform=Environment.OSVersion.Platform.ToString()}));

sealed class FragmentedStream(byte[] bytes,int maximum):MemoryStream(bytes){public override int Read(byte[] buffer,int offset,int count)=>base.Read(buffer,offset,Math.Min(count,maximum));}
sealed class BrokenStream:MemoryStream{public override int Read(byte[] buffer,int offset,int count)=>throw new IOException("controlled fixture failure");}
