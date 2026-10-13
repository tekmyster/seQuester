using System.Text;
using System.Text.Json;
using RansomFree.LinuxAgent;
if(!OperatingSystem.IsLinux()||!File.Exists("/.dockerenv")||Environment.GetEnvironmentVariable("SQ_PRIVATE_MOUNT_TEST")!="yes")throw new Exception("Isolated container required");
var checks=new List<string>();void Check(bool yes,string label){if(!yes)throw new Exception(label);checks.Add(label);Console.WriteLine("PASS "+label);}
var boot=File.ReadAllText("/proc/sys/kernel/random/boot_id").Trim();var stamp=DateTimeOffset.UtcNow.ToUnixTimeSeconds()+".123:911101";
var lines=new[]{
$"type=SYSCALL msg=audit({stamp}): arch=c000003e syscall=257 success=no exit=-13 a0=ffffff9c a1=0 a2=0 a3=0 items=1 ppid=123 pid=567 auid=1000 uid=1000 gid=2000 euid=1001 suid=1000 fsuid=1002 egid=2001 sgid=2000 fsgid=2002 tty=(none) ses=77 comm=\"actor\" exe=\"/exited/actor\" key=\"sequester_canary\"\n",
$"type=CWD msg=audit({stamp}): cwd=\"/owned\"\n",
$"type=PATH msg=audit({stamp}): item=0 name=\"/owned/target\" inode=32 dev=08:02 mode=0100000 ouid=0 ogid=0 rdev=00:00 nametype=NORMAL\n",
$"type=PROCTITLE msg=audit({stamp}): proctitle=2F6578697465642F6163746F72002D2D72656164\n"};
AuditPacket One(string data){var rows=new List<AuditPacket>();var errors=new List<string>();using var parser=new AuditParser(true,boot,rows.Add,errors.Add);parser.Feed(Encoding.UTF8.GetBytes(data));parser.Flush();Check(errors.Count==0&&rows.Count==1,"actual upstream parser accepts owned record");return rows.Single();}
var partial=One(lines[0]);Check(partial.Pid==567&&partial.Executable=="/exited/actor"&&partial.Attribution.FileSystemUserId==1002,"pathless syscall retains original actor and security context");
Check(partial.Paths.Length==0&&!partial.Attribution.CompleteRecordSet&&partial.Attribution.PathRole=="UNAVAILABLE","missing target marked explicitly");
Check(AuditPacketEvidence.Normalize(partial).Pid==567,"pathless explicit evidence accepted");
var refused=false;try{AuditPacketEvidence.Normalize(partial with{Attribution=partial.Attribution with{PathRole=null}});}catch(InvalidDataException){refused=true;}Check(refused,"unmarked target omission rejected");
var full=string.Concat(lines);var recovered=AuditLogRecovery.Parse(Encoding.UTF8.GetBytes(full),partial,true,boot)!;
Check(recovered.Paths.Single().Path=="/owned/target"&&recovered.Attribution.CompleteRecordSet&&recovered.Attribution.CommandLine=="/exited/actor --read","exact full record recovers target and command line");
foreach(var replacement in new[]{("pid=567","pid=568"),("uid=1000","uid=1004"),("fsuid=1002","fsuid=1005"),("ses=77","ses=78"),("auid=1000","auid=1003"),("ppid=123","ppid=124"),("exit=-13","exit=-2"),("/exited/actor","/different/actor"),("comm=\"actor\"","comm=\"different\"")})
{refused=false;try{AuditLogRecovery.Parse(Encoding.UTF8.GetBytes(full.Replace(replacement.Item1,replacement.Item2)),partial,true,boot);}catch(InvalidDataException){refused=true;}Check(refused,"recovery refuses changed "+replacement.Item1);}
refused=false;try{AuditLogRecovery.Parse(Encoding.UTF8.GetBytes(lines[0]),partial,true,boot);}catch(InvalidDataException){refused=true;}Check(refused,"incomplete source cannot claim full recovery");
Check(AuditLogRecovery.Parse(Encoding.UTF8.GetBytes(full.Replace(stamp,stamp.Replace("911101","911102"))),partial,true,boot)==null,"different kernel serial never matches");
Directory.CreateDirectory("/etc/audit");Directory.CreateDirectory("/fixture-private");var log="/fixture-private/audit.log";
void Put(string name,string text){File.WriteAllText(name,text,new UTF8Encoding(false));File.SetUnixFileMode(name,UnixFileMode.UserRead|UnixFileMode.UserWrite);}
Put("/etc/audit/auditd.conf","log_file = "+log+"\n");Put(log,full);
Check(AuditLogRecovery.Read(partial)!.SequenceEqual(Encoding.UTF8.GetBytes(full)),"bounded protected log reader selects exact record");
Put(log+".1",lines[0]+lines[1]);Put(log,lines[2]+lines[3]);Check(AuditLogRecovery.Parse(AuditLogRecovery.Read(partial)!,partial,true,boot)!.Paths.Length==1,"record spanning audit rotation recovers in order");
File.Delete(log+".1");Put(log,full.TrimEnd('\n'));Check(AuditLogRecovery.Read(partial)!.SequenceEqual(Encoding.UTF8.GetBytes(string.Concat(lines.Take(3)))),"unfinished final log line never fabricated");
Put(log,new string('x',9*1024*1024)+"\n"+full);Check(AuditLogRecovery.Read(partial)!.SequenceEqual(Encoding.UTF8.GetBytes(full)),"large log read bounded to tail");
File.SetUnixFileMode(log,UnixFileMode.UserRead|UnixFileMode.UserWrite|UnixFileMode.OtherWrite);refused=false;try{AuditLogRecovery.Read(partial);}catch(IOException){refused=true;}Check(refused,"writable audit source refused");
File.Delete(log);File.CreateSymbolicLink(log,"/etc/passwd");refused=false;try{AuditLogRecovery.Read(partial);}catch(IOException){refused=true;}Check(refused,"symlink source refused");File.Delete(log);
Check(AuditLogRecovery.Read(partial)==null,"missing log remains unavailable");
Put("/etc/audit/auditd.conf","log_file = "+log+"\nlog_file = "+log+"\n");refused=false;try{AuditLogRecovery.Read(partial);}catch(InvalidDataException){refused=true;}Check(refused,"ambiguous configuration refused");
foreach(var identity in new[]{boot+"::",boot+":.:1",boot+":1.234:"}){refused=false;try{AuditLogRecovery.Read(partial with{Identity=identity});}catch(InvalidDataException){refused=true;}Check(refused,"empty/invalid kernel identity refused");}
Console.WriteLine(JsonSerializer.Serialize(new{Passed=true,Checks=checks.Count,Cases=checks,Scope="Actual upstream parser and protected Linux log descriptor recovery in isolated container; synthetic records"}));
namespace RansomFree.LinuxAgent{internal static class AuditDispatcher{internal const string Key="sequester_canary";}}
