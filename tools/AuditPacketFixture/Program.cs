using RansomFree.Contracts;
using RansomFree.LinuxAgent;
var passed=0;
void Check(bool value,string name){if(!value)throw new Exception(name);passed++;Console.WriteLine("PASS "+name);}
if(args.Contains("--parse-metadata"))
{
    var stamp=DateTimeOffset.UtcNow.ToUnixTimeSeconds();
    var sample=$"type=SYSCALL msg=audit({stamp}.000:135): arch=c000003e syscall=257 success=no exit=-13 a0=ffffff9c a1=0 a2=0 a3=0 items=1 ppid=123 pid=567 auid=1000 uid=1000 gid=2000 euid=1001 suid=1000 fsuid=1002 egid=2001 sgid=2000 fsgid=2002 tty=(none) ses=77 comm=\"actor\" exe=\"/exited/actor\" key=\"sequester_canary\"\n"+
        $"type=CWD msg=audit({stamp}.000:135): cwd=\"/owned\"\n"+
        $"type=PATH msg=audit({stamp}.000:135): item=0 name=\"/owned/target\" inode=32 dev=08:02 mode=0100000 ouid=0 ogid=0 rdev=00:00 nametype=NORMAL\n"+
        $"type=PROCTITLE msg=audit({stamp}.000:135): proctitle=2F6578697465642F6163746F72002D2D72656164\n"+
        $"type=EOE msg=audit({stamp}.000:135):\n";
    AuditPacket Parse(string text,bool command=true)
    {
        var packets=new List<AuditPacket>();var errors=new List<string>();
        using var parser=new AuditParser(command,"owned-fixture-boot",packets.Add,errors.Add);
        parser.Feed(System.Text.Encoding.UTF8.GetBytes(text));parser.Flush();
        Check(errors.Count==0&&packets.Count==1,"actual libauparse produces one accepted record set");
        return packets[0];
    }
    var packet=Parse(sample);
    Check(packet.Attribution.FileSystemGroupId==2002&&packet.Attribution.GroupId==2000&&packet.Attribution.EffectiveGroupId==2001,"actual parser separates real/effective/filesystem GID");
    Check(packet.Attribution.ParentProcessId==123&&packet.Attribution.CommandLine=="/exited/actor --read","actual parser retains parent PID and proctitle");
    Check(packet.Attribution.CommandLineTruncated==false,"short kernel proctitle is below its byte limit");
    var capped=Parse(sample.Replace("2F6578697465642F6163746F72002D2D72656164",Convert.ToHexString(System.Text.Encoding.UTF8.GetBytes(new string('x',128)))));
    Check(capped.Attribution.CommandLineTruncated==true&&capped.Attribution.CommandLine!.Length==128,"kernel-capped proctitle is marked potentially truncated");
    Check(packet.Attribution.Outcome=="Failed"&&packet.Attribution.OsStatus=="-13"&&packet.Attribution.CompleteRecordSet,"actual failed-open result retained without claiming success");
    Check(Parse(sample.Replace(" fsgid=2002","")).Attribution.FileSystemGroupId==null,"legacy missing fsgid remains null");
    Check(Parse(sample.Replace("fsgid=2002","fsgid=4294967295")).Attribution.FileSystemGroupId==null,"unset fsgid sentinel remains null");
    var disabled=Parse(sample,false);Check(disabled.Attribution.CommandLine==null&&disabled.Attribution.CommandLineTruncated==null,"disabled command-line collection honored");
    foreach(var boundary in new[]{73,sample.IndexOf("type=CWD"),sample.IndexOf("type=PROCTITLE")})
    {
        var rows=new List<AuditPacket>();var failures=new List<string>();
        using var parser=new AuditParser(true,"owned-fragment-fixture",rows.Add,failures.Add);
        parser.Feed(System.Text.Encoding.UTF8.GetBytes(sample[..boundary]));
        Check(!parser.CanRotate,"maintenance cannot discard a partial input line or event set");
        parser.Feed(System.Text.Encoding.UTF8.GetBytes(sample[boundary..]));parser.Flush();
        Check(rows.Count==1&&failures.Count==0&&rows[0].Attribution.CompleteRecordSet&&rows[0].Attribution.FileSystemGroupId==2002,"fragmented record reassembles with full original credentials");
        Check(parser.CanRotate,"maintenance allowed after complete empty boundary");
    }
    {
        var rows=new List<AuditPacket>();var failures=new List<string>();
        using var parser=new AuditParser(true,"owned-shutdown-fixture",rows.Add,failures.Add);
        parser.Feed(System.Text.Encoding.UTF8.GetBytes(sample[..sample.IndexOf("type=PROCTITLE")]));
        Check(!parser.CanRotate,"pending syscall and target remain visible before graceful flush");
        parser.Flush();
        Check(rows.Count==1&&failures.Count==0&&rows[0].Pid==567&&rows[0].Executable=="/exited/actor"&&rows[0].Attribution.FileSystemGroupId==2002,"graceful flush salvages available actor and target evidence");
        Check(!rows[0].Attribution.CompleteRecordSet&&rows[0].Attribution.Level=="Partial attribution","graceful flush never invents missing terminal records");
    }
    {
        var parser=new AuditParser(true,"owned-disposal-fixture",_=>{},_=>{});
        parser.Dispose();parser.Dispose();
        var refused=false;try{parser.Feed([]);}catch(ObjectDisposedException){refused=true;}
        Check(refused,"disposed parser refuses native calls and tolerates repeated cleanup");
    }
    Console.WriteLine(System.Text.Json.JsonSerializer.Serialize(new{Passed=true,Checks=passed,Scope="Actual Linux libauparse metadata/denied-result parsing of owned fixture records; not live kernel denial capture."}));
    return;
}
var full=new AuditPacket("boot:audit:123",DateTimeOffset.UtcNow,42,"/usr/bin/cat","openat",new(){Provider="Linux Audit",Level="Full attribution",Basis="Kernel record",UserId=0,EffectiveUserId=0,FileSystemUserId=0,CompleteRecordSet=true,EventTimeCredentials=true},[new("/test/canary.txt","NORMAL")]);
Check(AuditPacketEvidence.Normalize(full)==full,"Complete native record preserved");
foreach(var missing in new[]{full with{Pid=null},full with{Pid=0},full with{Executable=""},full with{Executable=null!},full with{Attribution=full.Attribution with{UserId=null,EffectiveUserId=null,FileSystemUserId=null}}})
{var p=AuditPacketEvidence.Normalize(missing);Check(p.Identity==full.Identity&&p.Paths.SequenceEqual(full.Paths)&&p.Attribution.Level=="Partial attribution","Partial actor packet retained with original evidence identity");}
var none=AuditPacketEvidence.Normalize(full with{Pid=null,Executable="",Attribution=null!});
Check(none.Attribution.Level=="Detection only"&&none.Paths.Length==1,"All actor details missing remains a detection");
var fsuid=full.Attribution with{FileSystemUserId=65534};
Check(AuditPacketEvidence.User(fsuid)!.StartsWith("fsuid:65534;")&&AuditPacketEvidence.User(fsuid)!.Contains("uid:0"),"Filesystem identity is distinguished from real/effective identity");
Check(AuditPacketEvidence.User(none.Attribution)==null,"Missing identity stays null so presentation cannot treat a placeholder as a user");
foreach(var invalid in new[]{full with{Pid=-1},full with{Paths=[]},full with{Paths=[new("relative","NORMAL")]},full with{Executable=new string('a',1025)},full with{Identity="bad\nidentity"},full with{Attribution=full.Attribution with{Provider="Untrusted"}},full with{ObservedUtc=default}})
{var rejected=false;try{AuditPacketEvidence.Normalize(invalid);}catch(InvalidDataException){rejected=true;}Check(rejected,"Malformed packet is routed to retained quarantine");}
Console.WriteLine($"{passed} audit packet cases passed.");
namespace RansomFree.LinuxAgent{internal static class AuditDispatcher{internal const string Key="sequester_canary";}}
