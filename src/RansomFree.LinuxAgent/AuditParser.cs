using System.Globalization;
using System.Runtime.InteropServices;
using RansomFree.Contracts;

namespace RansomFree.LinuxAgent;

// Uses the distribution's upstream libauparse, not a fork or a regex audit parser.
// ABI: linux-audit/audit-userspace auparse.h and auparse-defs.h, LP64 x64/ARM64.
internal sealed class AuditParser:IDisposable
{
    const string Library="libauparse.so.0";
    [UnmanagedFunctionPointer(CallingConvention.Cdecl)] delegate void Callback(nint parser,int reason,nint data);
    [DllImport(Library)] static extern nint auparse_init(int source,nint data);
    [DllImport(Library)] static extern void auparse_destroy(nint parser);
    [DllImport(Library)] static extern void auparse_add_callback(nint parser,Callback callback,nint data,nint destroy);
    [DllImport(Library)] static extern int auparse_feed(nint parser,byte[] bytes,nuint length);
    [DllImport(Library)] static extern void auparse_feed_age_events(nint parser);
    [DllImport(Library)] static extern int auparse_flush_feed(nint parser);
    [DllImport(Library)] static extern int auparse_feed_has_data(nint parser);
    [DllImport(Library)] static extern int auparse_first_record(nint parser);
    [DllImport(Library)] static extern int auparse_next_record(nint parser);
    [DllImport(Library)] static extern int auparse_get_type(nint parser);
    [DllImport(Library)] static extern uint auparse_get_num_records(nint parser);
    [DllImport(Library)] static extern int auparse_first_field(nint parser);
    [DllImport(Library)] static extern int auparse_next_field(nint parser);
    [DllImport(Library)] static extern nint auparse_get_field_name(nint parser);
    [DllImport(Library)] static extern nint auparse_get_field_str(nint parser);
    [DllImport(Library)] static extern nint auparse_interpret_field(nint parser);
    [DllImport(Library)] static extern void auparse_set_escape_mode(nint parser,int mode);
    [DllImport(Library)] static extern long auparse_get_time(nint parser);
    [DllImport(Library)] static extern uint auparse_get_milli(nint parser);
    [DllImport(Library)] static extern ulong auparse_get_serial(nint parser);
    [DllImport(Library)] static extern nint auparse_get_node(nint parser);
    [DllImport("libc")] static extern void free(nint pointer);
    readonly nint parser;
    readonly Callback callback;
    readonly Action<AuditPacket> emit;
    readonly Action<string> error;
    readonly bool commandLine;
    readonly string boot;
    bool partialLine;
    bool disposed;
    public bool HadCollectionError {get;private set;}
    public AuditParser(bool commandLine,string boot,Action<AuditPacket> emit,Action<string> error)
    {
        this.emit=emit;this.error=error;this.commandLine=commandLine;this.boot=boot;
        parser=auparse_init(7,0);if(parser==0)throw new IOException("libauparse initialization failed.");
        callback=Ready;auparse_set_escape_mode(parser,0);auparse_add_callback(parser,callback,0,0);
    }
    public void Feed(byte[] bytes){ObjectDisposedException.ThrowIf(disposed,this);if(auparse_feed(parser,bytes,(nuint)bytes.Length)<0)throw new IOException("Audit parser feed failed.");if(bytes.Length>0)partialLine=bytes[^1]!=(byte)'\n';}
    public void Age(){ObjectDisposedException.ThrowIf(disposed,this);auparse_feed_age_events(parser);}
    public void Flush(){ObjectDisposedException.ThrowIf(disposed,this);if(auparse_flush_feed(parser)<0)throw new IOException("Audit parser flush failed.");}
    // Native pending-event state does not include an unfinished input line.
    public bool CanRotate {get{ObjectDisposedException.ThrowIf(disposed,this);return !partialLine&&auparse_feed_has_data(parser)==0;}}
    static string Text(nint p,int max=4096)
    {
        if(p==0)return "";
        var length=0;while(length<=max&&Marshal.ReadByte(p,length)!=0)length++;
        if(length>max)throw new InvalidDataException("Oversized audit field.");
        return Marshal.PtrToStringUTF8(p,length)??"";
    }
    static string Clean(string value,int max)=>new(value.Select(c=>char.IsControl(c)?' ':c).Take(max).ToArray());
    static uint? Id(string? value)=>uint.TryParse(value,NumberStyles.None,CultureInfo.InvariantCulture,out var n)&&n!=uint.MaxValue?n:null;
    static int? Pid(string? value)=>int.TryParse(value,NumberStyles.None,CultureInfo.InvariantCulture,out var n)&&n>0?n:null;
    void Ready(nint p,int reason,nint data)
    {
        try
        {
            if(reason!=0||auparse_get_num_records(p)>128)throw new InvalidDataException("Audit record set exceeds limit.");
            var syscall=new Dictionary<string,string>();var interpreted=new Dictionary<string,string>();
            var paths=new List<(string Name,string Role,string? Identity)>();string cwd="",title="";int syscalls=0;bool terminal=false;bool? titleTruncated=null;
            if(auparse_first_record(p)<=0)return;
            do
            {
                // Upstream libauparse completes on PROCTITLE or EOE and discards
                // a later standalone EOE. EOE alone would downgrade normal sets.
                var type=auparse_get_type(p);if(type is 1320 or 1327)terminal=true;
                if(type is not (1300 or 1302 or 1307 or 1327))continue;
                var fields=new Dictionary<string,string>();var resolved=new Dictionary<string,string>();
                if(auparse_first_field(p)>0)do
                {
                    var name=Text(auparse_get_field_name(p),128);
                    if(!new[]{"key","pid","ppid","uid","euid","fsuid","gid","egid","fsgid","auid","ses","exe","comm","arch","syscall","success","exit","items","name","nametype","inode","dev","cwd","proctitle"}.Contains(name))continue;
                    if(name=="proctitle"&&!commandLine)continue;
                    fields[name]=Text(auparse_get_field_str(p),8192);
                    if(name is "key" or "exe" or "comm" or "syscall" or "name" or "cwd" or "proctitle")resolved[name]=Text(auparse_interpret_field(p),8192);
                }while(auparse_next_field(p)>0);
                if(type==1300){syscalls++;syscall=fields;interpreted=resolved;}
                if(type==1302&&resolved.TryGetValue("name",out var path))paths.Add((path,fields.GetValueOrDefault("nametype", "Unknown"),fields.TryGetValue("dev",out var device)&&fields.TryGetValue("inode",out var inode)?"linux-audit:"+Clean(device,32)+":"+Clean(inode,32):null));
                if(type==1307)cwd=resolved.GetValueOrDefault("cwd","");
                if(type==1327&&commandLine)
                {
                    title=resolved.GetValueOrDefault("proctitle","");
                    var rawTitle=fields.GetValueOrDefault("proctitle","");
                    // The Linux kernel caps PROCTITLE at 128 bytes, before
                    // libauparse replaces NUL argument separators with spaces.
                    var rawBytes=rawTitle.Length>0&&rawTitle.Length%2==0&&rawTitle.All(Uri.IsHexDigit)
                        ?rawTitle.Length/2:System.Text.Encoding.UTF8.GetByteCount(title);
                    titleTruncated=rawBytes>=128;
                }
            }while(auparse_next_record(p)>0);
            // Do not collect other customers' audit rules or forwarded remote-host records.
            if(interpreted.GetValueOrDefault("key")!=AuditDispatcher.Key)return;
            if(syscalls!=1)throw new InvalidDataException("Ambiguous monitored audit syscall set; raw evidence must be retained.");
            var nodePointer=auparse_get_node(p);string node;
            try{node=Text(nodePointer,256);}finally{if(nodePointer!=0)free(nodePointer);}
            if(node.Length>0&&!node.Equals(Environment.MachineName,StringComparison.OrdinalIgnoreCase))throw new InvalidDataException("Non-local/custom audit node is not supported; attribution refused.");
            var stamp=DateTimeOffset.FromUnixTimeSeconds(auparse_get_time(p)).AddMilliseconds(auparse_get_milli(p));
            if(stamp>DateTimeOffset.UtcNow.AddMinutes(5))throw new InvalidDataException("Audit timestamp is in the future.");
            var id=$"{boot}:{auparse_get_time(p)}.{auparse_get_milli(p):D3}:{auparse_get_serial(p)}";
            var pid=Pid(syscall.GetValueOrDefault("pid"));var uid=Id(syscall.GetValueOrDefault("uid"));var euid=Id(syscall.GetValueOrDefault("euid"));
            var exe=Clean(interpreted.GetValueOrDefault("exe",""),1024);
            var complete=terminal&&int.TryParse(syscall.GetValueOrDefault("items"),out var count)&&count==paths.Count;
            var operation=Clean(interpreted.GetValueOrDefault("syscall",syscall.GetValueOrDefault("syscall","unknown")),64);
            var evidence=new EventAttribution{Provider="Linux Audit",Level=complete&&pid!=null&&uid!=null&&euid!=null&&exe.Length>0?"Full attribution":"Partial attribution",
                Basis="Kernel audit record identity; account IDs at event time. Historical PID is not a response handle. Full refers to core actor fields, not all possible telemetry.",
                EvidenceId=id,Syscall=Clean(syscall.GetValueOrDefault("arch","")+":"+operation,100),Outcome=syscall.GetValueOrDefault("success")=="yes"?"Success":syscall.GetValueOrDefault("success")=="no"?"Failed":"Unknown",
                UserId=uid,EffectiveUserId=euid,FileSystemUserId=Id(syscall.GetValueOrDefault("fsuid")),GroupId=Id(syscall.GetValueOrDefault("gid")),EffectiveGroupId=Id(syscall.GetValueOrDefault("egid")),FileSystemGroupId=Id(syscall.GetValueOrDefault("fsgid")),LoginUserId=Id(syscall.GetValueOrDefault("auid")),SessionId=Id(syscall.GetValueOrDefault("ses")),OsStatus=Clean(syscall.GetValueOrDefault("exit",""),64),
                ParentProcessId=Pid(syscall.GetValueOrDefault("ppid")),ProcessName=Clean(interpreted.GetValueOrDefault("comm",""),256),CommandLine=commandLine?Clean(title,2048):null,CommandLineTruncated=titleTruncated,
                EventTimeCredentials=true,CompleteRecordSet=complete};
            var observations=new List<AuditPath>();
            foreach(var (name,role,identity) in paths.Distinct())
            {
                if(role=="PARENT"||string.IsNullOrWhiteSpace(name)||name.Any(char.IsControl))continue;
                var absolute=name.StartsWith('/')?name:cwd.StartsWith('/')?Path.Combine(cwd,name):null;
                if(absolute==null)continue;absolute=Path.GetFullPath(absolute);
                if(absolute.Length>2048)continue;
                observations.Add(new(absolute,Clean(role,32)){StableId=identity});
            }
            if(operation is "rename" or "renameat" or "renameat2")
            {
                var from=observations.Where(x=>x.Role=="DELETE").ToArray();var to=observations.Where(x=>x.Role=="CREATE").ToArray();
                if(from.Length==1&&to.Length==1)evidence=evidence with{RenameSource=from[0].Path,RenameDestination=to[0].Path};
            }
            if(operation is "read" or "pread64" or "readv" or "preadv" or "preadv2" or "write" or "pwrite64" or "writev" or "pwritev" or "pwritev2"&&evidence.Outcome=="Success"&&long.TryParse(evidence.OsStatus,out var transferred)&&transferred>=0)evidence=evidence with{BytesTransferred=transferred};
            // A targeted SYSCALL can arrive before PATH/PROCTITLE when a relay
            // restarts. Keep its real actor/security fields; do not silently
            // discard it just because the target record has not arrived.
            if(observations.Count==0)evidence=evidence with{Level="Partial attribution",CompleteRecordSet=false,PathRole="UNAVAILABLE",Basis=evidence.Basis+" Target path unavailable; raw evidence retained for audit-log recovery."};
            emit(new(id,stamp,pid,exe,operation,evidence,observations.ToArray()));
        }
        catch(Exception ex){HadCollectionError=true;error("Audit record rejected: "+ex.GetType().Name);} // Never unwind across native callback.
    }
    public void Dispose(){if(disposed)return;disposed=true;auparse_destroy(parser);GC.KeepAlive(callback);}
}
internal sealed record AuditPath(string Path,string Role)
{
    [System.Text.Json.Serialization.JsonIgnore(Condition=System.Text.Json.Serialization.JsonIgnoreCondition.WhenWritingNull)]
    public string? StableId {get;init;}
}
internal sealed record AuditPacket(string Identity,DateTimeOffset ObservedUtc,int? Pid,string Executable,string Operation,EventAttribution Attribution,AuditPath[] Paths);
