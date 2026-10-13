using System.Text;

namespace RansomFree.LinuxAgent;

// Recovery is limited to an exact kernel timestamp/serial already observed
// through the authenticated relay. The upstream parser still interprets every
// field; this reader only selects the matching raw lines from auditd's log.
internal static class AuditLogRecovery
{
    const int Window=8*1024*1024,MaximumRecordBytes=262144,MaximumLine=32768;
    internal static byte[]? Read(AuditPacket expected)
    {
        var parts=expected.Identity.Split(':');
        if(parts.Length!=3||!Guid.TryParseExact(parts[0],"D",out _)||!decimal.TryParse(parts[1],System.Globalization.NumberStyles.AllowDecimalPoint,System.Globalization.CultureInfo.InvariantCulture,out var stamp)||stamp<0||!ulong.TryParse(parts[2],System.Globalization.NumberStyles.None,System.Globalization.CultureInfo.InvariantCulture,out _))
            throw new InvalidDataException("Invalid observed audit recovery identity.");
        var marker=Encoding.UTF8.GetBytes("msg=audit("+parts[1]+":"+parts[2]+"):" );
        const string configuration="/etc/audit/auditd.conf";
        Native.ValidateAdminPath(configuration,false);
        using var config=Native.FileAt(configuration,false,65536,true);
        if(config.Length>65536)throw new IOException("Audit configuration exceeds recovery limit.");
        using var reader=new StreamReader(config,Encoding.UTF8,false,4096,true);
        string? log=null,line;
        while((line=reader.ReadLine())!=null)
        {
            var text=line.Trim();if(text.StartsWith('#')||text.Length==0)continue;
            var split=text.IndexOf('=');if(split<0||text[..split].Trim()!="log_file")continue;
            if(log!=null)throw new InvalidDataException("Duplicate audit log path.");
            log=text[(split+1)..].Trim();
        }
        if(string.IsNullOrWhiteSpace(log)||!Path.IsPathFullyQualified(log)||log.Any(char.IsControl)||log.Length>2048)
            throw new InvalidDataException("Configured local audit log required for recovery.");
        using var result=new MemoryStream();
        // A record can straddle rotation. Inspect current and two immediate
        // predecessors, each through a no-symlink descriptor, bounded to its tail.
        foreach(var path in new[]{log+".2",log+".1",log})
        {
            if(!File.Exists(path))continue;
            Native.ValidateAdminPath(path,false);
            using var file=Native.FileAt(path,false,long.MaxValue,true);
            var end=file.Length;var start=Math.Max(0,end-Window);file.Position=start;
            var data=new byte[checked((int)Math.Min(Window,end-start))];var total=0;
            while(total<data.Length){var n=file.Read(data,total,data.Length-total);if(n==0)break;total+=n;}
            var offset=0;
            if(start>0){var first=Array.IndexOf(data,(byte)'\n',0,total);if(first<0)continue;offset=first+1;}
            while(offset<total)
            {
                var newline=Array.IndexOf(data,(byte)'\n',offset,total-offset);
                if(newline<0)break; // Never invent completion of a partial log line.
                var length=newline-offset;
                if(length<=MaximumLine)
                {
                    if(new ReadOnlySpan<byte>(data,offset,length).IndexOf(marker)>=0)
                    {
                        if(result.Length+length+1>MaximumRecordBytes)throw new IOException("Matching audit recovery record exceeds limit.");
                        result.Write(data,offset,length+1);
                    }
                }
                offset=newline+1;
            }
        }
        return result.Length==0?null:result.ToArray();
    }
    internal static AuditPacket? Parse(byte[] bytes,AuditPacket expected,bool commandLine,string boot)
    {
        AuditPacket? found=null;bool invalid=false;
        using var parser=new AuditParser(commandLine,boot,p=>
        {
            if(p.Identity!=expected.Identity)return;
            if(found!=null||!p.Attribution.CompleteRecordSet||p.Paths.Length==0||p.Pid!=expected.Pid||p.Executable!=expected.Executable
                ||p.Operation!=expected.Operation||p.Attribution.UserId!=expected.Attribution.UserId
                ||p.Attribution.EffectiveUserId!=expected.Attribution.EffectiveUserId||p.Attribution.FileSystemUserId!=expected.Attribution.FileSystemUserId
                ||p.Attribution.GroupId!=expected.Attribution.GroupId||p.Attribution.EffectiveGroupId!=expected.Attribution.EffectiveGroupId
                ||p.Attribution.FileSystemGroupId!=expected.Attribution.FileSystemGroupId||p.Attribution.ParentProcessId!=expected.Attribution.ParentProcessId
                ||p.Attribution.LoginUserId!=expected.Attribution.LoginUserId||p.Attribution.SessionId!=expected.Attribution.SessionId
                ||p.Attribution.Syscall!=expected.Attribution.Syscall||p.Attribution.ProcessName!=expected.Attribution.ProcessName
                ||p.Attribution.Outcome!=expected.Attribution.Outcome||p.Attribution.OsStatus!=expected.Attribution.OsStatus){invalid=true;return;}
            found=p;
        },_=>invalid=true);
        parser.Feed(bytes);parser.Flush();
        if(invalid)throw new InvalidDataException("Audit log recovery identity or record completeness mismatch.");
        return found;
    }
}
