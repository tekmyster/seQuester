using System.Buffers.Binary;
using System.Collections.Concurrent;
using System.Runtime.InteropServices;
using System.Text;

namespace RansomFree.LinuxAgent;

internal sealed record Observation(string Path,string Operation,string Source,int? Pid=null,int PidFd=-1,string? Executable=null,string? User=null)
{public DateTime ObservedUtc{get;init;}=DateTime.UtcNow;public string? EventId {get;init;} public RansomFree.Contracts.EventAttribution? Attribution {get;init;} public RansomFree.Contracts.ForensicEvidence? Forensics {get;init;}}
internal sealed class LinuxMonitors:IDisposable
{
    private readonly int notify,fan;
    private readonly ConcurrentDictionary<int,(string Path,bool Directory)> watches=new();
    private readonly HashSet<string> attached=new(StringComparer.Ordinal);
    private HashSet<string> tracked=new(StringComparer.Ordinal);
    private readonly Action<Observation> publish;
    private readonly CancellationTokenSource stop=new();
    private readonly Task reader;
    public bool IsRunning=>!stop.IsCancellationRequested&&!reader.IsCompleted;
    public string Mode=>fan>=0?"File activity: fanotify PIDFD + inotify names":"File activity: inotify; actor evidence supplied separately by Linux Audit when enabled";
    public LinuxMonitors(string mode,Action<Observation> publish)
    {
        this.publish=publish;
        notify=Native.Check(Native.inotify_init1(0x80000|0x800));fan=-1;
        try{if(mode=="fanotify")fan=Native.Check(Native.fanotify_init(1|2|0x80,0x80000));}
        catch{Native.close(notify);throw;}
        reader=Task.Run(ReadLoop);
    }
    public void Update(IEnumerable<Canary> canaries)
    {
        var items=canaries.Where(x=>x.Active).ToArray();Volatile.Write(ref tracked,items.Select(x=>x.Path).ToHashSet(StringComparer.Ordinal));
        lock(attached)
        {
            foreach(var item in items)
            {
                var folder=Path.GetDirectoryName(item.Path)!;
                if(attached.Add(folder+"/"))
                {
                    var wd=Native.inotify_add_watch(notify,Paths.NoLinks(folder),0x40|0x80|0x100|0x200|0x400|0x800|0x01000000|0x02000000);
                    if(wd<0){attached.Remove(folder+"/");throw new IOException("Cannot watch approved parent directory.");}watches[wd]=(folder,true);
                }
                if(!File.Exists(item.Path)||!attached.Add(item.Path))continue;
                var mask=0x4u|0x400u|0x800u|0x02000000u;if(fan<0)mask|=1|2|8|0x20;
                var fileWd=Native.inotify_add_watch(notify,Paths.NoLinks(item.Path),mask);
                if(fileWd<0){attached.Remove(item.Path);throw new IOException("Cannot watch canary inode.");}watches[fileWd]=(item.Path,false);
                if(fan>=0&&Native.fanotify_mark(fan,1|4,1|2|8|0x20,-100,item.Path)!=0){attached.Remove(item.Path);throw new IOException("Cannot attach fanotify canary mark.");}
            }
        }
    }
    private async Task ReadLoop()
    {
        var bytes=new byte[65536];
        try
        {
            while(!stop.IsCancellationRequested)
            {
                var n=Native.read(notify,bytes,(nuint)bytes.Length);if(n>0)ReadInotify(bytes,(int)n);else CheckRead(n);
                if(fan>=0){n=Native.read(fan,bytes,(nuint)bytes.Length);if(n>0)ReadFanotify(bytes,(int)n);else CheckRead(n);}
                await Task.Delay(50,stop.Token);
            }
        }
        catch(OperationCanceledException) when(stop.IsCancellationRequested){}
        catch(Exception ex){publish(new("Agent monitor","Monitoring stopped: "+ex.GetType().Name,"Linux monitor health"));}
    }
    private static void CheckRead(nint result){if(result<0&&Marshal.GetLastPInvokeError() is not (4 or 11))throw new IOException("Native monitor read failed.");}
    private void ReadInotify(byte[] bytes,int size)
    {
        for(var offset=0;offset<size;)
        {
            if(size-offset<16)throw new InvalidDataException("Truncated inotify event.");
            var wd=BitConverter.ToInt32(bytes,offset);var mask=BitConverter.ToUInt32(bytes,offset+4);var length=BitConverter.ToUInt32(bytes,offset+12);
            if(length>size-offset-16)throw new InvalidDataException("Invalid inotify name length.");
            if((mask&0x4000)!=0)publish(new("Agent monitor","Kernel event queue overflow; evidence may be missing","Linux monitor health"));
            if(watches.TryGetValue(wd,out var watch))
            {
                if((mask&0x2000)!=0||(watch.Directory&&(mask&(0x400|0x800|0x8000))!=0))publish(new(watch.Path,"Watch target unavailable; monitor coverage reduced","Linux monitor health"));
                var path=watch.Path;
                if(watch.Directory&&length>0){var name=Encoding.UTF8.GetString(bytes,offset+16,(int)length).TrimEnd('\0');path=Path.Combine(path,name);}
                if(Volatile.Read(ref tracked).Contains(path))
                {
                    var operation=(mask&(0x200|0x400))!=0?"Canary deleted":(mask&(0x40|0x800))!=0?"Canary moved/renamed":(mask&(0x80|0x100))!=0?"Canary path created/replaced":(mask&0x4)!=0?"Canary metadata changed":(mask&(2|8))!=0?"Canary modified (encryption possible)":(mask&1)!=0?"Content read (copy possible)":(mask&0x20)!=0?"File opened":null;
                    if(operation!=null)publish(new(path,operation,"Linux inotify"));
                }
                if((mask&0x8000)!=0){watches.TryRemove(wd,out _);lock(attached)attached.Remove(watch.Path+(watch.Directory?"/":""));}
            }
            offset+=16+(int)length;
        }
    }
    private void ReadFanotify(byte[] bytes,int size)
    {
        for(var offset=0;offset<size;)
        {
            if(size-offset<24)throw new InvalidDataException("Truncated fanotify metadata.");
            var length=BitConverter.ToUInt32(bytes,offset);var meta=BitConverter.ToUInt16(bytes,offset+6);
            if(bytes[offset+4]!=3||length<24||length>size-offset||meta<24||meta>length)throw new InvalidDataException("Unsupported fanotify metadata.");
            var mask=BitConverter.ToUInt64(bytes,offset+8);var fd=BitConverter.ToInt32(bytes,offset+16);var pid=BitConverter.ToInt32(bytes,offset+20);var pidfd=-1;
            try
            {
                for(var info=offset+meta;info<offset+length;)
                {
                    if(offset+length-info<4)throw new InvalidDataException("Truncated fanotify info.");var infoLength=BitConverter.ToUInt16(bytes,info+2);
                    if(infoLength<4||infoLength>offset+length-info)throw new InvalidDataException("Invalid fanotify info length.");
                    if(bytes[info]==4&&infoLength>=8){if(pidfd>=0)Native.close(pidfd);pidfd=BitConverter.ToInt32(bytes,info+4);}info+=infoLength;
                }
                if((mask&0x4000)!=0)publish(new("Agent monitor","Kernel fanotify overflow; evidence may be missing","Linux monitor health"));
                if(fd>=0&&pid!=Environment.ProcessId)
                {
                    var path=Native.Link("/proc/self/fd/"+fd);
                    if(path!=null&&Volatile.Read(ref tracked).Contains(path))
                    {
                        var operation=(mask&(2|8))!=0?"Canary modified (encryption possible)":(mask&1)!=0?"Content read (copy possible)":"File opened";
                        publish(new(path,operation,"Linux fanotify",pid>0?pid:null,pidfd));pidfd=-1;
                    }
                }
            }
            finally{if(fd>=0)Native.close(fd);if(pidfd>=0)Native.close(pidfd);}
            offset+=(int)length;
        }
    }
    private int disposed;
    public void Dispose(){if(Interlocked.Exchange(ref disposed,1)!=0)return;stop.Cancel();try{reader.GetAwaiter().GetResult();}catch(OperationCanceledException){}Native.close(notify);if(fan>=0)Native.close(fan);stop.Dispose();}
}
