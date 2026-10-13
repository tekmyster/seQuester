using System.Runtime.InteropServices;
using System.Text;
using System.Text.Json;
using System.Threading.Channels;

namespace RansomFree.LinuxAgent;

internal static class AuditDispatcher
{
    public const string Root="/var/lib/sequester-audit",Key="sequester_canary";
    public static IEnumerable<string> Files()=>Directory.EnumerateFiles(Root,"*.json").Where(p=>Path.GetFileName(p).Length==25&&Path.GetFileName(p)[..20].All(char.IsAsciiDigit));
    public static T Read<T>(string path)
    {
        return JsonSerializer.Deserialize<T>(ReadBytes(path),PrivateState.Json)??throw new InvalidDataException("Invalid audit packet.");
    }
    public static byte[] ReadBytes(string path)
    {
        Native.ValidateAdminPath(path,false);
        using var file=Native.FileAt(path,false);if(file.Length>262144)throw new IOException("Audit packet exceeds limit.");
        var bytes=new byte[checked((int)file.Length)];file.ReadExactly(bytes);return bytes;
    }
    static void Write<T>(string name,T value,bool replace=true)
    {
        var temp=Root+"/"+Guid.NewGuid().ToString("N")+".tmp";
        using(var file=new FileStream(temp,new FileStreamOptions{Mode=FileMode.CreateNew,Access=FileAccess.Write,Share=FileShare.None,UnixCreateMode=UnixFileMode.UserRead|UnixFileMode.UserWrite|UnixFileMode.GroupRead}))
        {JsonSerializer.Serialize(file,value,PrivateState.Json);file.Flush(true);}
        File.Move(temp,Root+"/"+name,replace);
    }
    public static Task Run(bool socketMode=false)=>Task.Factory.StartNew(()=>RunCore(socketMode),CancellationToken.None,TaskCreationOptions.LongRunning,TaskScheduler.Default);
    static void RunCore(bool socketMode)
    {
        if(!Native.Root)throw new UnauthorizedAccessException("Audit collector requires its separate root service.");
        Native.ValidateAdminPath(Root,true);
        var configuration=Read<ClientConfiguration>(Platform.ConfigPath);configuration.Audit.Validate();
        if(!configuration.Audit.Enabled)throw new InvalidOperationException("Audit ingestion is disabled in client configuration.");
        using var lease=new FileStream(Root+"/dispatcher.lock",new FileStreamOptions{Mode=FileMode.OpenOrCreate,Access=FileAccess.ReadWrite,Share=FileShare.None,UnixCreateMode=UnixFileMode.UserRead|UnixFileMode.UserWrite});
        var identity=Root+"/identity.json";
        if(!File.Exists(identity))Write("identity.json",Guid.NewGuid().ToString("N"),false);
        var epoch=Read<string>(identity);if(!Guid.TryParseExact(epoch,"N",out _))throw new InvalidDataException("Invalid audit inbox identity.");
        var files=new SortedDictionary<long,(string Path,long Bytes)>();long total=0;
        foreach(var file in Files().Take(16386)){Native.ValidateAdminPath(file,false);var size=new FileInfo(file).Length;files.Add(long.Parse(Path.GetFileName(file)[..20]),(file,size));total+=size;}
        if(files.Count>16384)throw new IOException("Audit inbox inventory exceeds limit; retained for recovery.");
        var old=File.Exists(Root+"/status.json")?Read<AuditBridgeStatus>(Root+"/status.json"):null;
        long sequence=Math.Max(old?.LastSequence??0,files.Count==0?0:files.Keys.Last()),dropped=old?.DroppedInputRecords??0,rejected=old?.RejectedRecords??0,retired=old?.RetiredPackets??0;
        var boot=File.ReadAllText("/proc/sys/kernel/random/boot_id").Trim();if(!Guid.TryParse(boot,out _))throw new InvalidDataException("Linux boot identity unavailable.");
        var instance=Guid.NewGuid().ToString("N");var startTicks=AuditHealth.StartTicks(Environment.ProcessId);long heartbeat=0;
        AuditTransport? transport=null;long inputBytes=0;DateTimeOffset? lastInput=null;long replayLossReported=old?.ReplayLossReported??0;bool parserError=false;
        var incomplete=new Dictionary<string,(AuditPacket Packet,DateTimeOffset Due,int Attempts)>(StringComparer.Ordinal);long recovered=old?.RecoveredAuditRecords??0;
        var nextLogRecovery=DateTimeOffset.MinValue;
        void SyncReplayLoss()
        {
            if(transport==null)return;
            var current=transport.ReplayLossTotal;
            if(current<replayLossReported)throw new InvalidDataException("Durable relay loss total regressed.");
            dropped=checked(dropped+current-replayLossReported);replayLossReported=current;
        }
        void Report(string message,bool running)
        {
            SyncReplayLoss();
            var snapshot=new AuditBridgeStatus(epoch,DateTimeOffset.UtcNow,sequence,files.Count==0?sequence+1:files.Keys.First(),dropped,rejected,retired,message)
        {DispatcherPid=Environment.ProcessId,DispatcherStartTicks=startTicks,BootId=boot,InstanceId=instance,HeartbeatSequence=++heartbeat,Running=running,
            Transport=socketMode?"Native AOT relay":"Diagnostic stdin",RelayPid=transport?.Peer?.Pid??0,RelayStartTicks=transport?.Peer?.StartTicks,TransportConnected=transport?.Peer!=null,InputBytes=inputBytes,LastInputUtc=lastInput,LastRelayFrameUtc=transport?.LastFrameUtc,TransportFailureCount=transport?.FailureCount??0,LastTransportFailure=transport?.LastFailure,
            ReplayLossReported=replayLossReported,ReplayPendingFrames=transport?.ReplayPendingCount??0,ReplayPendingBytes=transport?.ReplayPendingBytes??0,RelayQueue=transport?.LastRelayQueueStatus,PendingIncompleteAuditRecords=incomplete.Count,RecoveredAuditRecords=recovered};
            // Do not require the restricted rfclient to inspect root /proc exe
            // links or grant it ptrace/root. The root writer performs the same
            // strict live identity/relay/rule checks as --audit-health.
            var failure=AuditHealth.Failure(snapshot,fromCollector:true)??(parserError?"Audit parser collection failed; raw replay evidence retained, retirement blocked":incomplete.Count>0?"Incomplete monitored audit record; actor metadata delivered, raw retained for exact log recovery":snapshot.RelayQueue is {UnreportedLostChunks:>0} relayQueue&&relayQueue.Peer==transport?.Peer&&snapshot.UpdatedUtc-relayQueue.ReceivedUtc<TimeSpan.FromSeconds(10)?"Audit relay input loss pending; durable loss notes retained":null);
            Write("status.json",snapshot with{CollectorHealth=new(1,snapshot.UpdatedUtc,failure)});
        }
        Report("Starting dispatcher; native parser initialization pending",false);
        var queue=Channel.CreateBounded<AuditInput>(new BoundedChannelOptions(2048){SingleReader=true,SingleWriter=true,FullMode=BoundedChannelFullMode.Wait});
        using var stop=new CancellationTokenSource();
        using var term=PosixSignalRegistration.Create(PosixSignal.SIGTERM,c=>{c.Cancel=true;stop.Cancel();});
        // auditd forwards HUP. Exit cleanly on TERM; HUP does not reload partial configuration.
        using var hup=PosixSignalRegistration.Create(PosixSignal.SIGHUP,c=>c.Cancel=true);
        using var receiver=socketMode?new AuditTransport():null;transport=receiver;
        var status="Starting; audit rule coverage not verified";
        var input=receiver!=null?Task.Run(()=>receiver.Read(queue.Writer,stop.Token)):Task.Run(async()=>
        {
            try
            {
                using var reader=new StreamReader(Console.OpenStandardInput(),Encoding.UTF8,false,4096,true);
                var chars=new char[4096];var line=new StringBuilder();bool oversized=false;
                while(!stop.IsCancellationRequested)
                {
                    var n=await reader.ReadAsync(chars.AsMemory(),stop.Token);if(n==0)break;
                    for(var i=0;i<n;i++)
                    {
                        var ch=chars[i];
                        if(ch=='\n')
                        {
                            if(!oversized){line.Append('\n');if(!queue.Writer.TryWrite(new(Encoding.UTF8.GetBytes(line.ToString()))))Interlocked.Increment(ref dropped);}
                            line.Clear();oversized=false;
                        }
                        else if(!oversized){if(line.Length>=32768){oversized=true;line.Clear();Interlocked.Increment(ref dropped);}else line.Append(ch);}
                    }
                }
                if(line.Length>0||oversized)Interlocked.Increment(ref dropped);
            }
            catch(OperationCanceledException) when(stop.IsCancellationRequested){}
            catch{Interlocked.Increment(ref dropped);}
            finally{queue.Writer.TryComplete();}
        });
        var names=LocalAccountNames.Read();
        void Emit(AuditPacket packet)
        {
            var recoveryFull=packet.Paths.Length==0&&!incomplete.ContainsKey(packet.Identity)&&incomplete.Count>=64;
            if(packet.Paths.Length==0&&!recoveryFull)incomplete.TryAdd(packet.Identity,(packet,DateTimeOffset.UtcNow,0));
            string? Name(uint? id)=>id is {} value?names.GetValueOrDefault(value):null;
            var a=packet.Attribution;
            packet=packet with{Attribution=a with{UserName=Name(a.UserId),EffectiveUserName=Name(a.EffectiveUserId),LoginUserName=Name(a.LoginUserId),AccountNameSource="Best-effort /etc/passwd snapshot at dispatcher startup; IDs are authoritative. Directory-only accounts may remain numeric."}};
            var bytes=JsonSerializer.SerializeToUtf8Bytes(packet,PrivateState.Json).Length;
            if(bytes>262144)throw new IOException("Audit packet too large.");
            while(files.Count>=configuration.Audit.MaxInboxEvents||total+bytes>configuration.Audit.MaxInboxMiB*1048576L)
            {
                if(files.Count==0)throw new IOException("Audit packet exceeds configured inbox.");
                var first=files.First();Native.ValidateAdminPath(first.Value.Path,false);File.Delete(first.Value.Path);files.Remove(first.Key);total-=first.Value.Bytes;retired++;
            }
            var next=checked(sequence+1);var name=next.ToString("D20")+".json";Write(name,packet,false);sequence=next;
            files.Add(next,(Root+"/"+name,bytes));total+=bytes;
            if(recoveryFull)throw new IOException("Incomplete audit recovery inventory full; actor observation delivered, raw retained; collector restart required.");
        }
        bool lastInputWasReplay=false;long parsedReplayOrder=0;
        AuditParser Make()=>new(configuration.Audit.CaptureCommandLine,boot,Emit,e=>{parserError=true;rejected++;status=e;});
        var parser=Make();long lastDrop=dropped,bytesFed=0;var due=DateTimeOffset.MinValue;
        void Consume(AuditInput item)
        {
            if(item.Gap)
            {
                parser.Flush();parser.Dispose();parser=Make();bytesFed=0;
                Interlocked.Add(ref dropped,item.Dropped);lastDrop=dropped;rejected++;status="Relay input gap; recoverable partial evidence flushed before parser reset";
            }
            if(item.Bytes.Length>0){parser.Feed(item.Bytes);bytesFed+=item.Bytes.Length;inputBytes+=item.Bytes.Length;lastInput=DateTimeOffset.UtcNow;}
            if(item.ReplayOrder>0){parsedReplayOrder=item.ReplayOrder;lastInputWasReplay=true;}
            else if(item.Bytes.Length>0||item.Gap)lastInputWasReplay=false;
        }
        void RetireParsedReplay()
        {
            if(receiver==null||parsedReplayOrder==0||parserError||incomplete.Count>0||!parser.CanRotate)return;
            // Output packets and status precede raw retirement. An interrupted
            // checkpoint may replay stable event IDs; it cannot erase input.
            Report(status,transport?.Peer!=null);AuditTransport.FlushOutputDirectory();receiver.RetireReplayThrough(parsedReplayOrder);parsedReplayOrder=0;
        }
        try
        {
            while(!stop.IsCancellationRequested)
            {
                if(!socketMode&&dropped!=lastDrop)
                {
                    parser.Flush();
                    parser.Dispose();parser=Make();lastDrop=dropped;bytesFed=0;rejected++;status="Parser reset after input gap; recoverable partial evidence flushed";
                }
                else if(bytesFed>16*1024*1024&&parser.CanRotate)
                {
                    parser.Dispose();parser=Make();bytesFed=0;
                    status="Audit parser maintained at an empty event and input-line boundary";
                }
                for(int count=0;count<256&&queue.Reader.TryRead(out var item);count++)
                    Consume(item);
                parser.Age();
                // Never enter a second libauparse parser from a native callback.
                // Recovery runs only after the original feed/age/flush returned,
                // on the same collector OS thread as all interpretation work.
                // Bound recovery disk traffic globally, even during many incomplete events.
                foreach(var ticket in incomplete.Values.Where(x=>x.Due<=DateTimeOffset.UtcNow&&nextLogRecovery<=DateTimeOffset.UtcNow).Take(1).ToArray())
                {
                    nextLogRecovery=DateTimeOffset.UtcNow.AddSeconds(5);
                    var pending=ticket.Packet;bool resolved=false;
                    try
                    {
                        var raw=AuditLogRecovery.Read(pending);
                        var complete=raw==null?null:AuditLogRecovery.Parse(raw,pending,configuration.Audit.CaptureCommandLine,boot);
                        if(complete!=null){Emit(complete);incomplete.Remove(pending.Identity);recovered++;resolved=true;status="Incomplete relay record recovered from exact protected kernel audit log identity";}
                        else status="Incomplete kernel audit record; target unavailable event delivered, raw retained; exact log recovery pending";
                    }
                    catch(Exception e){status="Incomplete kernel audit record; raw retained; audit log recovery unavailable: "+e.GetType().Name;}
                    if(!resolved)incomplete[pending.Identity]=(pending,DateTimeOffset.UtcNow.AddSeconds(Math.Min(30,1<<Math.Min(5,ticket.Attempts))),Math.Min(5,ticket.Attempts+1));
                }
                RetireParsedReplay();
                if(DateTimeOffset.UtcNow>=due)
                {
                    due=DateTimeOffset.UtcNow.AddSeconds(5);
                    if(status.StartsWith("Starting"))status="Audit dispatcher active; rule coverage and kernel/auditd drops require administrator verification";
                    Report(status,!socketMode||transport?.Peer!=null);
                }
                if(queue.Reader.Completion.IsCompleted)
                {
                    if(socketMode&&!stop.IsCancellationRequested)throw new IOException("Audit transport stopped unexpectedly; collector must restart.");
                    if(!lastInputWasReplay)parser.Flush();break;
                }
                // libauparse 3.x has process-global interpretation state. Keep its
                // lifecycle, feeds, callbacks, aging and destruction on this one OS thread.
                stop.Token.WaitHandle.WaitOne(50);
            }
        }
        catch(OperationCanceledException) when(stop.IsCancellationRequested){}
        finally
        {
            stop.Cancel();string? shutdownDrainError=null;
            // Drain already-received input on this same parser OS thread.
            try
            {
                Exception? inputFailure=null;
                try{if(!input.Wait(TimeSpan.FromSeconds(2)))inputFailure=new IOException("Audit input did not return for graceful parser drain.");}
                catch(Exception ex){inputFailure=ex;}
                while(queue.Reader.TryRead(out var pending))Consume(pending);
                if(input.IsCompleted&&receiver!=null)
                    foreach(var pending in receiver.TakeShutdownTail())Consume(pending);
                // V2 partial record sets stay in durable raw storage for the
                // next parser instance; do not prematurely publish partial
                // evidence merely because the collector is restarting.
                if(!lastInputWasReplay)parser.Flush();
                RetireParsedReplay();
                if(inputFailure!=null)throw inputFailure;
            }
            catch(Exception ex){Interlocked.Increment(ref dropped);rejected++;shutdownDrainError="Audit shutdown drain failed: "+ex.GetType().Name;}
            finally{parser.Dispose();}
            try{Report("Dispatcher stopped; coverage unavailable"+(shutdownDrainError==null?"":"; "+shutdownDrainError),false);}catch{}
            // The bounded stdin task is cancelled; no external command or network operation is used.
            try{input.Wait(TimeSpan.FromSeconds(2));}catch{}
        }
    }
}
internal sealed record AuditBridgeStatus(string Epoch,DateTimeOffset UpdatedUtc,long LastSequence,long FirstSequence,long DroppedInputRecords,long RejectedRecords,long RetiredPackets,string Message)
{
    public AuditCollectorHealth? CollectorHealth {get;init;}
    public int DispatcherPid {get;init;}
    public string? DispatcherStartTicks {get;init;}
    public string? BootId {get;init;}
    public string? InstanceId {get;init;}
    public long HeartbeatSequence {get;init;}
    public bool Running {get;init;}
    public string? Transport {get;init;}
    public int RelayPid {get;init;}
    public string? RelayStartTicks {get;init;}
    public bool TransportConnected {get;init;}
    public long InputBytes {get;init;}
    public DateTimeOffset? LastInputUtc {get;init;}
    public DateTimeOffset? LastRelayFrameUtc {get;init;}
    public long TransportFailureCount {get;init;}
    public AuditTransportFailure? LastTransportFailure {get;init;}
    public long ReplayLossReported {get;init;}
    public int ReplayPendingFrames {get;init;}
    public long ReplayPendingBytes {get;init;}
    public AuditRelayQueueStatus? RelayQueue {get;init;}
    public int PendingIncompleteAuditRecords {get;init;}
    public long RecoveredAuditRecords {get;init;}
}
