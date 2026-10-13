using System.ComponentModel;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Text.Json;
using RansomFree.Client;
using RansomFree.Client.Forensics;

internal static class NativeBridgeLinuxChecks
{
    [DllImport("libc",SetLastError=true)]private static extern uint geteuid();
    [DllImport("libc",SetLastError=true)]private static extern int chown(string path,uint uid,uint gid);
    internal static void Consume(string inbox,string destination,string sensor)
    {
        if(!OperatingSystem.IsLinux()||geteuid()!=65534)throw new InvalidOperationException("Actual unprivileged qualification child required");
        using var source=LinuxProtectedDirectory.OpenRoot(inbox,65534);var spool=new EventSpool(destination,sensor);var importer=new LinuxNativeBridgeImport(destination,sensor,spool);
        var receipts=new List<LinuxNativeBridgeImport.Receipt>();
        foreach(var name in source.Names(256).Order(StringComparer.Ordinal))
        {
            if(!name.EndsWith(".json",StringComparison.Ordinal)||name.Length!=37)throw new InvalidDataException("Unexpected root export entry");
            receipts.Add(importer.Import(source,name[..32]));
        }
        bool writeDenied=false,publishDenied=false;
        try{File.WriteAllText(Path.Combine(inbox,"forged.json"),"untrusted");}catch(UnauthorizedAccessException){writeDenied=true;}
        try{source.PublishNew("forged.json",[1]);}catch(UnauthorizedAccessException){publishDenied=true;}
        if(!writeDenied||!publishDenied)throw new Exception("Unprivileged child can forge root exports");
        File.WriteAllText(Path.Combine(destination,"CHILD.json"),JsonSerializer.Serialize(new{Passed=true,Uid=geteuid(),Events=spool.Count,Receipts=receipts,WriteDenied=writeDenied,PublishDenied=publishDenied}));
    }
    internal static async Task Run(string packetRoot,string root,bool socketAcknowledgments=false)
    {
        if(!OperatingSystem.IsLinux()||geteuid()!=0||Directory.Exists(root))throw new ArgumentException("Fresh root Linux bridge fixture required");
        Directory.CreateDirectory(root,UnixFileMode.UserRead|UnixFileMode.UserWrite|UnixFileMode.UserExecute|UnixFileMode.GroupRead|UnixFileMode.GroupExecute|UnixFileMode.OtherRead|UnixFileMode.OtherExecute);
        var checks=new List<string>();void Check(bool ok,string label){if(!ok)throw new Exception(label);checks.Add(label);}
        void Reject(Action action,string label){try{action();}catch(Exception e)when(e is IOException or InvalidDataException or Win32Exception or UnauthorizedAccessException){Check(true,label);return;}throw new Exception("Accepted: "+label);}
        var sensor="11111111111111111111111111111111";
        var packets=Enumerable.Range(0,5).Select(i=>LinuxNativeBridgePacket.Parse(File.ReadAllBytes(Path.Combine(packetRoot,"packet-"+i+".json")),sensor)).ToArray();
        void GroupDirectory(string path,uint uid,uint gid)
        {
            Directory.CreateDirectory(path,UnixFileMode.UserRead|UnixFileMode.UserWrite|UnixFileMode.UserExecute|UnixFileMode.GroupRead|UnixFileMode.GroupExecute);
            if(chown(path,uid,gid)!=0)throw new Win32Exception(Marshal.GetLastPInvokeError());
        }
        var inbox=Path.Combine(root,"inbox");GroupDirectory(inbox,0,65534);
        using(var directory=LinuxProtectedDirectory.OpenRoot(inbox,65534))
        {
            var exporter=new LinuxNativeBridgeExport(directory,sensor);
            foreach(var p in packets)
            {
                var sha=exporter.Publish(p);var file=directory.Read(p.SourceEventId+".json",LinuxNativeBridgePacket.MaximumBytes);
                Check(LinuxNativeBridgePacket.Hash(file.Bytes)==sha&&file.File.Uid==0&&file.File.Gid==65534&&(file.File.Mode&0xfff)==416,"root publishes exact group-readable, nonexecutable immutable packet");
                Check(exporter.Publish(p)==sha&&directory.Names(256).Count(n=>n==p.SourceEventId+".json")==1,"repeat publication confirms same bytes without overwrite");
            }
            var first=packets[0];Reject(()=>directory.PublishNew(first.SourceEventId+".json",[42]),"renameat2 publication refuses existing destination");
            // The failed low-level publication leaves one root-owned temporary.
            Check(directory.Read(first.SourceEventId+".json",LinuxNativeBridgePacket.MaximumBytes).Bytes.AsSpan().SequenceEqual(first.Encode(sensor)),"publication collision retains original packet bytes");
        }
        // Use a separate clean inbox for the real unprivileged consumer; the
        // collision above intentionally retained a temporary in its own case.
        var clean=Path.Combine(root,"consumer-inbox");GroupDirectory(clean,0,65534);
        using(var directory=LinuxProtectedDirectory.OpenRoot(clean,65534))foreach(var p in packets)new LinuxNativeBridgeExport(directory,sensor).Publish(p);
        var destination=Path.Combine(root,"consumer-state");GroupDirectory(destination,65534,65534);
        var start=new ProcessStartInfo("/usr/bin/setpriv"){UseShellExecute=false,RedirectStandardOutput=true,RedirectStandardError=true};
        foreach(var arg in new[]{"--reuid","65534","--regid","65534","--clear-groups","--",Environment.ProcessPath!,"native-bridge-consume",clean,destination,sensor})start.ArgumentList.Add(arg);
        using(var child=Process.Start(start)??throw new IOException("Unprivileged bridge child failed to start"))
        {
            var stdout=child.StandardOutput.ReadToEndAsync();var stderr=child.StandardError.ReadToEndAsync();await child.WaitForExitAsync().WaitAsync(TimeSpan.FromSeconds(90));
            File.WriteAllText(Path.Combine(root,"child.stdout.log"),await stdout);File.WriteAllText(Path.Combine(root,"child.stderr.log"),await stderr);
            Check(child.ExitCode==0,"actual uid/gid 65534 consumer completed");
        }
        using(var child=JsonDocument.Parse(File.ReadAllBytes(Path.Combine(destination,"CHILD.json"))))
        {
            var e=child.RootElement;Check(e.GetProperty("Passed").GetBoolean()&&e.GetProperty("Uid").GetUInt32()==65534&&e.GetProperty("Events").GetInt32()==10,"unprivileged worker imported ten immutable native events");
            Check(e.GetProperty("WriteDenied").GetBoolean()&&e.GetProperty("PublishDenied").GetBoolean(),"consumer could neither create nor publish root packets");
            Check(e.GetProperty("Receipts").GetArrayLength()==5,"five local durable import receipts recorded");
        }
        foreach(var cut in new[]{"bridge-export-written","bridge-export-renamed","bridge-export-committed"})
        {
            var dir=Path.Combine(root,cut);GroupDirectory(dir,0,65534);using var directory=LinuxProtectedDirectory.OpenRoot(dir,65534);var exporter=new LinuxNativeBridgeExport(directory,sensor);
            Reject(()=>exporter.Publish(packets[0],point=>{if(point==cut)throw new IOException("Injected export interruption");}),"export interruption propagates: "+cut);
            Check(exporter.Publish(packets[0])==LinuxNativeBridgePacket.Hash(packets[0].Encode(sensor)),"export retry confirms durable exact packet: "+cut);
        }
        var quota=Path.Combine(root,"quota");GroupDirectory(quota,0,65534);
        using(var directory=LinuxProtectedDirectory.OpenRoot(quota,65534))
        {
            for(var i=0;i<256;i++)directory.PublishNew("pending-"+i+".tmp",[1]);
            Reject(()=>new LinuxNativeBridgeExport(directory,sensor).Publish(packets[0]),"bounded export inventory refuses growth without deleting retained entries");
            Check(directory.Names(256).Length==256,"quota failure retains all existing root entries");
        }
        var sourceJournal=File.ReadAllBytes(Path.Combine(packetRoot,"native-source-journal.db"));
        Check(LinuxNativeBridgePacket.Hash(sourceJournal)=="BAA56990CE17874AA4A1D68F617979ACF8EC800BBE9B9B41F34C9C27F62C1888","exact accepted R37 native journal required for composed delivery");
        var ownerState=Path.Combine(root,"root-owner-state");Directory.CreateDirectory(Path.Combine(ownerState,"linux-forensic-intake"));File.WriteAllBytes(Path.Combine(ownerState,"linux-forensic-intake/journal.db"),sourceJournal);
        var actorRoot=Path.Combine(ownerState,"actors");Directory.CreateDirectory(actorRoot,UnixFileMode.UserRead|UnixFileMode.UserWrite|UnixFileMode.UserExecute);
        foreach(var p in packets)
        {
            var pair=p.Validate(sensor);if(pair.Actor==null)continue;var id=pair.Completion.Forensics!.Preservation.EvidenceId!;
            foreach(var entry in new[]{(id+".bin",pair.Actor),(id+".json",pair.Manifest!)})
            {File.WriteAllBytes(Path.Combine(actorRoot,entry.Item1),entry.Item2);File.SetUnixFileMode(Path.Combine(actorRoot,entry.Item1),UnixFileMode.UserRead|UnixFileMode.UserWrite);}
        }
        var journalInbox=Path.Combine(root,"journal-inbox");GroupDirectory(journalInbox,0,65534);
        using(var journal=new LinuxForensicJournal(ownerState,sensor))
        using(var directory=LinuxProtectedDirectory.OpenRoot(journalInbox,65534))
        using(var actors=LinuxProtectedDirectory.OpenRoot(actorRoot))
        {
            var exporter=new LinuxNativeBridgeExport(directory,sensor);var privateSpool=new EventSpool(Path.Combine(ownerState,"private-queue"),sensor);
            Check(journal.PendingNativeExports(128).Length==5,"all five committed native pairs await local bridge delivery");
            foreach(var p in packets)
            {
                var pair=p.Validate(sensor);privateSpool.EnqueueExact(pair.OriginalBytes);privateSpool.EnqueueExact(pair.CompletionBytes);
                Check(exporter.PublishCommitted(journal,p.SourceEventId,actors)==LinuxNativeBridgePacket.Hash(p.Encode(sensor)),"journal-backed export exactly matches accepted native pair");
            }
            Check(privateSpool.Count==10,"root delivery queue contains ten immutable source events");
            using var childProof=JsonDocument.Parse(File.ReadAllBytes(Path.Combine(destination,"CHILD.json")));
            var imported=childProof.RootElement.GetProperty("Receipts").Deserialize<LinuxNativeBridgeImport.Receipt[]>()!;
            var first=imported[0];
            var channel=Path.Combine(root,"delivery-channel");
            if(socketAcknowledgments)GroupDirectory(channel,0,65534);
            using var listener=socketAcknowledgments?new LinuxNativeBridgeSocket(channel,65534,65534,sensor,NativeBridgeSocketChecks.Origin):null;
            if(listener!=null)
            {
                using(var cancellation=new CancellationTokenSource())
                {
                    var pending=listener.AcceptAsync(exporter,journal,privateSpool,cancellation.Token);cancellation.Cancel();
                    try{await pending;throw new Exception("Idle acknowledgment did not cancel");}catch(OperationCanceledException){Check(true,"idle acknowledgment cancellation releases exchange slot");}
                }
                foreach(var mode in new[]{"oversize","empty","truncated","unknown","duplicate","wrong-sensor","wrong-server","wrong-hash","wrong-completion","unpublished"})
                {
                    await NativeBridgeSocketChecks.Exchange(listener,exporter,journal,privateSpool,channel,root,first,mode,Check);
                    Check(privateSpool.Count==10&&journal.PendingNativeExports(128).Length==5&&directory.Names(256).Length==5,"rejected IPC acknowledgment retains all delivery copies: "+mode);
                }
            }
            Reject(()=>exporter.AcknowledgeImport(journal,privateSpool,first with{SensorId=Guid.NewGuid().ToString("N")}),"cross-sensor receipt cannot retire delivery copies");
            Reject(()=>exporter.AcknowledgeImport(journal,privateSpool,first with{PacketSha256=new string('0',64)}),"wrong packet hash cannot retire delivery copies");
            Reject(()=>exporter.AcknowledgeImport(journal,privateSpool,first with{CompletionEventId=Guid.NewGuid().ToString("N")}),"wrong completion receipt cannot retire delivery copies");
            var cuts=new[]{"bridge-import-ledger-committed","bridge-private-queue-retired","bridge-export-duplicate-retired","bridge-retirement-committed"};
            for(var i=0;i<imported.Length;i++)
            {
                var receipt=imported[i];
                if(i<cuts.Length)
                {
                    var cut=cuts[i];Reject(()=>exporter.AcknowledgeImport(journal,privateSpool,receipt,point=>{if(point==cut)throw new IOException("Injected acknowledgment interruption");}),"local acknowledgment interruption: "+cut);
                    Check(journal.PendingNativeImportRetirements().Any(x=>x==receipt)==(i<3),"committed unfinished retirement remains restart-recoverable: "+cut);
                }
                if(listener!=null)
                {
                    if(i==4)await NativeBridgeSocketChecks.Exchange(listener,exporter,journal,privateSpool,channel,root,receipt,"disconnect-after-send",Check);
                    await NativeBridgeSocketChecks.Exchange(listener,exporter,journal,privateSpool,channel,root,receipt,"valid",Check);
                    if(i==4)await NativeBridgeSocketChecks.Exchange(listener,exporter,journal,privateSpool,channel,root,receipt,"valid",Check);
                }
                else exporter.AcknowledgeImport(journal,privateSpool,receipt);
                Check(!privateSpool.Peek().Events.Any(x=>x.EventId==receipt.SourceEventId||x.EventId==receipt.CompletionEventId)&&!journal.PendingNativeExports(128).Contains(receipt.SourceEventId),"local acknowledgment retires only redundant delivery entries");
                var retained=journal.Read(receipt.SourceEventId);var packet=packets.Single(x=>x.SourceEventId==receipt.SourceEventId).Validate(sensor);
                Check(retained.Original!.AsSpan().SequenceEqual(packet.OriginalBytes)&&retained.Completion!.AsSpan().SequenceEqual(packet.CompletionBytes),"canonical forensic journal bytes remain after acknowledgment");
            }
            Check(privateSpool.Count==0&&journal.PendingNativeImportRetirements().Length==0&&directory.Names(256).Length==0,"all local delivery copies retired with empty pending recovery ledger");
            // A root export pass may hold an inventory read before the
            // independent listener committed these receipts. Replaying that
            // stale list, including with a new exporter, must not recreate it.
            foreach(var receipt in imported)
            {
                Check(exporter.PublishCommitted(journal,receipt.SourceEventId,actors)==receipt.PacketSha256,"stale export inventory honors committed import receipt");
                Check(new LinuxNativeBridgeExport(directory,sensor).PublishCommitted(journal,receipt.SourceEventId,actors)==receipt.PacketSha256&&directory.Names(256).Length==0&&privateSpool.Count==0,"fresh exporter cannot recreate retired duplicate");
            }
            foreach(var p in packets)
            {
                var pair=p.Validate(sensor);if(pair.Actor==null)continue;var id=pair.Completion.Forensics!.Preservation.EvidenceId!;
                Check(actors.Read(id+".bin",4*1024*1024).Bytes.AsSpan().SequenceEqual(pair.Actor)&&actors.Read(id+".json",65536).Bytes.AsSpan().SequenceEqual(pair.Manifest),"root actor evidence and manifest remain byte-identical after retirement");
            }
            if(listener!=null)
            {
                var pending=listener.AcceptAsync(exporter,journal,privateSpool,CancellationToken.None);listener.Dispose();
                try{await pending;throw new Exception("Disposed delivery listener did not cancel");}catch(Exception e)when(e is OperationCanceledException or ObjectDisposedException or System.Net.Sockets.SocketException){Check(true,"delivery listener shutdown cancels pending exchange");}
                using var parent=LinuxProtectedDirectory.OpenRoot(channel,65534);Check(!parent.Names(256).Contains(LinuxNativeBridgeSocket.Name),"delivery shutdown retires exact owned socket node");
                await NativeBridgeSocketChecks.Drain(exporter,journal,privateSpool,channel,root,imported[^1],Check);
            }
        }
        File.WriteAllText(Path.Combine(root,"RESULTS.json"),JsonSerializer.Serialize(new{Passed=true,Checks=checks.Count,Details=checks,Root=root,Scope="Actual Linux root publication, unprivileged immutable import, protected permissions, durable rename/retry and bounded inventory; no installed service/native activation"}));
        Console.WriteLine(JsonSerializer.Serialize(new{Passed=true,Checks=checks.Count,Root=root}));
    }
}
