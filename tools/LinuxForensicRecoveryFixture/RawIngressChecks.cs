using System.Diagnostics;
using System.Security.Cryptography;
using System.Text.Json;
using RansomFree.Client.Forensics;

static class RawIngressChecks
{
    internal static void Child(string root,string sensor,string collector,string cut)
    {
        var barrier=new LinuxSourceWorkBarrier();
        using var reserve=new LinuxRawIngressReserve(root,sensor,collector,"123",5,true,(stage,index)=>
        {if(stage==cut.Split(':')[0]&&index==int.Parse(cut.Split(':')[1]))Environment.Exit(73);});
        for(int i=0;i<6;i++)reserve.Commit(new byte[]{255,0,(byte)i},barrier.Current,DateTimeOffset.UtcNow);
        throw new Exception("Ingress cut was not reached");
    }
    internal static async Task DiskPressure(string root,string sensor,string collector)
    {
        if(!OperatingSystem.IsLinux()||Directory.Exists(root)||!root.StartsWith("/var/tmp/sequester-linux-ingress-",StringComparison.Ordinal))throw new ArgumentException("Fresh owned Linux qualification root required");
        var barrier=new LinuxSourceWorkBarrier();
        using(var bank=new LinuxRawIngressReserve(root,sensor,collector,"123",5))
        {
            Console.WriteLine(JsonSerializer.Serialize(new{Ready=true,bank.PhysicalAllocationEstablished}));
            if(await Console.In.ReadLineAsync()!="commit")throw new InvalidDataException("Owned ENOSPC handshake failed");
            for(int i=0;i<5;i++)if(!bank.Commit(new byte[]{255,0,(byte)i},barrier.Current,DateTimeOffset.UtcNow).Committed)throw new Exception("Preallocated raw ingress slot failed under pressure");
            if(bank.Commit("overflow"u8.ToArray(),barrier.Current,DateTimeOffset.UtcNow).Committed||bank.FirstBoundary?.Reason!="RAW_BACKLOG_EXHAUSTED")throw new Exception("No durable overflow boundary under pressure");
        }
        using var reopened=new LinuxRawIngressReserve(root,sensor,collector,"123",5);
        Console.WriteLine(JsonSerializer.Serialize(new{Passed=reopened.Entries.Length==5&&reopened.FirstBoundary!=null,Count=reopened.Entries.Length,Boundary=reopened.FirstBoundary,NoTypedAuthority=true}));
    }
    internal static async Task Run(string root,string sensor,string collector,string seedPath,byte[] native)
    {
        if(Directory.Exists(root))throw new ArgumentException("New isolated ingress fixture root required");Directory.CreateDirectory(root);int checks=0;
        void Check(bool ok,string label){if(!ok)throw new Exception(label);checks++;Console.WriteLine("PASS: "+label);}
        void Reject(Action action,string label){try{action();}catch(Exception ex)when(ex is IOException or InvalidDataException or InvalidOperationException or ArgumentException){Check(true,label);return;}throw new Exception("Unexpected ingress acceptance: "+label);}
        var barrier=new LinuxSourceWorkBarrier();var dir=Path.Combine(root,"mixed");LinuxRawIngressReserve.Entry[] entries;
        byte[][] frames=[native,[255,0,128],"{not valid JSON}"u8.ToArray(),new byte[65536],[]];
        LinuxRawIngressReserve.Boundary first;
        using(var bank=new LinuxRawIngressReserve(dir,sensor,collector,"123",5,true))
        {
            Check(bank.PhysicalAllocationEstablished==OperatingSystem.IsLinux()&&!bank.Reopened,"physical Linux allocation is distinct from Windows layout replay");
            for(int i=0;i<2;i++)Check(bank.Commit(frames[i],barrier.Current,DateTimeOffset.UtcNow).Committed,"raw-first frame accepts exact bytes without decoding: "+i);
            barrier.Fault("LOADER_LOST_COUNTER_INCREASED",DateTimeOffset.UtcNow);
            var receipt=bank.RecordBoundary("LOADER_LOST_COUNTER_INCREASED",barrier.Current,null,"owned-native-error");first=receipt.Boundary;
            Check(receipt.NewlyCommitted&&first.LastDurableSequence==2&&first.LastDurableDeliveryId==bank.Entries[1].DeliveryId,"fixed emergency boundary retains exact durable prefix");
            for(int i=2;i<frames.Length;i++)Check(bank.Commit(frames[i],barrier.Current,DateTimeOffset.UtcNow).Committed,"residual raw remains durable after fault: "+i);
            entries=bank.Entries;
            Check(entries.Take(2).All(x=>x.View.State=="Active")&&entries.Skip(2).All(x=>x.View.State=="Faulted"),"ingress records retain their actual control generation view");
            for(int i=0;i<frames.Length;i++)Check(bank.ReadRaw(entries[i]).SequenceEqual(frames[i]),"exact raw bytes read without normalization: "+i);
            Check(!bank.Commit(native,barrier.Current,DateTimeOffset.UtcNow).Committed&&bank.FirstBoundary==first,"full bank refuses data and preserves first boundary");
            Check(!bank.RecordBoundary("SECOND_ERROR",barrier.Current,2,null).NewlyCommitted&&bank.FirstBoundary==first,"additional reason is explicitly not claimed as newly persisted");
            Reject(()=>bank.ReadRaw(entries[0] with{DeliveryId=Guid.NewGuid().ToString("N")}),"foreign entry cannot address retained raw by a guessed sequence");
            Check(bank.ReadRaw(entries[0]).SequenceEqual(native),"foreign-entry rejection does not damage committed evidence");
            Reject(()=>new LinuxRawIngressReserve(dir,sensor,collector,"123",5,true),"raw ingress has one writer owner");
        }
        using(var reopened=new LinuxRawIngressReserve(dir,sensor,collector,"123",5,true))
        {
            Check(reopened.Reopened&&reopened.Entries.SequenceEqual(entries)&&reopened.FirstBoundary==first,"reopen retains exact entries/boundary without asserting prior caller acknowledgment");
            for(int i=0;i<frames.Length;i++)Check(reopened.ReadRaw(entries[i]).SequenceEqual(frames[i]),"recovered bytes exact: "+i);
        }
        foreach(var variant in new[]{"sensor","collector","epoch","capacity"})
            Reject(()=>new LinuxRawIngressReserve(dir,variant=="sensor"?Guid.NewGuid().ToString("N"):sensor,variant=="collector"?Guid.NewGuid().ToString("N"):collector,variant=="epoch"?"124":"123",variant=="capacity"?6:5,true),"changed header binding refused: "+variant);
        var clean=new LinuxSourceWorkBarrier();
        using(var bank=new LinuxRawIngressReserve(Path.Combine(root,"bounds"),sensor,collector,"123",5,true))
        {
            Reject(()=>bank.Commit(new byte[65537],clean.Current,DateTimeOffset.UtcNow),"oversized frame rejected before raw allocation");
            Reject(()=>bank.Commit(Array.Empty<byte>(),clean.Current,default),"missing receipt timestamp refused");
            Reject(()=>bank.Commit(Array.Empty<byte>(),clean.Current with{State="Closed"},DateTimeOffset.UtcNow),"closed source view cannot append new raw data");
            Check(bank.Entries.Length==0,"invalid admission did not consume reserved capacity");
            var one=bank.Commit(new byte[]{1},clean.Current,DateTimeOffset.UtcNow).Entry!;var two=bank.Commit(new byte[]{1},clean.Current,DateTimeOffset.UtcNow).Entry!;
            Check(one.DeliveryId!=two.DeliveryId&&one.Sequence+1==two.Sequence,"repeated pipe delivery has separate ingress identity; semantic dedup belongs downstream");
        }
        foreach(var point in new[]{"ingress-intent-committed:0","ingress-frame-committed:0","ingress-intent-committed:5","ingress-frame-committed:5"})
        {
            var childRoot=Path.Combine(root,point.Replace(':','-'));var start=new ProcessStartInfo(Environment.ProcessPath!){UseShellExecute=false,RedirectStandardOutput=true,RedirectStandardError=true};
            if(Path.GetFileNameWithoutExtension(Environment.ProcessPath)=="dotnet")start.ArgumentList.Add(typeof(RawIngressChecks).Assembly.Location);
            foreach(var arg in new[]{"ingress-child",seedPath,childRoot,point})start.ArgumentList.Add(arg);
            using var child=Process.Start(start)!;var stdout=child.StandardOutput.ReadToEndAsync();var stderr=child.StandardError.ReadToEndAsync();await FixtureProcessTiming.Wait(child);
            Check(child.ExitCode==73,"actual process interruption: "+point+" "+await stdout+await stderr);
            if(point.StartsWith("ingress-intent",StringComparison.Ordinal))
                Reject(()=>new LinuxRawIngressReserve(childRoot,sensor,collector,"123",5,true),"intent without frame is unknown coverage, never an unused slot: "+point);
            else
            {
                using var recovered=new LinuxRawIngressReserve(childRoot,sensor,collector,"123",5,true);
                Check(recovered.Reopened&&recovered.Entries.Length==(point.EndsWith(":5",StringComparison.Ordinal)?5:1),"complete frame survives process exit without inventing caller acknowledgment: "+point);
                if(point.EndsWith(":5",StringComparison.Ordinal))Check(recovered.FirstBoundary?.Reason=="RAW_BACKLOG_EXHAUSTED","preallocated overflow frame survives actual crash");
            }
        }
        var corrupt=Path.Combine(root,"corrupt");
        using(var bank=new LinuxRawIngressReserve(corrupt,sensor,collector,"123",5,true))bank.Commit(native,clean.Current,DateTimeOffset.UtcNow);
        var path=Path.Combine(corrupt,"raw-ingress-v3.bin");
        using(var f=new FileStream(path,FileMode.Open,FileAccess.ReadWrite)){f.Position=4096+6*128+60;int value=f.ReadByte();f.Position--;f.WriteByte((byte)(value^1));f.Flush(true);}
        var hash=Convert.ToHexString(SHA256.HashData(File.ReadAllBytes(path)));
        Reject(()=>new LinuxRawIngressReserve(corrupt,sensor,collector,"123",5,true),"corrupt raw frame fails closed before reinterpretation");
        Check(Convert.ToHexString(SHA256.HashData(File.ReadAllBytes(path)))==hash,"corrupt evidence bytes are retained unchanged");
        using(var bank=new LinuxRawIngressReserve(Path.Combine(root,"io-failure"),sensor,collector,"123",5,true,(stage,_)=>{if(stage=="ingress-intent-committed")throw new IOException("owned write failure");}))
        {
            Reject(()=>bank.Commit(native,clean.Current,DateTimeOffset.UtcNow),"failed write is not acknowledged as raw persistence");
            Reject(()=>bank.Commit(native,clean.Current,DateTimeOffset.UtcNow),"uncertain I/O permanently stops writes on that bank instance");
            Check(bank.Entries.Length==0,"failed write creates no in-memory success receipt");
        }
        var result=new{Passed=true,Checks=checks,Version=3,Scope="Exact undecoded raw ingress, bounded emergency and actual child interruptions; no typed source event, native authority or deployment"};
        File.WriteAllText(Path.Combine(root,"RESULTS.json"),JsonSerializer.Serialize(result));Console.WriteLine(JsonSerializer.Serialize(result));
    }
}
