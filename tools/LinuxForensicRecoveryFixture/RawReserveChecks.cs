using System.Security.Cryptography;
using System.Diagnostics;
using System.Text.Json;
using System.Text.Json.Nodes;
using RansomFree.Client;
using RansomFree.Client.Forensics;
using RansomFree.Contracts;

static class RawReserveChecks
{
    internal static async Task Run(string root,string sensor,string collector,byte[] raw,DateTimeOffset time,string seedPath,Action<bool,string> check)
    {
        void Reject(Action action,string label){try{action();}catch(Exception ex)when(ex is IOException or InvalidDataException or InvalidOperationException or ArgumentException){check(true,label);return;}throw new Exception("Expected rejection: "+label);}
        var directory=Path.Combine(root,"raw-backlog");var reserveRoot=Path.Combine(directory,"linux-raw-reserve");
        var events=Enumerable.Range(1,7).Select(n=>LinuxKernelDecoder.Decode(raw,sensor,collector,n,time)).ToArray();
        using(var reserve=new LinuxRawIntakeReserve(reserveRoot,sensor,5))
        using(var journal=new LinuxForensicJournal(directory,sensor))
        {
            check(reserve.PhysicalAllocationEstablished==OperatingSystem.IsLinux(),"raw reserve distinguishes Linux fallocate admission from Windows layout replay");
            for(int i=0;i<5;i++)check(reserve.Commit(raw,events[i],new()),"raw event commits independently of four-work capacity: "+i);
            for(int i=0;i<4;i++)journal.CommitObservation(raw,events[i],new());
            Reject(()=>journal.CommitObservation(raw,events[4],new()),"four active journal jobs cannot discard the separately committed fifth raw event");
            check(reserve.Records.Count==5&&journal.Pending().Length==4,"five durable raw records coexist with four active work rows");
            check(reserve.Commit(raw,events[0],new())&&reserve.Records.Count==5,"duplicate raw delivery is exact and consumes no new slot");
            Reject(()=>reserve.Commit(raw,events[0],new(false)),"conflicting policy cannot replace a reserved raw record");
            check(!reserve.Commit(raw,events[5],new())&&reserve.Overflow is {Reason:"RAW_BACKLOG_EXHAUSTED",OpenEnded:true},"overflow uses preallocated emergency slot with an open unknown range");
            var emergency=JsonSerializer.Serialize(reserve.Overflow);
            check(!reserve.Commit(raw,events[6],new())&&JsonSerializer.Serialize(reserve.Overflow)==emergency,"subsequent overflow cannot erase first unknown boundary");
            check(reserve.Overflow!.LastDurableEventId==events[4].EventId&&reserve.Overflow.FirstUncommittedEventId==events[5].EventId,"last durable and first uncommitted observations remain distinct");
            Reject(()=>new LinuxRawIntakeReserve(reserveRoot,sensor,5),"raw reserve has one writer owner");
            var spool=new EventSpool(Path.Combine(directory,"spool"),sensor);var errors=new List<string>();
            foreach(var e in events.Take(4))journal.CommitUnavailable(e.EventId,"fixture-native-acquisition-not-attempted");
            await using(var pipeline=new ForensicPipeline(sensor,directory,errors.Add))
                foreach(var e in events.Take(4))check(pipeline.TrySubmitPrepared(journal,e.EventId,spool),"previous raw row admitted to existing prepared worker: "+e.EventId);
            journal.CommitObservation(raw,events[4],new());
            check(errors.Count==0&&journal.Pending().SequenceEqual([events[4].EventId])&&spool.Count==8,"fifth raw event indexes after previous four finish without changing the raw record");
        }
        using(var reopened=new LinuxRawIntakeReserve(reserveRoot,sensor,5))
            check(reopened.Records.Count==5&&reopened.Overflow?.FirstUncommittedEventId==events[5].EventId&&reopened.Records.All(x=>Convert.FromBase64String(x.RawBase64).AsSpan().SequenceEqual(raw)),"raw backlog and emergency range survive owner restart with exact native bytes");
        Reject(()=>new LinuxRawIntakeReserve(reserveRoot,Guid.NewGuid().ToString("N"),5),"different sensor cannot reopen another raw reserve");
        Reject(()=>new LinuxRawIntakeReserve(reserveRoot,sensor,6),"changed capacity cannot reinterpret an existing raw reserve");
        var corruptRoot=Path.Combine(root,"corrupt-raw-reserve");
        using(var r=new LinuxRawIntakeReserve(corruptRoot,sensor,5))r.Commit(raw,events[0],new());
        var path=Path.Combine(corruptRoot,"raw-reserve-v2.bin");
        using(var f=new FileStream(path,FileMode.Open,FileAccess.ReadWrite)){f.Position=4096+6*256+60;var b=f.ReadByte();f.Position--;f.WriteByte((byte)(b^1));f.Flush(true);}
        var digest=Convert.ToHexString(SHA256.HashData(File.ReadAllBytes(path)));
        Reject(()=>new LinuxRawIntakeReserve(corruptRoot,sensor,5),"torn or corrupt raw slot produces explicit unknown coverage instead of fabricated input");
        check(Convert.ToHexString(SHA256.HashData(File.ReadAllBytes(path)))==digest,"corrupt raw reserve retained without overwrite or repair guess");
        foreach(var cut in new[]{0,5})
        {
            var cutRoot=Path.Combine(root,"raw-intent-cut-"+cut);var start=new ProcessStartInfo(Environment.ProcessPath!){UseShellExecute=false,RedirectStandardError=true,RedirectStandardOutput=true};
            if(string.Equals(Path.GetFileNameWithoutExtension(Environment.ProcessPath),"dotnet",StringComparison.OrdinalIgnoreCase))start.ArgumentList.Add(typeof(RawReserveChecks).Assembly.Location);
            foreach(var arg in new[]{"raw-cut",seedPath,cutRoot,cut.ToString()})start.ArgumentList.Add(arg);
            using var child=Process.Start(start)!;var errors=child.StandardError.ReadToEndAsync();var output=child.StandardOutput.ReadToEndAsync();
            await FixtureProcessTiming.Wait(child);
            File.WriteAllText(Path.Combine(root,"raw-intent-cut-"+cut+".log"),await output+await errors);
            check(child.ExitCode==73,"actual child exit after durable "+(cut==0?"raw":"emergency")+" intent before frame write");
            try{using var r=new LinuxRawIntakeReserve(cutRoot,sensor,5);throw new Exception("Interrupted intent appeared unused");}
            catch(InvalidDataException ex){check(ex.Message.Contains("RAW_RESERVE_INTERRUPTED_UNKNOWN",StringComparison.Ordinal),"durable intent plus all-zero data is explicit unknown coverage: "+cut);}
        }
        var failedRoot=Path.Combine(root,"raw-failed-write");
        using(var reserve=new LinuxRawIntakeReserve(failedRoot,sensor,5,(stage,_)=>{if(stage=="intent-committed")throw new IOException("owned injected write failure");}))
        {
            Reject(()=>reserve.Commit(raw,events[0],new()),"injected post-intent I/O failure does not acknowledge the raw frame");
            try{reserve.Commit(raw,events[1],new());throw new Exception("Failed reserve admitted new data");}
            catch(IOException ex){check(ex.Message.Contains("RAW_RESERVE_IO_FAILED_UNVERIFIED",StringComparison.Ordinal),"I/O failure permanently stops this reserve instance's admission");}
        }
        Reject(()=>new LinuxRawIntakeReserve(failedRoot,sensor,5),"interrupted failed-write intent remains visible after owner disposal");
        // Constructed maximum raw input and two maximum native paths, not a
        // claim that the archived actor actually ran from these paths.
        var node=JsonNode.Parse(raw)!.AsObject();var longPath="/"+new string('a',4094);
        foreach(var role in new[]{"actor","target"}){node[role+"Path"]=longPath;node[role+"PathResult"]=4096;node[role+"PathBytesBase64"]=Convert.ToBase64String(System.Text.Encoding.UTF8.GetBytes(longPath));}
        var expanded=System.Text.Encoding.UTF8.GetBytes(node.ToJsonString());var maximum=new byte[65536];Array.Fill(maximum,(byte)' ');expanded.CopyTo(maximum,0);
        var maximumEvent=LinuxKernelDecoder.Decode(maximum,sensor,collector,100,time);var maximumRoot=Path.Combine(root,"raw-maximum-envelope");
        using(var reserve=new LinuxRawIntakeReserve(maximumRoot,sensor,5))
            check(reserve.Commit(maximum,maximumEvent,new()),"maximum 64-KiB native input and two full paths fit formally bounded binary envelope");
        using(var reserve=new LinuxRawIntakeReserve(maximumRoot,sensor,5))
            check(reserve.Records.Count==1&&Convert.FromBase64String(reserve.Records[0].RawBase64).AsSpan().SequenceEqual(maximum)&&reserve.PreviousCommitAcknowledgmentsUnknown,"maximum raw bytes recover exactly without claiming prior caller received commit acknowledgment");
        check(LinuxRawIntakeReserve.MaximumEnvelopeBytes==94224&&LinuxRawIntakeReserve.MaximumEnvelopeBytes<131072-48,"binary envelope proof includes separate raw, typed observation and policy maxima");
    }
}
