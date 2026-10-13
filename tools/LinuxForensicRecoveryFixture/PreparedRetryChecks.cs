using System.Diagnostics;
using System.Text.Json;
using RansomFree.Client;
using RansomFree.Client.Forensics;
using RansomFree.Contracts;

internal static class PreparedRetryChecks
{
    internal static async Task Run(string root,string sensor,byte[] raw,AgentEvent observation,LinuxActorSnapshot snapshot,string seedPath)
    {
        if(Directory.Exists(root))throw new ArgumentException("Fresh root required");Directory.CreateDirectory(root);
        var checks=new List<string>();
        void Check(bool ok,string name){if(!ok)throw new Exception(name);checks.Add(name);}
        var direct=Path.Combine(root,"same-process");
        using(var journal=new LinuxForensicJournal(direct,sensor))
        {
            journal.CommitObservation(raw,observation,new());journal.CommitSnapshot(observation.EventId,snapshot);
            var spool=new EventSpool(Path.Combine(direct,"spool"),sensor);var errors=new List<string>();var evaluated=0;AgentEvent? input=null;
            await using(var pipeline=new ForensicPipeline(sensor,direct,errors.Add))
                Check(pipeline.TrySubmitPrepared(journal,observation.EventId,spool,checkpoint:point=>{if(point=="original-precommit")throw new IOException("Injected commit failure");},
                    prepareTrust:(value,_)=>{evaluated++;input=value;return null;}),"first attempt admitted");
            Check(evaluated==1&&input!=null&&errors.Count==1&&spool.Count==0&&journal.Read(observation.EventId).Original==null,"failed precommit exposes no original and evaluates once");
            var sourceInput=LinuxKernelTrustBinding.InputDigest(input!);errors.Clear();
            await using(var pipeline=new ForensicPipeline(sensor,direct,errors.Add))
                Check(pipeline.TrySubmitPrepared(journal,observation.EventId,spool,prepareTrust:(_,_)=>{evaluated++;throw new Exception("Policy refresh must not be consulted");}),"same-process retry admitted");
            var work=journal.Read(observation.EventId);var original=JsonSerializer.Deserialize<AgentEvent>(work.Original!)!;
            Check(evaluated==1&&errors.Count==0&&work.Done&&spool.Count==2,"retry uses frozen attempt without invoking new policy");
            Check(LinuxKernelTrustBinding.InputDigest(original)==sourceInput&&original.Forensics!.CollectorEpoch==input!.Forensics!.CollectorEpoch&&original.Forensics.CollectorSequence==input.Forensics.CollectorSequence&&original.Forensics.ProcessSequence==input.Forensics.ProcessSequence,"retry preserves all evidence and original Begin sequence");
            Check(original.Trust==null&&original.Forensics!.Detection.Disposition=="alert","unavailable trust never upgrades on retry");
            Check(journal.PrepareOriginal(observation.EventId,_=>throw new Exception("Committed original must not be recreated")).AsSpan().SequenceEqual(work.Original),"committed original ignores later factory entirely");
        }
        foreach(var cut in new[]{"original-precommit","original-prepared","original-spooled"})
        {
            var directory=Path.Combine(root,cut);var start=new ProcessStartInfo(Environment.ProcessPath!){UseShellExecute=false,RedirectStandardOutput=true,RedirectStandardError=true};
            if(string.Equals(Path.GetFileNameWithoutExtension(Environment.ProcessPath),"dotnet",StringComparison.OrdinalIgnoreCase))start.ArgumentList.Add(typeof(PreparedRetryChecks).Assembly.Location);
            foreach(var argument in new[]{"child",seedPath,directory,cut})start.ArgumentList.Add(argument);
            using(var child=Process.Start(start)!)
            {
                var stdout=child.StandardOutput.ReadToEndAsync();var stderr=child.StandardError.ReadToEndAsync();await FixtureProcessTiming.Wait(child);
                File.WriteAllText(Path.Combine(root,cut+".log"),await stdout+await stderr);Check(child.ExitCode==73,"actual child exit at "+cut);
            }
            using var journal=new LinuxForensicJournal(directory,sensor);var before=journal.Read(observation.EventId);
            Check((before.Original==null)==(cut=="original-precommit"),"durable boundary at "+cut);
            var spool=new EventSpool(Path.Combine(directory,"spool"),sensor);var errors=new List<string>();
            // Stopped recovery deliberately supplies no live-source callback.
            await using(var pipeline=new ForensicPipeline(sensor,directory,errors.Add))Check(pipeline.TrySubmitPrepared(journal,observation.EventId,spool),"stopped recovery admitted: "+cut);
            var after=journal.Read(observation.EventId);var original=JsonSerializer.Deserialize<AgentEvent>(after.Original!)!;
            Check(errors.Count==0&&after.Done&&spool.Count==2,"one original/completion pair recovered: "+cut);
            Check(original.Trust==null&&original.Forensics!.Detection.Disposition=="alert","stopped recovery cannot create whitelist authority: "+cut);
            Check(before.Original==null||before.Original.AsSpan().SequenceEqual(after.Original),"committed decision bytes never replaced: "+cut);
        }
        File.WriteAllBytes(Path.Combine(root,"checks.json"),JsonSerializer.SerializeToUtf8Bytes(new{Passed=true,Checks=checks.Count,Details=checks}));
        Console.WriteLine(JsonSerializer.Serialize(new{Passed=true,Checks=checks.Count,Scope="Journal retry and real managed-process crash boundaries with archived native data; not a live native source or kernel authority test"}));
    }
}
