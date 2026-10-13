using System.Text.Json;
using RansomFree.Client;
using RansomFree.Client.Forensics;
using RansomFree.Contracts;

static class IoWorkCapacityChecks
{
    internal static void Run(string root,string sensor,string collector,byte[] raw)
    {
        if(Directory.Exists(root))throw new ArgumentException("Fresh capacity fixture required");
        Directory.CreateDirectory(root);int checks=0;
        void Check(bool valid,string message){if(!valid)throw new InvalidDataException(message);checks++;Console.WriteLine("PASS: "+message);}
        foreach(var limit in new[]{4,16})
        {
            var directory=Path.Combine(root,"limit-"+limit);
            using(var journal=new LinuxForensicJournal(directory,sensor,pendingWorkLimit:limit))
            {
                for(int i=0;i<limit;i++)journal.CommitObservation(raw,
                    LinuxKernelDecoder.Decode(raw,sensor,collector,i+1,DateTimeOffset.UtcNow),new());
                Check(journal.Pending().Length==limit,"exact durable capacity admitted: "+limit);
                try{journal.CommitObservation(raw,LinuxKernelDecoder.Decode(raw,sensor,collector,limit+1,DateTimeOffset.UtcNow),new());throw new InvalidDataException("Capacity overflow admitted");}
                catch(IOException){Check(journal.Pending().Length==limit,"overflow retains every existing work item: "+limit);}
            }
            using(var reopened=new LinuxForensicJournal(directory,sensor))
                Check(reopened.Pending().Length==limit,"restart preserves backlog without eviction: "+limit);
        }
        foreach(var limit in new[]{0,5,17})
        {
            try{using var rejected=new LinuxForensicJournal(Path.Combine(root,"invalid-"+limit),sensor,pendingWorkLimit:limit);throw new InvalidDataException("Unqualified capacity admitted");}
            catch(ArgumentException){Check(true,"unqualified capacity rejected: "+limit);}
        }
        var result=new{Passed=true,Checks=checks,Scope="Actual durable journal admission/restart bounds. Native acquisition remains separately limited to four claims."};
        File.WriteAllText(Path.Combine(root,"RESULTS.json"),JsonSerializer.Serialize(result));Console.WriteLine(JsonSerializer.Serialize(result));
    }
}
