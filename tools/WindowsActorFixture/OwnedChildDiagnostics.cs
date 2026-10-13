using System.Diagnostics;
using System.Text.Json;

internal static class OwnedChildDiagnostics
{
internal static void Save(Process child,int pid,long created,string report,Exception failure)
{
    var evidence=new Dictionary<string,object?>{{"Schema","sequester.owned-child-failure/v1"},{"RecordedUtc",DateTimeOffset.UtcNow},{"Pid",pid},{"Created",created},{"OriginalFailure",failure.ToString()},{"BeforeOwnedChildTermination",true},{"ReadyMarkerExists",File.Exists(report+".ready.json")}};
    try
    {
        child.Refresh();evidence["Exited"]=child.HasExited;
        if(child.HasExited)evidence["ExitCode"]=child.ExitCode;
        else
        {
            evidence["TotalProcessorTimeMs"]=child.TotalProcessorTime.TotalMilliseconds;evidence["WorkingSetBytes"]=child.WorkingSet64;
            var threads=new List<object>();
            foreach(ProcessThread thread in child.Threads)
            {
                using(thread){if(threads.Count>=128)break;try{var state=thread.ThreadState;threads.Add(new{thread.Id,State=state.ToString(),WaitReason=state==System.Diagnostics.ThreadState.Wait?thread.WaitReason.ToString():null,CpuMs=thread.TotalProcessorTime.TotalMilliseconds});}catch(Exception ex){threads.Add(new{Error=ex.ToString()});}}
            }
            evidence["Threads"]=threads;
        }
    }
    catch(Exception ex){evidence["CollectionError"]=ex.ToString();}
    try{File.WriteAllText(report+".failure.json",JsonSerializer.Serialize(evidence,new JsonSerializerOptions{WriteIndented=true}));}catch(Exception ex){Console.Error.WriteLine("Child diagnostic write failed: "+ex);}
}
}
