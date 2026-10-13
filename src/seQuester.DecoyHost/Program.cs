using System.Text.Json;
using System.Text.Json.Serialization;
using RansomFree.WindowsDecoys;
if(args is ["--help"] or [])
{
    Console.WriteLine("seQuester virtual decoys · Windows local-session adapter");
    Console.WriteLine("--run JOB.json");
    Console.WriteLine("--session-once --journal EXISTING_LOCAL_FOLDER (non-elevated; installed broker required)");
    Console.WriteLine("Actions: create, observe, activate, repair, disable, retire. Types: V02 drive, V03 library.");
    Console.WriteLine("Job fields: action, stateDirectory, approvedRoot, plan { id, kind, name, drive }, expectedRevision.");
    Console.WriteLine("Creation is disabled. Retirement preserves backing folders. SYSTEM/global mappings are not supported.");return;
}
try
{
    if(args is ["--session-once","--journal",var journal])
    {
        var sessionResult=await SessionCompanion.RunOnce(journal,CancellationToken.None);Console.WriteLine(sessionResult);
        // A scheduler must not count refused, expired or unconfirmed work as success.
        Environment.ExitCode=sessionResult is "No assignments" or "Session result recorded"?0:2;return;
    }
    if(args is not ["--run",var jobPath]||!Path.IsPathFullyQualified(jobPath)||jobPath.StartsWith("\\\\",StringComparison.Ordinal)||!File.Exists(jobPath))throw new ArgumentException("Provide one existing local JSON job file of at most 16 KiB.");
    using var jobPin=RansomFree.DeploymentPathLease.Acquire(Path.GetDirectoryName(jobPath)!,jobPath);
    Job job;
    using(var input=new FileStream(jobPath,FileMode.Open,FileAccess.Read,FileShare.Read))
    {
        if(input.Length is <2 or >16384)throw new ArgumentException("Job file must be at most 16 KiB.");
        var data=new byte[(int)input.Length];input.ReadExactly(data);
        job=JsonSerializer.Deserialize<Job>(data,new JsonSerializerOptions{PropertyNameCaseInsensitive=true,AllowDuplicateProperties=false,RespectRequiredConstructorParameters=true,RespectNullableAnnotations=true,UnmappedMemberHandling=JsonUnmappedMemberHandling.Disallow,MaxDepth=8})??throw new ArgumentException("Job missing.");
    }
    var engine=new VirtualDecoys(job.StateDirectory,job.ApprovedRoot);
    object result=job.Action switch
    {
        "create"=>engine.Create(job.Plan??throw new ArgumentException("Plan required.")),
        "observe"=>job.Plan==null?(object)engine.Observe():engine.Observe(job.Plan),
        "activate"=>engine.SetActive(Id(),Revision(),true,expectedPlan:job.Plan),
        "disable"=>engine.SetActive(Id(),Revision(),false,expectedPlan:job.Plan),
        "retire"=>engine.SetActive(Id(),Revision(),false,true,job.Plan),
        "repair"=>engine.Repair(Id(),Revision(),job.Plan),
        _=>throw new ArgumentException("Unsupported action.")
    };
    string Id()=>job.Plan?.Id??throw new ArgumentException("Plan ID required.");
    long Revision()=>job.ExpectedRevision is >0?job.ExpectedRevision.Value:throw new ArgumentException("Expected revision required.");
    Console.WriteLine(JsonSerializer.Serialize(result,new JsonSerializerOptions{WriteIndented=true}));
}
catch(Exception ex)when(ex is not OutOfMemoryException){Console.Error.WriteLine("Action not confirmed: "+ex.Message);Environment.ExitCode=2;}
internal sealed record Job(string Action,string StateDirectory,string ApprovedRoot,VirtualDecoyPlan? Plan=null,long? ExpectedRevision=null);
