using System.Diagnostics;
using System.Text.Json;

if(!OperatingSystem.IsWindows()||args.Length!=1||!Path.IsPathFullyQualified(args[0])||!File.Exists(args[0]))throw new ArgumentException("Provide the isolated published DecoyHost executable.");
var executable=Path.GetFullPath(args[0]);
if(!executable.StartsWith(@"D:\Codex\RansomFree\tests\",StringComparison.OrdinalIgnoreCase)||Path.GetFileName(executable)!="RansomFree.DecoyHost.exe")throw new ArgumentException("Only a test publication is allowed.");
var root=Path.Combine(@"D:\Codex\RansomFree\tests","decoy-cli-"+Guid.NewGuid().ToString("N"));Directory.CreateDirectory(root);
var state=Path.Combine(root,"state");var targets=Path.Combine(root,"targets");Directory.CreateDirectory(state);Directory.CreateDirectory(targets);
var id=Guid.NewGuid().ToString("N");var plan=new {id,kind="V03",name="CLI fixture library"};var checks=new List<string>();var invocation=0;
void Check(bool pass,string label){if(!pass)throw new Exception(label);checks.Add("PASS: "+label);Console.WriteLine(checks[^1]);File.WriteAllLines(Path.Combine(root,"results.txt"),checks);}
async Task<(int Code,string Output)> Run(params string[] arguments)
{
    var start=new ProcessStartInfo(executable){UseShellExecute=false,CreateNoWindow=true,WindowStyle=ProcessWindowStyle.Hidden,RedirectStandardOutput=true,RedirectStandardError=true};
    foreach(var argument in arguments)start.ArgumentList.Add(argument);
    using var process=Process.Start(start)??throw new InvalidOperationException("Fixture executable did not start.");
    var output=process.StandardOutput.ReadToEndAsync();var error=process.StandardError.ReadToEndAsync();using var deadline=new CancellationTokenSource(TimeSpan.FromSeconds(20));
    try{await process.WaitForExitAsync(deadline.Token);}
    catch{if(!process.HasExited){process.Kill();await process.WaitForExitAsync();}throw;}
    var text=await output;var diagnostics=await error;File.WriteAllText(Path.Combine(root,$"invocation-{++invocation}.txt"),$"Exit: {process.ExitCode}\n{text}\n{diagnostics}");return(process.ExitCode,text);
}
string Job(string action,long? revision=null,object? actualPlan=null)=>JsonSerializer.Serialize(new {action,stateDirectory=state,approvedRoot=targets,plan=actualPlan??plan,expectedRevision=revision});
async Task<(int Code,string Output)> Execute(string json)
{
    var input=Path.Combine(root,Guid.NewGuid().ToString("N")+".json");File.WriteAllText(input,json);return await Run("--run",input);
}
async Task<JsonDocument> Successful(string action,long? revision=null)
{
    var result=await Execute(Job(action,revision));if(result.Code!=0)throw new InvalidOperationException("Fixture action failed: "+action);return JsonDocument.Parse(result.Output);
}
string? entry=null;long revision=1;bool active=false;
try
{
    var help=await Run("--help");Check(help.Code==0&&help.Output.Contains("seQuester"),"self-contained package starts and identifies seQuester");
    using(var created=await Successful("create")){revision=created.RootElement.GetProperty("Revision").GetInt64();Check(created.RootElement.GetProperty("State").GetString()=="Disabled"&&revision==1,"packaged CLI creates only a disabled resource");}
    using(var observed=await Successful("observe")){entry=observed.RootElement.GetProperty("Entry").GetString();Check(observed.RootElement.GetProperty("State").GetString()=="Disabled"&&!File.Exists(entry),"packaged observation is plan-bound and creates no pointer");}
    Check((await Execute(Job("observe").Replace("\"action\":\"observe\"","\"action\":\"observe\",\"Action\":\"retire\""))).Code==2,"case-variant duplicate action is rejected");
    Check((await Execute(Job("observe").Replace("\"action\":\"observe\"","\"action\":\"observe\",\"unexpected\":true"))).Code==2,"unknown job fields are rejected");
    Check((await Execute(Job("activate",revision,new {id,kind="V03",name="Changed plan"}))).Code==2,"packaged mutation refuses a different saved plan");
    using(var unchanged=await Successful("observe"))Check(unchanged.RootElement.GetProperty("State").GetString()=="Disabled"&&unchanged.RootElement.GetProperty("Revision").GetInt64()==revision,"invalid invocations preserve resource and revision");
    using(var enabled=await Successful("activate",revision)){revision=enabled.RootElement.GetProperty("Revision").GetInt64();active=enabled.RootElement.GetProperty("State").GetString()=="Active";Check(active&&File.Exists(entry),"packaged CLI activates only the isolated library pointer");}
    using(var retired=await Successful("retire",revision)){revision=retired.RootElement.GetProperty("Revision").GetInt64();active=false;Check(retired.RootElement.GetProperty("State").GetString()=="Retired"&&!File.Exists(entry)&&Directory.Exists(retired.RootElement.GetProperty("Target").GetString()),"packaged retirement removes its exact pointer and retains backing data");}
    Check((await Execute(Job("activate",revision))).Code==2,"packaged retired resource cannot reactivate");
    var missingJournal=Path.Combine(root,"not-provisioned");Check((await Run("--session-once","--journal",missingJournal)).Code==2&&!Directory.Exists(missingJournal),"invalid session startup returns failure without provisioning or contacting a broker");
}
finally
{
    if(active){var cleanup=await Execute(Job("disable",revision));if(cleanup.Code!=0)throw new InvalidOperationException("Fixture-only pointer cleanup needs review at "+root);}
    File.WriteAllText(Path.Combine(root,"final-state.json"),JsonSerializer.Serialize(new{Executable=executable,Entry=entry,PointerExists=entry!=null&&File.Exists(entry),BackingRootRetained=Directory.Exists(targets),InstalledBrokerTested=false}));
    Console.WriteLine(root);
}
