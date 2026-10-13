using RansomFree.LinuxAgent;

if(args.Length>0)
{
    // Separate, explicitly enabled user-manager fixture. These are mock text
    // inventories only; no auditctl or native audit subsystem is invoked.
    if(args.Length!=2||args[0] is not ("--lifecycle-clear" or "--lifecycle-reconcile")||Environment.GetEnvironmentVariable("SEQUESTER_RULE_LIFECYCLE_FIXTURE")!="1"||!OperatingSystem.IsLinux())throw new InvalidOperationException("Fixture invocation refused.");
    var directory=Path.GetFullPath(args[1]);
    if(!directory.StartsWith("/tmp/sequester-rules-fixture-",StringComparison.Ordinal)||directory[5..].Contains('/')||!Directory.Exists(directory)||new DirectoryInfo(directory).LinkTarget!=null)throw new InvalidOperationException("Fixture directory refused.");
    var inventory=Path.Combine(directory,"mock-inventory.txt");var log=Path.Combine(directory,"runs.log");
    foreach(var file in new[]{inventory,log})if(new FileInfo(file).LinkTarget!=null)throw new InvalidOperationException("Fixture link refused.");
    const string baseline="-w /fixture/unrelated -p wa -k fixture_baseline";
    if(args[0]=="--lifecycle-clear")File.WriteAllText(inventory,baseline+"\n");
    else
    {
        var desired=new[]{new ManagedAuditRule("b64","/fixture/canary.xlsx"),new ManagedAuditRule("b32","/fixture/canary.xlsx")};
        var result=await AuditRulePlan.Reconcile(desired,()=>Task.FromResult(File.ReadAllText(inventory)),rule=>{File.AppendAllText(inventory,string.Join(' ',rule.Arguments)+"\n");return Task.CompletedTask;});
        if(result.UnrelatedPreserved!=1)throw new IOException("Fixture unrelated baseline changed.");
        File.AppendAllText(log,$"expected={result.Expected} added={result.Added} unrelated={result.UnrelatedPreserved}\n");
    }
    return;
}

// No subprocesses, OS audit calls, live files, services or network. Exact production planner.
var passed=0;
void Check(bool value,string label){if(!value)throw new Exception(label);}
async Task Test(string name,Func<Task> action){await action();Console.WriteLine("PASS: "+name);passed++;}
async Task Reject(Func<Task> action){try{await action();}catch(InvalidDataException){return;}catch(IOException){return;}throw new Exception("Expected refusal.");}
string Line(ManagedAuditRule r)=>string.Join(' ',r.Arguments);
var a=new ManagedAuditRule("b64","/home/Finance/Payroll.xlsx");
var b=new ManagedAuditRule("b32",a.Path);
var c=new ManagedAuditRule("b64","/srv/Finance/Accounts.csv");
const string other="-w /etc/passwd -p wa -k baseline_identity";
const string expanded="open,bind,truncate,ftruncate,rename,mkdir,rmdir,creat,link,unlink,symlink,readlink,chmod,fchmod,chown,fchown,lchown,mknod,acct,swapon,quotactl,setxattr,lsetxattr,fsetxattr,getxattr,lgetxattr,fgetxattr,listxattr,llistxattr,flistxattr,removexattr,lremovexattr,fremovexattr,openat,mkdirat,mknodat,fchownat,unlinkat,renameat,linkat,symlinkat,readlinkat,fchmodat,fallocate,renameat2,openat2";
await Test("actual add preserves explicit approved all mask",()=>{
    Check(a.Arguments.SequenceEqual(new[]{"-a","always,exit","-F","arch=b64","-S","all","-F","path="+a.Path,"-F","perm=rwa","-k","sequester_canary"}),"exact add arguments");return Task.CompletedTask;});
await Test("legacy omitted mask normalized to explicit all",()=>{
    var desired=AuditRulePlan.Desired(Line(a).Replace(" -S all",""));Check(desired.Single().Arguments.SequenceEqual(a.Arguments),"explicit normalized authority");return Task.CompletedTask;});
await Test("exact observed 4.0.2 expanded mask refused before mutation",()=>Reject(()=>AuditRulePlan.Reconcile([a],()=>Task.FromResult(Line(a).Replace("-S all","-S "+expanded)),r=>throw new Exception("Unexpected mutation of conflicting live mask"))));
await Test("4.0.2 add-output model preserves all and remains idempotent",async()=>{
    var live=new List<string>{other};var adds=0;
    Task Add(ManagedAuditRule r){adds++;var output=Line(r);if(!r.Arguments.Contains("-S"))output=output.Replace(" -F path="," -S "+expanded+" -F path=");live.Add(output);return Task.CompletedTask;}
    var first=await AuditRulePlan.Reconcile([a,b],()=>Task.FromResult(string.Join('\n',live)),Add);
    var next=await AuditRulePlan.Reconcile([a,b],()=>Task.FromResult(string.Join('\n',live)),Add);
    Check(first.Added==2&&next.Added==0&&adds==2&&live[0]==other,"no inferred mask or duplicate");});
await Test("desired/live canonicalization",()=>{
    Check(AuditRulePlan.Parse("-a always,exit -F arch=b64 -S all -F path="+a.Path+" -F perm=rwa -F key=sequester_canary")==a,"canonicalization");
    Check(AuditRulePlan.Parse(Line(a).Replace("always,exit","exit,always"))==a,"order");return Task.CompletedTask;});
await Test("empty inventories",()=>{Check(AuditRulePlan.Snapshot("").Owned.Length==0&&AuditRulePlan.Snapshot("No rules\n").Owned.Length==0,"empty");return Task.CompletedTask;});
await Test("comments and CRLF",()=>{Check(AuditRulePlan.Desired("# reviewed\r\n"+Line(a)+"\r\n").Single()==a,"comments");return Task.CompletedTask;});
await Test("empty desired refused",()=>Reject(()=>{AuditRulePlan.Desired("# empty");return Task.CompletedTask;}));
await Test("duplicate desired refused",()=>Reject(()=>{AuditRulePlan.Desired(Line(a)+"\n"+Line(a));return Task.CompletedTask;}));
await Test("duplicate live refused",()=>Reject(()=>{AuditRulePlan.Snapshot(Line(a)+"\n"+Line(a));return Task.CompletedTask;}));
await Test("unsafe or unsupported syntax refused",async()=>{
    foreach(var line in new[]{"-D",Line(a)+" -F uid=0",Line(a)+" -k sequester_canary",Line(a).Replace("perm=rwa","perm=rw"),Line(a).Replace("arch=b64","arch=arm64"),Line(a).Replace(a.Path,"/home/../secret"),Line(a).Replace(a.Path,"/home/Finance/Pay roll.xlsx"),Line(a).Replace(a.Path,"/home//Finance/pay.xlsx"),Line(a)+" -S open"})await Reject(()=>{AuditRulePlan.Parse(line);return Task.CompletedTask;});});
await Test("ambiguous reserved key refused",()=>Reject(()=>{AuditRulePlan.Snapshot(other.Replace("baseline_identity","sequester_canary_extra"));return Task.CompletedTask;}));
await Test("malformed live output refused",async()=>{foreach(var line in new[]{"warning: unavailable","No rules\n"+other})await Reject(()=>{AuditRulePlan.Snapshot(line);return Task.CompletedTask;});});
await Test("bounds refused",async()=>{await Reject(()=>{AuditRulePlan.Desired(new string('x',4*1024*1024+1));return Task.CompletedTask;});await Reject(()=>{AuditRulePlan.Parse(new string('x',4097));return Task.CompletedTask;});});
await Test("first install adds exact six rules and preserves unrelated",async()=>{
    var desired=new[]{a,b,c,new ManagedAuditRule("b32",c.Path),new ManagedAuditRule("b64","/var/backups/Recovery/Keys.pdf"),new ManagedAuditRule("b32","/var/backups/Recovery/Keys.pdf")};
    var live=new List<string>{other};var additions=new List<ManagedAuditRule>();
    var result=await AuditRulePlan.Reconcile(desired,()=>Task.FromResult(string.Join('\n',live)),r=>{additions.Add(r);live.Add(Line(r));return Task.CompletedTask;});
    Check(result.Added==6&&result.UnrelatedPreserved==1&&live[0]==other&&additions.SequenceEqual(desired),"six exact additions");
    var again=await AuditRulePlan.Reconcile(desired,()=>Task.FromResult(string.Join('\n',live)),r=>throw new Exception("Duplicate addition"));
    Check(again.Added==0&&again.AlreadyPresent==6,"idempotent");});
await Test("existing subset adds only missing",async()=>{
    var live=new List<string>{Line(a),other};var adds=0;
    var result=await AuditRulePlan.Reconcile([a,b],()=>Task.FromResult(string.Join('\n',live)),r=>{Check(r==b,"only b");adds++;live.Add(Line(r));return Task.CompletedTask;});
    Check(adds==1&&result.AlreadyPresent==1,"subset");});
await Test("unexpected owned rule fails before mutation",async()=>{
    await Reject(()=>AuditRulePlan.Reconcile([a],()=>Task.FromResult(Line(c)),r=>throw new Exception("Unexpected mutation")));});
await Test("partial add failure visible; explicit retry missing-only",async()=>{
    var live=new List<string>{other};var verified=0;
    await Reject(()=>AuditRulePlan.Reconcile([a,b,c],()=>Task.FromResult(string.Join('\n',live)),r=>{if(r==b)throw new IOException("fixture failure");live.Add(Line(r));return Task.CompletedTask;},n=>verified=n));
    Check(verified==1&&live.SequenceEqual(new[]{other,Line(a)}),"partial state preserved");
    var retry=await AuditRulePlan.Reconcile([a,b,c],()=>Task.FromResult(string.Join('\n',live)),r=>{Check(r!=a,"no duplicate retry");live.Add(Line(r));return Task.CompletedTask;});
    Check(retry.Added==2&&retry.AlreadyPresent==1,"retry counts");});
await Test("success exit without live rule is refused",()=>Reject(()=>AuditRulePlan.Reconcile([a],()=>Task.FromResult(other),r=>Task.CompletedTask)));
await Test("concurrent unrelated change before add refused",async()=>{
    var lists=0;await Reject(()=>AuditRulePlan.Reconcile([a],()=>Task.FromResult(++lists==1?other:other+"\n-w /etc/group -p wa -k other"),r=>throw new Exception("Unexpected mutation")));});
await Test("concurrent managed removal refused",async()=>{
    var lists=0;await Reject(()=>AuditRulePlan.Reconcile([a,b],()=>Task.FromResult(++lists==1?Line(a):"No rules"),r=>throw new Exception("Unexpected mutation")));});
await Test("post-add unrelated mutation refused without rollback",async()=>{
    var live=other;var adds=0;await Reject(()=>AuditRulePlan.Reconcile([a,b],()=>Task.FromResult(live),r=>{adds++;live=Line(r);return Task.CompletedTask;}));Check(adds==1&&live==Line(a),"must not delete after error");});
await Test("inventory failure cannot mutate",()=>Reject(()=>AuditRulePlan.Reconcile([a],()=>throw new IOException("fixture list failure"),r=>throw new Exception("Unexpected mutation"))));
Console.WriteLine($"PASS: {passed} bounded production-planner cases. Scope: in-memory reconciliation only; no native auditctl/systemd/pilot acceptance.");
