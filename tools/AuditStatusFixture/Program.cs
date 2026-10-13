using RansomFree.LinuxAgent;

// Exact read-only LC_ALL=C auditctl -s pilot output, including feature annotation.
const string observed="enabled 1\nfailure 1\npid 200576\nrate_limit 0\nbacklog_limit 8192\nlost 0\nbacklog 0\nbacklog_wait_time 60000\nbacklog_wait_time_actual 0\nloginuid_immutable 0 unlocked\n";
var passed=0;
void Check(bool value){if(!value)throw new Exception("Fixture assertion failed.");}
void Test(string name,Action action){action();Console.WriteLine("PASS: "+name);passed++;}
void Reject(string text){try{AuditKernelStatus.ActivePid(text);}catch(InvalidDataException){return;}throw new Exception("Expected malformed/inactive status refusal.");}
Test("exact real 3.0.7 three-token feature output",()=>Check(AuditKernelStatus.ActivePid(observed)==200576));
Test("immutable audit and locked feature",()=>Check(AuditKernelStatus.ActivePid(observed.Replace("enabled 1","enabled 2").Replace("0 unlocked","1 locked"))==200576));
Test("feature annotation optional",()=>Check(AuditKernelStatus.ActivePid("enabled 1\npid 20\n")==20));
Test("CRLF and numeric future scalar",()=>Check(AuditKernelStatus.ActivePid(observed.Replace("\n","\r\n")+"future_counter 123\r\n")==200576));
Test("whitespace normalization",()=>Check(AuditKernelStatus.ActivePid("\n  enabled\t1\n\tpid 20\n \n")==20));
Test("duplicate critical fields",()=>{Reject(observed+"pid 200576\n");Reject(observed+"enabled 1\n");});
Test("duplicate optional fields",()=>Reject(observed+"loginuid_immutable 0 unlocked\n"));
Test("missing required fields",()=>{Reject("enabled 1\n");Reject("pid 20\n");Reject("");});
Test("invalid enabled state",()=>{foreach(var v in new[]{"0","3","enabled","-1","1 extra"})Reject(observed.Replace("enabled 1","enabled "+v));});
Test("invalid PID identity and overflow",()=>{foreach(var v in new[]{"0","1","-1","+20","2147483648","4294967296","20 extra"})Reject(observed.Replace("pid 200576","pid "+v));});
Test("invalid feature shape",()=>{foreach(var v in new[]{"2 locked","0","0 invalid","0 unlocked extra","-1 unlocked"})Reject(observed.Replace("0 unlocked",v));});
Test("unknown diagnostics not silently ignored",()=>{Reject(observed+"NLMSG_ERROR 1 (Operation not permitted)\n");Reject(observed+"warning unavailable\n");});
Test("bounded status length",()=>Reject(new string('x',65537)));
Test("bounded line length",()=>Reject(observed+new string('a',513)));
Test("bounded field count",()=>Reject(string.Concat(Enumerable.Repeat("counter 1\n",257))));
using var error=new StringWriter();
Check(await AuditCommandExit.Run(()=>Task.CompletedTask,error)==0&&error.ToString().Length==0);
Console.WriteLine("PASS: command success exits zero");passed++;
foreach(var exception in new Exception[]{new InvalidDataException("SECRET fixture value"),new IOException("SECRET fixture path"),new UnauthorizedAccessException("SECRET fixture user"),new InvalidOperationException("SECRET fixture state")})
{
    error.GetStringBuilder().Clear();
    Check(await AuditCommandExit.Run(()=>Task.FromException(exception),error)==1);
    Check(error.ToString().Contains(exception.GetType().Name)&&!error.ToString().Contains("SECRET")&&!error.ToString().Contains(" at "));
}
Console.WriteLine("PASS: operational failures return one without payload or stack trace");passed++;
Console.WriteLine($"PASS: {passed} production status/exit cases. No native auditctl, filesystem rule mutation or live service invoked.");
