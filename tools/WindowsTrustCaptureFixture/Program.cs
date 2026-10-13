using System.Diagnostics;
using System.Security.Cryptography;
using RansomFree;
using RansomFree.Contracts;
var root=Path.Combine("D:\\Codex\\RansomFree\\tests","windows-trust-"+Guid.NewGuid().ToString("N"));Directory.CreateDirectory(root);
var checks=new List<string>();void Check(bool value,string label){if(!value)throw new Exception(label);checks.Add("PASS: "+label);Console.WriteLine(checks[^1]);}
using var self=Process.GetCurrentProcess();var image=self.MainModule!.FileName;var now=DateTime.UtcNow;
var captured=ProcessControls.Capture(Environment.ProcessId,image,now);
Check(captured is {TrustVerified:true,Hash.Length:64,ImageCheckedUtc:not null},"own fixture process has live handle, locked image and bounded verified hash");
Check(captured!.Hash==CanaryMonitor.Hash(image),"native captured image hash matches independent fixture hash");
var hashes=ProcessControls.HashComputations;
Check(Enumerable.Range(0,100).All(_=>ProcessControls.Capture(Environment.ProcessId,image,DateTime.UtcNow) is {TrustVerified:true}),"stable locked image remains verified on 100 repeated native events");
Check(ProcessControls.HashComputations==hashes,"legacy Windows response/trust capture reuses stable identity hash instead of hashing twice per event");
Check(ProcessControls.Capture(Environment.ProcessId,image+".different",now)==null,"audit image mismatch cannot use same PID");
Check(ProcessControls.Capture(Environment.ProcessId,image,self.StartTime.ToUniversalTime().AddSeconds(-1))==null,"PID creation after event is rejected");
Check(ProcessControls.Capture(Environment.ProcessId,image,now.AddMinutes(2))?.TrustVerified!=true,"future event cannot earn process trust");
Check(ProcessControls.Capture(int.MaxValue,image,now)==null,"unavailable process does not fall back to path trust");
var rule=new TrustRule(Guid.NewGuid().ToString("N"),"organization","server","process",["read"],"informational",DateTimeOffset.UtcNow.AddMinutes(-1),DateTimeOffset.UtcNow.AddHours(1)){Enabled=true,Executable=image,Sha256=captured.Hash};
var actor=new TrustActor(Executable:captured.Executable,Sha256:captured.Hash,Verified:captured.TrustVerified);
var context=new TrustContext("server",null,Guid.NewGuid().ToString("N"),"windows",Path.Combine(root,"synthetic-canary.txt"),["read"],DateTimeOffset.UtcNow,actor);
Check(TrustEvaluation.Evaluate([rule],context,DateTimeOffset.UtcNow).Severity=="informational","exact native process hash/path read rule matches");
Check(TrustEvaluation.Evaluate([rule],context with{Actions=["write"]},DateTimeOffset.UtcNow).Severity=="normal","same trusted process write still alerts");
Check(TrustEvaluation.Evaluate([rule],context with{Actor=actor with{Sha256=new string('0',64)}},DateTimeOffset.UtcNow).Severity=="normal","changed process hash does not match");
File.WriteAllLines(Path.Combine(root,"results.txt"),checks);Console.WriteLine(root);Console.WriteLine("Read-only own-process capture only. No process stopped, audit setting changed or real canary deployed. Packaged native audit-to-UI acceptance remains pending.");
namespace RansomFree
{
    internal sealed record Alert(string Path,ProcessIdentity? Identity);
    internal static class CanaryMonitor {public static string Hash(string path){using var stream=File.OpenRead(path);return Convert.ToHexString(SHA256.HashData(stream));}}
}
