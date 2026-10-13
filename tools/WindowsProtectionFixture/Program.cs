using System.Text.Json;
using RansomFree;
using RansomFree.Contracts;

var cases=0;
void Check(bool valid,string name)
{
    if(!valid)throw new Exception(name);
    cases++;
}

Check(WindowsProtectionStatus.Build(null,3,true,true,"Monitoring") is null,"unknown inventory stays unreported");
Check(CanaryEvidence.Summarize([null,"Healthy"]) is null,"unverified canary remains unknown");
Check(CanaryEvidence.Summarize(["Cannot verify: IOException"]) is null,"failed integrity read remains unknown");
Check(CanaryEvidence.Summarize(["Healthy","Content changed / possible encryption","Missing","Audit rule missing"]) is {DeployedItems:3,IntegrityHealthy:false},"observed present files counted");
Check(CanaryEvidence.Summarize([]) is {DeployedItems:0,IntegrityHealthy:true},"explicit zero configuration");
Check(WindowsProtectionStatus.Build((0,true),0,false,false,"No canaries configured") is {DeployedCanaryAndHoneypotFiles:0,MonitoringState:"not-configured"},"empty configuration is explicit");
Check(WindowsProtectionStatus.Build((3,true),3,false,true,"Monitoring") is {DeployedCanaryAndHoneypotFiles:3,MonitoringState:"stopped"},"audit disconnected");
Check(WindowsProtectionStatus.Build((3,true),3,true,false,"Monitoring") is {MonitoringState:"degraded"},"watcher gap");
Check(WindowsProtectionStatus.Build((2,false),3,true,true,"Monitoring") is {DeployedCanaryAndHoneypotFiles:2,MonitoringState:"degraded"},"missing or changed canary");
Check(WindowsProtectionStatus.Build((3,true),3,true,true,"Policy application pending") is {MonitoringState:"degraded"},"policy warning");
var active=WindowsProtectionStatus.Build((3,true),3,true,true,"Monitoring");
Check(active is {DeployedCanaryAndHoneypotFiles:3,MonitoringState:"active"} && active.IsValid(),"active with complete evidence");
Check(WindowsProtectionStatus.Build((4,true),3,true,true,"Monitoring") is null,"impossible deployed count refused");
var wire=JsonSerializer.Serialize(new HeartbeatRequest("0.6.5-dev","Monitoring") {OperatingSystem="windows",Protection=active});
using var json=JsonDocument.Parse(wire);
Check(json.RootElement.GetProperty("Protection").GetProperty("DeployedCanaryAndHoneypotFiles").GetInt32()==3 &&
      json.RootElement.GetProperty("OperatingSystem").GetString()=="windows","wire report and platform");
Console.WriteLine($"PASS {cases} Windows protection report cases");
