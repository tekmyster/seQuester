using System.Collections.Concurrent;
using System.Diagnostics;

namespace RansomFree;

internal static class SelfTest
{
    public static void Exercise(string directory)
    {
        var files=Directory.GetFiles(directory).Where(p=>!p.EndsWith(".copy")).ToArray();
        foreach(var file in files) _=File.ReadAllBytes(file);
        File.Copy(files[0],files[0]+".copy");
        File.AppendAllText(files[1],"\r\nChanged in integration test");
        File.Delete(files[2]);
    }
    public static int Run()
    {
        var results=Path.Combine(AppContext.BaseDirectory,"test-results"); Directory.CreateDirectory(results);
        var root=Path.Combine(results,Guid.NewGuid().ToString("N")); Directory.CreateDirectory(root);
        var folder=Path.Combine(root,"canaries"); Directory.CreateDirectory(folder);
        var report=new List<string>(); uint? original=null; uint? handles=null;
        try
        {
            AuditPolicy.EnablePrivilege(); original=AuditPolicy.Read(); handles=AuditPolicy.Read(AuditPolicy.Handles);
            using var monitor=new CanaryMonitor(Path.Combine(root,"config"));
            var alerts=new ConcurrentQueue<Alert>(); monitor.Alerted+=alerts.Enqueue;
            monitor.HealthChanged+=s=>report.Add("Health: "+s);
            monitor.Deploy(folder); monitor.Start();
            if(!monitor.AuditConnected) throw new Exception("Audit subscription failed");
            if(monitor.Settings.Canaries.Count!=3) throw new Exception("Expected three canaries");
            using(var p=Process.Start(new ProcessStartInfo(Environment.ProcessPath!) { UseShellExecute=false, CreateNoWindow=true, ArgumentList={"--exercise",folder} })!) p.WaitForExit();
            var until=DateTime.UtcNow.AddSeconds(15);
            while(DateTime.UtcNow<until && (!alerts.Any(a=>a.Operation.Contains("Content read")) || !alerts.Any(a=>a.Operation.Contains("Content written")) || !alerts.Any(a=>a.Operation.Contains("Open /")))) Thread.Sleep(100);
            monitor.CheckIntegrity();
            void Require(string name,Func<Alert,bool> predicate) { if(!alerts.Any(predicate)) throw new Exception("FAIL: "+name); report.Add("PASS: "+name); }
            Require("Open/access auditing",a=>a.Operation.Contains("Open /"));
            Require("Content read auditing (including copy source)",a=>a.Operation.Contains("Content read"));
            foreach(var type in new[]{"docx","xlsx","pdf"})
                Require("Content read attributed for "+type,a=>a.Path.EndsWith("."+type,StringComparison.OrdinalIgnoreCase) && a.Source=="Windows audit 4663" && a.Operation.Contains("Content read"));
            Require("Write auditing",a=>a.Operation.Contains("Content written"));
            Require("Deletion access attributed",a=>a.Source=="Windows audit 4663"&&a.Operation.Contains("Delete access used"));
            foreach(var alert in alerts.Where(a=>a.Source is "Windows audit 4656" or "Windows audit 4663"))
                if(!RansomFree.Contracts.LocalActorEvidence.IsComplete(alert.Source,alert.User,alert.Executable??alert.Process,alert.ProcessId))throw new Exception("FAIL: local audit event missing user, process or PID");
            // Changes detected without OS actor evidence must still be retained.
            // These sources cannot identify the accessing user/process/PID.
            Require("Unattributed change notification retained",a=>a.Source=="File watcher");
            Require("Unattributed integrity detection retained",a=>a.Source=="Integrity check");
            foreach(var alert in alerts.Where(a=>a.Source is "File watcher" or "Integrity check"))
            {
                var unavailable=alert.Source=="File watcher"?"Unavailable for change notifications":"Unavailable for integrity checks";
                if(alert.User!=unavailable||alert.Process!=unavailable||alert.ProcessId!=null||alert.Executable!=null||alert.Identity!=null||alert.UserSid!=null)
                    throw new Exception("FAIL: unattributed detection contains manufactured actor evidence");
            }
            report.Add("PASS: OS audit alerts attributed; change/integrity detections retained with explicitly unavailable actor fields");
            if(alerts.Any(a=>a.Process.EndsWith($"(PID {Environment.ProcessId})"))) throw new Exception("Self-events were not filtered");
            report.Add("PASS: own-process audit events filtered");
            FeatureTests.RunAsync(root,report).GetAwaiter().GetResult();
            report.Add("Events: "+alerts.Count);
            File.WriteAllLines(Path.Combine(results,"latest.txt"),report);
            File.WriteAllText(Path.Combine(root,"events.json"),System.Text.Json.JsonSerializer.Serialize(alerts,new System.Text.Json.JsonSerializerOptions { WriteIndented=true }));
            return 0;
        }
        catch(Exception ex) { report.Add(ex.ToString()); File.WriteAllLines(Path.Combine(results,"latest.txt"),report); return 1; }
        finally { if(original.HasValue) AuditPolicy.Set(original.Value); if(handles.HasValue) AuditPolicy.Set(handles.Value,AuditPolicy.Handles); }
    }
}
