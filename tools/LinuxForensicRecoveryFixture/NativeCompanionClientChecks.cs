using System.Text.Json;
using RansomFree.Client.Forensics;

internal static class NativeCompanionClientChecks
{
    internal static void Run()
    {
        var checks=new List<string>();void Check(bool ok,string text){if(!ok)throw new Exception(text);checks.Add(text);}
        new LinuxNativeClientOptions().Validate();Check(true,"default configuration remains disabled without a native group or I/O");
        var valid=new LinuxNativeClientOptions{Enabled=true,ServiceGroup=65534};valid.Validate();Check(true,"explicit separate native channel and export roots accepted");
        foreach(var bad in new[]{valid with{ServiceGroup=0},valid with{ServiceGroup=uint.MaxValue},valid with{ChannelDirectory="/tmp/../run/native"},valid with{ChannelDirectory="relative"},valid with{ExportDirectory=valid.ChannelDirectory},valid with{ExportDirectory=valid.ChannelDirectory+"/exports"},valid with{ChannelDirectory=valid.ExportDirectory+"/channel"}})
        {
            try{bad.Validate();throw new Exception("Unsafe native options accepted");}catch(InvalidDataException){Check(true,"invalid native bridge configuration rejected: "+checks.Count);}
        }
        var names=Enumerable.Range(1,40).Select(x=>x.ToString("x32")+".json").ToArray();
        var a=LinuxNativeCompanionClient.DeliveryPage(names.Concat(["unfinished.tmp","not-an-event.json"]),null);
        Check(a.Length==16&&a.SequenceEqual(names.Take(16)),"bounded first page contains canonical completed packets only");
        var b=LinuxNativeCompanionClient.DeliveryPage(names,a[^1]);var c=LinuxNativeCompanionClient.DeliveryPage(names,b[^1]);
        Check(b.SequenceEqual(names.Skip(16).Take(16)),"sixteen failed retained packets cannot starve the next page");
        Check(c.Take(8).SequenceEqual(names.Skip(32))&&c.Skip(8).SequenceEqual(names.Take(8)),"last page wraps without discarding pending packets");
        Check(a.Concat(b).Concat(c).Distinct().Count()==40,"all pending packets attempted within three bounded passes");
        Check(LinuxNativeCompanionClient.DeliveryPage([],a[^1]).Length==0,"empty inbox does not manufacture delivery");
        var closed=new LinuxControlledSourceRuntime.Outcome("COMPLETED","session","ACTIVE","CLOSE_RETURNED_OK",0,0,false,
            new(2,"Faulted","LINUX_NATIVE_POLICY_EXPIRED_OR_REVOKED",DateTimeOffset.UtcNow),[],null,"COMPLETE",0)
            {NativeClosure=new(1,"runtime","session",DateTimeOffset.UtcNow,1,1,"CLOSE_RETURNED_OK",true,true,true,true)};
        Check(LinuxNativeCompanionService.CompletedExitCode(closed,false)==75,"expired policy can request new session only after verified complete closure");
        Check(LinuxNativeCompanionService.CompletedExitCode(closed with{Startup="FAILED_AFTER_LINK"},false)==75,"expiry during startup requires the same independently complete work and native closure gate");
        Check(new LinuxNativePolicyUnavailableException("LINUX_NATIVE_POLICY_EXPIRED_OR_REVOKED").Reason=="LINUX_NATIVE_POLICY_EXPIRED_OR_REVOKED","startup expiry exception retains exact admission reason rather than matching error text");
        Check(LinuxNativeCompanionService.CompletedExitCode(closed,true)==0,"requested shutdown never requests service restart");
        Check(LinuxNativeCompanionService.CompletedExitCode(null,false)==1,"missing source outcome cannot request restart");
        foreach(var unsafeOutcome in new[]{closed with{State="RECOVERY_PENDING"},closed with{PendingDelivery=1},
            closed with{CanonicalBacklogPresent=true},closed with{UnindexedRawRecords=1},closed with{RawRecoveryState="PENDING"},
            closed with{Errors=["failure"]},closed with{Close="CLOSE_RETURNED_ERROR"},closed with{NativeClosure=null},
            closed with{NativeClosure=closed.NativeClosure! with{IssuedWorkDrained=false}},
            closed with{NativeClosure=closed.NativeClosure! with{ChildAndPipesReturned=false}},
            closed with{NativeClosure=closed.NativeClosure! with{MapHandlesClosed=false}},
            closed with{NativeClosure=closed.NativeClosure! with{ChildHandlesClosed=false}},
            closed with{Stop=closed.Stop! with{Reason="NATIVE_EXPORT_UNAVAILABLE"}}})
            Check(LinuxNativeCompanionService.CompletedExitCode(unsafeOutcome,false)==1,"unresolved or unrelated source failure cannot request restart: "+checks.Count);
        Console.WriteLine(JsonSerializer.Serialize(new{Passed=true,Checks=checks.Count,Details=checks,Scope="Native client configuration and fair delivery selection; no IPC or installed activation"}));
    }
}
