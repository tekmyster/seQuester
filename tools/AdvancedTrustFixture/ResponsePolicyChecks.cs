using RansomFree.Contracts;
using System.Text.Json;

internal static class ResponsePolicyChecks
{
    internal static void Run(Action<bool,string> check)
    {
        var now=DateTimeOffset.UtcNow;var sensor=Guid.NewGuid().ToString("N");var id=Guid.NewGuid().ToString("N");
        var target=new ActiveResponseTarget(sensor,id,"windows",new(sensor,900,"133000000000000000","windows:fixture"),new string('A',64),@"C:\QA\actor.exe",@"C:\QA\canary.txt",null,"effective-user");
        var response=new ActiveResponsePolicy{Mode="manual",Actions=["end-process"]};
        var policy=new AssignedPolicy(Guid.NewGuid().ToString("N"),7,MonitoringPolicy.Default with{ActiveResponse=response});
        var command=new ResponseCommand(Guid.NewGuid().ToString("N"),id,"end-process","fixture","owned fixture",now,now.AddMinutes(1))
            {Target=target,PolicyRevision=policy.Revision,PolicyDigest=ResponseCommandPolicy.Digest(policy)};
        check(ResponseCommandPolicy.Permits(command,policy,sensor),"native response requires exact assigned policy and sensor");
        check(!ResponseCommandPolicy.Permits(command,null,sensor),"unknown policy cannot authorize a native response");
        check(!ResponseCommandPolicy.Permits(command,policy,Guid.NewGuid().ToString("N")),"response cannot move between sensors");
        check(!ResponseCommandPolicy.Permits(command with{EventId=Guid.NewGuid().ToString("N")},policy,sensor),"response cannot substitute its triggering event");
        check(!ResponseCommandPolicy.Permits(command with{PolicyRevision=8},policy,sensor),"response cannot use another policy revision");
        check(!ResponseCommandPolicy.Permits(command with{PolicyDigest=new string('B',64)},policy,sensor),"response rejects a changed policy digest");
        check(!ResponseCommandPolicy.Permits(command,policy with{GroupId=Guid.NewGuid().ToString("N")},sensor),"same revision in another group is not the same policy");
        check(!ResponseCommandPolicy.Permits(command,policy with{Settings=policy.Settings with{ActiveResponse=response with{MaximumActionsPerMinute=1}}},sensor),"same revision with changed limits cannot reuse authorization");
        bool WithPolicy(ActiveResponsePolicy changed,bool automatic=false)
        {
            var assigned=policy with{Settings=policy.Settings with{ActiveResponse=changed}};
            return ResponseCommandPolicy.Permits(command with{PolicyDigest=ResponseCommandPolicy.Digest(assigned)},assigned,sensor,automatic);
        }
        check(!WithPolicy(response with{Mode="observe"}),"observe policy cannot authorize execution even with its correct digest");
        check(!WithPolicy(response with{Actions=["disable-account"]}),"configured action list cannot authorize an omitted action");
        check(!WithPolicy(response with{AccountPrincipal="process-owner"}),"effective-user target cannot switch to process-owner policy");
        check(!WithPolicy(response with{Mode="automatic"}),"manual command cannot use automatic policy approval");
        check(WithPolicy(response with{Mode="automatic"},true),"automatic approval is separate and requires automatic policy");
        check(!ResponseCommandPolicy.Permits(command,policy,sensor,true),"automatic command cannot borrow manual policy approval");
        var restored=JsonSerializer.Deserialize<ResponseCommand>(JsonSerializer.Serialize(command))!;
        check(ResponseCommandPolicy.Permits(restored,policy,sensor),"exact native response binding survives wire serialization");
        var legacy=new ResponseCommand(command.Id,id,"end-process","fixture","legacy",now,now.AddMinutes(1));
        check(!JsonSerializer.Serialize(legacy).Contains("Target")&&!JsonSerializer.Serialize(legacy).Contains("PolicyDigest"),"legacy command wire format omits new optional native fields");
    }
}
