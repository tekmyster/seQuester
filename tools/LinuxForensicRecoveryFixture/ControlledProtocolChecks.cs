using RansomFree.Contracts;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using RansomFree.Client;

static class ControlledProtocolChecks
{
    internal static void ReadNativeCases(string path)
    {
        var data=File.ReadAllBytes(path);if(data.Length>4*1024*1024)throw new InvalidDataException("Native fixture manifest exceeds bound");using var document=JsonDocument.Parse(data);
        if(!document.RootElement.GetProperty("Passed").GetBoolean())throw new InvalidDataException("Accepted native fixture required");var readyCount=0;var activeCount=0;var completeCount=0;
        foreach(var entry in document.RootElement.GetProperty("Cases").EnumerateArray())
        {
            LinuxControlledLoaderProtocol.Ready? ready=null;
            foreach(var record in entry.GetProperty("Records").EnumerateArray())
            {
                var raw=Encoding.UTF8.GetBytes(record.GetRawText());
                if(record.TryGetProperty("controlledReady",out _)){ready=LinuxControlledLoaderProtocol.ParseReady(raw);readyCount++;}
                else if(record.TryGetProperty("controlledActivated",out _))
                {
                    if(ready==null)throw new InvalidDataException("Native activation preceded ready");
                    LinuxControlledLoaderProtocol.ParseActivated(raw,ready,entry.GetProperty("SessionId").GetString()!);activeCount++;
                }
                else if(record.TryGetProperty("controlledComplete",out _)){LinuxControlledLoaderProtocol.ParseCompletion(raw);completeCount++;}
            }
        }
        if(readyCount!=16||activeCount!=5||completeCount!=21)throw new InvalidDataException("Native controlled frame inventory changed");
        Console.WriteLine(JsonSerializer.Serialize(new{Passed=true,ReadyFrames=readyCount,ActivatedFrames=activeCount,CompletionFrames=completeCount,Scope="Managed parser acceptance of actual archived R14 controlled loader output; no new native operation"}));
    }
    internal static void Run()
    {
        var checks=0;
        void Check(bool ok,string label){if(!ok)throw new Exception(label);checks++;Console.WriteLine("PASS: "+label);}
        void Reject(Action action,string label){try{action();}catch(InvalidDataException){Check(true,label);return;}throw new Exception("Accepted invalid control frame: "+label);}
        byte[] Encode(JsonObject value)=>Encoding.UTF8.GetBytes(value.ToJsonString());
        var ready=JsonSerializer.SerializeToNode(new{controlledReady=true,controlVersion=1,schemaVersion=5,loadedProgramIds=new uint[]{1,2,3,4,5},attachedProgramIds=new uint[]{2,3,4},observeAttached=false,denialAttached=false,scratchMapFrozen=true,scratchMapId=11,configMapFrozen=true,configMapId=12,eventsMapId=13,lostMapId=14,providerEpoch=ulong.MaxValue,activationNonce="1234567890abcdef1234567890abcdef",targetInode=ulong.MaxValue,targetDevice=uint.MaxValue,targetPinned=true,mode=0,lostAtReady=9007199254740993UL,activationFrame="one-command-then-eof"})!.AsObject();
        var raw=Encode(ready);var parsed=LinuxControlledLoaderProtocol.ParseReady(raw);
        Check(parsed.Epoch==ulong.MaxValue&&parsed.TargetInode==ulong.MaxValue&&parsed.Lost==9007199254740993UL,"full-width native numbers retained beyond JavaScript exact range");
        var copy=parsed.Raw;copy[0]=0;raw[0]=0;
        Check(parsed.Raw[0]=='{'&&parsed.Programs.SequenceEqual(new uint[]{1,2,3,4,5}),"parsed raw and ID evidence cannot be mutated through caller buffers");
        const string session="11111111111111111111111111111111";
        Check(Encoding.ASCII.GetString(LinuxControlledLoaderProtocol.ActivationFrame(parsed,session))=="ACTIVATE "+session+" 18446744073709551615 1234567890abcdef1234567890abcdef\n","activation contains only canonical bound session/epoch/nonce");
        foreach(var change in new (string Name,JsonNode? Value)[]{("controlVersion",2),("schemaVersion",4),("observeAttached",true),("denialAttached",true),("configMapFrozen",false),("scratchMapFrozen",false),("targetPinned",false),("mode",1),("providerEpoch",0),("providerEpoch","18446744073709551615"),("providerEpoch",JsonNode.Parse("1e1")),("targetInode",0),("targetDevice",0),("activationNonce",new string('0',32)),("activationNonce",new string('A',32)),("activationFrame","one-command"),("lostMapId",11),("scratchMapId",0),("loadedProgramIds",JsonSerializer.SerializeToNode(new[]{1,2,3,4,4})),("attachedProgramIds",JsonSerializer.SerializeToNode(new[]{2,3,5})),("lostAtReady",null)})
        {
            var value=ready.DeepClone().AsObject();value[change.Name]=change.Value?.DeepClone();Reject(()=>LinuxControlledLoaderProtocol.ParseReady(Encode(value)),"ready rejects "+change.Name+" = "+change.Value);
        }
        foreach(var missing in ready.Select(x=>x.Key).ToArray())
        {var value=ready.DeepClone().AsObject();value.Remove(missing);Reject(()=>LinuxControlledLoaderProtocol.ParseReady(Encode(value)),"ready requires explicit field "+missing);}
        var duplicate=Encoding.UTF8.GetString(Encode(ready)).Replace("\"controlledReady\":true","\"controlledReady\":false,\"controlledReady\":true",StringComparison.Ordinal);
        Reject(()=>LinuxControlledLoaderProtocol.ParseReady(Encoding.UTF8.GetBytes(duplicate)),"duplicate keys cannot hide contradictory evidence");
        var oversized=new byte[4097];Reject(()=>LinuxControlledLoaderProtocol.ParseReady(oversized),"control frame byte bound enforced before parsing");
        foreach(var invalid in new[]{"",new string('0',32),new string('A',32),session+"\n",Guid.NewGuid().ToString("D")})Reject(()=>LinuxControlledLoaderProtocol.ActivationFrame(parsed,invalid),"noncanonical activation session rejected");
        var active=JsonSerializer.SerializeToNode(new{controlledActivated=true,controlVersion=1,sessionId=session,providerEpoch=ulong.MaxValue,activationNonce=parsed.Nonce,attachedProgramIds=new uint[]{2,3,4,1,5},observeAttached=true,denialAttached=true,lostAtActivation=parsed.Lost+7})!.AsObject();
        Check(LinuxControlledLoaderProtocol.ParseActivated(Encode(active),parsed,session).Lost==parsed.Lost+7,"activation loss count increase is retained for source fault handling");
        foreach(var change in new (string Name,JsonNode? Value)[]{("sessionId",new string('2',32)),("providerEpoch",1),("activationNonce",new string('f',32)),("attachedProgramIds",JsonSerializer.SerializeToNode(new[]{1,2,3,4,5})),("observeAttached",false),("denialAttached",false)})
        {var value=active.DeepClone().AsObject();value[change.Name]=change.Value?.DeepClone();Reject(()=>LinuxControlledLoaderProtocol.ParseActivated(Encode(value),parsed,session),"acknowledgement rejects mismatched "+change.Name);}
        var completed=JsonSerializer.SerializeToNode(new{controlledComplete=true,controlVersion=1,activated=true,observerAttempted=true,reason="CONTROLLED_STOPPED",nativeError=0,retainedLinksDestroyed=5,drainResult=0,lost=7,lostError=(int?)null})!.AsObject();
        Check(LinuxControlledLoaderProtocol.ParseCompletion(Encode(completed)).Lost==7,"normal final loss sample remains explicit");
        completed["lost"]=null;completed["lostError"]=5;
        Check(LinuxControlledLoaderProtocol.ParseCompletion(Encode(completed)) is {Lost:null,LostError:5},"counter lookup failure retains unavailable state and native errno");
        foreach(var change in new (string Name,JsonNode? Value)[]{("lost",7),("lostError",null),("lostError",0),("observerAttempted",false),("retainedLinksDestroyed",4),("retainedLinksDestroyed",6),("reason","not a stable code")})
        {var value=completed.DeepClone().AsObject();value[change.Name]=change.Value?.DeepClone();Reject(()=>LinuxControlledLoaderProtocol.ParseCompletion(Encode(value)),"completion rejects inconsistent "+change.Name);}
        completed["activated"]=false;completed["retainedLinksDestroyed"]=4;completed["reason"]="ACTIVATION_UNKNOWN";
        Check(LinuxControlledLoaderProtocol.ParseCompletion(Encode(completed)) is {Activated:false,ObserverAttempted:true},"partial activation preserves possible observation without a success claim");
        Console.WriteLine(JsonSerializer.Serialize(new{Passed=true,Checks=checks,Scope="Controlled loader protocol only; no attachment, source activation, persistence or deployment"}));
    }
}
