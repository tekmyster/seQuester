using RansomFree.Contracts;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using RansomFree.Client;

internal static class ControlledProtocolV2Checks
{
    internal static void ReadNativeReady(string path)
    {
        var raw=File.ReadAllBytes(path);var ready=LinuxControlledLoaderProtocol.ParseReady(raw);
        if(ready.ControlVersion!=2||ready.Targets?.Targets.Length!=32||ready.Targets.Targets[^1].Inode!=ulong.MaxValue||ready.Epoch!=ulong.MaxValue||ready.Lost!=ulong.MaxValue)
            throw new InvalidDataException("Exact maximum-width native encoder fixture required");
        Console.WriteLine(JsonSerializer.Serialize(new{Passed=true,NativeBytes=raw.Length,TargetCount=ready.Targets.Targets.Length,ready.Targets.Digest,Scope="Actual native C ready encoder bytes accepted by managed strict v2 parser; no native activation"}));
    }
    internal static JsonObject Ready(int count=2)=>JsonSerializer.SerializeToNode(new{
        controlledReady=true,controlVersion=2,schemaVersion=6,
        loadedProgramIds=new uint[]{1,2,3,4,5},attachedProgramIds=new uint[]{2,3,4},
        observeAttached=false,denialAttached=false,scratchMapFrozen=true,scratchMapId=11,
        configMapFrozen=true,configMapId=12,eventsMapId=13,lostMapId=14,
        providerEpoch=123,activationNonce=new string('a',32),targetCount=count,
        targets=Enumerable.Range(0,count).Select(i=>new{ordinal=i,device=uint.MaxValue,inode=ulong.MaxValue-(ulong)(count-1-i)}),
        targetsPinned=true,watchMapId=15,watchMapFrozen=true,mode=0,lostAtReady=0,
        activationFrame="one-command-then-eof"})!.AsObject();
    internal static byte[] Encode(JsonObject value)=>JsonSerializer.SerializeToUtf8Bytes(value);
    internal static void Run()
    {
        var checks=0;
        void Check(bool value,string label){checks++;if(!value)throw new IOException(label);}
        void Reject(Action action,string label){try{action();}catch(InvalidDataException){Check(true,label);return;}throw new IOException("Accepted "+label);}
        var ready=Ready();var parsed=LinuxControlledLoaderProtocol.ParseReady(Encode(ready));
        Check(parsed.ControlVersion==2&&parsed.SchemaVersion==6&&parsed.TargetInode==null&&parsed.TargetDevice==null&&parsed.WatchMapId==15&&parsed.Targets!.Targets.Length==2,"v2 has explicit versioned identities; no invented v1 target");
        Check(parsed.Maps.SequenceEqual(new uint[]{11,12,13,14}),"first four native map positions remain compatible");
        const string session="11111111111111111111111111111111";
        Check(Encoding.ASCII.GetString(LinuxControlledLoaderProtocol.ActivationFrame(parsed,session))=="ACTIVATE "+session+" 123 "+new string('a',32)+"\n","v2 activation binds the exact persisted ready epoch and nonce");
        foreach(var change in new (string Name,JsonNode? Value)[]{("controlVersion",1),("controlVersion",3),("schemaVersion",5),("watchMapId",14),("watchMapId",0),("watchMapFrozen",false),("targetsPinned",false),("targetCount",0),("targetCount",33),("targetCount",1),("targets",null),("targetPinned",true),("targetInode",1),("targetDevice",1),("mode",1)})
        {var value=ready.DeepClone().AsObject();value[change.Name]=change.Value?.DeepClone();Reject(()=>LinuxControlledLoaderProtocol.ParseReady(Encode(value)),"v2 field "+change.Name);}
        foreach(var field in new[]{"targets","targetCount","watchMapId","watchMapFrozen","targetsPinned"})
        {var value=ready.DeepClone().AsObject();value.Remove(field);Reject(()=>LinuxControlledLoaderProtocol.ParseReady(Encode(value)),"missing "+field);}
        var forged=new LinuxControlledLoaderProtocol.Ready(parsed.Epoch,parsed.Nonce,15,LinuxControlledTargetSet.Prepare(new[]{new LinuxControlledTargetSet.Identity(1,1)}),parsed.Lost,parsed.Programs,parsed.Maps,parsed.Raw);
        Reject(()=>LinuxControlledLoaderProtocol.ActivationFrame(forged,session),"in-memory table cannot differ from exact native ready bytes");
        var active=JsonSerializer.SerializeToNode(new{controlledActivated=true,controlVersion=2,sessionId=session,providerEpoch=123,activationNonce=parsed.Nonce,attachedProgramIds=new[]{2,3,4,1,5},observeAttached=true,denialAttached=true,lostAtActivation=0})!.AsObject();
        Check(LinuxControlledLoaderProtocol.ParseActivated(Encode(active),parsed,session).Lost==0,"matching v2 activation accepted");
        active["controlVersion"]=1;Reject(()=>LinuxControlledLoaderProtocol.ParseActivated(Encode(active),parsed,session),"legacy acknowledgement cannot activate v2");
        var complete=JsonSerializer.SerializeToNode(new{controlledComplete=true,controlVersion=2,activated=true,observerAttempted=true,reason="CONTROLLED_STOPPED",nativeError=0,retainedLinksDestroyed=5,drainResult=0,lost=0,lostError=(int?)null})!.AsObject();
        Check(LinuxControlledLoaderProtocol.ParseCompletion(Encode(complete),2).ControlVersion==2,"completion retains v2");
        Reject(()=>LinuxControlledLoaderProtocol.ParseCompletion(Encode(complete),1),"v2 completion cannot finish v1 source");
        complete["controlVersion"]=1;Reject(()=>LinuxControlledLoaderProtocol.ParseCompletion(Encode(complete),2),"v1 completion cannot finish v2 source");
        complete["controlVersion"]=3;Reject(()=>LinuxControlledLoaderProtocol.ParseCompletion(Encode(complete)),"unknown completion version");
        var maximum=Encode(Ready(32));var maxParsed=LinuxControlledLoaderProtocol.ParseReady(maximum);
        Check(maxParsed.Targets!.Targets.Length==32&&maximum.Length<4096,"actual full JSON ready frame fits 32 maximal-width tuples");
        var padded=maximum.Concat(Enumerable.Repeat((byte)' ',4096-maximum.Length)).ToArray();
        Check(LinuxControlledLoaderProtocol.ParseReady(padded).Targets!.Digest==maxParsed.Targets.Digest,"4096-byte inclusive frame limit");
        Reject(()=>LinuxControlledLoaderProtocol.ParseReady(padded.Concat(new byte[]{32}).ToArray()),"4097-byte frame rejected");
        Check(LinuxControlledLoaderProtocol.ParseReady(Encode(Ready(1))).Targets!.Targets.Length==1,"v2 single target supported without v1 fallback");
        Console.WriteLine(JsonSerializer.Serialize(new{Passed=true,Checks=checks,MaximumReadyBytes=maximum.Length,Scope="Managed control-v2 parser and exact table binding only; no qualified v2 launch or native map"}));
    }
}
