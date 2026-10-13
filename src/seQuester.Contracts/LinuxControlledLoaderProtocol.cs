using System.Collections.Immutable;
using System.Globalization;
using System.Text;
using System.Text.Json;

namespace RansomFree.Contracts;

// Control frames are separate from native observations. No native
// open/attach, journal commitment or I/O cancellation occurs in this parser.
internal static class LinuxControlledLoaderProtocol
{
    internal sealed class Ready
    {
        internal ulong Epoch { get; }
        internal string Nonce { get; }
        internal uint ControlVersion { get; }
        internal uint SchemaVersion => ControlVersion==1?5u:ControlVersion==2?6u:ControlVersion==3?7u:8u;
        internal uint? FileCallMapId {get;}
        internal uint? ScalarCallMapId {get;}
        internal uint? IterCallMapId {get;}
        internal ImmutableArray<ulong> HealthAtReady {get;}=[];
        internal ulong? TargetInode { get; }
        internal uint? TargetDevice { get; }
        internal uint? WatchMapId { get; }
        internal LinuxControlledTargetSet? Targets { get; }
        internal ulong Lost { get; }
        internal ImmutableArray<uint> Programs { get; }
        internal ImmutableArray<uint> Maps { get; }
        internal byte[] Raw => raw.ToArray();
        private readonly byte[] raw;
        internal Ready(ulong epoch,string nonce,ulong inode,uint device,ulong lost,ImmutableArray<uint> programs,ImmutableArray<uint> maps,byte[] raw)
        {ControlVersion=1;Epoch=epoch;Nonce=nonce;TargetInode=inode;TargetDevice=device;Lost=lost;Programs=programs;Maps=maps;this.raw=raw.ToArray();}
        internal Ready(ulong epoch,string nonce,uint watchMapId,LinuxControlledTargetSet targets,ulong lost,ImmutableArray<uint> programs,ImmutableArray<uint> maps,byte[] raw)
        {ControlVersion=2;Epoch=epoch;Nonce=nonce;WatchMapId=watchMapId;Targets=targets;Lost=lost;Programs=programs;Maps=maps;this.raw=raw.ToArray();}
        internal Ready(ulong epoch,string nonce,uint watchMapId,uint fileCallMapId,LinuxControlledTargetSet targets,ImmutableArray<ulong> health,ImmutableArray<uint> programs,ImmutableArray<uint> maps,byte[] raw,uint? scalarCallMapId=null,uint? iterCallMapId=null)
        {ControlVersion=scalarCallMapId==null?3u:4u;ScalarCallMapId=scalarCallMapId;IterCallMapId=iterCallMapId;Epoch=epoch;Nonce=nonce;WatchMapId=watchMapId;FileCallMapId=fileCallMapId;Targets=targets;HealthAtReady=health;Lost=health.Aggregate(0UL,(sum,value)=>checked(sum+value));Programs=programs;Maps=maps;this.raw=raw.ToArray();}
    }
    internal sealed record Activated(string SessionId,ulong Lost);
    internal sealed record Completion(bool Activated,bool ObserverAttempted,string Reason,int NativeError,uint ReturnedLinkCount,int DrainResult,ulong? Lost,int? LostError,uint ControlVersion);
    private static readonly string[] ReadyFields=["controlledReady","controlVersion","schemaVersion","loadedProgramIds","attachedProgramIds","observeAttached","denialAttached","scratchMapFrozen","scratchMapId","configMapFrozen","configMapId","eventsMapId","lostMapId","providerEpoch","activationNonce","targetInode","targetDevice","targetPinned","mode","lostAtReady","activationFrame"];
    private static readonly string[] ReadyV2Fields=["controlledReady","controlVersion","schemaVersion","loadedProgramIds","attachedProgramIds","observeAttached","denialAttached","scratchMapFrozen","scratchMapId","configMapFrozen","configMapId","eventsMapId","lostMapId","providerEpoch","activationNonce","targetCount","targets","targetsPinned","watchMapId","watchMapFrozen","mode","lostAtReady","activationFrame"];
    private static readonly string[] ReadyV3Fields=["controlledReady","controlVersion","schemaVersion","loadedProgramIds","attachedProgramIds","permissionAttached","scratchMapFrozen","scratchMapId","fileCallMapId","fileCallMapFrozen","configMapFrozen","configMapId","eventsMapId","lostMapId","providerEpoch","activationNonce","targetCount","targets","targetsPinned","watchMapId","watchMapFrozen","mode","healthAtReady","activationFrame"];
    private static readonly string[] ReadyV4Fields=[..ReadyV3Fields,"ioAttached","scalarCallMapId","scalarCallMapFrozen","iterCallMapId","iterCallMapFrozen"];
    private static readonly string[] ActiveFields=["controlledActivated","controlVersion","sessionId","providerEpoch","activationNonce","attachedProgramIds","observeAttached","denialAttached","lostAtActivation"];
    private static readonly string[] ActiveV3Fields=["controlledActivated","controlVersion","sessionId","providerEpoch","activationNonce","attachedProgramIds","permissionAttached","lostAtActivation"];
    private static readonly string[] ActiveV4Fields=[..ActiveV3Fields,"ioAttached"];
    private static readonly string[] CompleteFields=["controlledComplete","controlVersion","activated","observerAttempted","reason","nativeError","retainedLinksDestroyed","drainResult","lost","lostError"];
    private static bool Hex(string? value,int length)=>value is not null&&value.Length==length&&value.Any(x=>x!='0')&&value.All(x=>x is >= '0' and <= '9' or >= 'a' and <= 'f');
    private static InvalidDataException Invalid()=>new("Invalid or inconsistent controlled loader frame");
    private static JsonDocument Document(ReadOnlyMemory<byte> raw,string[]? fields)
    {
        if(raw.Length is <2 or >4096)throw Invalid();
        JsonDocument? document=null;
        try
        {
            document=JsonDocument.Parse(raw,new(){MaxDepth=4});var root=document.RootElement;
            if(root.ValueKind!=JsonValueKind.Object)throw Invalid();
            var names=root.EnumerateObject().Select(x=>x.Name).ToArray();
            // Select the ready layout only after rejecting duplicate keys. A
            // version switch cannot conceal contradictory legacy/v2 evidence.
            if(names.Distinct(StringComparer.Ordinal).Count()!=names.Length)throw Invalid();
            if(fields==null)
            {
                if(!root.TryGetProperty("controlVersion",out var version))throw Invalid();
                fields=Number(version) switch {1=>ReadyFields,2=>ReadyV2Fields,3=>ReadyV3Fields,4=>ReadyV4Fields,_=>throw Invalid()};
            }
            if(names.Length!=fields.Length||names.Distinct(StringComparer.Ordinal).Count()!=names.Length||names.Except(fields,StringComparer.Ordinal).Any())throw Invalid();
            return document;
        }
        catch(Exception ex)when(ex is JsonException or InvalidDataException){document?.Dispose();throw new InvalidDataException("Malformed controlled loader frame",ex);}
    }
    private static ulong Number(JsonElement value)
    {
        if(value.ValueKind!=JsonValueKind.Number||!value.TryGetUInt64(out var n)||n.ToString(CultureInfo.InvariantCulture)!=value.GetRawText())throw Invalid();return n;
    }
    private static ulong Number(JsonElement root,string name)=>Number(root.GetProperty(name));
    private static uint Id(JsonElement root,string name)
    {var n=Number(root,name);if(n is 0 or >uint.MaxValue)throw Invalid();return (uint)n;}
    private static bool Boolean(JsonElement root,string name)
    {var v=root.GetProperty(name);if(v.ValueKind is not (JsonValueKind.True or JsonValueKind.False))throw Invalid();return v.GetBoolean();}
    private static string Text(JsonElement root,string name)
    {var v=root.GetProperty(name);if(v.ValueKind!=JsonValueKind.String)throw Invalid();return v.GetString()!;}
    private static ImmutableArray<uint> Ids(JsonElement root,string name,int count)
    {
        var value=root.GetProperty(name);if(value.ValueKind!=JsonValueKind.Array||value.GetArrayLength()!=count)throw Invalid();
        var ids=value.EnumerateArray().Select(x=>Number(x)).ToArray();if(ids.Any(x=>x is 0 or >uint.MaxValue)||ids.Distinct().Count()!=count)throw Invalid();
        return ids.Select(x=>(uint)x).ToImmutableArray();
    }
    private static int Signed(JsonElement root,string name)
    {var v=root.GetProperty(name);if(v.ValueKind!=JsonValueKind.Number||!v.TryGetInt32(out var n)||n.ToString(CultureInfo.InvariantCulture)!=v.GetRawText())throw Invalid();return n;}
    internal static Ready ParseReady(ReadOnlyMemory<byte> raw)
    {
        using var document=Document(raw,null);var r=document.RootElement;var version=Number(r,"controlVersion");
        if(version is 3 or 4)return ParseReadyV3(r,raw);
        if(!Boolean(r,"controlledReady")||Number(r,"schemaVersion")!=(version==1?5u:6u)||Boolean(r,"observeAttached")||Boolean(r,"denialAttached")||
            !Boolean(r,"scratchMapFrozen")||!Boolean(r,"configMapFrozen")||!Boolean(r,version==1?"targetPinned":"targetsPinned")||Number(r,"mode")!=0||Text(r,"activationFrame")!="one-command-then-eof")throw Invalid();
        var programs=Ids(r,"loadedProgramIds",5);var attached=Ids(r,"attachedProgramIds",3);
        if(!attached.SequenceEqual(programs.Skip(1).Take(3)))throw Invalid();
        var maps=new[]{Id(r,"scratchMapId"),Id(r,"configMapId"),Id(r,"eventsMapId"),Id(r,"lostMapId")}.ToImmutableArray();
        var epoch=Number(r,"providerEpoch");var nonce=Text(r,"activationNonce");
        if(epoch==0||!Hex(nonce,32)||maps.Distinct().Count()!=4)throw Invalid();
        if(version==1)
        {
            var inode=Number(r,"targetInode");if(inode==0)throw Invalid();
            return new(epoch,nonce,inode,Id(r,"targetDevice"),Number(r,"lostAtReady"),programs,maps,raw.ToArray());
        }
        var count=Number(r,"targetCount");var watchMap=Id(r,"watchMapId");
        if(count is <1 or >LinuxControlledTargetSet.MaximumTargets||maps.Contains(watchMap)||!Boolean(r,"watchMapFrozen"))throw Invalid();
        return new(epoch,nonce,watchMap,LinuxControlledTargetSet.Parse(r.GetProperty("targets"),(int)count),Number(r,"lostAtReady"),programs,maps,raw.ToArray());
    }
    private static Ready ParseReadyV3(JsonElement r,ReadOnlyMemory<byte> raw)
    {
        var io=Number(r,"controlVersion")==4;
        if(!Boolean(r,"controlledReady")||Number(r,"schemaVersion")!=(io?8u:7u)||Boolean(r,"permissionAttached")||!Boolean(r,"scratchMapFrozen")||!Boolean(r,"fileCallMapFrozen")||
            !Boolean(r,"configMapFrozen")||!Boolean(r,"targetsPinned")||!Boolean(r,"watchMapFrozen")||Number(r,"mode")!=0||Text(r,"activationFrame")!="one-command-then-eof")throw Invalid();
        if(io&&(Boolean(r,"ioAttached")||!Boolean(r,"scalarCallMapFrozen")||!Boolean(r,"iterCallMapFrozen")))throw Invalid();
        var programs=Ids(r,"loadedProgramIds",io?11:7);
        if(!Ids(r,"attachedProgramIds",3).SequenceEqual(programs.Take(3)))throw Invalid();
        var maps=new[]{Id(r,"scratchMapId"),Id(r,"configMapId"),Id(r,"eventsMapId"),Id(r,"lostMapId")}.ToImmutableArray();
        var watch=Id(r,"watchMapId");var file=Id(r,"fileCallMapId");
        uint? scalar=io?Id(r,"scalarCallMapId"):null,iter=io?Id(r,"iterCallMapId"):null;
        if(io?maps.Append(watch).Append(file).Append(scalar!.Value).Append(iter!.Value).Distinct().Count()!=8:maps.Append(watch).Append(file).Distinct().Count()!=6)throw Invalid();
        var epoch=Number(r,"providerEpoch");var nonce=Text(r,"activationNonce");var count=Number(r,"targetCount");
        var healthValue=r.GetProperty("healthAtReady");
        if(epoch==0||!Hex(nonce,32)||count is <1 or >32||healthValue.ValueKind!=JsonValueKind.Array||healthValue.GetArrayLength()!=6)throw Invalid();
        var health=healthValue.EnumerateArray().Select(Number).ToImmutableArray();
        // No observed failure before activation may become a healthy baseline.
        if(health.Any(value=>value!=0))throw Invalid();
        return new(epoch,nonce,watch,file,LinuxControlledTargetSet.Parse(r.GetProperty("targets"),(int)count),health,programs,maps,raw.ToArray(),scalar,iter);
    }
    // Bytes alone do not grant activation. The source may write this frame only
    // after committing its NEW_SESSION_LINKED record, then must close stdin.
    internal static byte[] ActivationFrame(Ready ready,string sessionId)
    {
        if(!Hex(sessionId,32)||!Guid.TryParseExact(sessionId,"N",out _))throw Invalid();
        // Revalidate even internally constructed records; no mutable ID arrays.
        var exact=ParseReady(ready.Raw);
        if(exact.ControlVersion!=ready.ControlVersion||exact.Epoch!=ready.Epoch||exact.Nonce!=ready.Nonce||exact.TargetInode!=ready.TargetInode||exact.TargetDevice!=ready.TargetDevice||exact.WatchMapId!=ready.WatchMapId||exact.FileCallMapId!=ready.FileCallMapId||exact.ScalarCallMapId!=ready.ScalarCallMapId||exact.IterCallMapId!=ready.IterCallMapId||exact.Lost!=ready.Lost||!exact.Programs.SequenceEqual(ready.Programs)||!exact.Maps.SequenceEqual(ready.Maps))throw Invalid();
        if(exact.Targets!=null)exact.Targets.RequireSame(ready.Targets??throw Invalid());
        return Encoding.ASCII.GetBytes("ACTIVATE "+sessionId+" "+ready.Epoch.ToString(CultureInfo.InvariantCulture)+" "+ready.Nonce+"\n");
    }
    internal static Activated ParseActivated(ReadOnlyMemory<byte> raw,Ready ready,string sessionId)
    {
        _=ActivationFrame(ready,sessionId);
        if(ready.ControlVersion is 3 or 4)
        {
            var io=ready.ControlVersion==4;
            using var atomic=Document(raw,io?ActiveV4Fields:ActiveV3Fields);var a=atomic.RootElement;
            var order=io?new[]{0,1,2,4,6,8,10,3,5,7,9}:new[]{0,1,2,4,6,3,5};
            if(!Boolean(a,"controlledActivated")||Number(a,"controlVersion")!=ready.ControlVersion||Text(a,"sessionId")!=sessionId||Number(a,"providerEpoch")!=ready.Epoch||Text(a,"activationNonce")!=ready.Nonce||
                !Boolean(a,"permissionAttached")||io&&!Boolean(a,"ioAttached")||!Ids(a,"attachedProgramIds",order.Length).SequenceEqual(order.Select(n=>ready.Programs[n])))throw Invalid();
            return new(sessionId,Number(a,"lostAtActivation"));
        }
        using var document=Document(raw,ActiveFields);var r=document.RootElement;
        if(!Boolean(r,"controlledActivated")||Number(r,"controlVersion")!=ready.ControlVersion||Text(r,"sessionId")!=sessionId||Number(r,"providerEpoch")!=ready.Epoch||Text(r,"activationNonce")!=ready.Nonce||!Boolean(r,"observeAttached")||!Boolean(r,"denialAttached"))throw Invalid();
        if(!Ids(r,"attachedProgramIds",5).SequenceEqual(new[]{ready.Programs[1],ready.Programs[2],ready.Programs[3],ready.Programs[0],ready.Programs[4]}))throw Invalid();
        return new(sessionId,Number(r,"lostAtActivation"));
    }
    internal static Completion ParseCompletion(ReadOnlyMemory<byte> raw,uint? expectedVersion=null)
    {
        using var document=Document(raw,CompleteFields);var r=document.RootElement;
        var version=Number(r,"controlVersion");
        if(!Boolean(r,"controlledComplete")||version is not (1 or 2 or 3 or 4)||expectedVersion.HasValue&&version!=expectedVersion.Value)throw Invalid();
        var activated=Boolean(r,"activated");var attempted=Boolean(r,"observerAttempted");var reason=Text(r,"reason");var links=Number(r,"retainedLinksDestroyed");
        var maximum=version==4?11UL:version==3?7UL:5UL;
        if(links>maximum||activated&&(!attempted||links!=maximum)||reason.Length is <1 or >128||reason.Any(x=>x is not (>= 'A' and <= 'Z') and not '_'))throw Invalid();
        ulong? lost=r.GetProperty("lost").ValueKind==JsonValueKind.Null?null:Number(r,"lost");
        int? error=r.GetProperty("lostError").ValueKind==JsonValueKind.Null?null:Signed(r,"lostError");
        if(lost.HasValue==error.HasValue||error==0)throw Invalid();
        return new(activated,attempted,reason,Signed(r,"nativeError"),(uint)links,Signed(r,"drainResult"),lost,error,(uint)version);
    }
}
