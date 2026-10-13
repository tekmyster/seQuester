using RansomFree.Contracts;
using System.Buffers.Binary;
using System.ComponentModel;
using System.Text;
using System.Text.Json;
using RansomFree.Client;

internal static class ControlledMapSetChecks
{
    internal static void Run()
    {
        var checks=0;void Check(bool value,string label){if(!value)throw new InvalidDataException(label);checks++;}
        var ready=LinuxControlledLoaderProtocol.ParseReady(ControlledProtocolV2Checks.Encode(ControlledProtocolV2Checks.Ready()));
        void Reject(Action<Fake[]> corrupt,string label,int? failAt=null,LinuxControlledTargetSet? expected=null)
        {
            var readers=Make(ready);corrupt(readers);var opened=0;
            ILinuxControlledMapReader Open(uint id){if(failAt==opened)throw new Win32Exception(5);var value=readers[opened++];Check(id==value.Id,"Exact ID open order");return value;}
            try{using var maps=LinuxControlledMapSet.OpenForTest(ready,expected??ready.Targets!,Open);throw new Exception("Unexpected map acceptance: "+label);}
            catch(Exception ex)when(ex is InvalidDataException or Win32Exception or AggregateException)
            {Check(readers.Take(opened).All(r=>r.Closes==1)&&readers.Skip(opened).All(r=>r.Closes==0),label+" closes all and only owned descriptors");}
        }
        for(var map=0;map<5;map++)for(var field=0;field<7;field++)
        {var m=map;var f=field;Reject(r=>r[m].Info[f*4]^=1,"Map layout/name field mismatch");}
        for(var map=0;map<5;map++)
        {
            var m=map;Reject(_=>{},"Nth map open failure",map);Reject(r=>r[m].InfoFailure=true,"Nth map info failure");
            Reject(r=>r[m].ReturnedLength=39,"Truncated info response");Reject(r=>r[m].ReturnedLength=41,"Oversized info response");Reject(r=>r[m].Info=new byte[39],"Truncated info buffer");
        }
        foreach(var offset in new[]{0,8,16,20})Reject(r=>r[1].Value[offset]^=1,"Wrong config target/epoch/mode");
        Reject(r=>r[1].Value=new byte[23],"Short config");Reject(r=>r[3].Value[0]=1,"Ready loss changed");Reject(r=>r[3].Value=new byte[7],"Short loss");
        foreach(var map in new[]{1,3,4})Reject(r=>r[map].LookupFailure=true,"Config/loss/watch read error");
        Reject(r=>r[4].NextFailure=true,"Enumeration errno");Reject(r=>r[4].Keys.RemoveAt(1),"Missing watch row");
        Reject(r=>r[4].Keys[0][12]=1,"Nonzero key reserved");Reject(r=>r[4].Rows[0][4]=1,"Nonzero value reserved");
        Reject(r=>r[4].Rows[0][0]=32,"Out of range ordinal");Reject(r=>r[4].Rows[1][0]=0,"Duplicate ordinal");
        Reject(r=>r[4].Keys[0][0]^=1,"Wrong target inode");Reject(r=>r[4].Keys[0][8]^=1,"Wrong target device");
        Reject(r=>r[4].Keys[0]=new byte[15],"Short key");Reject(r=>r[4].Rows[0]=new byte[7],"Short value");
        Reject(r=>{r[4].Keys.Add(r[4].Keys[0]);r[4].Rows.Add(r[4].Rows[0]);},"Duplicate extra key cannot loop forever");
        Reject(r=>{r[4].Keys[0][12]=1;r[0].CloseFailure=true;r[4].CloseFailure=true;},"Admission plus multiple close failures retain all errors");
        Reject(_=>{},"Wrong prepared target set before opening anything",expected:LinuxControlledTargetSet.Prepare([new(1,1)]));
        foreach(var count in new[]{1,2,32})
        {
            var source=LinuxControlledLoaderProtocol.ParseReady(ControlledProtocolV2Checks.Encode(ControlledProtocolV2Checks.Ready(count)));var readers=Make(source);var opened=0;
            var maps=LinuxControlledMapSet.OpenForTest(source,source.Targets!,_=>readers[opened++]);
            Check(maps.Verified.Maps.Length==5&&maps.Verified.TargetSetSha256==source.Targets!.Digest&&maps.Verified.ProviderEpoch==source.Epoch&&maps.Verified.InitialLost==source.Lost,"Exact independently verified source proof");
            Check(maps.MatchesReadyFrame(source.Raw),"Exact ready frame binds every retained map role and source field");
            foreach(var field in new[]{"scratchMapId","configMapId","eventsMapId","lostMapId","watchMapId","activationNonce","providerEpoch","targetCount"})
            {
                var mutated=System.Text.Json.Nodes.JsonNode.Parse(source.Raw)!;
                mutated[field]=field=="activationNonce"?System.Text.Json.Nodes.JsonValue.Create(new string('b',32)):System.Text.Json.Nodes.JsonValue.Create(999);
                Check(!maps.MatchesReadyFrame(JsonSerializer.SerializeToUtf8Bytes(mutated)),"Changed ready field cannot reuse retained map proof: "+field);
            }
            Check(!maps.MatchesReadyFrame(source.Raw.AsSpan(0,source.Raw.Length-1)),"Truncated ready cannot match owned proof");
            Check(readers[0].Lookups==0&&readers[2].Lookups==0&&readers[1].Lookups==1&&readers[3].Lookups==1&&readers[4].Lookups==count&&readers[4].Nexts==count+1,"Only config/loss and bounded watched keys are read");
            maps.Dispose();maps.Dispose();Check(readers.All(r=>r.Closes==1),"Every descriptor closed exactly once");
            Check(!maps.MatchesReadyFrame(source.Raw),"Disposed map owner cannot reuse saved ready proof");
        }
        Console.WriteLine(JsonSerializer.Serialize(new{Passed=true,Checks=checks,Scope="Independent map identity, exact prepared targets, bounded enumeration and cleanup with injected transport; native ABI requires separate owned VM qualification"}));
    }
    internal static void RunNative(string readyPath,string preparedPath)
    {
        if(!OperatingSystem.IsLinux()||File.ReadAllText("/sys/class/dmi/id/product_uuid").Trim().ToLowerInvariant()!="82082842-9a2e-bd81-8cc0-1b589de10dc2"||Directory.EnumerateDirectories("/sys/class/net").Any(p=>Directory.Exists(Path.Combine(p,"device"))))throw new InvalidOperationException("Owned zero-NIC qualification VM required");
        var ready=LinuxControlledLoaderProtocol.ParseReady(File.ReadAllBytes(readyPath));using var doc=JsonDocument.Parse(File.ReadAllBytes(preparedPath));
        var expected=LinuxControlledTargetSet.Prepare(doc.RootElement.EnumerateArray().Select(x=>new LinuxControlledTargetSet.Identity(x.GetProperty("device").GetUInt32(),x.GetProperty("inode").GetUInt64())));
        try
        {
            using var maps=LinuxControlledMapSet.Open(ready,expected);var proof=maps.Verified;maps.Dispose();
            Console.WriteLine(JsonSerializer.Serialize(new{Passed=true,Proof=proof,ReadOnlyDescriptors=true,Closed=true}));
        }
        catch(Exception ex)when(ex is InvalidDataException or Win32Exception or AggregateException)
        {Console.WriteLine(JsonSerializer.Serialize(new{Passed=false,Error=ex.GetType().Name,Code=ex is Win32Exception native?native.NativeErrorCode:(int?)null,Reason=ex.Message}));Environment.ExitCode=15;}
    }
    private static Fake[] Make(LinuxControlledLoaderProtocol.Ready ready)
    {
        Fake[] readers=[new(29,ready.Maps[0],4,8432,0,1,"event_scratch"),new(2,ready.Maps[1],4,24,1,0,"lease_config"),new(27,ready.Maps[2],0,0,1048576,0,"events"),new(2,ready.Maps[3],4,8,1,0,"lost"),new(1,ready.WatchMapId!.Value,16,8,32,128,"watched_targets")];
        readers[1].Value=new byte[24];BinaryPrimitives.WriteUInt64LittleEndian(readers[1].Value.AsSpan(8),ready.Epoch);readers[3].Value=new byte[8];
        for(var i=0;i<ready.Targets!.Targets.Length;i++)
        {
            var target=ready.Targets.Targets[i];var key=new byte[16];BinaryPrimitives.WriteUInt64LittleEndian(key,target.Inode);BinaryPrimitives.WriteUInt32LittleEndian(key.AsSpan(8),target.Device);var value=new byte[8];BinaryPrimitives.WriteUInt32LittleEndian(value,(uint)i);readers[4].Keys.Add(key);readers[4].Rows.Add(value);
        }
        return readers;
    }
    private sealed class Fake:ILinuxControlledMapReader
    {
        internal readonly uint Id;internal byte[] Info=new byte[40],Value=[];internal readonly List<byte[]> Keys=[],Rows=[];
        internal int Closes,Lookups,Nexts;internal uint ReturnedLength=40;internal bool InfoFailure,LookupFailure,NextFailure,CloseFailure;
        internal Fake(uint type,uint id,uint key,uint value,uint count,uint flags,string name)
        {Id=id;uint[] fields=[type,id,key,value,count,flags];for(var n=0;n<6;n++)BinaryPrimitives.WriteUInt32LittleEndian(Info.AsSpan(n*4),fields[n]);Encoding.ASCII.GetBytes(name).CopyTo(Info,24);}
        public byte[] ReadInfo(out uint length){length=ReturnedLength;if(InfoFailure)throw new Win32Exception(5);return Info.ToArray();}
        public byte[] Lookup(byte[] key,int size){Lookups++;if(LookupFailure)throw new Win32Exception(5);return (Id==15?Rows[Nexts-1]:Value).ToArray();}
        public byte[]? NextKey(byte[]? previous,int size){if(NextFailure)throw new Win32Exception(5);var index=Nexts++;return index<Keys.Count?Keys[index].ToArray():null;}
        public void Dispose(){Closes++;if(CloseFailure)throw new Win32Exception(5);}
    }
}
