using System.Buffers.Binary;
using System.ComponentModel;
using System.Globalization;
using System.Text;
using System.Text.Json;
using RansomFree.Client;

static class LostMapChecks
{
    internal static void Run()
    {
        var checks=0;void Check(bool ok,string label){if(!ok)throw new Exception(label);checks++;Console.WriteLine("PASS: "+label);}
        void Reject(Transport t,string label,uint mapId=42,ulong sample=0)
        {try{using var map=LinuxBpfLostMap.OpenForTest(t,mapId,sample);}catch(Exception ex)when(ex is InvalidDataException or Win32Exception){Check(t.Disposals==1,label+"; owned handle closed");return;}throw new Exception("Unexpected map acceptance: "+label);}
        foreach(var offset in new[]{0,4,8,12,16,20})
        {var t=new Transport();t.Info[offset]^=1;Reject(t,"wrong map metadata rejected at field "+offset);Check(t.CounterReads==0,"invalid map metadata cannot become an initial counter");}
        {var t=new Transport();t.Info[24]=(byte)'x';Reject(t,"different named map rejected");}
        {var t=new Transport();t.Info[39]=1;Reject(t,"noncanonical map-name suffix rejected");}
        Reject(new Transport{Length=39},"short native identity response rejected");Reject(new Transport{Info=new byte[39]},"short allocated identity prefix rejected");
        Reject(new Transport(),"zero expected map identity rejected",0);Reject(new Transport{Counter=9},"mismatched initial ready sample rejected");
        Reject(new Transport{InfoFailure=true},"identity lookup failure retains OS error");Reject(new Transport{CounterFailure=true},"counter lookup failure never manufactures zero");
        var live=new Transport();var retained=LinuxBpfLostMap.OpenForTest(live,42,0);Check(retained.Identity is {Type:2,Id:42,KeySize:4,ValueSize:8,Entries:1,Flags:0,Name:"lost"},"exact qualified array-map identity retained");
        live.Counter=ulong.MaxValue;Check(retained.Sample()==ulong.MaxValue,"full-width unsigned counter returned without rounding");
        live.Counter=0;Check(retained.Sample()==0,"counter reset is exposed as observed value for source fault handling");
        Check(live.InfoReads==1&&live.CounterReads==3,"same retained handle sampled without repeated ID lookup or metadata substitution");
        live.CounterFailure=true;try{retained.Sample();throw new Exception("Failed lookup returned invented data");}catch(Win32Exception ex){Check(ex.NativeErrorCode==5,"active lookup keeps raw native errno");}
        retained.Dispose();retained.Dispose();Check(live.Disposals==1,"owned map descriptor disposed once");
        var before=live.CounterReads;try{retained.Sample();throw new Exception("Closed descriptor sampled");}catch(ObjectDisposedException){Check(live.CounterReads==before,"closed map cannot perform another lookup");}
        var atomic=new Transport{Counters=new ulong[6]};
        BinaryPrimitives.WriteUInt32LittleEndian(atomic.Info.AsSpan(16),6);
        atomic.Info.AsSpan(24).Clear();"op_health"u8.CopyTo(atomic.Info.AsSpan(24));
        using(var detailed=LinuxBpfLostMap.OpenForTest(atomic,42,0,atomic:true))
        {
            Check(detailed.SampleDetailed().Values.SequenceEqual(new ulong[6]),"atomic diagnostics retain all six observed zero counters");
            for(var i=0;i<6;i++)
            {
                Array.Clear(atomic.Counters);atomic.Counters[i]=12;
                var sample=detailed.SampleDetailed();
                Check(sample.Total==12&&sample.Values.SequenceEqual(atomic.Counters)&&detailed.Sample()==12,"exact counter category and unchanged aggregate: "+i);
                atomic.Counters[i]=13;
                Check(sample.Values[i]==12,"observed counter snapshot cannot change with later transport values: "+i);
            }
            atomic.CounterFailure=true;
            try{detailed.SampleDetailed();throw new Exception("Failed diagnostic read fabricated counters");}
            catch(Win32Exception ex){Check(ex.NativeErrorCode==5,"diagnostic read failure retains native errno instead of zero counters");}
            atomic.CounterFailure=false;Array.Clear(atomic.Counters);atomic.Counters[0]=ulong.MaxValue;atomic.Counters[1]=1;
            try{detailed.SampleDetailed();throw new Exception("Diagnostic total wrapped");}
            catch(OverflowException){Check(true,"diagnostic aggregate rejects unsigned overflow");}
        }
        Check(atomic.Disposals==1,"atomic diagnostic descriptor closed once");
        Console.WriteLine(JsonSerializer.Serialize(new{Passed=true,Checks=checks,Scope="Map identity, counter and lifecycle logic with injected transport; native interop requires owned Linux gate"}));
    }
    internal static async Task RunNative(string idText,string sampleText)
    {
        if(!OperatingSystem.IsLinux()||File.ReadAllText("/sys/class/dmi/id/product_uuid").Trim().ToLowerInvariant()!="82082842-9a2e-bd81-8cc0-1b589de10dc2"||Directory.EnumerateDirectories("/sys/class/net").Any(p=>Directory.Exists(Path.Combine(p,"device"))))throw new InvalidOperationException("Owned zero-NIC qualification VM required");
        var id=uint.Parse(idText,NumberStyles.None,CultureInfo.InvariantCulture);var sample=ulong.Parse(sampleText,NumberStyles.None,CultureInfo.InvariantCulture);
        try
        {
            using var map=LinuxBpfLostMap.Open(id,sample);var reader=new LinuxLoaderFrameReader(Console.OpenStandardInput(),128);
            Console.WriteLine(JsonSerializer.Serialize(new{Ready=true,Identity=map.Identity,Initial=map.InitialValue.ToString(CultureInfo.InvariantCulture),ReadOnlyDescriptorFlagsVerified=true}));
            while(await reader.ReadAsync() is {} raw)
            {
                var command=Encoding.ASCII.GetString(raw);if(command=="close")break;
                if(command!="sample")throw new InvalidDataException("Unexpected owned map probe command");
                Console.WriteLine(JsonSerializer.Serialize(new{Sample=map.Sample().ToString(CultureInfo.InvariantCulture)}));
            }
            map.Dispose();Console.WriteLine(JsonSerializer.Serialize(new{Closed=true}));
        }
        catch(Exception ex)when(ex is Win32Exception or InvalidDataException)
        {Console.WriteLine(JsonSerializer.Serialize(new{Failed=true,Error=ex.GetType().Name,Code=ex is Win32Exception native?native.NativeErrorCode:(int?)null,Reason=ex.Message}));Environment.ExitCode=15;}
    }
    private sealed class Transport:ILinuxLostMapTransport
    {
        internal byte[] Info=new byte[40];internal uint Length=40;internal ulong Counter;internal ulong[]? Counters;internal bool InfoFailure,CounterFailure;internal int InfoReads,CounterReads,Disposals;
        internal Transport(){uint[] values=[2,42,4,8,1,0];for(var i=0;i<values.Length;i++)BinaryPrimitives.WriteUInt32LittleEndian(Info.AsSpan(4*i),values[i]);"lost"u8.CopyTo(Info.AsSpan(24));}
        public byte[] ReadInfo(out uint length){InfoReads++;length=Length;if(InfoFailure)throw new Win32Exception(5);return Info.ToArray();}
        public ulong ReadCounter(){CounterReads++;if(CounterFailure)throw new Win32Exception(5);return Counter;}
        public ulong ReadCounter(uint key){CounterReads++;if(CounterFailure)throw new Win32Exception(5);return Counters==null?Counter:Counters[key];}
        public void Dispose()=>Disposals++;
    }
}
