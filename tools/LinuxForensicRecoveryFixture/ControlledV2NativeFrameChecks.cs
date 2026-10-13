using RansomFree.Contracts;
using System.Globalization;
using System.Text;
using System.Text.Json;
using RansomFree.Client;

internal static class ControlledV2NativeFrameChecks
{
    internal static void Run(string manifestPath)
    {
        using var manifest=JsonDocument.Parse(File.ReadAllBytes(manifestPath));
        if(!manifest.RootElement.GetProperty("Passed").GetBoolean())throw new InvalidDataException("Accepted immutable native manifest required");
        var root=Path.GetDirectoryName(Path.GetFullPath(manifestPath))!;var readies=0;var operations=0;var completions=0;var acknowledgments=0;
        foreach(var item in manifest.RootElement.GetProperty("Cases").EnumerateArray())
        {
            var name=item.GetProperty("Name").GetString()!;
            if(name.Length is <1 or >100||name.Any(c=>!char.IsAsciiLetterOrDigit(c)&&c!='-'&&c!='_'))throw new InvalidDataException("Invalid archive case name");
            var data=File.ReadAllBytes(Path.Combine(root,name+".stdout.jsonl"));
            if(data.Length is <1 or >4*1024*1024)throw new InvalidDataException("Native stdout outside bounded case size");
            LinuxControlledLoaderProtocol.Ready? ready=null;var collector=Guid.NewGuid().ToString("N");long sequence=0;
            var offset=0;
            while(offset<data.Length)
            {
                var next=Array.IndexOf(data,(byte)'\n',offset);if(next<0)throw new InvalidDataException("Native stdout ended in partial frame");
                var raw=new ReadOnlyMemory<byte>(data,offset,next-offset);offset=next+1;
                using var json=JsonDocument.Parse(raw);var r=json.RootElement;
                if(r.TryGetProperty("controlledReady",out _))
                {
                    if(ready!=null)throw new InvalidDataException("Repeated ready");ready=LinuxControlledLoaderProtocol.ParseReady(raw);
                    if(ready.ControlVersion!=2)throw new InvalidDataException("Native v2 ready required");readies++;
                }
                else if(r.TryGetProperty("controlledActivated",out _))
                {
                    if(ready==null)throw new InvalidDataException("ACK precedes ready");
                    LinuxControlledLoaderProtocol.ParseActivated(raw,ready,item.GetProperty("SessionId").GetString()!);acknowledgments++;
                }
                else if(r.TryGetProperty("controlledComplete",out _))
                {LinuxControlledLoaderProtocol.ParseCompletion(raw,2);completions++;}
                else
                {
                    if(ready==null)throw new InvalidDataException("Event has no bound native target set");
                    var decoded=LinuxKernelDecoder.Decode(raw,new string('1',32),collector,++sequence,DateTimeOffset.UtcNow);
                    var kernel=decoded.Attribution!.LinuxKernel!;var target=kernel.TargetIdentity??throw new InvalidDataException("Target identity unavailable in v2 event");
                    if(kernel.Version!=2||kernel.ProviderEpoch!=ready.Epoch.ToString(CultureInfo.InvariantCulture)||ready.Targets?.Contains(target.Ordinal,target.Device,ulong.Parse(target.Inode,CultureInfo.InvariantCulture))!=true)
                        throw new InvalidDataException("Actual native event did not match its ready revision");
                    operations++;
                }
            }
        }
        if(operations==0||readies==0||acknowledgments==0||completions!=manifest.RootElement.GetProperty("Cases").GetArrayLength())throw new InvalidDataException("Incomplete native frame inventory");
        Console.WriteLine(JsonSerializer.Serialize(new{Passed=true,ReadyFrames=readies,ActivatedFrames=acknowledgments,CompletionFrames=completions,Operations=operations,Scope="Exact archived native stdout frames through managed control/schema6 parsers and source target membership; no new activation or native capability"}));
    }
}
