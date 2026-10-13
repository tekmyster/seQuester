using RansomFree.Contracts;
using System.Collections.Immutable;
using System.Text.Json;
using RansomFree.Client;
using RansomFree.Client.Forensics;

internal static class ControlledLaunchChecks
{
    internal static void Run()
    {
        var checks=0;void Check(bool value,string label){if(!value)throw new InvalidDataException(label);checks++;}
        var root=Path.GetFullPath(Path.GetTempPath());var config=new LinuxOwnedLoaderProcess.Launch(Path.Combine(root,"loader"),Path.Combine(root,"object"),Path.Combine(root,"target"),root);
        Check(LinuxOwnedLoaderProcess.BuildArguments(config).SequenceEqual(new[]{"--controlled",config.ObjectFile,config.Target}),"Legacy single-target argv unchanged");
        var legacyJson=JsonSerializer.Serialize(new{config.Loader,config.ObjectFile,config.Target,config.LibraryDirectory});
        var old=JsonSerializer.Deserialize<LinuxOwnedLoaderProcess.Launch>(legacyJson)!;
        Check(old.ControlVersion==1&&old.Targets.IsEmpty&&LinuxOwnedLoaderProcess.BuildArguments(old).SequenceEqual(LinuxOwnedLoaderProcess.BuildArguments(config)),"Existing launch JSON stays v1");
        var qualification=new LinuxControlledSourceRuntime.Qualification(config,"kernel",new string('a',64),new string('b',64),new string('c',64),Path.Combine(root,"fresh-runtime"));
        Check(LinuxControlledSourceRuntime.ValidatePreparedTargets(qualification)==null,"Legacy configuration makes no target-set claim");
        foreach(var count in new[]{1,2,32})
        {
            var targets=Enumerable.Range(0,count).Select(n=>n==0?config.Target:Path.Combine(root,"target "+n+";literal")).ToImmutableArray();var v2=config with{ControlVersion=2,Targets=targets};
            var args=LinuxOwnedLoaderProcess.BuildArguments(v2);
            Check(args.Length==count+2&&args[0]=="--controlled-v2"&&args[1]==v2.ObjectFile&&args.Skip(2).SequenceEqual(targets),"Exact bounded argv preserves each path as one argument");
            var restored=JsonSerializer.Deserialize<LinuxOwnedLoaderProcess.Launch>(JsonSerializer.Serialize(v2))!;
            Check(LinuxOwnedLoaderProcess.BuildArguments(restored).SequenceEqual(args),"Explicit v2 launch survives immutable configuration serialization");
            var expected=Enumerable.Range(1,count).Select(n=>new LinuxControlledTargetSet.Identity(8,(ulong)n)).ToImmutableArray();var source=qualification with{Launch=v2,ExpectedTargets=expected};
            var prepared=LinuxControlledSourceRuntime.ValidatePreparedTargets(source)!;
            Check(prepared.Targets.SequenceEqual(expected)&&LinuxControlledSourceRuntime.ValidatePreparedTargets(JsonSerializer.Deserialize<LinuxControlledSourceRuntime.Qualification>(JsonSerializer.Serialize(source))!)!.Digest==prepared.Digest,"Independent prepared identities survive configuration serialization");
        }
        foreach(var invalid in new[]{qualification with{ExpectedTargets=[new(8,1)]},qualification with{Launch=config with{ControlVersion=2,Targets=[config.Target]}},qualification with{Launch=config with{ControlVersion=2,Targets=[config.Target,Path.Combine(root,"other")]},ExpectedTargets=[new(8,1)]},qualification with{Launch=config with{ControlVersion=2,Targets=[config.Target,Path.Combine(root,"other")]},ExpectedTargets=[new(8,1),new(8,1)]},qualification with{Launch=config with{ControlVersion=2,Targets=[config.Target]},ExpectedTargets=[new(0,1)]}})
        {
            try{LinuxControlledSourceRuntime.ValidatePreparedTargets(invalid);throw new Exception("Invalid independent target binding accepted");}catch(Exception ex)when(ex is ArgumentException or InvalidDataException){checks++;}
        }
        foreach(var invalid in new[]{config with{ControlVersion=0},config with{ControlVersion=3},config with{ControlVersion=2},config with{Targets=[config.Target]},config with{ControlVersion=2,Targets=[config.Target,config.Target]},config with{ControlVersion=2,Targets=[Path.Combine(root,"other")]},config with{ControlVersion=2,Targets=[config.Target,"relative"]},config with{ControlVersion=2,Targets=[config.Target,root+'\0']},config with{ControlVersion=2,Targets=Enumerable.Range(0,33).Select(n=>n==0?config.Target:Path.Combine(root,n.ToString())).ToImmutableArray()},config with{ObjectFile="relative"}})
        {
            try{LinuxOwnedLoaderProcess.BuildArguments(invalid);throw new Exception("Invalid source configuration fell back");}catch(ArgumentException){checks++;}
        }
        Console.WriteLine(JsonSerializer.Serialize(new{Passed=true,Checks=checks,Scope="Explicit bounded launch selection and legacy configuration compatibility; no native process started"}));
    }
}
