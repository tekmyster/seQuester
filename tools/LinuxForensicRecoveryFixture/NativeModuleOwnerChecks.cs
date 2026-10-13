using System.ComponentModel;
using System.Diagnostics;
using System.Security.Cryptography;
using System.Text.Json;
using RansomFree.Client;
using RansomFree.Client.Forensics;

internal static class NativeModuleOwnerChecks
{
    private const UnixFileMode Private=UnixFileMode.UserRead|UnixFileMode.UserWrite;
    internal static void Run(string inputs,string root)
    {
        if(!OperatingSystem.IsLinux()||Directory.Exists(root))throw new ArgumentException("Fresh owned Linux module fixture required");
        Directory.CreateDirectory(root,Private|UnixFileMode.UserExecute);using var key=RSA.Create(3072);
        var checks=new List<string>();var receipts=new List<object>();
        void Check(bool ok,string label){if(!ok)throw new Exception(label);checks.Add(label);}
        void Reject(Action action,string label){try{action();}catch(Exception e)when(e is IOException or InvalidDataException or Win32Exception or InvalidOperationException or AggregateException){Check(true,label);return;}throw new Exception("Accepted: "+label);}
        void Save(string path,byte[] bytes,UnixFileMode mode=Private){File.WriteAllBytes(path,bytes);File.SetUnixFileMode(path,mode);}
        (string Config,LinuxNativeInstallation.Manifest Manifest) Create(string name,bool wrongModule=false)
        {
            var b=Path.Combine(root,name);var config=Path.Combine(b,"config");var package=Path.Combine(b,"package");
            foreach(var p in new[]{b,config,package,Path.Combine(b,"private")})Directory.CreateDirectory(p,Private|UnixFileMode.UserExecute);
            var members=new List<LinuxNativeInstallation.Member>();
            foreach(var entry in new[]{("loader-v2","loader"),("lease-v2.bpf.o","object"),("sq_actor_lease.ko","module")})
            {
                var bytes=wrongModule&&entry.Item2=="module"?new byte[]{1,3,5,7}:File.ReadAllBytes(Path.Combine(inputs,entry.Item1));
                Save(Path.Combine(package,entry.Item1),bytes,Private|(entry.Item2=="loader"?UnixFileMode.UserExecute:0));
                members.Add(new(entry.Item1,entry.Item2,bytes.Length,Convert.ToHexString(SHA256.HashData(bytes))));
            }
            var target=Path.Combine(b,"target.txt");Save(target,"owned module qualification target"u8.ToArray());
            var start=new ProcessStartInfo("/usr/bin/python3"){UseShellExecute=false,RedirectStandardOutput=true,RedirectStandardError=true};
            start.ArgumentList.Add("-c");start.ArgumentList.Add("import os,sys,json;s=os.stat(sys.argv[1]);print(json.dumps(dict(Path=sys.argv[1],Device=(os.major(s.st_dev)<<20)|os.minor(s.st_dev),Inode=s.st_ino)))");start.ArgumentList.Add(target);
            using var stat=Process.Start(start)??throw new IOException("Independent target stat failed");var bytesStat=stat.StandardOutput.ReadToEnd();var error=stat.StandardError.ReadToEnd();stat.WaitForExit();if(stat.ExitCode!=0)throw new IOException(error);
            Save(Path.Combine(b,"independent-stat.json"),System.Text.Encoding.UTF8.GetBytes(bytesStat));
            var manifest=new LinuxNativeInstallation.Manifest(1,LinuxNativeInstallation.QualifiedKernel,"x64",LinuxNativeInstallation.QualifiedBtfSha256,"sq_actor_lease",2,160,2,6,4194304,4,members.ToArray(),[JsonSerializer.Deserialize<LinuxNativeInstallation.Target>(bytesStat)!]);
            var bytesManifest=JsonSerializer.SerializeToUtf8Bytes(manifest);Save(Path.Combine(package,"manifest.json"),bytesManifest);
            Save(Path.Combine(config,"installation-update.lock"),[]);Save(Path.Combine(package,"package-update.lock"),[]);
            var definition=new LinuxNativeInstallation.Configuration(1,true,"11111111111111111111111111111111","https://qualification.invalid/",Convert.ToBase64String(key.ExportSubjectPublicKeyInfo()),65534,65534,package,Convert.ToHexString(SHA256.HashData(bytesManifest)),Path.Combine(b,"private"),Path.Combine(b,"channel"),Path.Combine(b,"exports"));
            Save(Path.Combine(config,"installation.json"),JsonSerializer.SerializeToUtf8Bytes(definition));return(config,manifest);
        }
        var wrong=Create("wrong-module",true);
        using(var p=LinuxNativePackageAdmission.Open(wrong.Config))using(var t=LinuxNativeTargetAdmission.Open(wrong.Manifest.Targets))
        {
            Reject(()=>{using var _=LinuxNativeModuleOwner.Prepare(p,t);},"unqualified module bytes refused before native ownership");
            using var ph=p.HoldNativeLifetime();using var th=t.HoldNativeLifetime();
            Check(!Directory.Exists("/sys/module/sq_actor_lease"),"wrong module rejection leaves no module and no held admissions");
        }
        foreach(var scenario in new[]{"receipt-failure","verify-failure"})
        {
            var valid=Create(scenario);using var package=LinuxNativePackageAdmission.Open(valid.Config);using var targets=LinuxNativeTargetAdmission.Open(valid.Manifest.Targets);
            var faults=new List<string>();var releases=new List<string>();bool injectLoad=true,injectUnload=true,injectRelease=true;
            var owner=LinuxNativeModuleOwner.PrepareForQualification(package,targets,point=>
            {
                if(point.StartsWith("RELEASE_",StringComparison.Ordinal))releases.Add(point);
                if(injectLoad&&((scenario=="receipt-failure"&&point.StartsWith("RECEIPT:",StringComparison.Ordinal)&&point.EndsWith("-load-return.json",StringComparison.Ordinal))||(scenario=="verify-failure"&&point=="LOAD_VERIFY")))
                {injectLoad=false;faults.Add(point);throw new IOException("qualification load boundary fault");}
                if(injectUnload&&point=="UNLOAD_VERIFY"){injectUnload=false;faults.Add(point);throw new IOException("qualification unload verification fault");}
                if(injectRelease&&point=="RELEASE_TARGET"){injectRelease=false;faults.Add(point);throw new IOException("qualification target release fault");}
            });
            try
            {
                Reject(package.Dispose,scenario+": package disposal refused while owned");Reject(targets.Dispose,scenario+": target disposal refused while owned");
                Reject(owner.Load,scenario+": injected post-load evidence failure returned");
                Check(owner.State=="LoadedOwned"&&owner.LoadReturn is {Result:0,Error:0}&&Directory.Exists("/sys/module/sq_actor_lease")&&File.Exists("/dev/sq_actor_lease"),scenario+": successful actual load retains ownership through later failure");
                owner.RetryReceipt();Reject(owner.Load,scenario+": successful actual load is one use");Reject(owner.Dispose,scenario+": live module blocks owner disposal");
                var other=Create(scenario+"-preexisting");
                using(var op=LinuxNativePackageAdmission.Open(other.Config))using(var ot=LinuxNativeTargetAdmission.Open(other.Manifest.Targets))using(var outsider=LinuxNativeModuleOwner.Prepare(op,ot))
                {
                    outsider.Load();Check(outsider.State=="LoadFailedNoOwnership"&&outsider.LoadReturn==null,scenario+": preexisting module refuses without native call or ownership");
                    Reject(outsider.UnloadBeforeSource,scenario+": non-owner cannot unload original module");
                    Check(Directory.Exists("/sys/module/sq_actor_lease"),scenario+": failed second owner leaves first module present");
                    receipts.Add(new{Scenario=scenario+"-preexisting",outsider.OwnerId,outsider.State,outsider.EvidenceDirectory,outsider.LoadReturn,outsider.UnloadReturn});
                }
                using(var controller=new LinuxActorLeaseDevice())
                {
                    owner.UnloadBeforeSource();
                    Check(owner.State=="LoadedOwned"&&owner.UnloadReturn is {Result:-1,Error:11 or 16},scenario+": actual open controller makes non-forced unload busy");
                    Reject(package.Dispose,scenario+": busy module keeps package admission");Reject(targets.Dispose,scenario+": busy module keeps target admission");
                    Check(Directory.Exists("/sys/module/sq_actor_lease"),scenario+": busy module remains loaded");
                }
                Reject(owner.UnloadBeforeSource,scenario+": injected verification failure follows successful native unload");
                var returned=owner.UnloadReturn;
                Check(owner.State=="UnloadReturned"&&returned is {Result:0,Error:0}&&!Directory.Exists("/sys/module/sq_actor_lease")&&!File.Exists("/dev/sq_actor_lease"),scenario+": actual unload returned but evidence verification is pending");
                Reject(owner.Dispose,scenario+": pending verification keeps admissions owned");
                owner.UnloadBeforeSource();Check(owner.State=="UnloadVerifiedAbsent"&&ReferenceEquals(returned,owner.UnloadReturn),scenario+": verification retry does not repeat native unload");
                Reject(owner.Dispose,scenario+": injected release fault reports incomplete cleanup");
                Check(releases.SequenceEqual(new[]{"RELEASE_TARGET","RELEASE_PACKAGE","RELEASE_JOURNAL"}),scenario+": each independent cleanup attempted despite first failure");
                Reject(targets.Dispose,scenario+": unfinished target hold remains active");
                package.Dispose();Check(true,scenario+": completed package hold can actually close");
                Reject(owner.Load,scenario+": partial cleanup forbids new activation");
                owner.Dispose();Check(releases.SequenceEqual(new[]{"RELEASE_TARGET","RELEASE_PACKAGE","RELEASE_JOURNAL","RELEASE_TARGET"}),scenario+": cleanup retry only repeats unfinished resource");
                targets.Dispose();owner.Dispose();Check(true,scenario+": final cleanup and repeated dispose complete");
                receipts.Add(new{Scenario=scenario,owner.OwnerId,owner.State,owner.EvidenceDirectory,owner.LoadReturn,owner.UnloadReturn,Faults=faults,Releases=releases});
            }
            finally
            {
                injectLoad=injectUnload=injectRelease=false;
                owner.RetryReceiptIfPossibleForFixture();
                if(owner.State is "LoadedOwned" or "UnloadIntentPending" or "UnloadReturned")owner.UnloadBeforeSource();
                owner.Dispose();
            }
        }
        File.WriteAllText(Path.Combine(root,"RESULTS.json"),JsonSerializer.Serialize(new{Passed=true,Checks=checks.Count,Details=checks,Root=root,Owners=receipts,Scope="Actual owned module load/unload and fault boundaries; no loader, BPF source or installed service started"}));
        Console.WriteLine(JsonSerializer.Serialize(new{Passed=true,Checks=checks.Count,Root=root}));
    }
    private static void RetryReceiptIfPossibleForFixture(this LinuxNativeModuleOwner owner)
    {try{owner.RetryReceipt();}catch(ObjectDisposedException){}}
}
