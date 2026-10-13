using System.Diagnostics;
using System.Security.Cryptography;
using RansomFree.Client.Forensics;
using RansomFree.Contracts;

[System.Runtime.Versioning.SupportedOSPlatform("windows")]
internal static class WindowsRetentionChecks
{
    internal static void Run(string root,string sensor,string actor,Action<bool,string> check)
    {
        // Native executable handles plus synthetic kernel observations test retention
        // mechanics. The VMware minifilter matrix separately proves real token capture.
        WindowsTokenSnapshot Token(string sid,uint type)=>new(){Captured=31,Sid=sid,TokenId="0000000000000001",AuthenticationId="0000000000000002",ModifiedId="0000000000000003",Type=type,SessionId=0,IntegrityRid=8192,Elevated=false,QueryStatus=Enumerable.Repeat("0x00000000",5).ToArray()};
        AgentEvent Event(int pid,long start,string path,string instance="0123456789ABCDEF",string sid="S-1-5-19")
        {
            var kernel=new WindowsKernelEvidence{Instance=instance,Sequence=1,ProcessId=pid,ThreadId=71,ProcessCreatedFileTime=start,CompletedUtc=DateTimeOffset.UtcNow,MonotonicTicks=Stopwatch.GetTimestamp(),MonotonicFrequency=Stopwatch.Frequency,NativePath=Path.Combine(root,"target.txt"),NameSource="normalized",NormalizedNameStatus="0x00000000",SubjectSource="request-thread-snapshot",ThreadImpersonating=true,ThreadEffective=Token(sid,2),CreateAuthorization=Token(sid,2),RequestorPrimary=Token("S-1-5-18",1)};
            return new(Guid.NewGuid().ToString("N"),DateTimeOffset.UtcNow,"Content read (copy possible)",Path.Combine(root,"target.txt"),sid,path,pid,"Windows minifilter"){Attribution=new(){Provider="Windows minifilter",UserSid=sid,EventTimeCredentials=true,WindowsKernel=kernel}};
        }
        var info=new ProcessStartInfo(actor){RedirectStandardInput=true,RedirectStandardOutput=true,UseShellExecute=false,CreateNoWindow=true};info.ArgumentList.Add("--hold");
        if(Path.GetFileNameWithoutExtension(actor).Equals("dotnet",StringComparison.OrdinalIgnoreCase))info.ArgumentList.Insert(0,System.Reflection.Assembly.GetExecutingAssembly().Location);
        using var child=Process.Start(info)!;
        try
        {
            check(child.StandardOutput.ReadLine()=="ready","retention controlled child ready");
            var start=child.StartTime.ToUniversalTime().ToFileTimeUtc();var first=Event(child.Id,start,actor);long now=0;
            using var cache=new WindowsKernelImageRetention(2,TimeSpan.FromSeconds(30),()=>now);var health=new List<string>();
            using(var early=cache.Capture(first,sensor,health.Add))check(early.Image!=null&&cache.Count==1&&early.BindingSourceEventId==first.EventId,"native process image retained with first-event provenance");
            child.StandardInput.WriteLine();child.WaitForExit();
            var later=Event(child.Id,start,actor,sid:"S-1-5-20");using var retained=cache.Capture(later,sensor,health.Add);
            check(retained.Image!=null&&retained.Binding.Reason.StartsWith("retained-file-object"),"later event from exited process reopens retained original file object");
            check(retained.BindingSourceEventId==first.EventId&&retained.BindingCapturedUtc!=null&&retained.Process.InstanceId==ActorLease.Correlate(sensor,child.Id,start.ToString()),"retention preserves binding event and exact process instance");
            check(retained.Process.Owner.Sid=="S-1-5-18"&&retained.Process.EventSubject.Sid=="S-1-5-20"&&retained.Process.ThreadToken.Sid=="S-1-5-20","retained executable does not reuse previous event impersonation identity");
            check(retained.Process.CommandLine==null&&retained.Process.CommandLineStatus.State=="unavailable","retention does not invent prior command line or process metadata");
            var collector=new ForensicCollector(sensor,Path.Combine(root,"retention-evidence"));
            var result=collector.Complete(later,retained,collector.Begin(later,retained),new());
            check(result.IsValid()&&result.Preservation.HashMatched==true&&result.ActorExecutable.BindingSourceEventId==first.EventId,"later event preservation has verified bytes and structured binding provenance");
            check(!(result with{ActorExecutable=result.ActorExecutable with{BindingSourceEventId="bad"}}).IsValid()&&!(result with{ActorExecutable=result.ActorExecutable with{BindingCapturedUtc=null}}).IsValid(),"malformed binding provenance rejected");
            check((result with{ActorExecutable=result.ActorExecutable with{BindingSourceEventId=null,BindingCapturedUtc=null}}).IsValid(),"schema-one historical evidence without binding provenance remains readable");
            for(var i=0;i<100;i++){var repeated=Event(child.Id,start,actor);using var next=cache.Capture(repeated,sensor,health.Add);if(next.Image==null)throw new Exception("retention lost image");collector.Complete(repeated,next,collector.Begin(repeated,next),new(PreserveActorOnAlert:false));}
            check(cache.Count==1&&collector.HashComputations==1&&collector.CacheHits==100&&health.Count==0,"100 post-exit events use one retained file and one stable hash calculation");
            using(var other=cache.Capture(Event(child.Id,start+1,actor),sensor,health.Add))check(other.Image==null,"PID reuse with different kernel start time cannot inherit retained image");
            using(var other=cache.Capture(Event(child.Id,start,actor+".changed"),sensor,health.Add))check(other.Image==null,"different actor path cannot inherit retained image");
            using(var other=cache.Capture(Event(child.Id,start,actor,"FEDCBA9876543210"),sensor,health.Add))check(other.Image==null,"new kernel provider epoch cannot inherit retained image");
            using(var other=cache.Capture(later,Guid.NewGuid().ToString("N"),health.Add))check(other.Image==null,"different sensor cannot inherit retained image");
            using(var independent=WindowsKernelImageRetention.Reopen(retained.Image!,retained.File))
            {retained.Image!.Position=17;independent.Position=29;check(retained.Image.Position==17&&independent.Position==29,"reopened handles have independent stream positions");}
            now=31*Stopwatch.Frequency;cache.Expire();
            using(var expired=cache.Capture(later,sensor,health.Add))check(cache.Count==0&&expired.Image==null&&retained.Image!.CanRead,"fixed retention expiry releases cache ownership without closing active event lease");
        }
        finally{if(!child.HasExited){child.StandardInput.WriteLine();child.WaitForExit();}}

        using var current=Process.GetCurrentProcess();var currentEvent=Event(current.Id,current.StartTime.ToUniversalTime().ToFileTimeUtc(),actor);
        var warnings=new List<string>();var bounded=new WindowsKernelImageRetention(1);
        using(var first=bounded.Capture(currentEvent,sensor,warnings.Add)){}
        using(var second=bounded.Capture(currentEvent with{Attribution=currentEvent.Attribution! with{WindowsKernel=currentEvent.Attribution.WindowsKernel! with{Instance="FEDCBA9876543210"}}},sensor,warnings.Add)){}
        check(bounded.Count==1&&warnings.Count==1,"capacity evicts and reports oldest retained process image");bounded.Dispose();check(bounded.Count==0,"retention shutdown releases every cache handle");
        var stopped=false;try{using var invalid=bounded.Capture(currentEvent,sensor,warnings.Add);}catch(ObjectDisposedException){stopped=true;}check(stopped,"disposed retention cannot reopen actor handles");
        var path=Path.Combine(root,"retention-original.bin");File.WriteAllText(path,"original bytes");
        using(var source=new FileStream(path,FileMode.Open,FileAccess.Read,FileShare.Read|FileShare.Delete))
        {
            var before=NativeFileIdentity.Read(source);File.Move(path,path+".renamed");File.WriteAllText(path,"replacement malware name");
            using var copy=WindowsKernelImageRetention.Reopen(source,NativeFileIdentity.Read(source));
            check(Convert.ToHexString(SHA256.HashData(copy))==Convert.ToHexString(SHA256.HashData(System.Text.Encoding.UTF8.GetBytes("original bytes"))),"reopen follows original file object after rename and pathname replacement");
            check(NativeFileIdentity.Read(copy).StableId==before.StableId,"retained object keeps stable original identity after pathname replacement");
            var rejected=false;try{using var invalid=WindowsKernelImageRetention.Reopen(source,before with{ChangeMarker="changed"});}catch(IOException){rejected=true;}check(rejected,"changed executable marker rejects retained-image reuse");
        }
        var closed=File.OpenRead(path);var identity=NativeFileIdentity.Read(closed);closed.Dispose();var failed=false;
        try{using var invalid=WindowsKernelImageRetention.Reopen(closed,identity);}catch(ObjectDisposedException){failed=true;}check(failed,"unavailable retained handle fails explicitly");
    }
}
