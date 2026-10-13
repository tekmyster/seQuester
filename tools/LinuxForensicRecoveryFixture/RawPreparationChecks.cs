using System.Text.Json;
using RansomFree.Client.Forensics;

static class RawPreparationChecks
{
    internal static void Run(string root)
    {
        if(Directory.Exists(root))throw new ArgumentException("Fresh owned preparation fixture required");
        Directory.CreateDirectory(root);int checks=0;
        void Check(bool value,string name){if(!value)throw new Exception(name);checks++;Console.WriteLine("PASS: "+name);}
        void Reject(Action operation,string name)
        {
            try{operation();}
            catch(Exception e)when(e is IOException or ArgumentException or InvalidOperationException or InvalidDataException)
            {Check(true,name);return;}
            throw new Exception("Unexpected preparation acceptance: "+name);
        }
        var sensor=Guid.NewGuid().ToString("N");var collector=Guid.NewGuid().ToString("N");
        var directory=Path.Combine(root,"bound");var barrier=new LinuxSourceWorkBarrier();
        using(var prepared=LinuxRawIngressReserve.Prepare(directory,sensor,collector,5,true))
        {
            Check(prepared.Identity.Size>0&&prepared.CompletedMonotonic>=prepared.StartedMonotonic,"storage allocated before native epoch exists");
            Check(prepared.PhysicalAllocationEstablished==OperatingSystem.IsLinux(),"physical allocation distinguished from layout replay");
            Reject(()=>new LinuxRawIngressReserve(prepared,"0",true),"zero native epoch cannot bind preparation");
            Reject(()=>prepared.Take(directory,sensor,Guid.NewGuid().ToString("N"),5),"collector mismatch cannot consume held storage");
            Reject(()=>prepared.Take(directory,sensor,collector,6),"capacity mismatch cannot consume held storage");
            using(var bank=new LinuxRawIngressReserve(prepared,"123",true))
            {
                Check(bank.ProviderEpoch=="123"&&bank.CollectorInstance==collector&&!bank.Reopened,"real epoch bound to original held storage owner");
                Check(bank.Entries.Length==0&&bank.FirstBoundary==null,"new preparation has no historical events or boundaries");
                Check(bank.BankIdentity.StableId==prepared.Identity.StableId,"binding retains exact allocated file identity");
                Reject(()=>new LinuxRawIngressReserve(prepared,"456",true),"held descriptor cannot transfer twice");
                Check(bank.Commit(new byte[]{255,0,42},barrier.Current,DateTimeOffset.UtcNow).Committed,"raw event durable after binding");
            }
        }
        using(var reopened=new LinuxRawIngressReserve(directory,sensor,collector,"123",5,true))
            Check(reopened.Reopened&&reopened.Entries.Length==1&&reopened.ReadRaw(reopened.Entries[0]).SequenceEqual(new byte[]{255,0,42}),"existing full replay validates exact raw bytes");
        var abandoned=Path.Combine(root,"abandoned");
        var unused=LinuxRawIngressReserve.Prepare(abandoned,sensor,Guid.NewGuid().ToString("N"),5,true);
        unused.Dispose();
        Check(File.Exists(Path.Combine(abandoned,"raw-ingress-v3.bin")),"unbound failed attempt retained as evidence");
        Reject(()=>new LinuxRawIngressReserve(unused,"123",true),"closed preparation cannot later activate");
        Reject(()=>new LinuxRawIngressReserve(abandoned,sensor,unused.Collector,"123",5,true),"unbound file cannot be reinterpreted as a native source");
        Reject(()=>LinuxRawIngressReserve.Prepare(abandoned,sensor,unused.Collector,5,true),"preparation never overwrites an existing file");
        Reject(()=>LinuxRawIngressReserve.Prepare(Path.Combine(root,"invalid-owner"),"wrong",collector,5,true),"invalid storage owner rejected before allocation");
        var quotaRoot=Path.Combine(root,"quota");Directory.CreateDirectory(quotaRoot);
        var firstQuota=Path.Combine(quotaRoot,"source-one","raw");long size;
        using(var reserved=LinuxRawIngressReserve.Prepare(firstQuota,sensor,Guid.NewGuid().ToString("N"),5,true,quotaRoot,2*1024*1024))
            size=reserved.Identity.Size!.Value;
        var rejectedQuota=Path.Combine(quotaRoot,"source-two","raw");
        Reject(()=>LinuxRawIngressReserve.Prepare(rejectedQuota,sensor,Guid.NewGuid().ToString("N"),5,true,quotaRoot,size),"retained unbound preparation consumes storage quota");
        Check(!File.Exists(Path.Combine(rejectedQuota,"raw-ingress-v3.bin")),"quota rejection occurs before file allocation or loader startup");
        using(var reserved=LinuxRawIngressReserve.Prepare(rejectedQuota,sensor,Guid.NewGuid().ToString("N"),5,true,quotaRoot,size*2))
            Check(reserved.Identity.Size==size,"exact remaining quota permits new preparation");
        Reject(()=>LinuxRawIngressReserve.Prepare(Path.Combine(quotaRoot,"source-three","raw"),sensor,Guid.NewGuid().ToString("N"),5,true,root,size*3),"foreign quota parent cannot bypass retained storage accounting");
        Console.WriteLine(JsonSerializer.Serialize(new{Passed=true,Checks=checks,PhysicalLinuxQualification=OperatingSystem.IsLinux(),
            Scope="Raw preparation ownership, single transfer, durable replay and failure retention; no native observer or installed recovery qualification"}));
    }
}
