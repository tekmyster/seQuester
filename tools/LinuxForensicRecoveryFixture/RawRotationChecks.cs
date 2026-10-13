using System.Text.Json;
using RansomFree.Client.Forensics;
using RansomFree.Contracts;

static class RawRotationChecks
{
    internal static void Run(string root)
    {
        if(Directory.Exists(root))throw new ArgumentException("Fresh raw rotation fixture required");
        var sensor=Guid.NewGuid().ToString("N");var collector=Guid.NewGuid().ToString("N");
        Directory.CreateDirectory(root);int checks=0;
        void Check(bool ok,string name){if(!ok)throw new Exception(name);checks++;Console.WriteLine("PASS: "+name);}
        void Reject(Action action,string name){try{action();}catch(Exception e)when(e is IOException or InvalidDataException or InvalidOperationException){Check(true,name);return;}throw new Exception(name);}
        var source=Path.Combine(root,"source-test");var raw=Path.Combine(source,"raw");
        Directory.CreateDirectory(source);var barrier=new LinuxSourceWorkBarrier();
        using(var prepared=LinuxRawIngressReserve.Prepare(raw,sensor,collector,5,true,root,512L*1024*1024))
        using(var bank=new LinuxRawIngressReserve(prepared,"123",true,true,root,512L*1024*1024))
        using(var journal=new LinuxForensicJournal(Path.Combine(root,"journal"),sensor))
        {
            var session=journal.PrepareControlledSource(bank,new ForensicPolicy(),"0",DateTimeOffset.UtcNow,512L*1024*1024);
            Check(journal.ReadSourceBankFormat(session.Id)=="raw-ingress-v4-rotating","new source persists versioned rotating format");
            for(int i=1;i<=13;i++)
            {
                var result=bank.Commit(BitConverter.GetBytes(i),barrier.Current,DateTimeOffset.UtcNow);
                Check(result.Committed&&result.Entry!.Sequence==i&&result.Entry.Version==4,"global immutable sequence "+i);
                journal.VerifyIngressBank(session.Id,bank);
                Check(journal.IndexRawIngress(session.Id,bank,result.Entry!).AlreadyIndexed==false,"raw index crosses segment "+i);
            }
            Check(bank.Entries.Length==13&&bank.CanAppend&&bank.FirstBoundary==null,"two rotations preserve writable owner and evidence prefix");
            foreach(var entry in bank.Entries)Check(BitConverter.ToInt32(bank.ReadRaw(entry))==entry.Sequence,"exact readback across segments "+entry.Sequence);
            Check(Directory.GetFiles(raw,"rotation-*.json").Length==2,"immutable rotation receipts committed");
            var boundary=bank.RecordBoundary("FIXTURE_INDEX_FAILURE",barrier.Current,4,"fixture");
            Check(boundary.NewlyCommitted&&boundary.Boundary.LastDurableSequence==13,"emergency receipt selects active segment and global prefix after rotation");
            Check(bank.FirstBoundary==boundary.Boundary,"aggregate boundary exposes exact active-segment failure");
            Check(!bank.RecordBoundary("SECOND_FAILURE",barrier.Current,4,"fixture").NewlyCommitted,"later failures cannot overwrite the first boundary");
            Check(bank.SealInput(DateTimeOffset.UtcNow) is {Version:2,Entries:13,Capacity:15},"aggregate terminal seal covers all segments");
            Check(!bank.CanAppend,"terminal seal revokes appends");
            Reject(()=>bank.Commit(new byte[]{1},barrier.Current,DateTimeOffset.UtcNow),"sealed log rejects writes");
        }
        using(var historical=LinuxRawIngressReserve.OpenReadOnly(raw,sensor,collector,"123",5))
        {
            Check(historical.Entries.Length==13&&historical.SealedInput is {Version:2,Entries:13},"read-only reopen verifies entire chain and terminal seal");
            foreach(var entry in historical.Entries)Check(BitConverter.ToInt32(historical.ReadRaw(entry))==entry.Sequence,"historical exact bytes "+entry.Sequence);
            Check(!historical.CanAppend,"historical chain grants no write authority");
        }
        var receipt=Path.Combine(raw,"rotation-000002.json");var receiptBytes=File.ReadAllBytes(receipt);
        File.Delete(receipt);Reject(()=>LinuxRawIngressReserve.OpenReadOnly(raw,sensor,collector,"123",5).Dispose(),"missing rotation receipt retains uncommitted segment and rejects recovery");
        File.WriteAllBytes(receipt,receiptBytes);if(OperatingSystem.IsLinux())File.SetUnixFileMode(receipt,UnixFileMode.UserRead|UnixFileMode.UserWrite);
        var altered=receiptBytes.ToArray();var index=Array.IndexOf(altered,(byte)'1');altered[index]=(byte)'9';File.WriteAllBytes(receipt,altered);
        Reject(()=>LinuxRawIngressReserve.OpenReadOnly(raw,sensor,collector,"123",5).Dispose(),"tampered chain receipt rejected");
        File.WriteAllBytes(receipt,receiptBytes);
        var quotaSource=Path.Combine(root,"quota-source");Directory.CreateDirectory(quotaSource);var quotaRaw=Path.Combine(quotaSource,"raw");
        var quotaCollector=Guid.NewGuid().ToString("N");
        // Existing retained banks consume quota too. Exactly one new segment
        // fits; the following attempted allocation must fail without eviction.
        long retained=Directory.GetFiles(root,"raw-ingress-v3.bin",SearchOption.AllDirectories).Sum(p=>new FileInfo(p).Length);
        const long segmentBytes=4096+6L*(128+131072);
        using(var preparation=LinuxRawIngressReserve.Prepare(quotaRaw,sensor,quotaCollector,5,true))
        using(var bank=new LinuxRawIngressReserve(preparation,"456",true,true,root,retained+2*segmentBytes))
        {
            for(int i=0;i<10;i++)Check(bank.Commit(new byte[]{(byte)i},barrier.Current,DateTimeOffset.UtcNow).Committed,"quota prefix "+i);
            Reject(()=>bank.Commit(new byte[]{255},barrier.Current,DateTimeOffset.UtcNow),"retained quota stops further allocation explicitly");
            Check(bank.Entries.Length==10&&!bank.CanAppend,"quota failure preserves prefix and revokes intake");
            Check(bank.SealInput(DateTimeOffset.UtcNow).Entries==10,"quota failure still permits terminal sealing and normal owned drain");
        }
        using(var bank=LinuxRawIngressReserve.OpenReadOnly(quotaRaw,sensor,quotaCollector,"456",5))
            Check(bank.Entries.Length==10&&bank.SealedInput!=null,"quota closure remains verifiable on read-only restart");
        Console.WriteLine(JsonSerializer.Serialize(new{Passed=true,Checks=checks,NativeActivation=false,Scope="Raw segment rotation, global ordering, SQL migration/indexing, immutable replay, tamper rejection and quota failure"}));
    }
}
