using System.Text.Json;

namespace RansomFree.Client.Forensics;

internal sealed partial class LinuxForensicJournal
{
    private readonly HashSet<string> stoppedRecoveries=new(StringComparer.Ordinal);
    private sealed class StoppedRecoveryHandle(Action release):IDisposable
    {
        private Action? release=release;
        public void Dispose()=>Interlocked.Exchange(ref release,null)?.Invoke();
    }
    private IDisposable AcquireStoppedRecovery(string session,bool historical)
    {
        lock(gate)
        {
            if(admissionChecking||historical&&runtimeOwner||ReadSource(session).State!="CLOSED"||!stoppedRecoveries.Add(session))
                throw new InvalidOperationException("Stopped evidence recovery requires exclusive session ownership and terminal source proof");
            return new StoppedRecoveryHandle(()=>{lock(gate)stoppedRecoveries.Remove(session);});
        }
    }
    private string[] PendingForSource(string session)
    {
        lock(gate)
        {
            using var c=Open();using var q=Command(c,null,"SELECT w.event_id FROM work w JOIN canonical_events e ON e.event_id=w.event_id WHERE e.session_id=$id AND w.done=0 ORDER BY w.rowid",("$id",session));
            using var r=q.ExecuteReader();var ids=new List<string>();while(r.Read())ids.Add(r.GetString(0));return ids.ToArray();
        }
    }
    private sealed record HistoricalBank(string Session,string Path,string StableId,long Bytes,string Collector,string Epoch,string Format)
    {
        internal int Slots
        {
            get
            {
                // v3 is bounded and fixed-size; the full parser still verifies
                // the header and every intent/frame, including unused slots.
                var count=(Bytes-4096)/(128+131072)-1;
                if(count is <5 or >4096||4096+(count+1)*(128+131072)!=Bytes)throw new InvalidDataException("Invalid retained raw bank size");
                return (int)count;
            }
        }
    }
    private HistoricalBank[] HistoricalBanks()
    {
        using var c=Open();using var q=Command(c,null,"""
            SELECT s.session_id,b.path,b.stable_id,b.bytes,s.collector,s.provider_epoch,f.format
            FROM source_lifecycle s LEFT JOIN source_banks b USING(bank_id)
            LEFT JOIN source_bank_formats f USING(bank_id) ORDER BY s.session_id
            """);using var r=q.ExecuteReader();var rows=new List<HistoricalBank>();
        while(r.Read())rows.Add(new(r.GetString(0),r.GetString(1),r.GetString(2),r.GetInt64(3),r.GetString(4),r.GetString(5),r.GetString(6)));
        return rows.ToArray();
    }
    private LinuxRawIngressReserve OpenHistoricalBank(HistoricalBank descriptor)
    {
        if(descriptor.Format is not ("raw-ingress-v3" or "raw-ingress-v4-rotating"))throw new InvalidOperationException("Legacy source bank requires explicit recovery before a new owned source");
        var bank=LinuxRawIngressReserve.OpenReadOnly(Path.GetDirectoryName(descriptor.Path)!,sensor,descriptor.Collector,descriptor.Epoch,descriptor.Slots);
        try
        {
            if(bank.Format!=descriptor.Format||bank.FullPath!=descriptor.Path||bank.BankIdentity.StableId!=descriptor.StableId||bank.BankIdentity.Size!=descriptor.Bytes||bank.SealedInput==null)
                throw new InvalidDataException("RAW_RECOVERY_UNRESOLVED: retained input identity or terminal seal unavailable");
            return bank;
        }
        catch{bank.Dispose();throw;}
    }
    private int ValidateIndexedPrefix(string session,LinuxRawIngressReserve.Entry[] physical)
    {
        using var c=Open();using var q=Command(c,null,"SELECT entry FROM source_ingress WHERE session_id=$id ORDER BY sequence",("$id",session));
        using var r=q.ExecuteReader();var n=0;
        while(r.Read())
        {
            if(n>=physical.Length||!((byte[])r[0]).AsSpan().SequenceEqual(JsonSerializer.SerializeToUtf8Bytes(physical[n])))
                throw new InvalidDataException("Raw physical receipts and indexed prefix disagree");
            n++;
        }
        return physical.Length-n;
    }
    internal int CountUnindexedRaw(string session,LinuxRawIngressReserve bank)
    {
        VerifyIngressBank(session,bank);var physical=bank.Entries;
        lock(gate)return ValidateIndexedPrefix(session,physical);
    }
    internal void RecoverStoppedRaw(string session,LinuxRawIngressReserve bank)
    {
        using var owned=AcquireStoppedRecovery(session,historical:false);RecoverStoppedRawCore(session,bank);
    }
    private void RecoverStoppedRawCore(string session,LinuxRawIngressReserve bank)
    {
        VerifyIngressBank(session,bank);
        if(ReadSource(session).State!="CLOSED"||bank.SealedInput==null)
            throw new InvalidOperationException("Recovery needs terminal owner proof and sealed input; it cannot infer kernel closure");
        // File verification/decoding stays outside the journal gate. Exact
        // replay validates existing canonical bytes as well as missing rows.
        foreach(var entry in bank.Entries)
        {
            var result=IndexRawIngress(session,bank,entry);
            if(result.Status is "INDEX_PREDECESSOR_PENDING" or "POLICY_EVIDENCE_MISSING" or "POLICY_EVIDENCE_INVALID" or "CANONICAL_KEY_CONTRADICTION")
                throw new InvalidDataException("RAW_RECOVERY_UNRESOLVED:"+result.Status);
        }
        if(CountUnindexedRaw(session,bank)!=0)throw new InvalidDataException("Raw indexing did not cover sealed input");
    }
    // Explicit restart recovery opens only retained evidence. It has no actor
    // pathname/PID fallback, module/controller capability, or source activation.
    internal void RecoverStoppedRaw(string session)
    {
        using var owned=AcquireStoppedRecovery(session,historical:true);
        HistoricalBank descriptor;
        lock(gate)
        {
            descriptor=HistoricalBanks().Single(x=>x.Session==session);
        }
        using var bank=OpenHistoricalBank(descriptor);RecoverStoppedRawCore(session,bank);
    }
    internal async Task<bool> DeliverStoppedRaw(string session,ForensicPipeline pipeline,EventSpool spool,Action<string>? checkpoint=null)
    {
        using var owned=AcquireStoppedRecovery(session,historical:true);
        HistoricalBank descriptor;
        lock(gate)
        {
            descriptor=HistoricalBanks().Single(x=>x.Session==session);
        }
        using var bank=OpenHistoricalBank(descriptor);
        return await DeliverStoppedRawCore(session,bank,pipeline,spool,checkpoint).ConfigureAwait(false);
    }
    internal async Task<bool> DeliverStoppedRaw(string session,LinuxRawIngressReserve bank,ForensicPipeline pipeline,EventSpool spool,Action<string>? checkpoint=null)
    {
        using var owned=AcquireStoppedRecovery(session,historical:false);
        return await DeliverStoppedRawCore(session,bank,pipeline,spool,checkpoint).ConfigureAwait(false);
    }
    private async Task<bool> DeliverStoppedRawCore(string session,LinuxRawIngressReserve bank,ForensicPipeline pipeline,EventSpool spool,Action<string>? checkpoint)
    {
        RecoverStoppedRawCore(session,bank);
        while(true)
        {
            foreach(var entry in ReadDeferredCanonical(session,bank))
            {
                if(Pending().Length>=4)break;
                PromoteStoppedCanonicalUnavailable(session,bank,entry);
            }
            var submitted=new Dictionary<string,Task>();
            try
            {
                foreach(var id in PendingForSource(session))
                {
                    if(ReadNativePin(id)?.State is "PIN_COMMITTED" or "SELECTION_AUTHORIZED" or "NATIVE_STARTED")return false;
                    var callback=new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
                    if(pipeline.TrySubmitPrepared(this,id,spool,checkpoint,returned:()=>callback.TrySetResult()))submitted.Add(id,callback.Task);
                }
            }
            finally
            {
                // Only callbacks we actually submitted are part of this
                // drain. Unrelated occupied global permits cannot hold it.
                await Task.WhenAll(submitted.Values).ConfigureAwait(false);
            }
            if(submitted.Count==0)return PendingForSource(session).Length==0&&ReadDeferredCanonical(session,bank).Length==0;
            if(submitted.Keys.Any(id=>!Read(id).Done))return false;
        }
    }
}
