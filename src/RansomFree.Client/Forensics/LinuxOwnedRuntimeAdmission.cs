namespace RansomFree.Client.Forensics;

internal sealed partial class LinuxForensicJournal
{
    private bool runtimeOwner,admissionChecking;
    internal void RequireNativeInstallation(LinuxNativeInstallation.Configuration configuration)
    {
        lock(gate)
        {
            ObjectDisposedException.ThrowIf(disposed,this);
            if(sensor!=configuration.SensorId||root!=Path.Combine(configuration.PrivateDirectory,"linux-forensic-intake"))
                throw new InvalidDataException("Native journal differs from root-installed private directory or sensor");
            using var directory=LinuxProtectedDirectory.OpenRoot(root);directory.RequirePrivate();directory.RequireQualifiedLocalExt4();
        }
    }
    internal void AdmitOwnedRuntime()
    {
        HistoricalBank[] descriptors;
        lock(gate)
        {
            RequireAdmission();descriptors=HistoricalBanks();admissionChecking=true;
        }
        var banks=new List<(string Session,LinuxRawIngressReserve Bank)>();
        void CloseInventory()
        {
            Exception? failure=null;
            foreach(var item in banks)try{item.Bank.Dispose();}catch(Exception e){failure??=e;}
            banks.Clear();if(failure!=null)System.Runtime.ExceptionServices.ExceptionDispatchInfo.Capture(failure).Throw();
        }
        try
        {
            // Bounded by the registered bank quota. Never hold the journal
            // gate while reading/hashing disk evidence or waiting for I/O.
            foreach(var descriptor in descriptors)banks.Add((descriptor.Session,OpenHistoricalBank(descriptor)));
            var inventory=banks.Select(item=>(item.Session,Entries:item.Bank.Entries)).ToArray();
            // A read-handle disposal failure must occur before the exclusive
            // owner is admitted, so the caller cannot lose an admitted owner
            // simply because Start threw while releasing inventory handles.
            CloseInventory();
            lock(gate)
            {
                RequireAdmission(ownCheck:true);
                if(!descriptors.SequenceEqual(HistoricalBanks()))throw new InvalidOperationException("Source inventory changed during admission");
                foreach(var item in inventory)if(ValidateIndexedPrefix(item.Session,item.Entries)!=0)
                    throw new InvalidOperationException("RAW_RECOVERY_PENDING: physical receipts are not fully indexed");
                runtimeOwner=true;
            }
        }
        finally
        {
            try{CloseInventory();}
            finally{lock(gate)admissionChecking=false;}
        }
    }
    private void RequireAdmission(bool ownCheck=false)
    {
        using var c=Open();
        if(runtimeOwner||admissionChecking&&!ownCheck||stoppedRecoveries.Count!=0||Pending().Length!=0||Scalar(c,null,"SELECT count(*) FROM source_lifecycle WHERE state<>'CLOSED'")!=0||
            Scalar(c,null,"SELECT count(*) FROM canonical_events e LEFT JOIN work w ON e.event_id=w.event_id WHERE w.event_id IS NULL")!=0||
            Scalar(c,null,"SELECT count(*) FROM source_ingress WHERE classification NOT IN ('RAW_VALID','DUPLICATE','RAW_INVALID','RAW_FOREIGN_EPOCH','RAW_AFTER_FAULT','RAW_AFTER_STOP')")!=0)
            throw new InvalidOperationException("Prior source ownership/recovery must finish before launching another loader");
    }
    internal void ReleaseOwnedRuntime(string? source)
    {
        lock(gate)
        {
            if(!runtimeOwner)throw new InvalidOperationException("No runtime owner admitted");
            if(source!=null&&ReadSourceOwnership(source)?.Phase!="PREPARED_NO_OWNER"&&ReadSource(source).State!="CLOSED")
                throw new InvalidOperationException("Unresolved native owner must remain admitted");
            runtimeOwner=false;
        }
    }
}
