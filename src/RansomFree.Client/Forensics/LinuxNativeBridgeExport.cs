namespace RansomFree.Client.Forensics;

// A packet is only an immutable duplicate of committed journal/artifact bytes.
// This publisher owns no native operation and never releases source evidence.
internal sealed class LinuxNativeBridgeExport(LinuxProtectedDirectory directory,string sensor)
{
    private readonly object gate=new();
    internal string PublishCommitted(LinuxForensicJournal journal,string sourceEventId,LinuxProtectedDirectory actors)
    {
        // Inventory snapshots can become stale while the independent receipt
        // listener retires a packet. Serialize the full decision/publication/
        // ledger sequence with retirement, and honor its durable receipt even
        // after restart. Never recreate an acknowledged duplicate.
        lock(gate)
        {
        if(journal.ImportedNativeExportHash(sourceEventId) is {} imported)return imported;
        var work=journal.Read(sourceEventId);
        if(!work.Done||work.Original==null||work.Completion==null)throw new InvalidOperationException("Native event pair is not committed for export");
        var completion=System.Text.Json.JsonSerializer.Deserialize<RansomFree.Contracts.AgentEvent>(work.Completion)!;
        var preserved=completion.Forensics!.Preservation;byte[]? actor=null,manifest=null;
        if(preserved.Status.State=="captured")
        {
            if(!RansomFree.Contracts.EvidenceTransferLimits.Id(preserved.EvidenceId))throw new InvalidDataException("Native actor evidence identity invalid");
            actor=actors.Read(preserved.EvidenceId+".bin",4*1024*1024).Bytes;
            manifest=actors.Read(preserved.EvidenceId+".json",RansomFree.Contracts.EvidenceTransferLimits.ManifestBytes).Bytes;
        }
        var packet=LinuxNativeBridgePacket.Create(sensor,work.Original,work.Completion,actor,manifest);
        var hash=Publish(packet);journal.RecordNativeExport(sourceEventId,hash);return hash;
        }
    }
    internal void AcknowledgeImport(LinuxForensicJournal journal,EventSpool privateSpool,LinuxNativeBridgeImport.Receipt receipt,Action<string>? checkpoint=null)
    {
        // The receipt is unprivileged input. The root ledger binds it to an
        // already published exact packet and its completed original journal.
        // This clears only redundant local delivery copies, never source work.
        lock(gate)
        {
            var work=journal.RecordNativeImport(receipt);checkpoint?.Invoke("bridge-import-ledger-committed");
            privateSpool.AcknowledgeNativeBridgePair(work.Original!,work.Completion!);checkpoint?.Invoke("bridge-private-queue-retired");
            directory.RetireExportDuplicate(receipt.SourceEventId,receipt.PacketSha256);checkpoint?.Invoke("bridge-export-duplicate-retired");
            journal.FinishNativeImportRetirement(receipt);checkpoint?.Invoke("bridge-retirement-committed");
        }
    }
    internal string Publish(LinuxNativeBridgePacket packet,Action<string>? checkpoint=null)
    {
        var bytes=packet.Encode(sensor);var name=packet.SourceEventId+".json";
        lock(gate)
        {
            var inventory=directory.Names(256);
            if(inventory.Contains(name,StringComparer.Ordinal))
            {
                if(!directory.Read(name,LinuxNativeBridgePacket.MaximumBytes).Bytes.AsSpan().SequenceEqual(bytes))throw new InvalidDataException("Native export identity conflict; retained");
                directory.CommitDirectory();return LinuxNativeBridgePacket.Hash(bytes);
            }
            long total=bytes.Length;
            foreach(var item in inventory)
            {
                // Include retained incomplete publications in the same quota.
                var size=directory.Inspect(item).Size;
                total=checked(total+(long)size);
                if(total>64L*1024*1024)throw new IOException("Root export quota exhausted; original evidence retained");
            }
            if(inventory.Length>=256||total>64L*1024*1024)throw new IOException("Root export quota exhausted; original evidence retained");
            directory.PublishNew(name,bytes,checkpoint);return LinuxNativeBridgePacket.Hash(bytes);
        }
    }
}
