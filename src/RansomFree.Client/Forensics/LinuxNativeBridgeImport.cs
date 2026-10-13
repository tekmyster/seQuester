using System.Text.Json;

namespace RansomFree.Client.Forensics;

// The ordinary sensor remains the sole network sender. Receipt means local
// durable import, never server delivery or permission to release native state.
internal sealed class LinuxNativeBridgeImport(string directory,string sensor,EventSpool spool)
{
    internal sealed record Receipt(int Version,string SensorId,string SourceEventId,string CompletionEventId,string PacketSha256);
    private readonly object gate=new();
    internal Receipt Import(LinuxProtectedDirectory root,string sourceEventId,Action<string>? checkpoint=null)
    {
        if(!RansomFree.Contracts.EvidenceTransferLimits.Id(sourceEventId))throw new ArgumentException("Invalid bridge event ID");
        var input=root.Read(sourceEventId+".json",LinuxNativeBridgePacket.MaximumBytes,afterOpen:()=>checkpoint?.Invoke("bridge-export-opened"));
        return ImportVerifiedBytes(input.Bytes,sourceEventId,checkpoint);
    }
    // Only the descriptor-validated inbox path calls this in the installed
    // consumer. Internal access permits deterministic crash/replay fixtures.
    internal Receipt ImportVerifiedBytes(byte[] input,string sourceEventId,Action<string>? checkpoint=null)
    {
        var bytes=input.ToArray();var packet=LinuxNativeBridgePacket.Parse(bytes,sensor);
        if(packet.SourceEventId!=sourceEventId)throw new InvalidDataException("Bridge filename/event identity differs");
        var verified=packet.Validate(sensor);var receipt=new Receipt(1,sensor,sourceEventId,verified.Completion.EventId,LinuxNativeBridgePacket.Hash(bytes));
        lock(gate)
        {
            var receipts=Path.Combine(directory,"native-bridge-receipts");EvidenceStore.EnsurePrivate(receipts);
            var path=Path.Combine(receipts,sourceEventId+".json");var saved=JsonSerializer.SerializeToUtf8Bytes(receipt);
            if(File.Exists(path)){RequireExact(path,saved);return receipt;}
            if(verified.Actor!=null)
            {
                var actorRoot=Path.Combine(directory,"evidence","actors");EvidenceStore.EnsurePrivate(actorRoot);
                var id=verified.Completion.Forensics!.Preservation.EvidenceId!;
                SaveExact(Path.Combine(actorRoot,id+".bin"),verified.Actor);checkpoint?.Invoke("bridge-actor-imported");
                SaveExact(Path.Combine(actorRoot,id+".json"),verified.Manifest!);checkpoint?.Invoke("bridge-manifest-imported");
            }
            spool.EnqueueExact(verified.OriginalBytes);checkpoint?.Invoke("bridge-original-imported");
            spool.EnqueueExact(verified.CompletionBytes);checkpoint?.Invoke("bridge-completion-imported");
            new EvidenceUploadQueue(directory).Register(verified.Original,verified.Completion);checkpoint?.Invoke("bridge-upload-registered");
            SaveExact(path,saved);checkpoint?.Invoke("bridge-receipt-committed");return receipt;
        }
    }
    private static void RequireExact(string path,byte[] bytes)
    {
        EvidenceDurability.NoLinks(path);using var stream=new FileStream(path,FileMode.Open,FileAccess.Read,FileShare.Read);
        if(stream.Length!=bytes.LongLength)throw new InvalidDataException("Native import identity conflict; retained");
        var saved=new byte[bytes.Length];stream.ReadExactly(saved);
        if(!saved.AsSpan().SequenceEqual(bytes))throw new InvalidDataException("Native import contents conflict; retained");
        EvidenceDurability.DirectoryCommitted(Path.GetDirectoryName(path)!);
    }
    private static void SaveExact(string path,byte[] bytes)
    {
        if(File.Exists(path)){RequireExact(path,bytes);return;}
        try{EvidenceDurability.SaveNew(path,bytes);}catch(IOException)when(File.Exists(path)){RequireExact(path,bytes);}
    }
}
