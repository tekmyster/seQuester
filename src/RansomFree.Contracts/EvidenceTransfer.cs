namespace RansomFree.Contracts;

// All locations are server-generated. These messages never accept a filesystem path.
public sealed record EvidenceUploadStart(string CompletionEventId,string ManifestBase64);
public sealed record EvidenceUploadReceipt(int Version,string SensorId,string EvidenceId,string CompletionEventId,
    string Sha256,string ManifestSha256,long Size,long ReceivedBytes,string State,string ReceiptId,DateTimeOffset? ReceivedUtc);
public sealed record EvidenceTransferEvidence(string EvidenceId,string CompletionEventId,string ReceiptId,
    string Sha256,string ManifestSha256,long Size,DateTimeOffset ReceivedUtc);
public static class EvidenceTransferLimits
{
    public const int ChunkBytes=256*1024;
    public const int ManifestBytes=64*1024;
    public static bool Id(string? value)=>value is {Length:32}&&Guid.TryParseExact(value,"N",out _)&&value==value.ToLowerInvariant();
    public static bool Hash(string? value)=>value is {Length:64}&&value.All(Uri.IsHexDigit);
}
