using System.Text.Json;
using RansomFree.Contracts;

namespace RansomFree.Client.Forensics;

// Frozen five-field policy representation used by raw-reserve-v2. Keep the
// original default-v1 bytes even if the public policy record later evolves.
internal static class LinuxRawPolicyCodec
{
    internal static byte[] Encode(ForensicPolicy policy)
    {
        if(!policy.IsValid())throw new InvalidDataException("Invalid raw policy");
        using var buffer=new MemoryStream();
        using(var writer=new Utf8JsonWriter(buffer))
        {
            writer.WriteStartObject();
            writer.WriteBoolean("PreserveActorOnAlert",policy.PreserveActorOnAlert);
            writer.WriteString("PreservationThreshold",policy.PreservationThreshold);
            writer.WriteNumber("MaximumActorMiB",policy.MaximumActorMiB);
            writer.WriteNumber("EvidenceStoreMiB",policy.EvidenceStoreMiB);
            writer.WriteNumber("CacheEntries",policy.CacheEntries);
            writer.WriteEndObject();
        }
        return buffer.ToArray();
    }
    internal static ForensicPolicy Decode(ReadOnlyMemory<byte> bytes)
    {
        using var doc=JsonDocument.Parse(bytes);var p=doc.RootElement;
        if(p.ValueKind!=JsonValueKind.Object||p.EnumerateObject().Count()!=5)throw new InvalidDataException("Unsupported raw policy codec");
        var result=new ForensicPolicy(p.GetProperty("PreserveActorOnAlert").GetBoolean(),p.GetProperty("PreservationThreshold").GetString()!,
            p.GetProperty("MaximumActorMiB").GetInt32(),p.GetProperty("EvidenceStoreMiB").GetInt32(),p.GetProperty("CacheEntries").GetInt32());
        if(!Encode(result).AsSpan().SequenceEqual(bytes.Span))throw new InvalidDataException("Raw policy codec mismatch; explicit migration required");
        return result;
    }
}
