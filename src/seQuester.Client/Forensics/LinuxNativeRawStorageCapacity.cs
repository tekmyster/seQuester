using System.Text.Json;

namespace RansomFree.Client.Forensics;

// Root-only disk capacity configuration. This is not a policy lease, event
// suppression rule or permission to discard evidence. All retained banks still
// consume the bounded quota, including preparations that never started a loader.
internal static class LinuxNativeRawStorageCapacity
{
    internal const long DefaultBytes=512L*1024*1024;
    internal const long MaximumBytes=8L*1024*1024*1024;
    internal const string FileName="raw-bank-capacity.json";
    internal sealed record Definition(int Version,string SensorId,long QuotaBytes);
    internal static long RequireQuota(long value)
    {
        if(value<DefaultBytes||value>MaximumBytes||value%(1024*1024)!=0)
            throw new InvalidDataException("Native raw bank capacity must be a whole MiB between 512 MiB and 8 GiB");
        return value;
    }
    internal static long Parse(ReadOnlySpan<byte> bytes,string sensor)
    {
        if(!Guid.TryParseExact(sensor,"N",out _)||bytes.Length is <1 or >4096)
            throw new InvalidDataException("Bounded sensor-specific raw storage capacity required");
        Definition value;
        try{value=JsonSerializer.Deserialize<Definition>(bytes)??throw new InvalidDataException("Missing raw storage capacity");}
        catch(JsonException e){throw new InvalidDataException("Invalid raw storage capacity JSON",e);}
        if(value.Version!=1||value.SensorId!=sensor||!JsonSerializer.SerializeToUtf8Bytes(value).AsSpan().SequenceEqual(bytes))
            throw new InvalidDataException("Raw storage capacity must have exact canonical fields and sensor identity");
        return RequireQuota(value.QuotaBytes);
    }
    internal static long Read(LinuxProtectedDirectory root,string sensor)
    {
        root.RequirePrivate();root.RequireQualifiedLocalExt4();
        if(!root.Names(16384).Contains(FileName,StringComparer.Ordinal))return DefaultBytes;
        var captured=root.Read(FileName,4096);
        if((captured.File.Mode&0x3f)!=0)throw new IOException("Raw storage capacity must be root-private");
        return Parse(captured.Bytes,sensor);
    }
}
