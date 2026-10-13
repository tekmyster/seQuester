using System.Buffers.Binary;
using System.Collections.Immutable;
using System.Globalization;
using System.Security.Cryptography;
using System.Text.Json;

namespace RansomFree.Contracts;

// Immutable membership table for the opt-in controlled-v2 source. No filesystem
// lookup, native handle, pathname assertion or activation authority lives here.
// The digest is a managed derivation from the exact numeric identity table,
// distinct from the SHA-256 of the retained complete native ready frame.
internal sealed class LinuxControlledTargetSet
{
    internal const int MaximumTargets=32;
    internal readonly record struct Identity(uint Device,ulong Inode);
    internal ImmutableArray<Identity> Targets {get;}
    internal string Digest {get;}
    private static ReadOnlySpan<byte> Domain=>"sequester.linux-controlled-target-set/v1\0"u8;

    private LinuxControlledTargetSet(ImmutableArray<Identity> targets)
    {
        if(targets.Length is <1 or >MaximumTargets)throw Invalid();
        for(var i=0;i<targets.Length;i++)
        {
            var item=targets[i];if(item.Device==0||item.Inode==0)throw Invalid();
            if(i>0&&Compare(targets[i-1],item)>=0)throw Invalid();
        }
        Targets=targets;Digest=Convert.ToHexString(SHA256.HashData(CanonicalBytes()));
    }
    private static int Compare(Identity a,Identity b)
    {var device=a.Device.CompareTo(b.Device);return device!=0?device:a.Inode.CompareTo(b.Inode);}
    private static InvalidDataException Invalid()=>new("Invalid canonical controlled target identity set");

    // Explicitly canonicalize a prepared revision; the native-ready parser does
    // not sort or repair a producer's malformed table.
    internal static LinuxControlledTargetSet Prepare(IEnumerable<Identity> targets)
    {
        ArgumentNullException.ThrowIfNull(targets);
        var values=targets.Take(MaximumTargets+1).ToArray();
        if(values.Length is <1 or >MaximumTargets)throw Invalid();
        Array.Sort(values,Compare);return new(values.ToImmutableArray());
    }
    internal static LinuxControlledTargetSet Parse(JsonElement table,int count)
    {
        if(count is <1 or >MaximumTargets||table.ValueKind!=JsonValueKind.Array||table.GetArrayLength()!=count)throw Invalid();
        var values=ImmutableArray.CreateBuilder<Identity>(count);var index=0u;
        foreach(var entry in table.EnumerateArray())
        {
            if(entry.ValueKind!=JsonValueKind.Object)throw Invalid();
            var names=entry.EnumerateObject().Select(x=>x.Name).ToArray();
            if(names.Length!=3||names.Distinct(StringComparer.Ordinal).Count()!=3||names.Except(new[]{"ordinal","device","inode"},StringComparer.Ordinal).Any())throw Invalid();
            ulong Number(string name)
            {
                var field=entry.GetProperty(name);
                if(field.ValueKind!=JsonValueKind.Number||!field.TryGetUInt64(out var value)||field.GetRawText()!=value.ToString(CultureInfo.InvariantCulture))throw Invalid();
                return value;
            }
            var device=Number("device");var inode=Number("inode");
            if(Number("ordinal")!=index++||device is 0 or >uint.MaxValue||inode==0)throw Invalid();
            values.Add(new((uint)device,inode));
        }
        return new(values.MoveToImmutable());
    }
    internal bool Contains(uint ordinal,uint device,ulong inode)
        =>ordinal<Targets.Length&&Targets[(int)ordinal]==new Identity(device,inode);
    internal void RequireSame(LinuxControlledTargetSet expected)
    {
        ArgumentNullException.ThrowIfNull(expected);
        if(Digest!=expected.Digest||!Targets.SequenceEqual(expected.Targets))throw new InvalidDataException("Native watched identity set differs from the prepared immutable revision");
    }
    internal byte[] CanonicalBytes()
    {
        // Domain + uint32 count + canonical map keys. Sort is numeric device,
        // then inode; each key is inode64/device32/reserved32, little endian.
        var bytes=new byte[Domain.Length+4+16*Targets.Length];Domain.CopyTo(bytes);
        BinaryPrimitives.WriteUInt32LittleEndian(bytes.AsSpan(Domain.Length),(uint)Targets.Length);
        for(var i=0;i<Targets.Length;i++)
        {
            var offset=Domain.Length+4+16*i;
            BinaryPrimitives.WriteUInt64LittleEndian(bytes.AsSpan(offset),Targets[i].Inode);
            BinaryPrimitives.WriteUInt32LittleEndian(bytes.AsSpan(offset+8),Targets[i].Device);
            // Reserved bytes stay zero, matching the native lookup key.
        }
        return bytes;
    }
    internal void Write(Utf8JsonWriter writer)
    {
        writer.WriteStartArray();
        for(var i=0;i<Targets.Length;i++)
        {
            writer.WriteStartObject();writer.WriteNumber("ordinal",i);writer.WriteNumber("device",Targets[i].Device);writer.WriteNumber("inode",Targets[i].Inode);writer.WriteEndObject();
        }
        writer.WriteEndArray();
    }
}
