using RansomFree.Contracts;
using System.Buffers.Binary;
using System.Text.Json;
using RansomFree.Client;

internal static class ControlledTargetSetChecks
{
    internal static void Run()
    {
        var checks=0;
        void Check(bool value,string label){checks++;if(!value)throw new IOException(label);}
        void Reject(Action action,string label){try{action();}catch(InvalidDataException){Check(true,label);return;}throw new IOException("Accepted "+label);}
        byte[] Encode(LinuxControlledTargetSet set){using var stream=new MemoryStream();using(var writer=new Utf8JsonWriter(stream)){set.Write(writer);}return stream.ToArray();}
        var entries=new[]{new LinuxControlledTargetSet.Identity(8,100),new LinuxControlledTargetSet.Identity(9,200)};
        var prepared=LinuxControlledTargetSet.Prepare(entries.Reverse());
        Check(prepared.Targets.SequenceEqual(entries),"prepared revision has canonical numeric device/inode order");
        var canonical=prepared.CanonicalBytes();
        Check(BinaryPrimitives.ReadUInt64LittleEndian(canonical.AsSpan(canonical.Length-32))==100&&BinaryPrimitives.ReadUInt32LittleEndian(canonical.AsSpan(canonical.Length-24))==8&&canonical.AsSpan(canonical.Length-20,4).ContainsAnyExcept((byte)0)==false,"canonical digest keys use explicit little-endian zero-padded native identity");
        var saved=canonical.ToArray();canonical[0]^=0x40;entries[0]=new(8,999);
        Check(prepared.CanonicalBytes().AsSpan().SequenceEqual(saved)&&prepared.Targets[0].Inode==100,"caller arrays cannot mutate an accepted immutable revision");
        using(var json=JsonDocument.Parse(Encode(prepared))){var parsed=LinuxControlledTargetSet.Parse(json.RootElement,2);parsed.RequireSame(prepared);Check(parsed.Digest==prepared.Digest,"native-ready canonical table has exact prepared digest and tuple sequence");}
        Check(prepared.Contains(0,8,100)&&prepared.Contains(1,9,200)&&!prepared.Contains(0,9,200)&&!prepared.Contains(1,8,100)&&!prepared.Contains(2,8,100),"event tuple must match exact ordinal; no path-based substitution");
        var replacement=LinuxControlledTargetSet.Prepare(new[]{new LinuxControlledTargetSet.Identity(8,101),new LinuxControlledTargetSet.Identity(9,200)});
        Reject(()=>replacement.RequireSame(prepared),"replacement inode needs a new revision");
        Check(replacement.Digest!=prepared.Digest,"changed inode invalidates canonical target digest");
        Reject(()=>LinuxControlledTargetSet.Prepare(Array.Empty<LinuxControlledTargetSet.Identity>()),"empty set");
        Reject(()=>LinuxControlledTargetSet.Prepare(Enumerable.Range(1,33).Select(i=>new LinuxControlledTargetSet.Identity(8,(ulong)i))),"33 targets");
        Reject(()=>LinuxControlledTargetSet.Prepare(new[]{new LinuxControlledTargetSet.Identity(8,1),new LinuxControlledTargetSet.Identity(8,1)}),"duplicate hardlink identity");
        Reject(()=>LinuxControlledTargetSet.Prepare(new[]{new LinuxControlledTargetSet.Identity(0,1)}),"zero device");
        Reject(()=>LinuxControlledTargetSet.Prepare(new[]{new LinuxControlledTargetSet.Identity(1,0)}),"zero inode");
        foreach(var malformed in new[]{
            "[]", "{}", "[{\"ordinal\":1,\"device\":8,\"inode\":100}]",
            "[{\"ordinal\":0,\"device\":4294967296,\"inode\":100}]",
            "[{\"ordinal\":0,\"device\":8,\"inode\":0}]",
            "[{\"ordinal\":0,\"device\":8,\"inode\":1e2}]",
            "[{\"ordinal\":0,\"device\":8,\"inode\":\"100\"}]",
            "[{\"ordinal\":0,\"device\":8,\"inode\":100,\"inode\":101}]",
            "[{\"ordinal\":0,\"device\":8,\"inode\":100,\"path\":\"expected\"}]"})
        {
            using var json=JsonDocument.Parse(malformed);Reject(()=>LinuxControlledTargetSet.Parse(json.RootElement,1),"malformed or noncanonical native tuple");
        }
        foreach(var bad in new[]{
            "[{\"ordinal\":0,\"device\":9,\"inode\":200},{\"ordinal\":1,\"device\":8,\"inode\":100}]",
            "[{\"ordinal\":0,\"device\":8,\"inode\":100},{\"ordinal\":1,\"device\":8,\"inode\":100}]"})
        {using var json=JsonDocument.Parse(bad);Reject(()=>LinuxControlledTargetSet.Parse(json.RootElement,2),"native ready order/duplicate cannot be repaired by sorting");}
        var maximum=LinuxControlledTargetSet.Prepare(Enumerable.Range(0,32).Select(i=>new LinuxControlledTargetSet.Identity(uint.MaxValue,ulong.MaxValue-(ulong)i)));
        var maximumJson=Encode(maximum);using(var json=JsonDocument.Parse(maximumJson)){LinuxControlledTargetSet.Parse(json.RootElement,32).RequireSame(maximum);Check(true,"32 maximal-width target tuples round trip exactly");}
        Check(maximumJson.Length<3000,"actual textual JSON tuple table fits its declared budget; binary tuple width is not assumed");
        Console.WriteLine(JsonSerializer.Serialize(new{Passed=true,Checks=checks,PreparedDigest=prepared.Digest,CanonicalBytesHex=Convert.ToHexString(saved),MaximumJsonBytes=maximumJson.Length,Scope="Managed immutable target membership/digest only; no native watch map, v2 activation, service launch or filesystem claims"}));
    }
}
