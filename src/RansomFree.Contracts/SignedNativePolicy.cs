using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace RansomFree.Contracts;

// Relayable server evidence. Only a separately root-pinned public key may verify
// this envelope. Verification alone does not consume a challenge or start a source.
public sealed record NativePolicySnapshot(string Server,string SensorId,string Challenge,
    DateTimeOffset IssuedUtc,DateTimeOffset ExpiresUtc,AssignedTrustPolicy Trust,AssignedPolicy Monitoring)
{
    public int Version {get;init;}=1;
    public string Purpose {get;init;}="sequester.native-policy.v1";
    public void Validate()
    {
        if(Version!=1||Purpose!="sequester.native-policy.v1"||!ValidOrigin(Server)||!Guid.TryParseExact(SensorId,"N",out _)||
            !Hex(Challenge,64)||IssuedUtc==default||ExpiresUtc<=IssuedUtc||ExpiresUtc-IssuedUtc>TimeSpan.FromMinutes(5)||Trust==null||Monitoring==null)
            throw new InvalidDataException("Invalid native policy snapshot");
        Trust.Validate();
        if(Trust.EndpointId!=SensorId||Trust.GroupId!=Monitoring.GroupId||Trust.IssuedUtc!=IssuedUtc||Trust.ExpiresUtc!=ExpiresUtc||
            Trust.Policy.PublishedUtc>IssuedUtc||Monitoring.Revision<0||Monitoring.Settings?.IsValid()!=true)
            throw new InvalidDataException("Inconsistent native policy assignments");
    }
    public static bool ValidOrigin(string? value)=>value is {Length:<=2048}&&Uri.TryCreate(value,UriKind.Absolute,out var origin)&&
        origin.Scheme=="https"&&origin.AbsolutePath=="/"&&origin.UserInfo.Length==0&&origin.Query.Length==0&&origin.Fragment.Length==0&&origin.AbsoluteUri==value;
    internal static bool Hex(string? value,int length)=>value?.Length==length&&value.All(Uri.IsHexDigit);
}

public sealed record SignedNativePolicy(int Version,string Algorithm,string KeyId,string PayloadBase64,string SignatureBase64)
{
    private const int MaximumPayload=524288;
    private static readonly byte[] Domain=Encoding.ASCII.GetBytes("sequester.native-policy.signature.v1\0");
    private static byte[] SignedBytes(byte[] payload)=>[..Domain,..payload];
    public static string PublicKeyId(ReadOnlySpan<byte> subjectPublicKeyInfo)=>Convert.ToHexString(SHA256.HashData(subjectPublicKeyInfo));
    public static SignedNativePolicy Sign(NativePolicySnapshot snapshot,RSA key)
    {
        if(key.KeySize is not (3072 or 4096))throw new InvalidDataException("Native policy RSA key must be 3072 or 4096 bits");
        // Freeze before validation/signing; caller-owned arrays cannot change the
        // bytes between these operations. The verifier requires the same codec.
        var payload=JsonSerializer.SerializeToUtf8Bytes(snapshot);_=ReadPayload(payload);
        return new(1,"RSA-PSS-SHA256",PublicKeyId(key.ExportSubjectPublicKeyInfo()),Convert.ToBase64String(payload),
            Convert.ToBase64String(key.SignData(SignedBytes(payload),HashAlgorithmName.SHA256,RSASignaturePadding.Pss)));
    }
    public NativePolicySnapshot Verify(ReadOnlySpan<byte> pinnedPublicKey,string expectedServer,string expectedSensor,string expectedChallenge,DateTimeOffset now)
    {
        if(Version!=1||Algorithm!="RSA-PSS-SHA256"||pinnedPublicKey.Length is <300 or >1024||
            !NativePolicySnapshot.Hex(KeyId,64)||KeyId!=PublicKeyId(pinnedPublicKey)||!NativePolicySnapshot.ValidOrigin(expectedServer)||
            !Guid.TryParseExact(expectedSensor,"N",out _)||!NativePolicySnapshot.Hex(expectedChallenge,64))
            throw new InvalidDataException("Native policy verification context invalid");
        var payload=Decode(PayloadBase64,MaximumPayload);var signature=Decode(SignatureBase64,512);
        using var key=RSA.Create();key.ImportSubjectPublicKeyInfo(pinnedPublicKey,out var used);
        if(used!=pinnedPublicKey.Length||key.KeySize is not (3072 or 4096)||signature.Length!=key.KeySize/8||
            !key.VerifyData(SignedBytes(payload),signature,HashAlgorithmName.SHA256,RSASignaturePadding.Pss))
            throw new InvalidDataException("Native policy signature invalid");
        var snapshot=ReadPayload(payload);
        if(snapshot.Server!=expectedServer||snapshot.SensorId!=expectedSensor||snapshot.Challenge!=expectedChallenge||
            snapshot.IssuedUtc>now.AddSeconds(30)||snapshot.ExpiresUtc<=now)
            throw new InvalidDataException("Native policy context or validity mismatch");
        return snapshot;
    }
    private static byte[] Decode(string? value,int limit)
    {
        if(value==null||value.Length==0||value.Length>((limit+2)/3)*4)throw new InvalidDataException("Native policy encoding exceeds bound");
        byte[] bytes;try{bytes=Convert.FromBase64String(value);}catch(FormatException ex){throw new InvalidDataException("Invalid native policy encoding",ex);}
        if(bytes.Length>limit||Convert.ToBase64String(bytes)!=value)throw new InvalidDataException("Noncanonical native policy encoding");return bytes;
    }
    private static NativePolicySnapshot ReadPayload(byte[] payload)
    {
        if(payload.Length is <1 or >MaximumPayload)throw new InvalidDataException("Native policy payload exceeds bound");
        NativePolicySnapshot value;
        try{value=JsonSerializer.Deserialize<NativePolicySnapshot>(payload)??throw new InvalidDataException("Empty native policy snapshot");}
        catch(JsonException ex){throw new InvalidDataException("Invalid native policy JSON",ex);}
        value.Validate();
        if(!JsonSerializer.SerializeToUtf8Bytes(value).AsSpan().SequenceEqual(payload))
            throw new InvalidDataException("Unknown, duplicate or noncanonical native policy fields");
        return value;
    }
}
