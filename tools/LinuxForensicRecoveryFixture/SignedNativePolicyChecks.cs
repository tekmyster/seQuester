using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using RansomFree.Contracts;

internal static class SignedNativePolicyChecks
{
    internal static void Run(string root)
    {
        if(Directory.Exists(root))throw new ArgumentException("Fresh fixture root required");Directory.CreateDirectory(root);
        var checks=new List<string>();void Check(bool ok,string label){if(!ok)throw new Exception(label);checks.Add(label);}
        void Reject(Action action,string label){try{action();}catch(Exception ex)when(ex is InvalidDataException or ArgumentException or CryptographicException){Check(true,label);return;}throw new Exception("Accepted: "+label);}
        using var key=RSA.Create(3072);using var other=RSA.Create(3072);var pub=key.ExportSubjectPublicKeyInfo();
        var now=DateTimeOffset.UtcNow;var sensor=Guid.NewGuid().ToString("N");var nonce=Convert.ToHexString(RandomNumberGenerator.GetBytes(32));const string origin="https://qualification.invalid/";
        var policy=new TrustPolicy(1,"enforce",[],[],"fixture",now.AddMinutes(-1)){Version=3};
        var assignment=new AssignedTrustPolicy(sensor,null,policy,policy.Digest(),now,now.AddMinutes(2));
        var source=new NativePolicySnapshot(origin,sensor,nonce,now,now.AddMinutes(2),assignment,new(null,0,MonitoringPolicy.Default));
        var signed=SignedNativePolicy.Sign(source,key);
        NativePolicySnapshot Verify(SignedNativePolicy? value=null,byte[]? pin=null,string? server=null,string? endpoint=null,string? challenge=null,DateTimeOffset? at=null)=>(value??signed).Verify(pin??pub,server??origin,endpoint??sensor,challenge??nonce,at??now);
        Check(JsonSerializer.Serialize(Verify())==JsonSerializer.Serialize(source),"real RSA-PSS signature verifies exact assignments, sensor and challenge");
        Check(signed.KeyId==Convert.ToHexString(SHA256.HashData(pub)),"key identity is SHA-256 of exact pinned SPKI");
        Check(JsonSerializer.Serialize(Verify(JsonSerializer.Deserialize<SignedNativePolicy>(JsonSerializer.Serialize(signed))!))==JsonSerializer.Serialize(source),"JSON relay retains exact signed envelope");
        Reject(()=>Verify(pin:other.ExportSubjectPublicKeyInfo()),"different pinned verification key refused");
        Reject(()=>Verify(server:"https://another.invalid/"),"different server origin refused");
        Reject(()=>Verify(endpoint:Guid.NewGuid().ToString("N")),"different enrolled sensor refused");
        Reject(()=>Verify(challenge:Convert.ToHexString(RandomNumberGenerator.GetBytes(32))),"different root challenge refused");
        Reject(()=>Verify(at:source.ExpiresUtc),"expired envelope refused at exact expiry");
        Reject(()=>Verify(at:now.AddSeconds(-31)),"future-issued envelope refused beyond clock tolerance");
        Reject(()=>Verify(signed with{Version=2}),"unknown envelope version refused");
        Reject(()=>Verify(signed with{Algorithm="RSA-PKCS1-SHA256"}),"different signature algorithm refused");
        Reject(()=>Verify(signed with{KeyId=new string('0',64)}),"different key identifier refused");
        Reject(()=>Verify(signed with{PayloadBase64=signed.PayloadBase64+"\n"}),"noncanonical base64 refused");
        Reject(()=>Verify(signed with{SignatureBase64="invalid"}),"malformed signature encoding refused");
        var damaged=Convert.FromBase64String(signed.PayloadBase64);damaged[damaged.Length-2]^=1;
        Reject(()=>Verify(signed with{PayloadBase64=Convert.ToBase64String(damaged)}),"changed signed payload refused");
        var sig=Convert.FromBase64String(signed.SignatureBase64);sig[0]^=1;
        Reject(()=>Verify(signed with{SignatureBase64=Convert.ToBase64String(sig)}),"changed signature refused");
        SignedNativePolicy Raw(string json,bool domain=true)
        {
            var data=Encoding.UTF8.GetBytes(json);var input=domain?Encoding.ASCII.GetBytes("sequester.native-policy.signature.v1\0").Concat(data).ToArray():data;
            return new(1,"RSA-PSS-SHA256",signed.KeyId,Convert.ToBase64String(data),Convert.ToBase64String(key.SignData(input,HashAlgorithmName.SHA256,RSASignaturePadding.Pss)));
        }
        var exact=Encoding.UTF8.GetString(Convert.FromBase64String(signed.PayloadBase64));
        Reject(()=>Verify(Raw(exact,false)),"valid RSA signature without domain separation refused");
        Reject(()=>Verify(Raw(exact[..^1]+",\"Unreviewed\":true}")),"even correctly signed unknown policy fields refused");
        Reject(()=>Verify(Raw(exact[..^1]+",\"Version\":1}")),"duplicate signed JSON fields refused");
        Reject(()=>SignedNativePolicy.Sign(source with{Version=2},key),"unknown snapshot schema cannot be signed");
        Reject(()=>SignedNativePolicy.Sign(source with{Purpose="other"},key),"different snapshot purpose cannot be signed");
        Reject(()=>SignedNativePolicy.Sign(source with{Trust=assignment with{EndpointId=Guid.NewGuid().ToString("N")}},key),"mismatched assignment endpoint cannot be signed");
        Reject(()=>SignedNativePolicy.Sign(source with{Monitoring=new(Guid.NewGuid().ToString("N"),0,MonitoringPolicy.Default)},key),"inconsistent general and trust groups cannot be signed");
        Reject(()=>SignedNativePolicy.Sign(source with{ExpiresUtc=now.AddMinutes(6),Trust=assignment with{ExpiresUtc=now.AddMinutes(6)}},key),"overlong native policy lifetime refused");
        Reject(()=>SignedNativePolicy.Sign(source with{Monitoring=new(null,-1,MonitoringPolicy.Default)},key),"negative general policy revision refused");
        foreach(var bad in new[]{"http://qualification.invalid/","https://qualification.invalid/path","https://user@qualification.invalid/","https://qualification.invalid/?x=1"})Reject(()=>SignedNativePolicy.Sign(source with{Server=bad},key),"noncanonical or unsafe management origin refused: "+bad);
        using(var weak=RSA.Create(2048))Reject(()=>SignedNativePolicy.Sign(source,weak),"unsupported weaker signing key refused");
        var appended=pub.Concat(new byte[]{0}).ToArray();Reject(()=>Verify(signed with{KeyId=SignedNativePolicy.PublicKeyId(appended)},pin:appended),"trailing SPKI bytes refused");
        Reject(()=>Verify(signed with{PayloadBase64=new string('A',700000)}),"oversized signed envelope rejected before decoding");
        // Persist only public verification material; the test private key stays in memory.
        File.WriteAllBytes(Path.Combine(root,"public-key.der"),pub);File.WriteAllText(Path.Combine(root,"envelope.json"),JsonSerializer.Serialize(signed));
        File.WriteAllText(Path.Combine(root,"RESULTS.json"),JsonSerializer.Serialize(new{Passed=true,Checks=checks.Count,Details=checks,Scope="Actual local RSA signing and verification plus structural/context failures; root challenge persistence, signed server API and installed Linux service remain pending"}));
        Console.WriteLine(JsonSerializer.Serialize(new{Passed=true,Checks=checks.Count}));
    }
}
