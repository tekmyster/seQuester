using System.Security.Cryptography;
using RansomFree.Contracts;

namespace RansomFree.Server;

public sealed record NativePolicyChallenge(string Challenge);
public sealed record NativePolicyVerificationKey(int Version,string Server,string Algorithm,string KeyId,string SubjectPublicKeyInfoBase64);
internal sealed class NativePolicyNotReadyException:Exception;

internal sealed class NativePolicySigner(ProtectedNotificationFiles files,IConfiguration configuration)
{
    private const string FileName="native-policy-signing-key.protected";
    private readonly object gate=new();
    private sealed record SavedKey(int Version,string Server,string KeyId,string PrivatePkcs8Base64);
    internal string Server=>NativePolicySnapshot.ValidOrigin(configuration["NativePolicy:ServerOrigin"])?configuration["NativePolicy:ServerOrigin"]!:throw new NativePolicyNotReadyException();
    private RSA ReadKey()
    {
        var saved=files.Read<SavedKey>(FileName)??throw new NativePolicyNotReadyException();
        if(saved.Version!=1||saved.Server!=Server||saved.PrivatePkcs8Base64.Length>8192)throw new InvalidDataException("Native policy signing configuration changed");
        var bytes=Convert.FromBase64String(saved.PrivatePkcs8Base64);var key=RSA.Create();
        try{key.ImportPkcs8PrivateKey(bytes,out var used);if(used!=bytes.Length||key.KeySize!=3072||SignedNativePolicy.PublicKeyId(key.ExportSubjectPublicKeyInfo())!=saved.KeyId)throw new InvalidDataException("Native policy signing key changed");return key;}
        catch{key.Dispose();throw;}
        finally{CryptographicOperations.ZeroMemory(bytes);}
    }
    internal NativePolicyVerificationKey PublicKey()
    {
        lock(gate){using var key=ReadKey();return new(1,Server,"RSA-PSS-SHA256",SignedNativePolicy.PublicKeyId(key.ExportSubjectPublicKeyInfo()),Convert.ToBase64String(key.ExportSubjectPublicKeyInfo()));}
    }
    internal NativePolicyVerificationKey Initialize()
    {
        lock(gate)
        {
            _=Server;
            // Explicit local maintenance only. Never silently rotate a missing,
            // corrupt or changed key during normal request handling.
            using var lease=new FileStream(files.Resolve("native-policy-signing-init.lock"),FileMode.OpenOrCreate,FileAccess.ReadWrite,FileShare.None);
            if(File.Exists(files.Resolve(FileName)))throw new InvalidOperationException("Native policy signing key already exists; preserved");
            using var key=RSA.Create(3072);var bytes=key.ExportPkcs8PrivateKey();
            try{files.Write(FileName,new SavedKey(1,Server,SignedNativePolicy.PublicKeyId(key.ExportSubjectPublicKeyInfo()),Convert.ToBase64String(bytes)));}
            finally{CryptographicOperations.ZeroMemory(bytes);}
            return PublicKey();
        }
    }
    internal SignedNativePolicy Sign(NativePolicySnapshot snapshot)
    {lock(gate){if(snapshot.Server!=Server)throw new InvalidDataException("Native policy origin mismatch");using var key=ReadKey();return SignedNativePolicy.Sign(snapshot,key);}}
}

public sealed partial class Store
{
    public NativePolicySnapshot NativePolicySnapshot(string server,string endpoint,string challenge,DateTimeOffset now)
    {
        if(!Contracts.NativePolicySnapshot.ValidOrigin(server)||challenge is not {Length:64}||!challenge.All(Uri.IsHexDigit))throw new ArgumentException("Invalid native policy request");
        if(!HasTrustStorage())InitializeTrustStorage();
        using var c=Open();
        // WAL readers retain one consistent policy/group snapshot without
        // acquiring the write lock used by event and artifact ingestion.
        using var transaction=c is Microsoft.Data.Sqlite.SqliteConnection sqlite?
            sqlite.BeginTransaction(deferred:true):c.BeginTransaction(System.Data.IsolationLevel.Serializable);
        using(var check=Command(c,transaction,"SELECT COUNT(*) FROM endpoints WHERE id=$id AND revoked=0",("$id",endpoint)))
            if(Convert.ToInt64(check.ExecuteScalar())!=1)throw new ArgumentException("Enrolled sensor required");
        var monitoring=ReadAssigned(c,transaction,endpoint);var policy=ReadTrust(c,transaction);var expiry=now.AddMinutes(2);
        var result=new NativePolicySnapshot(server,endpoint,challenge,now,expiry,new(endpoint,monitoring.GroupId,policy,policy.Digest(),now,expiry),monitoring);
        result.Validate();transaction.Commit();return result;
    }
}

internal static class NativePolicyApi
{
    internal static void MapNativePolicy(this WebApplication app,Func<HttpContext,string?> authenticate,Func<HttpContext,bool> administrator)
    {
        // Perform additive storage preparation before listening. The renewal
        // POST below only authenticates, reads and signs; it cannot run DDL.
        app.Services.GetRequiredService<Store>().InitializeTrustStorage();
        app.MapGet("/api/v1/admin/native-policy/key",(HttpContext c,NativePolicySigner signer)=>
        {if(!administrator(c))return Results.Unauthorized();try{return Results.Ok(signer.PublicKey());}catch(NativePolicyNotReadyException){return Results.StatusCode(503);}});
        app.MapPost("/api/v1/agent/native-policy",(HttpContext c,NativePolicyChallenge request,Store store,NativePolicySigner signer)=>
        {
            if(authenticate(c) is not {} endpoint)return Results.Unauthorized();
            if(request.Challenge is not {Length:64}||!request.Challenge.All(Uri.IsHexDigit))return Results.BadRequest();
            try{return Results.Ok(signer.Sign(store.NativePolicySnapshot(signer.Server,endpoint,request.Challenge,DateTimeOffset.UtcNow)));}
            catch(NativePolicyNotReadyException){return Results.StatusCode(503);}
        });
    }
}
