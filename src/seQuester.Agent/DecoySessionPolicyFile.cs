using System.Text.Json;
using System.Text.Json.Serialization;
using RansomFree;
using RansomFree.Contracts;

internal static class DecoySessionPolicyFile
{
    public static DecoySessionPolicy Read(string path)
    {
        if(!Path.IsPathFullyQualified(path)||path.StartsWith("\\\\",StringComparison.Ordinal))throw new ArgumentException("Use an explicit local policy file.");
        using var pin=DeploymentPathLease.Acquire(Path.GetDirectoryName(path)!,path);
        using var file=new FileStream(path,FileMode.Open,FileAccess.Read,FileShare.Read);
        if(file.Length is <2 or >131072)throw new InvalidDataException("Session policy must be at most 128 KiB.");
        var data=new byte[(int)file.Length];file.ReadExactly(data);
        return DecoySessionProtocol.ReadPolicy(data);
    }
    // Invoked only after the existing maintenance-password check and stopped-service gate.
    public static void Publish(string input,string directory)
    {
        var policy=Read(input);if(policy.ExpiresUtc<=DateTimeOffset.UtcNow||policy.ExpiresUtc>DateTimeOffset.UtcNow.AddDays(7))throw new ArgumentException("Policy expiry must be within the next seven days.");
        using var pin=DeploymentPathLease.Acquire(directory);var destination=Path.Combine(directory,"decoy-session-policy.json");
        var lockPath=Path.Combine(directory,"decoy-session-publication.lock");
        using var lockPin=File.Exists(lockPath)?DeploymentPathLease.Acquire(directory,lockPath):null;
        using var publicationLock=new FileStream(lockPath,FileMode.OpenOrCreate,FileAccess.ReadWrite,FileShare.None);
        var ledger=Path.Combine(directory,"decoy-session-ledger.db");
        if(File.Exists(ledger)){using var ledgerPin=DeploymentPathLease.Acquire(directory,ledger);new DecoySessionLedger(ledger).ValidatePublication(policy);}
        if(File.Exists(destination))
        {
            var previous=Read(destination);
            if(policy.Revision==previous.Revision&&Same(policy,previous))return;
            if(policy.Revision<=previous.Revision)throw new InvalidOperationException("Publish a higher policy revision; prior policy preserved.");
            var backup=Path.Combine(directory,$"decoy-session-policy.revision-{previous.Revision}.json");
            if(File.Exists(backup))
            {
                if(!Same(Read(backup),previous))throw new InvalidDataException("Retained policy archive conflicts; nothing overwritten.");
            }
            else
            {
                if(Directory.EnumerateFiles(directory,"decoy-session-policy.revision-*.json").Take(32).Count()>=32)throw new IOException("Policy archive capacity reached. Export evidence before reviewed maintenance.");
                using var saved=new FileStream(backup,FileMode.CreateNew,FileAccess.Write,FileShare.None);JsonSerializer.Serialize(saved,previous);saved.Flush(true);
            }
        }
        var temporary=Path.Combine(directory,"decoy-session-policy."+Guid.NewGuid().ToString("N")+".pending");
        using(var file=new FileStream(temporary,FileMode.CreateNew,FileAccess.Write,FileShare.None)){JsonSerializer.Serialize(file,policy);file.Flush(true);}
        File.Move(temporary,destination,true);
    }
    private static bool Same(DecoySessionPolicy left,DecoySessionPolicy right)=>JsonSerializer.SerializeToUtf8Bytes(left).AsSpan().SequenceEqual(JsonSerializer.SerializeToUtf8Bytes(right));
}
