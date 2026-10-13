using System.Security.Cryptography;
using System.Text.Json;
using System.Text.Json.Serialization;
using RansomFree.Contracts;

internal sealed record DecoyJournalRecord(string Digest,string Nonce,DecoySessionReceipt? Receipt);

// Called only after the companion verifies the private root and acquires its session lock.
// Recovery reads evidence; it never executes an action, removes a record or rewrites intent.
internal static class DecoySessionJournal
{
    private static readonly JsonSerializerOptions Options=new()
    {
        AllowDuplicateProperties=false,RespectRequiredConstructorParameters=true,
        RespectNullableAnnotations=true,UnmappedMemberHandling=JsonUnmappedMemberHandling.Disallow,MaxDepth=8
    };
    public static DecoySessionReceipt? Recover(string root,DecoySessionJob job,string nonce,Action<FileInfo> verifyAcl)
    {
        DecoySessionProtocol.Validate(job);DecoySessionProtocol.Validate(new DecoySessionReceipt(job.JobId,nonce,"Unconfirmed"));
        var intent=Path.Combine(root,job.JobId+".json");var completed=intent+".completed";
        if(!File.Exists(intent))
        {
            if(Path.Exists(intent)||Path.Exists(completed))throw new InvalidDataException("Orphaned journal evidence requires review; no action replayed.");
            return null;
        }
        var digest=Convert.ToHexString(SHA256.HashData(JsonSerializer.SerializeToUtf8Bytes(job)));
        DecoyJournalRecord Read(string path)
        {
            using var pin=RansomFree.DeploymentPathLease.Acquire(root,path);verifyAcl(new FileInfo(path));
            using var file=new FileStream(path,FileMode.Open,FileAccess.Read,FileShare.Read);
            if(file.Length is <2 or >4096)throw new InvalidDataException("Journal record exceeds limit.");
            var saved=JsonSerializer.Deserialize<DecoyJournalRecord>(file,Options)??throw new InvalidDataException("Journal record missing.");
            if(saved.Digest!=digest||saved.Nonce!=nonce)throw new InvalidDataException("Journal identity differs from assignment; evidence preserved.");
            if(saved.Receipt is {} receipt)
            {
                DecoySessionProtocol.Validate(receipt);
                if(receipt.JobId!=job.JobId||receipt.Nonce!=nonce)throw new InvalidDataException("Journal receipt identity mismatch.");
            }
            return saved;
        }
        var original=Read(intent);
        if(Path.Exists(completed))
        {
            var result=Read(completed).Receipt??throw new InvalidDataException("Completion record has no result; evidence preserved.");
            if(original.Receipt!=null&&original.Receipt!=result)throw new InvalidDataException("Conflicting journal results preserved for review.");
            return result;
        }
        return original.Receipt??new(job.JobId,nonce,"Unconfirmed");
    }
}
