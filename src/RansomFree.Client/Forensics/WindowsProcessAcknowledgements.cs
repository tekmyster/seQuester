using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text.Json;
using RansomFree.Contracts;

namespace RansomFree.Client.Forensics;

internal sealed partial class WindowsStagedActorStore
{
    private const int MaximumPendingAcknowledgements=256,MaximumAcknowledgementAttempts=4;
    private readonly object acknowledgementGate=new();
    private Dictionary<string,ProcessAckIntent>? acknowledgementIndex;
    internal int AcknowledgementIndexLoads {get;private set;}
    private sealed record ProcessAckIntent(int Version,string Sensor,string SnapshotId,string ProcessIndex,string Provider,ulong Instance,string Claim,string ClaimSha256,DateTimeOffset QueuedUtc,DateTimeOffset RetryUntilUtc,int MaximumAttempts);
    private sealed record ProcessAckAttempt(int Version,string SnapshotId,string ClaimSha256,int Attempt,DateTimeOffset StartedUtc);
    private sealed record ProcessAckResult(int Version,string SnapshotId,string ClaimSha256,int Attempt,DateTimeOffset RecordedUtc,string Outcome,string? NativeCode,
        [property:System.Text.Json.Serialization.JsonIgnore(Condition=System.Text.Json.Serialization.JsonIgnoreCondition.WhenWritingNull)] string? ReplacesOutcomeSha256=null);
    private sealed record InvalidAckOutcome(int Version,string SnapshotId,string ClaimSha256,string OutcomeSha256,DateTimeOffset DetectedUtc);
    private string AckFile(string id,string suffix)=>Path.ChangeExtension(ArtifactPath(id),suffix);
    private static byte[] ProcessClaim(ProcessRecord record)=>WindowsStagedActorProtocol.DurableAcknowledgement(TransferFields(record.Ready) with
    {Status=EvidenceStatus.Captured("durable-process-acquisition"),SnapshotId=record.SnapshotId,SnapshotSha256=record.Sha256,SnapshotFile=record.SnapshotFile,PersistedUtc=record.RecordedUtc});
    private T ReadAckJson<T>(string path)
    {
        using var file=Open(path,FileMode.Open,FileAccess.Read);if(file.Length>8192)throw new InvalidDataException("Oversized actor acknowledgement record");
        return JsonSerializer.Deserialize<T>(file)??throw new InvalidDataException("Missing actor acknowledgement record");
    }
    private void SaveAckJson<T>(string path,T value)
    {
        var bytes=JsonSerializer.SerializeToUtf8Bytes(value);if(bytes.Length>8192)throw new InvalidDataException("Oversized actor acknowledgement record");
        lock(gate){SaveImmutable(path,bytes);if(!File.ReadAllBytes(path).AsSpan().SequenceEqual(bytes))throw new IOException("Actor acknowledgement readback differs");}
    }
    private ProcessAckIntent QueueProcessAcknowledgement(ProcessRecord record,Action<string> health)
    {
        var claim=ProcessClaim(record);var path=AckFile(record.SnapshotId!,"ack-intent.json");
        lock(acknowledgementGate)
        {
            EnsureAcknowledgementIndex(health);
            if(File.Exists(path))
            {
                var existing=ValidateAckIntent(path,record,claim);
                if(ReadAcknowledgementOutcome(existing,out _)==null)
                {
                    if(!acknowledgementIndex!.ContainsKey(existing.SnapshotId)&&acknowledgementIndex.Count>=MaximumPendingAcknowledgements)throw new IOException("Actor acknowledgement outbox capacity reached; ready cursor withheld");
                    acknowledgementIndex[existing.SnapshotId]=existing;
                }
                return existing;
            }
            if(acknowledgementIndex!.Count>=MaximumPendingAcknowledgements)
                throw new IOException("Actor acknowledgement outbox capacity reached; ready cursor withheld");
            var now=DateTimeOffset.UtcNow;
            // This is an explicit local retry window, not a claim about the
            // kernel clock or candidate/tombstone lifetime. Attempt count also
            // bounds retries if wall-clock time is adjusted during recovery.
            var intent=new ProcessAckIntent(1,sensor,record.SnapshotId!,Path.GetFileName(ProcessPath(record.Ready)),record.Ready.Provider,record.Ready.OperationInstance,Convert.ToBase64String(claim),Convert.ToHexString(SHA256.HashData(claim)),now,now.AddSeconds(30),MaximumAcknowledgementAttempts);
            SaveAckJson(path,intent);acknowledgementIndex.Add(intent.SnapshotId,intent);return intent;
        }
    }
    private void EnsureAcknowledgementIndex(Action<string> health)
    {
        if(acknowledgementIndex!=null)return;
        var pending=new Dictionary<string,ProcessAckIntent>(StringComparer.Ordinal);
        // Rebuild once for this store owner. Historical terminal records require
        // semantic validation on recovery, but not repeated binary hashing or a
        // directory scan on every retry tick. New durable intents update this
        // bounded index under acknowledgementGate.
        foreach(var path in Directory.EnumerateFiles(root,"*.ack-intent.json"))
        {
            var intent=ValidateAckIntent(path);
            if(ReadAcknowledgementOutcome(intent,out var invalid)==null)
            {
                if(pending.Count>=MaximumPendingAcknowledgements)throw new InvalidDataException("Actor ACK outbox exceeds bound during recovery");
                pending.Add(intent.SnapshotId,intent);
                if(invalid!=null)health("Invalid actor ACK terminal record retained; exact intent remains pending: "+intent.SnapshotId);
            }
        }
        acknowledgementIndex=pending;AcknowledgementIndexLoads++;
    }
    private ProcessAckResult? ReadAcknowledgementOutcome(ProcessAckIntent intent,out string? invalidHash)
    {
        invalidHash=null;var path=AckFile(intent.SnapshotId,"ack-outcome.json");
        if(!File.Exists(path))return null;
        byte[] bytes;
        using(var file=Open(path,FileMode.Open,FileAccess.Read))
        {
            if(file.Length>8192)throw new InvalidDataException("Oversized damaged ACK outcome retained; automatic repair refused");
            bytes=new byte[checked((int)file.Length)];file.ReadExactly(bytes);
        }
        var digest=Convert.ToHexString(SHA256.HashData(bytes));var marker=AckFile(intent.SnapshotId,"ack-outcome-invalid-"+digest+".json");
        if(File.Exists(marker))
        {
            var invalid=ReadAckJson<InvalidAckOutcome>(marker);
            if(invalid.Version!=1||invalid.SnapshotId!=intent.SnapshotId||invalid.ClaimSha256!=intent.ClaimSha256||invalid.OutcomeSha256!=digest||invalid.DetectedUtc==default)throw new InvalidDataException("Invalid ACK corruption marker");
        }
        else
        try
        {
            var outcome=JsonSerializer.Deserialize<ProcessAckResult>(bytes)??throw new InvalidDataException("Missing actor acknowledgement outcome");ValidateAcknowledgementOutcome(intent,outcome,null);return outcome;
        }
        catch(Exception ex)when(ex is InvalidDataException or JsonException or FileNotFoundException)
        {
            // Commit invalidity before any retry can create the missing proof.
            // Later ACK success cannot retroactively validate the old outcome.
            SaveAckJson(marker,new InvalidAckOutcome(1,intent.SnapshotId,intent.ClaimSha256,digest,DateTimeOffset.UtcNow));
        }
        invalidHash=digest;
        // A repair is a new immutable record linked to the exact damaged
        // bytes. The original outcome is never overwritten or discarded.
        var repair=AckFile(intent.SnapshotId,"ack-outcome-recovery-"+invalidHash+".json");
        if(!File.Exists(repair))return null;
        var recovered=ReadAckJson<ProcessAckResult>(repair);ValidateAcknowledgementOutcome(intent,recovered,invalidHash);return recovered;
    }
    private void ValidateAcknowledgementOutcome(ProcessAckIntent intent,ProcessAckResult outcome,string? replaced)
    {
        if(outcome.Version!=1||outcome.SnapshotId!=intent.SnapshotId||outcome.ClaimSha256!=intent.ClaimSha256||outcome.Attempt is <0 or >MaximumAcknowledgementAttempts||outcome.RecordedUtc==default||outcome.ReplacesOutcomeSha256!=replaced||
            outcome.Outcome is not ("ACK_CONFIRMED" or "ACK_TRANSPORT_EXHAUSTED" or "ACK_RETRY_WINDOW_EXPIRED" or "ACK_PROVIDER_CHANGED" or "ACK_CLOCK_ROLLBACK")||outcome.NativeCode?.Length>128)
            throw new InvalidDataException("Invalid actor ACK terminal linkage/state");
        if(outcome.Outcome=="ACK_TRANSPORT_EXHAUSTED"&&outcome.Attempt!=MaximumAcknowledgementAttempts||outcome.Outcome=="ACK_RETRY_WINDOW_EXPIRED"&&outcome.RecordedUtc<intent.RetryUntilUtc)
            throw new InvalidDataException("ACK terminal policy differs");
        for(var number=1;number<=outcome.Attempt;number++)
        {
            var attempt=ReadAckJson<ProcessAckAttempt>(AckFile(intent.SnapshotId,"ack-attempt-"+number+".json"));
            if(attempt.Version!=1||attempt.SnapshotId!=intent.SnapshotId||attempt.ClaimSha256!=intent.ClaimSha256||attempt.Attempt!=number||attempt.StartedUtc<intent.QueuedUtc||attempt.StartedUtc>=intent.RetryUntilUtc)throw new InvalidDataException("ACK terminal attempt differs");
        }
        if(outcome.Outcome=="ACK_CONFIRMED")VerifySavedAcknowledgement(intent);
    }
    private void VerifySavedAcknowledgement(ProcessAckIntent intent)
    {
        var claim=Convert.FromBase64String(intent.Claim);
        using var file=Open(AckFile(intent.SnapshotId,"ack"),FileMode.Open,FileAccess.Read);var saved=new byte[claim.Length];
        if(file.Length!=claim.Length)throw new InvalidDataException("Proactive ACK proof length differs");file.ReadExactly(saved);
        if(!saved.AsSpan().SequenceEqual(claim))throw new InvalidDataException("Proactive ACK proof differs");
    }
    private ProcessAckIntent ValidateAckIntent(string path,ProcessRecord? record=null,byte[]? claim=null)
    {
        var intent=ReadAckJson<ProcessAckIntent>(path);
        if(intent.Version!=1||intent.Sensor!=sensor||intent.MaximumAttempts!=MaximumAcknowledgementAttempts||intent.QueuedUtc==default||intent.RetryUntilUtc!=intent.QueuedUtc.AddSeconds(30)||intent.ProcessIndex==null||Path.GetFileName(intent.ProcessIndex)!=intent.ProcessIndex||!intent.ProcessIndex.EndsWith(".process.json",StringComparison.Ordinal)||path!=AckFile(intent.SnapshotId,"ack-intent.json"))throw new InvalidDataException("Invalid actor ACK intent");
        record??=ReadProcess(Path.Combine(root,intent.ProcessIndex));
        if(record.State!="captured"||record.SnapshotId!=intent.SnapshotId||record.Ready.Provider!=intent.Provider||record.Ready.OperationInstance!=intent.Instance||Path.GetFileName(ProcessPath(record.Ready))!=intent.ProcessIndex)throw new InvalidDataException("ACK intent process linkage differs");
        claim??=ProcessClaim(record);
        if(intent.Claim!=Convert.ToBase64String(claim)||intent.ClaimSha256!=Convert.ToHexString(SHA256.HashData(claim)))throw new InvalidDataException("Actor ACK intent claim differs");return intent;
    }
    private void AckOutcome(ProcessAckIntent intent,string outcome,int attempt,string? native,DateTimeOffset now,Action<string> health)
    {
        if(ReadAcknowledgementOutcome(intent,out var invalid)==null)
        {
            var suffix=invalid==null?"ack-outcome.json":"ack-outcome-recovery-"+invalid+".json";
            SaveAckJson(AckFile(intent.SnapshotId,suffix),new ProcessAckResult(1,intent.SnapshotId,intent.ClaimSha256,attempt,now,outcome,native,invalid));
            if(ReadAcknowledgementOutcome(intent,out _)==null)throw new InvalidDataException("Actor ACK terminal readback unavailable");
        }
        acknowledgementIndex?.Remove(intent.SnapshotId);
        if(outcome!="ACK_CONFIRMED")health("Committed proactive snapshot retained; acknowledgement terminal outcome="+outcome+", native="+(native??"unavailable"));
    }
    private void AttemptProcessAcknowledgement(ProcessAckIntent intent,string provider,ulong instance,Func<byte[],int,byte[]> send,Action<string> health,DateTimeOffset now)
    {
        lock(acknowledgementGate)
        {
            intent=ValidateAckIntent(AckFile(intent.SnapshotId,"ack-intent.json"));var claim=Convert.FromBase64String(intent.Claim);var ack=AckFile(intent.SnapshotId,"ack");
            if(ReadAcknowledgementOutcome(intent,out _)!=null){acknowledgementIndex?.Remove(intent.SnapshotId);return;}
            if(File.Exists(ack))
            {
                VerifySavedAcknowledgement(intent);AckOutcome(intent,"ACK_CONFIRMED",0,null,now,health);return;
            }
            if(intent.Provider!=provider||intent.Instance!=instance){AckOutcome(intent,"ACK_PROVIDER_CHANGED",0,null,now,health);return;}
            if(now<intent.QueuedUtc){AckOutcome(intent,"ACK_CLOCK_ROLLBACK",0,null,now,health);return;}
            if(now>=intent.RetryUntilUtc){AckOutcome(intent,"ACK_RETRY_WINDOW_EXPIRED",0,null,now,health);return;}
            ProcessAckAttempt? last=null;var count=0;
            for(var i=1;i<=MaximumAcknowledgementAttempts;i++)
            {
                var path=AckFile(intent.SnapshotId,"ack-attempt-"+i+".json");if(!File.Exists(path))break;
                var previous=ReadAckJson<ProcessAckAttempt>(path);
                if(previous.Version!=1||previous.SnapshotId!=intent.SnapshotId||previous.ClaimSha256!=intent.ClaimSha256||previous.Attempt!=i||previous.StartedUtc<intent.QueuedUtc||previous.StartedUtc>=intent.RetryUntilUtc)throw new InvalidDataException("Invalid actor ACK attempt");
                last=previous;count++;
            }
            if(count==MaximumAcknowledgementAttempts){AckOutcome(intent,"ACK_TRANSPORT_EXHAUSTED",count,null,now,health);return;}
            if(last!=null)
            {
                if(now<last.StartedUtc){AckOutcome(intent,"ACK_CLOCK_ROLLBACK",count,null,now,health);return;}
                if(now-last.StartedUtc<TimeSpan.FromSeconds(1<<(count-1)))return;
            }
            // Verify the committed source before releasing native bytes. A
            // crash after this attempt record consumes one attempt, not a copy.
            VerifyProcessBytes(ReadProcess(Path.Combine(root,intent.ProcessIndex)));
            var number=count+1;SaveAckJson(AckFile(intent.SnapshotId,"ack-attempt-"+number+".json"),new ProcessAckAttempt(1,intent.SnapshotId,intent.ClaimSha256,number,now));
            string outcome;string? native=null;
            try
            {
                if(!send(claim,claim.Length).AsSpan().SequenceEqual(claim))throw new InvalidDataException("Proactive acquisition ACK differs");
                lock(gate)SaveImmutable(ack,claim);outcome="ACK_CONFIRMED";
            }
            catch(Exception ex)when(ex is COMException or IOException or InvalidDataException or UnauthorizedAccessException or ArgumentException)
            {outcome="ACK_REPLY_UNAVAILABLE";native=ex is COMException or ArgumentException?"0x"+ex.HResult.ToString("X8"):ex.GetType().Name;health("Committed proactive snapshot retained; candidate ACK unavailable: "+native);}
            SaveAckJson(AckFile(intent.SnapshotId,"ack-attempt-"+number+".result.json"),new ProcessAckResult(1,intent.SnapshotId,intent.ClaimSha256,number,now,outcome,native));
            if(outcome=="ACK_CONFIRMED")AckOutcome(intent,outcome,number,null,now,health);
            else if(number==MaximumAcknowledgementAttempts)AckOutcome(intent,"ACK_TRANSPORT_EXHAUSTED",number,native,now,health);
        }
    }
    internal void RetryProcessAcknowledgements(string provider,ulong instance,Func<byte[],int,byte[]> send,Action<string> health,DateTimeOffset? at=null)
    {
        // One pending claim per pass, round robin. This worker never requests
        // executable bytes or holds the acquisition gate during native RPC.
        lock(acknowledgementGate)
        {
            EnsureAcknowledgementIndex(health);var pending=acknowledgementIndex!.Values.OrderBy(x=>x.SnapshotId,StringComparer.Ordinal).ToArray();if(pending.Length==0)return;
            var index=(int)((uint)Interlocked.Increment(ref acknowledgementCursor)%(uint)pending.Length);
            AttemptProcessAcknowledgement(pending[index],provider,instance,send,health,at??DateTimeOffset.UtcNow);
        }
    }
    private int acknowledgementCursor;
}
