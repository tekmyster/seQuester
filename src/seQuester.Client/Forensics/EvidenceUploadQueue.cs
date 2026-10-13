using System.Security.Cryptography;
using System.Text.Json;
using RansomFree.Contracts;
namespace RansomFree.Client.Forensics;

// Diagnostic context only: never expose credentials, response bodies or file paths.
public sealed class EvidenceUploadAttemptException(string? evidenceId,string phase,Exception cause)
    :Exception("Actor evidence transfer attempt failed.",cause)
{
    public string? EvidenceId {get;}=evidenceId;
    public string Phase {get;}=phase;
    public int? HttpStatus {get;}=cause is HttpRequestException {StatusCode:{} status}?(int)status:null;
    public string ErrorType {get;}=cause.GetType().Name;
    public string Diagnostic=>$"phase={Phase}; evidence={EvidenceId??"unavailable"}; http={HttpStatus?.ToString(System.Globalization.CultureInfo.InvariantCulture)??"unavailable"}; error={ErrorType}";
}

public sealed class EvidenceUploadQueue(string directory)
{
    private string? lastAttempted;
    private bool cursorLoaded;
    private sealed record Cursor(int Version,string EvidenceId);
    public sealed record Pending(int Version,AgentEvent Original,AgentEvent Completion);
    private string Root=>Path.GetFullPath(Path.Combine(directory,"evidence","uploads"));
    private static void NoLinks(string path)
    {for(string? p=Path.GetFullPath(path);p!=null;p=Path.GetDirectoryName(p))if((File.Exists(p)||Directory.Exists(p))&&(File.GetAttributes(p)&FileAttributes.ReparsePoint)!=0)throw new IOException("Evidence transfer cannot follow links.");}
    private string Resolve(string id,string suffix)
    {if(!EvidenceTransferLimits.Id(id))throw new InvalidDataException("Invalid evidence ID.");NoLinks(Root);EvidenceStore.EnsurePrivate(Root);var path=Path.Combine(Root,id+suffix);NoLinks(path);return path;}
    private static void Save(string path,object value)
    {
        NoLinks(path);var temporary=path+"."+Guid.NewGuid().ToString("N")+".tmp";
        var options=new FileStreamOptions{Mode=FileMode.CreateNew,Access=FileAccess.Write,Share=FileShare.None};
        if(!OperatingSystem.IsWindows())options.UnixCreateMode=UnixFileMode.UserRead|UnixFileMode.UserWrite;
        using(var file=new FileStream(temporary,options)){JsonSerializer.Serialize(file,value);file.Flush(true);}File.Move(temporary,path,false);EvidenceDurability.DirectoryCommitted(Path.GetDirectoryName(path)!);
    }
    // Scheduling hint only: never an evidence receipt. Rotation wraps back to
    // failed work; loss of this hint changes order, never acknowledges bytes.
    private string CursorPath()
    {
        NoLinks(Root);EvidenceStore.EnsurePrivate(Root);
        var path=Path.Combine(Root,"pump-cursor.json");NoLinks(path);return path;
    }
    private void LoadCursor()
    {
        if(cursorLoaded)return;
        var path=CursorPath();
        if(File.Exists(path))
        {
            try
            {
                if(new FileInfo(path).Length>1024)throw new InvalidDataException("Upload cursor exceeds bound.");
                var cursor=JsonSerializer.Deserialize<Cursor>(File.ReadAllText(path));
                if(cursor is not {Version:1}||!EvidenceTransferLimits.Id(cursor.EvidenceId))throw new InvalidDataException("Invalid upload cursor.");
                lastAttempted=Resolve(cursor.EvidenceId,".pending.json");
            }
            catch(Exception ex)when(ex is JsonException or InvalidDataException)
            {
                File.Move(path,path+".invalid."+Guid.NewGuid().ToString("N"),false);
                EvidenceDurability.DirectoryCommitted(Root);
                throw new EvidenceUploadAttemptException(null,"cursor-recovery",ex);
            }
        }
        cursorLoaded=true;
    }
    private void RememberAttempt(string path,string id)
    {
        lastAttempted=path;
        if(!EvidenceTransferLimits.Id(id))throw new InvalidDataException("Invalid upload cursor identity.");
        var target=CursorPath();var temporary=target+"."+Guid.NewGuid().ToString("N")+".tmp";
        var options=new FileStreamOptions{Mode=FileMode.CreateNew,Access=FileAccess.Write,Share=FileShare.None};
        if(!OperatingSystem.IsWindows())options.UnixCreateMode=UnixFileMode.UserRead|UnixFileMode.UserWrite;
        using(var file=new FileStream(temporary,options)){JsonSerializer.Serialize(file,new Cursor(1,id));file.Flush(true);}
        // Only this mutable hint may be replaced; artifacts and receipts still
        // use their existing create-new/no-overwrite commits.
        NoLinks(target);File.Move(temporary,target,true);EvidenceDurability.DirectoryCommitted(Root);
    }
    public void Register(AgentEvent original,AgentEvent completion)
    {
        var p=completion.Forensics?.Preservation;if(p is not {Status.State:"captured",HashMatched:true,EvidenceId:not null})return;
        if(original.EventId!=p.SourceEventId||completion.Forensics!.RelatedEventId!=original.EventId||!completion.Forensics.IsValid())throw new InvalidDataException("Invalid upload event linkage.");
        var path=Resolve(p.EvidenceId,".pending.json");var entry=new Pending(1,original,completion);
        var retired=Resolve(p.EvidenceId,".uploaded.json");
        // A replay cannot return already acknowledged bytes to the active queue.
        if(File.Exists(retired)){if(File.ReadAllText(retired)!=JsonSerializer.Serialize(entry))throw new InvalidDataException("Evidence queue identity conflict.");return;}
        if(File.Exists(path)){if(File.ReadAllText(path)!=JsonSerializer.Serialize(entry))throw new InvalidDataException("Evidence queue identity conflict.");EvidenceDurability.DirectoryCommitted(Path.GetDirectoryName(path)!);return;}
        try{Save(path,entry);}
        catch(IOException)when(File.Exists(path))
        {
            NoLinks(path);
            if(File.ReadAllText(path)!=JsonSerializer.Serialize(entry))throw new InvalidDataException("Evidence queue identity conflict.");
            EvidenceDurability.DirectoryCommitted(Path.GetDirectoryName(path)!);
        }
    }
    private static void Validate(EvidenceUploadReceipt r,Pending p)
    {
        var f=p.Completion.Forensics!;var e=f.Preservation;
        if(r.Version!=1||r.SensorId!=f.SensorId||r.EvidenceId!=e.EvidenceId||r.CompletionEventId!=p.Completion.EventId||r.Sha256!=e.Sha256||r.ManifestSha256!=e.ManifestSha256||r.Size!=e.Size||r.ReceivedBytes<0||r.ReceivedBytes>r.Size||r.State is not ("receiving" or "received")||!EvidenceTransferLimits.Id(r.ReceiptId)||r.State=="received"&&(r.ReceivedUtc==null||r.ReceivedBytes!=r.Size))throw new InvalidDataException("Evidence upload receipt does not match local preservation.");
    }
    private void Retire(string path,string id)
    {
        var retired=Resolve(id,".uploaded.json");NoLinks(path);
        // Invoked only after validating a received receipt against this exact
        // record. Preserve its bytes and all artifacts; never overwrite history.
        File.Move(path,retired,false);EvidenceDurability.DirectoryCommitted(Root);
    }
    // Called on a dedicated worker, never in an audit/file-I/O callback. Local artifacts are retained after receipt.
    public async Task<int> Pump(ManagementClient management,CancellationToken ct=default)
    {
        if(!Directory.Exists(Root))return 0;NoLinks(Root);var completedCount=0;
        var pending=Directory.EnumerateFiles(Root,"*.pending.json").Order(StringComparer.Ordinal).ToArray();
        if(pending.Length==0)return 0;
        LoadCursor();
        // Rotate across pump calls and normal restarts so failures cannot starve later evidence.
        if(lastAttempted!=null)pending=pending.Where(p=>StringComparer.Ordinal.Compare(p,lastAttempted)>0).Concat(pending.Where(p=>StringComparer.Ordinal.Compare(p,lastAttempted)<=0)).ToArray();
        try{if(!await management.EvidenceUploadSupported(ct))throw new InvalidDataException("Server evidence upload unavailable; local artifacts retained.");}
        catch(OperationCanceledException)when(ct.IsCancellationRequested){throw;}
        catch(Exception ex){throw new EvidenceUploadAttemptException(null,"capability-check",ex);}
        var attempted=0;var failures=new List<Exception>();
        var inspected=0;
        foreach(var path in pending)
        {
          string? evidenceId=null;var phase="queue-validation";
          try
          {
            ct.ThrowIfCancellationRequested();NoLinks(path);if(new FileInfo(path).Length>65536)throw new InvalidDataException("Evidence queue record exceeds limit.");
            // Bound legacy acknowledged-record migration, not just transfers.
            if(inspected++>=64)break;
            var entry=JsonSerializer.Deserialize<Pending>(File.ReadAllText(path))??throw new InvalidDataException("Invalid evidence queue record.");
            var f=entry.Completion.Forensics??throw new InvalidDataException("Forensic evidence missing.");var p=f.Preservation;
            if(entry.Version!=1||!f.IsValid()||f.RelatedEventId!=entry.Original.EventId||p.SourceEventId!=entry.Original.EventId||!EvidenceTransferLimits.Id(p.EvidenceId)||Path.GetFileName(path)!=p.EvidenceId+".pending.json")throw new InvalidDataException("Evidence queue binding invalid.");
            evidenceId=p.EvidenceId;
            phase="receipt-validation";
            var received=Resolve(p.EvidenceId!,".receipt.json");
            if(File.Exists(received))
            {
                if(new FileInfo(received).Length>8192)throw new InvalidDataException("Invalid receipt size.");
                var saved=JsonSerializer.Deserialize<EvidenceUploadReceipt>(File.ReadAllText(received))??throw new InvalidDataException("Invalid saved receipt.");Validate(saved,entry);if(saved.State!="received")throw new InvalidDataException("Unconfirmed saved receipt.");Retire(path,p.EvidenceId!);continue;
            }
            if(attempted++>=8)break;
            phase="cursor-persistence";RememberAttempt(path,evidenceId!);
            // Replays are immutable and idempotent. This also recovers a crash between queue registration and completion emission.
            phase="event-replay";
            await management.SendEventsAsync(new([entry.Original,entry.Completion]),ct);
            phase="local-artifact-validation";
            var artifact=Path.GetFullPath(Path.Combine(directory,"evidence","actors",p.EvidenceId+".bin"));
            var manifestPath=Path.GetFullPath(Path.Combine(directory,"evidence","actors",p.EvidenceId+".json"));NoLinks(artifact);NoLinks(manifestPath);
            if(new FileInfo(manifestPath).Length>EvidenceTransferLimits.ManifestBytes)throw new InvalidDataException("Manifest exceeds transfer limit.");
            var manifest=await File.ReadAllBytesAsync(manifestPath,ct);
            if(Convert.ToHexString(SHA256.HashData(manifest))!=p.ManifestSha256)throw new InvalidDataException("Local manifest hash mismatch; original retained.");
            using var image=new FileStream(artifact,FileMode.Open,FileAccess.Read,FileShare.Read);
            if(image.Length!=p.Size||Convert.ToHexString(await SHA256.HashDataAsync(image,ct))!=p.Sha256)throw new InvalidDataException("Local artifact hash mismatch; original retained.");
            phase="upload-reservation";
            var receipt=await management.StartEvidenceUpload(new(entry.Completion.EventId,Convert.ToBase64String(manifest)),ct);Validate(receipt,entry);
            image.Position=receipt.ReceivedBytes;
            for(var chunk=0;receipt.State!="received"&&image.Position<image.Length&&chunk<16;chunk++)
            {
                phase="chunk-upload";
                var offset=image.Position;var buffer=new byte[(int)Math.Min(EvidenceTransferLimits.ChunkBytes,image.Length-offset)];await image.ReadExactlyAsync(buffer,ct);
                receipt=await management.SendEvidenceChunk(p.EvidenceId!,offset,buffer,ct);Validate(receipt,entry);
                if(receipt.ReceivedBytes<image.Position)throw new InvalidDataException("Server did not acknowledge evidence bytes.");image.Position=receipt.ReceivedBytes;
            }
            if(receipt.ReceivedBytes==receipt.Size&&receipt.State!="received"){phase="upload-commit";receipt=await management.FinishEvidenceUpload(p.EvidenceId!,ct);Validate(receipt,entry);}
            if(receipt.State=="received"){phase="receipt-persistence";Save(received,receipt);Retire(path,p.EvidenceId!);completedCount++;}
          }
          catch(OperationCanceledException)when(ct.IsCancellationRequested){throw;}
          catch(Exception ex){lastAttempted=path;failures.Add(new EvidenceUploadAttemptException(evidenceId,phase,ex));if(failures.Count>=8)break;}
        }
        if(failures.Count>0)throw new AggregateException("One or more actor uploads remain pending; other eligible transfers were attempted.",failures);
        return completedCount;
    }
}

public sealed class EvidenceUploadWorker:IAsyncDisposable
{
    private readonly CancellationTokenSource stopping=new();
    private readonly Task worker;
    public EvidenceUploadWorker(ManagementClient? management,string directory,Action<string> error)
    {
        worker=management==null?Task.CompletedTask:Task.Run(async()=>
        {
            var queue=new EvidenceUploadQueue(directory);
            while(!stopping.IsCancellationRequested)
            {
                try{await queue.Pump(management,stopping.Token);}catch(OperationCanceledException)when(stopping.IsCancellationRequested){break;}
                catch(Exception ex){error(FailureDiagnostic(ex));}
                try{await Task.Delay(TimeSpan.FromSeconds(15),stopping.Token);}catch(OperationCanceledException){break;}
            }
        });
    }
    public static string FailureDiagnostic(Exception error)=>"Actor upload pending; local evidence retained: "+
        (error is AggregateException batch?string.Join(" | ",batch.InnerExceptions.Take(8).Select(e=>e is EvidenceUploadAttemptException attempt?attempt.Diagnostic:e.GetType().Name)):
         error is EvidenceUploadAttemptException attempt?attempt.Diagnostic:error.GetType().Name);
    public async ValueTask DisposeAsync(){stopping.Cancel();await worker;stopping.Dispose();}
}
