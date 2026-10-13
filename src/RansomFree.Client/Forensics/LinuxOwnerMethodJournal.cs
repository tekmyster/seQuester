using System.Text.Json;
using Microsoft.Data.Sqlite;

namespace RansomFree.Client.Forensics;

internal sealed partial class LinuxForensicJournal
{
    internal sealed record OwnerMethodReturn(int Version,string ReceiptId,string SourceSessionId,string Method,
        DateTimeOffset AttemptedUtc,DateTimeOffset ReturnedUtc,long AttemptedMonotonic,long ReturnedMonotonic,long MonotonicFrequency,
        string Outcome,string? ErrorKind=null,string? ErrorDomain=null,string? ErrorCode=null);
    private static void MigrateOwnerMethods(SqliteConnection c,Action<string>? checkpoint)
    {
        using var t=c.BeginTransaction();Execute(c,t,"""
            CREATE TABLE source_owner_returns(session_id TEXT NOT NULL REFERENCES source_lifecycle(session_id),
              method TEXT NOT NULL CHECK(method IN ('OPEN','CLOSE')),receipt BLOB NOT NULL CHECK(typeof(receipt)='blob' AND length(receipt)<=4096),
              PRIMARY KEY(session_id,method));
            PRAGMA user_version=12;
            """);checkpoint?.Invoke("owner-method-migration-before-commit");t.Commit();checkpoint?.Invoke("owner-method-migration-after-commit");
    }
    private static void ValidateOwnerReturn(string id,string method,OwnerMethodReturn value)
    {
        if(value.Version!=1||!Guid.TryParseExact(value.ReceiptId,"N",out _)||value.SourceSessionId!=id||value.Method!=method||method is not ("OPEN" or "CLOSE")||
            value.AttemptedUtc==default||value.ReturnedUtc==default||value.AttemptedMonotonic<=0||value.ReturnedMonotonic<value.AttemptedMonotonic||value.MonotonicFrequency<=0||
            value.Outcome is not ("returned" or "threw")||
            (value.Outcome=="returned"?value.ErrorKind!=null||value.ErrorDomain!=null||value.ErrorCode!=null:
                value.ErrorKind is not {Length:>0 and <=200}||value.ErrorDomain is not ("posix" or "dotnet")||value.ErrorCode is not {Length:>0 and <=32}))
            throw new InvalidDataException("Invalid exact owner method receipt");
    }
    internal OwnerMethodReturn? ReadOwnerMethodReturn(string id,string method)
    {
        lock(gate)
        {
            using var c=Open();using var q=Command(c,null,"SELECT receipt FROM source_owner_returns WHERE session_id=$id AND method=$method",("$id",id),("$method",method));
            if(q.ExecuteScalar() is not byte[] bytes)return null;
            var value=JsonSerializer.Deserialize<OwnerMethodReturn>(bytes)??throw new InvalidDataException("Owner method receipt missing");ValidateOwnerReturn(id,method,value);return value;
        }
    }
    internal void RecordOwnerMethodReturn(string id,OwnerMethodReturn value,Action<string>? checkpoint=null)
    {
        ValidateOwnerReturn(id,value.Method,value);var bytes=JsonSerializer.SerializeToUtf8Bytes(value);
        if(bytes.Length>4096)throw new InvalidDataException("Owner receipt exceeds bound");
        lock(gate)
        {
            var prior=ReadOwnerMethodReturn(id,value.Method);
            if(prior!=null)
            {
                if(!JsonSerializer.SerializeToUtf8Bytes(prior).AsSpan().SequenceEqual(bytes))throw new InvalidDataException("First owner method return cannot be replaced");return;
            }
            var source=ReadSource(id);var owner=ReadSourceOwnership(id);
            if(!IsControlledRawFormat(ReadSourceBankFormat(id))||owner==null||owner.Phase=="PREPARED_NO_OWNER")throw new InvalidOperationException("Actual owned opening attempt required");
            if(value.Method=="OPEN")
            {
                if(source.State is "CLOSED" or "CLOSE_UNKNOWN_OPEN"||owner.Phase!="OWNER_OPEN_ATTEMPTED")throw new InvalidOperationException("Opening outcome must precede linking or closing");
            }
            else
            {
                var opened=ReadOwnerMethodReturn(id,"OPEN");
                if(source.State!="CLOSE_UNKNOWN_OPEN"||opened?.Outcome!="returned"||value.MonotonicFrequency!=opened.MonotonicFrequency||value.AttemptedMonotonic<opened.ReturnedMonotonic)
                    throw new InvalidOperationException("Close return requires successful original open and durable close intent");
            }
            using var c=Open();using var t=c.BeginTransaction();
            Execute(c,t,"INSERT INTO source_owner_returns(session_id,method,receipt) VALUES($id,$method,$receipt) ON CONFLICT(session_id,method) DO NOTHING",("$id",id),("$method",value.Method),("$receipt",bytes));
            using(var q=Command(c,t,"SELECT receipt FROM source_owner_returns WHERE session_id=$id AND method=$method",("$id",id),("$method",value.Method)))
                if(q.ExecuteScalar() is not byte[] committed||!committed.AsSpan().SequenceEqual(bytes))throw new InvalidDataException("Owner method receipt collision; original retained");
            t.Commit();checkpoint?.Invoke("owner-method-return-committed");
        }
    }
    // Terminal startup proof supplied only by the live owner after actual
    // loader drain. A failed/not-called open has no CLOSE method or close time.
    // This must never infer "no controller" from a missing historical receipt.
    internal void RecordSourceNoController(string id,OwnerMethodReturn? failedOpen,DateTimeOffset time)
    {
        if(time==default||failedOpen?.Outcome=="returned")throw new InvalidOperationException("Exact no-controller startup outcome required");
        lock(gate)
        {
            var source=ReadSource(id);var owner=ReadSourceOwnership(id);var recorded=ReadOwnerMethodReturn(id,"OPEN");
            if(!runtimeOwner||!IsControlledRawFormat(ReadSourceBankFormat(id))||ReadSourceControl(id)!=null||ReadOwnerMethodReturn(id,"CLOSE")!=null||
                failedOpen!=recorded||failedOpen!=null&&failedOpen.Outcome!="threw"||source.State=="CLOSE_UNKNOWN_OPEN")
                throw new InvalidOperationException("Live ownership and exact failed/not-called opening proof required");
            var boundary=new SourceBoundary(failedOpen==null?"OWNER_OPEN_NOT_CALLED":"OWNER_OPEN_FAILED",time,null,source.LatestLost,null,null,null,[],OpenEnded:false,UnresolvedStatus:"none-no-controller");
            var bytes=EncodeBoundary(boundary);
            using var c=Open();using var t=c.BeginTransaction();
            if(source.State=="CLOSED")
            {
                using var prior=Command(c,t,"SELECT count(*) FROM source_boundaries WHERE session_id=$id AND boundary=$value",("$id",id),("$value",bytes));
                if(source.CloseReturnedUtc!=null||Convert.ToInt64(prior.ExecuteScalar())!=1)throw new InvalidDataException("No-controller terminal proof differs");return;
            }
            if(owner?.Phase is not ("PREPARED_NO_OWNER" or "OWNER_OPEN_ATTEMPTED")||recorded!=null&&owner.Phase!="OWNER_OPEN_ATTEMPTED")throw new InvalidOperationException("No-controller terminal source already linked");
            Execute(c,t,"INSERT INTO source_boundaries(session_id,boundary) VALUES($id,$value)",("$id",id),("$value",bytes));
            Execute(c,t,"UPDATE source_lifecycle SET state='CLOSED' WHERE session_id=$id",("$id",id));
            Execute(c,t,"UPDATE source_ownership SET phase='CLOSED',recorded_utc=$time WHERE session_id=$id",("$time",time.ToString("O")),("$id",id));t.Commit();
        }
    }
}
