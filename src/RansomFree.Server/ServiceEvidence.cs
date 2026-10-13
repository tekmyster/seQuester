using System.Text.Json;
using RansomFree.Contracts;
namespace RansomFree.Server;

public sealed record ServiceEvidence(long Sequence,DateTimeOffset ReceivedUtc,AgentEvent Event);
public sealed partial class Store
{
    public bool HasServiceEvidence()
    {
        using var c=Open();using var command=Command(c,null,sqlServer?"SELECT CASE WHEN OBJECT_ID(N'dbo.service_evidence',N'U') IS NULL THEN 0 ELSE 1 END":"SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='service_evidence'");
        var exists=Convert.ToInt64(command.ExecuteScalar())==1;if(exists&&sqlServer)RansomFree.Persistence.SqlServerSchema.Require(connectionString,"service-evidence",1);return exists;
    }
    public void InitializeServiceEvidence()
    {
        if(sqlServer){RansomFree.Persistence.SqlServerSchema.Require(connectionString,"service-evidence",1);return;}
        using var c=Open();using var command=Command(c,null,"CREATE TABLE IF NOT EXISTS service_evidence(sequence INTEGER PRIMARY KEY AUTOINCREMENT,event_id TEXT NOT NULL UNIQUE,received INTEGER NOT NULL,payload TEXT NOT NULL)");command.ExecuteNonQuery();
    }
    public long LatestServiceSequence(){if(!HasServiceEvidence())return 0;using var c=Open();using var cmd=Command(c,null,"SELECT COALESCE(MAX(sequence),0) FROM service_evidence");return Convert.ToInt64(cmd.ExecuteScalar());}
    public IReadOnlyList<ServiceEvidence> ServiceEvents(long after,int limit=100)
    {
        if(after<0||limit is <1 or >500)throw new ArgumentException("Invalid service history position.");if(!HasServiceEvidence())return [];
        using var c=Open();using var cmd=Command(c,null,"SELECT sequence,received,payload FROM service_evidence WHERE sequence>$after ORDER BY sequence LIMIT $limit",("$after",after),("$limit",limit));using var reader=cmd.ExecuteReader();var events=new List<ServiceEvidence>();
        while(reader.Read())events.Add(new(reader.GetInt64(0),DateTimeOffset.FromUnixTimeMilliseconds(reader.GetInt64(1)),JsonSerializer.Deserialize<AgentEvent>(reader.GetString(2))!));return events;
    }
    static void SaveServiceEvidence(System.Data.Common.DbConnection c,System.Data.Common.DbTransaction transaction,DecoyService service,string address,string method,DateTimeOffset observed)
    {
        var item=new AgentEvent(Guid.NewGuid().ToString("N"),observed,"Service access","service://"+service.Id,null,null,null,"Server service decoy")
        {ServiceContext=new(service.Id,service.Revision,service.Name,service.Description,address,method){Location=service.Location,Note=service.Note}};
        using var insert=Command(c,transaction,"INSERT INTO service_evidence(event_id,received,payload) VALUES($id,$time,$payload)",("$id",item.EventId),("$time",observed.ToUnixTimeMilliseconds()),("$payload",JsonSerializer.Serialize(item)));insert.ExecuteNonQuery();
    }
}
