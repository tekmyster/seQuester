namespace RansomFree.Server;
public sealed partial class Store
{
    bool HasServiceIncidentLinks()
    {
        using var c=Open();using var command=Command(c,null,sqlServer?"SELECT CASE WHEN OBJECT_ID(N'dbo.incident_service_events',N'U') IS NULL THEN 0 ELSE 1 END":"SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='incident_service_events'");
        var exists=Convert.ToInt64(command.ExecuteScalar())==1;if(exists&&sqlServer)RansomFree.Persistence.SqlServerSchema.Require(connectionString,"service-incident-links",1);return exists;
    }
    bool PrepareIncidentEvidence(long sequence)
    {
        if(sequence is 0 or long.MinValue)return false;if(sequence>0)return true;if(!HasServiceEvidence())return false;
        if(sqlServer){RansomFree.Persistence.SqlServerSchema.Require(connectionString,"service-incident-links",1);return true;}
        using var c=Open();using var cmd=Command(c,null,"CREATE TABLE IF NOT EXISTS incident_service_events(incident TEXT NOT NULL REFERENCES incidents(id),event_sequence INTEGER NOT NULL REFERENCES service_evidence(sequence),PRIMARY KEY(incident,event_sequence))");cmd.ExecuteNonQuery();return true;
    }
    public RansomFree.Contracts.StoredEvent? EvidenceRecord(long sequence)
    {
        if(sequence is 0 or long.MinValue)return null;if(sequence<0){if(!HasServiceEvidence())return null;var item=ServiceEvents(-sequence-1,1).FirstOrDefault(x=>x.Sequence== -sequence);return item==null?null:new(sequence,"server",item.ReceivedUtc,item.Event);}
        return Events(sequence-1,1).FirstOrDefault(x=>x.Sequence==sequence);
    }
}
