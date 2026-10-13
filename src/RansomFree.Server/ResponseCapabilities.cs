using RansomFree.Contracts;

namespace RansomFree.Server;

public sealed partial class Store
{
    private void InitializeResponseCapabilities()
    {
        if(sqlServer){RansomFree.Persistence.SqlServerSchema.Require(connectionString,"response-capabilities",1);return;}
        using var c=Open();using var command=Command(c,null,"CREATE TABLE IF NOT EXISTS response_capabilities(endpoint TEXT PRIMARY KEY REFERENCES endpoints(id),os TEXT NOT NULL,process_version INTEGER NOT NULL,reported INTEGER NOT NULL)");command.ExecuteNonQuery();
    }
    public bool RecordResponseCapabilities(string endpoint,NativeResponseCapabilities report)
    {
        if(!report.IsValid())throw new ArgumentException("Invalid response capability report.");
        InitializeResponseCapabilities();using var c=Open();using var t=c.BeginTransaction();
        using(var active=Command(c,t,"SELECT COUNT(*) FROM endpoints WHERE id=$id AND revoked=0",("$id",endpoint)))if(Convert.ToInt64(active.ExecuteScalar())!=1)return false;
        using(var update=Command(c,t,"UPDATE response_capabilities SET os=$os,process_version=$version,reported=$now WHERE endpoint=$id",("$id",endpoint),("$os",report.OperatingSystem),("$version",report.ProcessTerminationVersion),("$now",Now())))
        if(update.ExecuteNonQuery()==0){using var insert=Command(c,t,"INSERT INTO response_capabilities(endpoint,os,process_version,reported) VALUES($id,$os,$version,$now)",("$id",endpoint),("$os",report.OperatingSystem),("$version",report.ProcessTerminationVersion),("$now",Now()));insert.ExecuteNonQuery();}
        t.Commit();return true;
    }
}
