namespace RansomFree.Server;
public sealed partial class Store
{
    bool HasPlatformStorage()
    {
        using var c=Open();using var command=Command(c,null,sqlServer?"SELECT CASE WHEN OBJECT_ID(N'dbo.endpoint_platform',N'U') IS NULL THEN 0 ELSE 1 END":"SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='endpoint_platform'");
        var exists=Convert.ToInt64(command.ExecuteScalar())==1;if(exists&&sqlServer)RansomFree.Persistence.SqlServerSchema.Require(connectionString,"endpoint-platform",1);return exists;
    }
    void InitializePlatformStorage()
    {
        if(sqlServer){RansomFree.Persistence.SqlServerSchema.Require(connectionString,"endpoint-platform",1);return;}
        using var c=Open();using var command=Command(c,null,"CREATE TABLE IF NOT EXISTS endpoint_platform(endpoint TEXT PRIMARY KEY REFERENCES endpoints(id),os TEXT NOT NULL)");command.ExecuteNonQuery();
    }
}
