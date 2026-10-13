using RansomFree.Contracts;

namespace RansomFree.Server;

public sealed partial class Store
{
    bool HasProtectionStorage()
    {
        using var c=Open();using var command=Command(c,null,sqlServer?"SELECT CASE WHEN OBJECT_ID(N'dbo.endpoint_protection',N'U') IS NULL THEN 0 ELSE 1 END":"SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='endpoint_protection'");
        var exists=Convert.ToInt64(command.ExecuteScalar())==1;if(exists&&sqlServer)RansomFree.Persistence.SqlServerSchema.Require(connectionString,"endpoint-protection",1);return exists;
    }
    void InitializeProtectionStorage()
    {
        if(sqlServer){RansomFree.Persistence.SqlServerSchema.Require(connectionString,"endpoint-protection",1);return;}
        using var c=Open();using var command=Command(c,null,"CREATE TABLE IF NOT EXISTS endpoint_protection(endpoint TEXT PRIMARY KEY REFERENCES endpoints(id),deployed_items INTEGER NOT NULL,monitoring_state TEXT NOT NULL,reported INTEGER NOT NULL)");command.ExecuteNonQuery();
    }
}
