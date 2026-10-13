using System.Security.Cryptography;
using System.Text;
using Microsoft.Data.SqlClient;

namespace RansomFree.Persistence;

internal static class SqlServerSchema
{
    public static void Require(string connection,string component,int version)
    {
        using var c=new SqlConnection(connection);c.Open();using var cmd=c.CreateCommand();
        cmd.CommandText="IF OBJECT_ID(N'dbo.RansomFreeSchema',N'U') IS NULL SELECT CAST(-1 AS int) ELSE SELECT version FROM dbo.RansomFreeSchema WHERE component=@component";
        cmd.Parameters.AddWithValue("@component",component);
        if(Convert.ToInt32(cmd.ExecuteScalar()??-1)!=version)throw new InvalidOperationException("Database schema is missing or incompatible. Run the explicit migration command with a migration identity.");
    }
    public static void Apply(string connection,string component,int version,string script,string sentinel)
    {
        using var c=new SqlConnection(connection);c.Open();using var t=c.BeginTransaction(System.Data.IsolationLevel.Serializable);
        using var cmd=c.CreateCommand();cmd.Transaction=t;cmd.CommandTimeout=60;
        cmd.CommandText="DECLARE @result int; EXEC @result=sys.sp_getapplock @Resource=N'RansomFree.SchemaMigration',@LockMode='Exclusive',@LockOwner='Transaction',@LockTimeout=10000; IF @result<0 THROW 51000,'Schema migration lock unavailable',1; IF OBJECT_ID(N'dbo.RansomFreeSchema',N'U') IS NULL CREATE TABLE dbo.RansomFreeSchema(component nvarchar(64) NOT NULL PRIMARY KEY,version int NOT NULL,sha256 char(64) NOT NULL,applied datetimeoffset NOT NULL);";
        cmd.ExecuteNonQuery();var hash=Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(script)));
        cmd.CommandText="SELECT version,sha256 FROM dbo.RansomFreeSchema WHERE component=@component";cmd.Parameters.AddWithValue("@component",component);
        using(var reader=cmd.ExecuteReader())if(reader.Read())
        {
            if(reader.GetInt32(0)!=version||reader.GetString(1)!=hash)throw new InvalidOperationException("Unexpected schema version or migration checksum; no upgrade/downgrade was applied.");
            reader.Close();t.Commit();return;
        }
        cmd.CommandText="SELECT OBJECT_ID(@table,N'U')";cmd.Parameters.AddWithValue("@table","dbo."+sentinel);
        if(cmd.ExecuteScalar() is not DBNull)throw new InvalidOperationException("Existing unversioned target tables are preserved; explicit adoption is required.");
        cmd.Parameters.Clear();
        foreach(var batch in System.Text.RegularExpressions.Regex.Split(script,@"^\s*GO\s*$",System.Text.RegularExpressions.RegexOptions.Multiline|System.Text.RegularExpressions.RegexOptions.IgnoreCase))
        {if(string.IsNullOrWhiteSpace(batch))continue;cmd.CommandText=batch;cmd.ExecuteNonQuery();}
        cmd.CommandText="INSERT dbo.RansomFreeSchema(component,version,sha256,applied) VALUES(@component,@version,@hash,SYSUTCDATETIME())";
        cmd.Parameters.AddWithValue("@component",component);cmd.Parameters.AddWithValue("@version",version);cmd.Parameters.AddWithValue("@hash",hash);cmd.ExecuteNonQuery();t.Commit();
    }
}
