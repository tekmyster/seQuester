using System.Data.Common;
using Microsoft.Data.SqlClient;
using Microsoft.Data.Sqlite;

namespace RansomFree.Persistence;

public sealed class DatabaseSettings
{
    public bool SqlServer {get;}
    private readonly IConfiguration configuration;
    public DatabaseSettings(IConfiguration configuration)
    {
        this.configuration=configuration;var provider=configuration["Database:Provider"]??"Sqlite";
        if(provider is not ("SqlServer" or "Sqlite"))throw new InvalidOperationException("Database:Provider must be SqlServer or Sqlite.");
        SqlServer=provider=="SqlServer";
    }
    public string Connection(string component)
    {
        if(!SqlServer)throw new InvalidOperationException("SQL Server is not selected.");
        var value=configuration["Database:"+component+"ConnectionString"]??configuration["Database:ConnectionString"];
        if(string.IsNullOrWhiteSpace(value))throw new InvalidOperationException("Configure the SQL Server connection in protected server settings.");
        var settings=new SqlConnectionStringBuilder(value);
        if(string.IsNullOrWhiteSpace(settings.DataSource)||string.IsNullOrWhiteSpace(settings.InitialCatalog)||settings.DataSource.Contains("(localdb)",StringComparison.OrdinalIgnoreCase)||settings.UserInstance||settings.AttachDBFilename.Length!=0||settings.TrustServerCertificate||settings.PersistSecurityInfo)
            throw new InvalidOperationException("Use a named SQL Server database, validated TLS, and no LocalDB/attach/user-instance or persisted credentials.");
        settings.Encrypt=SqlConnectionEncryptOption.Mandatory;settings.TrustServerCertificate=false;settings.PersistSecurityInfo=false;
        settings.ConnectTimeout=10;settings.ApplicationName="RansomFree."+component;
        return settings.ConnectionString;
    }
}

internal static class Relational
{
    public static DbConnection Open(bool sqlServer,string value)
    {
        DbConnection connection=sqlServer?new SqlConnection(value):new SqliteConnection(value);
        try{connection.Open();return connection;}catch{connection.Dispose();throw;}
    }
    public static bool UniqueViolation(Exception exception)=>exception is SqliteException{SqliteErrorCode:19}||exception is SqlException{Number:2601 or 2627};
    public static DbCommand Command(DbConnection connection,DbTransaction? transaction,string sql,params (string,object)[] arguments)
    {
        var command=connection.CreateCommand();command.Transaction=transaction;command.CommandTimeout=30;
        command.CommandText=connection is SqlConnection?Sql(sql):sql;
        foreach(var (name,value) in arguments){var parameter=command.CreateParameter();parameter.ParameterName=connection is SqlConnection?name.Replace('$','@'):name;parameter.Value=value;command.Parameters.Add(parameter);}
        return command;
    }
    // This adapts only the fixed, parameterized query vocabulary in this repository.
    // It is not exposed to user SQL and deliberately rejects unported constructs.
    private static string Sql(string sql)
    {
        if(sql.Contains("ON CONFLICT",StringComparison.Ordinal)||sql.Contains("INSERT OR",StringComparison.Ordinal)||sql.Contains("PRAGMA",StringComparison.Ordinal))throw new InvalidOperationException("Unported SQL dialect construct.");
        sql=System.Text.RegularExpressions.Regex.Replace(sql,@"\$([A-Za-z_][A-Za-z0-9_]*)","@$1");
        sql=sql.Replace("COUNT(","COUNT_BIG(",StringComparison.Ordinal).Replace("THEN 1 ELSE 0 END","THEN CAST(1 AS bigint) ELSE CAST(0 AS bigint) END",StringComparison.Ordinal);
        if(sql.EndsWith(" RETURNING revision",StringComparison.Ordinal))sql=sql[..^" RETURNING revision".Length].Replace(" VALUES("," OUTPUT INSERTED.revision VALUES(",StringComparison.Ordinal);
        if(sql.Contains(" RETURNING ",StringComparison.Ordinal))throw new InvalidOperationException("Unported returning clause.");
        var limit=System.Text.RegularExpressions.Regex.Match(sql,@" LIMIT ([0-9]+|@[A-Za-z_][A-Za-z0-9_]*)$");
        if(limit.Success){if(!sql.Contains("ORDER BY",StringComparison.Ordinal))throw new InvalidOperationException("Pagination requires deterministic ordering.");sql=sql[..limit.Index]+" OFFSET 0 ROWS FETCH NEXT "+limit.Groups[1].Value+" ROWS ONLY";}
        return sql;
    }
}
