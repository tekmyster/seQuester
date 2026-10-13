using Microsoft.Data.SqlClient;
using Microsoft.Extensions.Configuration;
using RansomFree.Persistence;
using RansomFree.Server;
internal static class SqlChecks
{
    public static void Run(Action<bool,string> check)
    {
        DatabaseSettings Settings(string connection)=>new(new ConfigurationBuilder().AddInMemoryCollection(new Dictionary<string,string?>{["Database:Provider"]="SqlServer",["Database:ConnectionString"]=connection}).Build());
        foreach(var connection in new[]{"Server=(localdb)\\MSSQLLocalDB;Database=N05","Server=localhost;Database=N05;TrustServerCertificate=true","Server=localhost;Database=N05;Persist Security Info=true"})
        {var rejected=false;try{Settings(connection).Connection("Management");}catch(InvalidOperationException){rejected=true;}check(rejected,"SQL service storage rejects unsafe connection mode");}
        var safe=new SqlConnectionStringBuilder(Settings("Server=fixture.invalid;Database=N05;Integrated Security=true;Encrypt=false").Connection("Management"));
        check(safe.Encrypt==SqlConnectionEncryptOption.Mandatory&&!safe.TrustServerCertificate&&!safe.PersistSecurityInfo,"SQL service connections require validated encrypted transport");
        using var c=new SqlConnection();using var query=Relational.Command(c,null,"SELECT sequence,received,payload FROM service_evidence WHERE sequence>$after ORDER BY sequence LIMIT $limit",("$after",long.MaxValue-1),("$limit",100));
        check(query.CommandText=="SELECT sequence,received,payload FROM service_evidence WHERE sequence>@after ORDER BY sequence OFFSET 0 ROWS FETCH NEXT @limit ROWS ONLY"&&Convert.ToInt64(query.Parameters["@after"].Value)==long.MaxValue-1,"SQL durable service pagination uses ordered parameterized bigint positions");
        var assembly=typeof(Store).Assembly;string Schema(string suffix){using var stream=assembly.GetManifestResourceStream(assembly.GetManifestResourceNames().Single(n=>n.EndsWith(suffix)))!;using var reader=new StreamReader(stream);return reader.ReadToEnd();}
        check(Schema("ServiceEvidence001.sql").Contains("bigint IDENTITY")&&Schema("ServiceEvidence001.sql").Contains("event_id char(32) NOT NULL UNIQUE")&&Schema("ServiceIncidentLinks001.sql").Contains("REFERENCES dbo.service_evidence(sequence)"),"embedded SQL schemas preserve durable evidence identity and incident references");
        Console.WriteLine("PENDING: SQL Server runtime lifecycle/history/incident/count tests; no configured isolated SQL Server instance, no connection attempted.");
    }
}
