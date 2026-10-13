using System.Data;
using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using Microsoft.Data.SqlClient;
using Microsoft.Data.Sqlite;
using RansomFree.Persistence;

namespace RansomFree.Server;

internal static class SqliteImport
{
    private static readonly string[] Management=["enrollment","endpoints","events","audit","reports","endpoint_groups","policy_revisions","endpoint_groups_binding","incidents","incident_events","incident_notes","response_commands","incident_assignments","report_schedules"];
    private static readonly string[] Identity=["AspNetRoles","AspNetUsers","AspNetRoleClaims","AspNetUserClaims","AspNetUserLogins","AspNetUserRoles","AspNetUserTokens","UsedMfaCodes","RecoveryCodes","IdentityAudit","DirectoryIdentities","AccountControls","AccountRecoveries","OrganizationSecurity"];
    public static void Run(DatabaseSettings database,IConfiguration configuration,string[] args)
    {
        if(!database.SqlServer||!args.Contains("--acknowledge-offline-import"))throw new InvalidOperationException("Import requires SQL Server and explicit acknowledgement that all source/target servers and receivers are stopped.");
        string PathArgument(string name){var index=Array.IndexOf(args,name);if(index<0||index+1>=args.Length||!Path.IsPathFullyQualified(args[index+1]))throw new ArgumentException("Supply an absolute "+name+" path.");return Path.GetFullPath(args[index+1]);}
        var data=PathArgument("--source-data");
        var components=new List<(string Connection,string Name,string Path,string[] Tables)>
        {
            (database.Connection("Management"),"management",Path.Combine(data,"management.db"),Management),
            (database.Connection("Identity"),"identity",Path.Combine(data,"identity.db"),Identity)
        };
        if(configuration["Callbacks:Enabled"]=="true")
        {
            var callbacks=PathArgument("--source-callbacks");
            SqlServerSchema.Require(database.Connection("CallbackRegistry"),"callback-details",1);
            components.Add((database.Connection("CallbackRegistry"),"callback-registry",Path.Combine(callbacks,"registry","tokens.db"),["tokens","token_options","token_details"]));
            components.Add((database.Connection("CallbackInbox"),"callback-inbox",Path.Combine(callbacks,"inbox","hits.db"),["hits"]));
        }
        // Catch missing source components and incompatible target schemas before the first write.
        foreach(var component in components)ValidateSource(component.Path);
        foreach(var component in components)SqlServerSchema.Require(component.Connection,component.Name,1);
        foreach(var component in components)Import(component.Connection,component.Name,component.Path,component.Tables);
    }
    private static void ValidateSource(string path)
    {
        if(!File.Exists(path))throw new FileNotFoundException("Required source database is missing.");
        for(var current=path;current!=null;current=Path.GetDirectoryName(current))if((File.GetAttributes(current)&FileAttributes.ReparsePoint)!=0)throw new IOException("Source path must not traverse links.");
        foreach(var suffix in new[]{"-wal","-shm","-journal"})
            if(File.Exists(path+suffix)&&(File.GetAttributes(path+suffix)&FileAttributes.ReparsePoint)!=0)throw new IOException("Source sidecar must not be a link.");
    }
    private static string Fingerprint(string path)
    {
        using var aggregate=IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        foreach(var file in new[]{path,path+"-wal"})
        {
            aggregate.AppendData(Encoding.UTF8.GetBytes(file==path?"main":"wal"));
            if(!File.Exists(file)){aggregate.AppendData([0]);continue;}
            using var stream=new FileStream(file,FileMode.Open,FileAccess.Read,FileShare.Read);aggregate.AppendData(SHA256.HashData(stream));
        }
        return Convert.ToHexString(aggregate.GetHashAndReset());
    }
    private static void Import(string connection,string component,string path,string[] tables)
    {
        ValidateSource(path);
        SqlServerSchema.Require(connection,component,1);var fingerprint=Fingerprint(path);
        using var source=new SqliteConnection(new SqliteConnectionStringBuilder{DataSource=path,Mode=SqliteOpenMode.ReadOnly,DefaultTimeout=10}.ToString());source.Open();
        using var sourceTransaction=source.BeginTransaction(deferred:true);
        using var target=new SqlConnection(connection);target.Open();using var transaction=target.BeginTransaction(IsolationLevel.Serializable);
        using var command=target.CreateCommand();command.Transaction=transaction;command.CommandTimeout=60;
        command.CommandText="DECLARE @result int; EXEC @result=sys.sp_getapplock @Resource=N'RansomFree.DataImport',@LockMode='Exclusive',@LockOwner='Transaction',@LockTimeout=10000; IF @result<0 THROW 51001,'Import lock unavailable',1; IF OBJECT_ID(N'dbo.RansomFreeImports',N'U') IS NULL CREATE TABLE dbo.RansomFreeImports(component nvarchar(64) NOT NULL PRIMARY KEY,source_sha256 char(64) NOT NULL,rows_imported bigint NOT NULL,imported datetimeoffset NOT NULL);";command.ExecuteNonQuery();
        command.CommandText="SELECT source_sha256 FROM dbo.RansomFreeImports WHERE component=@component";command.Parameters.AddWithValue("@component",component);
        if(command.ExecuteScalar() is string prior)
        {
            if(prior!=fingerprint)throw new InvalidOperationException("A different source was already imported. Existing target data is preserved.");
            transaction.Commit();Console.WriteLine(component+": already imported from this source fingerprint.");return;
        }
        command.Parameters.Clear();
        foreach(var table in tables)
        {
            command.CommandText="SELECT COUNT_BIG(*) FROM dbo.["+table+"]";
            if(Convert.ToInt64(command.ExecuteScalar())!=0)throw new InvalidOperationException("Import requires empty target component tables. Existing records are preserved.");
        }
        long total=0;
        foreach(var table in tables)
        {
            // Older SQLite registries have no optional annotation rows to import.
            if(table=="token_details")
            {
                using var exists=source.CreateCommand();exists.Transaction=sourceTransaction;exists.CommandText="SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='token_details'";
                if(Convert.ToInt64(exists.ExecuteScalar())==0)continue;
            }
            using var shape=new DataTable{Locale=CultureInfo.InvariantCulture};command.CommandText="SELECT TOP(0) * FROM dbo.["+table+"]";
            using(var schema=command.ExecuteReader())for(var index=0;index<schema.FieldCount;index++)shape.Columns.Add(schema.GetName(index),schema.GetFieldType(index));
            using var select=source.CreateCommand();select.Transaction=sourceTransaction;select.CommandText="SELECT * FROM ["+table+"]";
            long count=0;var buffered=0L;
            using(var reader=select.ExecuteReader())
            using(var copy=new SqlBulkCopy(target,SqlBulkCopyOptions.KeepIdentity|SqlBulkCopyOptions.CheckConstraints,transaction){DestinationTableName="dbo.["+table+"]",BulkCopyTimeout=120,BatchSize=500})
            {
                var indexes=shape.Columns.Cast<DataColumn>().Select(column=>reader.GetOrdinal(column.ColumnName)).ToArray();
                if(reader.FieldCount!=shape.Columns.Count)throw new InvalidOperationException("Source and target columns differ; a version-specific import is required.");
                foreach(DataColumn column in shape.Columns)copy.ColumnMappings.Add(column.ColumnName,column.ColumnName);
                while(reader.Read())
                {
                    var row=shape.NewRow();for(var index=0;index<indexes.Length;index++)
                    {
                        var value=reader.GetValue(indexes[index]);
                        if(value is string text){if(text.Length>2097152)throw new InvalidDataException("Source field exceeds import bound.");buffered+=text.Length*2L;}
                        if(value is byte[] bytes){if(bytes.Length>4194304)throw new InvalidDataException("Source field exceeds import bound.");buffered+=bytes.Length;}
                        var type=shape.Columns[index].DataType;
                        row[index]=value is DBNull?DBNull.Value:type==typeof(DateTimeOffset)?DateTimeOffset.Parse(Convert.ToString(value,CultureInfo.InvariantCulture)!,CultureInfo.InvariantCulture,DateTimeStyles.None):type==typeof(byte[])?value:Convert.ChangeType(value,type,CultureInfo.InvariantCulture);
                    }
                    shape.Rows.Add(row);count++;
                    if(shape.Rows.Count>=500||buffered>=8388608){copy.WriteToServer(shape);shape.Clear();buffered=0;}
                }
                if(shape.Rows.Count>0)copy.WriteToServer(shape);
            }
            command.CommandText="SELECT COUNT_BIG(*) FROM dbo.["+table+"]";if(Convert.ToInt64(command.ExecuteScalar())!=count)throw new InvalidDataException("Imported row count mismatch.");
            // Preserve SQLite's high-water mark, even where historical rows were deleted.
            using var seed=source.CreateCommand();seed.Transaction=sourceTransaction;seed.CommandText="SELECT seq FROM sqlite_sequence WHERE name=$name";seed.Parameters.AddWithValue("$name",table);
            using var hasSequences=source.CreateCommand();hasSequences.Transaction=sourceTransaction;hasSequences.CommandText="SELECT COUNT(*) FROM sqlite_master WHERE name='sqlite_sequence'";
            if(Convert.ToInt64(hasSequences.ExecuteScalar())>0 && seed.ExecuteScalar() is long sequence)
            {
                if(sequence<0)throw new InvalidDataException("Invalid sequence high-water mark.");
                var reseed=count==0?checked(sequence+1):sequence;
                command.CommandText="DBCC CHECKIDENT ('dbo."+table+"', RESEED, "+reseed.ToString(CultureInfo.InvariantCulture)+") WITH NO_INFOMSGS";command.ExecuteNonQuery();
            }
            total+=count;
        }
        if(Fingerprint(path)!=fingerprint)throw new IOException("Source changed during import. This component was rolled back.");
        command.CommandText="INSERT dbo.RansomFreeImports(component,source_sha256,rows_imported,imported) VALUES(@component,@hash,@rows,SYSUTCDATETIME())";
        command.Parameters.AddWithValue("@component",component);command.Parameters.AddWithValue("@hash",fingerprint);command.Parameters.AddWithValue("@rows",total);command.ExecuteNonQuery();
        transaction.Commit();Console.WriteLine(component+": imported "+total.ToString(CultureInfo.InvariantCulture)+" rows. Source preserved.");
    }
}
