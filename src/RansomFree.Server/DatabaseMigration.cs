using Microsoft.EntityFrameworkCore;
using RansomFree.Persistence;

namespace RansomFree.Server;

internal static class DatabaseMigration
{
    private static string Script(string name)
    {
        using var stream=typeof(DatabaseMigration).Assembly.GetManifestResourceStream("RansomFree.Server.Database."+name)??throw new InvalidOperationException("Migration resource missing.");
        using var reader=new StreamReader(stream);return reader.ReadToEnd();
    }
    public static Task ApplyAsync(WebApplication app,DatabaseSettings database)
    {
        if(!database.SqlServer)throw new InvalidOperationException("Explicit migration command requires Database:Provider=SqlServer.");
        // Databases must exist already. Use a temporary DDL-capable migration identity;
        // normal server identities only need runtime data privileges and schema read access.
        SqlServerSchema.Apply(database.Connection("Management"),"management",1,Script("Management001.sql"),"endpoints");
        SqlServerSchema.Apply(database.Connection("Management"),"trust",1,Script("Trust001.sql"),"trust_revisions");
        SqlServerSchema.Apply(database.Connection("Management"),"trust-capabilities",1,Script("TrustCapabilities001.sql"),"trust_capabilities");
        SqlServerSchema.Apply(database.Connection("Management"),"trust-native-hash-capabilities",1,Script("TrustNativeHashCapabilities001.sql"),"trust_native_hash_capabilities");
        SqlServerSchema.Apply(database.Connection("Management"),"response-capabilities",1,Script("ResponseCapabilities001.sql"),"response_capabilities");
        SqlServerSchema.Apply(database.Connection("Management"),"decoy-services",1,Script("DecoyServices001.sql"),"decoy_services");
        SqlServerSchema.Apply(database.Connection("Management"),"decoy-jobs",1,Script("DecoyJobs001.sql"),"decoy_jobs");
        SqlServerSchema.Apply(database.Connection("Management"),"service-evidence",1,Script("ServiceEvidence001.sql"),"service_evidence");
        SqlServerSchema.Apply(database.Connection("Management"),"service-incident-links",1,Script("ServiceIncidentLinks001.sql"),"incident_service_events");
        SqlServerSchema.Apply(database.Connection("Management"),"endpoint-contact",1,Script("EndpointContact001.sql"),"endpoint_contact");
        SqlServerSchema.Apply(database.Connection("Management"),"endpoint-platform",1,Script("EndpointPlatform001.sql"),"endpoint_platform");
        SqlServerSchema.Apply(database.Connection("Management"),"endpoint-protection",1,Script("EndpointProtection001.sql"),"endpoint_protection");
        SqlServerSchema.Apply(database.Connection("Management"),"actor-evidence",1,Script("ActorEvidence001.sql"),"actor_evidence");
        using var scope=app.Services.CreateScope();var identity=scope.ServiceProvider.GetRequiredService<AuthDb>();
        SqlServerSchema.Apply(database.Connection("Identity"),"identity",1,identity.Database.GenerateCreateScript(),"AspNetUsers");
        if(app.Configuration["Callbacks:Enabled"]=="true")
        {
            SqlServerSchema.Apply(database.Connection("CallbackRegistry"),"callback-registry",1,Script("CallbackRegistry001.sql"),"tokens");
            SqlServerSchema.Apply(database.Connection("CallbackInbox"),"callback-inbox",1,Script("CallbackInbox001.sql"),"hits");
            SqlServerSchema.Apply(database.Connection("CallbackRegistry"),"callback-details",1,Script("CallbackDetails001.sql"),"token_details");
        }
        return Task.CompletedTask;
    }
}
