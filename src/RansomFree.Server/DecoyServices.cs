using System.Security.Claims;
using System.Security.Cryptography;
using System.Text.Json;
using Microsoft.AspNetCore.Antiforgery;
using Microsoft.AspNetCore.Identity;
namespace RansomFree.Server;

public sealed record DecoyService(string Id,string Name,string Description,bool Enabled,bool Retired,long Revision,DateTimeOffset UpdatedUtc){public string Location {get;init;}="";public string Note {get;init;}="";}
public sealed record CreatedDecoyService(DecoyService Service,string ActivationPath){public bool AlreadyExists {get;init;}}
public sealed record DecoyServiceChange(string Name,string Description,bool Enabled,long ExpectedRevision,string AdministratorPassword,string? Code=null,string? RecoveryCode=null)
{public string? RequestId {get;init;} public string? Location {get;init;} public string? Note {get;init;}}
public sealed record DecoyServiceRetirement(long ExpectedRevision,string AdministratorPassword,string? Code=null,string? RecoveryCode=null);
public sealed record DecoyServiceHit(long Sequence,string ServiceId,DateTimeOffset ObservedUtc,string SourceAddress,string Method);
public sealed class DecoyServiceConflictException:Exception;
public sealed partial class Store
{
    public bool HasDecoyServiceStorage()
    {
        using var c=Open();using var command=Command(c,null,sqlServer?"SELECT CASE WHEN OBJECT_ID(N'dbo.decoy_services',N'U') IS NULL THEN 0 ELSE 1 END":"SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='decoy_services'");
        var exists=Convert.ToInt64(command.ExecuteScalar())==1;if(exists&&sqlServer)RansomFree.Persistence.SqlServerSchema.Require(connectionString,"decoy-services",1);return exists;
    }
    public void InitializeDecoyServiceStorage()
    {
        if(sqlServer){RansomFree.Persistence.SqlServerSchema.Require(connectionString,"decoy-services",1);return;}
        using var c=Open();using var command=Command(c,null,"""
            CREATE TABLE IF NOT EXISTS decoy_services(id TEXT PRIMARY KEY,key_hash TEXT NOT NULL,payload TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS decoy_service_versions(sequence INTEGER PRIMARY KEY AUTOINCREMENT,id TEXT NOT NULL REFERENCES decoy_services(id),revision INTEGER NOT NULL,actor TEXT NOT NULL,payload TEXT NOT NULL,UNIQUE(id,revision));
            CREATE TABLE IF NOT EXISTS decoy_service_hits(sequence INTEGER PRIMARY KEY AUTOINCREMENT,id TEXT NOT NULL REFERENCES decoy_services(id),observed INTEGER NOT NULL,address TEXT NOT NULL,method TEXT NOT NULL);
            CREATE INDEX IF NOT EXISTS decoy_service_hit_order ON decoy_service_hits(id,sequence);
            """);command.ExecuteNonQuery();
    }
    static void ValidateDecoyChange(DecoyServiceChange body)
    {
        if(body.Name is not {Length:>0 and <=100}||body.Description is not {Length:<=1024}||body.Name.Any(char.IsControl)||body.Description.Any(char.IsControl)||body.ExpectedRevision<0)throw new ArgumentException("Invalid service definition.");
        if(body.Location?.Length>1024||body.Note?.Length>2000||body.Location?.Any(char.IsControl)==true||body.Note?.Any(c=>char.IsControl(c)&&c is not ('\r' or '\n' or '\t'))==true)throw new ArgumentException("Invalid service location or note.");
    }
    public CreatedDecoyService CreateDecoyService(DecoyServiceChange body,string actor)
    {
        ValidateDecoyChange(body);if(body.Enabled||body.ExpectedRevision!=0||!Guid.TryParseExact(body.RequestId,"N",out _))throw new ArgumentException("Create disabled with a unique request identity.");
        var id=body.RequestId;var key=Secret();var item=new DecoyService(id,body.Name,body.Description,false,false,1,DateTimeOffset.UtcNow){Location=body.Location??"",Note=body.Note??""};
        using var c=Open();using var transaction=c.BeginTransaction(System.Data.IsolationLevel.Serializable);
        using(var prior=Command(c,transaction,"SELECT payload FROM decoy_services WHERE id=$id",("$id",id)))if(prior.ExecuteScalar() is string old)
        {var existing=JsonSerializer.Deserialize<DecoyService>(old)!;if(existing.Name!=body.Name||existing.Description!=body.Description||existing.Location!=(body.Location??"")||existing.Note!=(body.Note??""))throw new DecoyServiceConflictException();return new(existing,""){AlreadyExists=true};}
        using(var count=Command(c,transaction,"SELECT COUNT(*) FROM decoy_services"))if(Convert.ToInt64(count.ExecuteScalar())>=1000)throw new InvalidOperationException("Service inventory limit reached; no existing resource removed.");
        using(var insert=Command(c,transaction,"INSERT INTO decoy_services(id,key_hash,payload) VALUES($id,$hash,$payload)",("$id",id),("$hash",Hash(key)),("$payload",JsonSerializer.Serialize(item))))insert.ExecuteNonQuery();
        SaveDecoyVersion(c,transaction,item,actor,"Decoy service created");transaction.Commit();return new(item,$"/decoy-api/{id}/{key}");
    }
    static void SaveDecoyVersion(System.Data.Common.DbConnection c,System.Data.Common.DbTransaction transaction,DecoyService item,string actor,string action)
    {
        using(var insert=Command(c,transaction,"INSERT INTO decoy_service_versions(id,revision,actor,payload) VALUES($id,$revision,$actor,$payload)",("$id",item.Id),("$revision",item.Revision),("$actor",actor),("$payload",JsonSerializer.Serialize(item))))insert.ExecuteNonQuery();
        Audit(c,transaction,action,JsonSerializer.Serialize(new{Actor=actor,item.Id,item.Revision}));
    }
    public DecoyService ChangeDecoyService(string id,DecoyServiceChange body,string actor,bool retire=false)
    {
        ValidateDecoyChange(body);if(!Guid.TryParseExact(id,"N",out _))throw new ArgumentException("Invalid service identity.");
        if(!HasDecoyServiceStorage())throw new KeyNotFoundException();
        using var c=Open();using var transaction=c.BeginTransaction(System.Data.IsolationLevel.Serializable);
        using var read=Command(c,transaction,"SELECT payload FROM decoy_services WHERE id=$id",("$id",id));var payload=read.ExecuteScalar() as string??throw new KeyNotFoundException();var old=JsonSerializer.Deserialize<DecoyService>(payload)!;
        if(old.Retired||old.Revision!=body.ExpectedRevision)throw new DecoyServiceConflictException();
        var next=old with{Name=body.Name,Description=body.Description,Location=body.Location??old.Location,Note=body.Note??old.Note,Enabled=!retire&&body.Enabled,Retired=retire,Revision=checked(old.Revision+1),UpdatedUtc=DateTimeOffset.UtcNow};
        using(var update=Command(c,transaction,"UPDATE decoy_services SET payload=$payload WHERE id=$id",("$payload",JsonSerializer.Serialize(next)),("$id",id)))update.ExecuteNonQuery();
        SaveDecoyVersion(c,transaction,next,actor,retire?"Decoy service retired":"Decoy service updated");transaction.Commit();return next;
    }
    public IReadOnlyList<DecoyService> DecoyServices()
    {
        if(!HasDecoyServiceStorage())return [];using var c=Open();using var command=Command(c,null,"SELECT payload FROM decoy_services ORDER BY id");using var reader=command.ExecuteReader();var items=new List<DecoyService>();while(reader.Read())items.Add(JsonSerializer.Deserialize<DecoyService>(reader.GetString(0))!);return items;
    }
    public IReadOnlyList<DecoyServiceHit> DecoyServiceHits(string id)
    {
        if(!Guid.TryParseExact(id,"N",out _))throw new ArgumentException("Invalid service identity.");if(!HasDecoyServiceStorage())return [];
        using var c=Open();using var command=Command(c,null,"SELECT sequence,id,observed,address,method FROM decoy_service_hits WHERE id=$id ORDER BY sequence DESC LIMIT 100",("$id",id));using var reader=command.ExecuteReader();var hits=new List<DecoyServiceHit>();while(reader.Read())hits.Add(new(reader.GetInt64(0),reader.GetString(1),DateTimeOffset.FromUnixTimeMilliseconds(reader.GetInt64(2)),reader.GetString(3),reader.GetString(4)));return hits;
    }
    public bool TouchDecoyService(string id,string key,string address,string method)
    {
        if(!Guid.TryParseExact(id,"N",out _)||key.Length!=64||!key.All(Uri.IsHexDigit)||address.Length>64||address.Any(char.IsControl)||method!="GET"||!HasDecoyServiceStorage())return false;
        InitializeServiceEvidence();
        using var c=Open();using var transaction=c.BeginTransaction(System.Data.IsolationLevel.Serializable);
        using var query=Command(c,transaction,"SELECT key_hash,payload FROM decoy_services WHERE id=$id",("$id",id));string expected;DecoyService item;
        using(var reader=query.ExecuteReader()){if(!reader.Read())return false;expected=reader.GetString(0);item=JsonSerializer.Deserialize<DecoyService>(reader.GetString(1))!;}
        if(!CryptographicOperations.FixedTimeEquals(Convert.FromHexString(expected),Convert.FromHexString(Hash(key)))||!item.Enabled||item.Retired)return false;
        using(var count=Command(c,transaction,"SELECT COUNT(*) FROM decoy_service_hits"))if(Convert.ToInt64(count.ExecuteScalar())>=500000)throw new InvalidOperationException("Decoy evidence storage full; no successful response emitted.");
        var observed=DateTimeOffset.UtcNow;
        using(var insert=Command(c,transaction,"INSERT INTO decoy_service_hits(id,observed,address,method) VALUES($id,$time,$address,$method)",("$id",id),("$time",observed.ToUnixTimeMilliseconds()),("$address",address),("$method",method)))insert.ExecuteNonQuery();
        SaveServiceEvidence(c,transaction,item,address,method,observed);transaction.Commit();return true;
    }
}
public static class DecoyServiceApi
{
    public static void MapDecoyServices(this WebApplication app)
    {
        var read=app.MapGroup("/api/v1/console/decoy-services").RequireAuthorization(p=>p.RequireRole("Administrator","Operator","Reader"));
        read.MapGet("",(Store store)=>Results.Ok(store.DecoyServices()));
        read.MapGet("/{id}/hits",(string id,Store store)=>Guid.TryParseExact(id,"N",out _)?Results.Ok(store.DecoyServiceHits(id)):Results.BadRequest());
        app.MapPost("/api/v1/console/decoy-services",async(HttpContext c,IAntiforgery csrf,DecoyServiceChange body,Store store,UserManager<LocalUser> users,SignInManager<LocalUser> signIn,AuthDb db)=>
        {
            if(!await NotificationAuthorization.Check(c,csrf,body.AdministratorPassword,body.Code,body.RecoveryCode,users,signIn,db))return Results.Unauthorized();
            try{store.InitializeDecoyServiceStorage();return Results.Ok(store.CreateDecoyService(body,c.User.FindFirstValue(ClaimTypes.NameIdentifier)!));}catch(ArgumentException){return Results.BadRequest(new{error="Create a disabled service with a name, description and request identity."});}catch(DecoyServiceConflictException){return Results.Conflict();}
        }).RequireAuthorization(p=>p.RequireRole("Administrator"));
        app.MapPost("/api/v1/console/decoy-services/{id}",async(HttpContext c,string id,IAntiforgery csrf,DecoyServiceChange body,Store store,UserManager<LocalUser> users,SignInManager<LocalUser> signIn,AuthDb db)=>
        {
            if(!await NotificationAuthorization.Check(c,csrf,body.AdministratorPassword,body.Code,body.RecoveryCode,users,signIn,db))return Results.Unauthorized();
            try{return Results.Ok(store.ChangeDecoyService(id,body,c.User.FindFirstValue(ClaimTypes.NameIdentifier)!));}catch(ArgumentException){return Results.BadRequest();}catch(KeyNotFoundException){return Results.NotFound();}catch(DecoyServiceConflictException){return Results.Conflict(new{error="Service changed or retired. Refresh before editing."});}
        }).RequireAuthorization(p=>p.RequireRole("Administrator"));
        app.MapPost("/api/v1/console/decoy-services/{id}/retire",async(HttpContext c,string id,IAntiforgery csrf,DecoyServiceRetirement body,Store store,UserManager<LocalUser> users,SignInManager<LocalUser> signIn,AuthDb db)=>
        {
            if(!await NotificationAuthorization.Check(c,csrf,body.AdministratorPassword,body.Code,body.RecoveryCode,users,signIn,db))return Results.Unauthorized();
            var prior=store.DecoyServices().SingleOrDefault(x=>x.Id==id);if(prior==null)return Results.NotFound();
            try{return Results.Ok(store.ChangeDecoyService(id,new(prior.Name,prior.Description,false,body.ExpectedRevision,body.AdministratorPassword),c.User.FindFirstValue(ClaimTypes.NameIdentifier)!,true));}catch(DecoyServiceConflictException){return Results.Conflict();}
        }).RequireAuthorization(p=>p.RequireRole("Administrator"));
        // Existing HTTPS listener/rate limit only: no new ports, credentials, bodies or external requests.
        app.MapGet("/decoy-api/{id}/{key}",(HttpContext c,string id,string key,Store store)=>
        {
            c.Response.Headers.CacheControl="no-store";
            return store.TouchDecoyService(id,key,c.Connection.RemoteIpAddress?.ToString()??"unknown","GET")?Results.Ok(new{service="Document archive",status="available",records=Array.Empty<object>()}):Results.NotFound();
        });
    }
}
