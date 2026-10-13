using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using Microsoft.AspNetCore.Antiforgery;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;

namespace RansomFree.Server;

public sealed class LocalUser : IdentityUser;
public sealed class UsedMfaCode
{
    public string Id {get;set;}="";
    public long Expires {get;set;}
}
public sealed class RecoveryCode
{
    public string Id {get;set;}="";
    public string UserId {get;set;}="";
}
public sealed class IdentityAudit
{
    public long Id {get;set;}
    public DateTimeOffset Time {get;set;}
    public string Actor {get;set;}="";
    public string Action {get;set;}="";
}
public sealed class AuthDb(DbContextOptions<AuthDb> options,IDataProtectionProvider protection) : IdentityDbContext<LocalUser>(options)
{
    public DbSet<UsedMfaCode> UsedMfaCodes=>Set<UsedMfaCode>();
    public DbSet<RecoveryCode> RecoveryCodes=>Set<RecoveryCode>();
    public DbSet<IdentityAudit> IdentityAudit=>Set<IdentityAudit>();
    public DbSet<DirectoryIdentity> DirectoryIdentities=>Set<DirectoryIdentity>();
    public DbSet<AccountControl> AccountControls=>Set<AccountControl>();
    public DbSet<AccountRecovery> AccountRecoveries=>Set<AccountRecovery>();
    public DbSet<OrganizationSecurity> OrganizationSecurity=>Set<OrganizationSecurity>();
    protected override void OnModelCreating(ModelBuilder b)
    {
        base.OnModelCreating(b);
        if(Database.IsSqlServer())
        {
            // Bound composite Identity keys below SQL Server's clustered-index key limit.
            b.Entity<LocalUser>().Property(x=>x.Id).HasMaxLength(128);b.Entity<IdentityRole>().Property(x=>x.Id).HasMaxLength(128);
            b.Entity<IdentityUserLogin<string>>().Property(x=>x.LoginProvider).HasMaxLength(128);
            b.Entity<IdentityUserLogin<string>>().Property(x=>x.ProviderKey).HasMaxLength(128);
            b.Entity<IdentityUserLogin<string>>().Property(x=>x.UserId).HasMaxLength(128);
            b.Entity<IdentityUserToken<string>>().Property(x=>x.UserId).HasMaxLength(128);
            b.Entity<IdentityUserToken<string>>().Property(x=>x.LoginProvider).HasMaxLength(128);
            b.Entity<IdentityUserToken<string>>().Property(x=>x.Name).HasMaxLength(128);
            b.Entity<IdentityUserRole<string>>().Property(x=>x.UserId).HasMaxLength(128);b.Entity<IdentityUserRole<string>>().Property(x=>x.RoleId).HasMaxLength(128);
            b.Entity<IdentityUserClaim<string>>().Property(x=>x.UserId).HasMaxLength(128);b.Entity<IdentityRoleClaim<string>>().Property(x=>x.RoleId).HasMaxLength(128);
        }
        b.Entity<DirectoryIdentity>().HasKey(x=>x.UserId);b.Entity<DirectoryIdentity>().HasIndex(x=>x.ObjectId).IsUnique();
        b.Entity<AccountControl>().HasKey(x=>x.UserId);
        b.Entity<AccountRecovery>().HasKey(x=>x.UserId);
        b.Entity<OrganizationSecurity>().Property(x=>x.Id).ValueGeneratedNever();
        var protector=protection.CreateProtector("RansomFree.Identity.Tokens.v1");
        b.Entity<IdentityUserToken<string>>().Property(t=>t.Value).HasConversion(v=>v==null?null:protector.Protect(v),v=>v==null?null:protector.Unprotect(v));
    }
}
public sealed record LoginBody(string UserName,string Password,string? Code=null,string? RecoveryCode=null);
public sealed record CreateUserBody(string UserName,string Password,string Role);
public sealed record MfaBody(string Password,string? Code=null,string? RecoveryCode=null);
public sealed record ChangePasswordBody(string Password,string NewPassword,string? Code=null,string? RecoveryCode=null);

public static partial class HumanIdentity
{
    private static readonly PasswordHasher<LocalUser> DummyHasher=new(Microsoft.Extensions.Options.Options.Create(new PasswordHasherOptions {IterationCount=600000}));
    private static readonly string DummyHash=DummyHasher.HashPassword(new LocalUser(),Convert.ToHexString(RandomNumberGenerator.GetBytes(32)));
    public static void AddHumanIdentity(this WebApplicationBuilder builder,string directory,bool lab)
    {
        builder.Services.AddSingleton(new DirectoryAuthenticator(builder.Configuration));
        var keys=builder.Services.AddDataProtection().SetApplicationName("RansomFree.Management").PersistKeysToFileSystem(new DirectoryInfo(Path.Combine(directory,"identity-keys")));
        if(builder.Configuration["IdentityKeys:CertificatePath"] is {} certificatePath)
        {
            var certificate=System.Security.Cryptography.X509Certificates.X509CertificateLoader.LoadPkcs12FromFile(certificatePath,builder.Configuration["IdentityKeys:CertificatePassword"],System.Security.Cryptography.X509Certificates.X509KeyStorageFlags.EphemeralKeySet);
            if(!certificate.HasPrivateKey || certificate.NotAfter.ToUniversalTime()<=DateTime.UtcNow)throw new InvalidOperationException("Identity-key encryption certificate must be current and contain its private key.");
            keys.ProtectKeysWithCertificate(certificate);
        }
        else if(OperatingSystem.IsWindows())keys.ProtectKeysWithDpapi();
        var database=new RansomFree.Persistence.DatabaseSettings(builder.Configuration);
        builder.Services.AddDbContext<AuthDb>(o=>{if(database.SqlServer)o.UseSqlServer(database.Connection("Identity"),sql=>sql.UseCompatibilityLevel(150));else o.UseSqlite(new Microsoft.Data.Sqlite.SqliteConnectionStringBuilder {DataSource=Path.Combine(directory,"identity.db")}.ToString());});
        var passwordPolicy=LocalPasswordPolicy.Load(builder.Configuration);
        builder.Services.AddSingleton(passwordPolicy);
        builder.Services.AddIdentity<LocalUser,IdentityRole>(o=>
        {
            passwordPolicy.Apply(o.Password);
            o.Lockout.MaxFailedAccessAttempts=5;o.Lockout.DefaultLockoutTimeSpan=TimeSpan.FromMinutes(15);o.Lockout.AllowedForNewUsers=true;
            o.User.AllowedUserNameCharacters="abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-._@";
        }).AddEntityFrameworkStores<AuthDb>().AddDefaultTokenProviders();
        builder.Services.Configure<PasswordHasherOptions>(o=>o.IterationCount=600000);
        builder.Services.Configure<SecurityStampValidatorOptions>(o=>o.ValidationInterval=TimeSpan.Zero);
        builder.Services.ConfigureApplicationCookie(o=>
        {
            o.Cookie.Name="RansomFree.Session";o.Cookie.HttpOnly=true;o.Cookie.SameSite=SameSiteMode.Strict;
            o.Cookie.SecurePolicy=lab?CookieSecurePolicy.SameAsRequest:CookieSecurePolicy.Always;
            o.ExpireTimeSpan=TimeSpan.FromMinutes(30);o.SlidingExpiration=false;
            o.Events.OnRedirectToLogin=c=>{c.Response.StatusCode=401;return Task.CompletedTask;};
            o.Events.OnRedirectToAccessDenied=c=>{c.Response.StatusCode=403;return Task.CompletedTask;};
        });
        builder.Services.AddAntiforgery(o=>{o.HeaderName="X-CSRF";o.Cookie.Name="RansomFree.Csrf";o.Cookie.SameSite=SameSiteMode.Strict;o.Cookie.SecurePolicy=lab?CookieSecurePolicy.SameAsRequest:CookieSecurePolicy.Always;});
        builder.Services.AddAuthorization();
        builder.Services.AddRateLimiter(o=>o.AddPolicy("identity",c=>System.Threading.RateLimiting.RateLimitPartition.GetFixedWindowLimiter(c.Connection.RemoteIpAddress?.ToString()??"unknown",_=>new(){PermitLimit=60,Window=TimeSpan.FromMinutes(1),QueueLimit=0})));
    }

    public static async Task InitializeIdentityAsync(this WebApplication app)
    {
        using var scope=app.Services.CreateScope();
        var db=scope.ServiceProvider.GetRequiredService<AuthDb>();
        if(db.Database.IsSqlServer())RansomFree.Persistence.SqlServerSchema.Require(db.Database.GetConnectionString()!,"identity",1);
        else
        {
        await db.Database.EnsureCreatedAsync();
        // Additive development-schema upgrade: preserve accounts created by the initial identity build.
        // Replace EnsureCreated with reviewed versioned migrations before enabling Production.
        await db.Database.ExecuteSqlRawAsync("""
            CREATE TABLE IF NOT EXISTS RecoveryCodes (Id TEXT NOT NULL PRIMARY KEY, UserId TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS IdentityAudit (Id INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT, Time TEXT NOT NULL, Actor TEXT NOT NULL, Action TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS DirectoryIdentities (UserId TEXT NOT NULL PRIMARY KEY,ObjectId TEXT NOT NULL,UserPrincipalName TEXT NOT NULL);
            CREATE UNIQUE INDEX IF NOT EXISTS IX_DirectoryIdentities_ObjectId ON DirectoryIdentities(ObjectId);
            CREATE TABLE IF NOT EXISTS AccountControls (UserId TEXT NOT NULL PRIMARY KEY,Disabled INTEGER NOT NULL DEFAULT 0);
            CREATE TABLE IF NOT EXISTS AccountRecoveries (UserId TEXT NOT NULL PRIMARY KEY,MustChangePassword INTEGER NOT NULL DEFAULT 0,MustEnrollMfa INTEGER NOT NULL DEFAULT 0,TemporaryPasswordExpires INTEGER);
            CREATE TABLE IF NOT EXISTS OrganizationSecurity (Id INTEGER NOT NULL PRIMARY KEY,MfaMode TEXT NOT NULL,Version INTEGER NOT NULL);
            """);
        }
        var roles=scope.ServiceProvider.GetRequiredService<RoleManager<IdentityRole>>();
        foreach(var name in new[]{"Administrator","Operator","Reader"})
            if(!await roles.RoleExistsAsync(name))
            {
                var result=await roles.CreateAsync(new(name));if(!result.Succeeded)throw new InvalidOperationException("Could not initialize identity roles.");
            }
    }

    public static void MapHumanIdentity(this WebApplication app,Func<HttpContext,bool> bootstrap)
    {
        app.MapGet("/password-policy.json",(LocalPasswordPolicy policy)=>Results.Ok(policy));
        app.MapGet("/api/v1/auth/csrf",(HttpContext c,IAntiforgery csrf)=>Results.Ok(new {token=csrf.GetAndStoreTokens(c).RequestToken}));
        // No public registration. Temporary development provisioning uses the existing bootstrap authority.
        app.MapPost("/api/v1/admin/users",async(HttpContext c,CreateUserBody body,UserManager<LocalUser> users,AuthDb db)=>
        {
            if(!bootstrap(c))return Results.Unauthorized();
            if(body.UserName is null || body.UserName.Length>100 || body.Password is null || body.Password.Length>256 || body.Role is not ("Administrator" or "Operator" or "Reader"))return Results.BadRequest();
            await using var transaction=await db.Database.BeginTransactionAsync();
            var user=new LocalUser {UserName=body.UserName,LockoutEnabled=true};
            var create=await users.CreateAsync(user,body.Password);if(!create.Succeeded)return Results.BadRequest(new {error="Account could not be created. Check username and password policy."});
            var role=await users.AddToRoleAsync(user,body.Role);if(!role.Succeeded)throw new InvalidOperationException("Role assignment failed.");
            await Log(db,user.Id,"Account provisioned by development bootstrap");
            await transaction.CommitAsync();return Results.Ok(new {id=user.Id,userName=user.UserName,role=body.Role});
        });
        app.MapPost("/api/v1/auth/login",async(HttpContext c,LoginBody body,IAntiforgery csrf,UserManager<LocalUser> users,SignInManager<LocalUser> signIn,AuthDb db)=>
        {
            if(!await Csrf(c,csrf))return Results.BadRequest();
            if(body.UserName is null || body.UserName.Length>100 || body.Password is null || body.Password.Length>256 || body.Code?.Length>16)return Results.Unauthorized();
            var user=await users.FindByNameAsync(body.UserName);
            if(user is null)
            {
                _=DummyHasher.VerifyHashedPassword(new LocalUser(),DummyHash,body.Password);
                await Log(db,"unknown","Local sign-in denied");return Results.Unauthorized();
            }
            if(await db.UserLogins.AnyAsync(x=>x.UserId==user.Id) || !await VerifyPrimaryPassword(c,user,body.Password,users,signIn,db)){await Log(db,user.Id,"Local sign-in denied");return Results.Unauthorized();}
            if(await users.GetTwoFactorEnabledAsync(user))
            {
                if(!await MfaProof(user,body.Code,body.RecoveryCode,users,db)){await users.AccessFailedAsync(user);await Log(db,user.Id,"MFA sign-in denied");return Results.Unauthorized();}
            }
            await users.ResetAccessFailedCountAsync(user);
            await Log(db,user.Id,"Local sign-in succeeded");
            await signIn.SignInAsync(user,false);return Results.NoContent();
        }).RequireRateLimiting("identity");
        app.MapPost("/api/v1/auth/password",async(HttpContext c,ChangePasswordBody body,IAntiforgery csrf,UserManager<LocalUser> users,SignInManager<LocalUser> signIn,AuthDb db)=>
        {
            if(!await Csrf(c,csrf))return Results.BadRequest();
            if(body.Password is null || body.Password.Length>256 || body.NewPassword is null || body.NewPassword.Length is <1 or >256 || body.NewPassword==body.Password)return Results.BadRequest();
            var user=await users.GetUserAsync(c.User);
            if(user is null || !await VerifyPrimaryPassword(c,user,body.Password,users,signIn,db))return Results.Unauthorized();
            if(await users.GetTwoFactorEnabledAsync(user) && !await MfaProof(user,body.Code,body.RecoveryCode,users,db))
            {await users.AccessFailedAsync(user);await Log(db,user.Id,"Password change denied: second-factor verification failed");return Results.Unauthorized();}
            await using var transaction=await db.Database.BeginTransactionAsync();
            var result=await users.ChangePasswordAsync(user,body.Password,body.NewPassword);
            if(!result.Succeeded)return Results.BadRequest();
            var recovery=await db.AccountRecoveries.FindAsync(user.Id);if(recovery!=null){recovery.MustChangePassword=false;recovery.TemporaryPasswordExpires=null;}
            await Log(db,user.Id,"Local password changed; sessions invalidated");
            await transaction.CommitAsync();await signIn.SignOutAsync();return Results.NoContent();
        }).RequireAuthorization().RequireRateLimiting("identity");
        app.MapPost("/api/v1/auth/logout",async(HttpContext c,IAntiforgery csrf,SignInManager<LocalUser> signIn)=>
        {
            if(!await Csrf(c,csrf))return Results.BadRequest();await signIn.SignOutAsync();return Results.NoContent();
        }).RequireAuthorization();
        app.MapGet("/api/v1/auth/me",async(HttpContext c,UserManager<LocalUser> users,AuthDb db)=>
        {
            var user=await users.GetUserAsync(c.User);if(user is null)return Results.Unauthorized();
            var recovery=await db.AccountRecoveries.AsNoTracking().SingleOrDefaultAsync(x=>x.UserId==user.Id);
            var enabled=await users.GetTwoFactorEnabledAsync(user);var required=await RequiredMfa(db,c.User);
            return Results.Ok(new {userName=user.UserName,roles=new[]{"Administrator","Operator","Reader"}.Where(c.User.IsInRole).ToArray(),mfaEnabled=enabled,mfaRequired=required,authentication=await db.UserLogins.AnyAsync(x=>x.UserId==user.Id)?"SSO":await db.DirectoryIdentities.AnyAsync(x=>x.UserId==user.Id)?"Directory":"Local",mustChangePassword=recovery?.MustChangePassword??false,mustEnrollMfa=(recovery?.MustEnrollMfa??false)||required&&!enabled});
        }).RequireAuthorization();
        app.MapPost("/api/v1/auth/mfa/setup",async(HttpContext c,MfaBody body,IAntiforgery csrf,UserManager<LocalUser> users,SignInManager<LocalUser> signIn,AuthDb db)=>
        {
            if(!await Csrf(c,csrf))return Results.BadRequest();var user=await users.GetUserAsync(c.User);
            if(user is null || body.Password is null || body.Password.Length>256 || !await VerifyPrimaryPassword(c,user,body.Password,users,signIn,db))return Results.Unauthorized();
            if(await users.GetTwoFactorEnabledAsync(user))return Results.Conflict();
            var key=await users.GetAuthenticatorKeyAsync(user);
            if(key is null){var reset=await users.ResetAuthenticatorKeyAsync(user);if(!reset.Succeeded)throw new InvalidOperationException("MFA setup failed.");key=await users.GetAuthenticatorKeyAsync(user);await signIn.RefreshSignInAsync(user);}
            return Results.Ok(new {key,uri=$"otpauth://totp/RansomFree:{Uri.EscapeDataString(user.UserName!)}?secret={key}&issuer=RansomFree&digits=6"});
        }).RequireAuthorization();
        app.MapPost("/api/v1/auth/mfa/enable",async(HttpContext c,MfaBody body,IAntiforgery csrf,UserManager<LocalUser> users,SignInManager<LocalUser> signIn,AuthDb db)=>
        {
            if(!await Csrf(c,csrf))return Results.BadRequest();var user=await users.GetUserAsync(c.User);
            if(user is null || body.Password is null || body.Password.Length>256 || !await VerifyPrimaryPassword(c,user,body.Password,users,signIn,db))return Results.Unauthorized();
            if(await users.GetTwoFactorEnabledAsync(user))return Results.Conflict();
            if(!await ConsumeCode(user,body.Code,users,db)){await users.AccessFailedAsync(user);return Results.Unauthorized();}
            await using var transaction=await db.Database.BeginTransactionAsync();
            var result=await users.SetTwoFactorEnabledAsync(user,true);if(!result.Succeeded)throw new InvalidOperationException("MFA activation failed.");
            var recoveryState=await db.AccountRecoveries.FindAsync(user.Id);if(recoveryState!=null)recoveryState.MustEnrollMfa=false;
            var recovery=Enumerable.Range(0,10).Select(_=>Convert.ToHexString(RandomNumberGenerator.GetBytes(16)).ToLowerInvariant()).ToArray();
            await db.RecoveryCodes.Where(x=>x.UserId==user.Id).ExecuteDeleteAsync();
            db.RecoveryCodes.AddRange(recovery.Select(code=>new RecoveryCode {Id=RecoveryHash(user.Id,code),UserId=user.Id}));
            await Log(db,user.Id,"MFA enabled; recovery codes issued");
            if(!(await users.UpdateSecurityStampAsync(user)).Succeeded)throw new InvalidOperationException("Session invalidation failed.");
            await transaction.CommitAsync();await signIn.SignOutAsync();return Results.Ok(new {recoveryCodes=recovery});
        }).RequireAuthorization().RequireRateLimiting("identity");
        app.MapPost("/api/v1/auth/mfa/disable",async(HttpContext c,MfaBody body,IAntiforgery csrf,UserManager<LocalUser> users,SignInManager<LocalUser> signIn,AuthDb db)=>
        {
            if(!await Csrf(c,csrf))return Results.BadRequest();var user=await users.GetUserAsync(c.User);
            if(await RequiredMfa(db,c.User))return Results.Conflict(new{error="MFA is required by organization policy."});
            if(user is null || body.Password is null || body.Password.Length>256 || !await VerifyPrimaryPassword(c,user,body.Password,users,signIn,db))return Results.Unauthorized();
            if(!await users.GetTwoFactorEnabledAsync(user))return Results.Conflict();
            if(!await MfaProof(user,body.Code,body.RecoveryCode,users,db)){await users.AccessFailedAsync(user);return Results.Unauthorized();}
            await using var transaction=await db.Database.BeginTransactionAsync();
            if(!(await users.SetTwoFactorEnabledAsync(user,false)).Succeeded || !(await users.ResetAuthenticatorKeyAsync(user)).Succeeded)throw new InvalidOperationException("MFA update failed.");
            await db.RecoveryCodes.Where(x=>x.UserId==user.Id).ExecuteDeleteAsync();
            await Log(db,user.Id,"MFA disabled after reauthentication");
            if(!(await users.UpdateSecurityStampAsync(user)).Succeeded)throw new InvalidOperationException("Session invalidation failed.");
            await transaction.CommitAsync();await signIn.SignOutAsync();return Results.NoContent();
        }).RequireAuthorization().RequireRateLimiting("identity");
        app.MapGet("/api/v1/console/endpoints",(Store store)=>Results.Ok(store.Inventory())).RequireAuthorization(p=>p.RequireRole("Reader","Operator","Administrator"));
        app.MapGet("/api/v1/console/events",(Store store,long after=0,int limit=100)=>after<0 || limit is <1 or >500?Results.BadRequest():Results.Ok(store.Events(after,limit))).RequireAuthorization(p=>p.RequireRole("Reader","Operator","Administrator"));
        app.MapEventHistory();
        app.MapPost("/api/v1/console/enrollment-codes",async(HttpContext c,IAntiforgery csrf,Store store)=>!await Csrf(c,csrf)?Results.BadRequest():Results.Ok(store.CreateCode(c.User.FindFirstValue(ClaimTypes.NameIdentifier)!))).RequireAuthorization(p=>p.RequireRole("Administrator"));
        app.MapGet("/api/v1/console/identity-audit",async(AuthDb db)=>Results.Ok(await db.IdentityAudit.OrderByDescending(x=>x.Id).Take(100).ToListAsync())).RequireAuthorization(p=>p.RequireRole("Administrator"));
    }
    private static async Task<bool> Csrf(HttpContext c,IAntiforgery csrf)
    {
        try{await csrf.ValidateRequestAsync(c);return true;}catch(AntiforgeryValidationException){return false;}
    }
    private static async Task<bool> ConsumeCode(LocalUser user,string? code,UserManager<LocalUser> users,AuthDb db)
    {
        if(code is null || code.Length!=6 || !code.All(char.IsAsciiDigit) || !await users.VerifyTwoFactorTokenAsync(user,TokenOptions.DefaultAuthenticatorProvider,code))return false;
        var now=DateTimeOffset.UtcNow.ToUnixTimeSeconds();
        await db.UsedMfaCodes.Where(x=>x.Expires<now).ExecuteDeleteAsync();
        var id=Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(user.Id+":"+code)));
        // Atomic insert enforces replay protection across concurrent requests and restarts.
        try{db.UsedMfaCodes.Add(new(){Id=id,Expires=now+300});await db.SaveChangesAsync();return true;}
        catch(DbUpdateException ex) when(ex.InnerException!=null && RansomFree.Persistence.Relational.UniqueViolation(ex.InnerException))
        {
            foreach(var entry in ex.Entries)entry.State=EntityState.Detached;
            return false;
        }
    }
    private static string RecoveryHash(string user,string code)=>Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(user+":"+code)));
    private static async Task<bool> MfaProof(LocalUser user,string? code,string? recovery,UserManager<LocalUser> users,AuthDb db)
    {
        if(!string.IsNullOrEmpty(code) && !string.IsNullOrEmpty(recovery))return false;
        if(!string.IsNullOrEmpty(recovery))
        {
            if(recovery.Length!=32 || !recovery.All(Uri.IsHexDigit))return false;
            var hash=RecoveryHash(user.Id,recovery.ToLowerInvariant());
            return await db.RecoveryCodes.Where(x=>x.UserId==user.Id && x.Id==hash).ExecuteDeleteAsync()==1;
        }
        return await ConsumeCode(user,code,users,db);
    }
    private static async Task Log(AuthDb db,string actor,string action)
    {
        db.IdentityAudit.Add(new(){Time=DateTimeOffset.UtcNow,Actor=actor,Action=action});await db.SaveChangesAsync();
    }
}
