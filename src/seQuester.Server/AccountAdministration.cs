using System.Security.Claims;
using Microsoft.AspNetCore.Antiforgery;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;

namespace RansomFree.Server;

public sealed record NewAccountBody(string UserName,string Role,string? NewPassword,string? DirectoryPrincipal,string? DirectoryObjectId,string AdministratorPassword,string? Code=null,string? RecoveryCode=null);
public sealed record EditAccountBody(string ConcurrencyStamp,string Role,bool Disabled,string AdministratorPassword,string? Code=null,string? RecoveryCode=null);
public static partial class HumanIdentity
{
    private static async Task<bool> VerifyPrimaryPassword(HttpContext c,LocalUser user,string password,UserManager<LocalUser> users,SignInManager<LocalUser> signIn,AuthDb db)
    {
        if(await db.AccountControls.AnyAsync(x=>x.UserId==user.Id && x.Disabled))return false;
        if(await db.UserLogins.AnyAsync(x=>x.UserId==user.Id))
        {
            var stamp=c.User.FindFirstValue("rf:sso_at");var current=DateTimeOffset.UtcNow.ToUnixTimeSeconds();
            return c.User.FindFirstValue(ClaimTypes.NameIdentifier)==user.Id && long.TryParse(stamp,out var occurred) && occurred>=current-300 && occurred<=current+60;
        }
        var now=DateTimeOffset.UtcNow.ToUnixTimeSeconds();
        if(await db.AccountRecoveries.AnyAsync(x=>x.UserId==user.Id && x.MustChangePassword && x.TemporaryPasswordExpires!=null && x.TemporaryPasswordExpires<=now))return false;
        var directory=await db.DirectoryIdentities.SingleOrDefaultAsync(x=>x.UserId==user.Id);
        if(directory is null)return (await signIn.CheckPasswordSignInAsync(user,password,true)).Succeeded;
        if(await users.IsLockedOutAsync(user))return false;
        var verified=await c.RequestServices.GetRequiredService<DirectoryAuthenticator>().VerifyAsync(directory,password,c.RequestAborted);
        if(!verified)await users.AccessFailedAsync(user);return verified;
    }
    internal static async Task<bool> ReauthenticateAdministrator(HttpContext c,string password,string? code,string? recovery,UserManager<LocalUser> users,SignInManager<LocalUser> signIn,AuthDb db)
    {
        var actor=await users.GetUserAsync(c.User);
        if(actor is null || password is null || password.Length>256 || !await VerifyPrimaryPassword(c,actor,password,users,signIn,db))return false;
        if(await users.GetTwoFactorEnabledAsync(actor) && !await MfaProof(actor,code,recovery,users,db)){await users.AccessFailedAsync(actor);return false;}
        return true;
    }
    internal static async Task<bool> StillAdministrator(HttpContext c,AuthDb db)
    {
        var id=c.User.FindFirstValue(ClaimTypes.NameIdentifier)!;
        return !await db.AccountControls.AnyAsync(x=>x.UserId==id && x.Disabled) && await (from link in db.UserRoles join role in db.Roles on link.RoleId equals role.Id where link.UserId==id && role.Name=="Administrator" select link).AnyAsync();
    }
    public static void MapAccountAdministration(this WebApplication app)
    {
        app.MapGet("/api/v1/auth/methods",(DirectoryAuthenticator directory)=>Results.Ok(new {local=true,directory=directory.Enabled}));
        var group=app.MapGroup("/api/v1/console/accounts").RequireAuthorization(p=>p.RequireRole("Administrator"));
        group.MapGet("",async(AuthDb db)=>
        {
            var users=await db.Users.AsNoTracking().OrderBy(x=>x.UserName).Take(500).ToListAsync();var ids=users.Select(x=>x.Id).ToArray();
            var roles=await (from link in db.UserRoles join role in db.Roles on link.RoleId equals role.Id where ids.Contains(link.UserId) select new {link.UserId,role.Name}).ToListAsync();
            var directories=await db.DirectoryIdentities.AsNoTracking().Where(x=>ids.Contains(x.UserId)).ToListAsync();var disabled=await db.AccountControls.Where(x=>ids.Contains(x.UserId) && x.Disabled).Select(x=>x.UserId).ToListAsync();
            var recoveries=await db.AccountRecoveries.AsNoTracking().Where(x=>ids.Contains(x.UserId)).ToListAsync();
            var sso=await db.UserLogins.Where(x=>ids.Contains(x.UserId)).Select(x=>x.UserId).Distinct().ToListAsync();
            return Results.Ok(users.Select(x=>new {x.Id,x.UserName,x.ConcurrencyStamp,mfaEnabled=x.TwoFactorEnabled,disabled=disabled.Contains(x.Id),roles=roles.Where(r=>r.UserId==x.Id).Select(r=>r.Name),authentication=sso.Contains(x.Id)?"SSO":directories.Any(d=>d.UserId==x.Id)?"Directory":"Local",mustChangePassword=recoveries.Any(r=>r.UserId==x.Id && r.MustChangePassword),mustEnrollMfa=recoveries.Any(r=>r.UserId==x.Id && r.MustEnrollMfa)}));
        });
        group.MapPost("",async(HttpContext c,IAntiforgery csrf,NewAccountBody body,UserManager<LocalUser> users,SignInManager<LocalUser> signIn,AuthDb db,DirectoryAuthenticator directory)=>
        {
            if(!await Csrf(c,csrf) || string.IsNullOrWhiteSpace(body.UserName) || body.UserName.Length>100 || body.Role is not ("Administrator" or "Operator" or "Reader"))return Results.BadRequest();
            var external=body.DirectoryPrincipal!=null;
            if(external ? !directory.ValidPrincipal(body.DirectoryPrincipal) || !Guid.TryParse(body.DirectoryObjectId,out _) || !string.IsNullOrEmpty(body.NewPassword) : body.NewPassword is null || body.NewPassword.Length is <1 or >256 || body.DirectoryObjectId!=null)return Results.BadRequest();
            if(!await ReauthenticateAdministrator(c,body.AdministratorPassword,body.Code,body.RecoveryCode,users,signIn,db))return Results.Unauthorized();
            await using var transaction=await db.Database.BeginTransactionAsync();
            if(!await StillAdministrator(c,db))return Results.Forbid();
            var user=new LocalUser {UserName=body.UserName.Trim(),LockoutEnabled=true};var result=external?await users.CreateAsync(user):await users.CreateAsync(user,body.NewPassword!);
            if(!result.Succeeded)return Results.BadRequest(new {error="Account could not be created. Check the name and password policy."});
            if(!(await users.AddToRoleAsync(user,body.Role)).Succeeded)throw new InvalidOperationException("Role assignment failed.");
            if(!external)db.AccountRecoveries.Add(new(){UserId=user.Id,MustChangePassword=true,TemporaryPasswordExpires=DateTimeOffset.UtcNow.AddHours(24).ToUnixTimeSeconds()});
            if(external)
            {
                var objectId=Guid.Parse(body.DirectoryObjectId!).ToString("N");
                if(await db.DirectoryIdentities.AnyAsync(x=>x.ObjectId==objectId))return Results.Conflict();
                db.DirectoryIdentities.Add(new(){UserId=user.Id,ObjectId=objectId,UserPrincipalName=body.DirectoryPrincipal!});
            }
            await Log(db,c.User.FindFirstValue(ClaimTypes.NameIdentifier)!,"Account created: "+user.Id+" / "+(external?"Directory":"Local"));
            await transaction.CommitAsync();return Results.Ok(new {user.Id,user.UserName});
        }).RequireRateLimiting("identity");
        group.MapPost("/{id}",async(HttpContext c,IAntiforgery csrf,string id,EditAccountBody body,UserManager<LocalUser> users,SignInManager<LocalUser> signIn,AuthDb db)=>
        {
            if(!await Csrf(c,csrf) || body.Role is not ("Administrator" or "Operator" or "Reader") || body.ConcurrencyStamp is null)return Results.BadRequest();
            var actor=c.User.FindFirstValue(ClaimTypes.NameIdentifier)!;if(actor==id)return Results.BadRequest(new {error="Another administrator must change your access."});
            if(!await ReauthenticateAdministrator(c,body.AdministratorPassword,body.Code,body.RecoveryCode,users,signIn,db))return Results.Unauthorized();
            await using var transaction=await db.Database.BeginTransactionAsync();
            if(!await StillAdministrator(c,db))return Results.Forbid();
            var user=await users.FindByIdAsync(id);if(user is null)return Results.NotFound();if(user.ConcurrencyStamp!=body.ConcurrencyStamp)return Results.Conflict();
            var prior=await users.GetRolesAsync(user);
            if(!(await users.RemoveFromRolesAsync(user,prior)).Succeeded || !(await users.AddToRoleAsync(user,body.Role)).Succeeded)throw new InvalidOperationException("Account role update failed.");
            var state=await db.AccountControls.FindAsync(id);if(state is null){state=new(){UserId=id};db.AccountControls.Add(state);}state.Disabled=body.Disabled;
            if(!(await users.UpdateSecurityStampAsync(user)).Succeeded)throw new InvalidOperationException("Session invalidation failed.");
            await Log(db,actor,"Account access changed: "+id+" / "+body.Role+" / "+(body.Disabled?"Disabled":"Enabled"));
            await transaction.CommitAsync();return Results.NoContent();
        }).RequireRateLimiting("identity");
    }
}
