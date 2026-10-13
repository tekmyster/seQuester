using System.Security.Claims;
using System.Security.Cryptography;
using Microsoft.AspNetCore.Antiforgery;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;

namespace RansomFree.Server;

public sealed class AccountRecovery
{
    public string UserId {get;set;}="";
    public bool MustChangePassword {get;set;}
    public bool MustEnrollMfa {get;set;}
    public long? TemporaryPasswordExpires {get;set;}
}
public sealed record RecoverAccountBody(string ConcurrencyStamp,bool ResetPassword,bool ResetMfa,string Reason,string AdministratorPassword,string? Code=null,string? RecoveryCode=null);

public static partial class HumanIdentity
{
    public static void UseAccountRecoveryRestrictions(this WebApplication app)
    {
        app.Use(async(c,next)=>
        {
            if(c.User.Identity?.IsAuthenticated==true && c.Request.Path.StartsWithSegments("/api"))
            {
                var id=c.User.FindFirstValue(ClaimTypes.NameIdentifier)!;
                var db=c.RequestServices.GetRequiredService<AuthDb>();
                var recovery=await db.AccountRecoveries.AsNoTracking().SingleOrDefaultAsync(x=>x.UserId==id);
                var required=await RequiredMfa(db,c.User) && await db.Users.AnyAsync(x=>x.Id==id && !x.TwoFactorEnabled);
                if(required || recovery is {MustChangePassword:true} or {MustEnrollMfa:true})
                {
                    var path=c.Request.Path.Value;
                    if(path is not ("/api/v1/auth/me" or "/api/v1/auth/csrf" or "/api/v1/auth/logout" or "/api/v1/auth/password" or "/api/v1/auth/mfa/setup" or "/api/v1/auth/mfa/enable" or "/api/v1/auth/sso/providers" or "/api/v1/auth/sso/pending" or "/api/v1/auth/sso/complete") && !c.Request.Path.StartsWithSegments("/api/v1/auth/sso/start"))
                    {c.Response.StatusCode=403;await c.Response.WriteAsJsonAsync(new {error="Complete account recovery before accessing management.",recoveryRequired=true});return;}
                }
            }
            await next(c);
        });
    }
    public static void MapAccountRecovery(this WebApplication app)
    {
        app.MapPost("/api/v1/console/accounts/{id}/recover",async(HttpContext c,IAntiforgery csrf,string id,RecoverAccountBody body,UserManager<LocalUser> users,SignInManager<LocalUser> signIn,AuthDb db)=>
        {
            if(!await Csrf(c,csrf) || string.IsNullOrWhiteSpace(body.ConcurrencyStamp) || !body.ResetPassword && !body.ResetMfa || string.IsNullOrWhiteSpace(body.Reason) || body.Reason.Length>500 || body.Reason.Any(char.IsControl))return Results.BadRequest();
            var actor=c.User.FindFirstValue(ClaimTypes.NameIdentifier)!;
            if(actor==id)return Results.BadRequest(new {error="Another administrator must recover your account."});
            if(!await ReauthenticateAdministrator(c,body.AdministratorPassword,body.Code,body.RecoveryCode,users,signIn,db))return Results.Unauthorized();
            await using var transaction=await db.Database.BeginTransactionAsync();
            if(!await StillAdministrator(c,db))return Results.Forbid();
            var user=await users.FindByIdAsync(id);if(user is null)return Results.NotFound();if(user.ConcurrencyStamp!=body.ConcurrencyStamp)return Results.Conflict();
            if(body.ResetPassword && (await db.DirectoryIdentities.AnyAsync(x=>x.UserId==id) || await db.UserLogins.AnyAsync(x=>x.UserId==id)))return Results.BadRequest(new {error="External passwords must be reset at the identity provider."});
            var recovery=await db.AccountRecoveries.FindAsync(id);if(recovery is null){recovery=new(){UserId=id};db.AccountRecoveries.Add(recovery);}
            string? temporaryPassword=null;
            if(body.ResetPassword)
            {
                temporaryPassword=c.RequestServices.GetRequiredService<LocalPasswordPolicy>().TemporaryPassword();
                var token=await users.GeneratePasswordResetTokenAsync(user);
                if(!(await users.ResetPasswordAsync(user,token,temporaryPassword)).Succeeded)throw new InvalidOperationException("Password recovery failed.");
                recovery.MustChangePassword=true;recovery.TemporaryPasswordExpires=DateTimeOffset.UtcNow.AddHours(24).ToUnixTimeSeconds();
            }
            if(body.ResetMfa)
            {
                if(!(await users.SetTwoFactorEnabledAsync(user,false)).Succeeded || !(await users.ResetAuthenticatorKeyAsync(user)).Succeeded)throw new InvalidOperationException("MFA recovery failed.");
                await db.RecoveryCodes.Where(x=>x.UserId==id).ExecuteDeleteAsync();recovery.MustEnrollMfa=true;
            }
            if(!(await users.ResetAccessFailedCountAsync(user)).Succeeded || !(await users.SetLockoutEndDateAsync(user,null)).Succeeded || !(await users.UpdateSecurityStampAsync(user)).Succeeded)throw new InvalidOperationException("Account recovery update failed.");
            await Log(db,actor,$"Account recovery: {id}; password={body.ResetPassword}; MFA={body.ResetMfa}; reason={body.Reason.Trim()}");
            await transaction.CommitAsync();
            return Results.Ok(new {temporaryPassword,expiresUtc=temporaryPassword==null?(DateTimeOffset?)null:DateTimeOffset.FromUnixTimeSeconds(recovery.TemporaryPasswordExpires!.Value),recovery.MustChangePassword,recovery.MustEnrollMfa});
        }).RequireAuthorization(p=>p.RequireRole("Administrator")).RequireRateLimiting("identity");
    }
}
