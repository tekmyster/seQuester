using System.Security.Claims;
using Microsoft.AspNetCore.Antiforgery;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;

namespace RansomFree.Server;

public sealed class OrganizationSecurity
{
    public int Id {get;set;}=1;
    public string MfaMode {get;set;}="Optional";
    public long Version {get;set;}
}
public sealed record SecurityPolicyBody(long ExpectedVersion,string MfaMode,string AdministratorPassword,string? Code=null,string? RecoveryCode=null);
public static partial class HumanIdentity
{
    internal static async Task<bool> RequiredMfa(AuthDb db,ClaimsPrincipal principal)
    {
        var mode=await db.OrganizationSecurity.AsNoTracking().Where(x=>x.Id==1).Select(x=>x.MfaMode).SingleOrDefaultAsync();
        return mode=="Everyone" || mode=="Administrators" && principal.IsInRole("Administrator");
    }
    public static void MapOrganizationSecurity(this WebApplication app)
    {
        var group=app.MapGroup("/api/v1/console/security-policy").RequireAuthorization(p=>p.RequireRole("Administrator"));
        group.MapGet("",async(AuthDb db)=>Results.Ok(await db.OrganizationSecurity.AsNoTracking().SingleOrDefaultAsync(x=>x.Id==1)??new()));
        group.MapPost("",async(HttpContext c,IAntiforgery csrf,SecurityPolicyBody body,UserManager<LocalUser> users,SignInManager<LocalUser> signIn,AuthDb db)=>
        {
            if(!await Csrf(c,csrf) || body.ExpectedVersion<0 || body.MfaMode is not ("Optional" or "Administrators" or "Everyone"))return Results.BadRequest();
            if(!await ReauthenticateAdministrator(c,body.AdministratorPassword,body.Code,body.RecoveryCode,users,signIn,db))return Results.Unauthorized();
            var actor=await users.GetUserAsync(c.User);if(actor==null)return Results.Unauthorized();
            if(body.MfaMode!="Optional" && !actor.TwoFactorEnabled)return Results.Conflict(new{error="Enable your own MFA before enforcing it."});
            await using var transaction=await db.Database.BeginTransactionAsync();if(!await StillAdministrator(c,db))return Results.Forbid();
            var policy=await db.OrganizationSecurity.SingleOrDefaultAsync(x=>x.Id==1);
            if((policy?.Version??0)!=body.ExpectedVersion)return Results.Conflict();
            if(policy==null){policy=new();db.OrganizationSecurity.Add(policy);}policy.MfaMode=body.MfaMode;policy.Version++;
            await Log(db,actor.Id,"Organization MFA policy changed: "+body.MfaMode);await transaction.CommitAsync();return Results.NoContent();
        }).RequireRateLimiting("identity");
    }
}
