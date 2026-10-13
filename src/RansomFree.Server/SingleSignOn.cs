using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.AspNetCore.Antiforgery;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;

namespace RansomFree.Server;

public sealed record SsoProvider(string Id,string Name,string Authority,string Issuer,string ClientId,string ClientSecret,bool EndSessionEnabled=false);
public sealed record SsoCompleteBody(string? Code=null,string? RecoveryCode=null);
public sealed record NewSsoAccountBody(string UserName,string Role,string Provider,string Subject,string AdministratorPassword,string? Code=null,string? RecoveryCode=null);
public sealed class SsoConfiguration
{
    public IReadOnlyList<SsoProvider> Providers {get;}
    public SsoConfiguration(IConfiguration config)
    {
        var providers=new List<SsoProvider>();
        foreach(var entry in config.GetSection("Sso:Providers").GetChildren())
        {
            if(entry["Enabled"]!="true")continue;
            var provider=new SsoProvider(entry["Id"]??"",entry["Name"]??"",entry["Authority"]??"",entry["Issuer"]??"",entry["ClientId"]??"",entry["ClientSecret"]??"",entry["EndSessionEnabled"]=="true");
            bool Https(string value)=>Uri.TryCreate(value,UriKind.Absolute,out var uri) && uri.Scheme=="https" && uri.UserInfo.Length==0 && uri.Query.Length==0 && uri.Fragment.Length==0;
            if(providers.Count>=8 || provider.Id.Length is <1 or >32 || provider.Id.Any(c=>!char.IsAsciiLetterOrDigit(c)&&c!='-') || providers.Any(x=>x.Id.Equals(provider.Id,StringComparison.OrdinalIgnoreCase)) ||
                string.IsNullOrWhiteSpace(provider.Name) || provider.Name.Length>60 || provider.Name.Any(char.IsControl) || !Https(provider.Authority) || !Https(provider.Issuer) ||
                string.IsNullOrWhiteSpace(provider.ClientId) || string.IsNullOrWhiteSpace(provider.ClientSecret))throw new InvalidOperationException("Invalid SSO provider configuration.");
            if(provider.Authority.Contains("/common",StringComparison.OrdinalIgnoreCase) || provider.Authority.Contains("/organizations",StringComparison.OrdinalIgnoreCase))throw new InvalidOperationException("Use a tenant-specific Entra authority and issuer.");
            providers.Add(provider);
        }
        Providers=providers;
    }
    public static string LoginKey(SsoProvider provider,string subject)=>Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(provider.Issuer+"\0"+subject)));
}
public static partial class HumanIdentity
{
    public static void AddSingleSignOn(this WebApplicationBuilder builder)
    {
        var config=new SsoConfiguration(builder.Configuration);builder.Services.AddSingleton(config);
        foreach(var provider in config.Providers)
        {
            builder.Services.AddAuthentication().AddOpenIdConnect("sso-"+provider.Id,provider.Name,options=>
            {
                options.SignInScheme=IdentityConstants.ExternalScheme;options.Authority=provider.Authority;options.ClientId=provider.ClientId;options.ClientSecret=provider.ClientSecret;
                options.CallbackPath="/signin-oidc/"+provider.Id;options.ResponseType="code";options.UsePkce=true;options.RequireHttpsMetadata=true;options.SaveTokens=false;options.GetClaimsFromUserInfoEndpoint=false;options.MapInboundClaims=false;
                options.SignOutScheme=IdentityConstants.ApplicationScheme;
                options.SignedOutCallbackPath="/signout-callback-oidc/"+provider.Id;
                options.RemoteSignOutPath="/signout-oidc/"+provider.Id;
                // Provider-initiated logout requires separate session-token validation work.
                options.Events.OnRemoteSignOut=context=>{context.HandleResponse();context.Response.StatusCode=404;return Task.CompletedTask;};
                options.Events.OnRedirectToIdentityProviderForSignOut=context=>
                {
                    if(!provider.EndSessionEnabled || !Uri.TryCreate(context.ProtocolMessage.IssuerAddress,UriKind.Absolute,out var destination)||destination.Scheme!="https"||destination.UserInfo.Length!=0)
                    {context.HandleResponse();context.Response.Redirect("/?sso=logout-unavailable");return Task.CompletedTask;}
                    context.ProtocolMessage.ClientId=provider.ClientId;return Task.CompletedTask;
                };
                options.Scope.Clear();options.Scope.Add("openid");options.Scope.Add("profile");
                options.ClaimActions.Clear();
                options.TokenValidationParameters.ValidateIssuer=true;options.TokenValidationParameters.ValidIssuer=provider.Issuer;options.TokenValidationParameters.ValidateAudience=true;options.TokenValidationParameters.ValidAudience=provider.ClientId;
                options.TokenValidationParameters.ClockSkew=TimeSpan.FromMinutes(1);
                options.Events.OnRedirectToIdentityProvider=context=>{context.ProtocolMessage.Prompt="login";context.ProtocolMessage.MaxAge="0";return Task.CompletedTask;};
                options.Events.OnTokenValidated=context=>
                {
                    var subject=context.Principal?.FindFirstValue("sub");var authTime=context.Principal?.FindFirstValue("auth_time");var now=DateTimeOffset.UtcNow.ToUnixTimeSeconds();
                    if(context.SecurityToken.Issuer!=provider.Issuer || string.IsNullOrWhiteSpace(subject) || subject.Length>256 || !long.TryParse(authTime,out var occurred) || occurred<now-300 || occurred>now+60)context.Fail("A fresh, supported identity-provider authentication is required.");
                    return Task.CompletedTask;
                };
                options.Events.OnRemoteFailure=context=>{context.HandleResponse();context.Response.Redirect("/?sso=failed");return Task.CompletedTask;};
            });
        }
        builder.Services.Configure<Microsoft.AspNetCore.Authentication.Cookies.CookieAuthenticationOptions>(IdentityConstants.ExternalScheme,o=>{o.Cookie.HttpOnly=true;o.Cookie.SecurePolicy=CookieSecurePolicy.Always;o.ExpireTimeSpan=TimeSpan.FromMinutes(5);o.SlidingExpiration=false;});
        builder.Services.Configure<SecurityStampValidatorOptions>(o=>o.OnRefreshingPrincipal=context=>
        {
            if(context.NewPrincipal?.Identity is ClaimsIdentity identity)
                foreach(var name in new[]{"rf:sso_at","rf:sso_provider"})if(context.CurrentPrincipal?.FindFirst(name) is {} claim)identity.AddClaim(claim);
            return Task.CompletedTask;
        });
    }
    private static async Task<(SsoProvider Provider,string Subject,ClaimsPrincipal Principal)?> PendingSso(HttpContext c,SsoConfiguration config)
    {
        var external=await c.AuthenticateAsync(IdentityConstants.ExternalScheme);
        if(!external.Succeeded || external.Principal==null || external.Properties==null || !external.Properties.Items.TryGetValue("LoginProvider",out var scheme) || scheme==null)return null;
        var provider=config.Providers.SingleOrDefault(p=>"sso-"+p.Id==scheme);var subject=external.Principal.FindFirstValue("sub");
        if(provider==null || string.IsNullOrWhiteSpace(subject) || subject.Length>256 || external.Principal.FindFirstValue("iss")!=provider.Issuer)return null;
        return (provider,subject,external.Principal);
    }
    public static void MapSingleSignOn(this WebApplication app)
    {
        app.MapGet("/api/v1/auth/sso/providers",(SsoConfiguration config)=>Results.Ok(config.Providers.Select(p=>new{p.Id,p.Name})));
        app.MapGet("/api/v1/auth/sso/logout-option",(HttpContext c,SsoConfiguration config)=>
        {
            var provider=config.Providers.SingleOrDefault(p=>p.Id==c.User.FindFirstValue("rf:sso_provider"));
            return Results.Ok(new{enabled=provider?.EndSessionEnabled??false,name=provider?.Name});
        }).RequireAuthorization();
        app.MapPost("/api/v1/auth/sso/logout",async(HttpContext c,IAntiforgery csrf,SsoConfiguration config,SignInManager<LocalUser> signIn,AuthDb db)=>
        {
            if(!await Csrf(c,csrf))return Results.BadRequest();
            var provider=config.Providers.SingleOrDefault(p=>p.Id==c.User.FindFirstValue("rf:sso_provider"));
            if(provider?.EndSessionEnabled!=true)return Results.Conflict(new{error="Provider sign-out is not configured. Local sign-out remains available."});
            await Log(db,c.User.FindFirstValue(ClaimTypes.NameIdentifier)!,"Provider sign-out requested: "+provider.Id);
            await signIn.SignOutAsync();await c.SignOutAsync(IdentityConstants.ExternalScheme);
            return Results.SignOut(new AuthenticationProperties{RedirectUri="/?sso=signedout"},["sso-"+provider.Id]);
        }).RequireAuthorization().RequireRateLimiting("identity");
        app.MapPost("/api/v1/auth/sso/start/{id}",async(string id,HttpContext c,IAntiforgery csrf,SsoConfiguration config,SignInManager<LocalUser> signIn)=>
        {
            if(!await Csrf(c,csrf))return Results.BadRequest();if(!c.Request.IsHttps)return Results.BadRequest();
            var provider=config.Providers.SingleOrDefault(p=>p.Id==id);if(provider==null)return Results.NotFound();
            await c.SignOutAsync(IdentityConstants.ApplicationScheme);
            await c.SignOutAsync(IdentityConstants.ExternalScheme);
            return Results.Challenge(signIn.ConfigureExternalAuthenticationProperties("sso-"+provider.Id,"/?sso=pending"),["sso-"+provider.Id]);
        }).RequireRateLimiting("identity");
        app.MapGet("/api/v1/auth/sso/pending",async(HttpContext c,SsoConfiguration config,UserManager<LocalUser> users)=>
        {
            var pending=await PendingSso(c,config);if(pending==null)return Results.Unauthorized();var info=pending.Value;
            var user=await users.FindByLoginAsync("sso-"+info.Provider.Id,SsoConfiguration.LoginKey(info.Provider,info.Subject));
            return Results.Ok(new{provider=info.Provider.Id,subject=info.Subject,linked=user!=null,mfaRequired=user!=null && await users.GetTwoFactorEnabledAsync(user)});
        }).RequireRateLimiting("identity");
        app.MapPost("/api/v1/auth/sso/complete",async(HttpContext c,IAntiforgery csrf,SsoCompleteBody body,SsoConfiguration config,UserManager<LocalUser> users,SignInManager<LocalUser> signIn,AuthDb db)=>
        {
            if(!await Csrf(c,csrf))return Results.BadRequest();var pending=await PendingSso(c,config);if(pending==null)return Results.Unauthorized();var info=pending.Value;
            var user=await users.FindByLoginAsync("sso-"+info.Provider.Id,SsoConfiguration.LoginKey(info.Provider,info.Subject));
            if(user==null || await db.AccountControls.AnyAsync(x=>x.UserId==user.Id && x.Disabled) || await users.IsLockedOutAsync(user))return Results.Unauthorized();
            if(await users.GetTwoFactorEnabledAsync(user) && !await MfaProof(user,body.Code,body.RecoveryCode,users,db)){await users.AccessFailedAsync(user);await Log(db,user.Id,"SSO second factor denied");return Results.Unauthorized();}
            var authTime=info.Principal.FindFirstValue("auth_time");var now=DateTimeOffset.UtcNow.ToUnixTimeSeconds();if(!long.TryParse(authTime,out var occurred) || occurred<now-300 || occurred>now+60)return Results.Unauthorized();
            await users.ResetAccessFailedCountAsync(user);await Log(db,user.Id,"SSO sign-in: "+info.Provider.Id);
            await signIn.SignInWithClaimsAsync(user,false,[new Claim("rf:sso_at",authTime!),new Claim("rf:sso_provider",info.Provider.Id)]);
            await c.SignOutAsync(IdentityConstants.ExternalScheme);return Results.NoContent();
        }).RequireRateLimiting("identity");
        app.MapPost("/api/v1/console/accounts/sso",async(HttpContext c,IAntiforgery csrf,NewSsoAccountBody body,SsoConfiguration config,UserManager<LocalUser> users,SignInManager<LocalUser> signIn,AuthDb db)=>
        {
            if(!await Csrf(c,csrf) || string.IsNullOrWhiteSpace(body.UserName) || body.UserName.Length>100 || body.Role is not ("Administrator" or "Operator" or "Reader") || string.IsNullOrWhiteSpace(body.Subject) || body.Subject.Length>256 || body.Subject.Any(char.IsControl))return Results.BadRequest();
            var provider=config.Providers.SingleOrDefault(x=>x.Id==body.Provider);if(provider==null)return Results.BadRequest();
            if(!await ReauthenticateAdministrator(c,body.AdministratorPassword,body.Code,body.RecoveryCode,users,signIn,db))return Results.Unauthorized();
            await using var transaction=await db.Database.BeginTransactionAsync();if(!await StillAdministrator(c,db))return Results.Forbid();
            var user=new LocalUser{UserName=body.UserName.Trim(),LockoutEnabled=true};if(!(await users.CreateAsync(user)).Succeeded)return Results.BadRequest();
            if(!(await users.AddLoginAsync(user,new UserLoginInfo("sso-"+provider.Id,SsoConfiguration.LoginKey(provider,body.Subject),provider.Name))).Succeeded)return Results.Conflict();
            if(!(await users.AddToRoleAsync(user,body.Role)).Succeeded)throw new InvalidOperationException("Role assignment failed.");
            await Log(db,c.User.FindFirstValue(ClaimTypes.NameIdentifier)!,"SSO account provisioned: "+user.Id+" / "+provider.Id);await transaction.CommitAsync();return Results.Ok(new{user.Id,user.UserName});
        }).RequireAuthorization(p=>p.RequireRole("Administrator")).RequireRateLimiting("identity");
    }
}
