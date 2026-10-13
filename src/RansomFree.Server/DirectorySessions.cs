using System.DirectoryServices.Protocols;
using System.Net;
using System.Security.Claims;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Caching.Memory;

namespace RansomFree.Server;

public sealed record DirectoryRoleRule(string GroupDn,string Role);
internal sealed record DirectorySessionState(bool Active,string[] AllowedRoles);

internal sealed class DirectorySessionValidator : IDisposable
{
    private readonly string host,searchBase,bindUser,bindPassword;
    private readonly int port,seconds;
    private readonly DirectoryRoleRule[] rules;
    private readonly MemoryCache cache=new(new MemoryCacheOptions{SizeLimit=10000});
    private readonly SemaphoreSlim slots=new(4);
    public bool Enabled {get;}
    public bool RoleRestrictions=>rules.Length>0;
    public int MaximumCacheSeconds=>seconds;
    public DirectorySessionValidator(IConfiguration config)
    {
        Enabled=config.GetValue<bool>("Directory:RevalidateSessions");
        host=config["Directory:Host"]??"";searchBase=config["Directory:SearchBase"]??"";port=config.GetValue("Directory:Port",636);
        bindUser=config["Directory:SessionBindUser"]??"";bindPassword=config["Directory:SessionBindPassword"]??"";
        seconds=config.GetValue("Directory:SessionCacheSeconds",60);
        rules=config.GetSection("Directory:RoleRestrictions").Get<DirectoryRoleRule[]>()??[];
        if(rules.Length>32 || rules.Any(r=>r is null || string.IsNullOrWhiteSpace(r.GroupDn)||r.GroupDn.Length>2048||r.GroupDn.Any(char.IsControl)||r.Role is not ("Administrator" or "Operator" or "Reader")))throw new InvalidOperationException("Invalid directory role restrictions.");
        if(rules.Length>0&&!Enabled)throw new InvalidOperationException("Directory role restrictions require session revalidation.");
        if(Enabled && (!config.GetValue<bool>("Directory:Enabled")||Uri.CheckHostName(host)!=UriHostNameType.Dns||port is <1 or >65535||string.IsNullOrWhiteSpace(searchBase)||searchBase.Length>2048||searchBase.Any(char.IsControl)||string.IsNullOrWhiteSpace(bindUser)||bindUser.Length>254||bindUser.Any(char.IsControl)||bindPassword.Length is <1 or >256||seconds is <1 or >300))throw new InvalidOperationException("Directory session revalidation requires LDAPS and protected read-only bind configuration.");
    }
    public async Task<DirectorySessionState> ValidateAsync(DirectoryIdentity identity,CancellationToken ct)
    {
        if(!Enabled)throw new InvalidOperationException("Directory session validation is disabled.");
        if(!Guid.TryParseExact(identity.ObjectId,"N",out var guid))return new(false,[]);
        var key=identity.ObjectId+":"+identity.UserPrincipalName;
        if(cache.TryGetValue(key,out DirectorySessionState? existing))return existing!;
        if(!await slots.WaitAsync(TimeSpan.FromSeconds(2),ct))throw new DirectoryUnavailableException();
        try
        {
            if(cache.TryGetValue(key,out existing))return existing!;
            var state=await Task.Run(()=>Read(identity,guid),ct);
            cache.Set(key,state,new MemoryCacheEntryOptions{AbsoluteExpirationRelativeToNow=TimeSpan.FromSeconds(seconds),Size=1});
            return state;
        }
        finally{slots.Release();}
    }
    private DirectorySessionState Read(DirectoryIdentity identity,Guid guid)
    {
        try
        {
            var elapsed=System.Diagnostics.Stopwatch.StartNew();
            using var connection=new LdapConnection(new LdapDirectoryIdentifier(host,port),new NetworkCredential(bindUser,bindPassword),AuthType.Basic);
            connection.AutoBind=false;connection.Timeout=TimeSpan.FromSeconds(10);connection.SessionOptions.ProtocolVersion=3;
            connection.SessionOptions.SecureSocketLayer=true;connection.SessionOptions.ReferralChasing=ReferralChasingOptions.None;connection.Bind();
            var objectFilter="(objectGUID="+string.Concat(guid.ToByteArray().Select(b=>"\\"+b.ToString("x2")))+")";
            var request=new SearchRequest(searchBase,"(&(objectClass=user)"+objectFilter+")",SearchScope.Subtree,"userPrincipalName","userAccountControl","accountExpires","msDS-User-Account-Control-Computed"){SizeLimit=2,TimeLimit=TimeSpan.FromSeconds(10)};
            var response=(SearchResponse)connection.SendRequest(request);if(response.Entries.Count!=1)return new(false,[]);
            var entry=response.Entries[0];
            string? Value(string attribute)=>entry.Attributes[attribute] is {Count:1} values?values[0] switch {byte[] bytes=>System.Text.Encoding.UTF8.GetString(bytes),{} value=>value.ToString(),_=>null}:null;
            if(!string.Equals(Value("userPrincipalName"),identity.UserPrincipalName,StringComparison.OrdinalIgnoreCase)||!long.TryParse(Value("userAccountControl"),out var flags)||(flags&2)!=0)return new(false,[]);
            // Fail closed if the bind identity cannot read computed account status or expiry.
            if(!long.TryParse(Value("msDS-User-Account-Control-Computed"),out var computed)||(computed&0x800010)!=0)return new(false,[]);
            if(!long.TryParse(Value("accountExpires"),out var expires))return new(false,[]);
            if(expires!=0&&expires!=long.MaxValue&&expires<=DateTime.UtcNow.ToFileTimeUtc())return new(false,[]);
            var allowed=new HashSet<string>(StringComparer.Ordinal);
            foreach(var rule in rules)
            {
                if(elapsed.Elapsed>TimeSpan.FromSeconds(20))throw new DirectoryUnavailableException();
                var membership=new SearchRequest(entry.DistinguishedName,"(&(objectClass=user)(memberOf:1.2.840.113556.1.4.1941:="+Escape(rule.GroupDn)+"))",SearchScope.Base,"objectGUID"){SizeLimit=1,TimeLimit=TimeSpan.FromSeconds(10)};
                if(((SearchResponse)connection.SendRequest(membership)).Entries.Count==1)allowed.Add(rule.Role);
            }
            return new(true,allowed.ToArray());
        }
        catch(Exception ex) when(ex is LdapException or DirectoryOperationException or PlatformNotSupportedException or DllNotFoundException){throw new DirectoryUnavailableException();}
    }
    private static string Escape(string value)=>value.Replace("\\","\\5c").Replace("*","\\2a").Replace("(","\\28").Replace(")","\\29").Replace("\0","\\00");
    public void Dispose(){cache.Dispose();slots.Dispose();}
}

internal static class DirectorySessions
{
    public static void UseDirectorySessions(this WebApplication app)
    {
        app.Use(async(context,next)=>
        {
            var validator=context.RequestServices.GetRequiredService<DirectorySessionValidator>();
            // Preserve logout even during an outage; no management data is exposed by it.
            if(!validator.Enabled||context.User.Identity?.IsAuthenticated!=true||context.Request.Path=="/api/v1/auth/logout"){await next(context);return;}
            var id=context.User.FindFirstValue(ClaimTypes.NameIdentifier);var db=context.RequestServices.GetRequiredService<AuthDb>();
            var identity=await db.DirectoryIdentities.AsNoTracking().SingleOrDefaultAsync(x=>x.UserId==id,context.RequestAborted);
            if(identity==null){await next(context);return;}
            var state=await validator.ValidateAsync(identity,context.RequestAborted);
            if(!state.Active)
            {
                await context.SignOutAsync(IdentityConstants.ApplicationScheme);context.Response.StatusCode=401;return;
            }
            if(validator.RoleRestrictions)
            {
                // Directory membership can only reduce explicitly provisioned local roles.
                // It never creates an account or grants a role absent from local assignment.
                foreach(var claims in context.User.Identities)
                    foreach(var role in claims.FindAll(claims.RoleClaimType).ToArray())
                        if(!state.AllowedRoles.Contains(role.Value,StringComparer.Ordinal))claims.RemoveClaim(role);
                if(!context.User.IsInRole("Administrator")&&!context.User.IsInRole("Operator")&&!context.User.IsInRole("Reader"))
                {context.Response.StatusCode=403;return;}
            }
            await next(context);
        });
    }
}
