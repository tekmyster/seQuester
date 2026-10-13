using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Security.Cryptography;
using System.Text.Json;
using System.Buffers.Binary;

internal static class IdentityChecks
{
    public static async Task Run(Uri origin,string admin,Action<bool,string> check)
    {
        using var client=new HttpClient(new HttpClientHandler {CookieContainer=new CookieContainer(),AllowAutoRedirect=false}) {BaseAddress=origin};
        const string password="QA-only-long-passphrase-904!";
        using(var shell=await client.GetAsync("/"))
        {
            var html=await shell.Content.ReadAsStringAsync();check(shell.IsSuccessStatusCode && html.Contains("login-form"),"packaged management shell served");
            check(html.Contains("Client-reported protection")&&html.Contains("<table aria-label=\"Sensors\">")&&html.Contains("<th scope=\"col\" aria-sort=\"none\"><button class=\"history-sort\" data-sort=\"host\">Host</button></th>")&&new[]{"path\">File","user\">User","process\">Process","pid\">PID"}.All(value=>html.Contains(value)),"management shell presents client protection and accessible sortable alert evidence columns without inventory gating");
            var fleetStart=html.IndexOf("<section id=\"fleet\"",StringComparison.Ordinal);var fleetEnd=html.IndexOf("<section id=\"alerts\"",fleetStart,StringComparison.Ordinal);var fleetView=html[fleetStart..fleetEnd];
            var fleetMetricIds=new[]{"fleet-total","fleet-online","fleet-stale","fleet-revoked"};
            check(!fleetView.Contains("class=\"metrics\"")&&!fleetView.Contains("Loaded endpoints")&&fleetMetricIds.All(id=>!fleetView.Contains($"id=\"{id}\"")),"Sensors presents per-client health without endpoint-count KPI tiles");
            check(shell.Headers.GetValues("Content-Security-Policy").Single().Contains("frame-ancestors 'none'"),"console framing/script policy present");
        }
        using(var script=await client.GetAsync("/console.js")){var javascript=await script.Content.ReadAsStringAsync();check(script.IsSuccessStatusCode,"packaged console script served");var forbidden=new[]{"fleet-total","fleet-online","fleet-stale","fleet-revoked","fleet.length","live.length","online.length"};check(forbidden.All(value=>!javascript.Contains(value)),"Sensors script has no inventory-derived endpoint-count KPI expression or binding");}
        using(var style=await client.GetAsync("/console.css"))check(style.IsSuccessStatusCode,"packaged console stylesheet served");
        async Task<HttpResponseMessage> Post(string path,object body,string? csrf=null,bool bootstrap=false)
        {
            using var request=new HttpRequestMessage(HttpMethod.Post,path) {Content=JsonContent.Create(body)};
            if(csrf!=null)request.Headers.Add("X-CSRF",csrf);
            if(bootstrap)request.Headers.Authorization=new AuthenticationHeaderValue("Bearer",admin);
            return await client.SendAsync(request);
        }
        async Task<string> Csrf()
        {
            using var response=await client.GetAsync("/api/v1/auth/csrf");response.EnsureSuccessStatusCode();
            using var json=await response.Content.ReadFromJsonAsync<JsonDocument>();return json!.RootElement.GetProperty("token").GetString()!;
        }
        void Status(HttpResponseMessage response,HttpStatusCode status,string text){using(response)check(response.StatusCode==status,text+" (HTTP "+(int)response.StatusCode+")");}
        Status(await Post("/api/v1/admin/users",new {userName="local-admin",password,role="Administrator"}),HttpStatusCode.Unauthorized,"public registration denied");
        Status(await Post("/api/v1/admin/users",new {userName="local-admin",password,role="Administrator"},bootstrap:true),HttpStatusCode.OK,"local administrator provisioned");
        Status(await Post("/api/v1/admin/users",new {userName="short-password",password="short",role="Reader"},bootstrap:true),HttpStatusCode.BadRequest,"weak account password refused");
        Status(await Post("/api/v1/auth/login",new {userName="local-admin",password}),HttpStatusCode.BadRequest,"login requires CSRF token");
        Status(await Post("/api/v1/auth/login",new {userName="local-admin",password="incorrect"},await Csrf()),HttpStatusCode.Unauthorized,"incorrect password denied");
        Status(await Post("/api/v1/auth/login",new {userName="local-admin",password},await Csrf()),HttpStatusCode.NoContent,"local password login creates session");
        using(var me=await client.GetAsync("/api/v1/auth/me"))
        {
            me.EnsureSuccessStatusCode();using var json=await me.Content.ReadFromJsonAsync<JsonDocument>();
            check(json!.RootElement.GetProperty("roles").EnumerateArray().Any(x=>x.GetString()=="Administrator"),"session has persisted administrator role");
        }
        Status(await Post("/api/v1/auth/mfa/setup",new {password}),HttpStatusCode.BadRequest,"MFA setup requires CSRF token");
        using var setup=await Post("/api/v1/auth/mfa/setup",new {password},await Csrf());setup.EnsureSuccessStatusCode();
        using var setupJson=await setup.Content.ReadFromJsonAsync<JsonDocument>();var secret=setupJson!.RootElement.GetProperty("key").GetString()!;
        check(secret.Length>=16,"authenticator secret provisioned after password reauthentication");
        var activation=Totp(secret,0);
        using var enabled=await Post("/api/v1/auth/mfa/enable",new {password,code=activation},await Csrf());enabled.EnsureSuccessStatusCode();
        using var recoveryJson=await enabled.Content.ReadFromJsonAsync<JsonDocument>();
        var recovery=recoveryJson!.RootElement.GetProperty("recoveryCodes").EnumerateArray().Select(x=>x.GetString()!).ToArray();
        check(recovery.Length==10 && recovery.Distinct().Count()==10,"TOTP proof enables MFA and issues unique recovery codes");
        Status(await client.GetAsync("/api/v1/auth/me"),HttpStatusCode.Unauthorized,"MFA activation ends existing session");
        Status(await Post("/api/v1/auth/login",new {userName="local-admin",password},await Csrf()),HttpStatusCode.Unauthorized,"password alone cannot bypass MFA");
        Status(await Post("/api/v1/auth/login",new {userName="local-admin",password,code=activation},await Csrf()),HttpStatusCode.Unauthorized,"consumed MFA activation code cannot be replayed");
        Status(await Post("/api/v1/auth/login",new {userName="local-admin",password,code=Totp(secret,1)},await Csrf()),HttpStatusCode.NoContent,"fresh TOTP completes MFA login");
        Status(await client.GetAsync("/api/v1/console/endpoints"),HttpStatusCode.OK,"human administrator can read management inventory");
        Status(await Post("/api/v1/console/enrollment-codes",new {}),HttpStatusCode.BadRequest,"cookie-authenticated administration requires CSRF");
        Status(await Post("/api/v1/console/enrollment-codes",new {},await Csrf()),HttpStatusCode.OK,"human administrator can issue enrollment code");
        Status(await Post("/api/v1/auth/logout",new {},await Csrf()),HttpStatusCode.NoContent,"authenticated logout succeeds");
        Status(await client.GetAsync("/api/v1/auth/me"),HttpStatusCode.Unauthorized,"logout removes browser access");
        Status(await Post("/api/v1/auth/login",new {userName="local-admin",password,recoveryCode=recovery[0]},await Csrf()),HttpStatusCode.NoContent,"recovery code permits MFA recovery login");
        Status(await Post("/api/v1/auth/logout",new {},await Csrf()),HttpStatusCode.NoContent,"recovery session logs out");
        Status(await Post("/api/v1/auth/login",new {userName="local-admin",password,recoveryCode=recovery[0]},await Csrf()),HttpStatusCode.Unauthorized,"recovery code cannot be reused");
        Status(await Post("/api/v1/auth/login",new {userName="local-admin",password,recoveryCode=recovery[1]},await Csrf()),HttpStatusCode.NoContent,"unused recovery code still works");
        Status(await Post("/api/v1/auth/mfa/disable",new {password,recoveryCode=recovery[2]},await Csrf()),HttpStatusCode.NoContent,"MFA disable requires password and unused second factor");
        Status(await Post("/api/v1/auth/login",new {userName="local-admin",password},await Csrf()),HttpStatusCode.NoContent,"optional MFA can be disabled after proof");
        Status(await client.GetAsync("/api/v1/console/identity-audit"),HttpStatusCode.OK,"administrator can read identity audit");
        Status(await Post("/api/v1/auth/logout",new {},await Csrf()),HttpStatusCode.NoContent,"administrator session closed");
        Status(await Post("/api/v1/admin/users",new {userName="reader-test",password,role="Reader"},bootstrap:true),HttpStatusCode.OK,"reader account provisioned");
        Status(await Post("/api/v1/auth/login",new {userName="reader-test",password},await Csrf()),HttpStatusCode.NoContent,"reader signs in");
        Status(await client.GetAsync("/api/v1/console/endpoints"),HttpStatusCode.OK,"reader can view inventory");
        Status(await Post("/api/v1/console/enrollment-codes",new {},await Csrf()),HttpStatusCode.Forbidden,"reader cannot issue enrollment codes");
        Status(await client.GetAsync("/api/v1/console/identity-audit"),HttpStatusCode.Forbidden,"reader cannot access identity administration audit");
        Status(await Post("/api/v1/auth/logout",new {},await Csrf()),HttpStatusCode.NoContent,"reader session closed");
        Status(await Post("/api/v1/admin/users",new {userName="lockout-test",password,role="Reader"},bootstrap:true),HttpStatusCode.OK,"lockout test account created");
        for(var i=0;i<5;i++)Status(await Post("/api/v1/auth/login",new {userName="lockout-test",password="wrong"},await Csrf()),HttpStatusCode.Unauthorized,"failed password attempt denied");
        Status(await Post("/api/v1/auth/login",new {userName="lockout-test",password},await Csrf()),HttpStatusCode.Unauthorized,"locked account rejects correct password");
    }
    private static string Totp(string secret,int offset)
    {
        const string alphabet="ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";var bytes=new List<byte>();int bits=0,buffer=0;
        foreach(var c in secret){buffer=(buffer<<5)|alphabet.IndexOf(char.ToUpperInvariant(c));bits+=5;if(bits>=8){bits-=8;bytes.Add((byte)(buffer>>bits));}}
        Span<byte> time=stackalloc byte[8];BinaryPrimitives.WriteInt64BigEndian(time,DateTimeOffset.UtcNow.ToUnixTimeSeconds()/30+offset);
        var digest=HMACSHA1.HashData(bytes.ToArray(),time);var start=digest[^1]&15;var value=BinaryPrimitives.ReadInt32BigEndian(digest.AsSpan(start,4))&0x7fffffff;
        return (value%1_000_000).ToString("D6");
    }
}
