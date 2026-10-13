using System.Security.Claims;
using Microsoft.AspNetCore.Antiforgery;
using RansomFree.Callbacks;

namespace RansomFree.Server;

public sealed record CreateCallbackBody(string Name,string Type,string? Destination=null,string Location="",string Description="",string Note="",bool EmailAlerts=false);
public sealed record TokenMechanism(string Id,string Name,string State,string Trigger);
public sealed class CallbackConfiguration
{
    public CallbackStorage? Storage {get;}
    public Uri? Origin {get;}
    public string? DnsZone {get;}
    public string? MailDomain {get;}
    public CallbackConfiguration(IConfiguration config)
    {
        if(config["Callbacks:Enabled"]!="true")return;
        if(!Uri.TryCreate(config["Callbacks:Origin"],UriKind.Absolute,out var origin) || origin.Scheme!="https" || origin.UserInfo.Length!=0 || origin.AbsolutePath!="/" || origin.Query.Length!=0 || origin.Fragment.Length!=0)throw new InvalidOperationException("Callbacks require an HTTPS receiver origin.");
        Origin=origin;DnsZone=config["Callbacks:DnsZone"]?.TrimEnd('.').ToLowerInvariant();
        if(DnsZone!=null && (Uri.CheckHostName(DnsZone)!=UriHostNameType.Dns || DnsZone.Length>190))throw new InvalidOperationException("Invalid callback DNS zone.");
        MailDomain=config["Callbacks:MailDomain"]?.ToLowerInvariant();
        if(MailDomain!=null && (Uri.CheckHostName(MailDomain)!=UriHostNameType.Dns || MailDomain.Length>190))throw new InvalidOperationException("Invalid callback mail domain.");
        Storage=new CallbackStorage(config["RF_CALLBACK_DATA"]??throw new InvalidOperationException("Set RF_CALLBACK_DATA to private callback storage."),false,new RansomFree.Persistence.DatabaseSettings(config));
    }
    public string Url(CallbackToken token)=>token.Type=="pdf" && DnsZone!=null?$"https://{token.Id}.{DnsZone}/t/{token.Id}/pixel.png":new Uri(Origin!,"t/"+token.Id+(token.Type=="mcp"?"/mcp":token.Type is "fast-redirect" or "slow-redirect"?"/open":"/pixel.png")).AbsoluteUri;
}
public sealed partial class Store
{
    public void CallbackAudit(string action,string actor,string id)
    {using var c=Open();using var t=c.BeginTransaction(System.Data.IsolationLevel.Serializable);Audit(c,t,action,actor+":"+id);t.Commit();}
}
public static class CallbackManagement
{
    public static readonly TokenMechanism[] Catalog=[
        new("docx","Microsoft Word","Implemented; untested","External image access in a compatible reader"),
        new("xlsx","Microsoft Excel","Implemented; untested","External worksheet image access in a compatible reader"),
        new("pdf","Acrobat Reader PDF","Implemented; untested","Page-open URI action; DNS resolution with configured token zone"),
        new("svg","SVG Image","Implemented; untested","External image loading"),
        new("web-image","Web image","Implemented; untested","HTTPS image request"),
        new("web-bug","Web bug","Implemented; untested","HTTPS resource request"),
        new("dns","DNS","Implemented; untested","Token hostname resolution"),
        new("qr","QR code","Implemented; untested","Scan and open a token link"),
        new("fast-redirect","Fast redirect","Implemented; untested","Follow a redirect"),new("slow-redirect","Slow redirect","Implemented; untested","Follow a two-second delayed redirect"),
        new("windows-folder","Windows Folder","Implemented; untested","DNS lookup for a remote folder icon; Windows version and policy restrictions apply"),new("fake-filesystem","Windows Fake File System","Pending","Specialized filesystem access"),new("network-folder","Network Folder","Implemented; untested","Authenticated read-only WebDAV folder access"),new("sensitive-command","Sensitive command","Pending","Audited command execution"),new("binary","Custom EXE / binary","Pending","Instrumented binary execution"),
        new("js-clone","JS cloned website","Implemented; untested","Script executes outside its approved HTTPS origin"),new("css-clone","CSS cloned website","Implemented; untested","Stylesheet resource loads without the approved origin referrer"),new("entra-login","Azure Entra ID login","Provider required","Identity provider sign-in"),new("saml-app","SAML IdP App","Provider required","Identity provider use"),new("fake-app","Fake App","Provider required","Application credential use"),
        new("aws-keys","AWS keys","Provider required","AWS credential use"),new("aws-infra","AWS Infra","Provider required","Instrumented cloud resource access"),new("azure-cert","Azure login certificate","Provider required","Azure credential use"),new("kubeconfig","Kubeconfig","Implemented; untested","Bearer credential use against a denial-only Kubernetes-compatible endpoint"),new("wireguard","WireGuard VPN","Pending","VPN handshake"),new("mcp","MCP configuration","Implemented; untested","Streamable HTTP MCP client initialization"),new("credit-card","Credit Card","Provider required","Payment network use"),
        new("mysql","MySQL","Implemented; untested","Windows MySQL LOAD_FILE DNS lookup during SQL execution; existing privileges/policy required"),new("mssql","Microsoft SQL Server","Pending","Instrumented database use"),new("svn","SVN","Pending","Repository operation"),new("email","Unique email address","Implemented; untested","Inbound STARTTLS SMTP receipt; content discarded"),new("log4shell","Log4shell","Implemented; untested","DNS-only JNDI lookup by a vulnerable/configured log processor")];
    private static readonly string[] Native=["docx","xlsx","pdf","svg","web-image","web-bug","dns","qr","fast-redirect","slow-redirect","js-clone","css-clone","mcp","windows-folder","kubeconfig","network-folder","email","mysql","log4shell"];
    public static void MapCallbacks(this WebApplication app)
    {
        var read=app.MapGroup("/api/v1/console/callbacks").RequireAuthorization(p=>p.RequireRole("Administrator","Operator","Reader"));
        read.MapGet("/catalog",(CallbackConfiguration config)=>Results.Ok(new{enabled=config.Storage!=null,dnsEnabled=config.DnsZone!=null,emailEnabled=config.MailDomain!=null,mechanisms=Catalog}));
        read.MapGet("/tokens",(CallbackConfiguration config)=>Results.Ok(config.Storage?.List()??[]));
        read.MapGet("/hits",(CallbackConfiguration config,long after=0)=>after<0?Results.BadRequest():Results.Ok(config.Storage?.Hits(after)??[]));
        read.MapGet("/delivery",(CallbackDeliveryStatus status)=>Results.Ok(new{status.Message,status.LastSentSequence}));
        var write=app.MapGroup("/api/v1/console/callbacks").RequireAuthorization(p=>p.RequireRole("Administrator"));
        async Task<bool> Csrf(HttpContext c,IAntiforgery csrf){try{await csrf.ValidateRequestAsync(c);return true;}catch(AntiforgeryValidationException){return false;}}
        write.MapPost("/tokens",async(HttpContext c,IAntiforgery csrf,CreateCallbackBody body,CallbackConfiguration config,Store audit)=>
        {
            if(!await Csrf(c,csrf) || string.IsNullOrWhiteSpace(body.Name) || body.Name.Length>160 || body.Name.Any(char.IsControl) || !Native.Contains(body.Type))return Results.BadRequest();
            if(config.Storage==null || (body.Type is "dns" or "windows-folder" or "mysql" or "log4shell") && config.DnsZone==null)return Results.Conflict(new{error="Receiver or DNS zone is not configured."});
            if(body.Type=="email" && config.MailDomain==null)return Results.Conflict(new{error="A mail domain is required."});
            if(body.Type is "docx" or "xlsx" or "pdf" or "svg")try{CanaryTemplates.Validate(new(body.Name,body.Type));}catch(ArgumentException){return Results.BadRequest();}
            string? destination=null;
            if(body.Type is "fast-redirect" or "slow-redirect" or "js-clone" or "css-clone")
            {
                if(body.Destination is not {Length:<=2048} || body.Destination.Any(char.IsControl) || !Uri.TryCreate(body.Destination,UriKind.Absolute,out var url) || url.Scheme!="https" || url.UserInfo.Length!=0 || url.Fragment.Length!=0)return Results.BadRequest();
                var clone=body.Type is "js-clone" or "css-clone";
                if(clone && (url.AbsolutePath!="/" || url.Query.Length!=0))return Results.BadRequest();
                if(!clone && url.Host.Equals(config.Origin!.Host,StringComparison.OrdinalIgnoreCase))return Results.BadRequest();
                destination=clone?url.GetLeftPart(UriPartial.Authority):url.AbsoluteUri;
            }
            else if(body.Destination!=null)return Results.BadRequest();
            CallbackDetails details;
            try{details=new CallbackDetails(body.Location,body.Description,body.Note,body.EmailAlerts).Validate();}catch(ArgumentException ex){return Results.BadRequest(new{error=ex.Message});}
            var token=config.Storage.Create(body.Name.Trim(),body.Type,destination,details);audit.CallbackAudit("Callback token created",c.User.FindFirstValue(ClaimTypes.NameIdentifier)!,token.Id);return Results.Ok(token);
        });
        write.MapPost("/tokens/{id}/details",async(HttpContext c,IAntiforgery csrf,string id,CallbackDetails body,CallbackConfiguration config,Store audit)=>
        {
            if(!await Csrf(c,csrf)||!CallbackStorage.ValidId(id))return Results.BadRequest();
            try{body=body.Validate();}catch(ArgumentException ex){return Results.BadRequest(new{error=ex.Message});}
            if(config.Storage==null)return Results.Conflict();
            if(!config.Storage.UpdateDetails(id,body))return Results.NotFound();
            audit.CallbackAudit("Callback token details updated",c.User.FindFirstValue(ClaimTypes.NameIdentifier)!,id);return Results.Ok(config.Storage.Get(id));
        });
        write.MapPost("/tokens/{id}/revoke",async(HttpContext c,IAntiforgery csrf,string id,CallbackConfiguration config,Store audit)=>
        {
            if(!await Csrf(c,csrf) || !CallbackStorage.ValidId(id))return Results.BadRequest();
            if(config.Storage==null)return Results.Conflict();var changed=config.Storage.Revoke(id);if(changed)audit.CallbackAudit("Callback token revoked",c.User.FindFirstValue(ClaimTypes.NameIdentifier)!,id);return changed?Results.NoContent():Results.NotFound();
        });
        write.MapPost("/tokens/{id}/download",async(HttpContext c,IAntiforgery csrf,string id,CallbackConfiguration config,Store audit)=>
        {
            if(!await Csrf(c,csrf) || !CallbackStorage.ValidId(id))return Results.BadRequest();
            if(config.Storage?.Get(id) is not {Revoked:false} token)return Results.NotFound();
            byte[] bytes;string name;
            if(token.Type is "docx" or "xlsx" or "pdf" or "svg")
            {var spec=new CanarySpec(token.Name,token.Type,config.Url(token));bytes=CanaryTemplates.Render(spec);name=CanaryTemplates.FileName(spec);}
            else if(token.Type is "mysql" or "log4shell")
            {if(config.DnsZone==null)return Results.Conflict(new{error="A token DNS zone is required."});bytes=DnsDiagnosticTokens.Render(token,config.DnsZone);name=token.Type=="mysql"?"canary-import.sql":"canary-log4j.txt";}
            else if(token.Type=="email")
            {if(config.MailDomain==null)return Results.Conflict(new{error="A mail domain is required."});bytes=System.Text.Encoding.UTF8.GetBytes(token.Id+"@"+config.MailDomain+"\n");name="canary-email.txt";}
            else if(token.Type=="network-folder")
            {bytes=System.Text.Encoding.UTF8.GetBytes($"Read-only WebDAV archive\nURL: {new Uri(config.Origin!,"dav/"+token.Id+"/").AbsoluteUri}\nUsername: archive\nPassword: rf_canary_{token.Id}\n\nProvision only in an approved WebDAV client, using this HTTPS URL and these decoy credentials. Never enter real domain credentials. No mapping or Windows service change is performed by this download. Client compatibility and TLS trust must be tested before deployment. Do not weaken client authentication or certificate policy.\n\nThe receiver provides a synthetic inventory.txt, no real filesystem access, uploads, locking or changes. Credential presentation records a callback. Client caching and background requests can affect alerts. Source address is not verified user/process identity. Revoke in management and remove the client mapping to retire.\n");name="canary-webdav.txt";}
            else if(token.Type=="kubeconfig")
            {bytes=KubeconfigToken.Render(token,config.Origin!);name="canary.kubeconfig.yaml";}
            else if(token.Type=="windows-folder")
            {if(config.DnsZone==null)return Results.Conflict(new{error="A token DNS zone is required."});bytes=WindowsFolderToken.Render(token,config.DnsZone);name="canary-folder.zip";}
            else if(token.Type=="qr")
            {using var generator=new QRCoder.QRCodeGenerator();using var data=generator.CreateQrCode(config.Url(token),QRCoder.QRCodeGenerator.ECCLevel.Q);using var png=new QRCoder.PngByteQRCode(data);bytes=png.GetGraphic(8);name="canary-qr.png";}
            else if(token.Type=="js-clone")
            {var approved=System.Text.Json.JsonSerializer.Serialize(token.Destination);var callback=System.Text.Json.JsonSerializer.Serialize(config.Url(token));bytes=System.Text.Encoding.UTF8.GetBytes($"// Deploy only on the approved origin. Does not collect page contents, form values, or URL parameters.\n(()=>{{if(location.origin!=={approved}){{const image=new Image();image.referrerPolicy='no-referrer';image.src={callback};}}}})();\n");name="canary-clone.js";}
            else if(token.Type=="css-clone")
            {var callback=System.Text.Json.JsonSerializer.Serialize(config.Url(token));bytes=System.Text.Encoding.UTF8.GetBytes($"/* A missing referrer can create alerts even on the approved site. Review existing pseudo-element styling before deployment. */\nbody::after {{content:'';position:fixed;width:1px;height:1px;pointer-events:none;background-image:url({callback});}}\n");name="canary-clone.css";}
            else if(token.Type=="mcp")
            {bytes=System.Text.Json.JsonSerializer.SerializeToUtf8Bytes(new{mcpServers=new Dictionary<string,object>{{"reference",new{type="http",url=config.Url(token)}}}},new System.Text.Json.JsonSerializerOptions{WriteIndented=true});name="canary.mcp.json";}
            else {bytes=System.Text.Encoding.UTF8.GetBytes(token.Type=="dns"?$"{token.Id}.{config.DnsZone}\n":config.Url(token)+"\n");name="canary-"+token.Type+".txt";}
            audit.CallbackAudit("Callback token artifact downloaded",c.User.FindFirstValue(ClaimTypes.NameIdentifier)!,id);return Results.File(bytes,"application/octet-stream",name);
        });
    }
}
