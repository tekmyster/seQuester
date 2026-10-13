using System.DirectoryServices.Protocols;
using System.Net;
using System.Text;

namespace RansomFree.Server;

public sealed class DirectoryIdentity
{
    public string UserId {get;set;}="";
    public string ObjectId {get;set;}="";
    public string UserPrincipalName {get;set;}="";
}
public sealed class AccountControl
{
    public string UserId {get;set;}="";
    public bool Disabled {get;set;}
}
public sealed class DirectoryUnavailableException : Exception;
public sealed class DirectoryAuthenticator
{
    private readonly string host,searchBase,domain;
    private readonly int port;
    public bool Enabled {get;}
    private readonly SemaphoreSlim slots=new(4);
    public DirectoryAuthenticator(IConfiguration config)
    {
        Enabled=config.GetValue<bool>("Directory:Enabled");host=config["Directory:Host"]??"";searchBase=config["Directory:SearchBase"]??"";domain=config["Directory:Domain"]??"cptnyc.com";port=config.GetValue("Directory:Port",636);
        if(Enabled && (Uri.CheckHostName(host)!=UriHostNameType.Dns || host.Any(char.IsWhiteSpace) || port is <1 or >65535 || string.IsNullOrWhiteSpace(searchBase) || searchBase.Length>2048 || searchBase.Any(char.IsControl) || Uri.CheckHostName(domain)!=UriHostNameType.Dns))throw new InvalidOperationException("Directory authentication requires a valid LDAPS hostname, port, search base, and UPN domain.");
    }
    public bool ValidPrincipal(string? name)=>name is {Length:>0 and <=254} && !name.Any(char.IsControl) && name.EndsWith("@"+domain,StringComparison.OrdinalIgnoreCase) && name.Count(ch=>ch=='@')==1 && name.IndexOf('@')>0;
    public async Task<bool> VerifyAsync(DirectoryIdentity identity,string password,CancellationToken ct)
    {
        if(!Enabled)throw new DirectoryUnavailableException();
        if(string.IsNullOrEmpty(password) || password.Length>256 || !ValidPrincipal(identity.UserPrincipalName) || !Guid.TryParseExact(identity.ObjectId,"N",out _))return false;
        if(!await slots.WaitAsync(TimeSpan.FromSeconds(2),ct))throw new DirectoryUnavailableException();
        try{return await Task.Run(()=>Verify(identity,password),ct);}
        finally{slots.Release();}
    }
    private bool Verify(DirectoryIdentity identity,string password)
    {
        try
        {
            using var connection=new LdapConnection(new LdapDirectoryIdentifier(host,port),new NetworkCredential(identity.UserPrincipalName,password),AuthType.Basic);
            connection.AutoBind=false;connection.Timeout=TimeSpan.FromSeconds(10);
            connection.SessionOptions.ProtocolVersion=3;connection.SessionOptions.SecureSocketLayer=true;
            connection.SessionOptions.ReferralChasing=ReferralChasingOptions.None;
            // Platform certificate validation is mandatory. No permissive validation callback or plaintext fallback.
            connection.Bind();
            var request=new SearchRequest(searchBase,"(&(objectClass=user)(userPrincipalName="+Escape(identity.UserPrincipalName)+"))",SearchScope.Subtree,"objectGUID","userAccountControl") {SizeLimit=2,TimeLimit=TimeSpan.FromSeconds(10)};
            var response=(SearchResponse)connection.SendRequest(request);
            if(response.Entries.Count!=1)return false;
            var entry=response.Entries[0];var values=entry.Attributes["objectGUID"];
            if(values?.Count!=1 || values[0] is not byte[] bytes || bytes.Length!=16 || new Guid(bytes).ToString("N")!=identity.ObjectId)return false;
            var flags=entry.Attributes["userAccountControl"];
            if(flags?.Count!=1 || !int.TryParse(flags[0]?.ToString(),out var control) || (control&2)!=0)return false;
            return true;
        }
        catch(LdapException ex) when(ex.ErrorCode==49){return false;}
        catch(Exception ex) when(ex is LdapException or DirectoryOperationException or PlatformNotSupportedException or DllNotFoundException){throw new DirectoryUnavailableException();}
    }
    private static string Escape(string value)
    {
        var text=new StringBuilder();foreach(var ch in value)text.Append(ch switch {'\\'=>"\\5c",'*'=>"\\2a",'('=>"\\28",')'=>"\\29",'\0'=>"\\00",_=>ch.ToString()});return text.ToString();
    }
}
