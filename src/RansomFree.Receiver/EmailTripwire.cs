using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Authentication;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using RansomFree.Callbacks;

// Restricted SMTP sink: no relay, forwarding, mailbox storage, AUTH or attachment handling.
internal sealed class EmailTripwire(IConfiguration configuration,CallbackStorage store,ILogger<EmailTripwire> logger):BackgroundService
{
    protected override async Task ExecuteAsync(CancellationToken ct)
    {
        if(configuration["Smtp:Enabled"]!="true")return;
        var domain=configuration["Smtp:Domain"]?.ToLowerInvariant()??"";
        if(Uri.CheckHostName(domain)!=UriHostNameType.Dns || domain.Length>190)throw new InvalidOperationException("Set the token mail domain.");
        var address=IPAddress.Parse(configuration["Smtp:BindAddress"]??"127.0.0.1");var port=int.Parse(configuration["Smtp:Port"]??"2525");
        if(port is <1 or >65535)throw new InvalidOperationException("Invalid SMTP port.");
        // Windows Schannel cannot use ephemeral private keys for this server handshake.
        // DefaultKeySet creates a provider-managed temporary key, removed on disposal;
        // do not request PersistKeySet or alter the machine certificate trust store.
        var keyStorage=OperatingSystem.IsWindows()?X509KeyStorageFlags.DefaultKeySet:X509KeyStorageFlags.EphemeralKeySet;
        using var certificate=X509CertificateLoader.LoadPkcs12FromFile(configuration["Smtp:CertificatePath"]??throw new InvalidOperationException("SMTP requires a TLS certificate."),configuration["Smtp:CertificatePassword"],keyStorage);
        if(!certificate.HasPrivateKey || certificate.NotAfter.ToUniversalTime()<DateTime.UtcNow || certificate.NotBefore.ToUniversalTime()>DateTime.UtcNow)throw new InvalidOperationException("SMTP certificate is not currently usable.");
        var listener=new TcpListener(address,port);listener.Start(16);
        try
        {
            while(!ct.IsCancellationRequested)
            {
                // One bounded session at a time; public ingress scaling remains a release gate.
                using var client=await listener.AcceptTcpClientAsync(ct);
                using var timeout=CancellationTokenSource.CreateLinkedTokenSource(ct);timeout.CancelAfter(TimeSpan.FromSeconds(45));
                try{await Session(client,domain,certificate,timeout.Token);}
                catch(Exception ex) when(ex is IOException or SocketException or AuthenticationException or OperationCanceledException)
                {if(ct.IsCancellationRequested)break;logger.LogDebug("SMTP session closed ({Type}); message content was not retained.",ex.GetType().Name);}
                catch(Exception ex){logger.LogWarning("SMTP receipt unavailable ({Type}); no successful delivery is claimed.",ex.GetType().Name);}
            }
        }
        catch(OperationCanceledException) when(ct.IsCancellationRequested){}
        finally{listener.Stop();}
    }
    private async Task Session(TcpClient client,string domain,X509Certificate2 certificate,CancellationToken ct)
    {
        Stream stream=client.GetStream();SslStream? tls=null;
        try
        {
            await Reply("220 "+domain+" ESMTP");var greeted=false;var sender=false;string? recipient=null;
            for(var commands=0;commands<100;commands++)
            {
                var line=await Line(stream,510,ct);if(line==null)return;
                if(line.Equals("QUIT",StringComparison.OrdinalIgnoreCase)){await Reply("221 Closing connection");return;}
                if(line.StartsWith("EHLO ",StringComparison.OrdinalIgnoreCase)||line.StartsWith("HELO ",StringComparison.OrdinalIgnoreCase))
                {
                    greeted=true;sender=false;recipient=null;
                    await Reply(line.StartsWith("EHLO ",StringComparison.OrdinalIgnoreCase)?"250-"+domain+"\r\n"+(tls==null?"250-STARTTLS\r\n":"")+"250 SIZE 65536":"250 "+domain);continue;
                }
                if(line.Equals("STARTTLS",StringComparison.OrdinalIgnoreCase))
                {
                    if(!greeted||tls!=null){await Reply("503 Bad sequence");continue;}
                    await Reply("220 Ready for TLS");tls=new SslStream(stream,false);
                    await tls.AuthenticateAsServerAsync(new SslServerAuthenticationOptions{ServerCertificate=certificate,EnabledSslProtocols=SslProtocols.Tls12|SslProtocols.Tls13,ClientCertificateRequired=false},ct);
                    stream=tls;greeted=false;sender=false;recipient=null;continue;
                }
                if(line.Equals("NOOP",StringComparison.OrdinalIgnoreCase)){await Reply("250 OK");continue;}
                if(line.Equals("RSET",StringComparison.OrdinalIgnoreCase)){sender=false;recipient=null;await Reply("250 Reset");continue;}
                if(tls==null){await Reply("530 STARTTLS required");continue;}
                if(!greeted){await Reply("503 Send EHLO first");continue;}
                if(line.StartsWith("MAIL FROM:",StringComparison.OrdinalIgnoreCase))
                {
                    sender=false;recipient=null;var value=line[10..].Trim();var end=value.IndexOf('>');
                    if(!value.StartsWith('<')||end<1){await Reply("501 Invalid envelope");continue;}
                    var options=value[(end+1)..].Trim();
                    if(options.Length>0 && (!options.StartsWith("SIZE=",StringComparison.OrdinalIgnoreCase)||!int.TryParse(options[5..],out var size)||size<0||size>65536))
                    {await Reply("552 Unsupported size or envelope option");continue;}
                    sender=true;await Reply("250 Sender accepted");continue;
                }
                if(line.StartsWith("RCPT TO:",StringComparison.OrdinalIgnoreCase))
                {
                    if(!sender){await Reply("503 MAIL required");continue;}
                    if(recipient!=null){await Reply("452 One recipient per transaction");continue;}
                    var value=line[8..].Trim();
                    if(!value.StartsWith('<')||!value.EndsWith('>')){await Reply("501 Invalid recipient");continue;}
                    var mailbox=value[1..^1];var suffix="@"+domain;
                    var id=mailbox.EndsWith(suffix,StringComparison.OrdinalIgnoreCase)?mailbox[..^suffix.Length]:"";
                    if(store.Get(id) is not {Type:"email",Revoked:false}){await Reply("550 Recipient unavailable");continue;}
                    recipient=id;await Reply("250 Recipient accepted");continue;
                }
                if(line.Equals("DATA",StringComparison.OrdinalIgnoreCase))
                {
                    if(recipient==null){await Reply("503 RCPT required");continue;}
                    await Reply("354 End with <CRLF>.<CRLF>");var bytes=0;
                    while(true)
                    {
                        var content=await Line(stream,998,ct);if(content==null)return;
                        if(content==".")break;bytes+=content.Length+2;
                        if(bytes>65536){await Reply("552 Message too large");return;}
                        // Discard every line, including headers. Never parse attachments or URLs.
                    }
                    try
                    {
                        var accepted=store.Record(recipient,"SMTP",((IPEndPoint)client.Client.RemoteEndPoint!).Address.ToString(),"Message received; content discarded");
                        await Reply(accepted?"250 Receipt recorded":"550 Recipient unavailable");
                    }
                    catch(Exception ex) when(ex is not OperationCanceledException)
                    {logger.LogWarning("SMTP receipt persistence failed ({Type}).",ex.GetType().Name);await Reply("451 Receipt temporarily unavailable");}
                    sender=false;recipient=null;continue;
                }
                await Reply("502 Command not supported");
            }
            await Reply("421 Session limit reached");
        }
        finally{if(tls!=null)await tls.DisposeAsync();}
        async Task Reply(string reply){await stream.WriteAsync(Encoding.ASCII.GetBytes(reply+"\r\n"),ct);await stream.FlushAsync(ct);}
    }
    private static async Task<string?> Line(Stream stream,int maximum,CancellationToken ct)
    {
        var bytes=new byte[maximum+2];var one=new byte[1];var count=0;
        while(count<bytes.Length)
        {
            if(await stream.ReadAsync(one,ct)==0)return null;bytes[count++]=one[0];
            if(one[0]==10)
            {
                if(count<2||bytes[count-2]!=13)throw new IOException("CRLF required.");
                return Encoding.ASCII.GetString(bytes,0,count-2);
            }
        }
        throw new IOException("SMTP line limit exceeded.");
    }
}
