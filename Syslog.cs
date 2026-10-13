using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Text;
using System.Text.Json;
using System.Security.Cryptography;

namespace RansomFree;

internal sealed record SyslogOptions
{
    public bool Enabled { get; init; }
    public string Host { get; init; }="";
    public int Port { get; init; }=514;
    public string Transport { get; init; }="TCP";
    public int Facility { get; init; }=16;
    public int Severity { get; init; }=4;
    public string Format { get; init; }="RFC3164";
    public bool OctetCounting { get; init; }
    [System.Text.Json.Serialization.JsonIgnore(Condition=System.Text.Json.Serialization.JsonIgnoreCondition.WhenWritingDefault)]
    public bool RequirePersistenceReceipt {get;init;}
    [System.Text.Json.Serialization.JsonIgnore(Condition=System.Text.Json.Serialization.JsonIgnoreCondition.WhenWritingNull)]
    public string? ServerCertificateSha256 {get;init;}
    public void Validate()
    {
        if(string.IsNullOrWhiteSpace(Host) || Host.Length>253 || Host.Any(char.IsWhiteSpace) || Host.Contains('/') || Port is <1 or >65535)
            throw new ArgumentException("Enter a hostname or IP address and a port from 1 to 65535.");
        if(!new[]{"UDP","TCP","TLS"}.Contains(Transport) || !new[]{"RFC3164","RFC5424"}.Contains(Format) || Facility is <0 or >23 || Severity is <0 or >7)
            throw new ArgumentException("Invalid syslog transport, facility, or severity.");
        if(RequirePersistenceReceipt&&Transport=="UDP")throw new ArgumentException("Storage receipts require TCP or TLS.");
        if(ServerCertificateSha256!=null&&(Transport!="TLS"||ServerCertificateSha256.Length!=64||!ServerCertificateSha256.All(Uri.IsHexDigit)))throw new ArgumentException("Enter a SHA-256 certificate fingerprint for TLS.");
    }
}

internal static class SyslogClient
{
    public static byte[] Format(Alert alert,SyslogOptions options)
    {
        // Printable ASCII hostname/header; JSON escaping prevents control-character injection in MSG.
        var host=new string(Environment.MachineName.Where(c=>c>32 && c<127).Take(255).ToArray());
        var severity=alert.PolicySyslogSeverity is >=0 and <=7?Math.Max(alert.PolicySyslogSeverity.Value,options.Severity):options.Severity;
        var header=$"<{options.Facility*8+severity}>1 {alert.Time.ToUniversalTime():yyyy-MM-ddTHH:mm:ss.fffZ} {host} RansomFree {Environment.ProcessId} CANARY - ";
        if(options.Format=="RFC3164") header=$"<{options.Facility*8+severity}>{alert.Time.ToString("MMM dd HH:mm:ss",System.Globalization.CultureInfo.InvariantCulture)} {host} RansomFree: ";
        return Encoding.UTF8.GetBytes(header+JsonSerializer.Serialize(alert));
    }
    public static async Task<string> SendAsync(Alert alert,SyslogOptions options,CancellationToken cancellationToken=default)
    {
        options.Validate();
        using var timeout=CancellationTokenSource.CreateLinkedTokenSource(cancellationToken); timeout.CancelAfter(TimeSpan.FromSeconds(6));
        var ct=timeout.Token;
        var addresses=await Dns.GetHostAddressesAsync(options.Host,ct);
        if(addresses.Length==0) throw new IOException("DNS returned no addresses.");
        var bytes=Format(alert,options);
        if(bytes.Length>60000) throw new IOException("Event exceeds the syslog transport size limit.");
        if(options.Transport=="UDP")
        {
            using var udp=new UdpClient(addresses[0].AddressFamily);
            await udp.SendAsync(bytes,new IPEndPoint(addresses[0],options.Port),ct);
            return $"UDP sent to {options.Host}:{options.Port}; delivery is unconfirmed.";
        }
        using var client=new TcpClient();
        client.NoDelay=true;
        await client.ConnectAsync(options.Host,options.Port,ct);
        var network=client.GetStream();
        SslStream? tls=null;
        try
        {
            Stream stream=network;
            if(options.Transport=="TLS")
            {
                tls=options.ServerCertificateSha256 is {} pin?new SslStream(network,false,(_,certificate,_,_)=>certificate!=null&&Convert.ToHexString(SHA256.HashData(certificate.GetRawCertData())).Equals(pin,StringComparison.OrdinalIgnoreCase)):new SslStream(network,false);
                await tls.AuthenticateAsClientAsync(new SslClientAuthenticationOptions { TargetHost=options.Host },ct);
                stream=tls;
            }
            // Write one complete RFC 6587 / 5425 frame. A small separate TLS
            // prefix write adds a record and a transport dependency before the
            // payload can be sent. Receivers still parse a byte stream.
            var prefix=options.OctetCounting||options.Transport=="TLS"?Encoding.ASCII.GetBytes(bytes.Length.ToString(System.Globalization.CultureInfo.InvariantCulture)+" "):Array.Empty<byte>();
            var frame=new byte[prefix.Length+bytes.Length+(prefix.Length==0?1:0)];
            prefix.CopyTo(frame,0);bytes.CopyTo(frame,prefix.Length);if(prefix.Length==0)frame[^1]=10;
            await stream.WriteAsync(frame,ct);await stream.FlushAsync(ct);
            if(options.RequirePersistenceReceipt)
            {
                var buffer=new byte[4096];var count=0;while(count<buffer.Length){var read=await stream.ReadAsync(buffer.AsMemory(count,1),ct);if(read==0)throw new IOException("Collector closed before storage receipt.");if(buffer[count++]==10)break;}
                if(count==buffer.Length&&buffer[count-1]!=10)throw new IOException("Collector receipt exceeds its limit.");
                using var receipt=JsonDocument.Parse(buffer.AsMemory(0,count));var body=receipt.RootElement;
                var hash=Convert.ToHexString(SHA256.HashData(JsonSerializer.SerializeToUtf8Bytes(alert)));
                if(!body.TryGetProperty("version",out var version)||!version.TryGetInt32(out var value)||value!=1||!body.TryGetProperty("persisted",out var persisted)||persisted.ValueKind!=JsonValueKind.True||
                    !body.TryGetProperty("event_id",out var id)||id.GetString()!=alert.EventId||!body.TryGetProperty("payload_sha256",out var digest)||!hash.Equals(digest.GetString(),StringComparison.OrdinalIgnoreCase))throw new IOException("Collector receipt does not match the event.");
                return $"{options.Transport} collector confirmed event storage.";
            }
            return $"{options.Transport} sent to {options.Host}:{options.Port}; collector persistence is unconfirmed.";
        }
        finally { if(tls!=null) await tls.DisposeAsync(); }
    }
    public static string Explain(Exception exception,SyslogOptions options)
    {
        var reason=exception is OperationCanceledException ? "Connection or send timed out" : exception.Message;
        return $"Syslog {options.Host}:{options.Port}/{options.Transport}: {reason}. Check DNS, receiver, route, certificate and outbound firewall policy; this does not prove a blocked port.";
    }
}

internal sealed class SyslogOutbox : IDisposable
{
    private sealed record Pending(string Id,Alert Alert,SyslogOptions Destination,int Attempts=0);
    private readonly object gate=new();
    private readonly List<Pending> queue=[];
    private readonly string path;
    private readonly CancellationTokenSource stop=new();
    private readonly SemaphoreSlim changed=new(0,1);
    private readonly Task worker;
    private volatile bool enabled;
    private bool loadFailed;
    public event Action<string>? Status;
    public string LastStatus { get; private set; }="Syslog idle";
    public int Count { get { lock(gate) return queue.Count; } }
    public SyslogOutbox(string directory,bool enabled=true)
    {
        this.enabled=enabled;
        Directory.CreateDirectory(directory); path=Path.Combine(directory,"syslog-outbox.json");
        if(File.Exists(path))
        {
            try { queue=JsonSerializer.Deserialize<List<Pending>>(File.ReadAllText(path)) ?? []; }
            catch(Exception ex) { loadFailed=true; LastStatus="Cannot load syslog queue; original file preserved: "+ex.Message; }
        }
        worker=Task.Run(WorkAsync);
    }
    public void Enqueue(Alert alert,SyslogOptions options)
    {
        var observed=new RansomFree.Contracts.AgentEvent(alert.EventId,alert.Time.ToUniversalTime(),alert.Operation,alert.Path,alert.User,alert.Process,alert.ProcessId,alert.Source){Attribution=alert.Attribution,Trust=alert.Trust,Forensics=alert.Forensics};
        if(alert.Trust?.IsLogOnlyFor(observed)==true)return;
        if(!options.Enabled) return;
        lock(gate)
        {
            if(loadFailed) throw new InvalidDataException(LastStatus);
            if(queue.Count>=1000) { Publish("Syslog queue full (1000 events); new event retained only in local activity log."); return; }
            queue.Add(new(Guid.NewGuid().ToString("N"),alert,options)); Save();
        }
        if(changed.CurrentCount==0) changed.Release();
    }
    public void SetEnabled(bool value)
    {
        enabled=value;
        if(!value) Publish("Syslog paused; queued events retained. Any in-flight send may finish.");
        else if(changed.CurrentCount==0) changed.Release();
    }
    private void Save()
    {
        var temp=path+".tmp";
        File.WriteAllText(temp,JsonSerializer.Serialize(queue)); File.Move(temp,path,true);
    }
    private void Publish(string status) { LastStatus=status; Status?.Invoke(status); }
    private async Task WorkAsync()
    {
        while(!stop.IsCancellationRequested)
        {
            Pending? item; lock(gate) item=enabled ? queue.FirstOrDefault():null;
            if(item==null)
            {
                try { await changed.WaitAsync(TimeSpan.FromSeconds(5),stop.Token); } catch(OperationCanceledException) { break; }
                continue;
            }
            try
            {
                var result=await SyslogClient.SendAsync(item.Alert,item.Destination,stop.Token);
                lock(gate) { queue.RemoveAll(p=>p.Id==item.Id); Save(); }
                Publish(result+$" Queue: {Count}.");
            }
            catch(OperationCanceledException) when(stop.IsCancellationRequested) { break; }
            catch(Exception ex)
            {
                Publish(SyslogClient.Explain(ex,item.Destination)+$" Queued: {Count}; retry in 30 seconds.");
                try { await Task.Delay(TimeSpan.FromSeconds(30),stop.Token); } catch(OperationCanceledException) { break; }
            }
        }
    }
    public void Dispose() { stop.Cancel(); }
}
