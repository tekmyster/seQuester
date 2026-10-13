using System.Buffers.Binary;
using System.Net;
using System.Net.Sockets;
using System.Text;
using RansomFree.Callbacks;

// Authoritative token-zone responder only; never a recursive resolver or an outbound DNS proxy.
internal sealed class DnsReceiver(IConfiguration configuration,CallbackStorage store,ILogger<DnsReceiver> logger):BackgroundService
{
    protected override async Task ExecuteAsync(CancellationToken ct)
    {
        if(configuration["Dns:Enabled"]!="true")return;
        var zone=configuration["Dns:Zone"]?.TrimEnd('.').ToLowerInvariant()??"";
        if(Uri.CheckHostName(zone)!=UriHostNameType.Dns || zone.Length>190)throw new InvalidOperationException("Set a delegated DNS token zone.");
        var address=IPAddress.Parse(configuration["Dns:BindAddress"]??"127.0.0.1");var port=int.Parse(configuration["Dns:Port"]??"5353");
        if(port is <1 or >65535)throw new InvalidOperationException("Invalid DNS port.");
        using var udp=new UdpClient(new IPEndPoint(address,port));var tcp=new TcpListener(address,port);tcp.Start(32);
        try{await Task.WhenAll(Udp(),Tcp());}
        catch(OperationCanceledException) when(ct.IsCancellationRequested){}
        finally{tcp.Stop();}
        async Task Udp()
        {
            while(!ct.IsCancellationRequested){var packet=await udp.ReceiveAsync(ct);var response=Answer(packet.Buffer,packet.RemoteEndPoint.Address.ToString(),zone);if(response!=null)await udp.SendAsync(response,packet.RemoteEndPoint,ct);}
        }
        async Task Tcp()
        {
            // Bounded sequential processing avoids connection/task amplification. Production sizing is pending.
            while(!ct.IsCancellationRequested)
            {
                using var client=await tcp.AcceptTcpClientAsync(ct);using var timeout=CancellationTokenSource.CreateLinkedTokenSource(ct);timeout.CancelAfter(TimeSpan.FromSeconds(2));
                try
                {
                    var stream=client.GetStream();var length=new byte[2];await stream.ReadExactlyAsync(length,timeout.Token);var size=BinaryPrimitives.ReadUInt16BigEndian(length);if(size is <12 or >512)continue;
                    var query=new byte[size];await stream.ReadExactlyAsync(query,timeout.Token);var response=Answer(query,((IPEndPoint)client.Client.RemoteEndPoint!).Address.ToString(),zone);if(response==null)continue;
                    BinaryPrimitives.WriteUInt16BigEndian(length,(ushort)response.Length);await stream.WriteAsync(length,timeout.Token);await stream.WriteAsync(response,timeout.Token);
                }
                catch(Exception ex) when(ex is IOException or SocketException or OperationCanceledException){if(ct.IsCancellationRequested)break;}
            }
        }
    }
    private byte[]? Answer(byte[] query,string source,string zone)
    {
        if(query.Length is <17 or >512 || (query[2]&0xF8)!=0 || query[4]!=0 || query[5]!=1)return null;
        var labels=new List<string>();var position=12;
        while(position<query.Length)
        {
            var length=query[position++];if(length==0)break;if(length>63 || position+length>query.Length || labels.Count>=10)return null;
            var label=Encoding.ASCII.GetString(query,position,length).ToLowerInvariant();if(label.Any(c=>!char.IsAsciiLetterOrDigit(c)&&c!='-'&&c!='_'))return null;labels.Add(label);position+=length;
        }
        if(position+4>query.Length || query[position+2]!=0 || query[position+3]!=1)return null;
        var name=string.Join('.',labels);var suffix="."+zone;var ours=name.EndsWith(suffix,StringComparison.Ordinal);
        var rcode=ours?3:5; // NXDOMAIN for our canary names; REFUSED for every other zone.
        if(ours)
        {
            var token=name[..^suffix.Length];
            try{store.Record(token,"DNS",source,"Query type "+BinaryPrimitives.ReadUInt16BigEndian(query.AsSpan(position,2)));}
            catch(Exception ex){rcode=2;logger.LogError("DNS callback persistence failed ({Type}).",ex.GetType().Name);}
        }
        var response=query[..(position+4)];response[2]=(byte)(0x80|(ours?4:0)|(query[2]&1));response[3]=(byte)rcode;Array.Clear(response,6,6);return response;
    }
}
