using System.Net;
using System.Net.Http.Json;

namespace RansomFree.Client;

public sealed record ConnectionDiagnostic(string Code,string Message,bool Reachable);

public sealed partial class ManagementClient
{
    /// <summary>Checks the configured origin without sending endpoint credentials or changing firewall settings.</summary>
    public async Task<ConnectionDiagnostic> DiagnoseAsync(CancellationToken ct=default)
    {
        try
        {
            using var response=await http.GetAsync("health/live",ct);
            if((int)response.StatusCode is >=300 and <400)return new("Redirect","The server redirected the request. Configure the final HTTPS origin; redirects are not followed.",false);
            if(!response.IsSuccessStatusCode)return new("HttpError",$"The server returned HTTP {(int)response.StatusCode}. Check the server or proxy configuration.",false);
            var health=await response.Content.ReadFromJsonAsync<HealthResponse>(ct);
            return health is {Status:"alive",ApiVersion:1}
                ?new("Reachable","Management API is reachable with a trusted TLS connection. Enrollment and event delivery are separate checks.",true)
                :new("UnexpectedResponse","The destination did not identify a compatible management API.",false);
        }
        catch(OperationCanceledException) when(!ct.IsCancellationRequested){return new("Timeout","The request timed out. Check routing, proxy, firewall, and server availability; a timeout does not identify the cause.",false);}
        catch(HttpRequestException e)
        {
            return e.HttpRequestError switch
            {
                HttpRequestError.NameResolutionError=>new("DnsError","The server name could not be resolved. Check DNS and the configured hostname.",false),
                HttpRequestError.SecureConnectionError=>new("TlsError","TLS verification failed. Check the certificate, hostname, trust chain, and system time.",false),
                HttpRequestError.ConnectionError=>new("ConnectionError","A connection could not be established. Check the listener, proxy, routing, and firewall; no firewall changes were made.",false),
                _=>new("TransportError","The connection failed or returned an invalid response. Check the server and proxy logs.",false)
            };
        }
        catch(System.Text.Json.JsonException){return new("UnexpectedResponse","The destination returned an invalid management health response.",false);}
        catch(NotSupportedException){return new("UnexpectedResponse","The destination returned an unsupported management health response.",false);}
    }
    private sealed record HealthResponse(string Status,int ApiVersion);
}
