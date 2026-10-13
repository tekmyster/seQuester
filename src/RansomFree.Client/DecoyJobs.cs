using System.Net.Http.Json;
using RansomFree.Contracts;
namespace RansomFree.Client;
public sealed partial class ManagementClient
{
    public async Task<DecoyJobExchange> PollDecoyJobsAsync(CancellationToken ct)
    {
        using var response=await Send("api/v1/agent/decoy-jobs",new{},true,ct);
        var exchange=await response.Content.ReadFromJsonAsync<DecoyJobExchange>(DecoyJobsProtocol.Json,ct)??throw new InvalidDataException("Job response missing.");
        if(exchange.Assignment is {} job)DecoyJobsProtocol.Validate(job);return exchange;
    }
    public async Task<DecoyReportAcknowledgement> SendDecoyReceiptAsync(DecoyJobReport report,CancellationToken ct)
    {
        DecoyJobsProtocol.Validate(report);using var response=await Send("api/v1/agent/decoy-jobs/receipt",report,true,ct);
        var ack=await response.Content.ReadFromJsonAsync<DecoyReportAcknowledgement>(DecoyJobsProtocol.Json,ct)??throw new InvalidDataException("Job acknowledgement missing.");
        if(!DecoyJobsProtocol.Nonce(ack.Challenge))throw new InvalidDataException("Reconciliation challenge missing.");return ack;
    }
    public async Task SendDecoyObservationAsync(DecoyNativeReport report,CancellationToken ct)
    {DecoyJobsProtocol.Validate(report);using var response=await Send("api/v1/agent/decoy-jobs/observation",report,true,ct);}
}
