using System.Net.Http.Headers;
using System.Net.Http.Json;
using RansomFree.Contracts;
namespace RansomFree.Client;

public sealed partial class ManagementClient
{
    public async Task<bool> EvidenceUploadSupported(CancellationToken ct=default)
    {using var response=await Send("api/v1/agent/capabilities",new{},true,ct);return (await response.Content.ReadFromJsonAsync<EvidenceCapability>(ct))?.EvidenceUploadVersion==1;}
    private sealed record EvidenceCapability(int EvidenceUploadVersion);
    public async Task<EvidenceUploadReceipt> StartEvidenceUpload(EvidenceUploadStart request,CancellationToken ct=default)
    {using var response=await Send("api/v1/agent/evidence/start",request,true,ct);return await UploadReceipt(response,ct);}
    public async Task<EvidenceUploadReceipt> FinishEvidenceUpload(string id,CancellationToken ct=default)
    {if(!EvidenceTransferLimits.Id(id))throw new ArgumentException("Invalid evidence ID.");using var response=await Send($"api/v1/agent/evidence/{id}/finish",new{},true,ct);return await UploadReceipt(response,ct);}
    public async Task<EvidenceUploadReceipt> SendEvidenceChunk(string id,long offset,byte[] data,CancellationToken ct=default)
    {
        if(!EvidenceTransferLimits.Id(id)||offset<0||data.Length is <1 or >EvidenceTransferLimits.ChunkBytes)throw new ArgumentException("Invalid evidence chunk.");
        using var request=new HttpRequestMessage(HttpMethod.Put,$"api/v1/agent/evidence/{id}/chunks/{offset}"){Content=new ByteArrayContent(data)};
        request.Content.Headers.ContentType=new("application/octet-stream");request.Headers.Authorization=new AuthenticationHeaderValue("Bearer",credential??throw new InvalidOperationException("Endpoint not enrolled."));
        using var response=await http.SendAsync(request,ct);response.EnsureSuccessStatusCode();return await UploadReceipt(response,ct);
    }
    private static async Task<EvidenceUploadReceipt> UploadReceipt(HttpResponseMessage response,CancellationToken ct)=>await response.Content.ReadFromJsonAsync<EvidenceUploadReceipt>(ct)??throw new InvalidDataException("Evidence receipt missing.");
}
