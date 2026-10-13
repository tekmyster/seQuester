using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using RansomFree.Contracts;

namespace RansomFree.Client;

public sealed partial class ManagementClient : IDisposable
{
    private readonly HttpClient http;
    private readonly HttpClient nativePolicyHttp;
    private readonly string? credential;
    internal ManagementClient(HttpClient transport,string? testCredential=null){http=transport;nativePolicyHttp=transport;credential=testCredential;}
    public ManagementClient(string server,string? credential=null)
    {
        if(!Uri.TryCreate(server,UriKind.Absolute,out var uri) || uri.Scheme!=Uri.UriSchemeHttps || uri.UserInfo.Length!=0 || uri.Query.Length!=0 || uri.Fragment.Length!=0 || uri.AbsolutePath!="/")
            throw new ArgumentException("Use an HTTPS server origin without credentials, path, query, or fragment.");
        if(credential!=null && (credential.Length!=64 || !credential.All(Uri.IsHexDigit)))throw new ArgumentException("Invalid endpoint credential.");
        this.credential=credential;
        var handler=new HttpClientHandler {AllowAutoRedirect=false,UseCookies=false};
        // Explicit console-lab trust anchor; never a general invalid-certificate switch.
        var labCertificate=Environment.GetEnvironmentVariable("RF_CONSOLE_LAB_CERTIFICATE");
        if(labCertificate!=null)
        {
            if(Environment.GetEnvironmentVariable("DOTNET_ENVIRONMENT")!="Development" || !Environment.GetCommandLineArgs().Contains("--console") || uri.Host!="localhost" || !Path.IsPathFullyQualified(labCertificate))throw new InvalidOperationException("Certificate pin requires the explicit Development console localhost lab.");
            using var expected=System.Security.Cryptography.X509Certificates.X509CertificateLoader.LoadCertificateFromFile(labCertificate);
            var pin=expected.GetCertHash(System.Security.Cryptography.HashAlgorithmName.SHA256);
            handler.ServerCertificateCustomValidationCallback=(request,certificate,chain,errors)=>
                request.RequestUri?.Host=="localhost" && certificate!=null &&
                (errors & ~System.Net.Security.SslPolicyErrors.RemoteCertificateChainErrors)==0 &&
                certificate.NotBefore.ToUniversalTime()<=DateTime.UtcNow && certificate.NotAfter.ToUniversalTime()>DateTime.UtcNow &&
                System.Security.Cryptography.CryptographicOperations.FixedTimeEquals(pin,certificate.GetCertHash(System.Security.Cryptography.HashAlgorithmName.SHA256));
        }
        http=new HttpClient(handler) {BaseAddress=uri,Timeout=TimeSpan.FromSeconds(15),MaxResponseContentBufferSize=1024*1024};
        // The native policy exchange shares the same TLS/redirect/cookie
        // handler, but allows bounded slow-server admission independently of
        // normal event, heartbeat and evidence-upload request deadlines.
        nativePolicyHttp=new HttpClient(handler,disposeHandler:false){BaseAddress=uri,Timeout=TimeSpan.FromSeconds(60),MaxResponseContentBufferSize=1024*1024};
    }
    public async Task<EnrollmentResponse> EnrollAsync(EnrollmentRequest request,CancellationToken ct=default)
    {
        using var response=await Send("api/v1/enroll",request,false,ct);
        return await response.Content.ReadFromJsonAsync<EnrollmentResponse>(ct) ?? throw new InvalidDataException("Enrollment response missing.");
    }
    public async Task HeartbeatAsync(HeartbeatRequest request,CancellationToken ct=default)
    {
        using var response=await Send("api/v1/agent/heartbeat",request with{OperatingSystem=request.OperatingSystem??(OperatingSystem.IsWindows()?"windows":OperatingSystem.IsLinux()?"linux":OperatingSystem.IsMacOS()?"macos":"unknown")},true,ct);
    }
    public async Task<AssignedPolicy> GetPolicyAsync(CancellationToken ct=default)
    {
        using var response=await Send("api/v1/agent/policy",new {},true,ct);
        var policy=await response.Content.ReadFromJsonAsync<AssignedPolicy>(ct)??throw new InvalidDataException("Policy response missing.");
        PolicyCache.Validate(policy);return policy;
    }
    public async Task AcknowledgePolicyAsync(AssignedPolicy policy,CancellationToken ct=default)
    {
        using var response=await Send("api/v1/agent/policy/receipt",new PolicyReceipt(policy.GroupId,policy.Revision){ForensicsVersion=1},true,ct);
    }
    public async Task<bool> ReportNativeResponseCapabilitiesAsync(NativeResponseCapabilities capabilities,CancellationToken ct=default)
    {
        if(!capabilities.IsValid())throw new ArgumentException("Invalid response capabilities.");
        try{using var response=await Send("api/v1/agent/response-capabilities",capabilities,true,ct);return true;}
        catch(HttpRequestException ex)when(ex.StatusCode==HttpStatusCode.NotFound){return false;}
    }
    public async Task<AssignedTrustPolicy> GetTrustPolicyAsync(CancellationToken ct=default,bool linuxKernelTrustSourceActive=false,bool linuxNativeHashSourceActive=false)
    {
        var os=OperatingSystem.IsWindows()?"windows":OperatingSystem.IsLinux()?"linux":OperatingSystem.IsMacOS()?"macos":"unknown";
        if(linuxKernelTrustSourceActive&&os!="linux")throw new InvalidOperationException("Kernel trust source capability requires Linux");
        if(linuxNativeHashSourceActive&&os!="linux")throw new InvalidOperationException("Native hash source capability requires Linux");
        using var response=await Send("api/v1/agent/trust-policy",new TrustCapabilitiesReport(1,4,linuxKernelTrustSourceActive?1:0,os){LinuxNativeHashTrustVersion=linuxNativeHashSourceActive?1:0},true,ct);
        var assignment=await response.Content.ReadFromJsonAsync<AssignedTrustPolicy>(ct)??throw new InvalidDataException("Trust policy response missing.");
        assignment.Validate();return assignment;
    }
    public async Task AcknowledgeTrustPolicyAsync(AssignedTrustPolicy assignment,CancellationToken ct=default)
    {
        assignment.Validate();
        using var response=await Send("api/v1/agent/trust-policy/receipt",new TrustPolicyReceipt(1,assignment.Policy.Revision,assignment.Digest,assignment.GroupId,assignment.Policy.Mode){PolicyVersion=assignment.Policy.Version},true,ct);
    }
    // Transport only. The root challenge owner must independently verify its
    // installation-pinned key, nonce, sensor, origin, expiry and durable floors.
    public async Task<SignedNativePolicy> RelayNativePolicyAsync(string challenge,CancellationToken ct=default)
    {
        if(challenge is not {Length:64}||!challenge.All(Uri.IsHexDigit))throw new ArgumentException("Exact native policy challenge required");
        using var response=await Send("api/v1/agent/native-policy",new{Challenge=challenge},true,ct,nativePolicyHttp);
        var envelope=await response.Content.ReadFromJsonAsync<SignedNativePolicy>(ct)??throw new InvalidDataException("Signed native policy response missing");
        if(envelope.Version!=1||envelope.Algorithm!="RSA-PSS-SHA256"||envelope.KeyId is not {Length:64}||
            envelope.PayloadBase64 is not {Length:>=1 and <=699052}||envelope.SignatureBase64 is not {Length:>=1 and <=684})
            throw new InvalidDataException("Signed native policy transport envelope unsupported or oversized");
        return envelope;
    }
    public async Task<BatchReceipt> SendEventsAsync(EventBatch batch,CancellationToken ct=default)
    {
        var attributed=batch.Events.Any(e=>e.Attribution!=null);
        var trusted=batch.Events.Any(e=>e.Trust!=null);
        var forensic=batch.Events.Any(e=>e.Forensics!=null);
        var kernelVersion=WindowsKernelEvidence.RequiredVersion(batch.Events);
        var syscall=batch.Events.Any(e=>e.Attribution?.WindowsSyscall!=null||e.Forensics?.ActorExecutable.Acquisition?.Version==2);
        var shareEvidence=batch.Events.Any(e=>e.Attribution?.WindowsShare!=null);
        var linuxKernelVersion=LinuxKernelEvidence.RequiredVersion(batch.Events);
        var creation=batch.Events.Any(e=>e.Forensics?.Process.Creation!=null);
        var acquired=batch.Events.Any(e=>e.Forensics?.ActorExecutable.Acquisition is {Version:1});
        var acquisitionObserved=batch.Events.Any(e=>e.Attribution?.WindowsKernel?.AcquisitionObservation!=null);
        var acquisitionRecovered=batch.Events.Any(e=>e.Attribution?.WindowsKernel?.AcquisitionObservation?.Version==2);
        var linuxAcquired=batch.Events.Any(e=>e.Forensics?.ActorExecutable.LinuxAcquisition!=null);
        var linuxWorkVersion=LinuxNativeWorkEvidence.RequiredVersion(batch.Events);
        if(attributed||trusted||forensic)
        {
            using var capabilities=await Send("api/v1/agent/capabilities",new{},true,ct);
            var support=await capabilities.Content.ReadFromJsonAsync<AttributionCapability>(ct);
            if(syscall&&support?.WindowsSyscallVersion!=1)throw new InvalidDataException("Server syscall evidence support unavailable; evidence retained.");
            if(shareEvidence&&support?.WindowsShareVersion!=1)throw new InvalidDataException("Server SMB evidence support unavailable; evidence retained.");
            if(creation&&support?.ProcessCreationVersion!=1)throw new InvalidDataException("Server process creation support unavailable; evidence retained.");
            if(acquired&&support?.ActorAcquisitionVersion!=1)throw new InvalidDataException("Server actor acquisition support unavailable; upgrade server first. Evidence retained.");
            if(acquisitionObserved&&support?.WindowsAcquisitionObservationVersion!=1)throw new InvalidDataException("Server Windows acquisition observation support unavailable; upgrade server first. Evidence retained.");
            if(acquisitionRecovered&&support?.WindowsAcquisitionRecoveryVersion!=1)throw new InvalidDataException("Server Windows acquisition recovery support unavailable; evidence retained.");
            if(linuxAcquired&&support?.LinuxActorAcquisitionVersion!=1)throw new InvalidDataException("Server Linux actor acquisition support unavailable; evidence retained.");
            if(!LinuxNativeWorkEvidence.Supports(linuxWorkVersion,support?.LinuxNativeWorkVersion??0))throw new InvalidDataException("Server Linux native work timeline support unavailable; evidence retained.");
            if(kernelVersion>0&&(support?.WindowsKernelVersion??0)<kernelVersion)throw new InvalidDataException("Server Windows token evidence support unavailable; upgrade server first. Evidence retained.");
            if(!LinuxKernelEvidence.Supports(linuxKernelVersion,support?.LinuxKernelVersion??0,support?.LinuxKernelTargetIdentityVersion??0,support?.LinuxPermissionObservationVersion??0,support?.LinuxIoObservationVersion??0))throw new InvalidDataException("Server Linux kernel evidence or target identity support unavailable; evidence retained.");
            if(forensic&&support?.ForensicsVersion!=1)throw new InvalidDataException("Server forensic support unavailable; upgrade server first. Evidence retained.");
            if(attributed&&support?.AttributionVersion!=1)throw new InvalidDataException("Server attribution support unavailable; upgrade server first. Evidence retained.");
            if(trusted&&support?.TrustVersion!=1)throw new InvalidDataException("Server trust evidence support unavailable; upgrade server first. Evidence retained.");
            if(batch.Events.Any(e=>e.Trust?.Version is 2 or 3 or 4)&&support?.WhitelistVersion!=1)throw new InvalidDataException("Server whitelist support unavailable; upgrade server first. Evidence retained.");
            if(batch.Events.Any(e=>e.Trust?.Version==3)&&support?.LinuxKernelTrustVersion!=1)throw new InvalidDataException("Server Linux kernel trust support unavailable; evidence retained.");
            if(batch.Events.Any(e=>e.Forensics?.LinuxPermissionPair!=null)&&support?.LinuxPermissionPairVersion!=1)throw new InvalidDataException("Server permission-pair evidence support unavailable; evidence retained.");
            if(batch.Events.Any(e=>e.Trust?.Version==4)&&support?.LinuxNativeHashTrustVersion!=1)throw new InvalidDataException("Server native hash trust support unavailable; evidence retained.");
        }
        using var response=await Send("api/v1/agent/events",batch,true,ct);
        var receipt=await response.Content.ReadFromJsonAsync<BatchReceipt>(ct) ?? throw new InvalidDataException("Event receipt missing.");
        if(syscall&&receipt.WindowsSyscallVersion!=1)throw new InvalidDataException("Server did not acknowledge syscall evidence; evidence retained.");
        if(shareEvidence&&receipt.WindowsShareVersion!=1)throw new InvalidDataException("Server did not acknowledge SMB evidence; evidence retained.");
        if(creation&&receipt.ProcessCreationVersion!=1)throw new InvalidDataException("Server did not acknowledge process creation evidence; evidence retained.");
        if(acquired&&receipt.ActorAcquisitionVersion!=1)throw new InvalidDataException("Server did not acknowledge actor acquisition evidence; evidence retained.");
        if(acquisitionObserved&&receipt.WindowsAcquisitionObservationVersion!=1)throw new InvalidDataException("Server did not acknowledge Windows acquisition observation; evidence retained.");
        if(acquisitionRecovered&&receipt.WindowsAcquisitionRecoveryVersion!=1)throw new InvalidDataException("Server did not acknowledge Windows acquisition recovery; evidence retained.");
        if(linuxAcquired&&receipt.LinuxActorAcquisitionVersion!=1)throw new InvalidDataException("Server did not acknowledge Linux actor acquisition evidence; evidence retained.");
        if(!LinuxNativeWorkEvidence.Supports(linuxWorkVersion,receipt.LinuxNativeWorkVersion))throw new InvalidDataException("Server did not acknowledge Linux native work timeline; evidence retained.");
        if(kernelVersion>0&&receipt.WindowsKernelVersion<kernelVersion)throw new InvalidDataException("Server did not acknowledge Windows token evidence; evidence retained.");
        if(!LinuxKernelEvidence.Supports(linuxKernelVersion,receipt.LinuxKernelVersion,receipt.LinuxKernelTargetIdentityVersion,receipt.LinuxPermissionObservationVersion,receipt.LinuxIoObservationVersion))throw new InvalidDataException("Server did not acknowledge Linux kernel evidence or target identity; evidence retained.");
        if(forensic&&receipt.ForensicsVersion!=1)throw new InvalidDataException("Server did not acknowledge forensic evidence; evidence retained.");
        if(attributed&&receipt.AttributionVersion!=1)throw new InvalidDataException("Server did not acknowledge attribution; evidence retained.");
        if(trusted&&receipt.TrustVersion!=1)throw new InvalidDataException("Server did not acknowledge trust evidence; evidence retained.");
        if(batch.Events.Any(e=>e.Trust?.Version is 2 or 3 or 4)&&receipt.WhitelistVersion!=1)throw new InvalidDataException("Server did not acknowledge whitelist evidence; evidence retained.");
        if(batch.Events.Any(e=>e.Trust?.Version==3)&&receipt.LinuxKernelTrustVersion!=1)throw new InvalidDataException("Server did not acknowledge Linux kernel trust evidence; evidence retained.");
        if(batch.Events.Any(e=>e.Forensics?.LinuxPermissionPair!=null)&&receipt.LinuxPermissionPairVersion!=1)throw new InvalidDataException("Server did not acknowledge permission-pair evidence; evidence retained.");
        if(batch.Events.Any(e=>e.Trust?.Version==4)&&receipt.LinuxNativeHashTrustVersion!=1)throw new InvalidDataException("Server did not acknowledge native hash trust evidence; evidence retained.");
        return receipt;
    }
    private sealed record AttributionCapability(int AttributionVersion,int WindowsShareVersion,int TrustVersion,int WhitelistVersion,int ForensicsVersion,int WindowsKernelVersion,int ActorAcquisitionVersion,int ProcessCreationVersion,int LinuxKernelVersion,int LinuxActorAcquisitionVersion,int LinuxNativeWorkVersion,int LinuxKernelTargetIdentityVersion,int LinuxKernelTrustVersion,int LinuxPermissionObservationVersion,int WindowsAcquisitionObservationVersion,int WindowsAcquisitionRecoveryVersion,int LinuxIoObservationVersion,int WindowsSyscallVersion,int LinuxNativeHashTrustVersion=0,int LinuxPermissionPairVersion=0);
    public async Task<ResponseCommand[]> PollResponsesAsync(CancellationToken ct=default)
    {
        using var response=await Send("api/v1/agent/responses",new{},true,ct);
        return await response.Content.ReadFromJsonAsync<ResponseCommand[]>(ct)??throw new InvalidDataException("Response commands missing.");
    }
    public async Task SendResponseReceiptAsync(ResponseReceipt receipt,CancellationToken ct=default)
    {using var response=await Send("api/v1/agent/responses/receipt",receipt,true,ct);}
    private async Task<HttpResponseMessage> Send(string path,object body,bool authenticate,CancellationToken ct,HttpClient? transport=null)
    {
        using var request=new HttpRequestMessage(HttpMethod.Post,path) {Content=JsonContent.Create(body)};
        if(authenticate)request.Headers.Authorization=new AuthenticationHeaderValue("Bearer",credential??throw new InvalidOperationException("Endpoint is not enrolled."));
        var response=await (transport??http).SendAsync(request,ct);
        if(!response.IsSuccessStatusCode)
        {
            var status=response.StatusCode;response.Dispose();
            throw new HttpRequestException(status switch
            {
                HttpStatusCode.Unauthorized=>"Enrollment or endpoint credential rejected; check expiry/revocation.",
                HttpStatusCode.Conflict=>"Event ID conflict. Preserve the queue for investigation.",
                HttpStatusCode.TooManyRequests=>"Management server rate limit reached; retry later.",
                _=>$"Management request failed with HTTP {(int)status}."
            },null,status);
        }
        return response;
    }
    public void Dispose(){if(!ReferenceEquals(nativePolicyHttp,http))nativePolicyHttp.Dispose();http.Dispose();}
}
