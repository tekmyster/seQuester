namespace RansomFree.Contracts;

// Security 5145 is a share authorization check, not completed file I/O or a
// snapshot of the application on the remote client. Keep those claims separate.
public sealed record WindowsShareEvidence
{
    public int Version {get;init;}=1;
    public string? SourceAddress {get;init;}
    public string? RawSourceAddress {get;init;}
    public int? SourcePort {get;init;}
    public string? ShareName {get;init;}
    public string? ShareLocalPath {get;init;}
    public string? RelativeTargetName {get;init;}
    public string? AccessReason {get;init;}
    public string AuthorizationOutcome {get;init;}="Unknown";
    public string RemoteProcessStatus {get;init;}="Unavailable: not supplied by event 5145";
    public bool IsValid()
    {
        static bool Text(string? s,int limit)=>s==null||s.Length<=limit&&!s.Any(char.IsControl);
        return Version==1&&SourcePort is null or >=0 and <=65535
            &&(SourceAddress==null||SourceAddress.Length<=64&&System.Net.IPAddress.TryParse(SourceAddress,out _))
            &&Text(RawSourceAddress,64)
            &&Text(ShareName,512)&&Text(ShareLocalPath,2048)&&Text(RelativeTargetName,2048)
            // Windows 5145 AccessReason is a multiline, tab-indented access-check
            // report. Preserve its exact text; path/identity fields remain strict.
            &&(AccessReason==null||AccessReason.Length<=4096&&!AccessReason.Any(c=>char.IsControl(c)&&c is not ('\r' or '\n' or '\t')))
            &&AuthorizationOutcome is "Granted" or "Denied" or "Unknown"
            &&RemoteProcessStatus=="Unavailable: not supplied by event 5145";
    }
    public static bool Matches(AgentEvent e)=>e.Attribution?.WindowsShare is not {} s
        ?e.Source!="Windows audit 5145"
        :s.IsValid()&&e.Source=="Windows audit 5145"&&e.Attribution.Provider=="Windows Security Audit"
        &&e.Attribution.WindowsKernel==null&&e.Attribution.LinuxKernel==null
        &&e.ProcessId==null&&e.Process is null or "Unavailable: remote application not supplied by SMB audit"&&!e.Attribution.CompleteRecordSet
        &&e.Attribution.Level!="Full attribution"
        &&e.Attribution.Outcome==(s.AuthorizationOutcome=="Denied"?"Failed":s.AuthorizationOutcome=="Granted"?"Share check granted":"Unknown")
        &&e.Operation==(s.AuthorizationOutcome=="Denied"?"Share access denied":"Share access checked")
        &&e.Trust?.Actor.Verified!=true;
}
