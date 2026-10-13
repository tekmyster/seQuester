namespace RansomFree.LinuxAgent;

// Presentation only. Never turn arbitrary provider text into a healthy result.
// Detailed provider status remains in the protected local status and event stream.
internal static class EndpointHealthSummary
{
    const string VerifiedAudit="Linux Audit: collector and relay verified; user/process attribution enabled (per-event completeness varies)";
    public static bool AuditReady(string status)=>status==VerifiedAudit;
    public static string Format(string health,bool monitorRunning,string auditStatus,DateTimeOffset? auditVerifiedUtc=null)
    {
        var monitoring=health=="Canary monitoring configured"&&monitorRunning
            ?"Canary monitoring active":health;
        if(!monitorRunning)monitoring+=" | Canary monitoring stopped";
        var attribution=AuditReady(auditStatus)?"User/process attribution active":auditStatus;
        if(auditVerifiedUtc is {} verified)attribution+=" | Audit last verified "+verified.ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ",System.Globalization.CultureInfo.InvariantCulture);
        return monitoring+" | "+attribution;
    }
}
