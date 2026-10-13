namespace RansomFree.UnixDesktop;

// Concise status only. Original provider evidence remains in Diagnostics.
internal static class DesktopStatusText
{
    public static string Sensor(string? value, bool stale = false)
    {
        if(stale)return "User/process attribution unconfirmed";
        var status=value??"Monitoring status unavailable";
        if(status=="FSEvents changes only (no open/read/process attribution)")return "File changes monitored · User/process attribution unavailable";
        if(status=="FSEvents + Endpoint Security helper (open intent, not copy proof)")return "File monitoring configured · User/process attribution unverified";
        foreach(var prefix in new[]{"File activity: inotify; actor evidence supplied separately by Linux Audit when enabled | ","File activity: fanotify PIDFD + inotify names | "})
            if(status.StartsWith(prefix,StringComparison.Ordinal)){status=status[prefix.Length..];break;}
        if(status.StartsWith("Linux Audit degraded:",StringComparison.Ordinal)||status.StartsWith("Audit unavailable:",StringComparison.Ordinal))return "User/process attribution needs attention. See Diagnostics.";
        if(status=="Audit disabled")return "User/process attribution disabled";
        if(status is "Audit connection not verified" or "Linux Audit: root checks passed; awaiting heartbeat advancement" or "Linux Audit: root checks passed; awaiting next heartbeat")return "Checking user/process attribution";
        return status=="Linux Audit: collector and relay verified; user/process attribution enabled (per-event completeness varies)"
            ?"User/process attribution active":"User/process attribution unconfirmed · See Diagnostics";
    }
}
