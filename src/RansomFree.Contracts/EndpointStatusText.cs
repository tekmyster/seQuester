namespace RansomFree.Contracts;

// Display only: callers retain the original message in Diagnostics.
public static class EndpointStatusText
{
    public static string Health(string? raw)
    {
        if(string.IsNullOrWhiteSpace(raw))return "Status unavailable";
        bool Has(string value)=>raw.Contains(value,StringComparison.OrdinalIgnoreCase);
        if(Has("queue")&&Has("full"))return "Alert storage full · New alerts at risk";
        if(Has("queue")&&Has("failed"))return "Alert storage needs attention";
        if(Has("stopped"))return "Monitoring stopped";
        if(Has("gap")||Has("loss")||Has("overflow"))return "Monitoring evidence incomplete";
        if(Has("automatic response paused"))return "Automatic response paused";
        if(Has("policy pending")||Has("deployment pending"))return "Policy update pending";
        if(Has("no canaries"))return "No canaries configured";
        if(raw is "Starting" or "Monitoring" or "Canary monitoring active")return raw;
        if(raw=="Canary monitoring configured")return "Monitoring configured";
        if(Has("failed")||Has("unavailable")||Has("degraded")||Has("warning"))return "Monitoring needs attention";
        return "Status unconfirmed · See Diagnostics";
    }
    public static string Delivery(string? raw)
    {
        if(string.IsNullOrWhiteSpace(raw))return "Delivery status unavailable";
        if(raw.Contains("queue full",StringComparison.OrdinalIgnoreCase))return "Syslog queue full · New alerts at risk";
        if(raw.StartsWith("Cannot load syslog queue",StringComparison.OrdinalIgnoreCase))return "Syslog queue unavailable · See Diagnostics";
        if(raw=="Syslog idle")return "Waiting for alerts";
        if(raw.StartsWith("Disabled",StringComparison.OrdinalIgnoreCase))return "Disabled · Alerts retained";
        if(raw.StartsWith("Waiting",StringComparison.OrdinalIgnoreCase))return "Waiting for alerts";
        if(raw.Contains("sent to",StringComparison.OrdinalIgnoreCase)&&raw.Contains("unconfirmed",StringComparison.OrdinalIgnoreCase))return "Sent · Receipt unconfirmed";
        if(raw.Contains("failed",StringComparison.OrdinalIgnoreCase)||raw.Contains("pending",StringComparison.OrdinalIgnoreCase)||raw.Contains("blocked",StringComparison.OrdinalIgnoreCase))return "Delivery pending · See Diagnostics";
        return "Delivery unconfirmed · See Diagnostics";
    }
    public static string Connectivity(string? raw)=>raw?.StartsWith("Offline / sync failed:",StringComparison.Ordinal)==true?"Offline · Sync pending":raw switch
    {
        "Connected"=>"Connected", "Offline"=>"Offline", "Not enrolled"=>"Not enrolled", "Connecting"=>"Connecting", "Not connected"=>"Not connected",
        _=>"Connection unconfirmed"
    };
}
