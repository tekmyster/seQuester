using RansomFree.UnixDesktop;
var prefix="File activity: inotify; actor evidence supplied separately by Linux Audit when enabled | ";
var ready="Linux Audit: collector and relay verified; user/process attribution enabled (per-event completeness varies)";
var cases=new (string? Input,string Expected)[]{
    (prefix+ready,"User/process attribution active"),
    ("File activity: fanotify PIDFD + inotify names | "+ready,"User/process attribution active"),
    (prefix+"Audit disabled","User/process attribution disabled"),
    (prefix+"Audit connection not verified","Checking user/process attribution"),
    (prefix+"Linux Audit degraded: relay disconnected","User/process attribution needs attention. See Diagnostics."),
    (prefix+"Audit unavailable: IOException","User/process attribution needs attention. See Diagnostics."),
    ("Unknown warning","User/process attribution unconfirmed · See Diagnostics"),
    (prefix+ready+"; degraded","User/process attribution unconfirmed · See Diagnostics"),
    ("FSEvents changes only (no open/read/process attribution)","File changes monitored · User/process attribution unavailable"),
    ("FSEvents + Endpoint Security helper (open intent, not copy proof)","File monitoring configured · User/process attribution unverified"),
    (null,"User/process attribution unconfirmed · See Diagnostics")
};
foreach(var (input,expected) in cases)if(DesktopStatusText.Sensor(input)!=expected)throw new Exception("Desktop presentation case failed");
foreach(var input in new string?[]{prefix+ready,"FSEvents changes only (no open/read/process attribution)",null})
    if(DesktopStatusText.Sensor(input,true)!="User/process attribution unconfirmed")throw new Exception("Stale desktop claimed current attribution");
Console.WriteLine($"PASS: {cases.Length+3} desktop presentation cases. No desktop/service runtime acceptance inferred.");
var healthCases=new (string? Raw,string Expected)[]{(null,"Status unavailable"),("Monitoring","Monitoring"),("Audit evidence gap: unread inbox; input drops 0, rejected 2 | inotify","Monitoring evidence incomplete"),("Management queue failed: IOException","Alert storage needs attention"),("Audit unavailable: Dispatcher executable identity unavailable","Monitoring needs attention"),("Trust policy pending · Automatic response paused","Automatic response paused"),("Unknown engine details","Status unconfirmed · See Diagnostics")};
foreach(var (raw,expected) in healthCases)if(RansomFree.Contracts.EndpointStatusText.Health(raw)!=expected)throw new Exception("Health copy mismatch");
if(RansomFree.Contracts.EndpointStatusText.Delivery("TCP sent to fixture:514; delivery is unconfirmed.")!="Sent · Receipt unconfirmed")throw new Exception("Send falsely confirmed");
if(RansomFree.Contracts.EndpointStatusText.Delivery("Delivery pending: IOException")!="Delivery pending · See Diagnostics")throw new Exception("Delivery exception leaked");
if(RansomFree.Contracts.EndpointStatusText.Connectivity("Offline / sync failed: IOException")!="Offline · Sync pending")throw new Exception("Connection exception leaked");
Console.WriteLine($"PASS: {healthCases.Length+3} shared desktop health/delivery/connection checks.");
if(RansomFree.Contracts.EndpointStatusText.Delivery("Syslog queue full (1000 events); new event retained only in local activity log.")!="Syslog queue full · New alerts at risk")throw new Exception("Queue capacity warning lost");
if(RansomFree.Contracts.EndpointStatusText.Health("Management queue full")!="Alert storage full · New alerts at risk")throw new Exception("Management capacity warning lost");
Console.WriteLine("PASS: 2 full-queue risk warnings remain explicit.");
