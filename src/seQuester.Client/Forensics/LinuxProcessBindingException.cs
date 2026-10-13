namespace RansomFree.Client.Forensics;

// Stable collection diagnostics, never inferred by parsing exception messages.
// These failures do not authorize binding a later PID/image to an audit event.
internal sealed class LinuxProcessBindingException(string reason):InvalidOperationException(reason)
{
    internal string Reason {get;}=reason;
    internal const string StartMismatch="LINUX_ACTOR_PROCESS_START_MISMATCH";
    internal const string StartAmbiguous="LINUX_ACTOR_PROCESS_START_ORDER_AMBIGUOUS";
    internal const string ImageMismatch="LINUX_ACTOR_EVENT_IMAGE_MISMATCH";
    internal const string ChangedDuringCapture="LINUX_ACTOR_EXITED_OR_IMAGE_CHANGED_DURING_CAPTURE";

    internal static void RequireStart(string? eventStart,string observedStart,DateTimeOffset birthUpperBound,DateTimeOffset eventTime)
    {
        if(eventStart is not null)
        {
            if(!string.Equals(eventStart,observedStart,StringComparison.Ordinal))throw new LinuxProcessBindingException(StartMismatch);
        }
        else if(birthUpperBound>eventTime)throw new LinuxProcessBindingException(StartAmbiguous);
    }
}
