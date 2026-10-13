using RansomFree.Contracts;

namespace RansomFree.LinuxAgent.EndpointSecurity;

// Managed semantic contracts ONLY. These values are NOT Apple ABI constants.
internal enum SensorState { Stopped, FallbackOnly, UnsupportedOs, UnsupportedApi, NativeBindingUnavailable, MissingEntitlement, MissingFullDiskAccess, AuthorizationDenied, InsufficientPrivilege, SubscriptionFailed, Running, QueueLoss, ProviderLoss, Failed }
internal enum ObservedOperation { Unknown, OpenIntent, Write, ModifiedClose, Delete, Rename, Permissions }
internal sealed record SensorStatus(SensorState State, bool NativeValidated = false, bool FallbackRunning = false)
{
    public bool RequestedCoverageAvailable => NativeValidated && State == SensorState.Running;
    public string Summary => State switch
    {
        SensorState.Stopped => "Sensor stopped; start monitoring.",
        SensorState.FallbackOnly => "File change monitoring selected; actor attribution is unavailable.",
        SensorState.UnsupportedOs => "Attribution unavailable; use a supported macOS host.",
        SensorState.UnsupportedApi => "Attribution unavailable; use a supported macOS API version.",
        SensorState.NativeBindingUnavailable => "Attribution unavailable; complete the reviewed Apple SDK binding and native acceptance.",
        SensorState.MissingEntitlement => "Attribution unavailable; obtain Apple approval and an entitled signed build.",
        SensorState.MissingFullDiskAccess => "Attribution unavailable; an administrator must approve Full Disk Access.",
        SensorState.AuthorizationDenied => "Attribution denied; review the operating system permission result.",
        SensorState.InsufficientPrivilege => "Attribution unavailable; use the approved service identity.",
        SensorState.SubscriptionFailed => "Attribution unavailable; inspect subscription diagnostics.",
        SensorState.Running when NativeValidated => "Endpoint Security subscribed; inspect per-event evidence limits.",
        SensorState.Running => "Provider subscribed; native attribution acceptance remains pending.",
        SensorState.QueueLoss => "Evidence lost in queue; reduce load and inspect loss counters.",
        SensorState.ProviderLoss => "Provider reported missing evidence; inspect sequence diagnostics.",
        _ => "Attribution failed; inspect diagnostics and restart the sensor."
    };
    public string Display => Summary + (FallbackRunning ? " FSEvents changes only; no actor/open/read attribution." : " FSEvents is not running.");
}

internal sealed record ActorEvidence(string? AuditTokenHex = null, int? Pid = null, int? ParentPid = null,
    string? Executable = null, string? SigningId = null, string? TeamId = null,
    uint? RealUserId = null, uint? EffectiveUserId = null, uint? AuditUserId = null, uint? SessionId = null);

// A future SDK-verified binding must copy all native data during its valid lifetime.
// No pointers, native structs or native integer constants cross this boundary.
// EventId belongs to the provider event and MUST survive retry/dedup unchanged.
internal sealed record ManagedEvent(string EventId, DateTimeOffset ObservedUtc, string ProviderEvent,
    ObservedOperation Operation, string? SourcePath, string? TargetPath, ActorEvidence? Actor,
    byte[] RawEvidence, bool PathTruncated = false, ulong? Sequence = null, ulong? GlobalSequence = null);

internal interface IEndpointSecurityProvider : IDisposable
{
    // Notifications only; no AUTH subscription/response is implemented in this increment.
    // Start reports actual client/subscription results. Failed starts must release partial resources.
    SensorStatus Start(Action<ManagedEvent?> onEvent, Action<long> onLoss);
    // Stop must unsubscribe/delete the client and quiesce callbacks before returning.
    void Stop();
}

internal sealed class UnavailableNativeProvider : IEndpointSecurityProvider
{
    // Retain the R2 construction seam; unsupported hosts never load a native library.
    private readonly SdkNativeProvider provider = new();
    public SensorStatus Start(Action<ManagedEvent?> onEvent, Action<long> onLoss) => provider.Start(onEvent, onLoss);
    public void Stop() => provider.Stop();
    public void Dispose() => provider.Dispose();
}

internal sealed record MappedEvidence(string EventId, DateTimeOffset Time, string Operation, string Path,
    string? Executable, int? Pid, EventAttribution Attribution);
