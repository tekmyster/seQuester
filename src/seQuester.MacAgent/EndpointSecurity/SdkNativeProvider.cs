using System.Runtime.InteropServices;
using System.Text.Json;

namespace RansomFree.LinuxAgent.EndpointSecurity;

// Apple structures and constants are confined to Native/sq_es.mm, compiled by the Apple SDK.
internal interface INativeEndpointApi
{
    int Open(out nint handle);
    int Read(nint handle, byte[] buffer, out ulong loss);
    int Close(nint handle);
}

internal sealed class SdkNativeProvider(INativeEndpointApi? injected = null) : IEndpointSecurityProvider
{
    private INativeEndpointApi? api;
    private nint handle;
    private CancellationTokenSource? cancellation;
    private Task? pump;
    private bool disposed, poisoned;
    // Lifecycle is serialized by EndpointSecuritySensor. The pump is the sole native reader.
    public SensorStatus Start(Action<ManagedEvent?> onEvent, Action<long> onLoss)
    {
        ObjectDisposedException.ThrowIf(disposed, this);
        Stop();
        if (poisoned) return new(SensorState.Failed);
        if (injected == null && !OperatingSystem.IsMacOS()) return new(SensorState.UnsupportedOs);
        if (injected == null && !OperatingSystem.IsMacOSVersionAtLeast(11)) return new(SensorState.UnsupportedApi);
        try { api = injected ?? NativeEndpointApi.Instance.Value; }
        catch (Exception e) when (e is DllNotFoundException or EntryPointNotFoundException or BadImageFormatException or FileNotFoundException)
        { return new(SensorState.NativeBindingUnavailable); }
        int result = api.Open(out handle);
        if (result != 0)
        {
            // ABI promises no handle on failed open. Defend against a broken bridge anyway.
            if (handle != 0) { api.Close(handle); handle = 0; poisoned = true; }
            return new(result switch
            {
                1 => SensorState.MissingEntitlement,
                // NOT_PERMITTED is an OS permission denial, not proof of a specific FDA/TCC setting.
                2 => SensorState.AuthorizationDenied,
                3 => SensorState.InsufficientPrivilege,
                4 => SensorState.SubscriptionFailed,
                _ => SensorState.Failed
            });
        }
        if (handle == 0) { poisoned = true; return new(SensorState.Failed); }
        cancellation = new();
        var token = cancellation.Token;
        pump = Task.Run(async () =>
        {
            var buffer = new byte[65536];
            try
            {
                while (!token.IsCancellationRequested)
                {
                    int length = api.Read(handle, buffer, out ulong loss);
                    if (loss != 0) onLoss((long)Math.Min(loss, (ulong)long.MaxValue));
                    if (length < 0 || length > buffer.Length) { onLoss(1); return; }
                    if (length == 0) { await Task.Delay(20, token); continue; }
                    try { onEvent(Decode(buffer.AsSpan(0, length))); }
                    catch { onLoss(1); }
                }
            }
            catch (OperationCanceledException) when (token.IsCancellationRequested) { }
            catch { try { onLoss(1); } catch { } }
        });
        // Subscription succeeds independently of deployment/native acceptance. Do not acknowledge
        // requested coverage until the frozen adapter passes the external native acceptance gates.
        return new(SensorState.Running, NativeValidated: false);
    }

    internal static ManagedEvent Decode(ReadOnlySpan<byte> bytes)
    {
        if (bytes.Length is 0 or > 65536) throw new InvalidDataException("Native snapshot size.");
        var owned = bytes.ToArray();
        using var json = JsonDocument.Parse(owned, new JsonDocumentOptions { MaxDepth = 8 });
        var root = json.RootElement;
        if (root.GetProperty("schema").GetInt32() != 1) throw new InvalidDataException("Native snapshot schema.");
        long nanos = root.GetProperty("nanoseconds").GetInt64();
        if (nanos is < 0 or >= 1000000000) throw new InvalidDataException("Native event time.");
        var time = DateTimeOffset.FromUnixTimeSeconds(root.GetProperty("seconds").GetInt64()).AddTicks(nanos / 100);
        string name = root.GetProperty("event").GetString() ?? throw new InvalidDataException("Native event name.");
        string operationName = root.GetProperty("operation").GetString() ?? "Unknown";
        // Explicit names avoid interpreting Apple integer values or arbitrary numeric enum strings.
        var operation = (name, operationName) switch
        {
            ("NOTIFY_OPEN", "OpenIntent") => ObservedOperation.OpenIntent,
            ("NOTIFY_WRITE", "Write") => ObservedOperation.Write,
            ("NOTIFY_CLOSE", "ModifiedClose") when root.GetProperty("details").GetProperty("modified").GetBoolean() => ObservedOperation.ModifiedClose,
            ("NOTIFY_UNLINK", "Delete") => ObservedOperation.Delete,
            ("NOTIFY_RENAME", "Rename") => ObservedOperation.Rename,
            ("NOTIFY_SETMODE", "Permissions") => ObservedOperation.Permissions,
            _ => ObservedOperation.Unknown
        };
        return new(Guid.NewGuid().ToString("N"), time, name, operation,
            root.GetProperty("source").GetString(), root.TryGetProperty("target", out var target) ? target.GetString() : null,
            root.TryGetProperty("actor", out var actor) ? actor.Deserialize<ActorEvidence>() : null, owned,
            root.GetProperty("truncated").GetBoolean(),
            root.TryGetProperty("sequence", out var sequence) ? sequence.GetUInt64() : null,
            root.TryGetProperty("globalSequence", out var global) ? global.GetUInt64() : null);
    }

    public void Stop()
    {
        cancellation?.Cancel();
        // The bridge read is a bounded buffer copy. The only callbacks are the existing bounded
        // Sensor callbacks; no IO/publication is performed here. Native close waits at most two
        // seconds for OS deletion, then isolates the still-owned state and disables further starts.
        pump?.GetAwaiter().GetResult(); pump = null;
        cancellation?.Dispose(); cancellation = null;
        if (handle != 0)
        {
            var closing = handle; handle = 0;
            if (api!.Close(closing) != 0) { poisoned = true; throw new IOException("Endpoint Security client shutdown failed; restart required."); }
        }
    }
    public void Dispose() { if (disposed) return; try { Stop(); } finally { disposed = true; } }
}

internal sealed class NativeEndpointApi : INativeEndpointApi
{
    internal static readonly Lazy<NativeEndpointApi> Instance = new(() => new());
    [UnmanagedFunctionPointer(CallingConvention.Cdecl)] private delegate uint Abi();
    [UnmanagedFunctionPointer(CallingConvention.Cdecl)] private delegate int OpenClient(out nint handle);
    [UnmanagedFunctionPointer(CallingConvention.Cdecl)] private delegate int ReadClient(nint handle, [Out] byte[] bytes, uint capacity, out ulong loss);
    [UnmanagedFunctionPointer(CallingConvention.Cdecl)] private delegate int CloseClient(nint handle);
    private readonly OpenClient open;
    private readonly ReadClient read;
    private readonly CloseClient close;
    private NativeEndpointApi()
    {
        // Absolute application-local path; no current-directory or environment library search.
        nint library = NativeLibrary.Load(Path.Combine(AppContext.BaseDirectory, "libsequester_es.dylib"));
        try
        {
            T Bind<T>(string name) where T : Delegate => Marshal.GetDelegateForFunctionPointer<T>(NativeLibrary.GetExport(library, name));
            if (Bind<Abi>("sq_es_abi")() != 1) throw new BadImageFormatException("Endpoint Security bridge ABI mismatch.");
            open = Bind<OpenClient>("sq_es_open"); read = Bind<ReadClient>("sq_es_read"); close = Bind<CloseClient>("sq_es_close");
            // Process lifetime residency: a failed es_delete_client may retain its native block.
        }
        catch { NativeLibrary.Free(library); throw; }
    }
    public int Open(out nint handle) => open(out handle);
    public int Read(nint handle, byte[] buffer, out ulong loss) => read(handle, buffer, (uint)buffer.Length, out loss);
    public int Close(nint handle) => close(handle);
}
