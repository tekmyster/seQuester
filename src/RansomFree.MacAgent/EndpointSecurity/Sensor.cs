using System.Threading.Channels;

namespace RansomFree.LinuxAgent.EndpointSecurity;

// Start/Stop are serialized by the owner. Callback work is bounded validation/copy/TryWrite.
internal sealed class EndpointSecuritySensor(IEndpointSecurityProvider provider, IEvidenceStore store,
    Action<MappedEvidence> publish, int capacity = 256) : IDisposable
{
    private Channel<ManagedEvent>? queue;
    private Task? worker;
    private long generation, rejected, queueLost, providerLost, deliveryFailed, accepted, archived;
    private SensorStatus status = new(SensorState.Stopped);
    private bool disposed;
    public SensorStatus Status => Volatile.Read(ref status);
    public (long Accepted, long Archived, long Rejected, long QueueLost, long ProviderLost, long DeliveryFailed) Metrics =>
        (Interlocked.Read(ref accepted), Interlocked.Read(ref archived), Interlocked.Read(ref rejected),
         Interlocked.Read(ref queueLost), Interlocked.Read(ref providerLost), Interlocked.Read(ref deliveryFailed));
    public void Start()
    {
        ObjectDisposedException.ThrowIf(disposed, this);
        Stop();
        if (capacity is < 1 or > 4096) throw new ArgumentOutOfRangeException(nameof(capacity));
        var epoch = Interlocked.Increment(ref generation);
        var channel = Channel.CreateBounded<ManagedEvent>(new BoundedChannelOptions(capacity) { FullMode = BoundedChannelFullMode.Wait, SingleReader = true });
        queue = channel;
        var starting = new SensorStatus(SensorState.SubscriptionFailed);
        status = starting;
        worker = Task.Run(async () =>
        {
            await foreach (var item in channel.Reader.ReadAllAsync())
            {
                try
                {
                    var id = store.Save(item);
                    Interlocked.Increment(ref archived);
                    var mapped = EvidenceMapper.Map(item, id);
                    if (mapped != null) publish(mapped);
                }
                catch { Interlocked.Increment(ref deliveryFailed); Volatile.Write(ref status, new(SensorState.Failed)); }
            }
        });
        try
        {
            var started = provider.Start(item =>
            {
                try
                {
                    if (epoch != Interlocked.Read(ref generation)) { Interlocked.Increment(ref rejected); return; }
                    if (!EvidenceMapper.Valid(item)) { Interlocked.Increment(ref rejected); Volatile.Write(ref status, new(SensorState.Failed)); return; }
                    var owned = item! with { RawEvidence = item!.RawEvidence.ToArray() };
                    if (channel.Writer.TryWrite(owned)) Interlocked.Increment(ref accepted);
                    else { Interlocked.Increment(ref queueLost); Volatile.Write(ref status, new(SensorState.QueueLoss)); }
                }
                catch { Interlocked.Increment(ref rejected); Volatile.Write(ref status, new(SensorState.Failed)); }
            }, count =>
            {
                if (epoch != Interlocked.Read(ref generation) || count <= 0) return;
                Interlocked.Add(ref providerLost, count);
                Volatile.Write(ref status, new(SensorState.ProviderLoss));
            });
            // Do not overwrite loss/failure from synchronous callbacks during Start.
            Interlocked.CompareExchange(ref status, started, starting);
        }
        catch { Volatile.Write(ref status, new(SensorState.Failed)); Stop(); Volatile.Write(ref status, new(SensorState.Failed)); }
    }
    public void Stop()
    {
        Interlocked.Increment(ref generation);
        try { provider.Stop(); }
        finally
        {
            queue?.Writer.TryComplete(); worker?.GetAwaiter().GetResult(); queue = null; worker = null;
            Volatile.Write(ref status, new(SensorState.Stopped));
        }
    }
    public void Dispose()
    {
        if (disposed) return;
        disposed = true;
        try { Stop(); } finally { provider.Dispose(); }
    }
}
