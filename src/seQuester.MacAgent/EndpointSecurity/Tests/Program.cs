#if SQ_ES_TESTS
using System.Text;
using RansomFree.LinuxAgent.EndpointSecurity;

static class Program
{
    static int checks;
    static void Check(bool value, string name) { if (!value) throw new Exception(name); checks++; }
    static readonly byte[] Snapshot = Encoding.UTF8.GetBytes("""
        {"schema":1,"seconds":1700000000,"nanoseconds":123456789,"event":"NOTIFY_OPEN","operation":"OpenIntent","source":"/canary","truncated":false,"details":{"fflag":1},"sequence":9,"globalSequence":12}
        """);
    static void Main()
    {
        var e = SdkNativeProvider.Decode(Snapshot);
        Check(e.Operation == ObservedOperation.OpenIntent, "open intent only");
        Check(e.Actor == null, "missing actor stays null");
        Check(e.Sequence == 9 && e.GlobalSequence == 12, "sequences");
        Check(e.ObservedUtc == DateTimeOffset.FromUnixTimeSeconds(1700000000).AddTicks(1234567), "event time");
        Check(e.RawEvidence.SequenceEqual(Snapshot), "raw snapshot");
        Check(!ReferenceEquals(e.RawEvidence, Snapshot), "owned bytes");
        Check(Guid.TryParseExact(e.EventId, "N", out _), "provider event identity");
        var unknown = Encoding.UTF8.GetBytes(Encoding.UTF8.GetString(Snapshot).Replace("OpenIntent", "1"));
        Check(SdkNativeProvider.Decode(unknown).Operation == ObservedOperation.Unknown, "no numeric enum coercion");
        foreach (var invalid in new[] { Array.Empty<byte>(), new byte[65537], Encoding.UTF8.GetBytes("{}"), Encoding.UTF8.GetBytes(Encoding.UTF8.GetString(Snapshot).Replace("123456789", "1000000000")) })
        { bool rejected = false; try { SdkNativeProvider.Decode(invalid); } catch { rejected = true; } Check(rejected, "invalid snapshot"); }
        foreach (var (result, expected) in new[] { (1, SensorState.MissingEntitlement), (2, SensorState.AuthorizationDenied), (3, SensorState.InsufficientPrivilege), (4, SensorState.SubscriptionFailed), (5, SensorState.Failed), (6, SensorState.Failed) })
        {
            var api = new Fake { Result = result };
            using var provider = new SdkNativeProvider(api);
            Check(provider.Start(_ => throw new Exception(), _ => throw new Exception()).State == expected, "start failure mapping");
            Check(api.Closed == 0, "no invented client cleanup");
        }
        var success = new Fake { Data = Snapshot, Loss = 3 };
        using (var provider = new SdkNativeProvider(success))
        {
            using var received = new ManualResetEventSlim();
            long loss = 0; int events = 0;
            var status = provider.Start(_ => { Interlocked.Increment(ref events); received.Set(); }, n => Interlocked.Add(ref loss, n));
            Check(status.State == SensorState.Running && !status.RequestedCoverageAvailable, "subscription not acceptance");
            Check(received.Wait(TimeSpan.FromSeconds(5)), "snapshot pumped");
            provider.Stop();
            Check(loss == 3 && events == 1, "loss and single event");
            Check(success.Closed == 1 && success.ActiveReads == 0, "reader quiesced before close");
            provider.Start(_ => {}, _ => {}); provider.Stop();
            Check(success.Closed == 2, "restart lifecycle");
        }
        var failedClose = new Fake { CloseResult = 6 };
        using (var provider = new SdkNativeProvider(failedClose))
        {
            provider.Start(_ => {}, _ => {});
            bool failed = false; try { provider.Stop(); } catch (IOException) { failed = true; }
            Check(failed, "shutdown error surfaced");
            Check(provider.Start(_ => {}, _ => {}).State == SensorState.Failed, "failed shutdown cannot restart");
        }
        if (!OperatingSystem.IsMacOS())
        {
            using var provider = new UnavailableNativeProvider();
            Check(provider.Start(_ => {}, _ => {}).State == SensorState.UnsupportedOs, "non mac no native load");
        }
        Console.WriteLine($"PASS {checks} managed adapter checks. Native SDK/Intel/arm64/lifetime/permissions tests NOT RUN.");
    }
    sealed class Fake : INativeEndpointApi
    {
        public int Result, CloseResult, Closed, ActiveReads;
        public byte[]? Data;
        public ulong Loss;
        public int Open(out nint handle) { handle = Result == 0 ? 1 : 0; return Result; }
        public int Read(nint handle, byte[] buffer, out ulong loss)
        {
            Interlocked.Increment(ref ActiveReads);
            try { loss = Loss; Loss = 0; var data = Interlocked.Exchange(ref Data, null); data?.CopyTo(buffer, 0); return data?.Length ?? 0; }
            finally { Interlocked.Decrement(ref ActiveReads); }
        }
        public int Close(nint handle) { Check(ActiveReads == 0, "close reader race"); Closed++; return CloseResult; }
    }
}
#endif
