using System.Diagnostics;
using System.Security.Cryptography;
using System.Text.Json;
using RansomFree.Contracts;

namespace RansomFree.Client.Forensics;

// The installed host must supply a root-validated pin/configuration and its owned
// journal. A new process generates a new unpredictable challenge; persisted
// policy receipts alone cannot reconstruct challenge or suppression authority.
internal sealed class LinuxNativePolicyAdmission:IDisposable
{
    private readonly LinuxForensicJournal journal;
    private readonly string server,sensor;
    private readonly byte[] publicKey;
    private readonly Func<DateTimeOffset> utc;
    private readonly Func<long> ticks;
    private readonly long frequency;
    private readonly object gate=new();
    private readonly object lease;
    private bool disposed;
    private LinuxNativePolicyLease? activePolicy;
    private string? challenge;
    private long requested;
    internal LinuxNativePolicyAdmission(LinuxForensicJournal journal,string server,string sensor,byte[] pinnedPublicKey,
        Func<DateTimeOffset>? utc=null,Func<long>? ticks=null,long? frequency=null)
    {
        if(!Guid.TryParseExact(sensor,"N",out _)||!NativePolicySnapshot.ValidOrigin(server))throw new ArgumentException("Root policy configuration invalid");
        this.journal=journal;this.server=server;this.sensor=sensor;publicKey=pinnedPublicKey.ToArray();
        using var key=RSA.Create();key.ImportSubjectPublicKeyInfo(publicKey,out var used);
        if(used!=publicKey.Length||key.KeySize is not (3072 or 4096))throw new InvalidDataException("Root policy verification pin invalid");
        this.utc=utc??(()=>DateTimeOffset.UtcNow);this.ticks=ticks??Stopwatch.GetTimestamp;this.frequency=frequency??Stopwatch.Frequency;
        if(this.frequency<=0)throw new ArgumentException("Monotonic frequency required");
        lease=journal.AcquireNativePolicyOwner(server,SignedNativePolicy.PublicKeyId(publicKey));
    }
    internal string Request()
    {lock(gate){ObjectDisposedException.ThrowIf(disposed,this);requested=ticks();challenge=Convert.ToHexString(RandomNumberGenerator.GetBytes(32));return challenge;}}
    internal bool IsActiveLease(LinuxNativePolicyLease value){lock(gate)return !disposed&&ReferenceEquals(activePolicy,value)&&value.IsCurrent;}
    internal void RequireInstallation(LinuxNativeInstallation.Configuration configuration,LinuxForensicJournal expectedJournal)
    {
        lock(gate)
        {
            ObjectDisposedException.ThrowIf(disposed,this);
            if(!ReferenceEquals(journal,expectedJournal)||server!=configuration.Server||sensor!=configuration.SensorId||Convert.ToBase64String(publicKey)!=configuration.PublicKeyBase64)
                throw new InvalidDataException("Policy owner differs from the root-installed server, sensor, key or journal");
        }
    }
    private void RequireCurrent()
    {
        var current=ticks();
        if(challenge==null||current<requested||(decimal)current-requested>30m*frequency)
            throw new InvalidDataException("Root policy challenge absent, expired or monotonic clock regressed");
    }
    internal NativePolicySnapshot Accept(SignedNativePolicy relayed,Action<string>? checkpoint=null)
    {
        lock(gate)
        {
            ObjectDisposedException.ThrowIf(disposed,this);
            RequireCurrent();var frozen=JsonSerializer.Deserialize<SignedNativePolicy>(JsonSerializer.SerializeToUtf8Bytes(relayed))!;
            var snapshot=frozen.Verify(publicKey,server,sensor,challenge!,utc());RequireCurrent();
            // A verified replacement may revoke a prior exception. A failed or
            // unknown commit must not leave that superseded exception active.
            activePolicy?.Invalidate();
            journal.CommitNativePolicy(frozen,snapshot,checkpoint);RequireCurrent();
            var admittedUtc=utc();
            if(snapshot.IssuedUtc>admittedUtc.AddSeconds(30)||snapshot.ExpiresUtc<=admittedUtc)
                throw new InvalidDataException("Root policy expired or clock moved during durable commit");
            challenge=null;
            // Caller must preserve this exact snapshot for its source revision,
            // enforce expiry during evaluation, and stop/drain on binding changes.
            return snapshot;
        }
    }
    internal LinuxNativePolicyLease AcceptLease(SignedNativePolicy relayed,Action<string>? checkpoint=null)
    {
        lock(gate)
        {
            var snapshot=Accept(relayed,checkpoint);var acceptedTicks=ticks();var acceptedUtc=utc();
            if(snapshot.IssuedUtc>acceptedUtc.AddSeconds(30)||snapshot.ExpiresUtc<=acceptedUtc)throw new InvalidDataException("Native policy expired before lease creation");
            var next=new LinuxNativePolicyLease(snapshot,acceptedUtc,acceptedTicks,frequency,utc,ticks);
            if(!next.IsCurrent)throw new InvalidDataException("Native policy lifetime unavailable");return activePolicy=next;
        }
    }
    public void Dispose()
    {
        lock(gate)
        {
            if(disposed)return;
            // A rejected release retains both the lease and its challenge.
            // The host must finish actual native close before retrying.
            journal.ReleaseNativePolicyOwner(lease);activePolicy?.Invalidate();challenge=null;disposed=true;
        }
    }
}
