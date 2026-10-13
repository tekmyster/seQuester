using System.Text.Json;
using RansomFree.Contracts;

namespace RansomFree.Client;

// This cache belongs in the service's protected state directory, not a user profile.
// Authentication is supplied by ManagementClient's HTTPS channel; a digest is not a signature.
public sealed class TrustPolicyCache
{
    private readonly string path, endpoint, server;
    private readonly object gate = new();
    private AssignedTrustPolicy? current;
    private bool damaged;
    private sealed record Saved(int Version, string Server, AssignedTrustPolicy Assignment);
    public TrustPolicyCache(string directory, string endpointId, string serverOrigin)
    {
        if (!Guid.TryParseExact(endpointId, "N", out _) || !Path.IsPathFullyQualified(directory)) throw new ArgumentException("Invalid trust cache location or enrollment.");
        if (!Uri.TryCreate(serverOrigin, UriKind.Absolute, out var origin) || origin.Scheme != "https" || origin.AbsolutePath != "/" || origin.UserInfo.Length != 0 || origin.Query.Length != 0 || origin.Fragment.Length != 0) throw new ArgumentException("Invalid management origin.");
        endpoint = endpointId; server = origin.AbsoluteUri; path = Path.Combine(directory, "managed-trust.json");
    }
    public AssignedTrustPolicy? Current { get { lock (gate) return Clone(current); } }
    public string? Warning(string? group,DateTimeOffset now)
    {
        lock(gate)return damaged||current==null||current.GroupId!=group||current.ExpiresUtc<=now||current.IssuedUtc>now.AddMinutes(1)?"Trust policy pending · Automatic response paused":null;
    }
    static AssignedTrustPolicy? Clone(AssignedTrustPolicy? value) => value == null ? null : JsonSerializer.Deserialize<AssignedTrustPolicy>(JsonSerializer.SerializeToUtf8Bytes(value));
    static void NoLinks(string file)
    {
        for (var entry = new FileInfo(file) as FileSystemInfo; entry != null; entry = entry is FileInfo f ? f.Directory : ((DirectoryInfo)entry).Parent)
            if ((File.Exists(entry.FullName) || Directory.Exists(entry.FullName)) && (entry.Attributes & FileAttributes.ReparsePoint) != 0) throw new InvalidDataException("Trust cache cannot use linked paths.");
    }
    public void Load()
    {
        lock (gate)
        {
            try
            {
                NoLinks(path);
                if (!File.Exists(path)) { if (current != null) damaged = true; return; }
                if (new FileInfo(path).Length > 524288) throw new InvalidDataException("Trust cache exceeds its size limit.");
                using var stream = File.OpenRead(path);
                var saved = JsonSerializer.Deserialize<Saved>(stream) ?? throw new InvalidDataException("Invalid trust cache.");
                if (saved.Version != 1 || saved.Server != server || saved.Assignment == null) throw new InvalidDataException("Trust cache belongs to another server.");
                ValidateIdentity(saved.Assignment); current = Clone(saved.Assignment); damaged = false;
            }
            catch { damaged = true; throw; }
        }
    }
    void ValidateIdentity(AssignedTrustPolicy value)
    {
        value.Validate();
        if (value.EndpointId != endpoint) throw new InvalidDataException("Trust cache belongs to another endpoint.");
    }
    // Persist before acknowledging; a failed write leaves the previous assignment in force.
    public void Save(AssignedTrustPolicy assignment, DateTimeOffset now)
    {
        lock (gate)
        {
            var next = Clone(assignment) ?? throw new InvalidDataException("Trust assignment missing.");
            ValidateIdentity(next);
            if (next.IssuedUtc > now.AddMinutes(1) || next.ExpiresUtc <= now) throw new InvalidDataException("Trust assignment is not current.");
            if (current != null && (next.Policy.Revision < current.Policy.Revision || next.IssuedUtc < current.IssuedUtc || next.Policy.Revision == current.Policy.Revision && next.Digest != current.Digest)) throw new InvalidDataException("Trust policy replay or conflicting revision.");
            NoLinks(path);
            if (damaged) throw new InvalidDataException("Trust cache needs administrator recovery; existing evidence preserved.");
            var temporary = path + "." + Guid.NewGuid().ToString("N") + ".tmp";
            try
            {
                var options = new FileStreamOptions { Mode = FileMode.CreateNew, Access = FileAccess.Write, Share = FileShare.None };
                if (!OperatingSystem.IsWindows()) options.UnixCreateMode = UnixFileMode.UserRead | UnixFileMode.UserWrite;
                using (var stream = new FileStream(temporary, options)) { JsonSerializer.Serialize(stream, new Saved(1, server, next)); stream.Flush(true); }
                NoLinks(path); File.Move(temporary, path, true); current = next;
            }
            finally { if (File.Exists(temporary)) File.Delete(temporary); }
        }
    }
    public TrustRuntimeDecision Evaluate(TrustContext context, DateTimeOffset now)
    {
        lock (gate)
        {
            TrustRuntimeDecision Pending(string status) => new(current?.Policy.Revision, current?.Digest, "pending", new(1, "normal", false, true, "normal", [], status));
            if (damaged || current == null) return Pending("Trust policy unavailable. Alerts retained; automatic response paused.");
            if (current.EndpointId != context.Host || current.GroupId != context.Group || context.Organization != current.Organization || current.IssuedUtc > now.AddMinutes(1) || current.ExpiresUtc <= now) return Pending("Trust policy needs refresh. Alerts retained; automatic response paused.");
            if (current.Policy.Mode == "legacy") return new(current.Policy.Revision, current.Digest, "legacy", new(1, "normal", false, false, "normal", [], "Existing policy controls apply."));
            return new(current.Policy.Revision, current.Digest, "enforce", TrustEvaluation.Evaluate(current.Policy.Rules, context, now, current.Policy.ApprovedRules()));
        }
    }
}
