using System.Security.Cryptography;
using System.Text.Json;
using RansomFree.Contracts;

namespace RansomFree.LinuxAgent.EndpointSecurity;

internal static class EvidenceMapper
{
    public const int MaxRawBytes = 65536;
    private static bool Text(string? value, int max) => value == null || value.Length <= max && !value.Any(char.IsControl);
    public static bool Valid(ManagedEvent? e) => e != null && Guid.TryParseExact(e.EventId, "N", out _)
        && e.ObservedUtc != default && Text(e.ProviderEvent, 100) && !string.IsNullOrEmpty(e.ProviderEvent)
        && Text(e.SourcePath, 4096) && Text(e.TargetPath, 4096)
        && (e.SourcePath == null || e.SourcePath.StartsWith('/')) && (e.TargetPath == null || e.TargetPath.StartsWith('/'))
        && e.RawEvidence is { Length: > 0 and <= MaxRawBytes }
        && (e.Actor is not {} a || (a.Pid is null or > 0 && a.ParentPid is null or >= 0
            && Text(a.Executable, 4096) && Text(a.SigningId, 512) && Text(a.TeamId, 512)
            && (a.AuditTokenHex == null || a.AuditTokenHex.Length <= 128 && a.AuditTokenHex.Length > 0 && a.AuditTokenHex.All(Uri.IsHexDigit))));

    public static MappedEvidence? Map(ManagedEvent e, string evidenceId)
    {
        if (!Valid(e)) throw new InvalidDataException("Malformed managed evidence.");
        var operation = e.Operation switch
        {
            ObservedOperation.OpenIntent => "File opened (read/write intent)",
            ObservedOperation.Write => "Canary write",
            ObservedOperation.ModifiedClose => "Canary close after modification",
            ObservedOperation.Delete => "Canary deleted",
            ObservedOperation.Rename => "Canary renamed",
            ObservedOperation.Permissions => "Canary permissions changed",
            _ => null
        };
        // Unknown or unrepresentable paths stay in raw evidence, never a fabricated alert path.
        if (operation == null || e.PathTruncated || e.SourcePath is not { Length: > 1 and <= 1024 }) return null;
        var a = e.Actor;
        var hasActor = a != null && (a.Pid != null || a.AuditTokenHex != null || a.Executable != null
            || a.SigningId != null || a.TeamId != null || a.RealUserId != null || a.EffectiveUserId != null || a.AuditUserId != null);
        var attribution = new EventAttribution
        {
            Provider = "macOS Endpoint Security", Level = hasActor ? "Partial attribution" : "Detection only",
            Basis = "Observed notification only; raw actor, signing and path lineage retained in local evidence. Native acceptance remains required.",
            EvidenceId = evidenceId, UserId = a?.RealUserId, EffectiveUserId = a?.EffectiveUserId,
            LoginUserId = a?.AuditUserId, SessionId = a?.SessionId, ParentProcessId = a?.ParentPid,
            EventTimeCredentials = a?.RealUserId != null || a?.EffectiveUserId != null || a?.AuditUserId != null,
            CompleteRecordSet = false, PathRole = e.Operation == ObservedOperation.Rename ? "source" : "observed"
        };
        return new(e.EventId, e.ObservedUtc, operation, e.SourcePath,
            a?.Executable is { Length: <= 1024 } ? a.Executable : null, a?.Pid, attribution);
    }
}

internal interface IEvidenceStore { string Save(ManagedEvent item); }

// Persist raw provider bytes AND the semantic snapshot before publishing a reference.
// Fixed quota, no eviction: on exhaustion retain existing evidence and stop new publication.
internal sealed class FileEvidenceStore(string directory, int maxFiles = 4096) : IEvidenceStore
{
    public string Save(ManagedEvent item)
    {
        if (!EvidenceMapper.Valid(item)) throw new InvalidDataException("Malformed evidence.");
        if (maxFiles < 1) throw new ArgumentOutOfRangeException(nameof(maxFiles));
        var bytes = JsonSerializer.SerializeToUtf8Bytes(item);
        var hash = Convert.ToHexString(SHA256.HashData(bytes)).ToLowerInvariant();
        var path = Path.Combine(directory, hash + ".json");
        // Caller supplies an existing private evidence directory; never follow a directory link.
        var info = new DirectoryInfo(directory);
        for (DirectoryInfo? parent = info; parent != null; parent = parent.Parent)
            if ((parent.Attributes & FileAttributes.ReparsePoint) != 0) throw new IOException("Evidence directory is linked.");
        if (File.Exists(path))
        {
            var existing = new FileInfo(path);
            if ((existing.Attributes & FileAttributes.ReparsePoint) != 0 || existing.Length != bytes.Length
                || !File.ReadAllBytes(path).AsSpan().SequenceEqual(bytes)) throw new IOException("Evidence identity conflict.");
            return "macos-es:sha256:" + hash;
        }
        if (Directory.EnumerateFiles(directory).Take(maxFiles).Count() >= maxFiles) throw new IOException("Evidence quota full.");
        var options = new FileStreamOptions { Mode = FileMode.CreateNew, Access = FileAccess.Write, Share = FileShare.None };
        if (!OperatingSystem.IsWindows()) options.UnixCreateMode = UnixFileMode.UserRead | UnixFileMode.UserWrite;
        using (var output = new FileStream(path, options)) { output.Write(bytes); output.Flush(true); }
        return "macos-es:sha256:" + hash;
    }
}
