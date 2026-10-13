namespace RansomFree.Contracts;

public static class LocalActorEvidence
{
    private static readonly HashSet<string> RequiredSources = new(StringComparer.Ordinal)
    {
        "Windows audit 4656",
        "Windows audit 4663",
        "File watcher",
        "Integrity check",
        "Linux Audit",
        "Linux fanotify",
        "Linux inotify",
        "Linux periodic metadata",
        "Windows minifilter prototype",
        "Windows minifilter",
        "Windows syscall",
        "Linux eBPF prototype",
        "Linux kernel"
    };

    public static bool IsRequired(string source) => RequiredSources.Contains(source);

    public static bool IsComplete(AgentEvent value) =>
        value.Source!="Windows audit 5145"&&(!IsRequired(value.Source) ||
        value.ProcessId is > 0 && PresentActor(value.User) && PresentProcess(value.Process));

    public static bool IsComplete(string source,string? user,string? process,int? processId) =>
        source!="Windows audit 5145"&&(!IsRequired(source) || processId is > 0 && PresentActor(user) && PresentProcess(process));

    private static bool PresentActor(string? value) => Present(value);

    private static bool PresentProcess(string? value) =>
        Present(value) && !value!.TrimStart().StartsWith("PID ",StringComparison.OrdinalIgnoreCase);

    private static bool Present(string? value)
    {
        if(string.IsNullOrWhiteSpace(value))return false;
        var normalized=value.Trim().ToLowerInvariant();
        return normalized is not ("unknown" or "unavailable" or "unavailable for change notifications" or "n/a" or "na" or "none" or "null" or "not available") &&
            !normalized.StartsWith("unknown ") && !normalized.StartsWith("unavailable ");
    }
}
