namespace RansomFree.Client.Forensics;

// Carries the actual signed-policy admission reason through startup unwind.
// This type alone never authorizes restart; the completed resource/work
// closure outcome must independently satisfy the service recovery gate.
internal sealed class LinuxNativePolicyUnavailableException(string reason)
    : InvalidOperationException("Native signed policy no longer permits this source session")
{
    internal string Reason { get; } = reason;
}
