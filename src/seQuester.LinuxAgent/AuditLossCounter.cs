namespace RansomFree.LinuxAgent;

internal static class AuditLossCounter
{
    public static long Delta(long current,long previous)
    {
        if(previous<0||current<previous)throw new InvalidDataException("Invalid relay loss counter.");
        return current-previous;
    }
}
