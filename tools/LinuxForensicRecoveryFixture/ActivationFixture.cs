using RansomFree.Contracts;
using System.Globalization;
using System.Diagnostics;
using System.Security.Cryptography;
using RansomFree.Client;
using RansomFree.Client.Forensics;

// Explicit synthetic control facts for journal-only fixtures. Native source
// qualification must pass its actual map sample and owned pipe receipt instead.
static class ActivationFixture
{
    internal static LinuxForensicJournal.ActivationSample Sample(LinuxForensicJournal journal,string id,string? lost="0",string? error=null)
    {
        var control=journal.ReadSourceControl(id)!;var ready=LinuxControlledLoaderProtocol.ParseReady(control.Ready);
        var command=LinuxControlledLoaderProtocol.ActivationFrame(ready,id);
        return new(2,Guid.NewGuid().ToString("N"),id,ready.Epoch.ToString(CultureInfo.InvariantCulture),new(2,ready.Maps[3],4,8,1,0,"lost"),
            Convert.ToHexString(SHA256.HashData(control.Ready)),Convert.ToHexString(SHA256.HashData(command)),command.Length,lost,error,DateTimeOffset.UtcNow,Stopwatch.GetTimestamp(),Stopwatch.Frequency);
    }
    internal static void BeforeWrite(LinuxForensicJournal journal,string id)=>journal.CommitSourceActivationSample(id,Sample(journal,id));
    internal static LinuxForensicJournal.OwnerMethodReturn OwnerReturn(string id,string method="OPEN",bool success=true)
    {
        var now=DateTimeOffset.UtcNow;var tick=Stopwatch.GetTimestamp();
        return new(1,Guid.NewGuid().ToString("N"),id,method,now,now,tick,tick,Stopwatch.Frequency,success?"returned":"threw",
            success?null:"System.ComponentModel.Win32Exception",success?null:"posix",success?null:"5");
    }
    internal static LinuxOwnedLoaderProcess.PipeWrite Returned(LinuxForensicJournal journal,string id)
    {var now=DateTimeOffset.UtcNow;var sample=journal.ReadSourceActivation(id)!.Sample;var tick=Stopwatch.GetTimestamp();return new(now,now,sample.CommandBytes,sample.CommandBytes,0,0,0,null,sample.CommandSha256,tick,tick,Stopwatch.Frequency);}
}
