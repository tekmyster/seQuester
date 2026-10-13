using System.IO.Compression;
using System.Text;
using RansomFree.Callbacks;

namespace RansomFree.Server;

// Generation only. Never opens the UNC resource, resolves DNS or changes host attributes.
internal static class WindowsFolderToken
{
    public static byte[] Render(CallbackToken token,string zone)
    {
        if(!CallbackStorage.ValidId(token.Id) || Uri.CheckHostName(zone)!=UriHostNameType.Dns || zone.Length>190)
            throw new ArgumentException("A valid token and DNS zone are required.");
        using var buffer=new MemoryStream();
        using(var archive=new ZipArchive(buffer,ZipArchiveMode.Create,true))
        {
            // Fixed archive paths prevent token display names becoming extraction paths.
            var folder=archive.CreateEntry("CanaryFolder/");
            folder.ExternalAttributes=(int)(FileAttributes.Directory|FileAttributes.System|FileAttributes.ReadOnly);
            var ini=archive.CreateEntry("CanaryFolder/desktop.ini");
            ini.ExternalAttributes=(int)(FileAttributes.Hidden|FileAttributes.System);
            using(var writer=new StreamWriter(ini.Open(),new UnicodeEncoding(false,true)))
                writer.Write($"[.ShellClassInfo]\r\nIconFile=\\\\{token.Id}.{zone}\\canary\\folder.ico\r\nIconIndex=0\r\n");
            var guide=archive.CreateEntry("DEPLOYMENT.txt");
            using var text=new StreamWriter(guide.Open(),new UTF8Encoding(false));
            text.Write("""
                Ransom Free - Windows folder DNS tripwire (development, untested)

                This artifact requests an icon at a token-specific UNC hostname. The supplied
                receiver records DNS queries and returns NXDOMAIN; it does not serve SMB or
                collect Windows authentication. Do not configure an A/AAAA/CNAME/wildcard
                for token hostnames or point them at a file server. Such a change could cause
                outbound authentication. Do not weaken enterprise remote-icon policy.

                Deployment is an explicit administrator action, not performed by download:
                1. Delegate the token DNS zone to the configured receiver and review egress.
                2. Extract into a new, approved folder. Never overwrite an existing desktop.ini.
                3. Preserve the folder's System/ReadOnly and desktop.ini's Hidden/System bits.
                   Some extractors drop DOS attributes; verify them before acceptance testing.
                4. Test with the exact Windows/Explorer version and existing security policy.

                Browsing or extraction may trigger a DNS query; copy alone is not guaranteed.
                Explorer caching, disabled remote icons and modern Windows policies can stop
                activation. Thinkst documents Windows 11 compatibility limitations. This is
                not a promise of support on every Windows version. Local agent monitoring is
                separate and does not depend on this icon mechanism.

                To retire: revoke the token in management. Remove only this owned desktop.ini
                and restore the folder's original attributes through reviewed local maintenance.
                Revocation stops recording future queries; it cannot remove distributed copies.

                A hit identifies the token and DNS resolver, not the browsing user or process.
                No scripts, commands, binaries or automatic configuration changes are included.
                """);
        }
        return buffer.ToArray();
    }
}
