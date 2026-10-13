using System.Text;
using RansomFree.Callbacks;

namespace RansomFree.Server;

internal static class DnsDiagnosticTokens
{
    public static byte[] Render(CallbackToken token,string zone)
    {
        if(!CallbackStorage.ValidId(token.Id)||Uri.CheckHostName(zone)!=UriHostNameType.Dns||zone.Length>190)throw new ArgumentException("Invalid DNS token configuration.");
        var host=token.Id+"."+zone;
        if(token.Type=="log4shell")
            return Encoding.UTF8.GetBytes("# Authorized diagnostic canary only; do not inject into third-party systems.\n# Requires a vulnerable/configured Log4j JNDI lookup path. Patched or disabled lookup behavior should not activate it.\n# DNS-only: no LDAP/RMI server, class loading, commands, environment data or hostname interpolation.\n# The receiver records resolver activity and returns NXDOMAIN. No callback does not establish that a system is safe.\n${jndi:dns://"+host+"/canary}\n");
        if(token.Type=="mysql")
        {
            // Hex literal avoids dependence on NO_BACKSLASH_ESCAPES or string escaping.
            var path=Convert.ToHexString(Encoding.UTF8.GetBytes("\\\\"+host+"\\canary\\inventory.txt"));
            return Encoding.UTF8.GetBytes("-- Ransom Free MySQL import DNS tripwire: Windows-hosted MySQL only, untested.\n-- Requires existing FILE privilege and compatible secure_file_priv / OS path policy.\n-- Do not grant privileges or weaken configuration to make this fire.\n-- Execute only in an approved isolated import workflow. It creates/changes no tables.\n-- Token hostname must stay NXDOMAIN: never add address/wildcard records or SMB service.\n-- Otherwise UNC access could initiate outbound Windows authentication.\n-- File reading is expected to fail; the signal is DNS resolution, not a successful file read.\n-- No callback proves neither absence of access nor safety. Linux MySQL is not supported by this variant.\nSELECT LOAD_FILE(CONVERT(0x"+path+" USING utf8mb4)) AS archive_reference;\n");
        }
        throw new ArgumentException("Unsupported DNS diagnostic mechanism.");
    }
}
