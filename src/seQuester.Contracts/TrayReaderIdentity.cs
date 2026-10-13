using System.Globalization;

namespace RansomFree.Contracts;

public static class TrayReaderIdentity
{
    // Only exact account SIDs. Authorization still compares WindowsIdentity.User,
    // not group membership; approving a group SID does not authorize its members.
    public static bool IsSupported(string? value)
    {
        if(value==null || value.Length>96)return false;
        var parts=value.Split('-');
        if(parts.Length!=8 || parts[0]!="S" || parts[1]!="1" ||
            !(parts[2]=="5" && parts[3]=="21" || parts[2]=="12" && parts[3]=="1"))return false;
        return parts.Skip(4).All(p=>uint.TryParse(p,NumberStyles.None,CultureInfo.InvariantCulture,out var n)&&p==n.ToString(CultureInfo.InvariantCulture));
    }
}
