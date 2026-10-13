namespace RansomFree;
internal static class BrandIcon
{
    public static System.Drawing.Icon Load()
    {
        using var stream=typeof(BrandIcon).Assembly.GetManifestResourceStream("Quiver.seQuester.Icon")??throw new InvalidOperationException("Application icon is missing.");
        using var icon=new System.Drawing.Icon(stream);return (System.Drawing.Icon)icon.Clone();
    }
}
