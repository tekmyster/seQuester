namespace RansomFree.LinuxAgent;

internal static class AuditCommandExit
{
    // Expected operational failures must fail the unit normally, not create an
    // unhandled-runtime abort/core dump. Never log exception messages or data.
    public static async Task<int> Run(Func<Task> command,TextWriter error,string component="Audit rule")
    {
        try{await command();return 0;}
        catch(Exception ex)
        {
            if(component=="Native installation validation")
            {
                var nativeError=ex is System.ComponentModel.Win32Exception native?native.NativeErrorCode:(int?)null;
                error.WriteLine(component+" unavailable: category="+ex.GetType().Name+"; native_error="+(nativeError?.ToString(System.Globalization.CultureInfo.InvariantCulture)??"unavailable")+"; "+(nativeError==11?"package lease busy; stop the owning service normally before validation.":"installation not validated; inspect protected configuration."));
            }
            else error.WriteLine("Audit rule command failed: category="+ex.GetType().Name+"; coverage unverified; inspect protected status and service result.");
            return 1;
        }
    }
}
