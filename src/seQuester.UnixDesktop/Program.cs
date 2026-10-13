using Avalonia;

namespace RansomFree.UnixDesktop;

internal static class Program
{
    [STAThread]
    public static int Main(string[] args)
    {
        if(args.SequenceEqual(new[]{"--version"})){Console.WriteLine($"{typeof(Program).Assembly.GetName().Version?.ToString(3)} seQuester Unix desktop (.NET 10)");return 0;}
        if(args.Length!=0){Console.Error.WriteLine("Use RansomFree.UnixDesktop [--version]. Configuration is managed by the administrator.");return 2;}
        if(!OperatingSystem.IsLinux()&&!OperatingSystem.IsMacOS()){Console.Error.WriteLine("This desktop client targets Linux and macOS.");return 2;}
        if(SafeStatusFile.IsRoot){Console.Error.WriteLine("Run the desktop as an approved ordinary user, never as root.");return 2;}
        if(OperatingSystem.IsLinux()&&string.IsNullOrEmpty(Environment.GetEnvironmentVariable("DISPLAY")))
        {Console.Error.WriteLine("A desktop X11/XWayland display is required. Use the agent CLI on headless hosts.");return 2;}
        return AppBuilder.Configure<EndpointApp>().UsePlatformDetect().StartWithClassicDesktopLifetime(args);
    }
}
