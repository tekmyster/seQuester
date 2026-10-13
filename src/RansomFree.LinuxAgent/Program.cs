global using Alert=RansomFree.LinuxAgent.Alert;
using System.Runtime.Versioning;
using System.Text.Json;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.DependencyInjection;
using RansomFree;
using RansomFree.Client;
using RansomFree.LinuxAgent;
#if MACOS
[assembly:SupportedOSPlatform("macos")]
#else
[assembly:SupportedOSPlatform("linux")]
#endif

if(!Platform.Supported)throw new PlatformNotSupportedException("This endpoint binary targets "+Platform.Name+" x64/ARM64 only; it is not a management server.");
#if !MACOS
if(args is ["--native-prepare",var nativeRequest]){Console.WriteLine(RansomFree.Client.Forensics.LinuxNativeCompanionService.PrepareInstallation(nativeRequest));return;}
if(args is ["--native-validate"]){Environment.ExitCode=await AuditCommandExit.Run(()=>{Console.WriteLine(RansomFree.Client.Forensics.LinuxNativeCompanionService.ValidateInstallation());return Task.CompletedTask;},Console.Error,"Native installation validation");return;}
if(args is ["--native-companion"])
{
    using var nativeStop=new CancellationTokenSource();
    using var nativeTerm=System.Runtime.InteropServices.PosixSignalRegistration.Create(System.Runtime.InteropServices.PosixSignal.SIGTERM,c=>{c.Cancel=true;nativeStop.Cancel();});
    using var nativeInterrupt=System.Runtime.InteropServices.PosixSignalRegistration.Create(System.Runtime.InteropServices.PosixSignal.SIGINT,c=>{c.Cancel=true;nativeStop.Cancel();});
    using var nativeHangup=System.Runtime.InteropServices.PosixSignalRegistration.Create(System.Runtime.InteropServices.PosixSignal.SIGHUP,c=>c.Cancel=true);
    Environment.ExitCode=await RansomFree.Client.Forensics.LinuxNativeCompanionService.RunAsync(
        message=>Console.WriteLine(JsonSerializer.Serialize(new{Utc=DateTimeOffset.UtcNow,Component="linux-native-companion",Status=message})),nativeStop.Token);
    return;
}
if(args is ["--audit-dispatch"]){await AuditDispatcher.Run();return;}
if(args is ["--audit-collect"]){await AuditDispatcher.Run(true);return;}
if(args is ["--audit-rules"]){AuditRules.Print();return;}
if(args is ["--audit-rules-file"]){AuditRules.Print(true);return;}
if(args is ["--audit-reconcile-rules"]){Environment.ExitCode=await AuditRuleReconciler.Run();return;}
if(args is ["--audit-health"]){Environment.ExitCode=await AuditCommandExit.Run(AuditHealth.AssertLive,Console.Error);return;}
if(args is ["--audit-verify",var canaryPath]){await AuditLiveValidation.Run(canaryPath);return;}
#endif
if(ConfigurationCommands.TryRun(args))return;
var command=args.FirstOrDefault()??"--run";
if(!new[]{"--run","--enroll","--diagnose","--set-password","--verify-maintenance","--status","--validate-config","--version"}.Contains(command))throw new ArgumentException("Use --run, --enroll, --diagnose, --set-password, --verify-maintenance, --status, --validate-config or --version.");
var seen=new HashSet<string>();
for(var i=1;i<args.Length;i+=2)if(!new[]{"--data","--config","--status-path"}.Contains(args[i])||!seen.Add(args[i])||i+1>=args.Length||args[i+1].StartsWith("--"))throw new ArgumentException("Unknown, duplicate or incomplete option.");
if(command=="--version"){Console.WriteLine(Platform.Version);return;}
string Option(string name,string fallback){var i=Array.IndexOf(args,name);return i<0?fallback:i+1<args.Length?args[i+1]:throw new ArgumentException("Missing option value.");}
var statusPath=Option("--status-path",Platform.StatusPath);
if(command=="--status"){var path=Paths.NoLinks(statusPath);if(new FileInfo(path).Length>2097152)throw new IOException("Status exceeds limit.");Console.WriteLine(File.ReadAllText(path));return;}
var directory=Option("--data",Platform.DataPath);
ClientConfiguration ReadConfig()
{
    var configPath=Paths.NoLinks(Option("--config",Platform.ConfigPath));
    if((File.GetUnixFileMode(configPath)&(UnixFileMode.GroupWrite|UnixFileMode.OtherWrite))!=0)throw new IOException("Client configuration must not be writable by ordinary users.");
    if(new FileInfo(configPath).Length>32768)throw new IOException("Client configuration too large.");
    var value=JsonSerializer.Deserialize<ClientConfiguration>(File.ReadAllBytes(configPath),PrivateState.Json)??throw new InvalidDataException("Missing configuration.");
    value.Validate(Paths.NoLinks(directory));return value;
}
if(command=="--diagnose"){using var diagnostic=new ManagementClient(ReadConfig().Server);Console.WriteLine(JsonSerializer.Serialize(await diagnostic.DiagnoseAsync()));return;}
if(command=="--validate-config"){_=ReadConfig();Console.WriteLine("Configuration valid. No enrollment, server probe, monitor or canary deployment executed.");return;}
var state=new PrivateState(directory);
string Secret(string prompt)
{
    Console.Error.WriteLine(prompt);if(Console.IsInputRedirected)return Console.ReadLine()??"";
    var result=new System.Text.StringBuilder();while(true){var key=Console.ReadKey(true);if(key.Key==ConsoleKey.Enter)break;if(key.Key==ConsoleKey.Backspace){if(result.Length>0)result.Length--;continue;}if(!char.IsControl(key.KeyChar)&&result.Length<256)result.Append(key.KeyChar);}Console.Error.WriteLine();return result.ToString();
}
if(command=="--verify-maintenance")
{
    var password=state.Read<PasswordSettings>("password.json");
    if(password==null||!PasswordHash.Verify(Secret("Endpoint maintenance password:"),password)){Environment.ExitCode=3;return;}
    Console.WriteLine("Maintenance verified for this invocation only.");return;
}
using var lease=state.Lease();
if(command=="--set-password")
{
    var old=state.Read<PasswordSettings>("password.json");
    if(old!=null&&!PasswordHash.Verify(Secret("Current endpoint maintenance password:"),old)){Environment.ExitCode=3;return;}
    state.Save("password.json",PasswordHash.Create(Secret("New endpoint maintenance password (12–256 characters):")));return;
}
var config=ReadConfig();
if(command=="--enroll")
{
    var verifier=state.Read<PasswordSettings>("password.json")??throw new InvalidOperationException("Set the endpoint maintenance password first.");
    if(!PasswordHash.Verify(Secret("Endpoint maintenance password:"),verifier)){Environment.ExitCode=3;return;}
    if(File.Exists(state.PathFor("connection.json")))throw new InvalidOperationException("Already enrolled; credentials preserved.");
    using var client=new ManagementClient(config.Server);
    var enrollment=await client.EnrollAsync(new(Secret("One-time enrollment code:"),Environment.MachineName,Platform.Version));
    if(!Guid.TryParseExact(enrollment.EndpointId,"N",out _))throw new InvalidDataException("Invalid enrollment reply.");
    using var validated=new ManagementClient(config.Server,enrollment.Credential);
    state.Save("connection.json",new Connection(config.Server,enrollment.EndpointId,enrollment.Credential),true);
    Console.WriteLine("Enrolled. No canaries deployed and no service started.");return;
}
var builder=Host.CreateApplicationBuilder();
// Native evidence import may still own a descriptor/commit after cancellation.
// Its opt-in service drop-in must likewise allow actual drain, not SIGKILL.
if(config.NativeCompanion.Enabled)builder.Services.Configure<HostOptions>(options=>options.ShutdownTimeout=Timeout.InfiniteTimeSpan);
builder.Services.AddSingleton(state);builder.Services.AddSingleton(config);builder.Services.AddSingleton(new PublicStatus(Paths.NoLinks(statusPath)));
builder.Services.AddHostedService<LinuxWorker>();
await builder.Build().RunAsync();
