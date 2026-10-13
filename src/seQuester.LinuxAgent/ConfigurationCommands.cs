using System.Text;
using System.Text.Json;
using System.Xml;

namespace RansomFree.LinuxAgent;

// Offline bootstrap commands. These do not create private state, enroll, contact
// a server or activate monitoring. Installed maintenance still verifies its password.
internal static class ConfigurationCommands
{
    public static bool TryRun(string[] args)
    {
        if(args.Length==0 || !new[]{"--stage-config","--same-server","--package-runtime"}.Contains(args[0]))return false;
        if(!Native.Root)throw new UnauthorizedAccessException("Configuration bootstrap requires root.");
        if(args[0]=="--package-runtime")
        {
            if(args.Length!=2)throw new ArgumentException("Use --package-runtime MANIFEST_JSON.");
            using var input=Native.FileAt(Canonical(args[1]),false);
            using var manifest=JsonDocument.Parse(input);
            var runtime=manifest.RootElement.GetProperty("Runtime").GetString();
            var expected=(OperatingSystem.IsMacOS()?"osx-":"linux-")+(System.Runtime.InteropServices.RuntimeInformation.ProcessArchitecture==System.Runtime.InteropServices.Architecture.Arm64?"arm64":"x64");
            if(runtime!=expected)throw new InvalidDataException("Package architecture mismatch.");
            Console.WriteLine(runtime);return true;
        }
        if(args.Length!=3)throw new ArgumentException("Use --stage-config INPUT_JSON PRIVATE_DIRECTORY or --same-server OLD_JSON NEW_JSON.");
        var config=Read(args[1]);
        if(args[0]=="--same-server")
        {
            if(new Uri(config.Server).GetLeftPart(UriPartial.Authority)!=new Uri(Read(args[2]).Server).GetLeftPart(UriPartial.Authority))
                throw new InvalidDataException("Server migration requires separate enrollment recovery; credentials preserved.");
            return true;
        }
        var stage=Canonical(args[2]);Native.ValidateAdminPath(stage,true,true);
        WriteNew(Path.Combine(stage,"client.json"),JsonSerializer.Serialize(config,PrivateState.Json)+"\n");
#if MACOS
        WriteNew(Path.Combine(stage,"com.ransomfree.endpoint.plist"),LaunchDaemon(config));
#else
        var unit="[Service]\nReadWritePaths=\nReadWritePaths=/var/lib/ransomfree-client /run/ransomfree-client\n";
        if(config.Folders.Count>0)unit+="ReadWritePaths="+string.Join(" ",config.Folders.Values.Select(p=>"\""+p.Replace("%","%%").Replace("\\","\\\\").Replace("\"","\\\"")+"\""))+"\n";
        if(config.Monitor=="fanotify")
        {
            var caps="CAP_SYS_ADMIN CAP_DAC_READ_SEARCH CAP_SYS_PTRACE"+(config.AllowRemoteProcessStop||config.AllowAutomaticProcessStop?" CAP_KILL":"");
            unit+="# Explicit administrator-selected privileged monitoring mode.\nCapabilityBoundingSet="+caps+"\nAmbientCapabilities="+caps+"\n";
        }
        WriteNew(Path.Combine(stage,"10-local.conf"),unit);
#endif
        Console.WriteLine("Configuration staged only. No service started, network contacted or folder permissions changed.");return true;
    }
    private static string Canonical(string path)
    {
        if(Paths.NoLinks(path)!=path)throw new InvalidDataException("Use canonical absolute paths.");
        return path;
    }
    private static ClientConfiguration Read(string path)
    {
        path=Canonical(path);Native.ValidateAdminPath(path,false);
        using var input=Native.FileAt(path,false);
        if(input.Length>32768)throw new InvalidDataException("Configuration exceeds 32 KiB.");
        using var document=JsonDocument.Parse(input,new(){MaxDepth=16});
        Unique(document.RootElement);
        if(document.RootElement.GetProperty("SchemaVersion").GetInt32()!=1)throw new InvalidDataException("Unsupported schema.");
        var config=document.RootElement.Deserialize<ClientConfiguration>(PrivateState.Json)??throw new InvalidDataException("Missing configuration.");
        if(config.Folders==null)throw new InvalidDataException("Approved folders must be an object.");
        foreach(var pathValue in config.Folders.Values)
            if(pathValue==null||pathValue.Length>1800||Canonical(pathValue)!=pathValue)throw new InvalidDataException("Approved folder path is invalid or too long.");
        config.Validate(Platform.DataPath);
        // Validate disabled destinations too, while allowing their empty hostname.
        var syslog=config.Syslog;
        if(syslog.Host==null||syslog.Host.Length>253||syslog.Host.Any(char.IsWhiteSpace)||syslog.Host.Contains('/'))throw new InvalidDataException("Invalid syslog host.");
        (syslog with{Host=syslog.Host.Length==0?"localhost":syslog.Host}).Validate();
        return config;
    }
    private static void Unique(JsonElement value)
    {
        if(value.ValueKind==JsonValueKind.Object)
        {
            var names=new HashSet<string>(StringComparer.Ordinal);
            foreach(var item in value.EnumerateObject()){if(!names.Add(item.Name))throw new InvalidDataException("Duplicate JSON field.");Unique(item.Value);}
        }
        else if(value.ValueKind==JsonValueKind.Array)foreach(var item in value.EnumerateArray())Unique(item);
    }
    private static void WriteNew(string path,string content)
    {
        using var output=Native.FileAt(path,true);
        File.SetUnixFileMode(output.SafeFileHandle,UnixFileMode.UserRead|UnixFileMode.UserWrite);
        output.Write(Encoding.UTF8.GetBytes(content));output.Flush(true);
    }
#if MACOS
    private static string LaunchDaemon(ClientConfiguration config)
    {
        const string root="/Library/Application Support/RansomFree";
        var result=new StringBuilder();
        using(var xml=XmlWriter.Create(result,new(){Indent=true,OmitXmlDeclaration=true}))
        {
            xml.WriteStartElement("plist");xml.WriteAttributeString("version","1.0");xml.WriteStartElement("dict");
            void Key(string value)=>xml.WriteElementString("key",value);
            void Text(string key,string value){Key(key);xml.WriteElementString("string",value);}
            void Number(string key,int value){Key(key);xml.WriteElementString("integer",value.ToString(System.Globalization.CultureInfo.InvariantCulture));}
            Text("Label","com.ransomfree.endpoint");Key("ProgramArguments");xml.WriteStartElement("array");xml.WriteElementString("string",root+"/Current/app/RansomFree.MacAgent");xml.WriteElementString("string","--run");xml.WriteEndElement();
            Text("UserName",config.Monitor=="endpoint-security"?"root":"_ransomfree");Text("GroupName","_ransomfree-ui");Text("WorkingDirectory",root+"/Data");Number("Umask",63);
            Key("RunAtLoad");xml.WriteStartElement("true");xml.WriteEndElement();Key("KeepAlive");xml.WriteStartElement("dict");Key("SuccessfulExit");xml.WriteStartElement("false");xml.WriteEndElement();xml.WriteEndElement();
            Number("ThrottleInterval",30);Number("ExitTimeOut",30);Text("ProcessType","Background");
            Key("EnvironmentVariables");xml.WriteStartElement("dict");Text("DOTNET_ENVIRONMENT","Production");Text("DOTNET_CLI_TELEMETRY_OPTOUT","1");Text("TMPDIR",root+"/Data/tmp");xml.WriteEndElement();
            Text("StandardOutPath",root+"/Logs/agent.log");Text("StandardErrorPath",root+"/Logs/agent-error.log");xml.WriteEndElement();xml.WriteEndElement();
        }
        return result+"\n";
    }
#endif
}
