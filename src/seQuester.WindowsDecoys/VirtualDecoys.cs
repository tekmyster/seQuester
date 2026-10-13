using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Security.Principal;
using System.Text;
using System.Text.Json;
using System.Xml.Linq;
using Microsoft.Win32.SafeHandles;
using Microsoft.Data.Sqlite;
namespace RansomFree.WindowsDecoys;

public sealed record VirtualDecoyPlan(string Id,string Kind,string Name,string? Drive=null);
public sealed record VirtualDecoyState(VirtualDecoyPlan Plan,string Target,string? TargetIdentity,string MarkerHash,string Owner,string Logon,string State,bool DesiredActive,long Revision,string? LinkIdentity=null,string? LinkHash=null);
public sealed record VirtualDecoyObservation(string Id,string State,bool DesiredActive,string Target,string? Entry,long Revision);

// Windows-only, current non-SYSTEM logon session. This is not a global service mapping,
// persistent boot mount, folder redirect, network share or kernel monitoring driver.
public sealed class VirtualDecoys
{
    private readonly string directory,root,path,owner,logon;
    private sealed record Inventory(int Version,string Root,List<VirtualDecoyState> Items);
    public VirtualDecoys(string stateDirectory,string approvedRoot)
    {
        if(!OperatingSystem.IsWindows())throw new PlatformNotSupportedException();
        using var identity=WindowsIdentity.GetCurrent();if(identity.IsSystem)throw new InvalidOperationException("Global SYSTEM device mappings are not supported by this adapter.");
        owner=identity.User?.Value??throw new InvalidOperationException("Logon identity unavailable.");logon=LogonIdentity(identity.Token);
        directory=LocalFolder(stateDirectory);root=LocalFolder(approvedRoot);
        if(directory.Equals(root,StringComparison.OrdinalIgnoreCase)||directory.StartsWith(root+"\\",StringComparison.OrdinalIgnoreCase)||root.StartsWith(directory+"\\",StringComparison.OrdinalIgnoreCase))throw new ArgumentException("State and deployment folders must be separate and non-nested.");
        path=Path.Combine(directory,"virtual-decoys.db");
        if(File.Exists(Path.Combine(directory,"virtual-decoys.json")))throw new InvalidDataException("Earlier preview inventory requires explicit migration; preserved without adopting its resources.");
    }
    static string LocalFolder(string value)
    {
        if(!Path.IsPathFullyQualified(value)||value.StartsWith("\\\\",StringComparison.Ordinal)||value.Length>180||value.Any(char.IsControl)||value[2..].Contains(':'))throw new ArgumentException("Use a short explicit local folder.");
        var full=Path.GetFullPath(value).TrimEnd('\\');if(full.Length<=3||!Directory.Exists(full))throw new ArgumentException("Approved folder must exist and cannot be a volume root.");
        foreach(var denied in new[]{Environment.GetFolderPath(Environment.SpecialFolder.Windows),Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles),Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86)})if(denied.Length>0&&(full.Equals(denied,StringComparison.OrdinalIgnoreCase)||full.StartsWith(denied+"\\",StringComparison.OrdinalIgnoreCase)))throw new ArgumentException("System and installation folders are not approved roots.");
        using var lease=RansomFree.DeploymentPathLease.Acquire(full);return full;
    }
    static void Validate(VirtualDecoyPlan plan)
    {
        if(!Guid.TryParseExact(plan.Id,"N",out _)||plan.Kind is not ("V02" or "V03")||plan.Name is not {Length:>0 and <=60}||plan.Name.Any(c=>!char.IsAsciiLetterOrDigit(c)&&c is not (' ' or '-' or '_')))throw new ArgumentException("Invalid virtual decoy definition.");
        if(plan.Kind=="V02"&&(plan.Drive is not {Length:2}||plan.Drive[0] is <'E' or >'Z'||plan.Drive[1]!=':')||plan.Kind=="V03"&&plan.Drive!=null)throw new ArgumentException("Use an unused E:–Z: drive for a drive decoy only.");
    }
    string Target(VirtualDecoyPlan p)=>Path.Combine(root,"sq-"+p.Id);
    string Marker(VirtualDecoyPlan p)=>Path.Combine(Target(p),".sequester-owner.json");
    string Entry(VirtualDecoyPlan p)=>p.Kind=="V02"?p.Drive!+"\\":Path.Combine(root,p.Name+"-"+p.Id[..8]+".library-ms");
    static string Digest(byte[] bytes)=>Convert.ToHexString(SHA256.HashData(bytes));
    byte[] MarkerBytes(VirtualDecoyPlan p)=>JsonSerializer.SerializeToUtf8Bytes(new{Product="Quiver seQuester",p.Id,p.Kind,Owner=owner,Target=Target(p)});
    byte[] LibraryBytes(VirtualDecoyPlan p)
    {
        XNamespace ns="http://schemas.microsoft.com/windows/2009/library";
        var document=new XDocument(new XDeclaration("1.0","utf-8",null),new XElement(ns+"libraryDescription",new XElement(ns+"name",p.Name),new XElement(ns+"version",1),new XElement(ns+"isLibraryPinned",false),new XElement(ns+"searchConnectorDescriptionList",new XElement(ns+"searchConnectorDescription",new XElement(ns+"isDefaultSaveLocation",false),new XElement(ns+"isSupported",true),new XElement(ns+"simpleLocation",new XElement(ns+"url",new Uri(Target(p)+"\\").AbsoluteUri))))));
        return Encoding.UTF8.GetBytes(document.ToString());
    }
    Inventory Load()
    {
        using var connection=Open();using var command=connection.CreateCommand();command.CommandText="SELECT payload FROM current_inventory WHERE id=1";var payload=command.ExecuteScalar() as string;
        if(payload==null)return new(1,root,[]);if(payload.Length>1048576)throw new InvalidDataException("Inventory exceeds limit.");
        var value=JsonSerializer.Deserialize<Inventory>(payload)??throw new InvalidDataException("Invalid inventory.");
        if(value.Version!=1||value.Root!=root||value.Items==null||value.Items.Count>1000||value.Items.Select(x=>x.Plan.Id).Distinct().Count()!=value.Items.Count)throw new InvalidDataException("Inventory does not match approved root.");
        foreach(var item in value.Items){Validate(item.Plan);if(item.Target!=Target(item.Plan)||item.Owner!=owner||item.Revision<1||item.MarkerHash!=Digest(MarkerBytes(item.Plan)))throw new InvalidDataException("Ownership or target mismatch.");}return value;
    }
    void Save(Inventory inventory,VirtualDecoyState item,string action)
    {
        var next=inventory.Items.Where(x=>x.Plan.Id!=item.Plan.Id).Append(item).ToList();var payload=JsonSerializer.Serialize(inventory with{Items=next});if(payload.Length>1048576)throw new InvalidDataException("Inventory exceeds limit.");
        using var connection=Open();using var transaction=connection.BeginTransaction();using var command=connection.CreateCommand();command.Transaction=transaction;
        command.CommandText="INSERT INTO virtual_audit(time,actor,logon,action,payload) VALUES($time,$actor,$logon,$action,$item); INSERT INTO current_inventory(id,payload) VALUES(1,$inventory) ON CONFLICT(id) DO UPDATE SET payload=excluded.payload";
        command.Parameters.AddWithValue("$time",DateTimeOffset.UtcNow.ToUnixTimeMilliseconds());command.Parameters.AddWithValue("$actor",owner);command.Parameters.AddWithValue("$logon",logon);command.Parameters.AddWithValue("$action",action);command.Parameters.AddWithValue("$item",JsonSerializer.Serialize(item));command.Parameters.AddWithValue("$inventory",payload);command.ExecuteNonQuery();transaction.Commit();
    }
    SqliteConnection Open()
    {
        foreach(var candidate in new[]{path,path+"-wal",path+"-shm",path+"-journal"})if(File.Exists(candidate)&&(File.GetAttributes(candidate)&FileAttributes.ReparsePoint)!=0)throw new IOException("Inventory cannot use linked files.");
        var connection=new SqliteConnection(new SqliteConnectionStringBuilder{DataSource=path,Pooling=false,DefaultTimeout=5}.ToString());
        try
        {
            connection.Open();using var command=connection.CreateCommand();command.CommandText="PRAGMA user_version";var version=Convert.ToInt64(command.ExecuteScalar());if(version is <0 or >1)throw new InvalidDataException("Unsupported virtual inventory version.");
            if(version==0){command.CommandText="SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'";if(Convert.ToInt64(command.ExecuteScalar())!=0)throw new InvalidDataException("Unrecognized inventory preserved.");command.CommandText="CREATE TABLE current_inventory(id INTEGER PRIMARY KEY CHECK(id=1),payload TEXT NOT NULL); CREATE TABLE virtual_audit(sequence INTEGER PRIMARY KEY AUTOINCREMENT,time INTEGER NOT NULL,actor TEXT NOT NULL,logon TEXT NOT NULL,action TEXT NOT NULL,payload TEXT NOT NULL); PRAGMA user_version=1";command.ExecuteNonQuery();}
            return connection;
        }
        catch{connection.Dispose();throw;}
    }
    T Locked<T>(Func<Inventory,T> work)
    {
        using var statePin=RansomFree.DeploymentPathLease.Acquire(directory);using var rootPin=RansomFree.DeploymentPathLease.Acquire(root);
        var lockPath=Path.Combine(directory,"virtual-decoys.lock");if(File.Exists(lockPath)&&(File.GetAttributes(lockPath)&FileAttributes.ReparsePoint)!=0)throw new IOException("State lock cannot be a link.");
        using var lease=new FileStream(lockPath,FileMode.OpenOrCreate,FileAccess.ReadWrite,FileShare.None);return work(Load());
    }
    public VirtualDecoyState Create(VirtualDecoyPlan plan)=>Locked(inventory=>
    {
        Validate(plan);var old=inventory.Items.SingleOrDefault(x=>x.Plan.Id==plan.Id);if(old!=null){if(old.Plan!=plan)throw new InvalidOperationException("Deployment identity cannot change.");return old;}
        if(inventory.Items.Count>=1000||Directory.Exists(Target(plan))||File.Exists(Target(plan))||plan.Kind=="V03"&&Path.Exists(Entry(plan)))throw new IOException("Target collision; existing objects preserved.");
        if(plan.Kind=="V02"&&Mappings(plan.Drive!).Length!=0)throw new IOException("Drive already exists; no mapping changed.");
        var item=new VirtualDecoyState(plan,Target(plan),null,Digest(MarkerBytes(plan)),owner,logon,"Creating",false,1);Save(inventory,item,"Create intent");
        Directory.CreateDirectory(item.Target);using var targetPin=RansomFree.DeploymentPathLease.Acquire(item.Target);
        if(Directory.EnumerateFileSystemEntries(item.Target).Any())throw new IOException("New target is not empty; no content removed.");
        using(var marker=new FileStream(Marker(plan),FileMode.CreateNew,FileAccess.Write,FileShare.None)){marker.Write(MarkerBytes(plan));marker.Flush(true);}
        item=item with{TargetIdentity=Identity(item.Target,true),State="Disabled"};Save(inventory,item,"Created disabled");return item;
    });
    void VerifyTarget(VirtualDecoyState item)
    {
        using var targetPin=RansomFree.DeploymentPathLease.Acquire(item.Target,Marker(item.Plan));
        if(item.TargetIdentity==null||Identity(item.Target,true)!=item.TargetIdentity||new FileInfo(Marker(item.Plan)).Length>4096||Digest(File.ReadAllBytes(Marker(item.Plan)))!=item.MarkerHash)throw new IOException("Target ownership changed; no external resource modified.");
    }
    VirtualDecoyObservation Observe(VirtualDecoyState item)
    {
        try
        {
            VerifyTarget(item);if(item.Logon!=logon)return new(item.Plan.Id,"Different logon session",item.DesiredActive,item.Target,Entry(item.Plan),item.Revision);
            bool active;
            if(item.Plan.Kind=="V02"){var maps=Mappings(item.Plan.Drive!);if(maps.Length>0&&(maps.Length!=1||maps[0]!="\\??\\"+item.Target))return new(item.Plan.Id,"Drive collision",item.DesiredActive,item.Target,Entry(item.Plan),item.Revision);active=maps.Length==1;}
            else
            {
                active=File.Exists(Entry(item.Plan));
                if(active)
                {
                    using var linkPin=RansomFree.DeploymentPathLease.Acquire(root,Entry(item.Plan));using var stream=File.OpenRead(Entry(item.Plan));
                    if(item.LinkIdentity==null||Identity(Entry(item.Plan),false)!=item.LinkIdentity||stream.Length>16384||Convert.ToHexString(SHA256.HashData(stream))!=item.LinkHash)return new(item.Plan.Id,"Library changed",item.DesiredActive,item.Target,Entry(item.Plan),item.Revision);
                }
            }
            return new(item.Plan.Id,item.State=="Retired"&&!active?"Retired":active==item.DesiredActive?active?"Active":"Disabled":"Needs repair",item.DesiredActive,item.Target,Entry(item.Plan),item.Revision);
        }
        catch(Exception ex)when(ex is IOException or UnauthorizedAccessException or Win32Exception){return new(item.Plan.Id,"Ownership needs review",item.DesiredActive,item.Target,Entry(item.Plan),item.Revision);}
    }
    public IReadOnlyList<VirtualDecoyObservation> Observe()=>Locked<IReadOnlyList<VirtualDecoyObservation>>(inventory=>inventory.Items.Select(Observe).ToArray());
    public VirtualDecoyObservation Observe(VirtualDecoyPlan expectedPlan)=>Locked(inventory=>
    {
        Validate(expectedPlan);var item=inventory.Items.SingleOrDefault(x=>x.Plan.Id==expectedPlan.Id)??throw new KeyNotFoundException();
        if(item.Plan!=expectedPlan)throw new InvalidOperationException("Assigned plan does not match the saved resource.");
        return Observe(item);
    });
    public VirtualDecoyState SetActive(string id,long expectedRevision,bool active,bool retire=false,VirtualDecoyPlan? expectedPlan=null)=>Locked(inventory=>
    {
        var item=inventory.Items.SingleOrDefault(x=>x.Plan.Id==id)??throw new KeyNotFoundException();
        if(expectedPlan!=null&&item.Plan!=expectedPlan)throw new InvalidOperationException("Assigned plan does not match the saved resource.");
        if(item.Revision!=expectedRevision||item.State=="Retired"||retire&&active)throw new InvalidOperationException("Stale or retired deployment.");
        VerifyTarget(item);using var targetPin=RansomFree.DeploymentPathLease.Acquire(item.Target,Marker(item.Plan));
        var observed=Observe(item);if(observed.State is "Drive collision" or "Library changed" or "Ownership needs review")throw new IOException("Resource ownership changed; no cleanup performed.");
        if(item.Logon!=logon){if(item.Plan.Kind=="V02"&&Mappings(item.Plan.Drive!).Length!=0)throw new IOException("Existing mapping belongs to another session; not adopted.");item=item with{Logon=logon};}
        if(item.DesiredActive==active&&item.State==(active?"Active":"Disabled")&&observed.State==item.State&&!retire)return item;
        item=item with{DesiredActive=active,Revision=checked(item.Revision+1),State=active?"Activating":"Disabling"};Save(inventory,item,active?"Activate intent":"Disable intent");
        if(item.Plan.Kind=="V02")
        {
            var maps=Mappings(item.Plan.Drive!);var expected="\\??\\"+item.Target;
            if(active&&maps.Length==0){if(!DefineDosDevice(1|8,item.Plan.Drive!,expected))throw new Win32Exception(Marshal.GetLastPInvokeError());}
            else if(!active&&maps.Length==1&&maps[0]==expected){if(!DefineDosDevice(1|2|4|8,item.Plan.Drive!,expected))throw new Win32Exception(Marshal.GetLastPInvokeError());}
            else if(maps.Length!=0&&(maps.Length!=1||maps[0]!=expected))throw new IOException("Drive changed during operation; unrelated mapping preserved.");
            var after=Mappings(item.Plan.Drive!);if(active?(after.Length!=1||after[0]!=expected):after.Length!=0)throw new IOException("Mapping outcome not confirmed.");
        }
        else if(active)
        {
            if(!File.Exists(Entry(item.Plan))){var bytes=LibraryBytes(item.Plan);using(var link=new FileStream(Entry(item.Plan),FileMode.CreateNew,FileAccess.Write,FileShare.None)){link.Write(bytes);link.Flush(true);}item=item with{LinkIdentity=Identity(Entry(item.Plan),false),LinkHash=Digest(bytes)};}
        }
        else if(File.Exists(Entry(item.Plan)))RemoveOwnedLibrary(Entry(item.Plan),item.LinkIdentity!,item.LinkHash!);
        item=item with{State=retire?"Retired":active?"Active":"Disabled"};Save(inventory,item,retire?"Retired; target retained":active?"Activated":"Disabled; target retained");return item;
    });
    // Explicit repair/reconciliation honors the saved desired state; never redirects an existing path.
    public VirtualDecoyState Repair(string id,long expectedRevision,VirtualDecoyPlan? expectedPlan=null)
    {var item=Locked(inventory=>inventory.Items.SingleOrDefault(x=>x.Plan.Id==id)??throw new KeyNotFoundException());return SetActive(id,expectedRevision,item.DesiredActive,expectedPlan:expectedPlan);}
    [DllImport("kernel32.dll",EntryPoint="DefineDosDeviceW",CharSet=CharSet.Unicode,SetLastError=true)] static extern bool DefineDosDevice(uint flags,string device,string target);
    [DllImport("kernel32.dll",EntryPoint="QueryDosDeviceW",CharSet=CharSet.Unicode,SetLastError=true)] static extern uint QueryDosDevice(string device,char[] target,uint size);
    public static string[] Mappings(string drive)
    {
        if(drive.Length!=2||drive[0] is <'A' or >'Z'||drive[1]!=':')throw new ArgumentException("Invalid drive.");var buffer=new char[32768];var size=QueryDosDevice(drive,buffer,(uint)buffer.Length);if(size==0){var error=Marshal.GetLastPInvokeError();if(error==2)return [];throw new Win32Exception(error);}return new string(buffer,0,(int)size).Split('\0',StringSplitOptions.RemoveEmptyEntries);
    }
    [DllImport("kernel32.dll",CharSet=CharSet.Unicode,SetLastError=true)] static extern SafeFileHandle CreateFile(string name,uint access,uint share,nint security,uint creation,uint flags,nint template);
    [DllImport("kernel32.dll",SetLastError=true)] static extern bool GetFileInformationByHandleEx(SafeFileHandle file,int informationClass,byte[] information,uint size);
    [DllImport("kernel32.dll",SetLastError=true)] static extern bool SetFileInformationByHandle(SafeFileHandle file,int informationClass,byte[] information,uint size);
    static string HandleIdentity(SafeFileHandle handle){var data=new byte[24];if(!GetFileInformationByHandleEx(handle,18,data,24))throw new Win32Exception(Marshal.GetLastPInvokeError());return Convert.ToHexString(data);}
    static string Identity(string path,bool folder){using var pin=RansomFree.DeploymentPathLease.Acquire(Path.GetDirectoryName(path)!,folder?null:path);using var handle=CreateFile(path,0x80,3,0,3,0x02200000,0);if(handle.IsInvalid)throw new Win32Exception(Marshal.GetLastPInvokeError());return HandleIdentity(handle);}
    static void RemoveOwnedLibrary(string path,string identity,string digest)
    {
        using var handle=CreateFile(path,0x80010000,1,0,3,0x00200000,0);if(handle.IsInvalid)throw new Win32Exception(Marshal.GetLastPInvokeError());
        var tag=new byte[8];if(!GetFileInformationByHandleEx(handle,9,tag,8)||(BitConverter.ToUInt32(tag,0)&0x410)!=0||HandleIdentity(handle)!=identity)throw new IOException("Library identity changed; preserved.");
        using var input=new FileStream(handle,FileAccess.Read);if(input.Length>16384||Convert.ToHexString(SHA256.HashData(input))!=digest)throw new IOException("Library content changed; preserved.");
        if(!SetFileInformationByHandle(handle,4,new byte[]{1,0,0,0},4))throw new Win32Exception(Marshal.GetLastPInvokeError());
    }
    [DllImport("advapi32.dll",SetLastError=true)] static extern bool GetTokenInformation(nint token,int kind,byte[] information,int size,out int needed);
    static string LogonIdentity(nint token){var bytes=new byte[256];if(!GetTokenInformation(token,10,bytes,bytes.Length,out _))throw new Win32Exception(Marshal.GetLastPInvokeError());return Convert.ToHexString(bytes.AsSpan(8,8));}
}
