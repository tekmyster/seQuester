using System.Runtime.InteropServices;
using System.Text.Json;
using System.Xml.Linq;
using RansomFree.WindowsDecoys;
var root=Path.Combine("D:\\Codex\\RansomFree\\tests","windows-virtual-"+Guid.NewGuid().ToString("N"));Directory.CreateDirectory(root);var state=Path.Combine(root,"state");var targets=Path.Combine(root,"targets");Directory.CreateDirectory(state);Directory.CreateDirectory(targets);
var evidence=new List<string>();void Check(bool value,string label){if(!value)throw new Exception(label);evidence.Add("PASS: "+label);Console.WriteLine(evidence[^1]);File.WriteAllLines(Path.Combine(root,"results.txt"),evidence);}
void Reject(Action action,string label){var denied=false;try{action();}catch(Exception ex)when(ex is ArgumentException or InvalidOperationException or IOException){denied=true;}Check(denied,label);}
var service=new VirtualDecoys(state,targets);var drive=Enumerable.Range('E',22).Reverse().Select(x=>(char)x+":").FirstOrDefault(x=>VirtualDecoys.Mappings(x).Length==0)??throw new InvalidOperationException("No unused test drive available; no mappings changed.");
Reject(()=>new VirtualDecoys(state,root),"native adapter refuses a deployment root containing its state");
var plan=new VirtualDecoyPlan(Guid.NewGuid().ToString("N"),"V02","Fixture archive",drive);var folder=new VirtualDecoyPlan(Guid.NewGuid().ToString("N"),"V03","Fixture library");
VirtualDecoyState? current=null,library=null;
try
{
    current=service.Create(plan);Check(current.State=="Disabled"&&VirtualDecoys.Mappings(drive).Length==0,"V02 create remains disabled with no drive mapping");
    Check(service.Create(plan)==current,"V02 create is idempotent");
    Reject(()=>service.Create(plan with{Name="Changed"}),"identity cannot redirect or change name");
    Reject(()=>service.Create(new(Guid.NewGuid().ToString("N"),"V02","System drive","C:")),"system drive cannot be targeted");
    Reject(()=>service.SetActive(plan.Id,current.Revision,true,expectedPlan:plan with{Name="Different assignment"}),"V02 assignment cannot mutate a different saved plan");
    Reject(()=>service.Observe(plan with{Name="Different assignment"}),"V02 observation cannot claim evidence for a different assigned plan");
    Check(service.Observe(plan).State=="Disabled","plan-bound V02 observation reports the saved disabled resource");
    current=service.SetActive(plan.Id,current.Revision,true);Check(service.Observe().Single(x=>x.Id==plan.Id).State=="Active","V02 native drive mapping created and verified");
    Check(File.ReadAllText(drive+"\\.sequester-owner.json")==File.ReadAllText(Path.Combine(current.Target,".sequester-owner.json")),"drive resolves only to the owned isolated target");
    Reject(()=>service.Create(new(Guid.NewGuid().ToString("N"),"V02","Collision",drive)),"existing drive collision refused without changing mapping");
    service=new VirtualDecoys(state,targets);Check(service.Observe().Single(x=>x.Id==plan.Id).State=="Active","restart reconciles existing exact mapping");
    Check(service.Repair(plan.Id,current.Revision).Revision==current.Revision,"healthy repair is idempotent");
    var userFile=Path.Combine(current.Target,"unrelated-fixture.txt");File.WriteAllText(userFile,"Preserve this test content");
    current=service.SetActive(plan.Id,current.Revision,false);Check(VirtualDecoys.Mappings(drive).Length==0&&File.ReadAllText(userFile)=="Preserve this test content","V02 disable removes only exact mapping and retains target content");
    current=service.SetActive(plan.Id,current.Revision,true);Check(service.Observe().Single(x=>x.Id==plan.Id).State=="Active","V02 reactivation works without recreating target");
    current=service.SetActive(plan.Id,current.Revision,false,true);Check(service.Observe().Single(x=>x.Id==plan.Id).State=="Retired"&&File.Exists(userFile),"V02 retirement retains target for recovery");
    Reject(()=>service.SetActive(plan.Id,current.Revision,true),"retired drive cannot reactivate");
    library=service.Create(folder);Check(!File.Exists(service.Observe().Single(x=>x.Id==folder.Id).Entry),"V03 create does not publish a library pointer");
    Reject(()=>service.SetActive(folder.Id,library.Revision,true,expectedPlan:folder with{Name="Different assignment"}),"V03 assignment cannot mutate a different saved plan");
    Reject(()=>service.Observe(folder with{Name="Different assignment"}),"V03 observation cannot claim a different assigned plan");
    Check(service.Observe(folder).State=="Disabled","plan-bound V03 observation retains disabled state");
    library=service.SetActive(folder.Id,library.Revision,true);var entry=service.Observe().Single(x=>x.Id==folder.Id).Entry!;var bytes=File.ReadAllBytes(entry);
    var xml=XDocument.Load(entry);XNamespace ns="http://schemas.microsoft.com/windows/2009/library";Check(xml.Descendants(ns+"url").Single().Value==new Uri(library.Target+"\\").AbsoluteUri,"V03 library points only to the owned local target");
    Check(ShellLibrary.Check(entry)==0,"Windows Shell accepts the generated library description");
    service=new VirtualDecoys(state,targets);Check(service.Observe().Single(x=>x.Id==folder.Id).State=="Active","V03 restart verifies library identity and hash");
    File.AppendAllText(entry,"\n<!-- changed by isolated fixture -->");Check(service.Observe().Single(x=>x.Id==folder.Id).State=="Library changed","library tampering produces explicit degraded state");
    Reject(()=>service.SetActive(folder.Id,library.Revision,false),"modified library is never removed by cleanup");Check(File.Exists(entry),"changed pointer preserved for investigation");
    File.WriteAllBytes(entry,bytes);library=service.SetActive(folder.Id,library.Revision,false);Check(!File.Exists(entry)&&Directory.Exists(library.Target),"V03 disable deletes only exact owned pointer; target retained");
    library=service.SetActive(folder.Id,library.Revision,true);Check(service.Observe().Single(x=>x.Id==folder.Id).State=="Active","V03 pointer recreated safely on activation");
    library=service.SetActive(folder.Id,library.Revision,false,true);Check(!File.Exists(entry)&&Directory.Exists(library.Target),"V03 retirement removes pointer without deleting backing content");
}
finally
{
    if(current is {State:not "Retired",DesiredActive:true}){var latest=service.Observe().Single(x=>x.Id==plan.Id);service.SetActive(plan.Id,latest.Revision,false);}
    if(library is {State:not "Retired",DesiredActive:true}){var latest=service.Observe().Single(x=>x.Id==folder.Id);if(latest.State=="Active")service.SetActive(folder.Id,latest.Revision,false);}
    File.WriteAllText(Path.Combine(root,"final-state.json"),JsonSerializer.Serialize(new{Drive=drive,RemainingMappings=VirtualDecoys.Mappings(drive),Objects=service.Observe()}));
    Console.WriteLine(root);
}
Console.WriteLine("Native isolated V02/V03 lifecycle only. No installed service, profile library registry, existing drive or unrelated content changed. No GUI, canary actor sensing or reboot acceptance inferred.");
static class ShellLibrary
{
    [ComImport,Guid("43826D1E-E718-42EE-BC55-A1E261C37BFE"),InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]interface IShellItem{}
    [ComImport,Guid("11A66EFA-382E-451A-9234-1E0E12EF3085"),InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]interface IShellLibrary{[PreserveSig]int LoadLibraryFromItem(IShellItem item,uint mode);}
    [DllImport("shell32.dll",CharSet=CharSet.Unicode,PreserveSig=true)]static extern int SHCreateItemFromParsingName(string path,nint context,ref Guid iid,out IShellItem item);
    public static int Check(string path)
    {
        var result=unchecked((int)0x80004005);Exception? failure=null;
        var thread=new Thread(()=>{IShellItem? item=null;object? library=null;try{var iid=typeof(IShellItem).GUID;result=SHCreateItemFromParsingName(path,0,ref iid,out item);if(result<0)return;library=Activator.CreateInstance(Type.GetTypeFromCLSID(new("D9B3211D-E57F-4426-AAEF-30A806ADD397"),true)!);result=((IShellLibrary)library!).LoadLibraryFromItem(item,0);}catch(Exception ex){failure=ex;}finally{if(library!=null)Marshal.ReleaseComObject(library);if(item!=null)Marshal.ReleaseComObject(item);}});thread.SetApartmentState(ApartmentState.STA);thread.Start();thread.Join();if(failure!=null)throw failure;return result;
    }
}
