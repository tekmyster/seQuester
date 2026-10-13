using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using Microsoft.Win32.SafeHandles;

record AccessCheck(string Name,uint Requested,ulong FileId,bool ExpectedCandidate,bool Passed,StagingSlot[] Candidates,int Win32Error);
record BarrierMember(Child Child,long ReadyObservedQpc,long ExitObservedQpc);
record BarrierCheck(bool AllFourAliveBeforeRelease,long ReleaseQpc,long Frequency,BarrierMember[] Members);
record BudgetAdmission(ulong CandidateId,ulong FileId,uint Bytes,ulong ReportedBytes);
record BudgetCheck(bool Passed,StagingHealth Before,StagingHealth After,BudgetAdmission[] Admissions,ulong[] EvictedIds);

static class AdmissionChecks
{
 internal static BudgetCheck Budget(SafeFileHandle port,string root,string fixture,Func<StagingHealth> health,Action drain)
 {
  const uint size=7*1024*1024;
  var handles=new List<SafeFileHandle>();var admissions=new List<BudgetAdmission>();var before=health();var byteLimit=Staging.ByteLimit(before.MetadataSlots);var expectedAdmissions=checked((int)(byteLimit/size)+2);
  try{
   for(int i=0;i<expectedAdmissions;i++){
    var path=Path.Combine(root,"budget-unbound-"+i+".exe");File.Copy(fixture,path);
    using(var extend=new FileStream(path,FileMode.Open,FileAccess.Write,FileShare.None))extend.SetLength(size);
    var handle=CreateFileW(path,0xA0000000,7,IntPtr.Zero,3,0,IntPtr.Zero);
    if(handle.IsInvalid){var error=Marshal.GetLastWin32Error();handle.Dispose();throw new System.ComponentModel.Win32Exception(error,"Budget fixture open failed");}
    handles.Add(handle);
    if(!GetFileInformationByHandle(handle,out var info))throw new System.ComponentModel.Win32Exception(Marshal.GetLastWin32Error());
    ulong fileId=((ulong)info.FileIndexHigh<<32)|info.FileIndexLow;
    var candidates=Staging.Table(port).Where(s=>s.FileId==fileId&&s.Pid==0&&s.Ready==1).ToArray();
    if(candidates.Length!=1)throw new IOException("Budget fixture candidate was not admitted");
    admissions.Add(new(candidates[0].Id,fileId,size,health().Bytes));drain();
   }
   var remaining=Staging.Table(port).Select(s=>s.Id).ToHashSet();
   var evicted=admissions.Where(a=>!remaining.Contains(a.CandidateId)).Select(a=>a.CandidateId).ToArray();
   var after=health();
   return new(admissions.Count==expectedAdmissions&&evicted.Length>=2&&after.UnboundEvictions-before.UnboundEvictions>=2&&after.PoolDrops==before.PoolDrops&&admissions.All(a=>a.ReportedBytes<=byteLimit),before,after,admissions.ToArray(),evicted);
  }finally{foreach(var handle in handles)handle.Dispose();drain();}
 }
 internal static int BarrierChild(string[] args)
 {
  using var ready=EventWaitHandle.OpenExisting(args[1]);
  using var release=EventWaitHandle.OpenExisting(args[2]);
  ready.Set();return release.WaitOne(30000)?0:3;
 }
 internal static AccessCheck[] Run(SafeFileHandle port,string root,string fixture)
 {
  using(var p=Process.Start(new ProcessStartInfo(Path.Combine(AppContext.BaseDirectory,"AccessRegression.exe")){UseShellExecute=false,CreateNoWindow=true})??throw new IOException("Access regression launch failed"))
  {var owned=p.Handle;if(!p.WaitForExit(15000)||p.ExitCode!=0)throw new IOException("Native access predicate regression failed");}
  var result=new List<AccessCheck>();
  foreach(var item in new[]{("generic-read-execute",0xA0000000u,true),("generic-all",0x10000000u,true),("specific-read-execute",0x100021u,true),("execute-only",0x100020u,false),("generic-read-only",0x80000000u,false),("maximum-allowed",0x02000000u,false)})
  {
   var path=Path.Combine(root,item.Item1+".exe");File.Copy(fixture,path);
   using var handle=CreateFileW(path,item.Item2,7,IntPtr.Zero,3,0,IntPtr.Zero);
   var error=Marshal.GetLastWin32Error();if(handle.IsInvalid)throw new System.ComponentModel.Win32Exception(error,"Access fixture open failed");
   if(!GetFileInformationByHandle(handle,out var info))throw new System.ComponentModel.Win32Exception(Marshal.GetLastWin32Error());
   ulong fileId=((ulong)info.FileIndexHigh<<32)|info.FileIndexLow;
   var candidates=Staging.Table(port).Where(s=>s.FileId==fileId).ToArray();
   bool passed=item.Item3
    ?candidates.Length==1&&candidates[0].Ready==1&&candidates[0].Pid==0&&candidates[0].QualificationVersion==2&&candidates[0].CreateStatus==0&&(candidates[0].MappedRequestedAccess&0x21)==0x21
    :candidates.Length==0;
   result.Add(new(item.Item1,item.Item2,fileId,item.Item3,passed,candidates,0));
  }
  return result.ToArray();
 }
 internal static BarrierCheck Barrier(Action drain,Action<Child> started,Action<Child,string> collect)
 {
  string executable=Environment.ProcessPath??throw new IOException("No apphost path");
  string expected=Convert.ToHexString(SHA256.HashData(File.ReadAllBytes(executable)));
  string token=Guid.NewGuid().ToString("N");
  using var release=new EventWaitHandle(false,EventResetMode.ManualReset,"Local\\SqRelease"+token);
  var children=new List<(Process P,Child C,EventWaitHandle Ready)>();var members=new List<BarrierMember>();
  long released=0;bool allAlive=false;
  try{
   for(int i=0;i<4;i++){
    var name="Local\\SqReady"+token+i;var ready=new EventWaitHandle(false,EventResetMode.ManualReset,name);
    var psi=new ProcessStartInfo(executable){UseShellExecute=false,CreateNoWindow=true};
    psi.ArgumentList.Add("--barrier-child");psi.ArgumentList.Add(name);psi.ArgumentList.Add("Local\\SqRelease"+token);
    var p=Process.Start(psi)??throw new IOException("Barrier child launch failed");var handle=p.Handle;
    var child=new Child("barrier-overlap",p.Id,p.StartTime.ToUniversalTime().ToFileTimeUtc(),executable);
    children.Add((p,child,ready));started(child);drain();
   }
   var deadline=Stopwatch.GetTimestamp()+15*Stopwatch.Frequency;
   while(children.Any(c=>!c.Ready.WaitOne(0))){drain();if(Stopwatch.GetTimestamp()>deadline||children.Any(c=>c.P.HasExited))throw new IOException("Barrier child did not become ready while alive");Thread.Sleep(10);}
   allAlive=children.All(c=>!c.P.HasExited);if(!allAlive)throw new IOException("Barrier lifetimes did not overlap");
   long readyAt=Stopwatch.GetTimestamp();released=Stopwatch.GetTimestamp();release.Set();
   foreach(var c in children){if(!c.P.WaitForExit(15000)||c.P.ExitCode!=0)throw new IOException("Barrier child failed");long ended=Stopwatch.GetTimestamp();collect(c.C,expected);members.Add(new(c.C,readyAt,ended));drain();}
   return new(allAlive,released,Stopwatch.Frequency,members.ToArray());
  }finally{
   release.Set();
   foreach(var c in children){if(!c.P.HasExited&&!c.P.WaitForExit(5000)){c.P.Kill();c.P.WaitForExit();}c.P.Dispose();c.Ready.Dispose();}
  }
 }
 [StructLayout(LayoutKind.Sequential)]struct FileInformation {public uint Attributes;public System.Runtime.InteropServices.ComTypes.FILETIME Creation,Access,Write;public uint Volume,SizeHigh,SizeLow,Links,FileIndexHigh,FileIndexLow;}
 [DllImport("kernel32.dll",CharSet=CharSet.Unicode,SetLastError=true)]static extern SafeFileHandle CreateFileW(string path,uint access,uint share,IntPtr security,uint disposition,uint flags,IntPtr template);
 [DllImport("kernel32.dll",SetLastError=true)][return:MarshalAs(UnmanagedType.Bool)]static extern bool GetFileInformationByHandle(SafeFileHandle handle,out FileInformation info);
}
