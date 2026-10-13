using System.Diagnostics;
using System.IO.MemoryMappedFiles;
using System.Runtime.InteropServices;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Text.Json;
using Microsoft.Win32.SafeHandles;

if(args.Length is not (3 or 4)||(args.Length==4&&args[3]!="--exit-immediately"))throw new ArgumentException("Arguments: operation, existing test file, report file, optional --exit-immediately");
var postOperationDelayMs=args.Length==4?0:750;
var operation=args[0];var file=Path.GetFullPath(args[1]);var report=Path.GetFullPath(args[2]);
var waitForRelease=Environment.GetEnvironmentVariable("SQ_FIXTURE_WAIT_FOR_RELEASE")=="1";
if(waitForRelease&&(args.Length==4||File.Exists(report+".release")))throw new ArgumentException("Live-actor qualification requires a new release marker and no immediate-exit flag");
void StartupPhase(string phase)=>File.AppendAllText(report+".startup.jsonl",JsonSerializer.Serialize(new{Phase=phase,Pid=Environment.ProcessId,Utc=DateTimeOffset.UtcNow,Monotonic=Stopwatch.GetTimestamp(),Frequency=Stopwatch.Frequency})+Environment.NewLine);
StartupPhase("managed-entry");
using var fixtureProcess=Process.GetCurrentProcess();
var fixtureCreated=fixtureProcess.StartTime.ToUniversalTime().ToFileTimeUtc();
var fixtureImage=Environment.ProcessPath;
var preOperationDelayMs=0;
if(Environment.GetEnvironmentVariable("SQ_FIXTURE_PRE_OPERATION_DELAY_MS") is {} configuredDelay)
{
 if(!int.TryParse(configuredDelay,out preOperationDelayMs)||preOperationDelayMs is <1000 or >60000)throw new ArgumentException("Fixture pre-operation delay must be bounded");
 File.WriteAllText(report+".ready.json",JsonSerializer.Serialize(new{Pid=fixtureProcess.Id,Created=fixtureCreated,PreOperationDelayMs=preOperationDelayMs,Utc=DateTimeOffset.UtcNow,Monotonic=Stopwatch.GetTimestamp(),Frequency=Stopwatch.Frequency}));
 StartupPhase("ready-marker-written");
 Thread.Sleep(preOperationDelayMs);
}
StartupPhase("before-token-query");
if(!Native.OpenProcessToken(fixtureProcess.Handle,operation=="duplicate-token-read"?10u:8u,out var primaryToken))throw new System.ComponentModel.Win32Exception();
using var ownedPrimary=primaryToken;
var primaryEvidence=Native.Describe(primaryToken);FileStream? transferred=null;object? openContext=null;
void OpenTransferred(){
 using var openingIdentity=WindowsIdentity.GetCurrent();
 openContext=new{ThreadId=Native.GetCurrentThreadId(),Primary=Native.Describe(primaryToken),Effective=Native.Describe(openingIdentity.AccessToken),Utc=DateTimeOffset.UtcNow,Monotonic=Stopwatch.GetTimestamp(),MonotonicFrequency=Stopwatch.Frequency};
 transferred=new FileStream(file,FileMode.Open,operation=="denied-handle-read"?FileAccess.Write:operation.StartsWith("locked-handle-")?FileAccess.ReadWrite:FileAccess.Read,operation.StartsWith("denied-handle-")||operation.StartsWith("locked-handle-")?FileShare.ReadWrite|FileShare.Delete:FileShare.Read,1);
}
void Run(){
 using var identity=WindowsIdentity.GetCurrent();
 var effectiveEvidence=Native.Describe(identity.AccessToken);
 var threadId=Native.GetCurrentThreadId();
 var started=DateTimeOffset.UtcNow;string? error=null;int? errorHResult=null;int? nativeWin32Error=null;var outcome="Success";
 try{
  switch(operation){
   case "read":case "impersonated-read":case "duplicate-token-read":case "denied-read":File.ReadAllBytes(file);break;
   case "open-impersonated-read-reverted":case "open-primary-read-impersonated":transferred!.ReadExactly(new byte[4096]);break;
   case "denied-handle-read":case "denied-handle-write":case "denied-handle-append":case "denied-handle-truncate":case "denied-handle-delete":case "denied-handle-rename":
    Native.DeniedHandleOperation(transferred!.SafeFileHandle,operation,file);break;
   case "locked-handle-read":case "locked-handle-write":
    Native.DeniedHandleOperation(transferred!.SafeFileHandle,operation.Replace("locked-handle-","denied-handle-"),file);break;
   case "write":case "denied-write":File.WriteAllText(file,"canary fixture write");break;
   case "append":case "denied-append":File.AppendAllText(file,"canary fixture append");break;
   case "truncate":case "denied-truncate":using(var stream=new FileStream(file,FileMode.Open,FileAccess.Write,FileShare.ReadWrite)){stream.SetLength(1);stream.Flush(true);}break;
   case "copy":File.Copy(file,file+".copy",false);break;
   case "rename":case "denied-rename":File.Move(file,file+".renamed");break;
   case "delete":case "denied-delete":File.Delete(file);break;
   case "mmap-read":using(var mapped=MemoryMappedFile.CreateFromFile(file,FileMode.Open)){using var view=mapped.CreateViewAccessor(0,0,MemoryMappedFileAccess.Read);_ = view.ReadByte(0);}break;
   case "mmap-write":using(var mapped=MemoryMappedFile.CreateFromFile(file,FileMode.Open)){using var view=mapped.CreateViewAccessor();view.Write(0,(byte)123);view.Flush();}break;
   case "async-read":using(var stream=new FileStream(file,FileMode.Open,FileAccess.Read,FileShare.Read,4096,FileOptions.Asynchronous)){stream.ReadAsync(new byte[4096]).AsTask().GetAwaiter().GetResult();}break;
   case "async-write":using(var stream=new FileStream(file,FileMode.Open,FileAccess.Write,FileShare.Read,4096,FileOptions.Asynchronous)){stream.WriteAsync(new byte[4096]).AsTask().GetAwaiter().GetResult();stream.Flush(true);}break;
   case "acl":case "denied-acl":var info=new FileInfo(file);var acl=info.GetAccessControl();acl.AddAccessRule(new FileSystemAccessRule(identity.User!,FileSystemRights.Read,AccessControlType.Allow));info.SetAccessControl(acl);break;
   case "burst":for(var i=0;i<500;i++)File.ReadAllBytes(file);break;
   default:throw new ArgumentException("Unknown operation");
  }
 }catch(Exception ex){outcome="Failed";error=ex.GetType().Name+": "+ex.Message;errorHResult=ex.HResult;if(ex is System.ComponentModel.Win32Exception nativeError)nativeWin32Error=nativeError.NativeErrorCode;else if((unchecked((uint)ex.HResult)&0xffff0000u)==0x80070000u)nativeWin32Error=ex.HResult&0xffff;}
 var result=new {Operation=operation,File=file,Host=Environment.MachineName,ProcessId=Environment.ProcessId,ThreadId=threadId,ProcessCreatedUtcFileTime=fixtureCreated,Image=fixtureImage,CommandLine=Native.CommandLine(),ManagedCommandLine=Environment.CommandLine,User=identity.Name,UserSid=identity.User!.Value,Primary=primaryEvidence,Effective=effectiveEvidence,OpenContext=openContext,StartedUtc=started,CompletedUtc=DateTimeOffset.UtcNow,PreOperationDelayMs=preOperationDelayMs,PostOperationDelayMs=postOperationDelayMs,WaitForRelease=waitForRelease,ReleaseDeadlineMs=waitForRelease?60000:0,Outcome=outcome,Error=error,ErrorHResult=errorHResult,NativeWin32Error=nativeWin32Error};
 File.WriteAllText(report,JsonSerializer.Serialize(result));
 if(waitForRelease)File.WriteAllText(report+".held","report-complete");
 if(outcome=="Failed"&&!operation.StartsWith("denied-")&&!operation.StartsWith("locked-handle-"))Environment.ExitCode=1;
 if(operation.StartsWith("denied-")&&(outcome!="Failed"||nativeWin32Error!=5))Environment.ExitCode=2;
 if(operation.StartsWith("locked-handle-")&&(outcome!="Failed"||nativeWin32Error!=33))Environment.ExitCode=2;
 if(postOperationDelayMs>0)Thread.Sleep(postOperationDelayMs);
 if(waitForRelease){var wait=Stopwatch.StartNew();while(!File.Exists(report+".release")){if(wait.ElapsedMilliseconds>60000)throw new TimeoutException("Owned live-actor release marker not received");Thread.Sleep(50);}}
}
if(operation=="duplicate-token-read"){
 // Same logon session permits reuse of the owned SMB mapping while independently
 // testing an actual impersonation token, distinct from the process primary token.
 if(!Native.DuplicateTokenEx(primaryToken,12,IntPtr.Zero,2,2,out var token))throw new System.ComponentModel.Win32Exception();
 using(token)WindowsIdentity.RunImpersonated(token,Run);
}else if(operation.StartsWith("denied-")||operation.StartsWith("locked-handle-")||operation is "impersonated-read" or "open-impersonated-read-reverted" or "open-primary-read-impersonated"){
 // Documented service logon avoids directory dependencies in a disconnected DC clone.
 var serviceFixture=Environment.GetEnvironmentVariable("SQ_FIXTURE_LOCAL_SERVICE")=="1";
 var password=serviceFixture?null:Environment.GetEnvironmentVariable("SQ_FIXTURE_PASSWORD")??throw new InvalidOperationException("Missing fixture account password");
 var domain=serviceFixture?"NT AUTHORITY":Environment.GetEnvironmentVariable("SQ_FIXTURE_DOMAIN")??".";
 var fixtureUser=Environment.GetEnvironmentVariable("SQ_FIXTURE_USER")??"sqfixture";
 if(!Native.LogonUser(serviceFixture?"LocalService":fixtureUser,domain,password,serviceFixture?5:2,0,out var token))throw new System.ComponentModel.Win32Exception();
 using(token){
  if(operation=="open-impersonated-read-reverted"){WindowsIdentity.RunImpersonated(token,OpenTransferred);using(transferred)Run();}
  else if(operation=="open-primary-read-impersonated"||operation.StartsWith("denied-handle-")||operation.StartsWith("locked-handle-")){OpenTransferred();using(transferred)WindowsIdentity.RunImpersonated(token,Run);}
  else WindowsIdentity.RunImpersonated(token,Run);
 }
}else Run();
internal static class Native{
 [DllImport("kernel32.dll",SetLastError=true)] [return:MarshalAs(UnmanagedType.Bool)] private static extern bool ReadFile(SafeFileHandle handle,byte[] buffer,uint length,out uint transferred,IntPtr overlapped);
 [DllImport("kernel32.dll",SetLastError=true)] [return:MarshalAs(UnmanagedType.Bool)] private static extern bool WriteFile(SafeFileHandle handle,byte[] buffer,uint length,out uint transferred,IntPtr overlapped);
 [DllImport("kernel32.dll",SetLastError=true)] [return:MarshalAs(UnmanagedType.Bool)] private static extern bool SetFilePointerEx(SafeFileHandle handle,long distance,out long position,uint method);
 [DllImport("kernel32.dll",SetLastError=true)] [return:MarshalAs(UnmanagedType.Bool)] private static extern bool SetEndOfFile(SafeFileHandle handle);
 [DllImport("kernel32.dll",SetLastError=true)] [return:MarshalAs(UnmanagedType.Bool)] private static extern bool SetFileInformationByHandle(SafeFileHandle handle,int infoClass,IntPtr data,uint length);
 internal static void DeniedHandleOperation(SafeFileHandle handle,string operation,string path)
 {
  bool ok;
  if(operation=="denied-handle-read")ok=ReadFile(handle,new byte[1],1,out _,IntPtr.Zero);
  else if(operation is "denied-handle-write" or "denied-handle-append")
  {
   if(operation=="denied-handle-append"&&!SetFilePointerEx(handle,0,out _,2))throw new System.ComponentModel.Win32Exception(Marshal.GetLastWin32Error());
   ok=WriteFile(handle,[0x53],1,out _,IntPtr.Zero);
  }
  else if(operation=="denied-handle-truncate")
  {
   if(!SetFilePointerEx(handle,1,out _,0))throw new System.ComponentModel.Win32Exception(Marshal.GetLastWin32Error());
   ok=SetEndOfFile(handle);
  }
  else
  {
   var name=System.Text.Encoding.Unicode.GetBytes(path+".denied-rename");
   // FILE_RENAME_INFO uses native pointer alignment; FileName starts at 20
   // on x64 and 12 on x86. FILE_DISPOSITION_INFO is a single BOOLEAN.
   var offset=IntPtr.Size==8?20:12;var size=operation=="denied-handle-delete"?1:offset+name.Length;
   var buffer=Marshal.AllocHGlobal(size);
   try{
    Marshal.Copy(new byte[size],0,buffer,size);
    if(operation=="denied-handle-delete")Marshal.WriteByte(buffer,1);
    else{Marshal.WriteInt32(buffer,IntPtr.Size==8?16:8,name.Length);Marshal.Copy(name,0,buffer+offset,name.Length);}
    ok=SetFileInformationByHandle(handle,operation=="denied-handle-delete"?4:3,buffer,(uint)size);
    var error=ok?0:Marshal.GetLastWin32Error();
    if(!ok)throw new System.ComponentModel.Win32Exception(error);
   }finally{Marshal.FreeHGlobal(buffer);}
   return;
  }
  if(!ok)throw new System.ComponentModel.Win32Exception(Marshal.GetLastWin32Error());
 }
 [DllImport("advapi32.dll",SetLastError=true)] [return:MarshalAs(UnmanagedType.Bool)] internal static extern bool DuplicateTokenEx(SafeAccessTokenHandle existing,uint access,IntPtr attributes,int level,int type,out SafeAccessTokenHandle token);
    [DllImport("kernel32.dll",ExactSpelling=true)]private static extern nint GetCommandLineW();
    internal static string CommandLine()=>Marshal.PtrToStringUni(GetCommandLineW())??throw new IOException("Native process command line unavailable");
 [DllImport("kernel32.dll")]internal static extern uint GetCurrentThreadId();
 [DllImport("advapi32.dll",SetLastError=true)] [return:MarshalAs(UnmanagedType.Bool)] internal static extern bool OpenProcessToken(IntPtr process,uint access,out SafeAccessTokenHandle token);
 [DllImport("advapi32.dll",SetLastError=true)] [return:MarshalAs(UnmanagedType.Bool)] static extern bool GetTokenInformation(SafeAccessTokenHandle token,int kind,IntPtr info,uint size,out uint needed);
 internal static object Describe(SafeAccessTokenHandle token)
 {
  var buffer=Marshal.AllocHGlobal(4096);try{
   void Query(int kind){GetTokenInformation(token,kind,IntPtr.Zero,0,out var needed);if(needed is 0 or >4096||!GetTokenInformation(token,kind,buffer,needed,out _))throw new System.ComponentModel.Win32Exception();}
   Query(10);var tokenId=unchecked((ulong)Marshal.ReadInt64(buffer)).ToString("X16");var logon=unchecked((ulong)Marshal.ReadInt64(buffer,8)).ToString("X16");var type=Marshal.ReadInt32(buffer,24);var level=type==2?(int?)Marshal.ReadInt32(buffer,28):null;var modified=unchecked((ulong)Marshal.ReadInt64(buffer,48)).ToString("X16");
   Query(12);var session=Marshal.ReadInt32(buffer);Query(20);var elevated=Marshal.ReadInt32(buffer)!=0;
   Query(25);var integrity=new SecurityIdentifier(Marshal.ReadIntPtr(buffer)).Value;var rid=uint.Parse(integrity.Split('-').Last());
   using var identity=new WindowsIdentity(token.DangerousGetHandle());return new{UserSid=identity.User!.Value,TokenId=tokenId,AuthenticationId=logon,ModifiedId=modified,TokenType=type,ImpersonationLevel=level,SessionId=session,IntegrityRid=rid,Elevated=elevated};
  }finally{Marshal.FreeHGlobal(buffer);}
 }
 [DllImport("advapi32.dll",CharSet=CharSet.Unicode,SetLastError=true)] [return:MarshalAs(UnmanagedType.Bool)] internal static extern bool LogonUser(string user,string domain,string? password,int type,int provider,out SafeAccessTokenHandle token);
}
