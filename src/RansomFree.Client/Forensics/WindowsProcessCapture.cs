using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Security.Principal;
using System.Text;
using Microsoft.Win32.SafeHandles;
using RansomFree.Contracts;
namespace RansomFree.Client.Forensics;

[System.Runtime.Versioning.SupportedOSPlatform("windows")]
internal static class WindowsProcessCapture
{
    [DllImport("kernel32.dll",SetLastError=true)]private static extern SafeProcessHandle OpenProcess(uint access,bool inherit,int pid);
    [DllImport("kernel32.dll",SetLastError=true)]private static extern bool GetProcessTimes(SafeProcessHandle process,out long created,out long exited,out long kernel,out long user);
    [DllImport("kernel32.dll",SetLastError=true,CharSet=CharSet.Unicode)]private static extern bool QueryFullProcessImageName(SafeProcessHandle process,uint flags,StringBuilder path,ref uint size);
    [DllImport("kernel32.dll",SetLastError=true)]private static extern uint WaitForSingleObject(SafeProcessHandle process,uint milliseconds);
    [DllImport("advapi32.dll",SetLastError=true)]private static extern bool OpenProcessToken(SafeProcessHandle process,uint access,out SafeAccessTokenHandle token);
    [DllImport("advapi32.dll",SetLastError=true)]private static extern bool GetTokenInformation(SafeAccessTokenHandle token,int kind,nint buffer,uint size,out uint required);
    [StructLayout(LayoutKind.Sequential)]private struct BasicInfo {public nint Reserved1,Peb,Reserved2,Reserved3,Pid,Parent;}
    [DllImport("ntdll.dll")]private static extern int NtQueryInformationProcess(SafeProcessHandle process,int kind,out BasicInfo data,uint size,out uint returned);
    [DllImport("ntdll.dll",EntryPoint="NtQueryInformationProcess")]private static extern int QueryWow64(SafeProcessHandle process,int kind,out nint data,uint size,out uint returned);
    [DllImport("kernel32.dll",SetLastError=true)]private static extern bool ReadProcessMemory(SafeProcessHandle process,nint address,byte[] data,nuint size,out nuint read);
    private static string Image(SafeProcessHandle handle)
    {var path=new StringBuilder(32768);uint size=(uint)path.Capacity;if(!QueryFullProcessImageName(handle,0,path,ref size))throw new Win32Exception();return path.ToString();}
    private static long Started(SafeProcessHandle handle)
    {if(!GetProcessTimes(handle,out var created,out _,out _,out _))throw new Win32Exception();return created;}
    public static void Capture(ActorLease lease,AgentEvent value,string sensor,bool deferMetadata=false)
    {
        var pid=value.ProcessId!.Value;
        var handle=OpenProcess(0x101000,false,pid); // synchronize + query limited information
        lease.MetadataHandle=handle; // Lease owns the handle, including every failure path.
        if(handle.IsInvalid)throw new Win32Exception();
        var start=Started(handle);var when=DateTimeOffset.FromFileTime(start);var path=Image(handle);
        if(value.Attribution?.WindowsKernel is {} kernel&&kernel.ProcessCreatedFileTime!=start)throw new InvalidOperationException("Kernel event process instance differs from current PID.");
        if(when>value.ObservedUtc||!path.Equals(value.Process,StringComparison.OrdinalIgnoreCase))throw new InvalidOperationException("Historical PID or image mismatch.");
        lease.Process=lease.Process with{StartedUtc=when,StartKey=start.ToString(System.Globalization.CultureInfo.InvariantCulture),InstanceId=ActorLease.Correlate(sensor,pid,start.ToString(System.Globalization.CultureInfo.InvariantCulture)),ExecutablePath=path,Status=EvidenceStatus.Captured("process-handle-start-time")};
        // Acquire the executable before account resolution, parent reads and command-line enrichment.
        // None of those optional reads is allowed to discard an already bound image.
        try
        {
            if(path.StartsWith(@"\\",StringComparison.Ordinal))throw new IOException("Network actor requires an explicit collection policy.");
            lease.Image=new FileStream(path,FileMode.Open,FileAccess.Read,FileShare.Read|FileShare.Delete);
            lease.File=NativeFileIdentity.Read(lease.Image);
            if(lease.File.ModifiedUtc>when||lease.File.CreatedUtc>when)throw new InvalidOperationException("Disk image newer than process start.");
            if(WaitForSingleObject(handle,0)!=258||Started(handle)!=start||!Image(handle).Equals(path,StringComparison.OrdinalIgnoreCase)||!NativeFileIdentity.Same(lease.File,NativeFileIdentity.Read(lease.Image)))throw new InvalidOperationException("Process exited or image changed during capture.");
            lease.Binding=EvidenceStatus.Captured("start-time-and-opened-disk-image; not-loaded-memory-verification");
        }
        catch(Exception ex)when(ActorLease.OptionalFailure(ex))
        {lease.Image?.Dispose();lease.Image=null;lease.Binding=ActorLease.FailedField("actor-image-capture-failed",ex);}
        if(deferMetadata)
        {
            lease.Process=lease.Process with{CommandLineStatus=EvidenceStatus.Unavailable("optional-metadata-deferred"),ParentStatus=EvidenceStatus.Unavailable("optional-metadata-deferred"),SessionStatus=EvidenceStatus.Unavailable("optional-metadata-deferred")};
            lease.DeferredMetadata=()=>Enrich(lease,value,sensor,handle,start);return;
        }
        Enrich(lease,value,sensor,handle,start);
        handle.Dispose();lease.MetadataHandle=null;
    }
    private static void Enrich(ActorLease lease,AgentEvent value,string sensor,SafeProcessHandle handle,long start)
    {
        var pid=value.ProcessId!.Value;
        PrincipalEvidence owner;
        try{owner=Token(handle);}catch(Exception ex)when(ActorLease.OptionalFailure(ex)){owner=new(){Status=ActorLease.FailedField("process-token-unavailable",ex)};}
        lease.Process=lease.Process with{Owner=owner,ProcessSessionId=owner.SessionId,SessionStatus=owner.SessionId!=null?EvidenceStatus.Captured("process-token-session-id"):EvidenceStatus.Unavailable("process-token-session-unavailable")};
        int? parentPid=null;string? parentKey=null;DateTimeOffset? parentTime=null;string? parentPath=null;
        var parentStatus=EvidenceStatus.Unavailable("parent-process-unavailable");
        // ProcessBasicInformation is declared in the installed Windows SDK. Failure is not a fabricated parent.
        if(NtQueryInformationProcess(handle,0,out var basic,(uint)Marshal.SizeOf<BasicInfo>(),out _)==0&&basic.Parent>0&&basic.Parent<=int.MaxValue)
        {
            parentPid=(int)basic.Parent;
            using var parent=OpenProcess(0x1000,false,parentPid.Value);
            if(parent.IsInvalid)parentStatus=new("partial","parent-pid-only",Marshal.GetLastWin32Error().ToString());
            else try
            {
                var stamp=Started(parent);
                if(stamp<=start){parentKey=stamp.ToString(System.Globalization.CultureInfo.InvariantCulture);parentTime=DateTimeOffset.FromFileTime(stamp);parentStatus=EvidenceStatus.Captured("parent-handle-start-not-newer-than-child");try{parentPath=Image(parent);}catch(Win32Exception ex){parentStatus=new("partial","parent-image-unavailable",ex.NativeErrorCode.ToString());}}
                else parentStatus=new("partial","parent-pid-reused-after-child-start");
            }
            catch(Win32Exception ex){parentStatus=new("partial","parent-start-unavailable",ex.NativeErrorCode.ToString());}
        }
        var command=CommandLine(pid,start);
        lease.Process=lease.Process with{ParentPid=parentPid,ParentStartKey=parentKey,ParentStartedUtc=parentTime,ParentInstanceId=parentKey!=null?ActorLease.Correlate(sensor,parentPid!.Value,parentKey):null,ParentExecutablePath=parentPath,ParentStatus=parentStatus,CommandLine=value.Attribution?.CommandLine??command.Value,CommandLineStatus=value.Attribution?.CommandLine!=null?EvidenceStatus.Captured("source-event"):command.Status};
    }
    private static (string? Value,EvidenceStatus Status) CommandLine(int pid,long started)
    {
        // Read only the documented SDK PEB/RTL_USER_PROCESS_PARAMETERS command-line member.
        // It is mutable process memory: a later observation, not a trusted creation-event command line.
        if(RuntimeInformation.ProcessArchitecture!=Architecture.X64)return(null,EvidenceStatus.Unavailable("command-line-reader-requires-x64-collector"));
        using var process=OpenProcess(0x101410,false,pid);
        if(process.IsInvalid)return(null,new("unavailable","command-line-process-access-denied",Marshal.GetLastWin32Error().ToString()));
        try
        {
            if(Started(process)!=started)throw new IOException("PID changed.");
            if(NtQueryInformationProcess(process,0,out var basic,(uint)Marshal.SizeOf<BasicInfo>(),out _)!=0)throw new IOException("PEB unavailable.");
            if(QueryWow64(process,26,out var wow64,(uint)IntPtr.Size,out _)!=0)throw new IOException("Process architecture unavailable.");
            var pointerSize=wow64!=0?4:8;var peb=wow64!=0?wow64:basic.Peb;
            byte[] Read(nint address,int size)
            {if(address<=0||size is <0 or >4096)throw new IOException("Invalid remote field bounds.");var bytes=new byte[size];if(size>0&&(!ReadProcessMemory(process,address,bytes,(nuint)size,out var count)||count!=(nuint)size))throw new Win32Exception();return bytes;}
            nint Pointer(byte[] bytes,int offset)=>pointerSize==8?checked((nint)BitConverter.ToInt64(bytes,offset)):(nint)BitConverter.ToUInt32(bytes,offset);
            // SDK: PEB starts with 4 bytes then aligned pointer fields; parameters follow three pointers.
            var parameters=Pointer(Read(peb+(pointerSize==8?32:16),pointerSize),0);
            var commandOffset=16+10*pointerSize+(pointerSize==8?16:8);
            var descriptor=Read(parameters+commandOffset,pointerSize==8?16:8);var length=BitConverter.ToUInt16(descriptor,0);var maximum=BitConverter.ToUInt16(descriptor,2);
            if((length&1)!=0||length>maximum)throw new IOException("Command-line descriptor changed.");
            var buffer=Pointer(descriptor,pointerSize==8?8:4);var body=Read(buffer,Math.Min((int)length,4096));
            if(!descriptor.AsSpan().SequenceEqual(Read(parameters+commandOffset,descriptor.Length))||Started(process)!=started||WaitForSingleObject(process,0)!=258)throw new IOException("Command line or process changed during capture.");
            var command=Encoding.Unicode.GetString(body);
            return(command,new(length>4096?"partial":"captured",length>4096?"PEB-command-line-truncated; mutable-later-observation":"PEB-command-line; mutable-later-observation"));
        }
        catch(Exception ex)when(ex is IOException or Win32Exception or OverflowException){return(null,new("unavailable","command-line-unavailable",ex is Win32Exception native?native.NativeErrorCode.ToString():ex.GetType().Name));}
    }
    private static PrincipalEvidence Token(SafeProcessHandle process)
    {
        if(!OpenProcessToken(process,8,out var token))return new(){Status=new("unavailable","OpenProcessToken",Marshal.GetLastWin32Error().ToString())};
        using(token)
        {
            nint Read(int kind)
            {
                GetTokenInformation(token,kind,0,0,out var length);
                if(length is 0 or >65536)throw new Win32Exception();
                var memory=Marshal.AllocHGlobal((int)length);
                if(!GetTokenInformation(token,kind,memory,length,out _)){var error=Marshal.GetLastWin32Error();Marshal.FreeHGlobal(memory);throw new Win32Exception(error);}return memory;
            }
            T Field<T>(int kind,Func<nint,T> get){var p=Read(kind);try{return get(p);}finally{Marshal.FreeHGlobal(p);}}
            var result=new PrincipalEvidence();
            try
            {
                var sid=Field(1,p=>new SecurityIdentifier(Marshal.ReadIntPtr(p)).Value);
                string? account=null;try{account=new SecurityIdentifier(sid).Translate(typeof(NTAccount)).Value;}catch(IdentityNotMappedException){}
                result=result with{Sid=sid,Account=account};
                var integrity=Field(25,p=>new SecurityIdentifier(Marshal.ReadIntPtr(p)).Value);
                result=result with{IntegritySid=integrity};
                var session=Field(12,p=>unchecked((uint)Marshal.ReadInt32(p)));
                result=result with{SessionId=session};
                var elevated=Field(20,p=>Marshal.ReadInt32(p)!=0);
                result=result with{Elevated=elevated};
                var type=Field(8,p=>Marshal.ReadInt32(p)==1?"primary":"impersonation");
                result=result with{TokenType=type};
                var ids=Field(10,p=>(Token:unchecked((ulong)Marshal.ReadInt64(p)).ToString("X16"),Auth:unchecked((ulong)Marshal.ReadInt64(p,8)).ToString("X16")));
                return new(){Sid=sid,Account=account,IntegritySid=integrity,SessionId=session,Elevated=elevated,TokenType=type,TokenId=ids.Token,AuthenticationId=ids.Auth,LogonId=ids.Auth,Status=EvidenceStatus.Captured("process-primary-token-after-observation")};
            }
            catch(Win32Exception ex){return result with{Status=new(result.Sid==null?"unavailable":"partial","GetTokenInformation",ex.NativeErrorCode.ToString())};}
        }
    }
}
