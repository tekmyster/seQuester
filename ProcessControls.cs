using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Text;
using Microsoft.Win32.SafeHandles;

namespace RansomFree;

internal record ProcessIdentity(int Pid, string Executable, long CreatedUtcFileTime, string Hash)
{
    public bool TrustVerified {get;init;}
    public DateTimeOffset? ImageCheckedUtc {get;init;}
}
internal record AllowRule(string Executable, string Hash, string? Folder=null, DateTime? ExpiresUtc=null)
{
    public bool Matches(Alert alert) => alert.Identity is { } identity &&
        (ExpiresUtc==null || ExpiresUtc>DateTime.UtcNow) &&
        string.Equals(Executable,identity.Executable,StringComparison.OrdinalIgnoreCase) &&
        Hash.Length>0 && string.Equals(Hash,identity.Hash,StringComparison.OrdinalIgnoreCase) &&
        (string.IsNullOrEmpty(Folder) || alert.Path.StartsWith(Folder.TrimEnd('\\')+"\\",StringComparison.OrdinalIgnoreCase));
}

internal static class ProcessControls
{
    [DllImport("kernel32.dll",SetLastError=true)] private static extern SafeProcessHandle OpenProcess(uint access,bool inherit,int pid);
    [DllImport("kernel32.dll",SetLastError=true)] private static extern bool GetProcessTimes(SafeProcessHandle process,out long creation,out long exit,out long kernel,out long user);
    [DllImport("kernel32.dll",CharSet=CharSet.Unicode,SetLastError=true)] private static extern bool QueryFullProcessImageName(SafeProcessHandle process,uint flags,StringBuilder name,ref int size);
    [DllImport("kernel32.dll",SetLastError=true)] private static extern bool IsProcessCritical(SafeProcessHandle process,out bool critical);
    [DllImport("kernel32.dll",SetLastError=true)] private static extern bool TerminateProcess(SafeProcessHandle process,uint code);
    [DllImport("kernel32.dll",SetLastError=true)] private static extern uint WaitForSingleObject(SafeProcessHandle handle,uint milliseconds);
    [StructLayout(LayoutKind.Sequential)] private struct FileBasicInfo {public long Created,Accessed,Written,Changed;public uint Attributes;}
    [DllImport("kernel32.dll",SetLastError=true)] private static extern bool GetFileInformationByHandleEx(SafeFileHandle file,int informationClass,out FileBasicInfo information,uint size);
    [StructLayout(LayoutKind.Sequential)] private struct FileIdInfo {public ulong Volume;[MarshalAs(UnmanagedType.ByValArray,SizeConst=16)]public byte[] Id;}
    [DllImport("kernel32.dll",SetLastError=true,EntryPoint="GetFileInformationByHandleEx")]private static extern bool FileId(SafeFileHandle file,int informationClass,out FileIdInfo information,uint size);
    private static readonly Dictionary<string,string> ImageHashes=[];
    private static readonly object Gate=new();
    private static long hashComputations;
    internal static long HashComputations=>Interlocked.Read(ref hashComputations);
    private static string HashLockedImage(FileStream image)
    {
        string? key=null;
        if(GetFileInformationByHandleEx(image.SafeFileHandle,0,out var basic,(uint)Marshal.SizeOf<FileBasicInfo>())&&FileId(image.SafeFileHandle,18,out var id,(uint)Marshal.SizeOf<FileIdInfo>()))
            key=$"{id.Volume:X16}:{Convert.ToHexString(id.Id)}:{image.Length}:{basic.Created}:{basic.Written}:{basic.Changed}";
        lock(Gate)
        {
            if(key!=null&&ImageHashes.TryGetValue(key,out var cached))return cached;
            // Caller holds a no-write/no-delete image handle throughout lookup/read and subsequent process checks.
            image.Position=0;var hash=Convert.ToHexString(System.Security.Cryptography.SHA256.HashData(image));Interlocked.Increment(ref hashComputations);
            if(key!=null){while(ImageHashes.Count>=256)ImageHashes.Remove(ImageHashes.Keys.First());ImageHashes[key]=hash;}
            return hash;
        }
    }

    public static ProcessIdentity? Capture(int pid,string expectedPath,DateTime eventUtc)
    {
        try
        {
            using var handle=OpenProcess(0x101000,false,pid);
            if(handle.IsInvalid) return null;
            var identity=Read(handle,pid);
            // A PID that was reused after this audit event is not the actor.
            if(identity.CreatedUtcFileTime>eventUtc.ToFileTimeUtc() || !identity.Executable.Equals(expectedPath,StringComparison.OrdinalIgnoreCase)) return null;
            // Trust is stricter than response evidence: no path-only hash-cache reuse, linked image,
            // file changed since process creation, historical event, or exited process.
            // The locked on-disk image is not proof against process hollowing/in-memory injection.
            var now=DateTimeOffset.UtcNow;
            if(now-eventUtc.ToUniversalTime()<=TimeSpan.FromSeconds(30)&&eventUtc.ToUniversalTime()<=now.UtcDateTime&&Path.IsPathFullyQualified(identity.Executable)&&!identity.Executable.StartsWith("\\\\",StringComparison.Ordinal))
            {
                var linked=false;for(string? part=identity.Executable;part!=null;part=Path.GetDirectoryName(part))if((File.GetAttributes(part)&FileAttributes.ReparsePoint)!=0){linked=true;break;}
                if(!linked)
                {
                    using var image=new FileStream(identity.Executable,FileMode.Open,FileAccess.Read,FileShare.Read,65536,FileOptions.SequentialScan);
                    if(image.Length is >0 and <=268435456&&GetFileInformationByHandleEx(image.SafeFileHandle,0,out var before,(uint)Marshal.SizeOf<FileBasicInfo>())&&before.Created<=identity.CreatedUtcFileTime&&before.Written<=identity.CreatedUtcFileTime&&before.Changed<=identity.CreatedUtcFileTime)
                    {
                        var hash=HashLockedImage(image);
                        var after=Read(handle,pid);
                        if(WaitForSingleObject(handle,0)==0x102&&after.CreatedUtcFileTime==identity.CreatedUtcFileTime&&after.Executable.Equals(identity.Executable,StringComparison.OrdinalIgnoreCase)&&GetFileInformationByHandleEx(image.SafeFileHandle,0,out var end,(uint)Marshal.SizeOf<FileBasicInfo>())&&before.Created==end.Created&&before.Written==end.Written&&before.Changed==end.Changed)
                            identity=identity with{Hash=hash,TrustVerified=true,ImageCheckedUtc=DateTimeOffset.UtcNow};
                    }
                }
            }
            if(identity.Hash.Length==0)
            {
                if(identity.Executable.StartsWith(@"\\",StringComparison.Ordinal))return null;
                using var image=new FileStream(identity.Executable,FileMode.Open,FileAccess.Read,FileShare.Read);
                if(image.Length is <=0 or >268435456)return null;
                identity=identity with{Hash=HashLockedImage(image)};
            }
            return identity;
        }
        catch { return null; }
    }
    private static ProcessIdentity Read(SafeProcessHandle handle,int pid)
    {
        if(!GetProcessTimes(handle,out var start,out _,out _,out _)) throw new Win32Exception();
        var text=new StringBuilder(32768); var size=text.Capacity;
        if(!QueryFullProcessImageName(handle,0,text,ref size)) throw new Win32Exception();
        return new(pid,text.ToString(),start,"");
    }
    public static void End(ProcessIdentity expected)
    {
        if(expected.Pid<=4 || expected.Pid==Environment.ProcessId) throw new InvalidOperationException("This process cannot be terminated from Ransom Free.");
        // Use one kernel handle for verification and termination, never reopen by PID after checking.
        using var handle=OpenProcess(0x100001|0x1000,false,expected.Pid);
        if(handle.IsInvalid) throw new Win32Exception();
        var actual=Read(handle,expected.Pid);
        if(actual.CreatedUtcFileTime!=expected.CreatedUtcFileTime || !actual.Executable.Equals(expected.Executable,StringComparison.OrdinalIgnoreCase))
            throw new InvalidOperationException("Process identity changed. No process was stopped.");
        if(!IsProcessCritical(handle,out var critical)) throw new Win32Exception();
        if(critical || actual.Executable.StartsWith(Environment.GetFolderPath(Environment.SpecialFolder.Windows).TrimEnd('\\')+"\\",StringComparison.OrdinalIgnoreCase))
            throw new InvalidOperationException("Critical processes and Windows-directory executables are excluded from termination.");
        if(expected.Hash.Length!=64 || !CanaryMonitor.Hash(actual.Executable).Equals(expected.Hash,StringComparison.OrdinalIgnoreCase))
            throw new InvalidOperationException("Executable content changed since attribution. No process was stopped.");
        if(!TerminateProcess(handle,1)) throw new Win32Exception();
        if(WaitForSingleObject(handle,5000)!=0) throw new InvalidOperationException("Termination requested; exit was not confirmed within five seconds.");
    }
}
