using System.ComponentModel;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;

namespace RansomFree;

// Keep every directory component open without delete sharing while deploying.
// Opening each component as a reparse point prevents a junction swap from redirecting privileged writes.
internal sealed class DeploymentPathLease:IDisposable
{
    private readonly List<SafeFileHandle> handles=[];
    [StructLayout(LayoutKind.Sequential)] private struct AttributeTag {public uint Attributes;public uint Tag;}
    [DllImport("kernel32.dll",CharSet=CharSet.Unicode,SetLastError=true)]
    private static extern SafeFileHandle CreateFile(string name,uint access,uint share,IntPtr security,uint creation,uint flags,IntPtr template);
    [DllImport("kernel32.dll",SetLastError=true)]
    private static extern bool GetFileInformationByHandleEx(SafeFileHandle file,int informationClass,out AttributeTag info,uint size);
    public static DeploymentPathLease Acquire(string folder,string? existingFile=null)
    {
        var lease=new DeploymentPathLease();
        try
        {
            var components=new Stack<string>();for(string? current=Path.GetFullPath(folder);current!=null;current=Path.GetDirectoryName(current))components.Push(current);
            while(components.TryPop(out var component))lease.Pin(component,true);
            if(existingFile!=null)lease.Pin(existingFile,false);
            return lease;
        }
        catch{lease.Dispose();throw;}
    }
    private void Pin(string path,bool directory)
    {
        var handle=CreateFile(path,0x80,3,IntPtr.Zero,3,0x02200000,IntPtr.Zero);
        if(handle.IsInvalid){handle.Dispose();throw new Win32Exception(Marshal.GetLastWin32Error(),"Cannot protect deployment path from replacement.");}
        handles.Add(handle);
        if(!GetFileInformationByHandleEx(handle,9,out var info,8))throw new Win32Exception(Marshal.GetLastWin32Error());
        if((info.Attributes&0x400)!=0 || directory && (info.Attributes&0x10)==0)throw new IOException("Deployment path contains a link or invalid folder.");
    }
    public void Dispose(){for(var i=handles.Count-1;i>=0;i--)handles[i].Dispose();handles.Clear();}
}
