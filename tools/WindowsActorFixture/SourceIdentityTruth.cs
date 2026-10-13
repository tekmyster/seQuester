using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Text;
using Microsoft.Win32.SafeHandles;

// Qualification ground truth from Win32 on the original file, independent of
// the minifilter companion protocol and of the identity of any private copy.
internal sealed record SourceIdentityTruth(string Path,string VolumeGuid,string FileIndex,string StableId,long Size,DateTimeOffset RecordedUtc)
{
    internal static SourceIdentityTruth Capture(string path)
    {
        path=System.IO.Path.GetFullPath(path);
        using var file=new FileStream(path,FileMode.Open,FileAccess.Read,FileShare.Read);
        if(!GetFileInformationByHandle(file.SafeFileHandle,out var before))throw new Win32Exception();
        var name=new StringBuilder(32768);
        var count=GetFinalPathNameByHandleW(file.SafeFileHandle,name,(uint)name.Capacity,1);
        if(count==0)throw new Win32Exception();
        if(count>=name.Capacity)throw new IOException("Independent volume path exceeds buffer");
        var final=name.ToString();
        if(!final.StartsWith(@"\\?\Volume",StringComparison.Ordinal)||final.Length<49||final[48]!='\\'||!Guid.TryParseExact(final.AsSpan(10,38),"B",out var guid))throw new IOException("Independent source is not a volume GUID path");
        if(!GetFileInformationByHandle(file.SafeFileHandle,out var after))throw new Win32Exception();
        if(!before.Equals(after))throw new IOException("Original executable changed during independent identity query");
        var index=((ulong)before.IndexHigh<<32)|before.IndexLow;
        if(index==0)throw new IOException("Independent original file index unavailable");
        var volume=guid.ToString("N").ToUpperInvariant();var id=index.ToString("X16");
        return new(path,volume,id,"windows-volume-guid:"+volume+":file-index:"+id,((long)before.SizeHigh<<32)|before.SizeLow,DateTimeOffset.UtcNow);
    }
    [StructLayout(LayoutKind.Sequential)]private struct FileInfo
    {
        public uint Attributes,CreatedLow,CreatedHigh,AccessedLow,AccessedHigh,WrittenLow,WrittenHigh,VolumeSerial,SizeHigh,SizeLow,Links,IndexHigh,IndexLow;
    }
    [DllImport("kernel32.dll",SetLastError=true)][return:MarshalAs(UnmanagedType.Bool)]private static extern bool GetFileInformationByHandle(SafeFileHandle file,out FileInfo information);
    [DllImport("kernel32.dll",CharSet=CharSet.Unicode,SetLastError=true)]private static extern uint GetFinalPathNameByHandleW(SafeFileHandle file,StringBuilder path,uint size,uint flags);
}
