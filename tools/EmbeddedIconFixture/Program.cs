using System.Buffers.Binary;
using System.Runtime.InteropServices;
using System.Security.Cryptography;

if(!OperatingSystem.IsWindows()||args.Length!=2||!args.All(Path.IsPathFullyQualified))throw new ArgumentException("Provide a Windows executable and canonical ICO path.");
var executable=Path.GetFullPath(args[0]);var canonical=Path.GetFullPath(args[1]);
if((File.GetAttributes(executable)&FileAttributes.ReparsePoint)!=0||(File.GetAttributes(canonical)&FileAttributes.ReparsePoint)!=0)throw new IOException("Use unlinked local files.");
var root=Path.Combine("D:\\Codex\\RansomFree\\tests","embedded-icon-"+Guid.NewGuid().ToString("N"));Directory.CreateDirectory(root);
var checks=new List<string>();void Check(bool result,string message){if(!result)throw new InvalidDataException(message);checks.Add("PASS: "+message);Console.WriteLine(checks[^1]);File.WriteAllLines(Path.Combine(root,"results.txt"),checks);}
var ico=File.ReadAllBytes(canonical);
Check(Convert.ToHexString(SHA256.HashData(ico))=="26627790C3D1748B756751C1EEA6E3FF958A0D4F64B5A309AF3ED94BC2DFB7A1","input is the frozen canonical-derived seQuester ICO");
Check(ico.Length>=6&&BinaryPrimitives.ReadUInt16LittleEndian(ico.AsSpan(0,2))==0&&BinaryPrimitives.ReadUInt16LittleEndian(ico.AsSpan(2,2))==1,"canonical ICO header valid");
var count=BinaryPrimitives.ReadUInt16LittleEndian(ico.AsSpan(4,2));Check(count is >0 and <=32&&ico.Length>=6+count*16,"bounded canonical frame directory");
// Load as inert resource data. This never starts the executable or runs DllMain.
var module=Native.LoadLibraryEx(executable,0,0x40|0x20);if(module==0)throw new System.ComponentModel.Win32Exception(Marshal.GetLastPInvokeError());
try
{
    byte[] Resource(nint name,nint type)
    {
        var resource=Native.FindResource(module,name,type);if(resource==0)throw new InvalidDataException("Icon resource missing.");
        var size=Native.SizeofResource(module,resource);if(size is 0 or >16777216)throw new InvalidDataException("Icon resource length invalid.");
        var loaded=Native.LoadResource(module,resource);var pointer=Native.LockResource(loaded);if(pointer==0)throw new InvalidDataException("Icon resource unreadable.");
        var bytes=new byte[size];Marshal.Copy(pointer,bytes,0,checked((int)size));return bytes;
    }
    var groups=new List<byte[]>();Exception? failure=null;
    Native.EnumName callback=(handle,type,name,parameter)=>{try{groups.Add(Resource(name,type));return groups.Count<=8;}catch(Exception ex){failure=ex;return false;}};
    var enumerated=Native.EnumResourceNames(module,14,callback,0);GC.KeepAlive(callback);
    if(failure!=null)throw failure;
    Check(enumerated&&groups.Count==1,"executable has exactly one application icon group");
    var group=groups.Single();
    Check(group.Length==6+count*14&&group.AsSpan(0,6).SequenceEqual(ico.AsSpan(0,6)),"embedded frame count and group header match canonical ICO");
    for(var i=0;i<count;i++)
    {
        var expected=ico.AsSpan(6+i*16,16);var actual=group.AsSpan(6+i*14,14);
        var length=BinaryPrimitives.ReadUInt32LittleEndian(expected[8..12]);var offset=BinaryPrimitives.ReadUInt32LittleEndian(expected[12..16]);
        Check(length>0&&(ulong)offset+length<=(ulong)ico.Length&&actual[..12].SequenceEqual(expected[..12]),"embedded frame "+(i+1)+" dimensions, depth and length match");
        var id=BinaryPrimitives.ReadUInt16LittleEndian(actual[12..14]);
        Check(Resource(id,3).AsSpan().SequenceEqual(ico.AsSpan(checked((int)offset),checked((int)length))),"embedded frame "+(i+1)+" pixel payload matches exactly");
    }
    File.WriteAllText(Path.Combine(root,"identity.txt"),executable+Environment.NewLine+Convert.ToHexString(SHA256.HashData(File.ReadAllBytes(executable)))+Environment.NewLine+"Resource integrity only; not Shell/taskbar appearance or code-signing acceptance.");
}
finally{Native.FreeLibrary(module);}
Console.WriteLine(root);
internal static class Native
{
    internal delegate bool EnumName(nint module,nint type,nint name,nint parameter);
    [DllImport("kernel32.dll",EntryPoint="LoadLibraryExW",CharSet=CharSet.Unicode,SetLastError=true)]internal static extern nint LoadLibraryEx(string path,nint file,uint flags);
    [DllImport("kernel32.dll",EntryPoint="FindResourceW",SetLastError=true)]internal static extern nint FindResource(nint module,nint name,nint type);
    [DllImport("kernel32.dll",SetLastError=true)]internal static extern uint SizeofResource(nint module,nint resource);
    [DllImport("kernel32.dll",SetLastError=true)]internal static extern nint LoadResource(nint module,nint resource);
    [DllImport("kernel32.dll",SetLastError=true)]internal static extern nint LockResource(nint resource);
    [DllImport("kernel32.dll",EntryPoint="EnumResourceNamesW",SetLastError=true)]internal static extern bool EnumResourceNames(nint module,nint type,EnumName callback,nint parameter);
    [DllImport("kernel32.dll")]internal static extern bool FreeLibrary(nint module);
}
