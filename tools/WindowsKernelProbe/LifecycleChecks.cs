using System.Buffers.Binary;
using System.Runtime.InteropServices;
using System.Text;
using System.Text.Json;
using Microsoft.Win32.SafeHandles;

internal static class LifecycleChecks
{
    internal static void Run(string directory)
    {
        Directory.CreateDirectory(directory);var file=Path.Combine(directory,"watched.bin");var neighbor=Path.Combine(directory,"unwatched.bin");
        File.WriteAllBytes(file,new byte[4096]);File.WriteAllBytes(neighbor,new byte[4096]);var checks=new List<string>();
        void Check(bool ok,string label){if(!ok)throw new Exception(label);checks.Add(label);}
        byte[] Message(uint command){var b=new byte[8];BinaryPrimitives.WriteUInt32LittleEndian(b,4);BinaryPrimitives.WriteUInt32LittleEndian(b.AsSpan(4),command);return b;}
        SafeFileHandle Connect(){Marshal.ThrowExceptionForHR(FilterConnectCommunicationPort("\\SeQuesterActorPrototype",0,IntPtr.Zero,0,IntPtr.Zero,out var result));return result;}
        byte[]? Peek(SafeFileHandle p){var b=new byte[3800];var hr=FilterSendMessage(p,Message(2),8,b,3800,out var size);if(hr>=0){Check(size==3800,"native event size");return b;}if(hr is unchecked((int)0x80070103) or unchecked((int)0x801F001A) or unchecked((int)0x8000001A))return null;Marshal.ThrowExceptionForHR(hr);return null;}
        void Ack(SafeFileHandle p,byte[] b){var a=new byte[24];Message(4).CopyTo(a,0);b.AsSpan(8,16).CopyTo(a.AsSpan(8));Marshal.ThrowExceptionForHR(FilterSendMessage(p,a,24,null,0,out _));}
        void Drain(SafeFileHandle p){for(var i=0;i<4096;i++){var b=Peek(p);if(b==null)return;Ack(p,b);}throw new Exception("Queue did not drain");}
        byte[] Health(SafeFileHandle p){var b=new byte[48];Marshal.ThrowExceptionForHR(FilterSendMessage(p,Message(3),8,b,48,out _));return b;}
        byte[] first;
        using(var port=Connect()){
            var target=new StringBuilder(4096);if(QueryDosDevice(file[..2],target,target.Capacity)==0)throw new System.ComponentModel.Win32Exception();
            var scope=new byte[1548];Message(5).CopyTo(scope,0);BinaryPrimitives.WriteUInt32LittleEndian(scope.AsSpan(8),1);Encoding.Unicode.GetBytes(target+file[2..]).CopyTo(scope,12);
            Marshal.ThrowExceptionForHR(FilterSendMessage(port,scope,(uint)scope.Length,null,0,out _));Drain(port);
            File.ReadAllBytes(neighbor);Check(Peek(port)==null,"exact-path scope excludes neighboring file");
            File.ReadAllBytes(file);first=Peek(port)??throw new Exception("No event");Check(first.SequenceEqual(Peek(port)!),"peek is stable until acknowledgement");
            File.WriteAllBytes(Path.Combine(directory,"before-disconnect.record"),first);
        }
        using(var port=Connect()){
            Check(first.SequenceEqual(Peek(port)!),"disconnect before ACK preserves identical queue head");
            var wrong=new byte[24];Message(4).CopyTo(wrong,0);Check(FilterSendMessage(port,wrong,24,null,0,out _)<0,"wrong ACK cannot remove evidence");
            Check(first.SequenceEqual(Peek(port)!),"wrong ACK leaves event intact");Drain(port);
            var before=Health(port);for(var i=0;i<1200;i++)File.ReadAllBytes(file);var after=Health(port);
            Check(BitConverter.ToInt32(after,40)<=2048,"kernel queue stays within bounded capacity");
            Check(BitConverter.ToInt64(after,24)>BitConverter.ToInt64(before,24),"disconnected-consumer overflow is visible in dropped counter");
            Drain(port);Check(BitConverter.ToInt32(Health(port),40)==0,"all acknowledged records drain after overflow");
            File.WriteAllText(Path.Combine(directory,"RESULTS.json"),JsonSerializer.Serialize(new{Passed=true,Assertions=checks.Count,Checks=checks.Distinct().ToArray(),Dropped=BitConverter.ToInt64(after,24),Queued=BitConverter.ToInt32(after,40),DriverInstance=BitConverter.ToUInt64(after,8).ToString("X16")}));
        }
    }
    [DllImport("fltlib.dll",CharSet=CharSet.Unicode)]private static extern int FilterConnectCommunicationPort(string name,uint options,IntPtr context,ushort size,IntPtr security,out SafeFileHandle port);
    [DllImport("fltlib.dll")]private static extern int FilterSendMessage(SafeFileHandle port,byte[] input,uint size,[Out]byte[]? output,uint outputSize,out uint returned);
    [DllImport("kernel32.dll",CharSet=CharSet.Unicode,SetLastError=true)]private static extern uint QueryDosDevice(string name,StringBuilder target,int length);
}
