using System.Buffers.Binary;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text.Json;
using Microsoft.Win32.SafeHandles;

// Synthetic nonpaged helper qualification, not filesystem callback coverage.
static class ApcPinChecks
{
    static uint U32(byte[] b,int offset)=>BinaryPrimitives.ReadUInt32LittleEndian(b.AsSpan(offset));
    static ulong U64(byte[] b,int offset)=>BinaryPrimitives.ReadUInt64LittleEndian(b.AsSpan(offset));
    static void Put32(byte[] b,int offset,uint value)=>BinaryPrimitives.WriteUInt32LittleEndian(b.AsSpan(offset),value);
    static void Put64(byte[] b,int offset,ulong value)=>BinaryPrimitives.WriteUInt64LittleEndian(b.AsSpan(offset),value);
    static byte[] Message(uint command,int size=8){var b=new byte[size];Put32(b,0,4);Put32(b,4,command);return b;}
    static byte[] Send(SafeFileHandle port,byte[] input,int length)
    {
        var b=new byte[length];Marshal.ThrowExceptionForHR(Native.FilterSendMessage(port,input,(uint)input.Length,b,(uint)length,out var returned));
        if(returned!=length)throw new IOException("APC branch reply size mismatch");return b;
    }
    static byte[] Query(Child? child,uint iterations=64)
    {
        var b=Message(36,32);Put64(b,8,(ulong)(child?.ProcessId??0));Put64(b,16,(ulong)(child?.CreatedFileTime??0));
        Put32(b,24,iterations);Put32(b,28,child==null?1u:0u);return b;
    }
    internal static object CopyLive(SafeFileHandle port,byte[] binding,Child child,string root,string image)
    {
        byte[] Request(uint operation,uint offset=0,uint length=0)
        {
            var b=Message(19,72);binding.AsSpan(16,16).CopyTo(b.AsSpan(8));
            Put64(b,24,U64(binding,32));Put64(b,32,U64(binding,40));Put64(b,40,(ulong)child.ProcessId);Put64(b,48,(ulong)child.CreatedFileTime);
            Put32(b,56,offset);Put32(b,60,length);Put32(b,64,operation);Put32(b,68,1);return b;
        }
        var metadata=Send(port,Request(13),144);var total=U32(metadata,8);
        void Validate(byte[] b,uint offset,uint length)
        {
            if(U32(b,0)!=3||U32(b,4)!=144||U32(b,8)!=total||U32(b,12)!=offset||U32(b,16)!=length||(U32(b,20)&13)!=13||U64(b,32)!=U64(binding,40)||U64(b,40)!=(ulong)child.ProcessId||U64(b,48)!=(ulong)child.CreatedFileTime||!b.AsSpan(120,16).SequenceEqual(binding.AsSpan(16,16))||U64(b,136)!=U64(binding,32))throw new IOException("Live actor copy identity mismatch");
        }
        if(total==0||total>8*1024*1024)throw new IOException("Live actor copy size invalid");Validate(metadata,0,0);
        var path=Path.Combine(root,"actor.evidence.bin");
        using(var file=new FileStream(path,FileMode.CreateNew,FileAccess.Write,FileShare.None))
        {
            for(uint offset=0;offset<total;){var length=Math.Min(65536u,total-offset);var bytes=Send(port,Request(10,offset,length),checked(144+(int)length));Validate(bytes,offset,length);file.Write(bytes,144,(int)length);offset+=length;}file.Flush(true);
        }
        var original=Convert.ToHexString(SHA256.HashData(File.ReadAllBytes(image)));var preserved=Convert.ToHexString(SHA256.HashData(File.ReadAllBytes(path)));
        if(original!=preserved)throw new IOException("Live preserved executable hash mismatch");Send(port,Request(11),0);
        return new{Path=path,Bytes=total,OriginalSha256=original,PreservedSha256=preserved,Provider=Convert.ToHexString(binding.AsSpan(16,16)),Generation=U64(binding,32),Candidate=U64(binding,40)};
    }
    internal static void Run(string directory)
    {
        var root=Path.GetFullPath(directory);if(Directory.Exists(root))throw new IOException("New private branch receipt directory required");Directory.CreateDirectory(root);
        Marshal.ThrowExceptionForHR(Native.FilterConnectCommunicationPort("\\SeQuesterActorPrototype",0,IntPtr.Zero,0,IntPtr.Zero,out var port));
        using(port)
        {
            var rows=new List<object>();bool started=false;Process? actor=null;
            // Event names must be passed explicitly; existing barrier child is bounded to 30 seconds.
            var readyName="Local\\SequesterAPCReady"+Guid.NewGuid().ToString("N");var releaseName="Local\\SequesterAPCRelease"+Guid.NewGuid().ToString("N");
            using var childReady=new EventWaitHandle(false,EventResetMode.ManualReset,readyName);
            using var childRelease=new EventWaitHandle(false,EventResetMode.ManualReset,releaseName);
            try
            {
                Send(port,Message(6),0);started=true;
                var before=OperationBindingChecks.Health(port);
                var image=Environment.ProcessPath??throw new IOException("Apphost required");
                var start=new ProcessStartInfo(image){UseShellExecute=false,CreateNoWindow=true};
                start.ArgumentList.Add("--barrier-child");start.ArgumentList.Add(readyName);start.ArgumentList.Add(releaseName);
                actor=Process.Start(start)??throw new IOException("Owned actor failed to start");var owned=actor.Handle;
                var child=new Child("apc-pin-branch",actor.Id,actor.StartTime.ToUniversalTime().ToFileTimeUtc(),image);
                if(!childReady.WaitOne(15000))throw new TimeoutException("Owned actor readiness missing");
                var slot=Staging.Table(port).Single(s=>s.Pid==(ulong)child.ProcessId&&s.Created==(ulong)child.CreatedFileTime&&s.Ready==1);
                var pins=Send(port,Query(child),112);
                if(U32(pins,0)!=1||U32(pins,4)!=112||U32(pins,8)!=1||U32(pins,12)!=64||U32(pins,16)!=64||U32(pins,20)!=64||U32(pins,24)!=2||U32(pins,28)!=88||U32(pins,32)!=1||U32(pins,36)!=0||U64(pins,64)!=slot.Id||U64(pins,72)!=(ulong)child.ProcessId||U64(pins,80)!=(ulong)child.CreatedFileTime||U64(pins,96)!=0||U64(pins,104)!=0)throw new IOException("Exact resident APC pins did not match independent actor");
                rows.Add(new{Name="resident-blob",Attempts=64,Pins=64,Release=64,Actor=child,Raw=Convert.ToHexString(pins)});
                var absent=Send(port,Query(null),112);
                if(U32(absent,16)!=0||U32(absent,20)!=0||U32(absent,32)!=0||U32(absent,92)!=2)throw new IOException("Null actor acquired bytes or lost absence reason");
                rows.Add(new{Name="absent-actor",Raw=Convert.ToHexString(absent)});
                var bad=Query(child);Put64(bad,16,(ulong)child.CreatedFileTime+1);
                if(Native.FilterSendMessage(port,bad,32,new byte[112],112,out _)!=unchecked((int)0x80070490))throw new IOException("Reused PID key accepted");
                var invalid=Query(child,65);
                if(Native.FilterSendMessage(port,invalid,32,new byte[112],112,out _)!=unchecked((int)0x80070057))throw new IOException("Unbounded branch request accepted");
                var copy=CopyLive(port,pins.AsSpan(24,88).ToArray(),child,root,image);
                rows.Add(new{Name="actor-copy",Copy=copy});
                var acknowledged=Send(port,Query(child),112);
                if(U32(acknowledged,16)!=0||U32(acknowledged,20)!=0||U32(acknowledged,32)!=2||U32(acknowledged,92)!=4)throw new IOException("Acknowledged actor blob remained available or unavailable reason is incorrect");
                rows.Add(new{Name="acknowledged-blob",Raw=Convert.ToHexString(acknowledged)});
                Send(port,Message(9),0);started=false;
                var retired=Send(port,Query(child),112);
                if(U32(retired,16)!=0||U32(retired,20)!=0||U32(retired,32)!=0||U32(retired,92)!=3)throw new IOException("Stopped provider acquired bytes or lost stop reason");
                rows.Add(new{Name="stopped-provider",Raw=Convert.ToHexString(retired)});
                var after=OperationBindingChecks.Health(port);
                if(after.OperationPins-before.OperationPins!=64||after.OperationPinsReleased-before.OperationPinsReleased!=64||after.Live!=0||after.ReferencesTaken!=after.ReferencesReleased)throw new IOException("APC pin references failed to drain");
                File.WriteAllText(Path.Combine(root,"RESULTS.json"),JsonSerializer.Serialize(new{Schema="sequester.windows-apc-pin-branch/v1",Passed=true,Host=Environment.MachineName,Cases=rows,Before=before,After=after,ActualCallbackCoverage="APC_CALLBACK_NOT_OBSERVED",Scope="Synthetic APC entry into nonpaged blob pin only; no token or filesystem callback guarantee"},new JsonSerializerOptions{WriteIndented=true}));
            }
            finally
            {
                childRelease.Set();if(actor!=null){if(!actor.WaitForExit(15000)){actor.Kill();actor.WaitForExit();}actor.Dispose();}
                if(started)Send(port,Message(9),0);
            }
        }
    }
}
