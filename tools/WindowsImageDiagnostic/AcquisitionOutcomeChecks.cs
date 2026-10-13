using System.Buffers.Binary;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text.Json;
using Microsoft.Win32.SafeHandles;

// Private qualification of actual queued operation snapshots; capability stays off.
static class AcquisitionOutcomeChecks
{
    static uint U32(byte[] b,int o)=>BinaryPrimitives.ReadUInt32LittleEndian(b.AsSpan(o));
    static ulong U64(byte[] b,int o)=>BinaryPrimitives.ReadUInt64LittleEndian(b.AsSpan(o));
    static void P32(byte[] b,int o,uint v)=>BinaryPrimitives.WriteUInt32LittleEndian(b.AsSpan(o),v);
    static void P64(byte[] b,int o,ulong v)=>BinaryPrimitives.WriteUInt64LittleEndian(b.AsSpan(o),v);
    static byte[] Message(uint command,int size=8){var b=new byte[size];P32(b,0,4);P32(b,4,command);return b;}
    static byte[] Send(SafeFileHandle p,byte[] q,int length)
    {
        var b=new byte[length];Marshal.ThrowExceptionForHR(Native.FilterSendMessage(p,q,(uint)q.Length,b,(uint)length,out var n));
        if(n!=length)throw new IOException("Acquisition reply length mismatch");return b;
    }
    static byte[] Key(byte[] provider,ulong epoch,byte[] e)
    {
        var q=Message(34,48);provider.CopyTo(q,8);P64(q,24,epoch);e.AsSpan(8,16).CopyTo(q.AsSpan(32));return q;
    }
    static void Reject(SafeFileHandle p,byte[] q)
    {
        var hr=Native.FilterSendMessage(p,q,(uint)q.Length,new byte[128],128,out _);
        if(hr!=unchecked((int)0x80070490))throw new IOException($"Wrong or acknowledged acquisition key accepted: {hr:X8}");
    }
    static void Ack(SafeFileHandle p,byte[] e){var q=Message(4,24);e.AsSpan(8,16).CopyTo(q.AsSpan(8));Send(p,q,0);}
    static byte[]? Head(SafeFileHandle p)
    {
        var q=Message(2);var b=new byte[3800];var hr=Native.FilterSendMessage(p,q,8,b,3800,out var n);
        if(hr is unchecked((int)0x80070103) or unchecked((int)0x801F001A) or unchecked((int)0x8000001A))return null;
        Marshal.ThrowExceptionForHR(hr);if(n!=3800||U32(b,0)!=4||U32(b,4)!=3800)throw new IOException("Operation wire schema mismatch");return b;
    }
    internal static int Child(string[] args)
    {
        using var ready=EventWaitHandle.OpenExisting(args[2]);using var go=EventWaitHandle.OpenExisting(args[3]);using var release=EventWaitHandle.OpenExisting(args[4]);
        File.ReadAllBytes(args[1]);ready.Set();if(!go.WaitOne(30000))return 3;
        File.ReadAllBytes(args[1]);ready.Set();return release.WaitOne(30000)?0:4;
    }
    internal static void Run(string directory,bool requireFaultControlsAbsent=false)
    {
        var root=Path.GetFullPath(directory);if(Directory.Exists(root))throw new IOException("New qualification root required");Directory.CreateDirectory(root);
        var path=Path.Combine(root,"acquisition-honeypot.txt");File.WriteAllText(path,"controlled operation outcome qualification");
        Marshal.ThrowExceptionForHR(Native.FilterConnectCommunicationPort("\\SeQuesterActorPrototype",0,IntPtr.Zero,0,IntPtr.Zero,out var port));
        using(port)
        {
            if(requireFaultControlsAbsent)
            {
                foreach(var command in new uint[]{41,42})
                {
                    var q=Message(command,command==41?64:8);
                    var hr=Native.FilterSendMessage(port,q,(uint)q.Length,new byte[128],128,out _);
                    // No output or byte-count evidence is usable after a failed call.
                    if(hr!=unchecked((int)0x80070057))throw new IOException($"Release exposes qualification fault command {command}: {hr:X8}");
                }
                File.WriteAllText(Path.Combine(root,"fault-controls-absent.json"),JsonSerializer.Serialize(new{Passed=true,Commands=new[]{41,42},ExpectedHResult="0x80070057",Host=Environment.MachineName}));
            }
            var suffix=Guid.NewGuid().ToString("N");var rn="Local\\SqAcqReady"+suffix;var gn="Local\\SqAcqGo"+suffix;var fn="Local\\SqAcqRelease"+suffix;
            using var ready=new EventWaitHandle(false,EventResetMode.ManualReset,rn);using var go=new EventWaitHandle(false,EventResetMode.ManualReset,gn);using var release=new EventWaitHandle(false,EventResetMode.ManualReset,fn);
            Process? actor=null;bool started=false;var rows=new List<object>();int drained=0,rejected=0;
            try
            {
                Send(port,Message(6),0);started=true;OperationBindingChecks.Scope(port,path);
                var before=OperationBindingChecks.Health(port);var provider=Convert.FromHexString(before.Provider);
                var caps=Send(port,Message(35),48);var epoch=U64(caps,24);
                if(U32(caps,0)!=1||U32(caps,4)!=48||!caps.AsSpan(8,16).SequenceEqual(provider)||epoch==0||U64(caps,32)!=0||U32(caps,40)!=1||U32(caps,44)!=128)throw new IOException("Unqualified capability unexpectedly enabled or malformed");
                byte[] Outcome(byte[] e,uint state)
                {
                    var q=Key(provider,epoch,e);var b=Send(port,q,128);
                    if(U32(b,0)!=1||U32(b,4)!=128||!b.AsSpan(8,16).SequenceEqual(provider)||U64(b,24)!=epoch||U64(b,32)!=U64(e,8)||U64(b,40)!=U64(e,16)||U64(b,80)==0||U32(b,92)!=state||U32(b,108)!=0||U64(b,112)!=0||U64(b,120)!=0)throw new IOException($"Immutable outcome state/key mismatch; expected {state}, got {U32(b,92)}");
                    return b;
                }
                byte[] FindRead(int pid,long created)
                {
                    for(int i=0;i<512;i++)
                    {
                        var e=Head(port)??throw new IOException("Expected controlled read absent");
                        if(U64(e,48)==(ulong)pid&&U64(e,40)==(ulong)created&&U32(e,76)==3&&U32(e,88)==0)return e;
                        Ack(port,e);drained++;
                    }
                    throw new IOException("Bounded queue search exhausted");
                }
                File.ReadAllBytes(path);
                var parent=FindRead(Environment.ProcessId,Process.GetCurrentProcess().StartTime.ToUniversalTime().ToFileTimeUtc());var absent=Outcome(parent,0);
                if(U64(absent,48)!=0||U64(absent,56)!=0||U64(absent,64)!=0||U64(absent,72)!=0||U32(absent,88)!=0xC0000225||U32(absent,100)!=0)throw new IOException("Preexisting process association fabricated");
                rows.Add(new{Name="preexisting-process-unavailable",Raw=Convert.ToHexString(absent),OperationSha256=Convert.ToHexString(SHA256.HashData(parent))});Ack(port,parent);
                while(Head(port) is { } old){Ack(port,old);drained++;if(drained>512)throw new IOException("Queue did not drain");}
                var image=Environment.ProcessPath??throw new IOException("Apphost required");var psi=new ProcessStartInfo(image){UseShellExecute=false,CreateNoWindow=true};
                foreach(var arg in new[]{"--acquisition-child",path,rn,gn,fn})psi.ArgumentList.Add(arg);
                actor=Process.Start(psi)??throw new IOException("Owned actor did not start");var owned=actor.Handle;var child=new Child("acquisition-outcome",actor.Id,actor.StartTime.ToUniversalTime().ToFileTimeUtc(),image);
                if(!ready.WaitOne(15000))throw new TimeoutException("First controlled actor read missing");
                var first=FindRead(child.ProcessId,child.CreatedFileTime);var pinned=Outcome(first,5);
                var bindingKey=Message(18,40);first.AsSpan(8,16).CopyTo(bindingKey.AsSpan(8));provider.CopyTo(bindingKey,24);var binding=Send(port,bindingKey,88);
                if(U64(pinned,48)!=U64(binding,32)||U64(pinned,64)!=U64(binding,40)||U64(pinned,72)!=U64(binding,32)||U64(pinned,56)!=0||U32(pinned,88)!=0||U32(pinned,100)!=2)throw new IOException("Pinned outcome differs from exact actor binding");
                foreach(int o in new[]{8,24,32,40}){var wrong=Key(provider,epoch,first);wrong[o]^=0x80;Reject(port,wrong);rejected++;}
                var copy=ApcPinChecks.CopyLive(port,binding,child,root,image);
                if(!Send(port,Key(provider,epoch,first),128).SequenceEqual(pinned))throw new IOException("ACK of actor bytes mutated queued operation snapshot");
                rows.Add(new{Name="pinned-operation-immutable-after-actor-ack",Raw=Convert.ToHexString(pinned),Copy=copy,Actor=child,OperationSha256=Convert.ToHexString(SHA256.HashData(first))});
                Ack(port,first);Reject(port,Key(provider,epoch,first));rejected++;
                while(Head(port) is { } old){Ack(port,old);drained++;if(drained>512)throw new IOException("Queue did not drain");}
                ready.Reset();go.Set();if(!ready.WaitOne(15000))throw new TimeoutException("Second controlled actor read missing");
                var second=FindRead(child.ProcessId,child.CreatedFileTime);var unavailable=Outcome(second,4);
                if(U64(unavailable,48)!=U64(pinned,48)||U64(unavailable,64)!=U64(pinned,64)||U64(unavailable,72)!=U64(pinned,72)||U32(unavailable,88)!=0xC0000225||U32(unavailable,96)!=0||U32(unavailable,100)!=1)throw new IOException("Retired bytes lost exact generation or became pending");
                rows.Add(new{Name="later-operation-bytes-unavailable",Raw=Convert.ToHexString(unavailable),OperationSha256=Convert.ToHexString(SHA256.HashData(second))});Ack(port,second);
                OperationBindingChecks.Scope(port,null);Send(port,Message(9),0);started=false;var after=OperationBindingChecks.Health(port);
                if(after.Live!=0||after.ReferencesTaken!=after.ReferencesReleased||after.OperationPins!=after.OperationPinsReleased)throw new IOException("Operation acquisition references did not drain");
                File.WriteAllText(Path.Combine(root,"RESULTS.json"),JsonSerializer.Serialize(new{Schema="sequester.windows-operation-acquisition-qualification/v1",Passed=true,Host=Environment.MachineName,Cases=rows,RejectedKeys=rejected,Drained=drained,Before=before,After=after,CapabilityAdvertised=false,ActualApcCallbackCoverage="APC_CALLBACK_NOT_OBSERVED",Scope="Actual controlled NTFS reads; exact immutable outcomes and actor copy; negative admission and failure qualification remain separate"},new JsonSerializerOptions{WriteIndented=true}));
            }
            finally
            {
                release.Set();go.Set();if(actor!=null){if(!actor.WaitForExit(15000)){actor.Kill();actor.WaitForExit();}actor.Dispose();}
                OperationBindingChecks.Scope(port,null);if(started)Send(port,Message(9),0);
            }
        }
    }
}
