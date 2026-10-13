using System.Buffers.Binary;
using System.ComponentModel;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;

namespace RansomFree.Client;

// Verified against lease.bpf.c and pinned Linux6.12 UAPI: lost is an ARRAY
// with one u32 key and one u64 value. The runtime must bind the ID to its owned
// child's ready message and stop sampling when that child exits. A surviving
// map FD alone never proves that a loader is alive or observations continuous.
internal sealed class LinuxBpfLostMap:IDisposable
{
    internal sealed record MapIdentity(uint Type,uint Id,uint KeySize,uint ValueSize,uint Entries,uint Flags,string Name);
    private readonly ILinuxLostMapTransport transport;
    private readonly object gate=new();
    private bool disposed;
    internal MapIdentity Identity {get;}
    internal ulong InitialValue {get;}
    private readonly bool atomic;
    private LinuxBpfLostMap(ILinuxLostMapTransport transport,uint expectedId,ulong expectedInitial,bool atomic=false)
    {
        this.atomic=atomic;
        this.transport=transport;var bytes=transport.ReadInfo(out var returnedLength);
        if(bytes.Length!=40||returnedLength<40)throw new InvalidDataException("BPF lost-map identity prefix unavailable");
        uint U(int offset)=>BinaryPrimitives.ReadUInt32LittleEndian(bytes.AsSpan(offset));
        var expectedName=new byte[16];if(atomic)"op_health"u8.CopyTo(expectedName);else "lost"u8.CopyTo(expectedName);
        if(expectedId==0||U(0)!=2||U(4)!=expectedId||U(8)!=4||U(12)!=8||U(16)!=(atomic?6u:1u)||U(20)!=0||!bytes.AsSpan(24).SequenceEqual(expectedName))
            throw new InvalidDataException("BPF lost-map identity/layout differs from the qualified provider");
        Identity=new(U(0),U(4),U(8),U(12),U(16),U(20),atomic?"op_health":"lost");
        InitialValue=ReadCounters();
        if(InitialValue!=expectedInitial)throw new InvalidDataException("BPF lost counter differs from owned loader ready sample");
    }
    internal static LinuxBpfLostMap Open(uint mapId,ulong readySample,bool atomic=false)
    {
        if(!OperatingSystem.IsLinux()||IntPtr.Size!=8||!BitConverter.IsLittleEndian)throw new PlatformNotSupportedException("Qualified Linux64 little-endian BPF ABI required");
        if(mapId==0)throw new ArgumentException("Nonzero owned loader map ID required");
        return OpenCore(new NativeTransport(mapId),mapId,readySample,atomic);
    }
    internal static LinuxBpfLostMap OpenForTest(ILinuxLostMapTransport transport,uint mapId,ulong readySample,bool atomic=false)=>OpenCore(transport,mapId,readySample,atomic);
    private static LinuxBpfLostMap OpenCore(ILinuxLostMapTransport transport,uint mapId,ulong readySample,bool atomic=false)
    {
        try{return new(transport,mapId,readySample,atomic);}
        catch(Exception original)
        {
            try{transport.Dispose();}catch(Exception cleanup){throw new AggregateException("BPF map admission failed and descriptor cleanup was uncertain",original,cleanup);}throw;
        }
    }
    internal ulong Sample()
    {lock(gate){ObjectDisposedException.ThrowIf(disposed,this);return ReadCounters();}}
    internal sealed record CounterSample(ulong Total,ulong[] Values);
    internal CounterSample SampleDetailed()
    {
        lock(gate)
        {
            ObjectDisposedException.ThrowIf(disposed,this);
            var values=new ulong[atomic?6:1];ulong total=0;
            for(uint key=0;key<values.Length;key++)
            {values[key]=atomic?transport.ReadCounter(key):transport.ReadCounter();total=checked(total+values[key]);}
            return new(total,values);
        }
    }
    private ulong ReadCounters()
    {
        if(!atomic)return transport.ReadCounter();
        ulong total=0;for(uint key=0;key<6;key++)total=checked(total+transport.ReadCounter(key));return total;
    }
    public void Dispose()
    {lock(gate){if(disposed)return;disposed=true;transport.Dispose();}}

    private sealed class NativeTransport:ILinuxLostMapTransport
    {
        private readonly MapHandle handle=new();
        [StructLayout(LayoutKind.Sequential)]private struct GetFdOptions {internal nuint Size;internal uint OpenFlags;internal uint Padding;}
        [DllImport("libbpf.so.1",SetLastError=true,CallingConvention=CallingConvention.Cdecl,EntryPoint="bpf_map_get_fd_by_id_opts")]
        private static extern int OpenMap(uint id,ref GetFdOptions options);
        [DllImport("libbpf.so.1",SetLastError=true,CallingConvention=CallingConvention.Cdecl,EntryPoint="bpf_obj_get_info_by_fd")]
        private static extern int GetInfo(MapHandle fd,[In,Out] byte[] info,ref uint length);
        [DllImport("libbpf.so.1",SetLastError=true,CallingConvention=CallingConvention.Cdecl,EntryPoint="bpf_map_lookup_elem")]
        private static extern int Lookup(MapHandle fd,ref uint key,out ulong value);
        [DllImport("libc",SetLastError=true,EntryPoint="fcntl")]private static extern int DescriptorFlags(MapHandle fd,int command);
        internal NativeTransport(uint id)
        {
            // BPF_F_RDONLY is bit3, not POSIX O_RDONLY. A referenced read-only
            // descriptor is opened once; sampling never reopens a numeric ID.
            var options=new GetFdOptions{Size=(nuint)Marshal.SizeOf<GetFdOptions>(),OpenFlags=1u<<3};
            if(options.Size!=16)throw new PlatformNotSupportedException("Unexpected libbpf option ABI");
            var fd=OpenMap(id,ref options);if(fd<0)throw new Win32Exception(Marshal.GetLastPInvokeError(),"BPF_MAP_GET_FD_BY_ID read-only open failed");handle.Initialize(fd);
            try
            {
                var flags=DescriptorFlags(handle,3); // Linux F_GETFL; O_ACCMODE mask3.
                if(flags<0)throw new Win32Exception(Marshal.GetLastPInvokeError(),"BPF map descriptor flags unavailable");
                if((flags&3)!=0)throw new InvalidDataException("BPF lost-map descriptor was not opened read-only");
            }
            catch(Exception original){handle.Dispose();if(handle.CloseError!=0)throw new AggregateException("Lost-map admission and descriptor cleanup failed",original,new Win32Exception(handle.CloseError));throw;}
        }
        public byte[] ReadInfo(out uint returnedLength)
        {
            var info=new byte[40];returnedLength=40;
            if(GetInfo(handle,info,ref returnedLength)!=0)throw new Win32Exception(Marshal.GetLastPInvokeError(),"BPF_OBJ_GET_INFO_BY_FD failed");return info;
        }
        public ulong ReadCounter()
        {
            uint key=0;if(Lookup(handle,ref key,out var value)!=0)throw new Win32Exception(Marshal.GetLastPInvokeError(),"BPF_MAP_LOOKUP_ELEM lost counter unavailable");return value;
        }
        public ulong ReadCounter(uint key)
        {if(key>=6)throw new ArgumentOutOfRangeException(nameof(key));if(Lookup(handle,ref key,out var value)!=0)throw new Win32Exception(Marshal.GetLastPInvokeError(),"BPF operation health counter unavailable");return value;}
        public void Dispose(){handle.Dispose();if(handle.CloseError!=0)throw new Win32Exception(handle.CloseError,"BPF map descriptor close returned an error; no retry");}
        private sealed class MapHandle:SafeHandleMinusOneIsInvalid
        {
            internal MapHandle():base(true){}
            internal int CloseError {get;private set;}
            internal void Initialize(int fd)=>SetHandle((IntPtr)fd);
            [DllImport("libc",SetLastError=true,EntryPoint="close")]private static extern int Close(int fd);
            protected override bool ReleaseHandle(){var result=Close(handle.ToInt32());if(result!=0)CloseError=Marshal.GetLastPInvokeError();return result==0;}
        }
    }
}
internal interface ILinuxLostMapTransport:IDisposable
{
    byte[] ReadInfo(out uint returnedLength);
    ulong ReadCounter();
    ulong ReadCounter(uint key)=>key==0?ReadCounter():throw new InvalidDataException("Transport cannot read atomic source health counters");
}
