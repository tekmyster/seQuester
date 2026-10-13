using RansomFree.Contracts;
using System.Buffers.Binary;
using System.Collections.Immutable;
using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Text;
using Microsoft.Win32.SafeHandles;

namespace RansomFree.Client;

// Independent parent-side reads of the exact maps advertised by the owned
// controlled-v2 child. No mutation, actor controller, or activation authority.
// Freeze is established by the hash-pinned native loader and its qualification;
// the map_info prefix itself does not expose a freeze bit.
internal sealed class LinuxControlledMapSet:IDisposable
{
    internal sealed record Layout(uint Type,uint Id,uint KeySize,uint ValueSize,uint Entries,uint Flags,string Name);
    internal sealed record Proof(ImmutableArray<Layout> Maps,string TargetSetSha256,ulong ProviderEpoch,ulong InitialLost);
    private readonly List<ILinuxControlledMapReader> owned=[];
    private readonly object gate=new();
    private bool disposed;
    private byte[] verifiedReady=[];
    internal Proof Verified {get;private set;}=null!;
    // Includes every map role, target, epoch, nonce and program ID actually
    // admitted against the retained descriptors. No ID-based map reopen.
    internal bool MatchesReadyFrame(ReadOnlySpan<byte> raw)
    {lock(gate)return !disposed&&verifiedReady.Length!=0&&raw.SequenceEqual(verifiedReady);}
    private LinuxControlledMapSet(){}
    internal static LinuxControlledMapSet Open(LinuxControlledLoaderProtocol.Ready ready,LinuxControlledTargetSet prepared)
    {
        if(!OperatingSystem.IsLinux()||RuntimeInformation.ProcessArchitecture!=Architecture.X64||!BitConverter.IsLittleEndian)throw new PlatformNotSupportedException("Qualified Linux x64 map ABI required");
        return OpenCore(ready,prepared,id=>new NativeReader(id));
    }
    internal static LinuxControlledMapSet OpenForTest(LinuxControlledLoaderProtocol.Ready ready,LinuxControlledTargetSet prepared,Func<uint,ILinuxControlledMapReader> open)=>OpenCore(ready,prepared,open);
    private static LinuxControlledMapSet OpenCore(LinuxControlledLoaderProtocol.Ready ready,LinuxControlledTargetSet prepared,Func<uint,ILinuxControlledMapReader> open)
    {
        // Reparse the exact immutable frame before any native descriptor opens.
        var exact=LinuxControlledLoaderProtocol.ParseReady(ready.Raw);
        if(exact.ControlVersion is not (2 or 3 or 4)||exact.Targets==null||exact.WatchMapId==null)throw new InvalidDataException("Controlled map identity required");
        exact.Targets.RequireSame(prepared);
        var result=new LinuxControlledMapSet();
        try
        {
            // lease_header=232, lease_event=8424, lease_scratch=8432 bytes in
            // the separately compiled SQ_CONTROLLED_V2 little-endian object.
            Layout[] expected=[new(29,exact.Maps[0],4,8432,0,1,"event_scratch"),new(2,exact.Maps[1],4,24,1,0,"lease_config"),
                new(27,exact.Maps[2],0,0,1048576,0,"events"),new(2,exact.Maps[3],4,8,1,0,"lost"),new(1,exact.WatchMapId.Value,16,8,32,128,"watched_targets")];
            if(exact.ControlVersion==3)expected=[new(29,exact.Maps[0],4,248,0,1,"inode_calls"),new(2,exact.Maps[1],4,8,1,0,"op_config"),
                new(27,exact.Maps[2],0,0,1048576,0,"op_events"),new(2,exact.Maps[3],4,8,6,0,"op_health"),new(1,exact.WatchMapId.Value,16,8,32,128,"op_targets"),
                new(29,exact.FileCallMapId!.Value,4,248,0,1,"file_calls")];
            if(exact.ControlVersion==4)expected=[new(29,exact.Maps[0],4,320,0,1,"inode_calls"),new(2,exact.Maps[1],4,8,1,0,"op_config"),
                new(27,exact.Maps[2],0,0,1048576,0,"op_events"),new(2,exact.Maps[3],4,8,6,0,"op_health"),new(1,exact.WatchMapId.Value,16,8,32,128,"op_targets"),
                new(29,exact.FileCallMapId!.Value,4,320,0,1,"file_calls"),new(29,exact.ScalarCallMapId!.Value,4,320,0,1,"scalar_calls"),new(29,exact.IterCallMapId!.Value,4,320,0,1,"iter_calls")];
            foreach(var layout in expected)
            {
                var reader=open(layout.Id)??throw new InvalidDataException("Map descriptor unavailable");result.owned.Add(reader);
                var bytes=reader.ReadInfo(out var size);
                // The pinned syscall returns min(requested length, map-info
                // size). This request is exactly40 bytes, so any other length
                // is a failed/truncated or contradictory transport response.
                if(size!=40||bytes.Length!=40)throw new InvalidDataException("BPF map identity prefix unavailable");
                uint U(int index)=>BinaryPrimitives.ReadUInt32LittleEndian(bytes.AsSpan(index*4));
                var name=new byte[16];Encoding.ASCII.GetBytes(layout.Name).CopyTo(name,0);
                if(U(0)!=layout.Type||U(1)!=layout.Id||U(2)!=layout.KeySize||U(3)!=layout.ValueSize||U(4)!=layout.Entries||U(5)!=layout.Flags||!bytes.AsSpan(24).SequenceEqual(name))
                    throw new InvalidDataException("Owned BPF map identity/layout mismatch: "+layout.Name);
            }
            var config=result.owned[1].Lookup(new byte[4],exact.ControlVersion is 3 or 4?8:24);
            if(exact.ControlVersion is 3 or 4?(config.Length!=8||BinaryPrimitives.ReadUInt64LittleEndian(config)!=exact.Epoch):
                config.Length!=24||BinaryPrimitives.ReadUInt64LittleEndian(config)!=0||BinaryPrimitives.ReadUInt64LittleEndian(config.AsSpan(8))!=exact.Epoch||BinaryPrimitives.ReadUInt64LittleEndian(config.AsSpan(16))!=0)
                throw new InvalidDataException("Controlled-v2 config must contain exact epoch and zero legacy target/diagnostic mode");
            var lost=result.owned[3].Lookup(new byte[4],8);
            if(lost.Length!=8||BinaryPrimitives.ReadUInt64LittleEndian(lost)!=exact.Lost)throw new InvalidDataException("Ready lost counter changed before map admission");
            if(exact.ControlVersion is 3 or 4)for(uint index=0;index<6;index++)
            {
                var healthKey=new byte[4];BinaryPrimitives.WriteUInt32LittleEndian(healthKey,index);var value=result.owned[3].Lookup(healthKey,8);
                if(value.Length!=8||BinaryPrimitives.ReadUInt64LittleEndian(value)!=exact.HealthAtReady[(int)index])throw new InvalidDataException("Atomic source health changed before map admission");
            }
            var seen=new HashSet<uint>();byte[]? previous=null;
            for(var n=0;;n++)
            {
                var key=result.owned[4].NextKey(previous,16);if(key==null)break;
                if(n>=32||key.Length!=16||BinaryPrimitives.ReadUInt32LittleEndian(key.AsSpan(12))!=0)throw new InvalidDataException("Invalid or unbounded watched map keys");
                var value=result.owned[4].Lookup(key,8);
                if(value.Length!=8||BinaryPrimitives.ReadUInt32LittleEndian(value.AsSpan(4))!=0)throw new InvalidDataException("Invalid watch map value");
                var ordinal=BinaryPrimitives.ReadUInt32LittleEndian(value);var inode=BinaryPrimitives.ReadUInt64LittleEndian(key);var device=BinaryPrimitives.ReadUInt32LittleEndian(key.AsSpan(8));
                if(!exact.Targets.Contains(ordinal,device,inode)||!seen.Add(ordinal))throw new InvalidDataException("Watch map differs from exact prepared/ready target identity set");
                previous=key;
            }
            if(seen.Count!=exact.Targets.Targets.Length)throw new InvalidDataException("Watch map missing configured identities");
            result.Verified=new(expected.ToImmutableArray(),exact.Targets.Digest,exact.Epoch,exact.Lost);result.verifiedReady=exact.Raw;return result;
        }
        catch(Exception original)
        {
            try{result.Dispose();}catch(Exception cleanup){throw new AggregateException("Map admission and descriptor cleanup failed",original,cleanup);}throw;
        }
    }
    public void Dispose()
    {
        lock(gate)
        {
            if(disposed)return;disposed=true;var failures=new List<Exception>();
            for(var n=owned.Count-1;n>=0;n--)try{owned[n].Dispose();}catch(Exception e){failures.Add(e);}
            if(failures.Count>0)throw new AggregateException("Owned map close failed; no descriptor retry",failures);
        }
    }
    private sealed class NativeReader:ILinuxControlledMapReader
    {
        private readonly MapHandle handle=new();
        [StructLayout(LayoutKind.Sequential)]private struct Options {internal nuint Size;internal uint OpenFlags;internal uint Padding;}
        [DllImport("libbpf.so.1",SetLastError=true,CallingConvention=CallingConvention.Cdecl,EntryPoint="bpf_map_get_fd_by_id_opts")]private static extern int OpenMap(uint id,ref Options options);
        [DllImport("libbpf.so.1",SetLastError=true,CallingConvention=CallingConvention.Cdecl,EntryPoint="bpf_obj_get_info_by_fd")]private static extern int Info(MapHandle fd,[In,Out] byte[] info,ref uint size);
        [DllImport("libbpf.so.1",SetLastError=true,CallingConvention=CallingConvention.Cdecl,EntryPoint="bpf_map_lookup_elem")]private static extern int Read(MapHandle fd,[In] byte[] key,[Out] byte[] value);
        [DllImport("libbpf.so.1",SetLastError=true,CallingConvention=CallingConvention.Cdecl,EntryPoint="bpf_map_get_next_key")]private static extern int Next(MapHandle fd,[In] byte[]? previous,[Out] byte[] next);
        [DllImport("libc",SetLastError=true,EntryPoint="fcntl")]private static extern int DescriptorFlags(MapHandle fd,int command);
        internal NativeReader(uint id)
        {
            var options=new Options{Size=(nuint)Marshal.SizeOf<Options>(),OpenFlags=1u<<3};
            if(options.Size!=16||id==0)throw new InvalidDataException("Invalid read-only map open ABI/ID");
            var fd=OpenMap(id,ref options);if(fd<0)throw Error("Read-only owned map open failed");handle.Initialize(fd);
            try{var flags=DescriptorFlags(handle,3);if(flags<0)throw Error("Map FD flags unavailable");if((flags&3)!=0)throw new InvalidDataException("Owned map FD is not read-only");}
            catch(Exception original){handle.Dispose();if(handle.CloseError!=0)throw new AggregateException("Map admission/close failed",original,new Win32Exception(handle.CloseError));throw;}
        }
        private static Win32Exception Error(string reason)=>new(Marshal.GetLastPInvokeError(),reason);
        public byte[] ReadInfo(out uint size){var bytes=new byte[40];size=40;if(Info(handle,bytes,ref size)!=0)throw Error("Map info unavailable");return bytes;}
        public byte[] Lookup(byte[] key,int size){var bytes=new byte[size];if(Read(handle,key,bytes)!=0)throw Error("Map value unavailable");return bytes;}
        public byte[]? NextKey(byte[]? previous,int size)
        {
            var next=new byte[size];if(Next(handle,previous,next)==0)return next;var error=Marshal.GetLastPInvokeError();
            if(error==2)return null;throw new Win32Exception(error,"Map enumeration failed");
        }
        public void Dispose(){handle.Dispose();if(handle.CloseError!=0)throw new Win32Exception(handle.CloseError,"Map descriptor close returned error; no retry");}
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
internal interface ILinuxControlledMapReader:IDisposable
{
    byte[] ReadInfo(out uint returnedLength);
    byte[] Lookup(byte[] key,int valueSize);
    byte[]? NextKey(byte[]? previous,int keySize);
}
