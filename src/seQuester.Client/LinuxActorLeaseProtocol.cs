using System.Buffers.Binary;
using System.ComponentModel;
using System.Globalization;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using Microsoft.Win32.SafeHandles;
using RansomFree.Contracts;
using RansomFree.Client.Forensics;

namespace RansomFree.Client;

// Mirrors the qualified sq_lease.h ABI, not a userspace process/path lookup.
// These ulong values are internal protocol values; transport must use the
// canonical decimal-string evidence contract before serializing them to SIEM.
public sealed record LinuxActorLeaseStatus(
    ulong Id,ulong Cookie,ulong StartedNs,ulong FinishedNs,ulong DeadlineNs,
    ulong Size,ulong Inode,ulong Device,ulong Bytes,ulong ProcessId,ulong ThreadId,ulong ProcessStartNs,
    ulong TaskStartNs,ulong SelfExecId,ulong AssociationGeneration,ulong ProviderEpoch,
    uint State,int Error,uint WriteLease,uint MetadataChanged,uint AssociationState,int AssociationError,uint SchemaVersion,uint StructSize)
{
    public static LinuxActorLeaseStatus Decode(ReadOnlySpan<byte> data)
    {
        if(data.Length!=160)throw new InvalidDataException("Linux actor lease status must be exactly 160 bytes");
        var u=new ulong[16];for(var i=0;i<u.Length;i++)u[i]=BinaryPrimitives.ReadUInt64LittleEndian(data[(i*8)..]);
        var x=new LinuxActorLeaseStatus(u[0],u[1],u[2],u[3],u[4],u[5],u[6],u[7],u[8],u[9],u[10],u[11],u[12],u[13],u[14],u[15],
            BinaryPrimitives.ReadUInt32LittleEndian(data[128..]),BinaryPrimitives.ReadInt32LittleEndian(data[132..]),BinaryPrimitives.ReadUInt32LittleEndian(data[136..]),BinaryPrimitives.ReadUInt32LittleEndian(data[140..]),
            BinaryPrimitives.ReadUInt32LittleEndian(data[144..]),BinaryPrimitives.ReadInt32LittleEndian(data[148..]),BinaryPrimitives.ReadUInt32LittleEndian(data[152..]),BinaryPrimitives.ReadUInt32LittleEndian(data[156..]));
        if(x.SchemaVersion!=2||x.StructSize!=160||x.State is <1 or >6||x.Id==0||x.Id>long.MaxValue||x.Size is 0 or >4194304||x.Bytes>x.Size||x.WriteLease>1||x.MetadataChanged>1||x.AssociationState>2||x.Error is >0 or <-4095||x.AssociationError is >0 or <-4095)
            throw new InvalidDataException("Unsupported or malformed Linux actor lease status");
        return x;
    }
    public bool Matches(LinuxKernelEvidence e)
    {
        static bool Equal(ulong value,string raw)=>value.ToString(CultureInfo.InvariantCulture)==raw;
        return e.IsValid()&&e.Lease>0&&e.Reservation==e.Lease&&e.FinalizeError==0&&Id==(ulong)e.Lease&&Equal(Cookie,e.Cookie)&&Equal(ProviderEpoch,e.ProviderEpoch)&&
            e.ProcessId is >0&&ProcessId==(ulong)e.ProcessId.Value&&e.ThreadId!=null&&ThreadId==e.ThreadId.Value&&Equal(ProcessStartNs,e.ProcessStartNs)&&Equal(TaskStartNs,e.TaskStartNs)&&Equal(SelfExecId,e.SelfExecId)&&
            Equal(Inode,e.ActorInode)&&Device==e.ActorDevice&&Equal(AssociationGeneration,e.AssociationAfter)&&AssociationError==e.AssociationError&&
            AssociationState==(AssociationError==0?1u:2u);
    }
    public bool Ready=>State==3&&Error==0&&Bytes==Size&&WriteLease==0&&StartedNs>0&&FinishedNs>=StartedNs&&FinishedNs<DeadlineNs;
    public LinuxActorLeaseEvidence ToEvidence()
    {
        static string D(ulong value)=>value.ToString(CultureInfo.InvariantCulture);
        var result=new LinuxActorLeaseEvidence{SchemaVersion=checked((int)SchemaVersion),StructSize=checked((int)StructSize),Id=D(Id),Cookie=D(Cookie),StartedNs=D(StartedNs),FinishedNs=D(FinishedNs),DeadlineNs=D(DeadlineNs),
            Size=D(Size),Inode=D(Inode),Device=D(Device),Bytes=D(Bytes),ProcessId=D(ProcessId),ThreadId=D(ThreadId),ProcessStartNs=D(ProcessStartNs),TaskStartNs=D(TaskStartNs),SelfExecId=D(SelfExecId),
            AssociationGeneration=D(AssociationGeneration),ProviderEpoch=D(ProviderEpoch),State=State,Error=Error,WriteLease=WriteLease,MetadataChanged=MetadataChanged,AssociationState=AssociationState,AssociationError=AssociationError};
        if(!result.IsValid())throw new InvalidDataException("Native lease status cannot be represented as valid acquisition evidence");
        return result;
    }
}

// An exclusive controller descriptor pins the module. All operations on its
// selected-stream cursor must be serialized. No timeout here pretends to cancel
// a blocked kernel worker: DROP/close may wait for kernel_read to drain.
public sealed partial class LinuxActorLeaseDevice:IDisposable
{
    // An owned runtime records the actual open boundary even when construction
    // fails before it can receive a controller object. This is observation,
    // never a persisted capability or an instruction to retry an unknown close.
    internal sealed class OpenAttempt
    {
        internal bool Entered,Returned,DescriptorCreated,FailedAdmissionCloseReturned;
        internal int? OpenError;
        internal bool NoDescriptorRemains=>!Entered||Returned&&(!DescriptorCreated||FailedAdmissionCloseReturned);
    }
    internal const uint StatusCommand=0xC0A05101,SelectCommand=0x40085102,DropCommand=0x40085103;
    private readonly ILinuxActorLeaseTransport transport;
    private readonly object gate=new();private bool disposed;private Exception? closeFailure;
    public LinuxActorLeaseDevice():this(new NativeTransport()){}
    internal LinuxActorLeaseDevice(OpenAttempt attempt):this(new NativeTransport(attempt)){}
    internal LinuxActorLeaseDevice(ILinuxActorLeaseTransport transport)=>this.transport=transport;
    private LinuxActorLeaseStatus StatusCore(ulong id)
    {
        var bytes=new byte[160];BinaryPrimitives.WriteUInt64LittleEndian(bytes,id);transport.Control(StatusCommand,bytes);return LinuxActorLeaseStatus.Decode(bytes);
    }
    public LinuxActorLeaseStatus Status(LinuxKernelEvidence observation)
    {
        lock(gate){ObjectDisposedException.ThrowIf(disposed,this);if(observation.Lease<=0)throw new InvalidDataException("No positive native lease");var status=StatusCore((ulong)observation.Lease);if(!status.Matches(observation))throw new InvalidDataException("Native lease does not match the complete observation identity");return status;}
    }
    public LinuxActorSnapshot ReadReadySnapshot(LinuxKernelEvidence observation)
    {
        lock(gate)
        {
            ObjectDisposedException.ThrowIf(disposed,this);var before=Status(observation);
            if(!before.Ready)throw new InvalidDataException("Native actor bytes are not successfully complete");
            SelectObserved(observation,before.Id);
            var bytes=new byte[checked((int)before.Size)];var offset=0;var buffer=new byte[65536];
            while(offset<bytes.Length){var count=transport.Read(buffer,Math.Min(buffer.Length,bytes.Length-offset));if(count<=0||count>Math.Min(buffer.Length,bytes.Length-offset))throw new InvalidDataException("Native actor read shortened or exceeded the requested range");buffer.AsSpan(0,count).CopyTo(bytes.AsSpan(offset));offset+=count;}
            if(transport.Read(buffer,1)!=0)throw new InvalidDataException("Native actor stream exceeds its completed snapshot size");
            var after=StatusCore(before.Id);if(after!=before||!after.Ready||!after.Matches(observation))throw new InvalidDataException("Native actor status changed during byte retrieval");
            // BPF observed size precedes the module's own write exclusion. The
            // native status owns the copy bound; retain any difference as data.
            return new(before,bytes,Convert.ToHexString(SHA256.HashData(bytes)),before.Size.ToString(CultureInfo.InvariantCulture)==observation.ActorSize);
        }
    }
    // Source integration uses physical private-file admission before SELECT.
    // The older memory-returning method remains for the immutable native probe.
    internal void ReadReadySnapshotInto(AgentEvent observation,LinuxSnapshotAdmission admission)
    {
        lock(gate)
        {
            ObjectDisposedException.ThrowIf(disposed,this);
            try
            {
                if(transport is NativeTransport&&!admission.PhysicalAllocationEstablished)throw new IOException("Linux physical snapshot admission required");
                var k=observation.Attribution?.LinuxKernel??throw new InvalidDataException("Native raw observation missing");
                var before=Status(k);admission.BeginRead(observation,before);
                SelectObserved(k,before.Id);
                var remaining=checked((long)before.Size);var buffer=new byte[65536];
                while(remaining>0)
                {
                    var count=transport.Read(buffer,(int)Math.Min(buffer.Length,remaining));
                    if(count<=0||count>Math.Min(buffer.Length,remaining))throw new InvalidDataException("Native read differs from admitted byte count");
                    admission.Append(buffer.AsSpan(0,count));remaining-=count;
                }
                if(transport.Read(buffer,1)!=0)throw new InvalidDataException("Native stream exceeded admitted size");
                var after=StatusCore(before.Id);
                if(after!=before||!after.Matches(k))throw new InvalidDataException("Native status changed during admitted read");
                admission.Finish(after);
            }
            catch{admission.MarkFailed();throw;}
        }
    }
    // Caller must commit the raw observation, private bytes and acquisition
    // manifest before disposal. This method never acknowledges by numeric ID alone.
    public void Drop(LinuxKernelEvidence observation)
    {
        lock(gate){ObjectDisposedException.ThrowIf(disposed,this);var status=Status(observation);if(observation.NativeSchemaVersion is 7 or 8){DropAtomic(AtomicKeyFor(observation));return;}var request=new byte[8];BinaryPrimitives.WriteUInt64LittleEndian(request,status.Id);transport.Control(DropCommand,request);}
    }
    internal void DropExact(LinuxKernelEvidence observation,LinuxActorLeaseStatus expected)
    {
        lock(gate)
        {
            ObjectDisposedException.ThrowIf(disposed,this);var status=Status(observation);
            if(status!=expected||!LinuxNativeDisposition.MayRelease(status))throw new InvalidDataException("Native terminal release tuple changed");
            if(observation.NativeSchemaVersion is 7 or 8){DropAtomic(AtomicKeyFor(observation));return;}
            var request=new byte[8];BinaryPrimitives.WriteUInt64LittleEndian(request,status.Id);transport.Control(DropCommand,request);
        }
    }
    private void SelectObserved(LinuxKernelEvidence observation,ulong id)
    {
        if(observation.NativeSchemaVersion is 7 or 8){SelectAtomic(AtomicKeyFor(observation));return;}
        var selected=new byte[8];BinaryPrimitives.WriteUInt64LittleEndian(selected,id);transport.Control(SelectCommand,selected);
    }
    private LinuxAtomicLeaseKey AtomicKeyFor(LinuxKernelEvidence observation)
    {
        if(observation.Lease<=0||!atomicRequests.TryGetValue((ulong)observation.Lease,out var request))throw new InvalidOperationException("No original atomic controller authorization");
        var key=request.Key;
        if(!key.Matches(observation))
            throw new InvalidDataException("Atomic selected stream differs from original canonical observation");
        return key;
    }
    public void Dispose()
    {
        lock(gate)
        {
            if(disposed)
            {
                if(closeFailure!=null)throw new IOException("Controller close previously failed; no retry or successful-close receipt is permitted",closeFailure);
                return;
            }
            disposed=true;
            try{transport.Dispose();}catch(Exception ex){closeFailure=ex;throw;}
        }
    }

    private sealed class NativeTransport:ILinuxActorLeaseTransport
    {
        private readonly SafeFileHandle file;
        [DllImport("libc",SetLastError=true,EntryPoint="open")]private static extern int Open(string path,int flags);
        [DllImport("libc",SetLastError=true,EntryPoint="ioctl")]private static extern int Ioctl(SafeFileHandle file,nuint request,byte[] value);
        [DllImport("libc",SetLastError=true,EntryPoint="read")]private static extern nint NativeRead(SafeFileHandle file,byte[] bytes,nuint count);
        [DllImport("libc",SetLastError=true,EntryPoint="statx")]private static extern int Statx(SafeFileHandle file,string path,int flags,uint mask,byte[] value);
        [DllImport("libc",SetLastError=true,EntryPoint="close")]private static extern int Close(int fd);
        public NativeTransport(OpenAttempt? attempt=null)
        {
            if(!OperatingSystem.IsLinux()||RuntimeInformation.ProcessArchitecture!=Architecture.X64||!BitConverter.IsLittleEndian)throw new PlatformNotSupportedException("The actor lease device ABI is qualified only on Linux x64");
            if(attempt!=null)attempt.Entered=true;
            var fd=Open("/dev/sq_actor_lease",2|0x80000|0x20000);var error=fd<0?Marshal.GetLastPInvokeError():0;
            if(attempt!=null){attempt.Returned=true;attempt.DescriptorCreated=fd>=0;attempt.OpenError=error;}
            if(fd<0)throw new Win32Exception(error);file=new SafeFileHandle((IntPtr)fd,true);
            try
            {
                var stat=new byte[256];if(Statx(file,"",0x1000,0x1b,stat)!=0)throw new Win32Exception(Marshal.GetLastPInvokeError());
                var mask=BinaryPrimitives.ReadUInt32LittleEndian(stat);var mode=BinaryPrimitives.ReadUInt16LittleEndian(stat.AsSpan(28));
                if((mask&0xb)!=0xb||(mode&0xf000)!=0x2000||(mode&0x1ff)!=0x180||BinaryPrimitives.ReadUInt32LittleEndian(stat.AsSpan(20))!=0)
                    throw new IOException("Actor controller must be a root-owned 0600 character device");
            }
            catch(Exception admission)
            {
                try{Dispose();if(attempt!=null)attempt.FailedAdmissionCloseReturned=true;}catch(Exception cleanup){throw new AggregateException("Controller admission and descriptor cleanup failed",admission,cleanup);}
                throw;
            }
        }
        public void Control(uint command,byte[] data){if(Ioctl(file,command,data)!=0)throw new Win32Exception(Marshal.GetLastPInvokeError());}
        public int Read(byte[] bytes,int count){var n=NativeRead(file,bytes,(nuint)count);if(n<0)throw new Win32Exception(Marshal.GetLastPInvokeError());return checked((int)n);}
        public void Dispose()
        {
            // The device gate excludes every read/ioctl before this close.
            // SafeFileHandle.Dispose hides close errors; retain the actual
            // libc result and never retry a possibly recycled descriptor.
            var fd=file.DangerousGetHandle().ToInt32();file.SetHandleAsInvalid();
            if(Close(fd)!=0)throw new Win32Exception(Marshal.GetLastPInvokeError(),"Actor controller close returned an error; ownership outcome unknown");
        }
    }
}
public sealed record LinuxActorSnapshot(LinuxActorLeaseStatus NativeStatus,ReadOnlyMemory<byte> Bytes,string Sha256,bool SizeMatchesEarlierObservation);
internal interface ILinuxActorLeaseTransport:IDisposable
{
    void Control(uint command,byte[] request);
    int Read(byte[] destination,int count);
}
