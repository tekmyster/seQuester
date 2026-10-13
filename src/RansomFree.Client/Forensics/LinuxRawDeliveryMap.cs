using RansomFree.Contracts;

namespace RansomFree.Client.Forensics;

// Canonical delivery mapping backed only by the already committed raw bank.
// It owns no native descriptor, never indexes a work row before raw commit and
// does not claim source continuity. Lifecycle gaps/rotation belong to the source.
internal sealed class LinuxRawDeliveryMap:IDisposable
{
    internal sealed record Admission(bool RawCommitted,bool Duplicate,string IdentityKind,
        LinuxRawIntakeReserve.RawRecord? Record,LinuxRawIntakeReserve.UnknownRange? Overflow);
    private readonly LinuxRawIntakeReserve reserve;
    private readonly string sensor,collector=Guid.NewGuid().ToString("N");
    private readonly Dictionary<(string Epoch,string Cookie),LinuxRawIntakeReserve.RawRecord> identities=[];
    private readonly object gate=new();
    private long sequence;
    private bool disposed;
    private string? failure;
    internal string? Failure {get{lock(gate)return failure;}}
    internal IReadOnlyList<LinuxRawIntakeReserve.RawRecord> Records {get{lock(gate)return reserve.Records;}}
    internal bool PhysicalAllocationEstablished=>reserve.PhysicalAllocationEstablished;
    internal bool Reopened=>reserve.Reopened;
    internal string CollectorInstance=>collector;
    internal string SensorId=>sensor;
    internal string FullPath=>reserve.FullPath;
    internal FileIdentityEvidence BankIdentity=>reserve.BankIdentity;
    internal LinuxRawIntakeReserve.UnknownRange? Overflow=>reserve.Overflow;
    internal LinuxRawDeliveryMap(string directory,string sensor,int slots)
    {
        this.sensor=sensor;reserve=new(directory,sensor,slots);
        try
        {
            foreach(var record in reserve.Records)
                if(Key(record.Observation.Attribution!.LinuxKernel!) is {} key&&!identities.TryAdd(key,record))
                    throw new InvalidDataException("RAW_NATIVE_MAPPING_CONFLICT: multiple canonical deliveries; bank retained");
        }
        catch{reserve.Dispose();throw;}
    }
    private static (string Epoch,string Cookie)? Key(LinuxKernelEvidence value)=>
        value.ProviderEpoch=="0"||value.Cookie=="0"?null:(value.ProviderEpoch,value.Cookie);
    internal Admission Admit(ReadOnlyMemory<byte> raw,ForensicPolicy policy,DateTimeOffset receivedUtc)
    {
        lock(gate)
        {
            ObjectDisposedException.ThrowIf(disposed,this);
            if(failure!=null)throw new IOException(failure+": raw admission stopped; source unknown range required");
            try
            {
                var nextSequence=checked(sequence+1);
                var observation=LinuxKernelDecoder.Decode(raw,sensor,collector,nextSequence,receivedUtc);
                var key=Key(observation.Attribution!.LinuxKernel!);
                if(key is {} native&&identities.TryGetValue(native,out var prior))
                {
                    if(!Convert.FromBase64String(prior.RawBase64).AsSpan().SequenceEqual(raw.Span))
                    {
                        failure="RAW_NATIVE_IDENTITY_CONFLICT";
                        throw new InvalidDataException("Same provider/cookie changed exact raw bytes; original bank retained");
                    }
                    // First committed timestamp, collector identity and policy
                    // remain canonical even after a restart/policy refresh.
                    return new(true,true,"provider-cookie",prior,reserve.Overflow);
                }
                if(!policy.IsValid())throw new InvalidDataException("Invalid raw delivery policy");
                sequence=nextSequence;
                var result=reserve.CommitRecord(raw,observation,policy);
                if(!result.Committed)
                    return new(false,false,key==null?"collector-delivery-only":"provider-cookie",null,result.Overflow);
                var committed=result.Record!;
                if(key is {} unique)identities.Add(unique,committed);
                return new(true,result.Duplicate,key==null?"collector-delivery-only":"provider-cookie",committed,result.Overflow);
            }
            catch
            {
                // This in-memory state is intentionally not a durable source
                // loss marker. A supervisor must retain a lifecycle gap on
                // reopen and persist malformed/oversize boundaries separately.
                failure??="RAW_DELIVERY_ADMISSION_FAILED";throw;
            }
        }
    }
    public void Dispose(){lock(gate){if(disposed)return;disposed=true;reserve.Dispose();}}
}
