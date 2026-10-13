namespace RansomFree.Client.Forensics;

// Discovery has no file operation or accessing-thread identity. A consumer must
// persist a process-acquisition record, never manufacture an AgentEvent for it.
internal sealed record WindowsReadyActor(string Provider,uint ProviderStatus,ulong OperationInstance,
    ulong ReadySequence,ulong Generation,ulong Candidate,int Pid,long Created,ulong Deadline,
    uint ByteLength,uint State,uint OriginalAccess,uint MappedAccess,uint QualificationVersion,uint CreateStatus,ulong FileIndex)
{
    internal byte[] Request(uint operation,uint offset=0,uint count=0)
    {
        if(operation is not (10 or 13 or 26 or 27)||Generation==0||Candidate==0||Pid<=0||Created<=0||Provider.Length!=32)throw new InvalidDataException("Full ready candidate identity required");
        var b=WindowsStagedActorProtocol.Message(19,72);Convert.FromHexString(Provider).CopyTo(b,8);
        WindowsStagedActorProtocol.Put(b,24,Generation);WindowsStagedActorProtocol.Put(b,32,Candidate);
        WindowsStagedActorProtocol.Put(b,40,(ulong)Pid);WindowsStagedActorProtocol.Put(b,48,(ulong)Created);
        WindowsStagedActorProtocol.Put32(b,56,offset);WindowsStagedActorProtocol.Put32(b,60,count);
        WindowsStagedActorProtocol.Put32(b,64,operation);WindowsStagedActorProtocol.Put32(b,68,1);return b;
    }
}
internal sealed record WindowsReadyActorPage(uint Flags,ulong OldestRetained,ulong HighestPublished,ulong NextSequence,WindowsReadyActor[] Actors)
{
    internal bool CursorResetRequired=>(Flags&1)!=0;
    internal bool ProviderInactive=>(Flags&2)!=0;
    internal bool SequenceExhausted=>(Flags&4)!=0;
}
internal static class WindowsReadyActorProtocol
{
    internal const int PageBytes=1352,PageEntries=16,Capacity=256;
    internal static byte[] Request(string provider,ulong after,uint maximum=PageEntries)
    {
        if(provider.Length!=32||!provider.All(Uri.IsHexDigit)||maximum is 0 or >PageEntries)throw new InvalidDataException("Invalid ready feed request");
        var b=WindowsStagedActorProtocol.Message(25,40);Convert.FromHexString(provider).CopyTo(b,8);
        WindowsStagedActorProtocol.Put(b,24,after);WindowsStagedActorProtocol.Put32(b,32,maximum);WindowsStagedActorProtocol.Put32(b,36,1);return b;
    }
    internal static WindowsReadyActorPage Decode(byte[] b,string provider,ulong instance,ulong after,uint maximum=PageEntries)
    {
        if(maximum is 0 or >PageEntries||b.Length!=PageBytes)throw new InvalidDataException("Invalid ready page length");
        uint N(int o)=>WindowsStagedActorProtocol.U32(b,o);ulong Q(int o)=>WindowsStagedActorProtocol.U64(b,o);
        if(N(0)!=1||N(4)!=PageBytes||Convert.ToHexString(b.AsSpan(8,16))!=provider||N(24) is not (0 or 0x40020056)||N(28)>7||Q(32)!=instance||instance==0||N(68)!=Capacity)throw new InvalidDataException("Ready feed provider/schema mismatch");
        var flags=N(28);var oldest=Q(40);var highest=Q(48);var next=Q(56);var count=N(64);
        if(count>maximum||after>highest||oldest!=(highest>=Capacity?highest-Capacity+1:1))throw new InvalidDataException("Ready cursor bounds invalid");
        var reset=after<oldest-1;
        if(((flags&1)!=0)!=reset||reset&&(count!=0||next!=oldest-1)||!reset&&(count!=Math.Min((ulong)maximum,highest-after)||next!=after+count))throw new InvalidDataException("Ready feed cursor gap was not explicit");
        if((flags&4)!=0&&highest!=ulong.MaxValue)throw new InvalidDataException("Invalid ready feed exhaustion state");
        var actors=new WindowsReadyActor[count];var generations=new HashSet<ulong>();var candidates=new HashSet<ulong>();
        for(var i=0;i<count;i++)
        {
            var o=72+i*80;var pid=Q(o+24);var created=Q(o+32);var state=N(o+52);
            if(Q(o)!=after+(uint)i+1||Q(o+8)==0||Q(o+16)==0||pid is 0 or >int.MaxValue||created is 0 or >long.MaxValue||Q(o+40)==0||N(o+48) is 0 or >WindowsStagedActorProtocol.MaximumBytes||state is 0 or >5||((flags&2)!=0)!=(state==5)||N(o+64)!=2||unchecked((int)N(o+68))<0||!generations.Add(Q(o+8))||!candidates.Add(Q(o+16)))throw new InvalidDataException("Invalid ready candidate row");
            actors[i]=new(provider,N(24),instance,Q(o),Q(o+8),Q(o+16),(int)pid,(long)created,Q(o+40),N(o+48),state,N(o+56),N(o+60),N(o+64),N(o+68),Q(o+72));
        }
        if(b.AsSpan(72+checked((int)count)*80).IndexOfAnyExcept((byte)0)>=0)throw new InvalidDataException("Unused ready page rows are not zero");
        return new(flags,oldest,highest,next,actors);
    }
}
