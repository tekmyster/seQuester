using System.Buffers.Binary;
using System.Text.Json;
using RansomFree.Client;
using RansomFree.Contracts;
using RansomFree.Client.Forensics;

static class AtomicIntegrationChecks
{
    static int checks;
    static void Check(bool valid,string label){if(!valid)throw new Exception(label);checks++;Console.WriteLine("PASS "+label);}
    static void Reject(Action action,string label)
    {try{action();}catch(Exception e)when(e is InvalidDataException or InvalidOperationException or ArgumentException){Check(true,label);return;}throw new Exception("Expected rejection: "+label);}
    static readonly LinuxAtomicLeaseKey Key=new(1,2,100,101,1000,1001,1,2,10,2049,44,2049,55,3);
    internal static byte[] Frame(uint stage=1,uint schema=1,int permission=0,uint credentials=63)
    {
        var bytes=new byte[232];void U(int n,uint x)=>BinaryPrimitives.WriteUInt32LittleEndian(bytes.AsSpan(n),x);
        void Q(int n,ulong x)=>BinaryPrimitives.WriteUInt64LittleEndian(bytes.AsSpan(n),x);
        U(0,schema);U(4,232);U(8,1);U(12,stage);
        var key=schema==2?Key with{Cookie=0,LeaseId=0,OperationNonce=0,AssociationGeneration=0}:Key;
        key.Encode().CopyTo(bytes,16);Q(128,2000);Q(136,1900);Q(144,128);Q(152,1);
        U(168,unchecked((uint)permission));U(172,4);U(196,credentials);U(224,7);return bytes;
    }
    internal static byte[] Envelope(byte[] frame)=>JsonSerializer.SerializeToUtf8Bytes(new{schemaVersion=7,atomicObservation=Convert.ToBase64String(frame)});
    internal static void Run()
    {
        var raw=Envelope(Frame());var f=LinuxAtomicObservationFrame.DecodeEnvelope(raw);
        Check(f.CanAuthorizeCopy&&f.Uid==0&&f.PermissionResult==null,"ENTRY retains root UID and no invented permission result");
        Check(LinuxAtomicLeaseKey.Decode(Key.Encode())==Key,"all fourteen native key fields round trip");
        Reject(()=>LinuxAtomicLeaseRequest.Authorized(Key,""),"missing durable receipt cannot authorize START");
        Reject(()=>LinuxAtomicLeaseRequest.Authorized(Key,Guid.Empty.ToString("N")),"empty durable receipt cannot authorize START");
        Reject(()=>(new LinuxAtomicLeaseRequest(Key with{OperationNonce=0},1,0)).Encode(),"missing operation nonce rejected");
        const string sensor="11111111111111111111111111111111",collector="22222222222222222222222222222222";
        var entry=LinuxKernelDecoder.Decode(raw,sensor,collector,1,DateTimeOffset.UtcNow);var k=entry.Attribution!.LinuxKernel!;
        Check(k.IsValid()&&LinuxKernelEvidence.Matches(entry)&&k.Version==3&&k.Lease==1,"versioned ENTRY reaches canonical event contract");
        var denied=LinuxKernelDecoder.Decode(Envelope(Frame(2,permission:-13)),sensor,collector,2,DateTimeOffset.UtcNow);
        Check(denied.Attribution!.LinuxKernel!.PermissionObservation!.PermissionResult==-13&&denied.Attribution.Outcome=="Unknown","denial retained without claiming final syscall result");
        Check(denied.Attribution.LinuxKernel.Lease==0&&denied.Attribution.LinuxKernel.CanonicalCookie!=k.CanonicalCookie,"RESULT has separate journal key and no copy authority");
        Check(EventActivity.From(denied) is {Evidence:"permission-check",Outcome:"unknown"} activity&&activity.Actions.SequenceEqual(new[]{"read"}),"requested read remains distinct from completed or denied syscall outcome");
        var diagnostic=LinuxKernelDecoder.Decode(Envelope(Frame(3,2)),sensor,collector,3,DateTimeOffset.UtcNow);
        Check(diagnostic.Attribution!.LinuxKernel!.Cookie=="0"&&diagnostic.Attribution.LinuxKernel.Lease==0,"diagnostic retains context without actor-copy authority");
        var missing=LinuxKernelDecoder.Decode(Envelope(Frame(credentials:0)),sensor,collector,4,DateTimeOffset.UtcNow);
        Check(missing.User==null&&missing.Attribution!.LinuxKernel!.Uid==null,"unavailable credentials remain null");
        Check(!LinuxKernelEvidence.Supports(3,1,1)&&LinuxKernelEvidence.Supports(3,1,1,1)&&LinuxKernelEvidence.Supports(2,1,1),"server receipt requires additive permission capability and preserves old schema support");
        var before=JsonSerializer.SerializeToUtf8Bytes(k);var round=JsonSerializer.Deserialize<LinuxKernelEvidence>(before)!;
        Check(round==k&&round.IsValid(),"SIEM permission fields survive serialization");
        var invalid=Frame();BinaryPrimitives.WriteUInt32LittleEndian(invalid.AsSpan(200),uint.MaxValue);
        Reject(()=>LinuxAtomicObservationFrame.Decode(invalid),"invalid UID cannot masquerade as available");
        invalid=Frame();BinaryPrimitives.WriteUInt32LittleEndian(invalid.AsSpan(168),1);
        Reject(()=>LinuxAtomicObservationFrame.Decode(invalid),"ENTRY cannot assert operation return");
        invalid=Frame();BinaryPrimitives.WriteUInt32LittleEndian(invalid.AsSpan(228),1);
        Reject(()=>LinuxAtomicObservationFrame.Decode(invalid),"nonzero reserved ABI bytes rejected");
        Reject(()=>LinuxAtomicObservationFrame.Decode(new byte[231]),"truncated native observation rejected");
        Check(!LinuxAtomicObservationFrame.Decode(Frame(2)).CanAuthorizeCopy,"RESULT never authorizes executable copy");
        var port=new Port();using var device=new LinuxActorLeaseDevice(port);
        Reject(()=>device.StartAtomicAuthorizedCopy(Key,Guid.NewGuid().ToString("N")),"unregistered source cannot start native copy");
        device.RegisterAtomicSource(Key.ProviderEpoch);
        Check(port.Registers==1&&port.Starts==0,"source registration does not start copying");
        Reject(()=>device.RegisterAtomicSource(Key.ProviderEpoch),"source cannot be rebound on a retained controller");
        Reject(()=>device.StartAtomicAuthorizedCopy(Key with{ProviderEpoch=11},Guid.NewGuid().ToString("N")),"foreign source epoch rejected");
        port.ReportedKey=Key with{ProcessStartNs=1002};
        Reject(()=>device.StartAtomicAuthorizedCopy(Key,Guid.NewGuid().ToString("N")),"PID reuse lifetime mismatch rejected before START");
        port.ReportedKey=Key with{OperationNonce=4};
        Reject(()=>device.StartAtomicAuthorizedCopy(Key,Guid.NewGuid().ToString("N")),"stale operation nonce rejected before START");
        port.ReportedKey=Key;port.State=2;
        Reject(()=>device.StartAtomicAuthorizedCopy(Key,Guid.NewGuid().ToString("N")),"unfinished native finalization cannot START");
        port.State=3;var authorization=Guid.NewGuid().ToString("N");device.StartAtomicAuthorizedCopy(Key,authorization);
        Check(port.Starts==1&&port.Request==LinuxAtomicLeaseRequest.Authorized(Key,authorization),"START binds original full key and durable receipt");
        Reject(()=>device.StartAtomicAuthorizedCopy(Key,authorization),"duplicate START cannot redispatch");
        Reject(()=>device.SelectAtomic(Key),"copying actor cannot be selected");
        Reject(()=>device.DropAtomic(Key),"actor ownership must drain before DROP");
        port.State=7;device.SelectAtomic(Key);device.DropAtomic(Key);
        Check(port.Selects==1&&port.Drops==1,"completed drained bytes use exact SELECT and DROP authorization");
        using var ambiguous=new LinuxActorLeaseDevice(new Port{StartThrows=true});ambiguous.RegisterAtomicSource(10);
        Reject(()=>ambiguous.StartAtomicAuthorizedCopy(Key,authorization),"ambiguous native START return exposed");
        Reject(()=>ambiguous.StartAtomicAuthorizedCopy(Key,authorization),"ambiguous START is not retried");
        RunJournal();
        Console.WriteLine($"Atomic integration checks: {checks} passed");
    }
    internal static byte[] Ready()=>JsonSerializer.SerializeToUtf8Bytes(new{controlledReady=true,controlVersion=3,schemaVersion=7,
        loadedProgramIds=new[]{1,2,3,4,5,6,7},attachedProgramIds=new[]{1,2,3},permissionAttached=false,scratchMapFrozen=true,scratchMapId=11,
        fileCallMapId=16,fileCallMapFrozen=true,configMapFrozen=true,configMapId=12,eventsMapId=13,lostMapId=14,providerEpoch=10,
        activationNonce=new string('a',32),targetCount=1,targets=new[]{new{ordinal=0,device=2049,inode=55}},targetsPinned=true,watchMapId=15,
        watchMapFrozen=true,mode=0,healthAtReady=new[]{0,0,0,0,0,0},activationFrame="one-command-then-eof"});
    private static void RunJournal()
    {
        var ready=LinuxControlledLoaderProtocol.ParseReady(Ready());
        Check(ready.ControlVersion==3&&ready.SchemaVersion==7&&ready.Programs.Length==7&&ready.HealthAtReady.Length==6,"control v3 retains seven programs and six source health counters");
        var changed=System.Text.Json.Nodes.JsonNode.Parse(Ready())!;changed["healthAtReady"]![5]=1;
        Reject(()=>LinuxControlledLoaderProtocol.ParseReady(JsonSerializer.SerializeToUtf8Bytes(changed)),"nonzero health cannot become a healthy activation baseline");
        changed=System.Text.Json.Nodes.JsonNode.Parse(Ready())!;changed["fileCallMapId"]=11;
        Reject(()=>LinuxControlledLoaderProtocol.ParseReady(JsonSerializer.SerializeToUtf8Bytes(changed)),"aliased source maps rejected");
        RunMaps(ready);
        const string sensor="11111111111111111111111111111111";
        var root=Path.Combine(@"D:\Codex\RansomFree\windows-token-20260930","atomic-integration-"+Guid.NewGuid().ToString("N"));Directory.CreateDirectory(root);
        using var journal=new LinuxForensicJournal(root,sensor);
        using var bank=new LinuxRawIngressReserve(Path.Combine(root,"bank"),sensor,Guid.NewGuid().ToString("N"),"10",8,true);
        var barrier=new LinuxSourceWorkBarrier();var session=journal.PrepareControlledSource(bank,new(),"0",DateTimeOffset.UtcNow,512L*1024*1024).Id;
        journal.RecordSourceOwnerOpenAttempt(session,DateTimeOffset.UtcNow);journal.RecordOwnerMethodReturn(session,ActivationFixture.OwnerReturn(session));
        journal.CommitSourceControlLink(session,Ready(),DateTimeOffset.UtcNow);
        var command=LinuxControlledLoaderProtocol.ActivationFrame(ready,session);
        var sample=ActivationFixture.Sample(journal,session) with{Map=new(2,14,4,8,6,0,"op_health")};
        journal.CommitSourceActivationSample(session,sample);journal.MarkSourceControlWriteStarted(session,DateTimeOffset.UtcNow);
        journal.RecordSourceActivationWrite(session,ActivationFixture.Returned(journal,session));
        var active=JsonSerializer.SerializeToUtf8Bytes(new{controlledActivated=true,controlVersion=3,sessionId=session,providerEpoch=10,activationNonce=new string('a',32),attachedProgramIds=new[]{1,2,3,5,7,4,6},permissionAttached=true,lostAtActivation=0});
        Reject(()=>LinuxControlledLoaderProtocol.ParseActivated(System.Text.Encoding.UTF8.GetBytes(System.Text.Encoding.UTF8.GetString(active).Replace("[1,2,3,5,7,4,6]","[1,2,3,4,5,6,7]")),ready,session),"entry-before-exit attachment order rejected");
        journal.RecordSourceControlActivated(session,active);
        var raw=Envelope(Frame());var entry=bank.Commit(raw,barrier.Current,DateTimeOffset.UtcNow).Entry!;
        File.WriteAllBytes(Path.Combine(root,"raw-entry.json"),raw);File.WriteAllBytes(Path.Combine(root,"raw-result.json"),Envelope(Frame(2,permission:-13)));
        var indexed=journal.IndexRawIngress(session,bank,entry);var k=indexed.CanonicalEvent!.Attribution!.LinuxKernel!;
        Check(indexed.Status=="RAW_VALID","atomic ENTRY is durably indexed under exact target source");
        Check(journal.ReadPermissionPair(session,k).Reason=="PERMISSION_RESULT_NOT_DURABLE","missing RESULT explicitly unavailable");
        var work=barrier.TryIssue(indexed.CanonicalEventId!)!;var claim=journal.CommitNativePin(session,bank,entry,barrier,work);
        Reject(()=>journal.RequireAtomicCopyAuthorization(claim),"pin commit alone cannot issue atomic START");
        Check(journal.AuthorizeNativePin(claim),"atomic pin authorization commits in original journal");
        Reject(()=>journal.RequireAtomicCopyAuthorization(claim),"authorization without durable start cannot issue atomic START");
        journal.MarkNativePinStarting(claim);var authorized=journal.RequireAtomicCopyAuthorization(claim);
        Check(authorized.Key==Key&&authorized.AuthorizationId==journal.ReadNativePin(work.EventId)!.Authorization!.AuthorizationId,"durable raw and start link to exact atomic key and receipt");
        var result=bank.Commit(Envelope(Frame(2,permission:-13)),barrier.Current,DateTimeOffset.UtcNow).Entry!;
        var resultIndex=journal.IndexRawIngress(session,bank,result);
        Check(resultIndex.Status=="RAW_VALID"&&resultIndex.CanonicalEventId!=indexed.CanonicalEventId,"paired RESULT retains distinct canonical raw event");
        var pair=journal.ReadPermissionPair(session,k);
        Check(pair.Status=="paired"&&pair.PermissionResult==-13&&pair.EntryEventId==indexed.CanonicalEventId&&pair.ResultEventId==resultIndex.CanonicalEventId,"durable pair validates identity and exposes denied permission return");
        var second=Frame();var secondKey=Key with{LeaseId=2,Cookie=4,OperationNonce=5};secondKey.Encode().CopyTo(second,16);BinaryPrimitives.WriteUInt64LittleEndian(second.AsSpan(152),2);
        var secondEntry=bank.Commit(Envelope(second),barrier.Current,DateTimeOffset.UtcNow).Entry!;var secondIndex=journal.IndexRawIngress(session,bank,secondEntry);
        var secondWork=barrier.TryIssue(secondIndex.CanonicalEventId!)!;var secondClaim=journal.CommitNativePin(session,bank,secondEntry,barrier,secondWork);
        var copyPort=new Port{ReportedKey=secondKey,CompleteOnStart=true};using var copyDevice=new LinuxActorLeaseDevice(copyPort);copyDevice.RegisterAtomicSource(10);
        var worker=new LinuxSerialNativeWorker(journal,barrier,copyDevice,session);var returned=worker.RunAsync(secondClaim).GetAwaiter().GetResult();
        var captured=journal.Read(secondWork.EventId);
        Check(returned?.Error==null&&captured.Acquisition is {Status.State:"captured"}&&captured.DropState=="returned","serial worker integrates durable START, private snapshot and native DROP");
        Check(copyPort.Starts==1&&copyPort.Selects==1&&copyPort.Drops==1,"integrated worker calls atomic START/SELECT/DROP exactly once");
        Check(captured.Acquisition!.SnapshotSha256==Convert.ToHexString(System.Security.Cryptography.SHA256.HashData(copyPort.Bytes)),"private actor executable bytes verified against SHA256");
        Check(journal.ReadNativeWorkEvidence(secondWork.EventId) is {Version:2,State:"NATIVE_RETURNED_RECEIPT_COMMITTED"},"completed atomic worker emits compatible durable evidence linkage");
        barrier.Fault("TEST_AFTER_DURABLE_START",DateTimeOffset.UtcNow);
        Reject(()=>journal.RequireAtomicCopyAuthorization(claim),"source fault before actual START closes atomic authorization");
        journal.CommitUnavailable(work.EventId,"ATOMIC_FIXTURE_NO_NATIVE_IO");journal.RecordDrop(work.EventId,"unresolved");journal.RecordNativePinReturn(claim,DateTimeOffset.UtcNow,"ATOMIC_FIXTURE_NO_NATIVE_IO");
        Check(barrier.InFlight==0,"test returns journal ownership without pretending native I/O");
        File.WriteAllText(Path.Combine(root,"RESULTS.json"),JsonSerializer.Serialize(new{Passed=true,Checks=checks,Scope="Managed protocol and actual SQLite raw/start/pair integration; no kernel attachment"}));
        Console.WriteLine("Retained journal fixture: "+root);
    }
    private static Map[] Maps()=>[new(29,11,4,248,0,1,"inode_calls"),new(2,12,4,8,1,0,"op_config"),new(27,13,0,0,1048576,0,"op_events"),
        new(2,14,4,8,6,0,"op_health"),new(1,15,16,8,32,128,"op_targets"),new(29,16,4,248,0,1,"file_calls")];
    private static void RunMaps(LinuxControlledLoaderProtocol.Ready ready)
    {
        var good=Maps();using(var maps=LinuxControlledMapSet.OpenForTest(ready,ready.Targets!,id=>good.Single(x=>x.Id==id)))
            Check(maps.Verified.Maps.Length==6&&maps.MatchesReadyFrame(ready.Raw),"all six atomic map layouts and frozen target revision independently admitted");
        Check(good.All(x=>x.Closes==1),"atomic map descriptors close once");
        for(var index=0;index<6;index++)for(var field=0;field<7;field++)
        {
            var readers=Maps();readers[index].Info[field*4]^=1;
            Reject(()=>{using var map=LinuxControlledMapSet.OpenForTest(ready,ready.Targets!,id=>readers.Single(x=>x.Id==id));},"atomic map role/layout mismatch "+index+":"+field);
        }
        for(var index=0;index<6;index++)
        {
            var readers=Maps();readers[3].Counters[index]=1;
            Reject(()=>{using var map=LinuxControlledMapSet.OpenForTest(ready,ready.Targets!,id=>readers.Single(x=>x.Id==id));},"collection-health counter change rejected "+index);
        }
    }
    sealed class Map:ILinuxControlledMapReader
    {
        internal uint Id;internal byte[] Info=new byte[40];internal ulong[] Counters=new ulong[6];internal int Closes,next;
        internal Map(uint type,uint id,uint key,uint value,uint entries,uint flags,string name)
        {Id=id;uint[] fields=[type,id,key,value,entries,flags];for(int i=0;i<6;i++)BinaryPrimitives.WriteUInt32LittleEndian(Info.AsSpan(i*4),fields[i]);System.Text.Encoding.ASCII.GetBytes(name).CopyTo(Info,24);}
        public byte[] ReadInfo(out uint size){size=40;return Info;}
        public byte[] Lookup(byte[] key,int size)
        {
            var value=new byte[8];if(Id==12)BinaryPrimitives.WriteUInt64LittleEndian(value,10);
            if(Id==14)BinaryPrimitives.WriteUInt64LittleEndian(value,Counters[BinaryPrimitives.ReadUInt32LittleEndian(key)]);return value;
        }
        public byte[]? NextKey(byte[]? prior,int size)
        {if(Id!=15||next++!=0)return null;var key=new byte[16];BinaryPrimitives.WriteUInt64LittleEndian(key,55);BinaryPrimitives.WriteUInt32LittleEndian(key.AsSpan(8),2049);return key;}
        public void Dispose(){Closes++;}
    }
    sealed class Port:ILinuxActorLeaseTransport
    {
        internal int Registers,Starts,Selects,Drops;internal uint State=3;
        internal LinuxAtomicLeaseKey ReportedKey=Key;internal LinuxAtomicLeaseRequest? Request;internal bool StartThrows,CompleteOnStart;
        internal byte[] Bytes=Enumerable.Range(0,128).Select(i=>(byte)i).ToArray();private int position;
        public void Control(uint command,byte[] bytes)
        {
            if(command==LinuxActorLeaseDevice.AtomicRegisterCommand){Registers++;return;}
            if(command==LinuxActorLeaseDevice.StatusCommand)
            {
                var key=ReportedKey;ulong[] fields=[key.LeaseId,key.Cookie,1800,2050,2000000000,128,key.ActorInode,key.ActorDevice,128,key.ProcessId,key.ThreadId,key.ProcessStartNs,key.TaskStartNs,key.SelfExecId,key.AssociationGeneration,key.ProviderEpoch];
                for(int i=0;i<fields.Length;i++)BinaryPrimitives.WriteUInt64LittleEndian(bytes.AsSpan(i*8),fields[i]);
                BinaryPrimitives.WriteUInt32LittleEndian(bytes.AsSpan(128),3);BinaryPrimitives.WriteUInt32LittleEndian(bytes.AsSpan(144),1);BinaryPrimitives.WriteUInt32LittleEndian(bytes.AsSpan(152),2);BinaryPrimitives.WriteUInt32LittleEndian(bytes.AsSpan(156),160);return;
            }
            if(command==LinuxActorLeaseDevice.AtomicStatusCommand)
            {
                ReportedKey.Encode().CopyTo(bytes,8);
                BinaryPrimitives.WriteUInt64LittleEndian(bytes.AsSpan(120),Request?.ReceiptLow??0);
                BinaryPrimitives.WriteUInt64LittleEndian(bytes.AsSpan(128),Request?.ReceiptHigh??0);
                BinaryPrimitives.WriteUInt32LittleEndian(bytes.AsSpan(136),State);
                BinaryPrimitives.WriteUInt64LittleEndian(bytes.AsSpan(168),128);
                BinaryPrimitives.WriteUInt64LittleEndian(bytes.AsSpan(176),State==7?128UL:0);
                BinaryPrimitives.WriteUInt32LittleEndian(bytes.AsSpan(184),State==7?0u:1u);
                BinaryPrimitives.WriteUInt32LittleEndian(bytes.AsSpan(188),State==7?0u:1u);return;
            }
            var request=new LinuxAtomicLeaseRequest(LinuxAtomicLeaseKey.Decode(bytes.AsSpan(8,112)),BinaryPrimitives.ReadUInt64LittleEndian(bytes.AsSpan(120)),BinaryPrimitives.ReadUInt64LittleEndian(bytes.AsSpan(128)));
            if(command==LinuxActorLeaseDevice.AtomicStartCommand){Starts++;Request=request;State=CompleteOnStart?7u:5u;if(StartThrows)throw new InvalidOperationException("ambiguous test return");return;}
            if(Request!=request)throw new Exception("wrong copy receipt");
            if(command==LinuxActorLeaseDevice.AtomicSelectCommand){Selects++;position=0;return;}
            if(command==LinuxActorLeaseDevice.AtomicDropCommand){Drops++;return;}throw new Exception("unexpected command");
        }
        public int Read(byte[] buffer,int count){if(!CompleteOnStart)throw new InvalidOperationException("no byte read in protocol fixture");var n=Math.Min(count,Bytes.Length-position);Array.Copy(Bytes,position,buffer,0,n);position+=n;return n;}
        public void Dispose(){}
    }
}
