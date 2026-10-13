using System.Diagnostics;
using System.Security.Cryptography;
using RansomFree.Client.Forensics;
using RansomFree.Contracts;
using RansomFree.Server;
using RansomFree.Client;

internal static class NativeHashChecks
{
    internal static void Run(AgentEvent input,AgentEvent returned,string sensor,byte[] ready,byte[] activated,string session,Action<bool,string> check)
    {
        var root=Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),"Codex","sequester-native-hash-fixture-"+Guid.NewGuid().ToString("N"));Directory.CreateDirectory(root);
        var k=input.Attribution!.LinuxKernel!;var size=int.Parse(k.ActorSize,System.Globalization.CultureInfo.InvariantCulture);var file=Path.Combine(root,"owned-synthetic-actor.bin");var bytes=Enumerable.Repeat((byte)'A',size).ToArray();File.WriteAllBytes(file,bytes);var hash=Convert.ToHexString(SHA256.HashData(bytes));
        using var actor=ActorLease.Capture(input,sensor);actor.Image=File.OpenRead(file);actor.SnapshotFile=NativeFileIdentity.Read(actor.Image);actor.File=new(){StableId="linux-kernel-device:257:inode:88",Size=size,Status=EvidenceStatus.Captured("source-event")};
        var native=new LinuxActorLeaseEvidence{Id="1",Cookie=k.Cookie,StartedNs="2000",FinishedNs="2001",DeadlineNs="9999",Size=k.ActorSize,Inode="88",Device="257",Bytes=k.ActorSize,ProcessId="31",ThreadId="31",ProcessStartNs=k.ProcessStartNs,TaskStartNs=k.TaskStartNs,SelfExecId=k.SelfExecId,AssociationGeneration=k.AssociationAfter,ProviderEpoch=k.ProviderEpoch,State=3,AssociationState=1};
        var now=DateTimeOffset.UtcNow;actor.LinuxAcquisition=new(){SourceEventId=input.EventId,NativeObservationSha256=k.NativeObservationSha256,NativeStatus=native,SnapshotId=Guid.NewGuid().ToString("N"),SnapshotSha256=hash,SnapshotFile=actor.SnapshotFile,PersistedUtc=now,SizeMatchesEarlierObservation=true,Status=EvidenceStatus.Captured("synthetic-fixture")};
        var pin=Guid.NewGuid().ToString("N");actor.LinuxNativeWork=new(){Version=2,PinId=pin,SourceSessionId=session,SourceEventId=input.EventId,CompletionEventId=Guid.NewGuid().ToString("N"),NativeObservationSha256=k.NativeObservationSha256,PolicySha256=new string('A',64),CollectorInstance=k.CollectorInstance,CollectorSequence=k.CollectorSequence,ProviderEpoch=k.ProviderEpoch,Cookie=k.Cookie,Lease=1,State="NATIVE_RETURNED_RECEIPT_COMMITTED",IssuedGeneration=1,IssuedUtc=now,PinCommittedUtc=now,AuthorizationId=Guid.NewGuid().ToString("N"),AuthorizationGeneration=1,AuthorizationCommittedUtc=now,StartingGeneration=1,StartingState="Active",StartOrdering="SAME_GENERATION_START",StartRecordedUtc=now,ActualReturnUtc=now,ReturnOutcome="committed",ReturnReason="NATIVE_METHOD_RETURNED",Method=new(){PinId=pin,ControllerMethodAttempted=true,LastStep="DROP_RECEIPT_COMMIT",LatestStatus=native,DropMethodAttempted=true,DropMethodReturned=true,DropReceiptCommitObserved=true}};
        actor.Binding=EvidenceStatus.Captured("synthetic-fixture");actor.BindingSourceEventId=input.EventId;actor.BindingCapturedUtc=now;
        var value=input with{Forensics=new ForensicCollector(sensor,root).Begin(input,actor)};
        if(!value.Forensics.IsValid()||!LinuxKernelEvidence.Matches(value))Console.WriteLine(System.Text.Json.JsonSerializer.Serialize(new{ForensicValid=value.Forensics.IsValid(),KernelValid=LinuxKernelEvidence.Matches(value),LeaseValid=native.IsValid(),LeaseMatches=native.Matches(k),WorkValid=actor.LinuxNativeWork.IsValid(input.EventId,null),WorkMatches=actor.LinuxNativeWork.Matches(k),AcquisitionValid=actor.LinuxAcquisition.IsValid(actor.Process,input.EventId,null,null,actor.File),ProcessStart=actor.Process.StartKey,ThreadId=actor.Process.ThreadId,SourceSize=k.ActorSize,SnapshotSize=actor.SnapshotFile.Size}));
        check(value.Forensics.IsValid()&&LinuxKernelEvidence.Matches(value),"synthetic held actor fixture preserves actual I/O evidence contracts");
        check(LinuxNativeHashBinding.ActorHash(value)==hash,"native hash facts require captured source-bound bytes rather than a pathname");
        var responsePolicy=new ActiveResponsePolicy{Mode="manual",Actions=["end-process"],RequirePreservedActor=false};
        var response=ActiveResponseEvidence.Preview(sensor,value,responsePolicy,value.ObservedUtc);
        check(response.Target is {} target&&target.Process.Pid==k.ProcessId&&target.ActorSha256==hash,"response preview identifies the exact native process lifetime and held executable hash");
        check(!response.Eligible&&response.Reasons.SequenceEqual(["RESPONSE_PROTECTED_ACCOUNT"]),"root actor remains protected even with complete native executable evidence");
        check(!ActiveResponseEvidence.Preview(sensor,value,responsePolicy with{Mode="observe"},now).Eligible,"observe mode cannot advertise an executable response");
        check(!ActiveResponseEvidence.Preview(sensor,value,responsePolicy,value.ObservedUtc.AddMinutes(3)).Eligible,"expired native event cannot authorize response");
        check(!ActiveResponseEvidence.Preview(Guid.NewGuid().ToString("N"),value,responsePolicy,now).Eligible,"response rejects evidence from another sensor");
        check(ActiveResponseEvidence.Preview(sensor,value,responsePolicy with{RequirePreservedActor=true},now).Reasons.Contains("RESPONSE_ACTOR_PRESERVATION_REQUIRED"),"response requiring preservation rejects a snapshot without a preserved artifact");
        check(ActiveResponseEvidence.Preview(sensor,value,responsePolicy with{Actions=["block-resource"]},now).Reasons.Contains("RESPONSE_RESOURCE_PATH_UNAVAILABLE"),"Linux operation source cannot invent a pathname for file ACL changes");
        var preservation=new PreservationEvidence{EvidenceId=Guid.NewGuid().ToString("N"),SourceEventId=value.EventId,ProcessInstanceId=value.Forensics.Process.InstanceId,Sha256=hash,HashMatched=true,Status=EvidenceStatus.Captured("synthetic-preservation")};
        var preserved=value with{Forensics=value.Forensics with{Preservation=preservation}};
        var completionId=Guid.NewGuid().ToString("N");
        var completion=value with{EventId=completionId,Source="Forensic enrichment",Forensics=value.Forensics with{EventId=completionId,RelatedEventId=value.EventId,ActorExecutable=value.Forensics.ActorExecutable with{Sha256=hash},Preservation=preservation}};
        var joined=ActiveResponseEvidence.AttachPreservation(value,completion);
        check(joined.Forensics?.Preservation.EvidenceId==preservation.EvidenceId&&ReferenceEquals(joined.Forensics.Process,value.Forensics.Process)&&ReferenceEquals(joined.Attribution,value.Attribution),"preservation completion never replaces original process or accessing-thread evidence");
        check(ReferenceEquals(value,ActiveResponseEvidence.AttachPreservation(value,completion with{Forensics=completion.Forensics with{SensorId=Guid.NewGuid().ToString("N")}})),"another sensor's artifact cannot authorize response");
        check(ReferenceEquals(value,ActiveResponseEvidence.AttachPreservation(value,completion with{Forensics=completion.Forensics with{Preservation=preservation with{HashMatched=false}}})),"failed artifact hash verification cannot authorize response");
        check(ReferenceEquals(value,ActiveResponseEvidence.AttachPreservation(value,completion with{Forensics=completion.Forensics with{Process=completion.Forensics.Process with{InstanceId=new string('B',64)}}})),"another process lifetime's artifact cannot authorize response");
        check(ReferenceEquals(value,ActiveResponseEvidence.AttachPreservation(value,completion with{Source="Agent response"})),"response telemetry cannot impersonate forensic completion");
        check(ActiveResponseEvidence.Preview(sensor,preserved,responsePolicy with{RequirePreservedActor=true},now).ActorPreserved,"matching preservation links event, executable bytes and process instance");
        check(!ActiveResponseEvidence.Preview(sensor,preserved with{Forensics=preserved.Forensics! with{Preservation=preservation with{HashMatched=false}}},responsePolicy with{RequirePreservedActor=true},now).Eligible,"preservation hash failure cannot authorize response");
        check(!ActiveResponseEvidence.Preview(sensor,preserved with{Forensics=preserved.Forensics! with{Preservation=preservation with{SourceEventId=Guid.NewGuid().ToString("N")}}},responsePolicy with{RequirePreservedActor=true},now).Eligible,"preservation for a different source event cannot authorize response");
        var tick=Math.Max(Stopwatch.GetTimestamp(),value.Forensics.MonotonicTicks+1);var health=new LinuxKernelSourceHealthEvidence(1,0,0,now,now,now,now,tick,tick+1,tick+2,tick+3,tick+4,Stopwatch.Frequency);
        var parsed=LinuxControlledLoaderProtocol.ParseReady(ready);var source=new LinuxKernelSourceMatchEvidence(session,k.ProviderEpoch,k.CollectorInstance,Convert.ToBase64String(ready),Convert.ToHexString(SHA256.HashData(ready)),Convert.ToBase64String(activated),Convert.ToHexString(SHA256.HashData(activated)),parsed.Targets!.Digest,health);
        var binding=LinuxNativeHashBinding.Create(value,source);check(binding.Matches(value),"native hash binding verifies source activation, target membership and zero-loss generation");
        check(actor.AcquiredLinuxNativeHash(value)==hash,"client requires the still-held unchanged private image descriptor");
        check(!(binding with{ActorSha256=new string('B',64)}).Matches(value),"claimed binary hash substitution rejected");
        check(!(binding with{Source=source with{Health=health with{LostAtSample=1}}}).Matches(value),"source loss cannot produce whitelist authority");
        check(!(binding with{SourceGeneration=2}).Matches(value),"source generation replacement rejected");
        check(!(binding with{PolicyInputSha256=new string('B',64)}).Matches(value),"policy-input tampering rejected");
        check(LinuxNativeHashBinding.ActorHash(value with{Forensics=value.Forensics with{ActorExecutable=value.Forensics.ActorExecutable with{BindingStatus=EvidenceStatus.Unavailable("missing")}}})==null,"unavailable actor preservation remains alerting");
        using var returnActor=ActorLease.Capture(returned,sensor);
        var returnedEvidence=new ForensicCollector(sensor,root).Begin(returned,returnActor);
        returnedEvidence=k.IoObservation!=null?returnedEvidence with{LinuxIoPair=new(){Status="paired",Reason="EXACT_DURABLE_IO_PAIR",EntryEventId=value.EventId,ReturnEventId=returned.EventId,EntryKernel=k,ActorCompletionEventId=actor.LinuxNativeWork.CompletionEventId,ActorSha256=hash,ActorStatus=EvidenceStatus.Captured("EXACT_IO_ENTRY_VERIFIED_PRIVATE_ACTOR")}}:
            returnedEvidence with{LinuxPermissionPair=new(){Status="paired",Reason="EXACT_DURABLE_PERMISSION_PAIR",EntryEventId=value.EventId,ReturnEventId=returned.EventId,EntryKernel=k,ActorCompletionEventId=actor.LinuxNativeWork.CompletionEventId,ActorSha256=hash,ActorStatus=EvidenceStatus.Captured("EXACT_PERMISSION_ENTRY_VERIFIED_PRIVATE_ACTOR")}};
        var result=returned with{Forensics=returnedEvidence};
        var returnTick=Math.Max(Stopwatch.GetTimestamp(),returnedEvidence.MonotonicTicks+1);
        var returnSource=source with{Health=new(1,0,0,now,now,now,now,returnTick,returnTick+1,returnTick+2,returnTick+3,returnTick+4,Stopwatch.Frequency)};
        check(LinuxKernelEvidence.Matches(result)&&result.Forensics.IsValid(),"paired return remains its own valid observation without acquiring another lease");
        check(LinuxNativeHashBinding.ActorHash(result)==null,"completed operation alone cannot claim a captured executable hash");
        var resultBinding=LinuxNativeHashBinding.Create(result,returnSource,value);
        check(resultBinding.Matches(result)&&resultBinding.ActorSha256==hash,"completed write hash is verified against exact durable entry snapshot and fresh source health");
        check(!(resultBinding with{EntryEvent=value with{EventId=Guid.NewGuid().ToString("N")}}).Matches(result),"another entry event cannot authorize the return hash");
        check(!(resultBinding with{EntryEvent=value with{Forensics=value.Forensics with{SensorId=Guid.NewGuid().ToString("N")}}}).Matches(result),"entry proof from another sensor cannot authorize the return hash");
        check(!(resultBinding with{Source=returnSource with{Health=returnSource.Health with{LostAtSample=1}}}).Matches(result),"source loss between entry and return invalidates whitelist authority");
        check(!(resultBinding with{EntryEvent=null}).Matches(result),"omitting exact entry proof cannot authorize completed-operation suppression");
        var decision=new TrustRuntimeDecision(1,new string('A',64),"enforce",new(1,"log-only",true,true,"informational",[],"synthetic verified matching"));
        var trust=new EventTrust(4,"linux",null,LinuxNativeHashBinding.ActorFor(sensor,result,hash),decision){EvaluatedUtc=now,ProcessBasis=LinuxNativeHashBinding.Basis,LinuxNativeHashBinding=resultBinding};
        check(trust.IsValid()&&trust.IsLogOnlyFor(result),"versioned return trust decision requires the complete entry proof");
        var round=System.Text.Json.JsonSerializer.Deserialize<EventTrust>(System.Text.Json.JsonSerializer.Serialize(trust))!;
        check(round.IsLogOnlyFor(result),"return trust entry proof survives SIEM/wire serialization");
        var store=new Store(Path.Combine(root,"server-replay"));store.InitializeTrustStorage();var enrolled=store.Enroll(new(store.CreateCode().Code,"native-hash-replay","fixture"))!;
        store.RecordTrustCapabilities(enrolled.EndpointId,new(PolicyVersion:4,OperatingSystem:"linux"){LinuxNativeHashTrustVersion=1});
        store.RecordNativeHashTrustCapabilities(enrolled.EndpointId,new(PolicyVersion:4,OperatingSystem:"linux"){LinuxNativeHashTrustVersion=1});
        AgentEvent SensorEvent(AgentEvent eventValue)
        {
            var f=eventValue.Forensics!;var instance=Convert.ToHexString(SHA256.HashData(System.Text.Encoding.UTF8.GetBytes(enrolled.EndpointId+":"+eventValue.ProcessId+":"+eventValue.Attribution!.LinuxKernel!.ProcessStartKey)));
            return eventValue with{Forensics=f with{SensorId=enrolled.EndpointId,Process=f.Process with{InstanceId=instance}}};
        }
        var serverEntry=SensorEvent(value);var serverResult=SensorEvent(result);
        var action=k.IoObservation!=null?"write":"read";
        var rule=new TrustRule(Guid.NewGuid().ToString("N"),"organization","server","process",[action],"log-only",now.AddMinutes(-1),now.AddHours(1)){Enabled=true,OperatingSystem="linux",ProcessMatch=TrustEvaluation.LinuxNativeHashProcessMatch,Sha256=hash};
        var policy=store.PublishTrustPolicy(new(0,"enforce",[rule],[],""),"fixture");var evaluated=DateTimeOffset.UtcNow;
        var serverBinding=LinuxNativeHashBinding.Create(serverResult,returnSource,serverEntry);var identity=LinuxNativeHashBinding.ActorFor(enrolled.EndpointId,serverResult,hash);
        var context=TrustIdentityContext.Bind(new("server",null,enrolled.EndpointId,"linux",serverResult.Path,[action],serverResult.ObservedUtc,identity){ProcessBasis=LinuxNativeHashBinding.Basis},serverResult);
        var actualDecision=TrustEvaluation.Evaluate(policy.Rules,context,evaluated,policy.ApprovedRules());
        var serverTrust=new EventTrust(4,"linux",null,identity,new(policy.Revision,policy.Digest(),"enforce",actualDecision)){EvaluatedUtc=evaluated,ProcessBasis=LinuxNativeHashBinding.Basis,LinuxNativeHashBinding=serverBinding};
        serverResult=serverResult with{Trust=serverTrust};var stored=new StoredEvent(1,enrolled.EndpointId,DateTimeOffset.UtcNow,serverResult);
        check(store.ClassifyTrust(stored)==TrustEventClassification.PolicyUnknown,"server refuses return suppression until its original entry exists in the same sensor's database");
        check(store.Ingest(enrolled.EndpointId,new([serverEntry,serverResult]))?.Accepted==2,"server persists exact entry proof and trusted return without dropping either event");
        check(store.ClassifyTrust(stored)==TrustEventClassification.LogOnly,"server independently replays completed-write hash whitelist against persisted entry evidence");
        var mutated=serverResult with{Trust=serverTrust with{LinuxNativeHashBinding=serverBinding with{EntryEvent=serverEntry with{User="fabricated user"}}}};
        check(store.ClassifyTrust(stored with{Event=mutated})==TrustEventClassification.PolicyUnknown,"server cannot suppress using an altered entry identity");
        if(serverResult.Forensics?.LinuxPermissionPair!=null)
        {
            using var spool=new EventSpool(Path.Combine(root,"permission-spool"),enrolled.EndpointId);spool.Enqueue(serverResult);var batch=spool.Peek();
            var receipt=new BatchReceipt(1,0){AttributionVersion=1,TrustVersion=1,WhitelistVersion=1,ForensicsVersion=1,LinuxKernelVersion=1,LinuxKernelTargetIdentityVersion=1,LinuxPermissionObservationVersion=1,LinuxIoObservationVersion=1,LinuxNativeHashTrustVersion=1};
            try{spool.Acknowledge(batch,receipt);throw new InvalidDataException("Old receipt cleared new permission evidence");}
            catch(InvalidDataException error)when(error.Message.Contains("Permission-pair evidence",StringComparison.Ordinal)){check(spool.Peek().Events.Length==1,"old-server receipt retains the complete permission-pair evidence in the durable queue");}
            spool.Acknowledge(batch,receipt with{LinuxPermissionPairVersion=1});check(spool.Peek().Events.Length==0,"explicit permission-pair receipt permits exact durable queue acknowledgment");
            using var handler=new PermissionCapabilityHandler();using var transport=new HttpClient(handler){BaseAddress=new Uri("https://isolated.invalid/")};using var client=new ManagementClient(transport,new string('A',64));
            void Refuses(string expected,string label)
            {
                try{client.SendEventsAsync(batch).GetAwaiter().GetResult();throw new InvalidDataException("Unsupported receipt accepted");}
                catch(InvalidDataException error)when(error.Message.Contains(expected,StringComparison.Ordinal)){check(true,label);}
            }
            Refuses("permission-pair evidence support unavailable","client preflight refuses a server that would discard permission-pair fields");check(handler.EventPosts==0,"unsupported server receives no permission-pair event POST");
            handler.Supported=true;Refuses("did not acknowledge permission-pair","client rejects a receipt that omits negotiated permission-pair support");
            handler.Acknowledged=true;check(client.SendEventsAsync(batch).GetAwaiter().GetResult().Accepted==1,"client accepts an explicitly negotiated permission-pair receipt");
        }
        // These are explicit synthetic method facts; no native capability was opened or executed.
    }
}

internal sealed class PermissionCapabilityHandler:HttpMessageHandler
{
    internal bool Supported,Acknowledged;internal int EventPosts;
    protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request,CancellationToken token)
    {
        object payload;
        if(request.RequestUri!.AbsolutePath.EndsWith("/capabilities",StringComparison.Ordinal))payload=new{AttributionVersion=1,TrustVersion=1,WhitelistVersion=1,ForensicsVersion=1,LinuxKernelVersion=1,LinuxKernelTargetIdentityVersion=1,LinuxPermissionObservationVersion=1,LinuxIoObservationVersion=1,LinuxNativeHashTrustVersion=1,LinuxPermissionPairVersion=Supported?1:0};
        else{EventPosts++;payload=new BatchReceipt(1,0){AttributionVersion=1,TrustVersion=1,WhitelistVersion=1,ForensicsVersion=1,LinuxKernelVersion=1,LinuxKernelTargetIdentityVersion=1,LinuxPermissionObservationVersion=1,LinuxIoObservationVersion=1,LinuxNativeHashTrustVersion=1,LinuxPermissionPairVersion=Acknowledged?1:0};}
        return Task.FromResult(new HttpResponseMessage(System.Net.HttpStatusCode.OK){Content=new StringContent(System.Text.Json.JsonSerializer.Serialize(payload),System.Text.Encoding.UTF8,"application/json")});
    }
}
