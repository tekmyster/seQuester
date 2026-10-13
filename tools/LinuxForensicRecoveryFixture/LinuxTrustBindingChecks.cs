using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using RansomFree.Client.Forensics;
using RansomFree.Contracts;

internal static class LinuxTrustBindingChecks
{
    internal static void Run(string evidence,string root)
    {
        if(Directory.Exists(root))throw new ArgumentException("Fresh output directory required");
        byte[] Exact(string name,string sha)
        {
            var bytes=File.ReadAllBytes(Path.Combine(evidence,name));
            if(Convert.ToHexString(SHA256.HashData(bytes))!=sha)throw new InvalidDataException("Accepted R36 evidence required: "+name);
            return bytes;
        }
        var events=JsonNode.Parse(Exact("events.json","09D3DFC1501CC00CE9EF550EEB9E301BE5A8C7829B30E557E9B081790315C3B4"))!;
        var samples=JsonNode.Parse(Exact("source-health.json","9C19E06A9FCBE7EFA8689F47BB5F894F0E7584D5E95AB31449F5D82C6D646A85"))!;
        var originals=events["Originals"]!.Deserialize<AgentEvent[]>()!;
        var completions=events["Completions"]!.Deserialize<AgentEvent[]>()!;
        var checks=new List<string>();
        void Check(bool ok,string label){if(!ok)throw new Exception(label);checks.Add(label);}
        LinuxKernelSourceMatchEvidence Source(string id)=>samples["Observations"]!.AsArray().Single(n=>n!["EventId"]!.GetValue<string>()==id)!["Result"]!["Evidence"]!.Deserialize<LinuxKernelSourceMatchEvidence>()!;
        Check(originals.Length==5&&completions.Length==5,"five actual native pairs");
        var bindings=new List<LinuxKernelTrustBinding>();
        foreach(var original in originals)
        {
            var before=JsonSerializer.SerializeToUtf8Bytes(original);
            var binding=LinuxKernelTrustBinding.Create(original,Source(original.EventId));bindings.Add(binding);
            Check(binding.Matches(original),"source and actor agree: "+original.EventId);
            var clone=JsonSerializer.Deserialize<AgentEvent>(before)!;
            Check(clone.Attribution!.LinuxKernel==original.Attribution!.LinuxKernel&&clone.Forensics!.ActorExecutable.LinuxNativeWork==original.Forensics!.ActorExecutable.LinuxNativeWork,"current native kernel/work value records remain equal across JSON clone: "+original.EventId);
            Check(JsonSerializer.Deserialize<LinuxKernelTrustBinding>(JsonSerializer.Serialize(binding))==binding,"binding roundtrip: "+original.EventId);
            Check(before.AsSpan().SequenceEqual(JsonSerializer.SerializeToUtf8Bytes(original))&&original.Trust==null,"construction cannot mutate original or grant policy authority: "+original.EventId);
            Check(!binding.Matches(completions.Single(e=>e.Forensics!.RelatedEventId==original.EventId)),"completion cannot create authority: "+original.EventId);
            Check(!binding.Matches(originals.First(e=>e.EventId!=original.EventId)),"actor event cross-association refused: "+original.EventId);
        }
        var e=originals[0];var b=bindings[0];
        void Reject(string field,JsonNode? replacement)
        {
            var node=JsonSerializer.SerializeToNode(b)!;var parts=field.Split('.');var cursor=node;
            foreach(var part in parts[..^1])cursor=cursor[part]!;
            cursor[parts[^1]]=replacement;
            Check(!node.Deserialize<LinuxKernelTrustBinding>()!.Matches(e),"reject "+field);
        }
        Reject("Version",2);Reject("SensorId",new string('a',32));Reject("Actor",null);Reject("Source",null);Reject("PolicyInputSha256",new string('a',64));
        // Every represented actor fact is compared with a fresh derivation,
        // including fields that used to be getter-only descriptive constants.
        foreach(var property in JsonSerializer.SerializeToNode(b.Actor)!.AsObject())
        {
            var element=JsonSerializer.SerializeToElement(property.Value);
            JsonNode replacement=element.ValueKind switch
            {
                JsonValueKind.String=>JsonValue.Create("mismatch")!,
                JsonValueKind.Number=>JsonValue.Create(element.GetInt64()+1)!,
                _=>throw new Exception("Unexpected actor fact type: "+property.Key)
            };
            // Timestamp properties must remain deserializable to exercise the comparison.
            if(property.Key.EndsWith("Utc",StringComparison.Ordinal))replacement=JsonValue.Create(DateTimeOffset.UnixEpoch)!;
            Reject("Actor."+property.Key,replacement);
        }
        foreach(var name in new[]{"SourceSessionId","ProviderEpoch","CollectorInstance","ReadyBase64","ReadySha256","ActivatedBase64","ActivatedSha256","TargetSetSha256"})
            Reject("Source."+name,"mismatch");
        Reject("Source.Health",null);Reject("Source.Health.Generation",2);Reject("Source.Health.LostAtReady",1);Reject("Source.Health.LostAtSample",1);
        Reject("Source.Health.Semantics","ZERO_LOSS_UNTIL_FSYNC");Reject("Source.Health.ChildExitNotObservedAtCheck",false);
        Reject("Source.Health.MonotonicFrequency",1);Reject("Source.Health.ActiveBeforeTicks",1);
        Reject("Source.Health.SampleStartedTicks",0);Reject("Source.Health.SampleReturnedTicks",0);Reject("Source.Health.ChildCheckedTicks",0);Reject("Source.Health.SealedTicks",0);
        foreach(var name in new[]{"StartedUtc","ReturnedUtc","ChildCheckedUtc","SealedUtc"})Reject("Source.Health."+name,JsonValue.Create(default(DateTimeOffset)));
        Check((b with{Source=b.Source with{Health=b.Source.Health with{ReturnedUtc=b.Source.Health.StartedUtc.AddHours(-1)}}}).Matches(e),"wall-clock jump does not override stronger monotonic ordering");
        void Frame(bool ready,Action<JsonObject> mutate,string label)
        {
            var source=b.Source;var node=JsonNode.Parse(Convert.FromBase64String(ready?source.ReadyBase64:source.ActivatedBase64))!.AsObject();mutate(node);
            var bytes=JsonSerializer.SerializeToUtf8Bytes(node);var text=Convert.ToBase64String(bytes);var hash=Convert.ToHexString(SHA256.HashData(bytes));
            source=ready?source with{ReadyBase64=text,ReadySha256=hash}:source with{ActivatedBase64=text,ActivatedSha256=hash};
            Check(!(b with{Source=source}).Matches(e),label);
        }
        Frame(true,n=>n["activationNonce"]=new string('b',32),"validly rehashed ready nonce cannot disagree with activation");
        Frame(true,n=>n["targetCount"]=1,"invalid target count refused after rehash");
        Frame(true,n=>n["lostAtReady"]=1,"initial source loss refused after rehash");
        Frame(true,n=>n["extra"]=true,"unknown source ABI field refused");
        Frame(false,n=>n["sessionId"]=new string('b',32),"different activation session refused");
        Frame(false,n=>n["providerEpoch"]=1,"different activation epoch refused");
        Frame(false,n=>n["observeAttached"]=false,"missing native observation attachment refused");
        Frame(false,n=>n["denialAttached"]=false,"missing native denial attachment refused");
        Frame(false,n=>n["lostAtActivation"]=1,"activation loss refused");
        Frame(false,n=>n["attachedProgramIds"]![0]=999,"wrong activated program association refused");
        var raw=Encoding.UTF8.GetString(Convert.FromBase64String(b.Source.ActivatedBase64));
        var duplicate=Encoding.UTF8.GetBytes(raw[..^1]+",\"lostAtActivation\":0}");
        Check(!(b with{Source=b.Source with{ActivatedBase64=Convert.ToBase64String(duplicate),ActivatedSha256=Convert.ToHexString(SHA256.HashData(duplicate))}}).Matches(e),"duplicate control properties cannot hide contradictory data");
        Check(!(b with{Source=b.Source with{ReadyBase64=" "+b.Source.ReadyBase64}}).Matches(e),"noncanonical base64 refused");
        Check(!b.Matches(null),"missing original refused");
        var now=b.Source.Health.StartedUtc.AddMilliseconds(-1);
        var rule=new TrustRule(Guid.NewGuid().ToString("N"),"organization","server","process",["open"],"log-only",e.ObservedUtc.AddMinutes(-1),now.AddDays(1))
        {Enabled=true,OperatingSystem="linux",ProcessMatch=TrustEvaluation.LinuxKernelProcessMatch,Executable=b.Actor.Executable,Sha256=b.Actor.Sha256};
        var policy=new TrustPolicy(3,"enforce",[rule],[],"qualification",e.ObservedUtc.AddMinutes(-1)){Version=3};policy.Validate();
        var context=new TrustContext("server",null,b.SensorId,"linux",e.Path,["open"],e.ObservedUtc,b.TrustActor()){ProcessBasis=LinuxKernelTrustBinding.Basis};
        var decision=TrustEvaluation.Evaluate(policy.Rules,context,now);
        Check(decision.LogOnly&&decision.RetainEvidence,"new exact task-root path plus SHA rule retains evidence and suppresses selected open request");
        var trust=new EventTrust(3,"linux",null,b.TrustActor(),new(policy.Revision,policy.Digest(),"enforce",decision))
            {EvaluatedUtc=now,ProcessBasis=LinuxKernelTrustBinding.Basis,LinuxKernelBinding=b};
        Check(trust.IsValid()&&TrustEvaluation.Evaluate(policy.Rules,trust.Context(b.SensorId,e),now).LogOnly,"versioned claim replays new context without inventing syscall success");
        foreach(var version in new[]{1,2})
        {
            bool invalid=false;try{(policy with{Version=version}).Validate();}catch(ArgumentException){invalid=true;}
            Check(invalid,"new rule cannot be published under old policy "+version);
            Check(!(trust with{Version=version}).IsValid(),"new binding cannot hide in old event trust "+version);
        }
        Check(!TrustEvaluation.Evaluate([rule],context with{Actor=context.Actor with{Sha256=new string('a',64)}},now).LogOnly,"same name/path with different bytes remains alerting");
        Check(!TrustEvaluation.Evaluate([rule],context with{Actor=context.Actor with{Sha256=null}},now).LogOnly,"unknown hash remains alerting");
        Check(!TrustEvaluation.Evaluate([rule],context with{Actor=context.Actor with{Executable=context.Actor.Executable!.ToUpperInvariant()}},now).LogOnly,"new path comparison is ordinal and case sensitive");
        Check(!TrustEvaluation.Evaluate([rule],context with{Actions=["read"]},now).LogOnly,"pre-open source cannot claim a completed read action");
        Check(!TrustEvaluation.Evaluate([rule],context with{ProcessBasis=null,Path="/bait"},now).LogOnly,"Audit-style context cannot match new path scope");
        Check(!TrustEvaluation.Evaluate([rule with{ProcessMatch=null}],context,now).LogOnly,"old exact path/hash rule is not silently reinterpreted");
        Check(!TrustEvaluation.Evaluate([rule with{ProcessMatch="event-path",Sha256=null}],context,now).LogOnly,"old path-only rule cannot match native task-root source");
        Check(!TrustEvaluation.Narrows(rule,rule with{ProcessMatch="event-path",Sha256=null}),"new scope is not an automatic narrowing of old path-only authority");
        Check(TrustEvaluation.Narrows(rule,rule),"same new scope can narrow itself");
        var account=rule with{Subject="account-and-process",Authority=b.SensorId,AccountId=b.Actor.FileSystemUid.ToString(System.Globalization.CultureInfo.InvariantCulture),AccountKind="uid"};
        Check(TrustEvaluation.Evaluate([account],context,now).LogOnly,"captured filesystem UID can constrain process/hash rule");
        Check(!TrustEvaluation.Evaluate([account],context with{Actor=context.Actor with{AccountId="4294967294"}},now).LogOnly,"different effective account cannot stand in for captured filesystem UID");
        foreach(var bad in new[]{rule with{OperatingSystem="windows"},rule with{Path="/bait"},rule with{ParentExecutable="/bin/parent"},rule with{Signer="publisher"},rule with{Publisher="publisher"},rule with{Executable="/tmp/a (deleted)"},rule with{Sha256=null},account with{AccountKind="sid",AccountId="S-1-5-18"}})
        {
            bool invalid=false;try{TrustEvaluation.Validate([bad]);}catch(ArgumentException){invalid=true;}
            Check(invalid,"unsupported native rule rejected: "+JsonSerializer.Serialize(bad));
        }
        Check(!TrustEvaluation.Evaluate([rule],trust.Context(new string('a',32),e),now).LogOnly,"server endpoint identity must match binding sensor");
        Check(!TrustEvaluation.Evaluate([rule],trust.Context(b.SensorId,e with{ProcessId=e.ProcessId+1}),now).LogOnly,"contradictory original cannot acquire verified context");
        Check(!(trust with{Actor=trust.Actor with{AccountId="4294967294"}}).IsValid(),"claim account cannot disagree with filesystem UID binding");
        Check(!(trust with{ProcessCreatedUtc=e.ObservedUtc}).IsValid(),"native lifetime key never manufactures wall-clock process creation");
        using(var actor=ActorLease.Unavailable(e,"qualification-replay-no-native-handle"))
        {
            var before=JsonSerializer.SerializeToUtf8Bytes(e);var calls=0;
            var prepared=LinuxPreparedTrustDecision.Apply(e,actor,(input,held)=>{calls++;Check(held==actor&&input.Trust==null&&input.Forensics!.Detection.ReasonCodes.SequenceEqual(["POLICY_INPUT_EXCLUDES_DETECTION"]),"preparation callback receives only projected decision input");return trust;});
            Check(calls==1&&prepared.Reason=="LINUX_TRUST_DECISION_PREPARED"&&JsonSerializer.Serialize(prepared.Event.Trust)==JsonSerializer.Serialize(trust)&&prepared.Event.Forensics!.Detection.Disposition=="log-only","one preparation freezes claim and resulting detection");
            Check(before.AsSpan().SequenceEqual(JsonSerializer.SerializeToUtf8Bytes(e))&&LinuxKernelTrustBinding.InputDigest(prepared.Event)==LinuxKernelTrustBinding.InputDigest(e),"original remains unchanged and every nondecision field is identical");
            Check(prepared.Event.Forensics!.CollectorEpoch==e.Forensics!.CollectorEpoch&&prepared.Event.Forensics.CollectorSequence==e.Forensics.CollectorSequence&&prepared.Event.Forensics.ProcessSequence==e.Forensics.ProcessSequence,"no second Begin or process sequence allocation");
            var unavailable=LinuxPreparedTrustDecision.Apply(e,actor,(_,_)=>null);
            Check(unavailable.Event.Trust==null&&unavailable.Event.Forensics!.Detection.Disposition=="alert","missing authority retains normal alert");
            var changed=LinuxPreparedTrustDecision.Apply(e,actor,(input,_)=>{input.Forensics!.Observation.Actions[0]="write";return trust;});
            Check(changed.Reason.StartsWith("LINUX_TRUST_PREPARATION_FAILED")&&changed.Event.Trust==null&&changed.Event.Forensics!.Detection.Disposition=="alert"&&LinuxKernelTrustBinding.InputDigest(changed.Event)==LinuxKernelTrustBinding.InputDigest(e),"callback cannot mutate original action through input arrays");
            var threw=LinuxPreparedTrustDecision.Apply(e,actor,(_,_)=>throw new IOException("source unavailable"));
            Check(threw.Event.Trust==null&&threw.Event.Forensics!.Detection.ReasonCodes.Contains("LINUX_TRUST_PREPARATION_FAILED"),"failed preparation is visible with unsuppressed evidence");
            var wrong=LinuxPreparedTrustDecision.Apply(e,actor,(_,_)=>trust with{LinuxKernelBinding=b with{PolicyInputSha256=new string('b',64)}});
            Check(wrong.Event.Trust==null&&wrong.Event.Forensics!.Detection.Disposition=="alert","wrong frozen input digest cannot suppress");
        }
        Directory.CreateDirectory(root);File.WriteAllBytes(Path.Combine(root,"bindings.json"),JsonSerializer.SerializeToUtf8Bytes(bindings));
        File.WriteAllBytes(Path.Combine(root,"checks.json"),JsonSerializer.SerializeToUtf8Bytes(new{Passed=true,Checks=checks.Count,Details=checks}));
        Console.WriteLine(JsonSerializer.Serialize(new{Passed=true,Checks=checks.Count,Scope="Replay of exact accepted native actor/source samples plus contradictory evidence; no new source authority, policy suppression or deployment"}));
    }
}
