using System.Globalization;
using System.Security.Cryptography;

namespace RansomFree.Contracts;

// Schema-8 captures operation-bound backing bytes without claiming a pathname.
// Hash-only rules are explicit; this must not be interpreted as a legacy
// task-root pathname rule, an executed-memory hash, or a safety verdict.
public sealed record LinuxNativeHashBinding(string SensorId,string SourceSessionId,long SourceGeneration,
    string ActorSha256,LinuxKernelSourceMatchEvidence Source,string PolicyInputSha256)
{
    public int Version {get;init;}=1;
    [System.Text.Json.Serialization.JsonIgnore(Condition=System.Text.Json.Serialization.JsonIgnoreCondition.WhenWritingNull)]
    public AgentEvent? EntryEvent {get;init;}
    public const string Basis="linux-control-v4-operation-backing-sha256-v1";
    public static string? ActorHash(AgentEvent value,AgentEvent? entry=null)
    {
        if(entry!=null)
        {
            if(value.Source!="Linux kernel"||value.Attribution?.LinuxKernel is not {} result||!LinuxKernelEvidence.Matches(value)||
                value.Forensics is not {} returned||!returned.IsValid()||returned.EventId!=value.EventId||returned.RelatedEventId!=null)return null;
            string? entryId,hash;LinuxKernelEvidence? linked;
            if(result.IoObservation is {Stage:2}&&returned.LinuxIoPair is {Status:"paired",ActorStatus.State:"captured"} io&&io.Matches(result,value.EventId,null))
            {entryId=io.EntryEventId;hash=io.ActorSha256;linked=io.EntryKernel;}
            else if(result.PermissionObservation is {Stage:2}&&returned.LinuxPermissionPair is {Status:"paired",ActorStatus.State:"captured"} permission&&permission.Matches(result,value.EventId,null))
            {entryId=permission.EntryEventId;hash=permission.ActorSha256;linked=permission.EntryKernel;}
            else return null;
            if(entry.Trust!=null||entry.Forensics?.SensorId!=returned.SensorId||entry.EventId!=entryId||entry.Attribution?.LinuxKernel is not {} entered||
                !(LinuxKernelEvidence.SameIoOperation(entered,result)||LinuxKernelEvidence.SamePermissionOperation(entered,result))||entered.NativeObservationSha256!=linked?.NativeObservationSha256||
                ActorHash(entry) is not {} entryHash||entryHash!=hash)return null;
            return entryHash;
        }
        if(value.Source!="Linux kernel"||value.Attribution?.LinuxKernel is not {CredentialFields:63,CredentialError:0,FileSystemUid:not null} k||
            !(k is {Version:4,NativeSchemaVersion:8,IoObservation:{Schema:3,Stage:1,IdentityFields:7,IdentityError:0,ActorMetadataError:0}}||k is {Version:3,NativeSchemaVersion:7,PermissionObservation:{Schema:1,Stage:1,IdentityFields:7,IdentityError:0,ActorMetadataError:0}})||
            !k.IsValid()||!LinuxKernelEvidence.Matches(value)||k.FileSystemUid==uint.MaxValue||k.Lease<=0||k.AssociationError!=0||k.AssociationBefore=="0"||k.AssociationBefore!=k.AssociationAfter||
            value.Forensics is not {} f||f.EventId!=value.EventId||f.RelatedEventId!=null||!f.IsValid()||
            f.ActorExecutable is not {BindingStatus.State:"captured",LinuxAcquisition:{Status.State:"captured",RecoveryStatus:null,NativeStatus:{Ready:true,MetadataChanged:0,AssociationState:1,AssociationError:0},SnapshotSha256:not null,SnapshotId:not null,SnapshotFile:not null,PersistedUtc:not null}} actor)return null;
        var a=actor.LinuxAcquisition!;var work=actor.LinuxNativeWork;
        if(actor.BindingSourceEventId!=value.EventId||actor.BindingCapturedUtc!=a.PersistedUtc||a.SourceEventId!=value.EventId||!a.Matches(k)||!a.IsValid(f.Process,value.EventId,null,actor.Sha256,actor.File)||
            k.ActorSize!="0"&&a.NativeStatus!.Size!=k.ActorSize||
            work is not {Version:2,State:"NATIVE_RETURNED_RECEIPT_COMMITTED",ReturnOutcome:"committed",StartingState:"Active",StartOrdering:"SAME_GENERATION_START",Method:{ControllerMethodAttempted:true,DropMethodAttempted:true,DropMethodReturned:true,DropReceiptCommitObserved:true,ErrorKind:null,LatestStatus.Ready:true}}||
            !work.IsValid(value.EventId,null)||!work.Matches(k)||work.IssuedGeneration!=work.AuthorizationGeneration||work.IssuedGeneration!=work.StartingGeneration||work.Method.LatestStatus!.Size!=a.NativeStatus!.Size)return null;
        return a.SnapshotSha256;
    }
    public static TrustActor ActorFor(string sensor,AgentEvent value,string hash)=>new(Authority:sensor,AccountId:value.Attribution!.LinuxKernel!.FileSystemUid!.Value.ToString(CultureInfo.InvariantCulture),Sha256:hash,AccountKind:"uid",Verified:true);
    public bool Matches(AgentEvent value)
    {
        var k=value.Attribution?.LinuxKernel;var f=value.Forensics;var work=(EntryEvent??value).Forensics?.ActorExecutable.LinuxNativeWork;
        if(Version!=1||f?.SensorId!=SensorId||!EvidenceTransferLimits.Id(SensorId)||ActorHash(value,EntryEvent) is not {} hash||hash!=ActorSha256||work==null||
            SourceSessionId!=work.SourceSessionId||SourceGeneration!=work.IssuedGeneration||Source?.Health?.IsValid(SourceGeneration)!=true||
            Source.SourceSessionId!=SourceSessionId||Source.ProviderEpoch!=k!.ProviderEpoch||Source.CollectorInstance!=k.CollectorInstance||
            Source.Health.MonotonicFrequency!=f.MonotonicFrequency||Source.Health.ActiveBeforeTicks<f.MonotonicTicks||PolicyInputSha256!=LinuxKernelTrustBinding.InputDigest(value))return false;
        try
        {
            byte[] Frame(string encoded,string digest){if(encoded is not {Length:>0 and <=5464}||!EvidenceTransferLimits.Hash(digest))throw new InvalidDataException("Invalid source frame");var bytes=Convert.FromBase64String(encoded);if(bytes.Length>4096||Convert.ToBase64String(bytes)!=encoded||Convert.ToHexString(SHA256.HashData(bytes))!=digest)throw new InvalidDataException("Invalid source frame");return bytes;}
            var ready=LinuxControlledLoaderProtocol.ParseReady(Frame(Source.ReadyBase64,Source.ReadySha256));
            if(ready.ControlVersion!=4||ready.Epoch.ToString(CultureInfo.InvariantCulture)!=k.ProviderEpoch||ready.Lost!=Source.Health.LostAtReady||ready.Targets?.Digest!=Source.TargetSetSha256||
                k.TargetIdentity is not {} target||!ready.Targets.Contains(target.Ordinal,target.Device,ulong.Parse(target.Inode,CultureInfo.InvariantCulture)))return false;
            return LinuxControlledLoaderProtocol.ParseActivated(Frame(Source.ActivatedBase64,Source.ActivatedSha256),ready,SourceSessionId).Lost==0;
        }
        catch(Exception e)when(e is InvalidDataException or FormatException or ArgumentException or OverflowException){return false;}
    }
    public static LinuxNativeHashBinding Create(AgentEvent value,LinuxKernelSourceMatchEvidence source,AgentEvent? entry=null)
    {
        var hash=ActorHash(value,entry)??throw new InvalidDataException("Operation-bound Linux executable hash unavailable");var work=(entry??value).Forensics!.ActorExecutable.LinuxNativeWork!;
        var result=new LinuxNativeHashBinding(value.Forensics!.SensorId,work.SourceSessionId,work.IssuedGeneration,hash,source,LinuxKernelTrustBinding.InputDigest(value)){EntryEvent=entry};
        if(!result.Matches(value))throw new InvalidDataException("Linux native hash binding inconsistent");return result;
    }
}
