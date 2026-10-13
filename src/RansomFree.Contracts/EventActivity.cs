namespace RansomFree.Contracts;

// Read-side interpretation, never a replacement for the original event or a response handle.
public sealed record EventActivity(int Version,string[] Actions,string Evidence,string Outcome,string Basis)
{
    public static EventActivity From(AgentEvent value)
    {
        var source=value.Source;var raw=value.Operation;
        EventActivity Result(string evidence,string outcome,string basis,params string[] actions)=>new(1,actions,evidence,outcome,basis);
        if(source=="Windows syscall")
        {
            if(!WindowsSyscallObservation.Matches(value)||value.Attribution?.WindowsSyscall is not {} s)
                return Result("unknown","unknown","Syscall evidence is missing or contradictory.","unknown");
            var n=s.Native;var action=n.Operation switch{1=>"read",2=>"write",3 when n.InformationClass is 10 or 65=>"rename",3 when n.InformationClass is 13 or 64=>"delete-request",3 when n.InformationClass==20=>"truncate",_=>"metadata"};
            return Result("syscall-return",n.Outcome,"Native submission return; pending is not final completion, append is not established by write alone, and delete disposition is not final deletion.",action);
        }
        if(source=="Linux kernel")
        {
            if(value.Attribution?.LinuxKernel is {Version:4,IoObservation:{} io}&&LinuxKernelEvidence.Matches(value))
            {
                if(io.Diagnostic)return Result("collection-diagnostic","unknown","Unpairable native I/O capture diagnostic; no completed operation asserted.","unknown");
                var action=io.AppendRequested==true?"append":"write";
                return Result(io.Stage==1?"io-entry":io.Outcome=="pending"?"io-pending":"kernel-operation",io.Outcome switch{"success"=>"success","failure"=>"failed",_=>"unknown"},
                    "Synchronous VFS entry/return; byte count is not disk durability or asynchronous completion. Inode sizes are nonexclusive samples.",io.Stage==1?action+"-request":action);
            }
            if(value.Attribution?.LinuxKernel is {Version:3,PermissionObservation:{} p}&&LinuxKernelEvidence.Matches(value))
            {
                if(p.Diagnostic)return Result("collection-diagnostic","unknown","Unpairable kernel collection diagnostic; no completed file operation is asserted.","unknown");
                var requested=new List<string>();
                if((p.AccessMask&4)!=0)requested.Add("read");
                if((p.AccessMask&2)!=0||(p.AccessMask&8)!=0)requested.Add("write");
                if((p.AccessMask&1)!=0)requested.Add("execute");
                if(requested.Count==0)requested.Add("access-request");
                return Result("permission-check","unknown","Requested Linux permission mask; hook return and final syscall result remain distinct.",requested.ToArray());
            }
            return value.Attribution?.LinuxKernel!=null&&LinuxKernelEvidence.Matches(value)
                ?Result("permission-check","unknown","BPF LSM file_open observation; the preceding BPF result is not the final syscall result.","open-request")
                :Result("unknown","unknown","Linux kernel evidence is missing or contradictory.","unknown");
        }
        if(source=="Windows minifilter"&&value.Attribution is {Provider:"Windows minifilter",WindowsKernel:{} k})
        {
            var action=k.Major switch{0=>"open",3=>"read",4=>"write",6 when k.OperationClass is 10 or 65=>"rename",6 when k.OperationClass is 13 or 64=>"delete-request",6=>"metadata",21=>"permissions",255=>"mapping-request",_=>"unknown"};
            return Result(k.Major==255?"permission-check":"kernel-operation",value.Attribution.Outcome switch{"Success"=>"success","Failed"=>"failed",_=>"unknown"},"Pre-operation actor snapshot and post-operation status; delete disposition is not final deletion and mapping is not every later memory access.",action);
        }
        var kernel=KernelActivityRules.All.FirstOrDefault(rule=>rule.Provider==source&&rule.Provider==value.Attribution?.Provider&&rule.Operation==raw);
        if(kernel!=null)
            return Result(kernel.Evidence,kernel.Evidence=="intent"?"unknown":value.Attribution?.Outcome switch{"Success"=>"success","Failed"=>"failed",_=>"unknown"},
                "Kernel actor snapshot. Permission checks, intent and completed I/O are distinct. Delete disposition does not establish final deletion; mapping checks do not observe every later memory access.",kernel.Action);
        if(source=="Server service decoy"&&value.ServiceContext is {Method:"GET"})return Result("observed-request","success","Request and immutable service context committed by the server; source address is not user/process attribution.","service-access");
        if(source=="Linux Audit"&&value.Attribution is {Provider:"Linux Audit",Syscall:not null} audit)
        {
            var syscall=audit.Syscall[(audit.Syscall.LastIndexOf(':')+1)..];
            var action=syscall switch
            {
                "open" or "openat" or "openat2"=>"open",
                "read" or "pread64" or "readv" or "preadv" or "preadv2"=>"read",
                "write" or "pwrite64" or "writev" or "pwritev" or "pwritev2"=>"write",
                "truncate" or "ftruncate"=>"truncate",
                "rename" or "renameat" or "renameat2"=>"rename",
                "unlink" or "unlinkat" or "rmdir"=>"delete",
                "chmod" or "fchmod" or "fchmodat" or "fchmodat2"=>"permissions",
                "chown" or "fchown" or "lchown" or "fchownat"=>"ownership",
                "mkdir" or "mkdirat"=>"create",
                "creat"=>"create-or-truncate",
                "link" or "linkat"=>"hardlink",
                "symlink" or "symlinkat"=>"symlink",
                "stat" or "fstat" or "lstat" or "newfstatat" or "statx" or "access" or "faccessat" or "faccessat2"=>"query",
                // Without syscall argument/path-role correlation these do not prove a copy.
                "copy_file_range" or "sendfile" or "splice"=>"transfer",
                _=>"unknown"
            };
            var outcome=audit.Outcome switch{"Success"=>"success","Failed"=>"failed",_=>"unknown"};
            return Result(action=="unknown"?"unknown":"intent",outcome,"Recorded syscall; byte count, final file state and copy lineage are not established.",action);
        }
        if(source=="Windows audit 5145"&&WindowsShareEvidence.Matches(value))return Result("share-authorization",value.Attribution!.WindowsShare!.AuthorizationOutcome=="Denied"?"failed":"unknown","SMB share authorization; granted access is not completed NTFS I/O. Remote application/PID is not supplied by this source.","open-request");
        if(source=="Windows audit 4656")return Result("intent",raw=="Access denied"?"failed":"unknown","Handle access request; requested rights are not proof of completed I/O.","open");
        if(source=="Windows audit 4663")
        {
            var actions=new List<string>();
            foreach(var part in raw.Split(", ",StringSplitOptions.None))
            {
                var action=part switch{"Content read (copy possible)"=>"read","Content written"=>"write","Delete access used"=>"delete","Permissions changed"=>"permissions-or-ownership",_=>"unknown"};
                if(!actions.Contains(action))actions.Add(action);
            }
            return Result(actions.Contains("unknown")?"unknown":"access-used","success","Object access rights used; not proof of a complete copy, deletion or encryption.",actions.ToArray());
        }
        if(source is "Linux inotify" or "Linux fanotify" or "macOS FSEvents")
        {
            var action=raw switch
            {
                "Content read (copy possible)"=>"read",
                "File opened"=>"open",
                "Canary modified (encryption possible)"=>"write",
                "Canary content/metadata changed (encryption possible)"=>"content-or-metadata",
                "Canary deleted"=>"delete",
                "Canary moved/renamed"=>"rename-or-move",
                "Canary path created/replaced" or "Canary path moved/replaced"=>"create-or-replace",
                "Canary metadata changed"=>"metadata",
                _=>"unknown"
            };
            // Reject impossible combinations instead of laundering submitted strings as sensor proof.
            if(source=="macOS FSEvents"&&action is "read" or "open")action="unknown";
            if(source=="Linux fanotify"&&action is not ("read" or "open" or "write"))action="unknown";
            return Result(action=="unknown"?"unknown":"notification","unknown","Provider notification; actor completeness is separate. No copy or encryption conclusion.",action);
        }
        return Result("unknown","unknown","No reviewed normalization for this provider/event.","unknown");
    }
}

// Shared reviewed vocabulary also drives the database action filter/sort projection.
// Submitted strings from a different provider never acquire kernel semantics.
public sealed record KernelActivityRule(string Provider,string Operation,string Action,string Evidence);
public static class KernelActivityRules
{
    public static IReadOnlyList<KernelActivityRule> All {get;}=Array.AsReadOnly(new KernelActivityRule[]{
        new("Windows minifilter","File open","open","kernel-operation"),
        new("Windows minifilter","Content read (copy possible)","read","kernel-operation"),
        new("Windows minifilter","Content written","write","kernel-operation"),
        new("Windows minifilter","File renamed","rename","kernel-operation"),
        new("Windows minifilter","Delete requested","delete-request","kernel-operation"),
        new("Windows minifilter","File metadata changed","metadata","kernel-operation"),
        new("Windows minifilter","Permissions changed","permissions","kernel-operation"),
        new("Windows minifilter","Memory mapping requested","mapping-request","permission-check"),
        new("Windows minifilter prototype","File open","open","kernel-operation"),
        new("Windows minifilter prototype","Content read (copy possible)","read","kernel-operation"),
        new("Windows minifilter prototype","Content written","write","kernel-operation"),
        new("Windows minifilter prototype","File renamed","rename","kernel-operation"),
        new("Windows minifilter prototype","Delete requested","delete-request","kernel-operation"),
        new("Windows minifilter prototype","File metadata changed","metadata","kernel-operation"),
        new("Windows minifilter prototype","Permissions changed","permissions","kernel-operation"),
        new("Windows minifilter prototype","Memory mapping requested","mapping-request","permission-check"),
        new("Linux eBPF prototype","Kernel open permission","open-request","permission-check"),
        new("Linux eBPF prototype","Kernel access permission","access-request","permission-check"),
        new("Linux eBPF prototype","Kernel inode permission","access-request","permission-check"),
        new("Linux eBPF prototype","Kernel content read","read","kernel-operation"),
        new("Linux eBPF prototype","Kernel content written","write","kernel-operation"),
        new("Linux eBPF prototype","Kernel rename intent","rename-request","intent"),
        new("Linux eBPF prototype","Kernel unlink intent","delete-request","intent"),
        new("Linux eBPF prototype","Kernel metadata intent","metadata-request","intent"),
        new("Linux eBPF prototype","Kernel mapping permission","mapping-request","permission-check")
    });
}

public sealed record SensorCapability(string Provider,string ActorSupport,string[] Signals,string[] Boundaries,string Acceptance);
public static class SensorCapabilities
{
    // Source capability inventory, not an assertion that an endpoint enabled or passed a sensor.
    public static IReadOnlyList<SensorCapability> Inventory=>[
        new("Linux Audit","Event-time PID and kernel account IDs when present",["syscall intent","outcome","path role"],["Only approved audit rules","Record completeness varies","No byte count or copy lineage in current event contract"],"Native operation matrix pending; selected open-intent pilots only"),
        new("Linux inotify","Path-level detection; actor identity unavailable",["open","read notification","write notification","name change","metadata change"],["Coalescing and queue loss","No actor identity","No copy/encryption proof"],"Detections retained; actor evidence supplied independently"),
        new("Linux fanotify","PID/PIDFD; enrichment may be incomplete",["open","read notification","write notification"],["Configured masks only","Names supplied separately by inotify","Not remote-client process identity"],"Native operation matrix pending"),
        new("Windows audit 4656/4663","Event-time user, process and PID when supplied; partial detections retained",["handle request","access rights used"],["SACL and audit policy required","Delete right is not final deletion","No copy/encryption proof"],"Missing actor fields remain explicit"),
        new("Windows minifilter prototype","Requestor PID, process creation time, image and effective SID",["open","read","write","rename","delete disposition","permissions","mapping check"],["Prototype","Some kernel contexts provide partial attribution","Production signing and deployment gates pending"],"Prototype; host capability and rollout validation required"),
        new("Linux eBPF prototype","Event-time PID, process start, executable name/inode and UID/EUID/FSUID",["permissions","read","write","rename intent","unlink intent","metadata intent","mapping check"],["Qualified BTF kernels only","Full paths depend on the hook","Kernel workers are not inferred originators"],"Prototype; host capability and rollout validation required"),
        new("macOS FSEvents","None",["content or metadata change","name change"],["No open/read","No user/process identity","Events may be coalesced"],"Native operation matrix pending"),
        new("macOS Endpoint Security","Provider required",[],["Managed native adapter not release-ready","Apple entitlement/signing and permissions required"],"Blocked: provider/native acceptance")
    ];
}
