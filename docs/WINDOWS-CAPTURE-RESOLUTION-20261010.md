## October 11: Windows 10 boot-time syscall source in private qualification

The failed TRACE_ENGINE wrapper experiment was restored completely: fresh administrative authentication/privileges, original absent DTrace installation and boot setting, stopped baseline filter, normal power-off, original 4096 MiB RAM and CPU limit -1, and unchanged nested-virtualization setting. No forced reset or live driver unload was used.

Actual Microsoft binary disassembly confirms that the built-in syscall provider bypasses the wrapped table. A separate BootTrace.c implementation now exports the kernel's boot-time tracing initializer and registers owned syscall entry/return callbacks through the exact kernel context. The Windows 10 kernel SHA and matching Microsoft PDB were independently checked. The private driver compiles with warnings treated as errors. The first runtime test measures callback context and operation identity only; token queries, general target monitoring, actor capture, central transport and deployment remain pending. No production sensor or server changes are made by this test.

Evidence: WINDOWS-DTRACE-CONTEXT-RESTORATION-20261011-R1.json, WINDOWS-KERNEL-DYNAMIC-TRACE-ABI-20261011-R1.json and WINDOWS-KERNEL-DYNAMIC-TRACE-CALLOUT-ABI-20261011-R1.json in diagnostics/windows-token-20260930. Build: boot-trace-context-r1 and boot-trace-context-package-r1 under the existing C: diagnostic root. Plan: docs/WINDOWS-DTRACE-TOKEN-ADAPTER-PLAN.md. Whole-product QA remains pending; no runtime acceptance is claimed.

## October 11: Windows 10 probe-binding failure under repair

The first context-adapter runtime test failed before token collection: the actor received ERROR_NO_MORE_ITEMS (259), and adapter health reported zero bound target probes, zero observed events and zero lost records. The actor and collector exited naturally; retained native evidence is empty. This is a failed qualification, not a pass. The earlier private Server 2019 and Server 2012 R2 nine-case token proofs remain valid; production coverage and central integration remain incomplete.

Provider registration, callback-table size, lookup/create, global/armed fire counts and last armed callback context have been added to the separate private adapter diagnostics. Diagnostic driver/control/native fixture builds compile with warnings treated as errors. No production sensor is updated by these builds. The test launch now uses a transferred, hash-checked script file with an execution-policy override restricted to its PowerShell process. System execution policy is unchanged. The first lab's normal restoration and fresh access validation are in progress with the original session retained.

Evidence: diagnostics/windows-token-20260930/WINDOWS-DTRACE-CONTEXT-FAILURE-20261011-R1.json; immutable dtrace-context-r4, dtrace-control-r2, dtrace-context-native-r3 and dtrace-context-package-r3 outputs under C:/Users/dmessana/AppData/Local/Codex/sequester-windows-syscall-observer-20261011-r1. No full product QA or deployment completion is claimed.

## October 11: both server kernels pass the new failed-operation capture proof

The private Server 2019 (17763.9020) and Server 2012 R2 (9600) guests each passed all nine existing-handle cases. Independent raw-data verification passed on both: six insufficient-rights failures, two byte-lock failures and one successful read, exact PID/TID/process birth, actual NTSTATUS, all owner/effective token fields, unchanged targets and zero lost records. The managed decoder passed 103 checks against each actual raw artifact. Both guests passed fresh restored administrative access, were shut down normally, and had exact original CPU, RAM and nested-virtualization settings restored. No production source is enabled by these tests; the existing production 24-operation gap remains open.

The separate Windows 10 DTrace context adapter and fixture compile reproducibly. Its actual callback IRQL, interrupt state and APC state must pass qualification before token metadata queries are added. This adapter is context-only and has not established token capture, central integration or production compatibility.

Evidence: WINDOWS-SYSCALL-2019-NATIVE-RAW-ACCEPTANCE-20261011-R1.json and WINDOWS-SYSCALL-DC-NATIVE-RAW-ACCEPTANCE-20261011-R1.json under diagnostics/windows-token-20260930; final-restoration.json in each private lab output. Plans: docs/WINDOWS-SYSCALL-OBSERVER-PLAN.md and docs/WINDOWS-DTRACE-TOKEN-ADAPTER-PLAN.md.

## October 11: failed existing-handle operation capture now demonstrated in the private Server 2019 guest

The new pre-filesystem native observer passed nine cases: six insufficient-rights failures, two lock failures, and one successful read. Independently decoded raw records matched actual PID, TID, process birth, SYSTEM process owner and LOCAL SERVICE impersonating-thread identity (SYSTEM in the non-impersonating control), all token fields and actual NTSTATUS, with zero lost records. The managed decoder passed 103 checks against those raw records, including JSON and malformed-input tests. Central source integration and production rollout are NOT complete; production still has 24 missing handle-rights failures across the four hosts. The Intel research driver does not work on the current AMD/Hyper-V desktop. Normal guest cleanup is in progress with the original administrative session retained after a transient VMware Guest Operations error; no forced reset or unload.

Evidence: diagnostics/windows-token-20260930/WINDOWS-SYSCALL-2019-NATIVE-RAW-ACCEPTANCE-20261011-R1.json and docs/WINDOWS-SYSCALL-OBSERVER-PLAN.md. This result does not establish full-specification completion or whole-product regression acceptance.

## October 11 Windows pre-filesystem capture implementation in progress

The four-host existing-handle gap remains 24 unobserved permission failures.
A separate private NtReadFile/NtWriteFile/NtSetInformationFile observer now builds
and links. It uses the sensor token layout/helper, actual file-object references,
PID/birth/TID, owner/effective token evidence, native result and ordered records.
It rejects recycled handles and has a bounded 128-record queue with loss counters.

The guest entry bridge passed 3,000 argument/status/nonvolatile-register checks.
The first-instruction relocation check admitted all 12 actual on-disk Nt exports
across the four hosts. Neither result is a VM-exit or filesystem-capture pass.
The observer pins pageable source code pages and counts callbacks in VM-exit
before redirect, with return routed directly to the original caller before the
count is decremented. Startup failure disables redirects and drains before VMX
shutdown. Dynamic unload remains unqualified and disabled in the private build.

Production hardware admission is mixed: storage exposes Intel VMX; NVR/DC are
VMware guests without VMX exposed; the desktop is AMD with Hyper-V active and no
SVM exposed. The Intel backend is not a solution for the desktop. A separate
compatible source is still required there. No production hypervisor was loaded.

A single zero-NIC Server 2019 VMware qualification is in progress, with nested
virtualization, a 1000 MHz CPU limit, retained original administrative access and
fresh protected-device/restoration gates. The test captures raw observed tokens
alongside independent token truth for nine existing-handle cases. Native capture,
VM-exit return, resource cost, broader lifecycle and central integration are pending.
Current package is an initial experiment, not a production completion claim.

Artifacts: diagnostics/windows-token-20260930/WINDOWS-SYSCALL-PROLOGUE-ADMISSION-20261011-R1.json;
WINDOWS-SYSCALL-CPU-{Desktop,NVR,Storage,DC}-20261011-R*.json;
WINDOWS-SYSCALL-VMWARE-ADMISSION-20261011-R1.json.
Builds: C:/Users/dmessana/AppData/Local/Codex/sequester-windows-syscall-observer-20261011-r1,
observer-r9, native-r3, bridge-abi-r1 and lab-package-r1. C: is used because D:
has insufficient free space. Original failed build receipts remain retained.

## October 11 final Windows deployment and failed-handle qualification

All four Windows hosts run sensor 0.6.26 and the full deferred-token driver.
Server 0.6.45 is deployed. The production 15-case matrix passed on every host:
60 cases and 64 independently downloaded, hash-verified actor/manifest pairs.
Fresh authenticated host health samples after restoration passed on all four.
Private qualification of actual APC callbacks remains a separate 132-case gate.

A fresh nine-case existing-handle matrix ran on each host: 36 cases total.
All nine opens per host succeeded. The normal read and byte-range-lock denied
read/write controls were captured; all 12 controls passed central PID/birth,
thread, owner/effective-token and independently downloaded actor/manifest checks.
The six insufficient-handle-rights operations per host still had no corresponding
operation record: 24 unobserved failed operations. Their successful CREATE records
are not substituted for the later failed operation or its impersonated identity.
These failures are rejected before filesystem dispatch. The all-failed-operations
coverage result is explicitly FALSE in the native and central aggregate receipts.

Receipts (workspace diagnostics/windows-token-20260930):
- WINDOWS-DEFERRED-FOUR-HOST-PRODUCTION-ACCEPTANCE-20261011-R1.json
- WINDOWS-DEFERRED-FOUR-HOST-HANDLE-BOUNDARY-NATIVE-20261011-R1.json
- WINDOWS-DEFERRED-FOUR-HOST-HANDLE-BOUNDARY-CENTRAL-20261011-R1.json
- WINDOWS-DEFERRED-FOUR-HOST-FINAL-HEALTH-20261011-R1.json

The first two desktop boundary attempts used packages lacking some requested
commands and failed explicitly; original settings were restored both times.
The successful repeat used the previously qualified lock/denied-handle package,
including every manifest file, not just its common managed executable launcher.
The first boundary central verifier expected zero transfer bytes on failed I/O.
The source deliberately reports null because the result is unavailable. Corrected
verification preserves that null and separately validates native failure status.
Historical failures remain retained; they are not rewritten as passes.

No administrative ACL, credential or management firewall changes accompanied
this rollout or qualification. No native test process was forcibly terminated.
The 24 pre-filesystem failures still need an independent syscall capture source.
Kernel-Audit-API-Calls templates on these four actual hosts contain no file handle
or effective token data; classic syscall ETW also lacks those arguments. DTrace
has an isolated Windows 10 proof, not a complete token/central integration, and
its available installer does not admit the older Server kernels. This work does
not establish complete denied-operation coverage, immutable historical token
metadata, all unsupported callback contexts, or the entire forensic specification.

## October 11 four-host Windows production acceptance

Server 0.6.45 and sensor 0.6.26 with driver SHA-256
82B79CC6BD79D53AA07C1E3D14FB6B8EAE8354D748427F5B39E4C963EFFD5373
are deployed to the Windows desktop, NVR, storage server and domain controller.
All four hosts passed the 15-case native and central operation matrix: 60 cases,
64 independently downloaded actor executable/manifest pairs, verified hashes,
event/process linkage, process birth, PID, TID, user and token fields. Exact test
settings were restored. Fresh service/driver/capability samples passed on all four.

NVR central verifier R1 timed out while an artifact was not yet uploaded.
Its received receipt was committed after the timeout; R2 independently downloaded
and verified every expected artifact. The original failure receipt is retained.
This was transfer latency, not a reason to accept missing central evidence.

Receipt: diagnostics/windows-token-20260930/
WINDOWS-DEFERRED-FOUR-HOST-PRODUCTION-ACCEPTANCE-20261011-R1.json.
The matrix includes denied OPEN cases. Failed operations on already-open handles
remain a separate qualification. A fresh bounded repeat is in progress; its first
attempt used an older managed fixture without those commands, failed explicitly,
restored settings and retained its receipt. The repeat now binds to the previously
qualified denied-handle package and verifies every package file against its manifest.

Read-only inspection of the actual Kernel-Audit-API-Calls provider on all four
hosts found eight event templates, none carrying file/handle or effective-token
fields. This is schema evidence, not a runtime trace or complete absence proof.
The 24 pre-filesystem insufficient-rights failures remain unresolved. Mutable
historical token fields, queue saturation and unsupported contexts remain explicit
limitations; no entire-specification completion is claimed.

## October 11 production integration checkpoint: NVR acceptance in progress

Server 0.6.45 and all four Windows sensor packages 0.6.26 are installed.
Windows 10 production passed 15 independently validated file-operation cases.
The management server matched the expected user, process, PID, birth time,
thread and token fields, and independently downloaded and verified 16 preserved
actor executable/manifest pairs. This matrix includes six denied OPEN cases;
it does not close failed later operations on insufficient-rights handles.
The NVR now runs the same qualified full driver; its live matrix is in progress.
Storage and domain-controller driver activation remain pending acceptance.
The published sensor DLL also passed decoding/JSON/queue restart for all 33
full-driver Windows 10 APC fixture records. Separate process-owner and effective
thread identities remain labeled by collection timing.

The 24 operations rejected before filesystem dispatch remain unresolved.
Retaining the accessing thread's impersonation token does not freeze mutable
metadata into a historical snapshot. Queue saturation, unsupported callback
contexts and broader Linux/specification tasks are still open. No claim of
complete deployment acceptance or complete specification is made here.
No administrative ACL, credential or management firewall changes were made.

## October 11 Windows integration checkpoint

Windows 10 and Windows 11 callback lab r12 each passed 96 actual reads,
including 32 Filter Manager generated APC-entry callbacks. Their test drivers
were normally removed, separate fresh administrative checks passed, and the
original VM resources were restored. The earlier Win10 sleeping-guest recovery
is complete; its VM is off with original CPU allocation and 4096 MiB restored.

Server 2019 r12 passed 64 ordinary/control reads but failed the generated read
check. Its probes were normally removed and fresh access/resource restoration
passed. A corrected fixture flushes its owned preparation write before the
noncached read and emits all failed reply fields. Rerun r14 is in progress.

A private, feature-gated sensor integration now compiles: bounded PASSIVE
worker, entry-referenced impersonation token, separately labeled later primary
and image queries, additive command 45, and orderly worker draining. The new
native fixture and reproducible frozen-source builder compile. Native integrated
qualification, managed decoding/ingestion and deployment remain pending.
The 24 missing production insufficient-rights failures remain unresolved.

# Windows capture resolution investigation

## Completed experiments

An isolated Microsoft Detours observer now captures normal calls to NtReadFile,
NtWriteFile and NtSetInformationFile that fail before the minifilter observes an
operation. The pinned r6 package was tested on all four current Windows hosts:

| Evidence | Measured result |
| --- | --- |
| Failed read/write/append/truncate/rename/delete and locked read/write | 32/32 API observations matched actor truth |
| PID plus process birth and actual TID | Matched in every positive case |
| SYSTEM primary versus LOCAL SERVICE impersonation token | All compared token fields matched |
| Normal native denied-read controls | 4/4 observed |
| Direct-system-call denied-read controls | 0/4 observed; native failure confirmed |
| Production settings, services, ACLs and credentials changed | None |
| Final deployed agent/minifilter health | Four running; zero pending uploads |

The initial prototype could query the effective token but could not open its
SYSTEM process token while impersonating LOCAL SERVICE. The documented
[GetCurrentProcessToken query-only pseudo-handle](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-getcurrentprocesstoken)
resolved that problem on every tested Windows version. No impersonation was
temporarily removed and no access control was weakened.

This is **supplemental in-process evidence**, not a complete or protected sensor
source. The direct-call controls prove a bypass. Equal token statistics before
and after a call do not prove an atomic snapshot of every authorization step.
Logs remain private QA JSONL; no production server ingestion, trust suppression
or executable preservation is attributed to this prototype.

See the [source and reproduction instructions](../tools/WindowsApiObserverPrototype/README.md)
and [four-host receipt](../../../diagnostics/windows-token-20260930/WINDOWS-API-OBSERVER-ACCEPTANCE-20261010-R1.json).
The r7 allocation-order and provenance improvements now passed the same eight
positive and two control cases on all four hosts. Independent final service,
version, hash and filter-route checks passed on all four. These current-build
receipts are separate from the historical r6 acceptance. The r7 direct-call
controls still demonstrate four bypasses; no production integration is claimed.

## APC-level token investigation

There is a concrete contract discrepancy: the admitted WDK 10.0.26100.0 ntifs.h
declares PsReferenceImpersonationToken with `_IRQL_requires_max_(APC_LEVEL)`,
but [Microsoft Learn specifies PASSIVE_LEVEL](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-psreferenceimpersonationtoken).
The same header declares primary-token reference and token dereference at
PASSIVE_LEVEL. [Token information querying is documented at PASSIVE_LEVEL](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-sequeryinformationtoken).

A separate APC token-reference probe compiled with /kernel /W4 /WX. Its source
and WDK header hashes are recorded. It performs no token query at APC and does
not assert a historical full-token snapshot. It is not linked into the deployed
driver and has no runtime qualification. A held token object controls lifetime,
not mutation of privileges/groups or ModifiedId. A NULL callback thread supplies
no accessing thread whose historical token can be reconstructed.
That initial preflight was followed by a separate secured lab device and owned
SYSTEM fixture. On Windows 11 26300.9457 and Windows 10 19045.6456, each of 64
APC-level references retained the independently identified LOCAL SERVICE token
after RevertToSelf. Queries and release ran at PASSIVE_LEVEL. Both platforms also
passed mutable-token, no-impersonation, short-buffer and cleanup controls. The
mutation control deliberately changed a duplicated token after reference; the
later query observed its changed ModifiedId. This confirms lifetime retention,
and demonstrates why later mutable fields are not historical snapshots.

Separate fresh administrative guest sessions opened the protected device before
testing. The probes were normally unloaded, baseline minifilters remained
stopped, VMs were normally shut down and exact CPU allocation was restored. No
production collector was replaced. Server 2019 17763.9020 and Server 2012 R2
build 9600 also passed 64 cases each and the controls, bringing the native
total to 256. Each probe was unloaded, its baseline filter state preserved,
and the VM normally shut down with exact CPU allocation restored. The Server
2012 R2 baseline filter was preserved in its recorded state; it was not forced
to stop to make the probe pass.
The WDK/Learn contract discrepancy remains unresolved; manual APC-level IOCTL
qualification is not actual filesystem-callback qualification or Driver Verifier
qualification for this separate device.

Qualification transport repairs: normalize vCenter-supplied PEM certificates to
DER before hashing, select Windows guest file attributes, use Stop-VMGuest for
normal shutdown, and restore unlimited CPU through the vSphere configuration
API. Early helper failures are retained, including their recovery-lifecycle
defects; they are not acceptance passes. The current direct runner retains its
command host on recovery and catches failed recovery commands.

## Kernel syscall source investigation

Microsoft's [DTrace syscall provider](https://learn.microsoft.com/en-us/windows-hardware/drivers/devtest/dtrace)
offers entry arguments and return status, unlike classic syscall ETW. Its
[file-operation example](https://learn.microsoft.com/en-us/windows-hardware/drivers/devtest/dtrace-programming)
demonstrates syscall arguments. This is a candidate for failures that do not
reach the minifilter, including direct calls; it is not yet a validated source.

The official 2.0 installer was downloaded and its Microsoft signature verified.
The [installer requirements](https://www.microsoft.com/en-us/download/details.aspx?id=100441)
specify Windows 10 build 19040 or later. The current Server 2012 R2 and Server
2019 kernels are below that minimum. Do not install this package on them or claim
that the broad documentation applicability banner establishes compatibility.

A new owned barrier fixture and PID-scoped, finite DTrace script are prepared
for normal and direct denied-read comparisons. They include independent handle,
PID, TID, process birth and status truth. The official installer is now being
qualified in the isolated Windows 10 lab with its original boot setting recorded,
separate fresh administrative access checks and an owned cleanup path. No
production DTrace installation has occurred. Runtime collection, full thread-token
collection, asynchronous completion and server ingestion remain unqualified.
No DTrace built-in Windows UID is assumed: the inspected Microsoft source
excludes the UID/GID implementation under _WIN32. The new script invents no SID.

## Work required before production integration

The new CallbackTokenLab source and reproducible build exercise a real READ
minifilter callback for one explicitly armed, owned thread. Native callback
IRQL is recorded separately from an optional artificially raised APC control.
The query occurs later at PASSIVE through the secured device. Its build is
complete; native qualification is still pending. It neither supplies arbitrary
thread access nor replaces the production collector. Deferred token metadata
must remain clearly labeled as later observation, even if identity matches.

1. Resolve the APC reference contract discrepancy and qualify token-reference
   lifetime, deferred release, token changes and actual callback contexts on the
   supported kernels before modifying the driver. Preserve the distinction
   between entry-time reference and later metadata observation.
2. Establish an independent source for direct calls rejected before filesystem
   dispatch. The public syscall ETW schema supplies routine address and status,
   but not the operation's file handle/arguments or security token. It cannot
   fill these fields by itself. No complete supported source has been established.
3. If the supplemental API path is integrated, use authenticated process-instance
   transport, explicit source authority, schema validation and visible collection
   failure states. Its records must not authorize whitelist suppression or
   impersonate kernel observations. Link actor executable preservation through
   independently verified identity.
4. Qualify asynchronous final completion, WOW64, protected-process exclusions,
   token mutation, safe lifetime and bounded high-volume performance. The current
   synchronous logger is a proof mechanism, not a production transport.

New Manus research was submitted, but the API returned `quota_limit`; no new
Manus answer was obtained. Investigation proceeded using primary Microsoft
sources, the actual SDK/WDK inputs and controlled native experiments.

**The full capture requirement remains open.** The prototype establishes a
useful additional path and a measured bypass; it does not close the original
24 missing deployed failure events or universally unavailable callback contexts.
