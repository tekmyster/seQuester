# Windows system-call capture for operations rejected before filesystem dispatch

## Evidence and scope

The October 11 production repeat ran nine operations on each of four Windows
hosts. All opens succeeded. The normal read and byte-range-lock denied read/write
controls reached the minifilter and passed central attribution and preservation
checks. Six insufficient-handle-rights operations per host did not reach it.
Successful CREATE records do not establish attribution for these later failures.
The gap is 24 operations, not a reporting delay.

The existing Kernel-Audit-API-Calls templates on the actual four kernels do not
provide the file handle and effective token needed for this correlation. Classic
system-call ETW lacks the arguments. A Windows 10 DTrace experiment captured the
failures, but the available installer does not admit the older server kernels.

## Implementation plan

1. `tools/WindowsSyscallObserver/Admission.cpp` and its immutable build script:
   collect actual processor/virtualization evidence without installing a driver.
   Record CPUID leaves, OS build, and explicit runtime qualification = false.
   Inspect actual kernel exports and first instructions on every host. Export
   presence alone is not compatibility evidence.
2. A separate research driver, initially restricted to an owned process/thread
   and already-open file objects, will observe actual `NtReadFile`, `NtWriteFile`
   and `NtSetInformationFile` entry/return. It must preserve original results.
   Do not intercept `Zw*` wrappers using ordinary C calling conventions.
3. Reuse the sensor's token evidence layout and documented token-query APIs.
   Capture owner and effective accessing-thread identity separately at entry,
   including PID/birth/TID, token IDs, SID, impersonation state and collection
   status. Compare token modification markers around queries. A changed marker
   is incomplete evidence, not a successful immutable snapshot.
4. Record operation, handle/file-object linkage, requested length/offset when
   safely readable, raw returned NTSTATUS, sequence, UTC and monotonic values.
   STATUS_PENDING is submission status, not fabricated completion or byte count.
   Unsupported IRQL/context and unreadable parameters remain explicit failures.
5. Reuse actor executable hashing, stable identity, preservation and central
   upload after the native source is qualified. Do not hash/copy target files.
   A token-only prototype is not full forensic integration.
6. Add a versioned additive source contract only after raw native evidence passes.
   Keep observation, attribution, detection and response separate. Do not label
   successful minifilter CREATE observations as failed later operations.

## Research dependency assessment

The pinned MIT-licensed DdiMon/HyperPlatform research source is under evaluation:
DdiMon b6999c888f11bea37c0a40ab34ea8310e47e4c31;
HyperPlatform d52a42d7365cb07a1e5703f038f7304e65fae780;
Capstone 512cc96485c6e1fd9cb425d7047beb905544c00f.

Its default process-hiding and PatchGuard demonstration handlers are excluded
from the proposed observer. The original trampoline copies instructions without
relocation; reject RIP-relative and relative-control-flow instructions unless
proper relocation is implemented and tested. A one-second unload sleep is not
callback rundown. Do not reuse that lifetime policy for production.

Intel VT-x/EPT, nested virtualization under VMware, VBS/Hyper-V coexistence,
actual prologues, hotplug/power transitions, page changes, resource cost and safe
lifetime must be qualified. The research source's old OS guard is not proof of
support on current kernels. A research candidate has now been loaded in the
isolated Server 2019 guest only; no production host has this source.

## October 11 native qualification result

Candidate observer-r9 and native-r3 passed all nine existing-handle cases on
17763.9020. The guest kernel hash matches the production Server 2019 hosts.
Six insufficient-rights failures returned C0000022; both byte-range lock
failures returned C0000054; the normal read returned zero. Independent native
token truth and separately decoded raw records matched PID, TID, process birth,
SYSTEM owner, LOCAL SERVICE effective identity in the eight impersonating cases,
and SYSTEM effective identity in the non-impersonating control. All token masks
were 31; no records were lost. The saved 6264-byte nine-pair raw artifact hashes
to 2f6457c2381442c5016585a07d4e2ef92915d80784ec71c3bf004f7233529ab0.

The additive WindowsSyscallEvidence contract and WindowsSyscallDecoder decode
the actual 408-byte records, retaining native status, ordering, PID/birth/TID,
owner/effective snapshots and raw SHA-256. The focused managed test passed 103
checks, including actual native truth, JSON round trips, PID-reuse separation,
pending status, malformed records and explicit unavailable byte counts/frequency.
These classes do not enable a production event source or central trust matching.

The first normal cleanup attempt encountered VMware Guest Operations error 3016
during reboot. The original administrative session was retained. The guest
subsequently reported a new boot generation and running VMware Tools. Cleanup
is being retried with fresh authentication and exact resource restoration gates.
No forced reset, shutdown, or live driver unload was used. Both restoration gates
subsequently passed: fresh authenticated administrative access, experimental
service absent, original filter state, normal shutdown, and exact resource values.

The same immutable candidate and native fixture subsequently passed all nine
cases on the private Server 2012 R2 guest, whose kernel SHA-256 matches the
production domain controller. Independent raw-data verification passed; the
6264-byte raw file hashes to
d66d1d0acbc2420ac30788af661e5f8f1b307a6315f7ac9d144beb9ca7ce72b1.
The managed decoder passed the same 103 checks on these actual records. Fresh
access, normal shutdown and exact original resource restoration also passed.

Production's 24 missing handle-rights failures remain an open deployment gap.
The research candidate is owned-thread scoped, lacks full actor/target evidence
integration, and has not passed lifecycle, load, direct-syscall, handle-reuse or
other-kernel qualification. The actual desktop is AMD with active Hyper-V and
unavailable SVM; it cannot use this Intel backend. DTrace is being investigated
as a separate compatible source, without claiming its standalone public-source
stubs supply the kernel trace engine or event-time token evidence.

## Acceptance before rollout

Use an isolated VMware guest, one at a time, with exact baseline/resource
restoration and retained administrative sessions for access changes. Test each
of the six handle-rights failures, both lock failures, normal success controls,
direct system calls, impersonation changes, PID/handle reuse and process exit.
Compare independent native truth against captured return status and entry token.
Measure event loss, bounded queues, CPU/RAM cost and lifecycle behavior. Then
verify the authenticated central API and independently downloaded actor/manifest
hashes. Expand to each actual supported Windows kernel only after those gates.

Sources: https://github.com/tandasat/DdiMon and
https://tandasat.github.io/HyperPlatform/userdocument/ .
