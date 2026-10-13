## Linux exact write/append deployment completed - 2026-10-10 13:21 UTC

All 26 Linux sensors passed installed acceptance for exact synchronous write/append
classification and immediate first-use actor executable capture. Acceptance R10
records 364 cases (seven operations under UID 0 and UID 1000 per sensor), 1,456
linked server events, and 364 authenticated executable/manifest download pairs.
The matrix covers write, append, pwrite, writev, appendv, pwritev and
pwritev2 RWF_APPEND. Returned bytes, offset/append flags, PID plus process birth,
UID/EUID/FSUID, actor inode and SHA-256 were checked. Actors exit and unlink
immediately; preserved bytes were verified locally and after server download.
The exact HWE qualification also delayed source admission by 12 seconds without
a pre-operation delay. All sensors passed a normal source stop/restart and final
live readiness; historical evidence remained intact across restart.

NetBox, XWiki, Plex and MySQL now use the separately qualified Ubuntu 22.04
6.8.0-138 HWE kernel/profile. Exact kernel/BTF, existing services/application
ports, fresh root SSH from 10.81.100.20, old-kernel retention and future boot
default were verified individually. Existing security modules were retained.
Plex retains all six existing monitored files; its original three-target preparation
assertion failure is retained and the corrected preparation passed. Plex service
and port are healthy, but its separate media mount reports CIFS BAD_NETWORK_NAME
for //10.81.60.190/media/media. The CIFS driver is present and loaded. No share,
path or credential change was made; media availability is not asserted.
Their 0.9.43 package contains a protected private libbpf; the native service sets
its library path explicitly. NetBox's original startup failure and all prior
qualification failures remain recorded. Audit migration intervals and rejection
counters are recorded; migration was not asserted to be lossless. No management
ACL, credential or firewall change was made for this rollout.

Qualified bounds remain explicit: four actor leases and a 4 MiB actor-copy limit;
quota/size/collection failures report unavailable evidence. mmap, io_uring,
splice and copy_file_range are not qualified by these synchronous hooks. This
work does not qualify Windows, rerun all 14 canary file types, enable controlled-v4
hash whitelist eligibility, or deploy Wazuh forwarding/active response.
Actor executables are hashed and preserved; target files are not hashed or copied
by default. This acceptance closes these bounded Linux deployment features,
not every requirement in the broader forensic specification.

## Linux deployment checkpoint - 2026-10-10 13:11 UTC

25 of 26 Linux sensors passed deployed operation, central evidence, normal restart
and readiness checks: 350 operation cases, 1,400 linked server events and 350
authenticated evidence pairs (acceptance R8). XWiki and Plex are complete. Plex
retains all six active monitored files; the original three-target assertion
failure is retained and corrected preparation R2 passed. Its separate CIFS
media mount returns BAD_NETWORK_NAME; the CIFS driver is loaded, Plex service
and port are healthy, and no share or credential change was made. MySQL passed
fresh root SSH, exact HWE boot and service/port checks; sensor deployment and
acceptance are in progress. The 4 MiB/four-lease and synchronous-hook bounds
remain unchanged.

## Linux deployment checkpoint - 2026-10-10 12:41 UTC

Verified deployment is now 23 of 26 Linux sensors: 322 operation cases, 1,288 linked central events and 322 authenticated executable/manifest download pairs (acceptance R6). NetBox passed the exact HWE kernel/BTF boot, fresh root SSH session from 10.81.100.20, unchanged application services/containers, installed 14-case matrix, central evidence verification, normal stop/restart, kernel-default commit and final live readiness. The original DllNotFoundException startup record remains retained; the managed companion now uses its protected, hash-checked private libbpf library via a service dropin. The new HWE profile passed isolated qualification R5, 142 definition checks and 39 packaged runtime checks. XWiki is in its guarded trial boot; Plex and MySQL remain on their old running kernels. The old kernels/releases and evidence are retained.

## Linux HWE qualification checkpoint - 2026-10-10 12:05 UTC

Owned-VM attempt R4 did not reach native qualification: Ubuntu linux-modules-extra required wireless-regdb, absent in the Debian-based lab. Its failure and normal baseline/resource restoration are retained. The dependency was verified against Ubuntu APT SHA-256 metadata and supplied only to the isolated lab for R5. All four production hosts already have it installed (boot-prerequisite receipt R1); their current kernels and monitoring services remain unchanged. The NetBox-built, SHA-verified seven-operation test actor is staged on all four hosts without execution. Qualification and installed acceptance remain pending; verified deployment is still 22 of 26. Actor-build receipt R2 corrects the inherited ReadOnly flag in R1 and retains the original record.

## Linux deployment checkpoint - 2026-10-10 11:42 UTC

Exact write/append and immediate first-use actor capture remain verified on 22 of 26 Linux sensors (acceptance R5: 308 cases, 1,232 linked server events, 308 authenticated executable/manifest download pairs). The four Ubuntu 5.15 hosts remain unchanged. Their five frozen HWE kernel packages are staged only. The owned VMware qualification attempt R3 ended on a guest-command transport failure before native tests; normal shutdown and baseline/resource restoration succeeded. R4 now retries read-only progress collection across transient guest-agent failures. No HWE native qualification or production kernel boot has passed yet. The corrected library inventory R2 passed on all four hosts and confirms private libbpf.so.1 is required; the original R1 inventory failed and remains retained.

## Linux exact I/O checkpoint - 2026-10-10 10:52 UTC

22 of 26 Linux sensors are deployed and verified for the seven synchronous
write/append variants and first-use actor capture. FreePBX Linux 6.1 passed
14 installed root/non-root cases, 56 linked central events, 14 authenticated
binary/manifest downloads, normal rotating restart and final live readiness.
Combined: 308 operation cases, 1,232 central events, 308 artifact pairs.
Receipt: LINUX-IO-DEPLOYMENT-ACCEPTANCE-20261010-R5.json.

Only MySQL, NetBox, Plex and XWiki remain unqualified on Linux 5.15. The Ubuntu
22.04 HWE 6.8.138 candidate compiled against its authenticated extracted BTF;
isolated VMware runtime qualification is in progress. No production kernel has
been migrated. Four leases, the 4 MiB actor limit and unqualified asynchronous
I/O paths remain explicit limitations; this does not close the full spec.

## Linux exact I/O deployment checkpoint - 2026-10-10 10:39 UTC

21 of 26 Linux sensors now passed installed write/append and first-use actor
executable capture, central evidence verification, and fresh readiness checks.
The newly installed OpenRADIUS Witness (6.12.95) and Wazuh Manager (6.12.86)
each passed 14 root/non-root operation cases, 56 linked central events and 14
authenticated binary/manifest download pairs, plus normal rotating restart.
Combined deployment evidence: 294 cases, 1,176 central events, 294 artifact pairs.
Receipt: LINUX-IO-DEPLOYMENT-ACCEPTANCE-20261010-R4.json.

The isolated VMware Linux 6.1 candidate passed 14 operation cases and 35 physical
actor copies after immediate exit/unlink, including delayed START processing.
Zero observed loss, normal module removal, guest shutdown and baseline restore
passed (LINUX-IO-EXACT-KERNEL-61-RUNTIME-20261010-R4.json). Its exact profile is
admitted in source; the 134-check definition fixture and managed build passed.
FreePBX installed/central acceptance remains pending. Four Ubuntu 22.04 sensors
remain on 5.15; authenticated HWE 6.8.138 kernel inputs were privately extracted,
with no production installation or boot change.

The historical Debian build issue was static kfunc filter IDs compared against
relocated IDs from .BTF.base. Exact-BTF builds without MODULE_PAHOLE_FLAGS fixed
this candidate defect; runtime filtering was retained. The 6.1 verifier failure
was spin locks in sleepable task_alloc; only the explicit 6.1 candidate now uses
the bounded non-sleepable task hook. All failed attempts remain recorded.

Scope remains seven synchronous write/append variants, root and UID1000, four
leases and a 4 MiB actor limit. mmap/io_uring/splice/copy_file_range are outside
these qualified hooks; unavailable evidence remains explicit. This is not full
specification or all-sensor completion. Windows is unchanged in this scope.

## Linux exact I/O deployment checkpoint - 2026-10-10 09:25 UTC

19 of 26 Linux sensors have the new exact write/append and retained first-use actor executable capture implementation deployed and qualified. Final read-only readiness passed on all 19. End-to-end tests cover 266 cases (write, append, pwrite, writev, appendv, pwritev, pwritev2 RWF_APPEND under UID 0 and 1000), 1064 linked server events, and 266 authenticated executable/manifest download pairs. Test actors exit and unlink immediately; captured executable bytes match the expected SHA-256. These are operation cases, not canary file types.

Debian 6.12.94 and Ubuntu 6.8.0-134 are qualified. OpenConnect and PlexContainer now have BPF enabled in their boot LSM lists; prior LSMs were preserved and authenticated root recovery, prior services/containers, operation capture, central evidence, and normal source close/recovery/restart were checked. Management credentials and firewall rules were not changed.

Deployment remains incomplete on freepbx01, mysql01, netbox01, openradius-witness01, plex01, wazuhman01, and xwiki01. FreePBX's compile-only attempt exposed actual Linux 6.1 API differences (kfunc annotations, executable-reference API, inode mtime accessor, and missing program-type filter). A distinct compatibility candidate is in progress; it is not a runtime pass. No remaining host has been admitted using an unqualified profile.

Limits: capture remains bounded to four actor leases and 4 MiB per actor, with explicit failure states; mmap, io_uring, splice, and copy_file_range are outside this tested operation scope. This checkpoint does not establish complete specification, Windows, Wazuh, or whole-product acceptance.

Evidence: diagnostics/windows-token-20260930/LINUX-IO-DEPLOYMENT-ACCEPTANCE-20261010-R2.json and LINUX-IO-QUALIFIED-SENSORS-20261010-R2.json. Earlier failed attempts and receipts are retained.

## Linux exact I/O rollout checkpoint - 2026-10-10 08:10 UTC

Deployment is still in progress. Ops, backup01, scanopy_trusted01, scanopy_dmz01, scanopy_iot01 and scanopy_wireless01 have passed fresh installed and central qualification. Each sensor passed 14 root/non-root scalar, positioned, vector and append/RWF_APPEND cases, 276 contiguous indexed raw records across rotation, 56 linked server events and 14 authenticated executable/manifest download pairs. Executable SHA-256, size, process birth, PID, UID/EUID/FSUID and exact entry/return operation details were checked. Ops also passed normal close, retained-history recovery and restart. NGINX has passed activation and installed tests; its central checks remain in progress.

Ubuntu 6.8.0-134-generic now has its separately built and qualified manifest-5 native bundle. Native qualification passed 14 operation cases, 70 observations and 35 hash-matching executable captures, including immediate process exit/path deletion and a deliberately delayed first START. Collection loss was zero and all hooks/module closed normally. Managed package R17 passed 39 packaged runtime checks and 110 native profile-definition checks. Activation on www-legacy passed, retaining all existing raw evidence; installed/server qualification is pending. Qualification used the identical precompiled test actor because that production host has no compiler. VMware compilation clone was shut down normally and restored to its original baseline.

The NGINX activation initially stopped on a retained historical LOADER_LOSS_SAMPLE_FAILED source. Its exact directory/session/count/error and complete physical closure were verified before a narrowly scoped migration guard was added. Unexpected errors still reject migration; no failed evidence was deleted. This does not establish the old fault's cause. Current collection failures retain all six individual kernel health counters.

Limits remain explicit: nine older kernel/container profiles have not qualified these features. mmap, io_uring, splice and copy_file_range are outside the current tested hook set. Actor capture is bounded to 4 MiB/four concurrent leases; unavailable collection remains visible. Target files are not hashed or preserved by default. A successful package/activation receipt alone is not a completed deployment. See diagnostics deployment checkpoint R5 and each sensor's installed/central receipts for current results.

## Linux write/append deployment checkpoint — 2026-10-10, package R16

Ops01 is running managed build R17 with the exact watch-first native artifacts under manifest 5 / control 4 / native schema 8. Fourteen installed root/non-root write, append, positioned and vector cases passed, including immediate actor exit/path deletion and exact executable SHA-256/copy verification. One continuous native PID indexed 276 ordered records across a rotation. Central verification passed 56 linked events and 14 authenticated executable/manifest download pairs. Normal restart/recovery passed. Evidence: LINUX-IO-INSTALLED-OPS-PRESSURE-20261010-R10, LINUX-IO-INSTALLED-CENTRAL-20261010-R6, LINUX-IO-ROTATING-RESTART-20261010-R3, and LINUX-IO-OPS-NATIVE-PROFILE-COMPLETE-20261010-R1.

The earlier R15 package retained old trust pins and failed startup; its failure receipts remain preserved. The corrected manifest 5 explicitly binds the new module/loader/BPF hashes without changing legacy manifest 4. Definition tests passed 104 checks, including mixed-bundle and protocol/platform substitutions. Six individual kernel collection counters are now retained in terminal failure metadata. Previous backup01 loss is not retrospectively assigned a cause. Other sensors must pass fresh installed and central qualification before deployment is considered complete; older kernel profiles remain unqualified for these new operations. No target-file hashing or copying was enabled by default.


## Wider Linux I/O gate - 2026-10-10: stopped on backup01

All fifteen matching Debian packages staged successfully. Only backup01 was activated before the wider rollout stopped. All fourteen immediate-exit operation/actor-copy cases passed there, but the continuity gate failed and a later check confirmed LOADER_LOSS_CHANGED and normal fault closure at 276 raw records. This is NOT a passing installed qualification. The collector retained all records and completed stopped recovery. Ops remains separately qualified by R9/central R5/restart R2; the other fourteen hosts retain their old active selectors. A read-only six-counter observer is investigating the native loss before any further activation.

## Linux I/O current installed acceptance - 2026-10-10

Corrected managed R15 / package R13 is installed on Ops. LINUX-IO-INSTALLED-OPS-PRESSURE-20261010-R9 passed all fourteen root/UID1000 scalar/vector/positioned/append cases, immediate-exit/path-removal executable capture, hash-verified private preservation and post-rotation same-instance health. Its source contains 276 contiguous indexed records across one rotation. LINUX-IO-INSTALLED-CENTRAL-20261010-R5 independently verified 56 linked production events and fourteen authenticated binary/manifest pairs. The preceding R8 failure is retained below; these fresh gates qualify its dispatch-order correction on Ops. Restart recovery and wider activation are next. Other kernel profiles and asynchronous/mmap paths are not qualified by these receipts.

## Linux I/O deployment check - 2026-10-10 (current)

The final Ops installed test R8 failed after six successful cases: source dispatch stopped with InvalidDataException before the next completion. Do not treat R7's earlier 28-case pass as proof of final R12 package consistency. Retained source closed normally with all raw records recovered, no pending delivery and no unindexed records; disk had 88 GiB available. Wider activation remains held.

LinuxDeferredWork now snapshots append-only raw entries after the canonical SQL query. The old ordering could select a newly indexed canonical row absent from the earlier bank snapshot and stop dispatch. A regression inserts raw/indexed events between verification and query. Linux fixture LINUX-DEFERRED-RACE-FIXTURE-20261010-R1 passed 48 deferred-work checks and 79 rotation checks. Managed build R15 / package R13 carries this correction; installed and central acceptance remain pending.
# Linux operation capture: current evidence and integration gates

Latest acceptance: installed Ops pressure R7 passed 28 cases and 528 ordered records across two rotations, with the original native PID still healthy after final restoration. Central R3 independently verified 112 events and 28 exact binary/manifest downloads. Restart R1 verified normal closure, unchanged rotated history and a fresh ready native instance. These are package R10 / managed R12 proofs. Final package R12 / managed R14 corrects emergency receipt locking/versioning and passed 404 Linux fixture checks plus 39 packaged runtime checks; its fresh installed gate remains pending. Wider servers remain on their original services.


## Current installed and rotation gate (2026-10-10)

Ops installed pressure R6 verified all fourteen root/UID1000 write/append operations and immediate-exit executable captures. Production central R2 verified 56 exact events and fourteen downloaded executable/manifest pairs. A later health check found that the source exhausted its 256-record bank and closed. Those operation results are valid, but they do not establish sustained collection or wider deployment.

The correction uses version-4 raw segments under the same live source, collector, epoch and monotonically increasing receipt sequence. Before advancing, the predecessor is sealed, the next physically allocated bank is linked by an immutable receipt containing its file identity and the predecessor seal hash. Read-only recovery verifies the whole chain and terminal aggregate seal. Journal schema 13 admits this explicit format while retaining version-2/3 history. No native reload occurs during rotation. Existing retained banks and stranded allocations count toward the configured quota; storage exhaustion remains an explicit failure, never silent eviction.

Candidate checks: Linux rotation fixture R1 passed 76 checks (ordering, SQL indexing, exact replay, tamper/missing-receipt rejection and quota failure), and legacy physical preparation passed 20 checks. Managed R12 builds from unchanged sources. Exact packaged and installed stress/continuity acceptance must pass before rollout. Older kernels and non-qualified I/O paths remain separate gates.


Updated 2026-10-10. This is an implementation and acceptance record, not a completed native rollout.

## Active implementation: completed writes and immediate actor retention

The next release must qualify both completed scalar/vector writes and executable retention without adding a process-start delay. The implementation will reuse the existing atomic reservation, durable raw journal, private snapshot, SHA-256 verification and server artifact transfer. An ambiguous later audit PID lookup will not be accepted as a substitute.

- Native source: add `Lease/Atomic` as the maintained source of the existing v27 atomic provider, then extend its operation BPF and controlled loader. Capture at `vfs_write`/`vfs_iter_write` entry and retain the executable before the task returns. Record a separate return observation with signed result, requested/transferred bytes, offsets, size samples, file flags and append intent. Keep permission observations distinct. A pending asynchronous result must never become completed bytes.
- Managed source/contracts: extend `LinuxAtomicObservationFrame`, `LinuxKernelDecoder`, `LinuxKernelEvidence` and native work admission with a separately versioned I/O observation. Update server capability negotiation before sensors emit the new schema. Keep old schema-6/7 records readable and canonical.
- Immediate first-use capture: use native task/process birth nanoseconds, executable generation, event credentials and the retained image lease. Test actors which open/write/truncate and exit immediately after exec; no injected birth delay. Retain explicit failure evidence on queue, filesystem, image-size or provenance failures.
- Qualification/deployment: build at low priority against each actual kernel and BTF. First qualify verifier, capture, normal detach/drain, rejected/short/zero/pending results, vector writes, O_APPEND, PID/exec changes and queue exhaustion. Then compare live sensor and central artifact bytes before staged rollout. Audit-only hosts require an appropriate native provider; their existing audit collector alone cannot establish these guarantees.
- Preserve current target files, evidence journals, policy and service configuration. Close existing owners normally before any module replacement. No forced unload, no global syscall logging and no heavy VM load test under the current resource pressure.

Status October 10: native and owned managed runtime qualification passed on Ops (Debian 6.12.94). The candidate uses vfs_write and do_iter_readv_writev, whose actual BTF prototype was verified; vector syscalls bypass vfs_iter_write. Authenticated central replay passed 502 checks with 35 verified binary/manifest pairs; the packaged UI passed 48 checks. Server 0.6.43 is deployed. Installed Ops 0.9.43 passed fourteen root/UID1000 operation cases with immediate-exit actors; production stored all 56 linked events and authenticated downloads verified fourteen executable/manifest pairs (LINUX-IO-INSTALLED-OPS-TEST-20261010-R11 and LINUX-IO-INSTALLED-CENTRAL-20261010-R1). Other-kernel qualification and wider rollout remain separate gates. Existing 0.9.42 sensors do not establish completion of this deployment.

Installed pressure testing also exposed delayed native START calls: counting all unfinished forensic deliveries against the four native permits held new acquisition behind managed completion work. Two recorded START calls returned ENOENT; their leases were no longer available, and the source stopped explicitly. The dispatcher now bounds active native calls independently of forensic delivery. That correction requires a fresh installed pressure test before rollout. Failed receipts are retained; serial matrix success does not establish burst reliability. Source startup and current-instance readiness must precede tests, and the non-root test image must permit its own post-operation `/proc/self/exe` truth check. Test target bytes, inode and timestamps are restored in `finally`.

### Retention and copy budgets under qualification

The former single ten-second deadline covered both durable admission and copying. Installed pressure failures retained POSIX ENOENT receipts after admission/cursor delay exceeded that window. The next module candidate retains the operation-time executable reference and write exclusion for at most sixty seconds while raw evidence is admitted, then starts a separate ten-second copy budget on the first authorized START. An exact START retry does not renew the deadline. The four-slot and 4 MiB limits are unchanged. This can temporarily retain write exclusion after an actor exits, for the bounded retention window; it does not open an executable later by PID or pathname.

The source-pinned module build passed (`LINUX-IO-RETENTION-MODULE-BUILD-20261010-R1`). Actual native qualification R2 passed all fourteen operations, 35 verified copies, 70 observations, a START delayed twelve seconds after actor exit/path removal, unchanged deadline on exact retry, zero loss, normal detach/unload, restored installed service and unchanged retained raw banks. R1 failed because the test stopped reading queued observations during its intentional twelve-second delay; it restored the sensor and retained its receipt. Manifest version 4 now binds the exact new module/BPF hashes while versions 1�3 remain accepted. The updated definition/capacity/worker fixture passed 96 + 9 + 108 checks; packaged runtime passed 39. Installed pressure and central acceptance remain pending. The intake-yield experiment did not establish pressure reliability and was removed.

### October 10 pressure failure retained

The R6 installed pressure receipt (`LINUX-IO-INSTALLED-OPS-PRESSURE-20261010-R2`) passed the first root write, then failed the append actor check after native START returned POSIX ENOENT. The source closed normally, retained thirty raw records, and drained all deliveries. The failed actor entry was received at 03:15:19.755 UTC, but its work token was not issued until 03:15:27.190 UTC. Its START returned at 03:15:28.193 UTC. Dedicated copy workers and larger delivery capacity alone did not establish pressure reliability. The next candidate also gives durable admission its own dedicated dispatcher instead of the shared pool. It must pass fresh installed pressure and central artifact validation before any wider feature rollout.

### October 10 queue and ordering correction

The installed R6 package (source SHA-256 `a1a6c0272c8b4e999a50cd276425534b59b14cc4593097c1768cb10514ae306b`) separates the four active native acquisition permits from a sixteen-item durable delivery backlog for ControlVersion 4. Legacy profiles retain their four-item limit. Native controller work runs on dedicated bounded threads, avoiding shared thread-pool scheduling. Paired return enrichment waits for the entry completion to commit, so it cannot report a temporary missing copy as a final preservation result.

The actual Linux journal tests passed nine admission/restart/overflow checks, and serial worker tests passed 108 checks across eleven injected success/failure/stop/receipt scenarios. These use real private files and SQLite with an injected controller transport; they do not establish kernel performance. The packaged relay/runtime suite passed 39 checks. Ops activation passed with normal source closure and all retained raw banks unchanged. Fresh installed pressure and central acceptance remain required (`LINUX-IO-SCHEDULING-FIXTURE-20261010-R1`, `LINUX0943-PACKAGE-RUNTIME-20261010-R6`, `LINUX0943-IO-OPS-ACTIVATION-20261010-R8`).

### October 9 native qualification update

LINUX-IO-CAPTURE-QUALIFICATION-20261009-R7.json passed on actual Ops Debian 6.12.94. Fourteen operations covered write, append, pwrite, writev, appendv, pwritev and pwritev2/RWF_APPEND under root and UID 1000. Returned bytes, offsets, size samples, append flags, PID/birth, executable device/inode and event credentials matched independent test data. All 35 native actor copies matched the original SHA-256 after immediate process exit and removal of its executable pathname. Loss was zero; all 11 hooks detached normally, the candidate module unloaded normally, and the original 0.9.42 sensor returned ready with retained banks and configuration unchanged.

Vector writes now use do_iter_readv_writev with type WRITE because writev does not pass through vfs_iter_write. This is native qualification, not production acceptance. Managed pipeline integration, linked entry actor evidence, central uploads/downloads, other kernel profiles and production rollout remain gates. The provider bounds actor copies to four leases and 4 MiB on the qualified local filesystem; larger images and asynchronous/mmap paths are not established by this receipt.

Debian rejected the older registration format until the maintained module used BTF_KFUNCS. Distilled BTF also relocated function IDs and broke the prototype's ID filter. The qualified build uses the exact pinned kernel BTF with MODULE_PAHOLE_FLAGS empty so the filter retains its expected full-base IDs. No verifier or access check was disabled. Failure receipts R1–R6 remain retained. R4 passed nine operation/copy checks but failed its overall early unload check; R7 includes a bounded normal-cleanup wait and passed the complete lifecycle.

## Established cause

The controlled NGINX01 write and append changed the deployed honeypot as independently expected. The kernel audit log contained the write-open, but no matching `pwrite64`/`write` operation. The restored target retained its original inode and bytes. File-permission audit rules intentionally omit individual read/write syscalls and inspect open flags instead; see [auditctl permission-filter documentation](https://man7.org/linux/man-pages/man8/auditctl.8.html). Increasing the server quota or changing the audit parser cannot recover an operation the kernel source did not emit.

The existing native manifest-v1 collector observes open checks. The manifest-v2 candidate observes permission checks. Neither permission success nor open intent establishes final write completion or bytes transferred.

## Fresh evidence

All receipt names below are under `diagnostics/windows-token-20260930` in the main workspace.

- `LINUX-ACTUAL-WRITE-DIAGNOSIS-20261009-R1.json`: exact test actor PID, kernel syscall records and collector packets.
- `LINUX-OWNED-INPLACE-OPERATIONS-20261009-R4.json`: write/append failed exact-operation acceptance; truncation was detected; original target restored. Overall receipt failed.
- `LINUX-OWNED-TRUNCATE-EVIDENCE-DIAGNOSIS-20261009-R1.json`: immediate first-use truncation reached the server, but process binding/hash/preservation were explicitly unavailable. The audit/process start-time guard is conservative at clock-tick boundaries. Do not count this as complete actor capture.
- `LINUX-OWNED-TRUNCATE-CENTRAL-20261009-R5.json`: a separate actor with an explicit 100 ms birth delay passed exact command line, PID/start/session/parent, event-time credentials, stable executable identity, SHA-256, preservation and actual server artifact/manifest download checks. This does not establish immediate first-use capture.
- `LINUX0941-NGINX-POST-OPERATIONS-READS-CENTRAL-20261009-R1.json`: six fresh native read events and actual actor artifact pairs passed after restoring the native service.
- `LINUX0941-NATIVE-RECOVERY-UNITS-20261009-R4.json`: all 17 deployed native companions active and ready on the current 0.9.41 release.

The original pilot's backup hard link conflicted with the native collector's single-link target admission requirement. The native owner closed and drained; ordinary audit collection continued. The corrected in-place pilot uses no hard links. Preserve the failed receipts and closure records. Do not weaken target admission to make a test pass.

## Verified kernel interfaces and required changes

`LINUX-OPERATION-KERNEL-PROTOTYPES-20261009-R1.json` reads actual NGINX01 BTF, without loading or attaching anything. Kernel `6.12.94+deb13-amd64`, BTF SHA-256 `1f985fb42ab930ef42ff4c228990ec085d89faf589b115ee256ddd717624dc8e`.

The installed kernel exposes `vfs_write(file, const char *, size_t, loff_t *) -> ssize_t`, `vfs_read`, `vfs_iter_write`, `vfs_iter_read`, `do_truncate`, `vfs_rename` and `vfs_unlink`. Presence in BTF does not prove attach eligibility or verifier acceptance. [Linux 6.12 read/write implementation](https://github.com/torvalds/linux/blob/v6.12/fs/read_write.c) confirms the distinction between permission checks and operation return values. Vector I/O and asynchronous I/O have separate paths; do not promise their coverage from scalar VFS hooks alone.

Continue integration through the existing components:

1. Native `sq_actor_lease` module and operation BPF source: reserve the exact actor executable at operation entry using the existing bounded atomic lease mechanism. Preserve accessing-task credentials and process/task birth plus executable generation. A later PID lookup is insufficient.
2. Versioned native frame/loader, `LinuxAtomicObservationFrame`, `LinuxKernelDecoder`, and contracts: add explicit I/O-entry/result stages with requested length, offset availability, signed return value, transferred bytes, observed sizes, errno and exact operation correlation. Keep existing schema-6/7 permission evidence readable; never reinterpret it as successful I/O.
3. `LinuxNativeWorkJournal` and pairing journal: retain original observations before asynchronous enrichment, pair only exact task/birth/generation/target/nonce matches, and report unmatched or failed collections. Reuse executable hashing, preservation and central evidence transfer.
4. Native admission/ownership: qualify lifecycle handling for renamed/deleted target paths while retaining held target identities and mount checks. Do not silently disable identity validation or replace live maps.
5. Acceptance: independently compare actual read/write/append/truncate/rename/delete and failed operations; test short-lived actors, exec changes, PID reuse, queue exhaustion and detach/drain. Download actual server evidence for each accepted case. Add vector/asynchronous coverage separately, including pending completion rather than treating `-EIOCBQUEUED` as transferred bytes.

## Diagnostics implementation before deployment

`LinuxProcessCapture` now uses typed failures for start mismatch, ambiguous birth order, event-image mismatch and exit/image change during binding. `ActorLease` retains those stable reason codes in unavailable collection status, preserves raw OS errors, and does not trust arbitrary exception messages. Existing binding acceptance rules are unchanged.

`LINUX-BINDING-STATUS-CHECKS-20261009-R1.json` passed 10 component checks. `LINUX-BINDING-NATIVE-REGRESSION-20261009-R2.json` passed 57 actual Linux forensic regression checks, including real stale-event and mismatched-image rejection. At this pre-release checkpoint these changes had not been released to sensors. The completed 0.9.42 deployment is recorded below; missing native operation hooks remain unresolved.

## Resource gate and remaining work

The latest VMware capacity receipt showed approximately 100% host CPU and 431.40/447.89 GiB RAM in use. The owned qualification VM remained off. Heavy VM load testing is pending capacity; lightweight source inspection and isolated regression testing continued. Full Linux operation rollout, first-use actor capture, broader kernel qualification, sustained-load testing and final three-pass product QA remain pending. Wazuh remains an end-of-work discussion item.

2026-10-09 deployment in progress: Linux diagnostics release 0.9.42 was sealed and passed 39 packaged runtime/launcher checks, following 10 binding-status checks and 57 actual Linux forensic regression checks. The launcher explicitly accepts the new release version without changing its ownership, permissions, architecture, SHA-256 or process protection checks. The initial immutable package was rejected by its old version allowlist before any installation; the corrected package is LINUX0942-BINDING-PACKAGE-20261009-R3.

Twenty-five Linux sensors are activated, with 102 fresh read/actor-artifact pairs centrally accepted across 17 hosts so far. The four Windows sensors remain current at 0.6.25 with running drivers and zero pending evidence uploads; management server remains 0.6.42, with global evidence capacity 32 GiB. Failed test host-guard and early Plex status-file polling receipts are retained; the corrected host tests passed and Plex was verified without an additional restart. The final legacy web-host deployment and remaining read/server gates are still pending. This update supplies precise Linux collection-failure reasons; it does not add missing write/append hooks or complete the broader specification.

## 2026-10-09 Linux 0.9.42 deployment completed

All 26 existing Linux sensors now run 0.9.42-linux-dev. The live management API confirms those exact sensor identities and the four Windows sensors at 0.6.25; the management server remains 0.6.42. All 17 native Linux companions were independently checked active and ready after rollout; the other nine retain their existing audit-only mode. No new kernel/module profile was deployed.

Fresh read acceptance passed six cases on each Linux sensor: 156 cases, with independently checked user/process/PID, process-instance and executable identity, and 156 actual server executable/manifest download pairs with hashes and event linkage checked. Two additional living-audit denied-open retests (Ops and Plex) passed actual central actor artifact checks. Those two tests are representative checks, not a new denied-operation qualification on all hosts. The existing Windows build retains its separately recorded 60-operation/four-host central acceptance and 64 artifact pairs.

The final web-host activation harness initially assumed the native service was still failed; its pre-installation assertion stopped before changing services or selectors. Read-only diagnosis confirmed the recovered native service was healthy. The corrected active-service lifecycle passed, including clean shutdown, BPF/module closure checks and unchanged retained raw evidence. The earlier failed receipt is retained. Normal audit relay transitions had measured intervals; no lossless transition claim is made. Measured rejected-record increments remain visible in activation receipts rather than being reported as zero.

After deployment, all 26 Linux hosts completed read-only approximately 10-second resource samples. Maximum observed combined CPU was 3.85 percent of a sensor VM; summed process RSS ranged from 218.16 to 424.68 MiB. This was not injected sustained-load testing. RSS sums may double-count shared pages and are not a resource ceiling.

This release adds stable Linux actor collection failure reason codes while retaining process birth/image validation and raw OS errors. It does not add exact Linux write/append hooks or solve immediate first-use actor capture. Full Linux operation matrices, broader kernel/load qualification, all consumer callback file-type acceptance and final product-wide three-pass QA remain pending. Wazuh remains an end-of-work discussion item.

Immutable acceptance: diagnostics/windows-token-20260930/LINUX0942-ALL-DEPLOYMENT-ACCEPTANCE-20261009-R1.json. Release ransomfree-client-0.9.42-dev.20261009T200141Z-fd4fa98b0ae0-linux-x64, archive SHA-256 b60f2fcca24cfe494248c78bc13735a84bbe2d834b13e03e49e41e200cf0e79e. Supporting receipts: LINUX0942-SERVER-INVENTORY-FINAL-20261009-R1, LINUX0942-NATIVE-READINESS-FINAL-20261009-R1, LINUX0942-ALL-POST-DEPLOYMENT-RESOURCES-20261009-R1, LINUX0942-REMAINING-ROLLOUT-20261009-R4, and all read/denied central receipts linked by the acceptance summary. Previous in-progress entries above are historical checkpoints.
