# Linux operation-time executable evidence — qualification prototype

## Linux actor capture buffer and pathname evidence — qualified R13, October 1 UTC

The owned Debian **6.12.94 / local ext4** candidate passed **925 native checks**, recorded **48 observations**, and preserved **38 actor executables**. Independent acceptance verified each artifact's bytes, SHA-256, size, source inode/device, process/thread start identity, event cookie and provenance status. No target file was hashed or copied. The latest diagnostic schema is **5**; the retention module ABI remains **2**, with the exact accepted R8 module source.

Changes and verified behavior:

- Actor and target paths are captured from referenced file objects, preserving exact bytes. Unicode, quotes, backslashes, controls and invalid UTF-8 names are covered. Invalid UTF-8 has a null display value. Paths are explicitly current-task filesystem-root renderings, not original syscall text or globally canonical names; namespace identity is unavailable, and a textual deleted suffix is not treated as proof of deletion.
- Scalar process/credential evidence remains on the invocation stack. Large task-local path buffers use unique atomic owner tokens and are looked up again after sleepable retention calls. Allocation failure, busy storage, deletion after capture/finalization and changed ownership retain compact observations and useful actor bytes. Missing path data is null, never another event's data. All six UID/EUID/FSUID/GID/EGID/FSGID fields have explicit read status and kernel-global encoding labels.
- The loader freezes userspace scratch mutation **before** attaching observation hooks. A separate root test process opened the map by ID and the exact actor by pidfd: same-cookie replacement and deletion both returned **EPERM**, with byte-for-byte unchanged storage. BPF-side scratch helpers remain functional. This is not protection against a compromised kernel or root loading arbitrary BPF programs.
- A second open in the same process after an injected changed owner remained compact/unavailable; it did not silently clear another owner's buffer. Executable bytes were preserved for both events.

**Denied-open correction:** the real fixture received EACCES from a later BPF security program, while the earlier observer recorded prior return 0 and final outcome **not observed**. That distinction passed. On the pinned x86 kernel, a nonzero modify-return program short-circuits later observers, so this is **not** complete coverage of earlier LSM or pre-hook DAC denials. R12's test incorrectly expected a preceding denial result and failed; it remains retained. R13 corrects the fixture claim rather than manufacturing a denied result. Linux Audit remains required for its separate denied-event coverage, and short-lived denied actors can still lack preserved bytes.

Verification passes for this diagnostic scope: (1) native identity/path capture and exact actor preservation; (2) races, buffer faults, freeze enforcement, deadline/capacity and provenance regressions; (3) verifier admission plus deliberate rejected programs, real runtime permission tests, zero reported ring losses and normal teardown. All five owned hooks detached, module/device disappeared, references drained, and the guest was confirmed off at **2026-10-01T08:06:11.4432113Z**. All four owned qualification guests were independently off with zero NICs. Product UI, service activation, central transport/SIEM and Linux hash-whitelist integration are **not completed by this proof**.

Earlier results are preserved: R10 **604/39/29**, R11 **844/45/35** (checks/observations/copies). R12's first run stopped at 891 checks because the harness used an incorrect library location; the corrected-harness retry stopped at 907 checks on the invalid prior-denial expectation. Neither is relabeled a pass. R13 acceptance archive SHA-256: `1b2983d119024c298c37406bc633a4e7f4c0b20e09b67c799b39260458d1c4d1`.

Production readback at **08:00:53 UTC** confirmed all **30 expected sensors active** (four Windows **0.6.13-dev**, 26 Linux **0.9.17-linux-dev**), 33 retained enrollments and server **0.6.15.0**. The event-history API responded again at snapshot 37456 after earlier timed-out requests; root cause of those transient timeouts is not established. The original strict callback-PID continuity gate failed because the server logged a separate **Ansible reboot at 07:03 UTC**, before this continuation. A separate post-reboot inventory receipt verifies current health without pretending the old PID remained unchanged. No production restart, deployment, driver activation or policy change was performed in this continuation.

Remaining gates: trusted product transport of Linux kernel evidence and copies, full operation/result coverage, broader kernels/filesystems and sustained load qualification; Windows production altitude/signing and rollout. Existing Windows R6 native/server/UI acceptance below remains unchanged. The deployed Windows audit source still cannot supply the accessing-thread token.

Receipts in workspace diagnostics: `LINUX-ACTOR-LEASE-ACCEPTANCE-R13.json`, `LINUX-ACTOR-LEASE-NATIVE-R12.json`, `LINUX-ACTOR-LEASE-NATIVE-R12-SCRATCHRETRY.json`, `INVENTORY-POST-REBOOT-ACCEPTANCE-20261001T0800.json`, `SERVER-RESTART-READBACK-20261001T0805.json`, and Manus V14–V16 reviews. Historical sections below describe earlier stages.

## Linux actor-file provenance and retention — qualified R8, October 1 UTC

The isolated Debian **6.12.94** / local ext4 prototype passed **365 native checks**, recorded **35 observations**, and preserved **25 actor executables** with independently verified bytes, SHA-256, sizes and source identities. Before/after provenance guards now bracket a provisional retained-file handoff. Metadata version two records the process and thread start keys, exec identity, provider epoch, association generation and explicit association error. No target file is hashed or preserved.

The native cases include process exit, same-path replacement and rename, four-slot capacity, queue failure, deadline rejection, wrong-cookie and duplicate finalization, abandoned reservation expiry, shared-VM inheritance, uncertain private forks, failed executable-reassignment attempts, and actual cross-TGID executable reassignment. A reassignment timed entirely inside retention was detected: the original bytes were preserved with association uncertainty. An unprivileged user 65534 test matched UID/EUID/FSUID and GID/EGID/FSGID. Unknown association never discards the observation or useful captured bytes, and every event remains ineligible for whitelist suppression.

Source review found and corrected two R7 lifecycle defects: Drop now claims cancellation atomically with its ID lookup; the provisional reaper no longer waits behind a controller draining another copy. Targeted native overlap tests passed both cases. All four owned BPF hooks detached with **zero reported ring losses**, the module/device were removed normally, and the zero-NIC guest was confirmed off at **06:52:10 UTC**. The default build separately excludes all four diagnostic fault controls. R7's earlier 333-check result and the identified defects remain retained. Manus's exact R8 source review found no additional concrete lifetime, double-release or lock-order fault; that review is not product acceptance.

Verification passes for this diagnostic scope: functional capture/preservation; race/error regression; native load/verifier/permissions/unload plus independent archive/hash validation. Product UI, service startup, transport and SIEM integration are **not qualified by this prototype**. A separate **67-check / 6-observation real delayed-I/O test passed** with the exact R8 module. On a private local ext4/dm-delay device, 496 cold source pages and the worker kernel stack established actual blocked filesystem I/O. The copy held write exclusion past its deadline, occupied its slot, and rejected selection. It drained after **5,763.56 ms**, recorded **131,072 of 2,097,152 bytes** with ETIMEDOUT, and published no partial artifact; normal capture then recovered. All hooks/module/device, temporary mount, kernel mapping, device node and loop attachment were removed; the guest was off at **07:13:11 UTC**. The two earlier harness setup/cleanup failures remain retained. No hard cancellation guarantee is claimed. See `LINUX-ACTOR-LEASE-BLOCKEDIO-ACCEPTANCE-R8.json`.

Production remains unchanged. API readback at **06:42:21 UTC** reports **30/30** expected sensors active, 33 retained enrollments, server **0.6.15.0**. Windows production still uses its deployed audit source. Broader Linux filesystems/kernels, pre-hook DAC-denied coverage, complete target I/O results and trusted hash-policy integration remain open. Disk executable bytes do not establish loaded-memory integrity.

Receipts: `LINUX-ACTOR-LEASE-ACCEPTANCE-R8.json`, `LINUX-ACTOR-LEASE-DEFAULT-BUILD-R8.json`, `LINUX-LEASE-PROVENANCE-PLAN.md` and `MANUS-LINUX-ACTOR-LEASE-V13-R8-EXACT.md` in workspace diagnostics. Historical entries below retain their earlier stage-specific results.

## Asynchronous actor-file lease prototype — October 1, 05:50 UTC

Manus V10's acquired-file handoff was independently checked against the actual stable-kernel sources. A module kfunc can receive the unmodified, NULL-checked `bpf_get_task_exe_file()` reference through `KF_TRUSTED_ARGS | KF_SLEEPABLE`, take a separate file reference/write-exclusion count, and copy bytes later. The module takes its own entry lifetime reference; BPF still releases its original reference. There is no supported hard cancellation guarantee for a blocked `kernel_read`: expired reads must drain before releasing write exclusion and cannot publish evidence afterward. See [kfunc registration](https://raw.githubusercontent.com/gregkh/linux/v6.12.94/kernel/bpf/btf.c), [trusted references and module lifetime](https://raw.githubusercontent.com/gregkh/linux/v6.12.94/kernel/bpf/verifier.c), [kernel reads](https://raw.githubusercontent.com/gregkh/linux/v6.12.94/fs/read_write.c) and [work cancellation](https://raw.githubusercontent.com/gregkh/linux/v6.12.94/kernel/workqueue.c).

The diagnostic prototype `linux-actor-lease-v1/` now builds against Debian's matching 6.12.94 headers with module BTF, positive and two deliberately invalid BPF objects, a ring collector and harmless actor. It is restricted to four local ext4 executable snapshots, at most 4 MiB each, a root-only single controller and a two-second publication deadline. A deliberate 500 ms queue delay tests process exit before copying. No target file is copied or hashed, and every observation remains `whitelistEligible=false`. The first two compiler failures are retained. Build r3 passed all six compile/link steps; **module load, verifier behavior and native lease tests are still pending**.

The tools/headers were extracted into private research storage without system package installation. No module was loaded on production. A separate zero-NIC VMware clone is being prepared for native module qualification. This isolated proof must still integrate the existing shared-mm provenance/taint guards and pass cancellation, overload, lifecycle and filesystem acceptance before product integration or trusted hash matching.

Receipts: `MANUS-LINUX-ACTOR-LEASE-V10.md`, `MANUS-LINUX-ACTOR-LEASE-SOURCES-R12.md`, `LINUX-ACTOR-LEASE-BUILD-TOOLS.json`, `LINUX-ACTOR-LEASE-BUILD-R3.jsonl`, and `VMWARE-LINUX-LEASE-LAB.json` in workspace diagnostics. Some line anchors in the external report differ from the retrieved stable source; conclusions were checked by symbol and body, not accepted from the cited line numbers alone.

## Status, October 1, 2026 UTC

### Asynchronous actor-file retention preflight

The next research question is an exact file-object lease with independently owned write denial, allowing hashing/copying after process exit. Manus received the proposal and the independently observed kernel export constraints. No companion module or new production provider has been loaded; hash-based suppression remains disabled.

Read-only preflight confirmed kernel `6.12.94+deb13-amd64`, BPF LSM/module/IMA/module-BTF support, and current lockdown `none`. Matching Debian header packages `6.12.94-1` were downloaded, SHA-256 verified and extracted under an owned private `/var/tmp` directory without package installation. Their `Module.symvers` hash is `1c7611b80fea8087f0c4b3937955afc9d9158d400bde7b5bf0f7523319de01f6`. The exact packages export `get_task_mm`, `mmput`, BTF kfunc/destructor registration, `kernel_read` and `fput`. They do **not** export `get_task_exe_file`, `get_mm_exe_file` or `security_add_hooks`. `deny_write_access` and `allow_write_access` are header inlines, so their absence from the export table is not an API failure.

The candidate approach passes an already acquired BPF executable-file pointer to a narrow module kfunc that would take its own file reference and write-denial count. The [6.12.94 kfunc documentation](https://raw.githubusercontent.com/gregkh/linux/v6.12.94/Documentation/bpf/kfuncs.rst) describes acquired pointers as trusted arguments; this is source support for a prototype, not native verifier acceptance. The [built-in executable-file kfunc](https://raw.githubusercontent.com/gregkh/linux/v6.12.94/fs/bpf_fs_kfuncs.c) takes a file reference, while [mm executable replacement](https://raw.githubusercontent.com/gregkh/linux/v6.12.94/kernel/fork.c) separately releases write denial. A file reference alone must not be treated as a content-immutability lease. Blocking filesystem I/O also prevents claiming a hard cancellation deadline without qualification.

Receipts and reviewed request text: `LINUX-ACTOR-LEASE-CAPABILITIES.json`, `LINUX-ACTOR-LEASE-HEADER-METADATA.json`, `LINUX-ACTOR-LEASE-HEADER-RECEIPT.json`, `research-async-actor-lease-request.txt`, and `research-actor-lease-export-feedback.txt` in workspace diagnostics.

This is an isolated research prototype, not a deployed sensor provider or a hash-based whitelist implementation. Existing Linux audit collection, forensic enrichment and alert behavior remain unchanged. An unavailable or ambiguous actor hash never suppresses an alert.

The native proof loaded and attached a sleepable `lsm.s/file_open` program on Linux `6.12.94+deb13-amd64`. It acquires the current task's executable with `bpf_get_task_exe_file`, calls `bpf_ima_file_hash` on that referenced file, records the returned algorithm and digest, and releases the file before returning. Each invocation preserves the incoming BPF LSM result. Only the exact device/inode of an owned test target is measured; actor reads are capped at 32 MiB. No target content is hashed.

The helper associates the hash request with the executable file during the callback. It avoids substituting a later `/proc/PID/exe` image after the process executes another program. It does not prove memory integrity or universal IMA cache freshness.

## Native evidence

The six-scenario run passed its explicit assertions:

| Scenario | Observed result |
| --- | --- |
| Short-lived process | Correct actor SHA-256, PID/TID and UID/EUID/FSUID captured before exit. |
| Immediate same-PID exec | Two correct, different hashes/inodes with the same PID and task-start value. |
| Renamed executable | Expected original bytes/hash despite the `notepad.exe` label. |
| Replacement at the same pathname | Expected replacement hash and new inode. |
| Unprivileged access | UID/EUID/FSUID and GID/EGID/FSGID all matched 65534. |
| DAC-denied open boundary | Fixture failed with its expected access error; no `file_open` event was produced. This confirms a coverage limitation, not successful denied-open capture. |

The final r4 proof adds independent fork-return PID ground truth: all six image-bearing observations matched the fixture PID/TID, expected credentials and independently calculated actor SHA-256 values. The earlier r3 proof is retained. The final archive receipt is `LINUX-BPF-ARCHIVE-R4.json`. Every observation explicitly has `whitelistEligible=false` and `hashFreshness=not-proven`. No ring losses occurred in this bounded test. Each program detached on collector exit, and independent BPF program inventories were empty before and after. These are pre-open observations, not completed I/O results or full read/write coverage.

The first run retained a diagnostic mismatch: raw kernel-managed inode version changed from 4 to 5 because IMA set the `I_VERSION_QUERIED` low bit. The corrected proof records both raw values and superblock flags, and compares shifted values only when `SB_I_VERSION` is set. Self-managed values remain opaque. Equal markers alone never authorize a whitelist match. The failed run remains available.

Evidence and sources are in `../../../diagnostics/windows-token-20260930/`: `LINUX-BPF-ACCEPTANCE-R4.json`, `LINUX-BPF-BUILD-R4.jsonl`, `LINUX-BPF-NATIVE-PROOF.jsonl` (first failure), and the four `linux-bpf-probe*` / actor source files. Tool packages were extracted only into owned research storage; no system package, service, boot or LSM configuration was changed.

## Integration plan and admission requirements

1. Add a versioned Linux kernel observation contract and optional `LinuxKernelSource` alongside the existing audit source. Preserve operation stage, result availability, effective credentials, task lifetime, actor device/inode, hash algorithm, digest semantics, loss counters and collector epoch separately.
2. Keep platform APIs in a dedicated native provider. Runtime load/attach probing, rather than a kernel version comparison, admits a provider. Older kernels and unsupported configurations retain audit collection and explicit unavailable evidence.
3. Extend existing `ActorLease`, `LinuxProcessCapture` and `ForensicCollector` to compare later retained image identity/hash against the operation-time record. Later preservation is a separate result; it cannot repair a missing operation-time identity.
4. Reuse the existing evidence store, upload queue, server persistence and SIEM envelope. Add stable reason codes for unsupported hooks, hash algorithm/type, freshness uncertainty, association rewriting, process exit, mismatch and loss. No target hashing or preservation default changes.
5. Keep whitelist matching disabled until a source-supported freshness contract and native adversarial tests establish a narrowly defined eligible profile. Validate executable deny-write semantics, IMA cache/type, filesystem behavior, writable mappings, `PR_SET_MM` association rewrites, shared-mm relationships, exec lifecycle, loss/restart and latency before enabling any suppression.
6. Test permission failures through an additional source: DAC failures can precede `file_open`, and `file_permission` is not a sleepable hook for this hash helper. Do not apply one open-time hash to later operations without a proven binding.

Unresolved coverage includes complete read/write/rename/denial timelines, exec/association taint lifecycle, namespace mapping, remote/FUSE/memfd behavior, high-volume cost and unavailable evidence. The prototype is a demonstrated building block, not completion of the Linux specification.

## Stable-kernel write exclusion

A separate native check on `6.12.94+deb13-amd64` copied a harmless executable into owned storage, ran it, and attempted a write-only open without writing or truncating. The open failed with `ETXTBSY` (errno 26); the actor bytes remained unchanged. Receipt: `LINUX-EXEC-WRITE-EXCLUSION.json`. The original upstream v6.12 source and later stable revisions differ here: [v6.12.94 exec](https://raw.githubusercontent.com/gregkh/linux/v6.12.94/fs/exec.c) and [mm executable references](https://raw.githubusercontent.com/gregkh/linux/v6.12.94/kernel/fork.c) include deny-write accounting. This supports investigating a version-qualified profile; it does not prove IMA freshness, shared-mm association lifetime or all filesystems.
The follow-up native barrier matrix passed **8/8** checks: running write/read-write/truncating opens and path truncate returned `ETXTBSY`; write-open after exit succeeded; an existing writer or shared writable mapping prevented exec; a private copy mapping allowed exec without changing backing bytes. These are owned local ELF tests, recorded in `LINUX-EXEC-BARRIER-ACCEPTANCE.json`. They do not establish shared-mm rewrite provenance, IMA synchronization or remote filesystem behavior.

## Research revision and remaining matching gate

Manus' final version-specific report (`MANUS-LINUX-FRESH-PROFILE-V4.md`, with recorded SHA-256) identifies a possible narrow raw-hash profile on 6.12.94-equivalent kernels. It requires a continuous executable deny-write reference, qualified local filesystem, explicit IMA/hash state and reliable exclusion/provenance for `PR_SET_MM_EXE_FILE` and `PR_SET_MM_MAP` association changes. A per-task taint flag is insufficient: distinct processes can share an mm. Preexisting associations also need qualification after attachment/restart.

The suggested global `PR_SET_MM` guard would enforce an additional OS restriction. It has not been added or enabled. It would require an explicit optional policy, compatibility tests and proof of the shared-mm lifecycle; existing behavior must not change silently. The current native prototype remains report-only, with every hash ineligible for suppression. Source review and the write-exclusion check are evidence toward this contract, not acceptance of the remaining premises.
## Native shared-mm rewrite qualification — October 1 UTC

A separate controlled experiment confirmed the association weakness. An owned fixture unmapped its original executable mappings while continuing in a separate fixture library. A different-TGID `CLONE_VM` peer then successfully called `PR_SET_MM_EXE_FILE`. The parent's next monitored open retained the same PID and process-start value but reported the replacement association's inode and SHA-256. Opening the original executable for writing became possible, while the newly associated executable still returned `ETXTBSY`. No executable bytes were written or changed. Both captured hashes matched independent file hashes, and the probe detached completely.

Receipts: `LINUX-MM-REWRITE-ACCEPTANCE.json` and `LINUX-MM-PROOF-ARCHIVE.json` in the workspace diagnostics directory. The preserved native archive SHA-256 is `c01a8049837699a0db1edce881f5a48cc539af3d8e5e88d48880930eefaed587`. This test validates the limitation; it does not qualify suppression.

A report-only provenance experiment was then built to mark fresh execs, taint shared-mm state before either `PR_SET_MM` association-changing form, and remove state at mm teardown. Its first native admission attempt failed with `EBUSY` attaching `fentry/__mmput`; that function is absent from this kernel's available ftrace functions. The provider refused to run and all its loaded programs were released. `LINUX-PROVENANCE-NATIVE-R3.jsonl` retains that failure. Kernel configuration was not changed. The LSM-only correction below removes the teardown-hook dependency. All hashes remain ineligible for suppression.

## Lifetime-bound association provenance — r8/r9

Four actual BPF LSM hooks now implement the report-only prototype: `bprm_committed_creds` assigns a unique saturating generation to a fresh ordinary exec, `task_prctl` permanently taints that shared mm before either association-changing request, `task_alloc` propagates only validated `CLONE_VM` identity, and sleepable `file_open` checks provenance before and after hashing. Lifetime-bound task storage holds the mm key, generation and the task's own `self_exec_id`. Kernel pointers stay private. Missing storage, map errors, mismatches or taint remain explicitly unknown/ineligible.

Only the ordinary-exec marker replaces an mm-map entry with `BPF_ANY`, after clearing the task token and before binding it on successful insertion. A fresh generation prevents a reused allocator address from transferring an old identity. The r5 `BPF_NOEXIST` experiment lost known provenance on an ordinary exec; that failure remains retained. Manus V7 corrected its blanket prohibition on replacement under these stronger invariants. Native load/attach also confirmed that the short spin-lock snapshots used here work in these LSM hooks. No helper executes while the lock is held.

The **r8 nine-case native matrix passed**: fresh exec; preexisting fork without exec stays unknown; same-PID exec gets a different generation; cross-TGID shared-mm rewrite taints both peers; a `CLONE_VM` child inherits the generation using its own exec ID; a private-fork child stays unknown; failed `EXE_FILE` and `MAP` attempts still taint conservatively; and 64 independently identified successive execs have distinct generations and correct actor SHA-256 values. Each run detached all four hooks and reported zero ring loss. Receipt: `LINUX-PROVENANCE-ACCEPTANCE-R8.json`. Downloaded source/native archive SHA-256: `bbf1b3ebfa1d1bccebe8359cd3dfce62c4faab823c990c2bcfb1ff44ee297bda`.

The **r9 concurrent rewrite test passed** with independently recorded monotonic timings: a different-TGID shared-mm peer completed its association rewrite entirely inside the actor hash interval. The original actor hash/inode remained accurate, while the pre/post generation word changed from 2 to 3 and post-check reported `-EUCLEAN`; the event was rejected for provenance matching. No executable bytes changed during the test. Receipt: `LINUX-PROVENANCE-RACE-ACCEPTANCE-R9.json`; archive SHA-256: `715bf25e47378a04a6ed84f91ae3bb728fd149374c57f788f85e29261283f81d`.

The r9 instrumented provider repeated all nine regression scenarios successfully (`LINUX-PROVENANCE-ACCEPTANCE-R9.json`). The r10 loader then injected faults only into its own fresh, unpinned maps: a one-entry map filled with a sentinel and an already-saturated generation counter. Each case observed **64 independent execs** with correct actor hashes, unknown provenance and the exact expected raw errors (`-E2BIG` and `-EAGAIN`). Neither produced a known or eligible identity. A third fresh-map run recovered correct provenance for another 64 execs; this does not establish continuity for a process spanning restart. Receipt: `LINUX-PROVENANCE-FAULT-ACCEPTANCE-R10.json`; downloaded archive SHA-256: `a67ebe02e50092c5589064445d76975df88652e89fb4b25bff19885981f4e6f7`.

This is not a performance or whole-profile acceptance. The owned 24 MiB test ELF took approximately **363 ms** to hash synchronously on the research host. Production needs bounded asynchronous work or a separately proven cache contract. IMA freshness, qualified filesystem behavior, production capacity recovery, epoch/reload continuity, event loss and broader operation coverage remain separate gates. No production provider, whitelist suppression or OS enforcement was deployed.

## Hash semantics and cache decision

Manus V8's central API limitation was independently checked against stable kernel source: `__ima_inode_hash` may copy an existing collected IMA digest or perform a temporary file measurement, while `bpf_ima_file_hash` returns the algorithm without identifying that branch. A matching test digest is not proof of universal freshness. Readings of `S_IMA`, inode versions and file metadata can narrow a source-qualified profile, but do not add an API-attested cache-origin field. See [IMA implementation](https://raw.githubusercontent.com/gregkh/linux/v6.12.94/security/integrity/ima/ima_main.c) and [BPF helper contract](https://raw.githubusercontent.com/gregkh/linux/v6.12.94/kernel/bpf/bpf_lsm.c).

A later userspace `/proc/PID/exe` lease can retain useful forensic bytes and reject an identity mismatch; it cannot manufacture a missing operation-time hash. Cross-lifetime hash reuse based solely on path/inode/size/timestamps will not be enabled. A kernel cache confined to a proven ordinary-exec generation is a possible future design, but its initial synchronous measurement cost and IMA digest semantics still need acceptance. The current default remains report-only evidence with no hash-based suppression. The complete external analysis and its hashes are retained as `MANUS-LINUX-PROVENANCE-V8.md` and `MANUS-LINUX-PROVENANCE-V8-RECEIPTS.jsonl`; that analysis is not itself a native test pass.

## Primary references

- [Owned executable-file kfuncs](https://raw.githubusercontent.com/torvalds/linux/v6.12/fs/bpf_fs_kfuncs.c)
- [Permitted sleepable hooks and IMA helper](https://raw.githubusercontent.com/torvalds/linux/v6.12/kernel/bpf/bpf_lsm.c)
- [IMA cache and file hashing](https://raw.githubusercontent.com/torvalds/linux/v6.12/security/integrity/ima/ima_main.c)
- [Kernel inode version semantics](https://raw.githubusercontent.com/torvalds/linux/v6.12/include/linux/iversion.h)

Manus' original broad claim that BPF could not acquire an executable-file reference was rejected after source verification. Its corrected revision acknowledges the v6.12 mechanism and the remaining freshness limitations. Neither report substitutes for native qualification.


## Linux kernel transport and forensic identity - October 3, 2026 UTC

Implemented an additive Linux kernel observation contract (native schema 5, transport version 1), a bounded decoder, explicit capability/receipt negotiation, queue/server validation, and history action projection. Exact pathname bytes are preserved as base64; displayed paths escape controls and have a marked display limit. Native 64-bit identifiers use canonical decimal strings. Initial-user-namespace UID/EUID/FSUID/GID/EGID/FSGID remain separate from unavailable account resolution and process-owner identity. A pre-open observation remains Open Requested with unknown final outcome, including a nonzero preceding BPF LSM result. No target hashing was added.

The existing forensic collector now retains Linux kernel task credentials and a provider-epoch/process-start/exec correlation, with no later PID lookup substituting for a missing kernel lease. Missing retained executable bytes produce explicit unavailable hash/preservation evidence and a linked completion. Source filesystem classification remains unknown because the native pathname namespace was not captured. No new whitelist eligibility is inferred.

Acceptance: tools/LinuxKernelFixture replayed all 48 observations from the accepted R13 archive (SHA-256 1B2983D119024C298C37406BC633A4E7F4C0B20E09B67C799B39260458D1C4D1), plus seven constructed edge observations. Build r4 had zero warnings/errors; 629 checks passed. All 55 originals and 55 linked forensic completions survived durable queue restart, authenticated loopback HTTP, database storage, administrative history API and the existing SIEM formatter. Cases include PID reuse/exec/epoch separation, full uint64 values, invalid UTF-8, control characters, two maximum 4095-byte paths, unavailable credentials, contradictory fields, old-server capabilities and missing receipt support. The native hash identifies the archived Event JSON bytes replayed by this fixture; it does not claim original loader-line formatting.

Evidence: D:/Codex/RansomFree/windows-token-20260930/linux-transport-310dfbe89a1e4c02bd00d848d27be74e/RESULTS.json; linux-kernel-transport-r4-build.log and linux-kernel-transport-r4-test.log in that artifact root's parent. Earlier transport-only r3 passed 349 checks and remains retained. Existing server regression passed 156 checks and activity-contract regression passed 213 checks against the r3 shared contract/server changes; those runs preceded the added r4 forensic identity projection and are not its native acceptance.

Remaining: live Linux provider/service activation, managed retained-lease acquisition and durable recovery, successful actor-byte preservation/upload through this kernel adapter, hash-based suppression qualification, native capacity/restart/loss tests, full read/write/rename and denied-open coverage, network SIEM delivery, UI/runtime acceptance and production deployment. These isolated replay checks do not qualify those gates or finish the product-wide three-pass QA.


### Linux managed lease reader / Manus R53 checkpoint

The shared forensic regression passed 95 checks using its native Windows apphost (linux-transport-forensic-apphost-test.log; artifacts forensic-regression/60c9cc0e29ad433ab640bef8aec7c052). The first invocation used dotnet DLL hosting and failed the fixture's unsigned-apphost assumption because that makes the signed dotnet host the actor; that invocation remains retained in linux-transport-forensic-test.log and is not a product pass.

LinuxActorLeaseProtocol.cs now implements the existing native schema-2 160-byte status/select/read/drop ABI. It checks the complete observation binding, bounds copies to 4 MiB, validates status again after reading, computes SHA-256 of actual returned bytes, and requires the same complete identity before DROP. It never automatically drops bytes after reading. A pre-reservation size difference is retained explicitly; the module's post-exclusion size is authoritative. ctime-only rename changes and unavailable association provenance do not silently erase otherwise complete bytes. DROP/close can wait for real kernel I/O to drain; the implementation does not pretend a userspace timeout cancels it.

R6 replay passed 904 checks with all 38 archived native actor copies and 55 observation/completion pairs. Results: D:/Codex/RansomFree/windows-token-20260930/linux-transport-a310a4714a424dc4bee9745fe339c94e/RESULTS.json, plus linux-kernel-transport-r6-build.log/test.log. The device transport was substituted for these replay tests; live P/Invoke/device acceptance is a separate R14 isolated VMware run, still pending at this checkpoint. LinuxLeaseNativeProbe is a lab-only consumer; it does not activate any installed sensor. The sealed self-contained package is linux-managed-lease-r2.tar.gz, SHA-256 68a2b081369dfc68554e37d247454cd91002c781160bbe6c3aca691570994d98. Source snapshot: D:/Codex/RansomFree/windows-token-20260930/source-linux-managed-r2.

Manus R53 review is retained as linux-r53-retained-actor-byte-integration-review.md (SHA-256 63BDAFF527F9044752D9B88969D4656049E39347C2581F03D92AEDE7E5561657). Required remaining integration work includes durable raw-first ledger, directory fsync, quota reservation, crash recovery, separate copy/provenance status and truthful CLOSE_DRAINING/unknown-range telemetry. No native producer-quiesce or slot-inventory API currently exists. The review is design evidence, not native qualification.

The ioctl encoding and statx layout/availability checks were verified against Linux v6.12.94 primary headers: https://raw.githubusercontent.com/gregkh/linux/v6.12.94/include/uapi/asm-generic/ioctl.h and https://raw.githubusercontent.com/gregkh/linux/v6.12.94/include/uapi/linux/stat.h . Native admission is limited to Linux x64; no new production deployment, strong whitelist matching or full operation coverage is claimed.


### Forensic consistency and native dispatch update

R7 strengthened cross-record validation: forensic PID/TID, process instance/start key, event-time and effective credentials, original collector sequence, target path and unknown outcome must agree with the Linux kernel observation. A forged enrichment cannot contradict its original native actor. The complete replay fixture passed 1,014 checks; result: D:/Codex/RansomFree/windows-token-20260930/linux-transport-827908eb10cf4387a49be26ef1e8d1bc/RESULTS.json. R7 build had no warnings/errors. This is still archived replay, not production acceptance.

Managed R14 did not execute the native probe. The 36,448,074-byte package transfer remained incomplete (11,059,200 bytes observed, module absent); the controller's initial exception was masked by its three-minute guest-shutdown deadline exception. Both diagnostics are retained; the exact initial transfer exception is unavailable. A subsequent read showed the guest off, and baseline snapshot VirtualMachineSnapshot-snapshot-15012 was restored at 2026-10-03T03:14:46.4171660Z. Receipt: linux-lease-run-managedr14-20261003T030216Z/cleanup-restored.json. No native pass or new kernel behavior is inferred from this dispatch failure.

The retry controller records the primary exception before cleanup, allows five minutes for graceful guest shutdown, and uses the documented GuestFileManager upload API with certificate pinning to the authenticated vCenter host certificate. The API returns a PEM certificate, so the DER certificate fingerprint must be derived by parsing PEM. Reference: https://developer.broadcom.com/xapis/vsphere-web-services-api/latest/vim.vm.guest.FileManager.html and https://developer.broadcom.com/xapis/vsphere-web-services-api/latest/vim.host.ConfigInfo.html . The guest remains zero-NIC; no installed sensor or production service was changed.

Next integration steps: add a versioned Linux actor-acquisition companion and its distinct capability acknowledgement; a durable raw-first work ledger; private file/manifest directory fsync; explicit transient/retained quotas; recovery using only private snapshot identities and hashes; and existing EvidenceStore/upload integration. Native status copy size is recorded separately from pre-reservation observed size. The largest tested unavailable-lease completion already occupies 23,227 of the current 24,576 event bytes, so the complete acquisition/preservation envelope requires an explicit size/migration test before activation. Do not silently truncate raw path or actor metadata to fit it. Live native extraction, crash cuts, blocked-close handling, loss/epoch telemetry, server binary upload, UI and deployment remain distinct gates.


### Linux actor acquisition, preservation and central transport - October 3, 2026 UTC

Added independently versioned LinuxActorAcquisitionEvidence v1 and a named-field
projection of native lease status ABI 2. Native uint64 identities remain canonical
decimal strings. The acquisition links the source event and exact native-observation
digest to provider/process/task/exec/association identity, source device/inode,
private snapshot identity/hash and collection/recovery status. Original source
and private-copy metadata remain distinct; unavailable source timestamps stay null.
Backing-file bytes do not establish executed-memory integrity or whitelist eligibility.

The common forensic collector and evidence manifest retain the Linux acquisition.
The server checks it against both the original native observation and completion,
including the full process context and source file metadata. Initial raw evidence
may precede acquisition. Missing or inconsistent manifest companions cannot gain a
central receipt. LinuxActorAcquisitionVersion=1 is required in capabilities and
receipts before dequeue; old servers cannot silently acknowledge stripped evidence.

Queue schema 4 rebuilds the table transactionally, retaining exact old payload bytes,
FIFO sequence, capacity counters and acknowledged sequence high-water marks. Only
events carrying Linux acquisition gain a 64 KiB bound; ordinary events retain 24 KiB.
A complete maximum-path/acquisition/preservation envelope measured 25,438 bytes.
Existing count/byte quotas, 256 KiB batch target and 512 KiB HTTP body bound remain.
An incompatible old binary must not be used to open this upgraded queue.

Accepted replay/integration: linux-kernel-transport-r13, 1,871 checks, zero compiler
warnings/errors. Receipt root:
D:/Codex/RansomFree/windows-token-20260930/linux-transport-f834c17a71d8485ca6b8c38dd7486acd.
Inputs are the accepted native R13 archive (48 observations and 38 actor copies),
plus seven constructed observation edges and one constructed preservation envelope.
The Windows-hosted fixture ran the common collector on the archived actor bytes,
made 38 actual local forensic copies, uploaded all 38 through the real authenticated
loopback client/server API, verified artifact and manifest downloads, retained local
copies, and rejected six altered manifests. This is archived replay, not fresh Linux
kernel capture. Queue v1/v2/v3 upgrade and rollback failure cases passed.

Related regressions: server 156 checks (root test-results/server/
3f6e4972c6eb43ba88cd625efbe38edd under the diagnostic artifact root), Windows forensic
apphost 95 checks (forensic-regression/42123e0860d646f49b448db787f3e864), existing
upload fixture 56 checks (D:/Codex/RansomFree/forensic-gaps-20260925/
fixture-cab9f109a9834e06a414ace352c5f975). The expected Production-startup refusal in
the server fixture is a passing gate, not a live service failure.

Retained negative harness evidence: transport R9 assumed paths plus acquisition alone
would exceed 24 KiB, but measured 24,442 bytes; the corrected full-preservation case
measured 25,438 and passed in R10/R11/R12/R13. An initial R11 invocation supplied the
wrong argument count and stopped before tests; the corrected invocation passed 1,483.
R12 added common preservation and passed 1,635 before R13 added central upload checks.

Native managed-device dispatch remains a separate gate. R15 rejected the incorrectly
hashed PEM certificate before upload; the corrected helper parses DER and passed TLS
preflight. R16 then hit its nine-minute transfer timeout before the native harness ran.
Its owned VM was verified powered off, zero NICs, and baseline-restored at
2026-10-03T03:39:57.0829968Z. R17 is retrying the same sealed R2 managed payload as six
separate, hashed parts, with full reassembly hash verification. Neither failed dispatch
is a native pass. The sealed R2 device probe predates the acquisition transport changes.

Still pending: actual Linux durable intake/ledger, private snapshot recovery, directory
fsync/space-reservation integration, qualified source activation, crash-cut/blocked-I/O
and sustained-volume gates; fresh native managed-device acceptance; and deployment.
No production sensor, server, firewall or physical-host reboot occurred in this step.
Windows signing/assigned altitude and final product-wide three QA passes remain pending.


#### Linux evidence display and qualification-harness review

Event History now exposes separate Linux accessing-task credentials, process/task
start and exec/provider identity, native observation/path bytes and actor-acquisition
panels. The forensic event-principal label uses filesystem UID when supplied, with
its namespace; effective UID remains separately visible. Missing actor/path/copy
fields remain unavailable. No sensor-list layout or OS/status fields were removed.

Offline browser acceptance: 33 Linux evidence checks, seeded from four confirmed
archived-native upload completions plus explicit UI edge cases; 21 existing Event
History checks and 95 presentation checks passed. Desktop 1440px and phone 430px
screenshots are retained under D:/Codex/RansomFree/windows-token-20260930/
linux-evidence-dom-r1. The phone rendering was visually reviewed. This does not
establish signed-in production UI acceptance or deployment. An encoding round-trip
mistake during editing was detected and corrected before the browser tests.

The final R13 replay receipt contains 193 stored events and a maximum envelope of
25,579 bytes after common preservation was added; the earlier R11 envelope was
25,438 bytes. Both require the versioned acquisition queue expansion.

Before native execution, independent verifier R2 corrected a timing assumption:
a rename performed after process exit can happen after the native copy completed,
so MetadataChanged may legitimately be 0. The verifier now preserves that measured
flag and independently compares the archived replacement/original actor bytes to
the native snapshot. The original verifier remains retained; no failed native
result was reclassified to justify this correction.


### Linux native managed capture and durable handoff - October 3, 2026

Managed native R19 passed 121 harness checks and an independent 464-check archive
verification on the owned, zero-NIC Linux VMware clone (6.12.94+deb13-amd64).
Eleven observations produced ten verified private actor copies plus the expected
publication-deadline failure. Coverage includes exited actors, replaced/unlinked
paths, renamed and invalid-UTF8 binaries, UID 65534, association uncertainty and
recovery after a deadline. Archive SHA-256:
a0b444564eb2e7477f154ce52c0c0ec6c0c2dbb6512e3befbac314f370361eca.
Receipt: diagnostics/windows-token-20260930/LINUX-ACTOR-LEASE-NATIVE-R13-MANAGEDR19.json.
The VM was off and its baseline restored at 2026-10-03T04:23:33.8381105Z.
Detach took 11.538 seconds; the captured stack shows an RCU/ftrace BPF detach wait.
The ten-second deadline was exceeded and remains recorded; no forced kill/unload.

R17 and R18 remain failed receipts. R17 was a hex-case comparison error in the
harness. R18 used a pathname outside the sealed case fixture's permitted prefix;
its first seven captures passed but association-case execution and the ten-second
cleanup budget failed. R19 uses an owned hardlink to the identical target inode to
satisfy both existing fixture guards, records actor exit diagnostics, and measures
an explicit sixty-second graceful detach budget. Native/managed R2 binaries did
not change. Reconstructed runtime files were individually hash-checked and the
entire resulting sealed tar verified, before executing any fixture.

New internal LinuxForensicJournal and prepared ForensicPipeline path reuse the
existing collector, EventSpool, preservation store and upload queue. Raw native
bytes, policy, private snapshot result and stable completion ID commit first.
Original/completion payloads become immutable before queue delivery. Completion
spool precedes upload registration; retry uses the exact saved pair. Private
snapshot corruption retains historical source metadata and emits failed recovery
without usable hash or original-path/PID fallback. New collector epochs label new
completion ordering after restart. Linux file publication now syncs containing
directories as well as file contents. No kernel source installation is enabled.

Windows-hosted recovery fixture R3 passed 141 checks, including eight actual child
process exits, prior-original ACK, corrupt snapshot, full completion spool, failed
and concurrent upload registrations, identity mismatches, four pending work items
and quota limits. Artifacts: D:/Codex/RansomFree/windows-token-20260930/
linux-recovery-results-r3. R1 exposed a missing InvalidDataException catch during
snapshot recovery; R2 corrected it (122 checks), and R3 adds queue/upload faults.
The sealed source is source-linux-recovery-r1 in that artifact directory. A native
Linux replay of this recovery fixture is in progress; power-loss and blocked-read
recovery are not established by process-exit tests.

Regressions after the durable handoff changes: Linux transport R14 1,871 checks
including 38 real loopback binary uploads; existing Windows forensic fixture 95;
existing evidence transfer fixture 56. All compiled with zero warnings/errors.
No production service, installed sensor or signed-in production UI was updated.

Remaining gates: live raw-intake/native acquisition scheduling, durable overflow
and physical ENOSPC handling, native DROP and blocked-close crash cuts, profile
qualification on other Linux kernels/filesystems, Windows signing/assigned
altitude/remaining runtime qualification, deployment and fresh all-sensor tests.
Four pending journal rows and logical storage reservation are bounded behavior,
not a lossless live-intake guarantee. Manus R55 is reviewing this admission gap;
R54's metadata reservation arithmetic omitted the third raw/original/completion
record and was corrected before implementation. Final product-wide QA remains
pending; none of these receipts establishes full specification completion.


#### Native Linux recovery acceptance and R55 follow-up

The same sealed recovery fixture passed all 141 checks on the owned Linux clone.
Forty-two checked evidence files were root-owned 0600. Eight real process-exit
cuts, corrupt snapshot, full spool and upload-registration failure/retry ran on
Linux filesystems with the directory-fsync path enabled. Archive SHA-256:
14ca2114b6fe2de53d24ec978e217dccd7fd32c683d6f99c7fa96627ac22b249.
Receipt: diagnostics/windows-token-20260930/LINUX-FORENSIC-RECOVERY-NATIVE-R1.json.
VM off/baseline restored: 2026-10-03T04:45:16.3120953Z. This test loaded no kernel
module and reused archived R19 observations; it does not qualify power loss or
live native resource release. A separate read-only progress query overlapped
shutdown and timed out waiting for VMware Tools; the controller's archive and
final shutdown receipt were obtained successfully.

Manus R55 completed. Report: linux-r55-durable-intake-scheduling-review.md,
SHA-256 24351769f4a69114aec181ee39fb7859c7fdb1d3f48dc480d3bbc514254922b6.
It confirms the next required correction before live activation: separate a
physically reserved raw backlog/emergency health record from the four native
acquisition jobs. Serialize device ownership; defer DROP while native reads are
not terminal; preserve explicit epoch/loss/close unknown ranges. Logical journal
quota is not physical ENOSPC protection. The existing four-row admission remains
an internal qualification limit, not an activated production intake policy.
Primary API references were checked: Linux fallocate(2), kernel BPF ring buffer
documentation, and SQLite synchronous pragmas. These are design inputs, not tests.

Latest read-only altitude mailbox check: 2026-10-03T04:40:19.120162Z. Original sent
copy verified; no replies from fsfcomm@microsoft.com. The request was not resent.


Independent recovery verifier R2 passed 121 archive/database checks: 16 raw rows,
11 completed event pairs and nine preserved executable/upload pairs (the raw-only
and corrupt-copy cases correctly have no successful preservation). The R1 verifier
could not open a WAL-mode SQLite image deserialized into memory; R2 reads bounded
analysis copies with their sidecars in read-only mode. Original archive bytes were
unchanged. Receipt: linux-lease-run-recoveryr1-20261003T043534Z/INDEPENDENT-RECOVERY.json.


#### Reserved raw admission prototype (not live source activation)

LinuxRawIntakeReserve adds an append-only, bounded raw record bank under the
private evidence directory. Each 128-KiB slot stores the native bytes, immutable
typed observation and frozen policy with a checked frame index, SHA-256 and
padding. The bank has a sensor/capacity/platform header and a dedicated emergency
slot. Linux admission uses fallocate on this exact file range, file flush and
directory fsync; Windows tests are explicitly layout replay, not physical Linux
allocation. Slots are never reused or silently evicted. A full bank retains the
first unknown open-ended overflow boundary and refuses further admission.

The recovery fixture R4 passed 165 managed checks, including five durable raw
records beside four active journal rows and indexing the fifth after prior work
finishes. Duplicate/conflicting delivery, owner restart, sensor/capacity mismatch
and corrupt raw frames are covered. Source freeze: source-linux-recovery-r2;
sealed package receipt: LINUX-RECOVERY-RECONSTRUCTION-R2.json in diagnostics.
Native qualification is running on the owned Linux VM, including actual ENOSPC
in a disposable 64-MiB ext4 image; the VM/host root filesystems are not filled.

The raw reserve remains a storage primitive, not a running sensor intake. It
requires source scheduling, stable native-event duplicate mapping, explicit
provider/close unknown ranges and a qualified lifecycle/rotation policy. Physical
snapshot admission before native SELECT and native DROP/blocked-close recovery
remain separate work. No production opt-in or lossless-capture claim is enabled.
Manus R56 is independently reviewing the exact primitive and those boundaries.


#### Raw-reserve native negative result and required intent protocol

Native recovery R2 failed before the physical ENOSPC step. It successfully reached
five raw reservations and the fifth-row indexing test, then found a Linux-only
FileStream option error: UnixCreateMode was passed with FileMode.Open while
reopening an existing reserve. The fix sets creation permissions only for new
files. Failed archive SHA-256:
cbc909c087b72279f883c40e98bc9bb36cfa576b36314118eb35cf13bfc273ef.
Receipt LINUX-FORENSIC-RECOVERY-NATIVE-R2.json remains failed. A new R3 package is
being prepared; no ENOSPC success is claimed for R2.

Manus R56 completed an exact-source review (report linux-r56-raw-reserve-primitive-
review.md, SHA-256 e50aac95b95c03db28b92756f137a708836dda1686063b4bef20138a017a24ce).
Before durable live intake is enabled, add an independently flushed preallocated
intent stripe: a surviving intent plus zero/invalid data must expose interrupted
coverage, including the emergency record. The existing v1 bank cannot distinguish
an entirely lost first frame from unused zero space. Establish a formal whole-
envelope bound; the normalized observation currently has a 24-KiB bound, but the
JSON/base64 envelope also needs an explicit proof or a binary versioned layout.
Serialize disposal, make I/O/fsync failures sticky for admission, and preserve
native delivery identity mapping plus explicit source lifecycle unknown ranges.
These findings are unresolved in the v1 reserve even if its narrow ENOSPC rerun
passes. Physical-space testing must not be relabeled full crash-durability proof.


## 2026-10-03: Raw-reserve v2 native recovery and ENOSPC qualification

The corrected v1 R3 package passed 165 native fixture checks and 170 independent
archive checks. Its actual 64-MiB ext4 exhaustion case retained five raw records
and an emergency marker after unrelated writes failed with errno 28. The VM was
off and baseline restored at 05:20:18.4464448Z. This narrow pass does not repair
the v1 torn-zero ambiguity; immutable v1 artifacts remain historical evidence.

V2 uses a separately flushed 256-byte intent per frame and a binary body bounded
at 94,224 bytes (64-KiB native input, 24-KiB typed observation, 4-KiB policy and
16-byte envelope). It retains v1 files without reinterpretation. Intent with a
missing frame is explicit unknown coverage. Admission stops after I/O failure;
recovered bytes do not establish whether a prior caller received a commit ACK.

Native recovery R4 passed 175 fixture checks, including actual child exits after
raw and emergency intents and before data writes. All 49 observed evidence files
were root-owned 0600. The owned 64-MiB ext4 filesystem was exhausted: both filler
and unrelated 4-KiB writes failed with errno 28, while the preallocated v2 bank
committed, flushed, read back and reopened five raw frames and the emergency
range. The filesystem was unmounted and loop device detached. No driver loaded.

Independent Python verification passed 248 checks over the downloaded immutable
archive, 21 journal rows, 15 completed pairs and nine actual preserved actor
executables. It verified v2 intents, frames, raw hashes, complete identity links,
maximum input, retained corrupt bytes and zero-frame crash cuts. Archive SHA-256:
bdd250193e99c802f4d8bb7b0893ca1c88803426b0fbdb718d55a007a3cd2721.
Receipt: diagnostics/windows-token-20260930/LINUX-FORENSIC-RECOVERY-NATIVE-R4.json.
VM 15011 was off with baseline restored and zero NICs at 05:31:17.7142627Z.

Manus R57 review SHA-256:
b1a55401b89c26093ccc005db8fd181d73d88ff23a23f42b4ca457b8e5e3492f.
Its recovery VerifyIntent and fixed-width validation recommendations already
exist through the complete scan and decoded-event equality/IsValid gates.
Remaining work includes an explicit frozen policy codec, per-record recovered
ACK status, additional fault-path tests, native delivery mapping, bank lifecycle,
provider/close unknown ranges, snapshot admission before SELECT and serialized
native scheduling/release. No installed source activation, power-loss acceptance,
production upload/deployment or final product-wide three-pass QA is claimed.


## 2026-10-03: Canonical native delivery mapping and admitted snapshot work

Sealed native recovery R5 passed 262 Linux fixture checks and 333 independent
archive checks, including the v2 ENOSPC scenario. All 79 observed private evidence
files were root-owned 0600. Archive SHA-256:
e50b36d629bfb87125c8db67dca7302d34f4792ead2f7f0bfc760732865d1dca.
VM 15011 off/baseline restored at 05:51:05.6190575Z; zero NICs.

LinuxRawDeliveryMap rebuilds provider-epoch/cookie mappings from the raw bank.
Exact redelivery keeps the original event, receipt time and frozen policy.
Changed raw bytes for the same usable native key stop admission; zero-cookie or
zero-epoch deliveries remain distinct collector identities. It has no native
control operations or continuity/rotation claim. Raw v2 policy serialization is
now an explicit five-field codec; recovered records separately expose verified
content and unknown prior caller acknowledgment. Injected failures at intent and
frame write/flush/readback boundaries and nineteen retained corruption cases
were covered. These are post-operation injected exceptions, not actual OS EIO.

Manus R58 review (SHA-256
08af40d40f67931a2cecd95746b929ca28a2fd755f4b94c2a4029d528a2d9c1c)
identified duplicate-policy ordering: the current source recognizes an exact
committed native duplicate before validating a newly supplied policy. It also
returns the exact committed record from raw admission, rather than inferring
it from the last row. These fixes postdate sealed R5 and are not included in its
acceptance. Current local R8 fixture: 302 checks, no compile warning/error.

The new, not-yet-source-wired LinuxSnapshotAdmission/LinuxSnapshotJournal path
uses the existing journal (schema 2, atomic v1 migration) and full terminal native
status. It allocates a unique private destination and commits its write intent
before SELECT, verifies full status before/after exact streaming read, hashes
streamed and private readback bytes, and commits a private receipt before the
existing acquisition record. Recovery reads only the intent-named private file.
No committed private receipt means explicit unavailable even if bytes look
complete; no source-path/PID recapture. SQLite outcome failure leaves raw and
private bytes unresolved and does not call DROP. An uncommitted allocation is
retained and counts against quota. Native R6 qualification is being prepared.

New local tests cover identity changes, short/excess/failed reads, write-intent,
partial/private-receipt cuts, actual SQLite trigger failures, quota rejection,
corruption and recovery. New snapshot cuts currently use exception/dispose/reopen;
they are not abrupt-process or power-loss acceptance. Existing eight process-exit
cuts remain distinct. Live native scheduling, lifecycle/rotation, malformed-input
unknown ranges, native DROP/blocked-close and deployment remain pending. No source
activation or final product-wide QA/deployment completion is claimed.


## 2026-10-03: Snapshot admission linkage correction and crash qualification

Native filesystem R6 completed 302 fixture checks and 435 independent archive
checks. It used real Linux file allocation/permissions/SQLite/ENOSPC and archived
actor bytes with a simulated native device transport. No module was loaded.
All 108 observed evidence files were root-owned 0600. Archive SHA-256:
a63486154b65a6ca711c8215df6abfa5f6f25e0a04dcdce9f1dedaf69bc71cb6.
VM 15011 was off/baseline restored with zero NICs at 06:06:38.3178800Z.

R6 retains a documented defect: a failed first write-intent could leave a private
allocation with no durable source-event association. Manus R59 identified this
window; report SHA-256:
3093f32e5b8d739ff3a5168dc0e6e3d04cf451cf1a523add460bbcbbdb4cadd8.
R6 remains a bounded historical acceptance, not acceptance of the correction.

Current source fixes this through journal schema 3: commit allocation intent
with event ID/snapshot UUID/full expected status BEFORE file creation; allocate,
flush and identify the private file; commit write intent; issue an immutable
receipt after reading back the exact journal row. Native selection requires that
receipt. The admission object serializes mutable operations/disposal. A highlevel
acquisition boundary finalizes read failures as explicit unavailable evidence;
if SQLite cannot commit the outcome it reports ACQUISITION_OUTCOME_UNCOMMITTED
and performs no DROP. The older memory snapshot API cannot bypass admitted work.
Storage health now exposes allocation/write/verified intents and unindexed private
file count/bytes, with all retained files included in quota accounting.

Current local R12 fixture passed 355 checks with no compiler warning/error. Seven
new actual child process exits cover allocation intent, private allocation, write
intent, partial copy, private verification, receipt commit and acquisition commit.
Four actual child exits cover schema 1/2 migration before/after transaction commit;
reopen sees either the old schema or fully committed schema 3 and retains raw and
existing snapshot rows. Existing eight journal pipeline exits and two raw-intent
exits remain separately covered. These are process-crash tests, not power-loss.

Native filesystem R7 is running the sealed correction. Its actual kernel-device
integration, snapshot-specific physical ENOSPC, live scheduling/DROP/draining,
source lifecycle/rotation, unknown-range publication and deployment remain gates.
Current source is not activated on installed sensors. No full specification or
product-wide three-pass QA completion is claimed.


## 2026-10-03: Explicit receipt and ordinary admission-failure boundary

Both Windows and Linux agent projects compiled with zero warnings/errors after
the allocation-intent implementation (admitted-snapshot-windows-build-r1 and
admitted-snapshot-linux-build-r1 under D:/Codex/RansomFree/windows-token-20260930).
These are build checks, not endpoint deployment/runtime acceptance.

Manus R60 review SHA-256:
1be05ab8436c70af3f5c6272d13cf548d7eb21e90c8319e32b0651f75df5298e.
Its mutable-Boolean concern was conditional: IntentCommitted had already become
a read-only view of the bound private receipt. Current source further removes
that Boolean as an authorization predicate. BeginRead and successful commit
require the immutable receipt; failure finalization takes that receipt explicitly
and matches it against the current journal row. A foreign receipt cannot finalize
another work item.

The high-level acquisition boundary now covers allocation/preallocation and
write-intent exceptions. It commits ACTOR_COPY_UNAVAILABLE_SNAPSHOT_ADMISSION_FAILED
with native error code/type, or reports ACQUISITION_OUTCOME_UNCOMMITTED while
retaining the exact allocation intent and private bytes. Neither case SELECTs or
DROPs. Concurrent/repeated admission cannot finalize another admitted work item.
Current local R13 fixture passed 367 checks, including foreign receipt rejection,
initial/write-intent failure, failure of the unavailable-outcome transaction and
full successful acquisition through the owning boundary. These latest changes
postdate sealed native R7 (355-check package), which is still in progress.

Next finite integration work from R60: source lifecycle and close-unknown journal,
malformed/oversize input boundaries, loader lost-counter changes and provider
restart handling. Cookie jumps are NOT loss evidence because the native generation
counter is shared with association changes. No automatic live bank rotation or
bounded/cancellable native close is claimed. Actual native-control integration,
snapshot-specific ENOSPC, and deployment remain pending.


## 2026-10-03: Corrected native filesystem archive accepted; actual device run

Sealed recovery R7 passed 355 Linux fixture checks and 549 independent immutable
archive checks: 50 raw journal rows, 15 completed canonical pairs, nine preserved
forensic executables, five additional admitted snapshot successes, 17 explicit
unavailable snapshot results, and four recovered schema migrations. All 132
observed private evidence files were root-owned 0600. Archive SHA-256:
30ca7d20f8e5d8960fed4fba80007a74ce2c6f1d1f1cc08cc20f757fdd157106.
VM 15011 was off/baseline restored with zero NICs at 06:21:49.0681293Z.
The acquisition device transport in this R7 filesystem run was simulated; real
fallocate/SQLite/permissions/process exits and the raw-bank ENOSPC test were used.

LinuxLeaseNativeProbe now has an explicit --admitted qualification mode. It
commits the original raw record, uses the journal's allocation/write-intent path
against the actual exclusive kernel device, verifies the recovered private file,
and releases only after the durable acquisition plus a matching current terminal
status. It retains the old memory-read mode for historical probe compatibility.
Per-operation journals are isolated diagnostic outputs, not an installed sensor
scheduler. Native ManagedR20 (module R13) is running on the owned zero-NIC clone
with the established eleven actual actor scenarios. No native result is claimed
yet. Sealed admitted payload raw tar SHA-256:
93f8aadd4459e476a6773fbb38af654dbbad359066ba7990a65c3e1e231298ac.

The existing Microsoft altitude request was checked read-only at
2026-10-03T06:27:40.869971Z. Sent copy was verified; no reply found. No request was
resent. The initial DNS attempt failed and the read succeeded using the existing
profile IP and pinned SSH host key. This does not assign an altitude or change
Windows driver signing/deployment status.


## 2026-10-03: Actual admitted kernel-device run completed, audit pending

Native ManagedR20 used module R13 and the new --admitted probe. The native harness
passed 195 checks across eleven actual actor scenarios, including exited,
replaced-at-same-path, deleted, renamed-notepad, Unicode/invalid-UTF8 names,
unprivileged UID, association-taint and deadline cases. Ten admitted copies
matched independently hashed original actor bytes. The expired case retained an
explicit unavailable acquisition and performed no select/drop. Successful cases
committed their private acquisition before matching terminal native release.

Native cleanup reported loader exit 0, controller close/exit 0, reference count 0,
unload exit 0, module/device absent and all owned BPF programs absent. Loader close
was 6.905 seconds; this is a measurement, not a cancellation/deadline guarantee.
Archive SHA-256:
c520cbaf229db4fcd7f5aa0419ea4e1882ea8edca59e0b793660240bb7f59d86.
Independent archive/database verification and VM off/baseline restoration are
still pending for this run. No sensor deployment, source continuity, event upload,
blocked-read close, final operation outcome or hash-whitelist qualification is
inferred from this diagnostic native pass.


## 2026-10-03: ManagedR20 independent archive rejection

ManagedR20's native harness passed 195 checks and completed real native cleanup;
VM 15011 was off/baseline restored at 06:31:38.7943632Z. Independent artifact
verification failed: the inherited archive loop only included top-level capture
files and omitted all eleven nested intake databases/private destinations. The
top-level raw/result/manifest/copy files remain retained, but this is NOT a full
independent admitted-artifact acceptance. Failure record is
INDEPENDENT-ADMITTED-LEASE-FAILED.json in the R20 local artifact root. The native
receipt is retained unchanged; its harness success does not override this failure.

ManagedR21 is rerunning the same sealed admitted binary and module, with recursive
regular-file capture archival and explicit expected nested-evidence checks. Missing
nested evidence makes the result fail while retaining the available archive. The
new controller has not completed. No production systems were changed.


## 2026-10-03: Admitted native ManagedR21 independently accepted

The corrected archive run used the SAME sealed admitted payload as R20 and module
R13. Native harness: 195 checks, eleven observations, ten captured actor copies
and one explicit native-deadline unavailable acquisition. Independent archived
raw/identity/private-file/SQLite/permission/cleanup verification: 549 checks.
The archive contains all eleven nested intake databases and ten admitted private
executables. Each captured copy matches the independently hashed original actor;
source and private inode identities remain distinct, with exact source-event,
full native status and acquisition-receipt linkage. Successful DROP is recorded
after durable acquisition; the expired case has no snapshot intent or DROP.

Archive SHA-256:
131c72f4b311ae4123f9bf809e40c14a80103f89010b359306bcd0178d516024.
Receipt: LINUX-ACTOR-LEASE-NATIVE-R13-MANAGEDR21.json.
Independent report: INDEPENDENT-ADMITTED-LEASE.json in its LocalRoot.
Actual module references drained to zero, unload succeeded, device/module and all
owned BPF programs were absent. Loader close measured 9.683 seconds; controller
close measured 0.374 seconds. VM 15011 was off/baseline restored with zero NICs at
2026-10-03T06:41:59.8045862Z. R20's missing-nested-archive rejection is retained.

Scope remains a diagnostic owned-VM native acquisition test. This does not prove
sensor activation, final file-operation result, gapless delivery, production
upload, hash-whitelist eligibility, blocked-read close, complete Linux metadata,
or deployment across installed sensors. Next implementation gate is the R60
source lifecycle/unknown-range/close/bank handoff design, followed by serialized
native scheduling and qualified source integration. Snapshot-specific physical
ENOSPC and native resource-release crash cuts remain separate acceptance items.
Windows altitude reply/signing/deployment gates and final product-wide three-pass
QA remain open. Production services and the physical desktop were not changed.


## 2026-10-03: Linux source lifecycle admission gate (R60/R61)

Implemented in LinuxSourceLifecycle.cs and LinuxSourceSession.cs, reusing the existing LinuxForensicJournal and raw delivery bank. Journal schema 4 adds retained bank identity/quota, immutable session/collector/provider identity, loader-counter samples, source state, and ordered open-ended continuity boundaries. Existing event/SIEM schema and installed source activation are unchanged.

- OPEN, CONTINUITY_FAULTED, CLOSE_UNKNOWN_OPEN and CLOSED are explicit states. Actual close return is required before CLOSED. Blocking/throwing close retains ownership; a failed final database transaction retries only that transaction.
- Exact source-session lookup uses its immutable, unique collector plus provider epoch; a new same-epoch session cannot finalize historical work from a closed collector.
- Malformed/oversize input faults before raw commitment. OOM sets a sticky boundary-uncommitted stop without requiring another allocation. Database failures retain the original pending loss reason/sample for later persistence.
- Loader counter increase/reset/unavailability opens an unknown range. Cookie jumps alone never imply event loss. Provider epoch change prohibits old native status/select/drop calls and retains finalized private evidence.
- A single-use source opening permit binds the controller. Initially faulted/overflowed sources grant no permit; foreign controllers cannot capture/release current-session work. Test-only factories/callbacks require explicit diagnostic replay mode.
- Diagnostic text/key lists are bounded before lifecycle writes and carry explicit truncation/omission metadata. SQLite/WAL capacity remains ordinary durable storage, not a physically reserved guarantee.
- Unclosed-process recovery records COLLECTOR_RESTART_UNKNOWN and refuses a new owner. Manual native ownership reconciliation remains a separate acceptance gate; no timeout, PID/path fallback or old lease-ID retry establishes closure.

Local fixture R17: 488 checks, zero build warnings/errors. Includes actual process exits around journal migration/restart, deterministic controller close blocking/failure, three input failures, loader loss/cookie distinction, five snapshot stages on epoch transition, same-epoch session isolation, opening permits, OOM injection, bounded telemetry, raw overflow/retention, and capture/release via simulated native transport. Earlier R14/R15/R16 results (462/466/469 checks) remain historical; R17 includes the R61 corrections.

Sealed Linux filesystem qualification R8 is running in the owned zero-NIC VMware clone. Bundle SHA256 44981507a3bcfca3043a830dc7eaca1736bea646fa357f54de299621bba6a87f; source/build manifest SHA256 e70a44d76117682ae812220d84929ea44c62165797fb88ab7ea79c59f158805f. No production deployment or live driver/source acceptance is claimed by this fixture.

Remaining: native source scheduling and terminal-unavailable handling, snapshot-specific actual ENOSPC, native blocked-read/resource-release crash cuts and ownership reconciliation, source/server activation, qualified sensor rollout, Windows altitude/signing and remaining qualification, and final product-wide three-pass QA.


## 2026-10-03: Native status disposition and pressure qualification preparation

Local fixture R18 passed 600 checks with zero build warnings/errors. LinuxNativeProgress.cs adds journal schema 5 with a bounded latest-progress record; this is explicitly not a reconstructed operation timeline. Valid completed FAILED tuples preserve error/status as unavailable; malformed COMPLETE states cannot produce an actor hash/copy; pending/copying/provisional and expired-draining states remain nonterminal. Release requires committed outcome plus exact current tuple revalidation. LinuxActorLeaseDevice.DropExact rechecks under its device lock immediately before DROP. A changed tuple or failed drop-record write faults the source and prevents automatic retry. No-lease metadata acquisitions support explicit not-applicable resource release.

Tests cover fourteen native-state/invariant combinations, expired-to-actually-failed progression, tuple change at the release requery and inside DropExact, release-journal failure with exactly one native call, and two actual schema5 migration exits. These use deterministic native transport. Current kernel resource-drain qualification and installed source scheduling remain pending.

NativeDiskPressureChecks.cs adds two Linux-only owned-filesystem handshake modes: failure before snapshot allocation and exhaustion after physical snapshot allocation. The fixture retains raw/native metadata, verifies the exact admitted private bytes, and exercises recovery after the controller removes only its own filler. R19 compilation succeeded with zero warnings/errors; these new pressure modes have not yet run.

Filesystem run R8 is a retained FAILED run: the inherited 300-second suite limit expired after progressive durable writes. Archive SHA256 a2e4d853a861828bd6f448f693dab5d177709008a89b7f431406a1e554c8646f. First/last retained writes span 290 seconds; the older smaller R7 suite already spanned 269 seconds. R8 VM powered off and baseline restored at 2026-10-03T07:27:49.6243641Z. R9 reruns the unchanged sealed schema4 R8 payload (488 checks) with a finite 900-second suite bound and per-line elapsed timing. It is still running. Do not treat that package as qualification of the later schema5 changes.

Latest targeted altitude mail read: 2026-10-03T07:19:23.064151+00:00, sent-copy verified, reply search succeeded with no reply. Request was not resent. All production activation/rollout and final product-wide three-pass QA remain pending.


## 2026-10-03: Sealed schema4 lifecycle run R9 independently accepted

The unchanged R8 payload completed the larger filesystem suite in 598.911 seconds under the corrected finite harness bound: 488 managed/native-filesystem checks, 206 root-owned 0600 evidence files, and actual ext4 ENOSPC with successful reserved raw/emergency writes. Archive SHA256 64760417c7d91a82f69d6f4af3120ca4bfa94a5b06c3f4d51a87b86020e7ab8b. VM powered off and baseline restored at 2026-10-03T07:45:52.3609664Z.

Independent verify-linux-source-lifecycle-r1.py passed 1,245 checks: 67 journal work rows, 15 completed event pairs, 9 preserved executables, 19 captured acquisitions, 30 unavailable acquisitions, 29 source sessions and 49 explicit source boundaries, plus raw intent/frame integrity and exact private hashes. This uses actual Linux SQLite/fallocate/filesystems and simulated native transport; no driver is loaded. Earlier R8 timeout remains failed historical evidence.

The next package (schema5 terminal progress plus snapshot pressure modes) is separately sealed: raw bundle SHA256 8feb805e0440b9fdfd9ad2f5cd14509351fe2506612bce0bd954977fcd663fef; manifest SHA256 c7beb765e3741aae008781dfc435c0aec1bf78f94da787b21554073669997d87. R10 native filesystem controller is starting only after verified R9 restoration. R9 does not qualify schema5 or the new pressure modes.

R62 recovery premise was corrected against the actual loader: it does not have a withheld-ready/activation phase. R63 controlled-loader design is under review. No new production source or automatic interrupted-owner recovery is enabled.


## 2026-10-03: Schema5 recovery follow-up and controlled loader build

RecoveryR10 is retained as a FAILED run, archive a401b73863268e91f537d67c72bfbc0ca98aaa6f984c8c41e4de8c9dd95a2240. Its 30-second diagnostic child bound expired at original-prepared; the archived journal was internally consistent and had the expected original checkpoint, but this did not establish child completion or suite acceptance. The owned zero-NIC VM was powered off and restored at 07:58:19Z.

Managed revision R20 passes 610 local checks. Linux diagnostic children now report measured start/return times with a finite 120-second bound. Controller close finalizes unfinished prepared acquisitions explicitly as ACTOR_COPY_UNAVAILABLE_CONTROLLER_CLOSED without changing their last observed native status. A retry after a failed close receipt retains the original actual return timestamp. This is not a native cancellation guarantee.

Sealed payload R10 (raw tar 3b326677be0a26b5b0f4661b1c0857a900cb0548c7bd01a3dcbcec71f78d6ac4; manifest 37884c6a4830f439ead43837a0e00033efb57143696297934c5630f50f473f75) is under RecoveryR11 native filesystem qualification. It includes real owned ext4 ENOSPC tests for preallocated and not-yet-allocated private snapshots. Native transport in that fixture remains simulated. Independent schema5 archive verification is prepared, not yet accepted.

Manus R63's spinlocked-config plus BPF_MAP_FREEZE proposal was rejected after checking pinned Linux6.12.94 map_freeze special-field rejection. R64's configure-and-freeze-before-observer-attachment alternative is implemented as isolated loader revision R14, diagnostic sources linux-actor-lease-v7. All ten build steps pass; archive 77c99da022083c60472d466d5a70bada6983c3d03c3f5dec4d8abf3e000e39f0. Controlled mode retains an O_PATH reference to the configured target inode; it attaches only three provenance hooks at ready, and requires one bounded ACTIVATE command followed by EOF before attaching denial(mode0) then observe. Loaded IDs and attached IDs are distinct, lost counters are actual lookups, and partial activation retains an explicit unknown outcome. The ordinary diagnostic entry point remains unchanged. This is BUILD acceptance only; native controlled-mode qualification, durable product session linkage, reconciliation and service integration remain pending.

No production service, sensor package, firewall or physical-host protection was changed in this continuation. Windows signing/altitude and remaining qualification, final cross-platform deployment and three-pass product QA remain pending. Web UI: https://cptnycdc01.cptnyc.com:7443 .


## 2026-10-03: Controlled loader native gate and durable startup records

RecoveryR11 schema5 passed 610 Linux fixture checks and 1,772 independent archive checks. Archive be4ad7d467eb6bbd65ed391cac1110064bd1f2f87f44529665cabc01866116aa; off/baseline restored 08:27:02.8008046Z. Includes real private-snapshot and raw-reserve ENOSPC. Preallocated actor bytes survived with their exact hash, but the unavailable SQLite receipt correctly prevented promotion to captured. A first independent verifier compared hexadecimal digest text case-sensitively and failed; R3 corrected that comparison only and accepted the unchanged archive.

Controlled loader R14/C2 passed 209 native assertions across 22 cases and 171 independent archive checks, with six actual retained actor executable copies matching independent actor hashes and UID/EUID/FSUID/GID/EGID/FSGID/PID/TID. Independent kernel link inventory verified only provenance at ready; separate root map update/delete returned EPERM; the first post-activation reservation proved no pre-activation reservation; an actual actor ran during attach before acknowledgment. Frozen target identity remained on the original inode after its pathname was replaced. Four non-pipe input types, eight malformed/EOF/signal activation cases, partial attachments, and ready/activation/final loss lookup failures were exercised. Ordinary diagnostic mutability/event contract also passed. Archive 52c11c889efb3d498e7af9437ee76c340fb0957fba8a71c2c2cc67707cbe358e; off/restored 08:46:02.6297725Z. C1 is retained FAILED: a harness library path error occurred before module load; C2 resolves the installed libbpf and uses a hash-verified prebuilt diagnostic shim.

Added LinuxControlledLoaderProtocol.cs (strict bounded frames, canonical full-width integers, exact owned session/epoch/nonce binding, loaded/attached separation) and LinuxSourceControlJournal.cs (internal SQLite schema6 immutable link/write-attempt/ack/completion records). A final success frame cannot manufacture a missing acknowledgment or historical native-controller close. Local protocol69, control-journal27 (including actual migration child exits), and regression610 pass. The managed Windows parser also accepted actual native C2 frames: 16 ready, 5 active and 21 complete. These are preparation components; no owned production loader process or activation write is enabled.

Payload R11 was sealed with raw-tar SHA256 605a6cf20bb91f74117cdd686f4f789d55c1c6d383b50833801531e54e72de89 and manifest 56f0c2fd88779a000531b456c81aae8f31a7792586cc1d9e04a991d1531b14c7. RecoveryR12 native schema6 fixtures passed recovery610, protocol69, control-journal27, all42 actual archived control frames, and both snapshot-pressure cases. Archive a047d2ce447145b1fe436dd4b89bd05a5b282b26fa3c7f552ac59aa12db459e2; off/restored 09:00:05.0543429Z. Independent R4 archive verification is recorded separately. This filesystem suite uses archived observations and simulated native copy transport; C2 is the separate actual-driver gate.

Latest unsealed helper LinuxLoaderFrameReader.cs keeps raw bytes exact within65,536 bytes, handles fragmented UTF-8 without normalization, rejects oversized/unterminated frames, prohibits competing readers and refuses continuation after a failed/cancelled managed read. Local R25 passes25 meaningful framing checks; Linux runtime integration remains pending. R24's first test run failed because its rejection helper omitted InvalidDataException; the reader correctly rejected the oversized frame. R25 fixes the test catch only; R24 negative log is retained.

Manus R65 review downloaded (SHA256 f75a12126bf414d6b780c655a0acb9df2537d27e96fcbfe0f71bf35f8db24654). Next: owned child/pipes and retained verified lost-map FD, serial raw pump plus bounded4 capture/deferred dispatcher sharing common32 pipeline capacity, actual stop/drain/close, and receipt-only interrupted-owner state until a real reconciliation gate is qualified. Do not infer automatic recovery, production activation, signing/altitude approval or all-sensor deployment. No production service/firewall/package changes occurred in this continuation.

RecoveryR12 independent schema6 archive verification completed: 1,801 checks passed, including 3 exact source_control rows in 5 control-journal databases. Receipt INDEPENDENT-SOURCE-LIFECYCLE-R4.json; all owned qualification VMs are powered off/restored as of 09:00:05Z.


## 2026-10-03: Native managed loss sampling and restart receipts

LinuxBpfLostMap.cs now retains one read-only kernel map descriptor, verifies its ID/type/name/layout and initial counter against the owned loader ready message, and preserves full unsigned 64-bit samples and native errors. Native MapR1 passed20 integration checks plus25 byte-framing and27 injected-map checks; independent archive verification passed114 checks. Actual kernel samples7,18446744073709551615,0 were read through the same managed FD. Wrong map shape and wrong initial value were refused. The loader remained disabled and created no actor observations in this gate. Archive b89078c77c395e9ff5f8b44ba5ac418420c74f051ff78e589608c9f09e18be3d; off/baseline restored09:26:53.6123323Z. Payload R12 raw tar445bf361e98995a564d5310ff39926fcca7111b2482dab974fa01b940ce4ec1d. This qualifies map interop, not a running production source. The first archive verifier used an incorrect source-manifest property Name rather than Path; correcting that read accepted the unchanged archive.

Internal journal schema7 adds LinuxSourceReconciliation.cs: immutable RECONCILIATION_REQUIRED receipt stores first pre-restart session, collector, epoch, prior lifecycle, last known loss (or null), recorded bank path/stable identity/length and observation time. These are historical metadata, not invented fresh file observations. Receipt, restart boundary and lifecycle transition commit atomically. No native controller or old lease ID is opened, no CLOSED timestamp is invented, and unresolved ownership still refuses a new source. Manus R66 requested the single transaction; the earlier payload R13 is retained as superseded and was not used for native acceptance. Local R29 passed53 initial receipt checks,27 existing control-journal checks and610 regression checks. Atomic R31 expanded receipt coverage to64 checks including actual process exits at startup/activation/close states, unavailable loss, missing old bank, failed receipt/boundary writes and migration before/after commits.

Payload R14 (raw tar7f956ab77a4cc959dfed3e403a06de424a7bc6d7d7d42c85e97d4eea5e9f5765) passed native ReconciliationR1:64 checks,12 SQLite integrity checks and55 private files at0600. Archive c77a6fece6329816561d0983be4afcaaa17826970110aac38e02f7bdaea65bb6. Independent archive review and final powered-off restoration are recorded separately. This gate loads no kernel module and does not authorize automatic recovery.

LinuxSourceWorkBarrier.cs is a PREPARATION component, not wired into the installed source. R34 passed25 deterministic blocked-task checks: bounded four in-flight work entries, first-fault preservation, explicit pre-fault/late-selection ordering, no work after stop, and actual-drain coordination. Canceling a managed wait cannot decrement work or claim native close. It grants no native authority by itself. Full owned Process/pipe runtime, raw-only deferred dispatcher, source-gate/journal-I/O split, residual raw handling and native blocked-I/O integration remain pending.

Manus R66 review SHA2563e62a4d8e7a5cfc06e79229847b6c37e48ea1d88dbc31749bbed7e15c8412de9. One correction still required before relying on its emergency-write proposal: current raw reserve v2 accepts typed observations and only RAW_BACKLOG_EXHAUSTED emergency records; it does NOT yet accept arbitrary malformed-frame or control-fault records. Do not claim this already exists. Plan a versioned bounded raw-ingress extension with the existing intent-before-frame persistence pattern, preserving old evidence unchanged.

Windows altitude mailbox read09:36:19.189403Z confirms the original sent message; no reply found. No resend. No production packages, services, firewall rules or physical-host protections changed. Final product-wide QA, source integration, signing/altitude approval and qualified deployment across sensors remain outstanding. Web UI remains https://cptnycdc01.cptnyc.com:7443 .


ReconciliationR1 independent review completed: 260 checks passed, including 9 immutable first-owner receipts, 12 schema7 databases, and historical bank records collected while the old bank path was absent. The owned zero-NIC VM was powered off and its baseline restored at 09:43:46.0979794Z. Receipt INDEPENDENT-RECONCILIATION-R1.json.

New preparation component LinuxRawIngressReserve.cs extends the existing intent-before-frame persistence pattern in a separate version3 file. It preserves exact bounded bytes before decoding, stores source generation and receive order, retains one explicit bounded emergency record, and allows residual raw records after a control fault while capacity remains. It keeps metadata in memory and reads raw bytes from the reserved bank on demand. Version2 evidence is unchanged. These raw receipts grant no typed-event or native access authority. Source linkage, a frozen/persisted forensic policy, typed classification and canonical dedup remain required before future integration. Missing policy evidence must not be replaced with current configuration after a restart.

R37 passed 47 local raw ingress checks, including malformed UTF8/JSON, zero-length and maximum-size frames, residual records, exact-byte reopen, conflicting owner/header rejection, deliberate corruption and four actual child process exits across raw/emergency intent/frame commits. R36 initially failed to compile four collection-expression arguments in the test fixture; R37 uses explicit byte arrays. No product behavior was changed by that test syntax correction. R38 published and sealed payload R15 (raw tar c2ab28b758124062f1700e487a6ebf4f1b7552ae288db01be3cd1958b0ef3f4e; manifest 2d59565e37493d7dc692452ee017b9a09a752cba67bfd15c2155680f9efc2fd9). IngressR1 native testing is running: 47 raw checks, 25 work-barrier checks and an owned 64MiB ext4 ENOSPC case. Native acceptance is pending its completed archive and independent verification.


IngressR1 native qualification completed successfully: 47 raw-ingress checks, 25 work-barrier checks, and real ext4 ENOSPC with five exact records plus a durable overflow marker while ordinary allocations failed. Archive ba8460ed69c0afeacb7623bb60a5b5429f87f48cc0a3904e37c76161b050faef; 9 saved banks. The owned VM is off/baseline restored at 10:02:53.9358052Z. The schema7/common-pipeline regression was rerun against R37 after the atomic restart change: all 610 checks passed. Independent v3 archive acceptance is recorded separately. Manus R67 was asked to review the next narrow source-policy/canonical-index bridge. No production changes or automatic native recovery were enabled.


IngressR1 independent binary/archive review passed 282 checks, including all nine raw banks, exact malformed/residual bytes, four retained negative artifacts and physical ENOSPC records. Receipt INDEPENDENT-RAW-INGRESS-R1.json. The verifier initially used the guest directory name capture for the copied archive directory pressure-evidence; correcting that archive path expectation accepted the unchanged native archive.


## 2026-10-03: Schema8 controlled source policy preparation

LinuxSourcePolicyJournal.cs adds explicit bank format, a canonical frozen five-field ForensicPolicy with SHA256, and native ownership phase. The existing logical source lifecycle remains compatible with v2; a separate source_ownership phase records PREPARED_NO_OWNER, OWNER_OPEN_ATTEMPTED, LINKED_OWNER or CLOSED. Logical OPEN alone never proves native ownership. A fresh verified v3 bank, source row, format marker, policy and prepared phase commit atomically before any open attempt. Preparation requires the same sensor identity. The future controlled runtime must persist the one-use open-attempt marker before its actual device open; current metadata methods do not themselves open a descriptor or grant native authority.

Control linkage now requires the attempted phase and valid frozen policy for v3, atomically records linkage/phase, and rejects an activation-write marker if policy is missing or invalid. Legacy format2 keeps its prior per-record policy behavior. A crash while only prepared records PREPARED_SOURCE_INTERRUPTED_NO_OWNER with no invented native-owner reconciliation; a crash after open-attempt keeps the existing explicit unknown owner receipt. No automatic opening or policy substitution occurs on recovery. All journal connections now verify foreign_keys=ON after enabling it.

R41 local tests passed: source policy45, control journal27, receipt-only reconciliation64 and regression610. Six actual child exits in policy tests cover prepared/open-attempt/link/write-start and both migration cuts; failed policy/ownership insertions roll back bank/source/policy together. R40 initially had a test local-variable shadowing compile error; R41 corrected the test name only. R42 published payload R16, raw-tar SHA25694b001a1bf699b39d8eeb21d64b3f9a3635ba9cbd2d59c212efc8fa4e3d3e725. SourcePolicyR1 Linux qualification is pending. Schema8 canonical ingress indexing, durable native pins, source gate/I/O split, owned runtime and deployment remain outstanding.

Manus R67 review (SHA2564fb08264bdb3e02b819fe62ad8731503a9ea4f9db85edc2fdaef43b524c2813d) supports a fixed policy per controlled source lifetime. Preserve existing dynamic legacy policy behavior. When implementing canonical dedup, store full unsigned cookies as canonical decimal TEXT and use a non-null positive-cookie partial unique index, not an Int64 or rounded SQLite numeric conversion. Exact duplicate comparison must decode against the FIRST committed context (collector/sequence/receivedUTC); later delivery context necessarily yields different AgentEvent bytes and must not falsely report a contradiction. Raw invalid/foreign data belongs in a separate diagnostic envelope, never a fabricated file-operation AgentEvent.


SourcePolicyR1 native gate passed 45 checks with 11 schema8 databases and 53 private files at0600. Archive e159fe13ed16865f685450272419feee63a7d60161af86840f665ac640fa2474. Powered-off baseline restoration and independent acceptance are still being completed. R43 has two unsealed changes beyond that native payload: it rejects CLOSE_UNKNOWN_OPEN for PREPARED_NO_OWNER, and extends the fixture to verify existing schema7 v2 banks migrate without fabricated source-level policy/ownership. The extended local policy fixture passes48 checks. Do not report those extra three assertions as part of the older native45 gate.


## 2026-10-03 - canonical ingress schema9 development

SourcePolicyR1 native acceptance completed: 45 checks plus 270 independent checks, archive e159fe13ed16865f685450272419feee63a7d60161af86840f665ac640fa2474; owned VM off/restored at 10:26:13Z. Local schema9 R49 canonical index passed 69 checks; R47 shared recovery 610, control 27, reconciliation 64 and source policy 48 passed. Canonical indexing preserves first raw receive context, exact frozen policy and unsigned cookie identity; invalid/residual input remains diagnostics. Replays reject changed stored context. Actual process cuts and real SQLite lock failures passed locally. Native CanonicalR1/real ext4 ENOSPC remains running, not accepted yet. Payload R17 SHA256 cc1578e5d468e74c39b084087d6c8585e483ecfbcd29db6176fb6560dc3caab5. R47 canonical fixture stopped at normal foreign-key enforcement during intended corruption injection; R48 made the offline corruption explicit and retained the negative log. No live sensor deployment or native runtime integration is claimed. Manus R68 concurrency review requested.


## 2026-10-03 - canonical acceptance and native work ordering

CanonicalR1 accepted: 69 actual Linux checks and 759 independent archive checks across 22 databases, 26 indexed deliveries, 15 canonical events. Real 64 MiB owned ext4 exhaustion produced SQLite FULL (13); exact raw and emergency boundary survived, then one canonical event recovered. Archive 8175771c8136becf984d942f98310b6b7abb9546d1972a08950c2b8d5618cc9f. Owned VM off/restored 11:00:14Z. No module/controller was opened by this gate.

R52 local schema10 adds atomic observation/completion/native-pin commit, one-use durable authorization and start markers, actual-return records, same-process finalizer exclusion and unknown pin recovery semantics. Conservative final barrier check refuses work if fault/stop wins during DB commit; only previously confirmed authorization may drain. Local native-pin fixture58 (six real process cuts) and barrier36 passed; shared610, canonical69, control27, reconciliation64 and source-policy48 regressions passed. This is metadata/concurrency qualification, not live device qualification or deployment. Manus R68 review archived SHA256 07d6755e62229b837c5fdd599b9460607a174941b4491644306ab9fb3c706525. Remaining: split expensive private I/O from journal gate, reconcile/publish unknown work without invented acquisition, bind exact retained controller and owned loader lifecycle, actual native controlled pipeline, Windows external/native gates and final qualified rollout.


## 2026-10-03 - private I/O and interrupted native work delivery

NativeWorkR1 accepted: 120 Linux checks (60 native pin, 24 paused private I/O, 36 barrier) plus 656 independent archive checks across 20 databases, 9 durable pins and 4 verified private copies. Archive ca6476592fa13f2b1ce26235ef6c10bc8231b659bc7eea60ccad79cb858a847d. Owned VM powered off and baseline restored at 11:40:15Z. No kernel module/controller in this metadata gate. Heavy allocation/hash/readback/fsync/enrichment now releases the journal gate while per-event ownership prevents finalizer races.

R59 adds LinuxNativeWorkEvidence version1 with raw/policy/event/collector/epoch/cookie/lease and durable authorization/start/actual-return ordering. Interrupted native work remains UNKNOWN. Only a committed bytes-verified private receipt can recover an actor artifact; unverified allocation/write intents retain null durable acquisition. Both original and completion preserve exact raw USER/process/PID and surface LINUX_NATIVE_WORK_OUTCOME_UNKNOWN. No historic PID/path/controller is reopened. New explicit server capability/acknowledgement LinuxNativeWorkVersion=1 prevents old-server silent loss. Actor preservation manifests and central possession events retain the same timeline.

Local crash delivery115 passed (seven actual child exits, linkage corruption and old-server acknowledgements); shared recovery610 passed at R58. R59 actor-manifest additions built without warnings. Actual isolated loopback server transport47 passed:14 original/completion events through authenticated HTTP, database, history and SIEM formatter; one verified actor copy uploaded and downloaded with matching hash; possession still reports native outcome UNKNOWN. This is not production qualification. Linux NativeWorkR2 is running235 checks on sealed payload R19 SHA25650554bb2a089acf78606f20b5b951921bff17b25e32c29306d9f6a524a0b9cc4; do not accept before archive verification and VM off/restored. Manus R69 review requested.

Remaining: bind private owned loader/pipes, verified lost-map handle and exclusive controller to serial native work; durable event-driven backlog dispatch and real native controlled end-to-end checks; Windows altitude/signing and remaining qualification; complete product QA and qualified sensor rollout. No production services, protections, server SQL storage or sensor packages changed in this continuation. Additional storage is authorized if required; current deliberate disk-full gates are isolated test volumes.


## 2026-10-03 - Linux recovery delivery accepted; owned process integration started

NativeWorkR2 passed235 on actual Linux, with930 independent archive checks:28 databases,17 pins,5 verified private copies. Archive bb0efa3f99213547a9a95ea5fa023b2654e49d6f0383acf3fcf5750f43ad9dd2; VM off/restored12:10:08Z. First independent verifier attempt hit Windows slash conversion in an archive permission lookup; corrected verifier examined the same immutable archive and passed. No product failure or native rerun was hidden.

Manus R69 review archived as linux-r59-interrupted-native-work-recovery-review.md, SHA2560bab1ca0bbca5e149402f6beb315c91532b9a39b7c6bb8c99342d90c9e07cc93. Existing work(done=0), atomic pin/work commit and stable completion IDs already implement durable preparation discovery; exact prepared event bytes are reused. Native work and artifact receipts remain separate. Server checks typed evidence and exact manifest equality; original kernel bytes remain on the sensor, so central independent raw re-decoding is not claimed. R60 additionally freezes native timeline across enrichment and original/completion; local119 crash/corruption checks and24 private-I/O tests passed.

R63 introduces LinuxOwnedLoaderProcess (not wired to the sensor): private Process, independent stdout/stderr readers, bounded4 frame queue and8192-byte stderr tail, one raw blocking activation write plus observable EOF close, retained pidfd signalling, actual exit/drain completion before disposal. Failure/cancellation is not native completion. Linux x64 syscall IDs were verified against Linux6.12.94; .NET10 Process.Unix confirms AnonymousPipeClientStream backing. Five real-child scenarios are prepared:normal, stdout/stderr flood, canceled wait, overlong frame and early exit. NativeWorkR3 is planned279checks using payloadR21; do not claim qualification before actual results. R62/R20 publish retained unsealed because fixture cleanup was strengthened before sealing R63/R21.

Windows targeted mailbox read12:05:08Z confirmed original altitude request remains in Sent; no Microsoft reply. No production rollout or SQL storage migration. Local development storage still has about60GB free on D: and1.86TB on C:.

Owned-process API references: https://raw.githubusercontent.com/dotnet/runtime/v10.0.0/src/libraries/System.Diagnostics.Process/src/System/Diagnostics/Process.Unix.cs (OpenStream); https://raw.githubusercontent.com/gregkh/linux/v6.12.94/arch/x86/entry/syscalls/syscall_64.tbl (424/434); https://man7.org/linux/man-pages/man7/pipe.7.html ; https://man7.org/linux/man-pages/man2/pidfd_open.2.html ; https://man7.org/linux/man-pages/man2/pidfd_send_signal.2.html .


## 2026-10-03: owned loader negative gate and correction

NativeWorkR3 passed the four preceding suites (239 checks), then failed on an oversized loader frame: InvalidDataException bypassed the IOException handler. Retained negative archive SHA256 cd735b8b40fe94ead378101a2e2c59cee3989be9b8b440cc429578cd6aaf2c5a; owned VM powered off and baseline restored at2026-10-03T12:31:36.9594705Z. This is not an acceptance. R67 explicitly handles the parsing exception and tests8192 residual bytes plus partial EOF; NativeWorkR4/R22 is running331 expected checks including deferred canonical delivery47.

R68 adds explicit libc close return/error capture for the actor controller, and retains a failed-close outcome across repeated Dispose calls. Eight injected controller-close checks passed locally (one-use, OS error, failed retry, canceled wait during blocked actual close). Real controller qualification pending. No production update, protection change or storage migration. Manus R70 focused owned lifecycle review requested.


## 2026-10-03: R4/R5 accepted lifecycle gates; integration in progress

- NativeWorkR4:331 native checks and1048 independent archive checks;29 SQLite journals,17 durable pins,5 verified private actor copies. Archive SHA256 c71c3717973304918fd849098bfd3013405e3c98201c6e0ddaaa8c6f962c4434. Owned VM off/baseline restored2026-10-03T12:49:46.3842264Z. Exact user/process/PID and stopped canonical delivery verified.
- NativeWorkR5:113 native lifecycle checks and151 independent checks. Archive SHA25641b9ffea89de14f0ff1ef933b9dc12ef5d0ec86ef5cd405e470271e4d0aef339. Owned VM off/restored2026-10-03T12:58:18.7925992Z. Real child processes/pipes/pidfd; explicit injected managed-close, reported-close-error and bind-failure cases. No actor controller opened.
- Manus R70 review SHA256 baaa6674bc6552475a86063f8b999985c8d8b61e75e152fad631a4551b13b5a2 identified independent framing-fault signaling, exact reader-buffer accounting, input-close failure blocking SIGTERM, bind-failure ownership and explicit descriptor-close outcomes. Owned loader now exposes the failure signal, exact bounded prefix, separate pipe remainder, retained input/pidfd close receipts, and startup binding failure state.
- R70 control/raw router23 local checks, native-pin60 and crash-delivery119 passed. Native work now requires committed activation ACK. Pre-ACK bytes remain faulted raw diagnostics; a later ACK cannot authorize them; persistence failure stops admission.
- R71 serial native worker47 local checks passed with injected controller transport, real private files, journal and common spool. Slow status does not hold the ingress/journal gates; stop waits actual method return; expired/draining kernel work remains unknown/unreleased; committed private bytes survive a DROP failure. SQLite return-receipt retry preserves actual return time and issues no new native operation. Latest warning cleanup not rebuilt yet.
- These are component gates; full owned managed source composition, real controller integration, Windows external signing/altitude/qualification and final product QA/deployment remain pending. No production change. D:58,843,500,544 bytes free; C:1,868,628,938,752 bytes free. Storage migration not needed for current work.

Primary Linux close semantics verified: https://man7.org/linux/man-pages/man2/close.2.html (do not retry close errors or equate descriptor close with outstanding I/O cancellation).


## 2026-10-03 R75 integration refinements

R75 builds without warnings. Controlled ingress28 and serial native worker52 local checks passed (injected native transport, real SQLite/private files/common spool). Exact bank identity is checked; first fault latches without SQLite and persists idempotently through failure/retry. Loss-mismatch and late ACK frames remain raw evidence and cannot occupy the activation record. Native authority independently verifies ACK loss equals linked ready baseline.

Manus R71 review SHA25670ba948480f960173f876db334b61c92d3eab6188f4deb83c93285b3c5cd6e6c reviewed critically: unchanged status already causes no SQLite update; two-stage durable authorization/start is retained because its final barrier check handles concurrent STOP. The new failed-start-commit test establishes zero device calls, retained authorization history, and explicit pre-native-start interruption. Structured method-return error/step evidence and complete owned runtime composition are still required.

Targeted Microsoft altitude mailbox check at2026-10-03T13:18:04.292469+00:00 verified sent copy and found no reply. No duplicate email sent. No production/storage change.


## 2026-10-03 native work receipt and server transport qualification

Linux native-work event v2 now preserves method stage, attempted/returned release, database confirmation, original return timestamp, and explicit error domain/code. Version 1 remains readable; batch acknowledgement requires the highest version actually present. A failed release can coexist with a verified actor copy without claiming native success.

- NativeWorkR6: 289 actual Linux fixture checks across 41 SQLite databases; 1,414 independent archive checks. Seven actor copies verified against original bytes. Raw bank ownership/digests, original user/process/PID, control admission, native method facts and publication linkage verified. Native transport/source facts are injected; this is not the integrated kernel runtime.
- Immutable archive SHA-256: 8e0851319ce868b163f328e1463b2169ab06c151fc0c48bc6fd449429e6741c0. Owned zero-NIC VM15011 powered off and baseline restored at 2026-10-03T13:49:40.3837104Z. R24 sealed payload: a6daa8cfd88d892db30582206e3d024f1ca794c8c8ab00e96f3945b25ffb5390.
- Actual isolated server transport R4: 73 checks, 22 original/completion events in two FIFO batches, one actor upload, exact API/database/history/SIEM evidence, downloaded artifact/manifest SHA-256 and possession linkage. Production was not changed.
- Negative transport R3 retained: fixture expected all 22 events in one request; production queue correctly capped the first batch at 20 events / 252582 bytes. Fixed fixture to verify every actual prefix and receipt; no production batching change.
- R78 local: explicit control/canonical/diagnostic/capacity disposition (33 checks); native worker shutdown waits for actual queued work and uncommitted return receipts (97 checks). Source owner must separately await the source barrier and actual controller close. R78 is not yet frozen or native-qualified.
- Remaining: full private owned-source runtime composition, durable preactivation loss/write evidence, actual controller integration/close, Windows altitude/signing gates, final three product QA passes and qualified sensor rollout. No all-sensor health or all-canary acceptance claim from these isolated runs.


## 2026-10-03 activation qualification and next integration changes

NativeWorkR7 accepted 292 actual Linux fixture checks and 1,708 independent archive checks; 49 schema11 databases, 26 durable pins and six verified private actor copies. Archive bbcd090caa93442508805369448140d1c10d168c352418712c4b955a1cc8cd7d. Owned zero-NIC VM15011 off and baseline restored 2026-10-03T14:20:52.4101343Z. Source/native method facts remain injected in this component gate; no production change. Latest sealed payload remains R25/R82 a59abc031427411e38fbb979089afe47f21217728cf2b0c0c9133080ae3c6327.

R6 independent aggregate correction retained separately as INDEPENDENT-NATIVE-WORK-R6-REV2.json: still 1,414 checks; 29 total pins, including the controlled-ingress pin omitted from the original aggregate. Original immutable archive unchanged.

Post-seal R83: actual activation command SHA-256 and monotonic sample/attempt/return linkage; write receipt SQL compare-and-set with exact duplicate comparison. Backward v1 proof readable; fresh activation requires v2 proof. Local 120 checks/17 cases passed, including clock step and competing receipt. Post-seal R84 compiles schema12 owned OPEN/CLOSE return journal and exclusive runtime admission; owned-method-specific qualification still pending. Full owned-source runtime, actual controller integration, final three QA passes and rollout remain pending. Manus R82 review archived; integration findings are being reconciled against actual code.


## Linux owned source integration - 2026-10-03 (R87-R92)

Implemented receipt-only recovery for pre-native journal failures (52 checks), immutable controller method receipts (92 checks), and shared worker capacity wakeups (8 checks). The assembled qualification-only runtime now builds: loader/map ownership, raw intake, loss sampling, actor capture, shared enrichment delivery, and actual controller shutdown. R91 compiled with zero warnings. Actual composed runtime qualification remains pending; earlier component checks do not establish it. No production sensor activation or deployment claimed. Target files are not hashed or preserved by default.


## Linux composed runtime R93 / payload R26 - 2026-10-03

Manus R91 review archived as r91-linux-r91-owned-runtime-implementation-review.md (SHA256 186df42e5f3ed957f2a610c82d76d9fac6381e7652d3b1fd4601d608ac378159). Corrected optional framing archive ordering to follow actual controller close; unconditional teardown first-fault persistence with preallocated emergency fallback; explicit no-controller startup terminal proof with no fabricated CLOSE call/time; tracked scheduling slot before native worker start; and defensive continuation of drain after dispatcher failure. Prepared completion tasks are currently result-only, so the review's faulted-callback premise is not a current reachable producer path; defensive individual fault observation was still added. Local owner-method tests: 110 checks / 11 cases; control ingress: 40.

Fresh qualification-only managed payload R26 SHA256 690d8da4e8803c49d9a1b0c53f5cdd2212299194cfe2fdf5c325fa442309aecf; 202 files / 191 cached, 911361 transferred bytes. Actual OwnedRuntimeR1 test is starting against pinned native R14 (77c99da022083c60472d466d5a70bada6983c3d03c3f5dec4d8abf3e000e39f0). No acceptance or production activation claimed yet. The 100ms lost-counter sampler detects observed changes; it cannot prove a gapless interval between samples. The native controller preserves an unresolved guest instead of rebooting/restoring it on a diagnostic timeout.


## Actual composed Linux runtime R1 and central transport - 2026-10-03

Actual R14 kernel + R26 composed runtime: five short-lived/root/unprivileged/renamed-name/replaced-path/deleted-path actor cases (five total), five original and five completion events, five exact preserved actor executables; 56 native assertions and 208 independent archive assertions. Native archive 8f898efe3a0a62a152c9322cf2d2396e22b49eff2fa88bd8d3fbcfae62fb94a9. Runtime source/controller close returned, journal pending zero. Original test retained a negative cleanup outcome because it incorrectly compared the entire changing host BPF inventory. Separate live reconciliation confirmed exact owned programs 243/240/242/241/244 and maps 56/53/54/55 absent, no module/device/processes; guest off and baseline restored 2026-10-03T15:27:09.4700156Z. Original negative artifact preserved; acceptance is INDEPENDENT-OWNED-RUNTIME-R1.json with explicit reconciliation.

Actual isolated server transport of these exact native events: 69 checks, 10 events in one bounded batch, five central executable/manifest uploads and hash-verified downloads, 15 stored events including server possession receipts. Exact user/process/PID and structured evidence retained through API, DB/history and SIEM. This is not production deployment or confirmation of all file operations/denied opens, Windows qualification, all sensors or all canary types. Fault-injected composed runtime gates, sustained volume, installed service integration and final three product QA passes remain outstanding. Mailbox checked 2026-10-03T15:20:31.543821Z; altitude request sent copy verified, zero replies.


## 2026-10-03 stopped raw recovery continuation

- Accepted actual composed Linux R27/R14 failure qualification: 85 native checks / 7 cases, independent archive review 177 checks. Archive SHA256 726658840a6671892e912289224c79a020a7d0c2a461e9529ddb44fc851d63e6. Owned VM off/baseline restored 2026-10-03T16:08:50.9847483Z. Includes actual EBUSY and post-ACK loss, explicitly injected loader failures; not full operation coverage.
- R1 negative diagnostic library path and R2 negative inherited preload injection retained. Production child environment sanitation remains intact; explicit pinned diagnostic launcher used for R3. Independent verifier first incorrectly applied artifact0600 to diagnostic shim.trace0644; negative retained and narrowed REV2 checks passed.
- R94 close-intent read now lives inside receipt retry, preserving the live owner on transient database read failure. Actual read-failure injection remains pending.
- R97 raw recovery: immutable input seal sidecar (rawv3/SQLite12 unchanged), read-only historical bank validation, physical-vs-index admission check, exact reindex and unavailable-executable delivery through existing bounded pipeline. No old PID/path/native capability is reconstructed. 75 local checks incl five actual process exits, full shared32 capacity, blocked owned callback, deliveryfailure retry; owner110/control40 also pass. Native qualification of these changes is pending.
- Full implementation, final three product QA passes and all-sensor rollout remain pending. No production changes or SQL migration in this continuation. Development D had55,865,597,952 bytes free at15:41Z; live SQL storage was not measured.


### R99 / frozen R28 recovery corrections

- Local 87 checks pass, including source-specific delivery ownership: concurrent closed sources A/B do not submit or await each other's work, duplicate same-source recovery is rejected, and an outstanding callback blocks new runtime admission even after work.done. Five actual process exits and shared32-capacity coverage retained. Build/release publish have zero warnings.
- Raw seal attempted after pump/dispatcher/native work drain before controller close; a seal write failure does not delay actual native close, and its original timestamp is retained for post-close retry. Raw recovery precedes optional framing archive. Existing raw v3 and SQLite12 unchanged. Historical missing seals still explicitly unresolved.
- INDEX_PREDECESSOR_PENDING was already a transient nonpersistable result (schema CHECK test passes); a terminal-classification allowlist additionally rejects unknown future states. Admission now attempts disposal of every inventory handle before admitting an owner.
- Frozen R28 SHA256 209c00e445a176c8901cb81d135b1ad575841106c5d2737816c2fdab53afdcb5. Native R4 qualification is running, not yet accepted. No production change.


### Actual Linux raw recovery and R5 pending gates

- Original R4 remains negative due to diagnostic checker KeyError on omitted optional LinuxNativeWork. Actual Linux managed87 checks passed. An independent60-check review accepted only the recovered-event subset: real monitored file access survived SQLite indexing failure, exact original User/Process/PID and inode retained, original/completion linked, never-acquired executable explicitly unavailable. No overall R4 or close-intent-case pass. Archive SHA256 520d1c8aebd6cf253d2d4ae21ff1ebd7d56174fe04fc9c6e337cb6775cb07d32; owned VM off/restored 2026-10-03T16:51:25.8410953Z.
- R100 adds only qualification probe admission-check command. Frozen R29 SHA256 84880d18499e964d8c0564fcb244c1427320afe1d7d156348996b4f79c3fec93. R5 is running three actual cases: corrected index failure, close-intent write retry, and optional malformed-prefix archive retry after real controller closure.
- Admission deliberately remains held until the same runtime commits its bounded diagnostic prefix, even though native closure and raw recovery have completed. This is visible retry state, not retained native capability; R5 qualifies this policy. Historical missing seals remain explicit unresolved.
- Microsoft altitude mailbox read 2026-10-03T16:53:39Z confirms sent request and no reply. No production changes or full product completion claim.


### R5 native recovery accepted - 2026-10-03

Actual native R14 + frozen R100/R29 passed50 checks across3 scenarios: raw SQLite index-failure recovery preserving exact User/Process/PID, actual close-intent write failure and receipt-only retry, optional65537-byte malformed framing-prefix archive obstruction/retry after controller close and raw sealing/recovery. Independent archive review143 checks passed; prior real Linux87 managed suite remains separately hash-linked to retained negativeR4 archive. R5 archive SHA256 aa4f4b2226fde128329220e9b0f76dc4bd59007f531842c38dc8f25212add03e. Exact owned BPF maps/programs and module/device absent; owned Linux VM off/baseline restored2026-10-03T17:00:41.4250531Z. Deliberate evidence-completeness admission block during optional-prefix retry was observed, then released after successful retry without repeated native close. These changes remain qualification-only; installed runtime integration, wider native operation/version coverage, final product QA and qualified rollout remain pending. Next work returns to Windows pending callback/STOP qualification.

### Linux immutable multi-target implementation in progress - 2026-10-03
Added LinuxControlledTargetSet, strict control-v2 parsing, source-control version binding, schema6 target identity, and raw-to-canonical source target-set validation. Exact immutable tuples use kernel device/inode and ordinal; actor executable identity remains separate. Legacy schema5 target identity stays unavailable and its optional-field serialization is preserved. Mismatched schema6 targets remain raw diagnostics with NATIVE_TARGET_BINDING_FAILED, stop the source, and cannot become canonical work. Existing qualified runtime explicitly remains controlled-v1 only pending the full new gate.
Managed checks: R101 target set25 plus independent Python digest/byte checks2; R102 protocol-v2 34, unchanged v1 protocol69, real database control journal31 (including process-exit migration cuts); R103 existing canonical ingress69; R104 target association31. R103 target-association fixture initially failed before ingress because its test bank capacity4 was below the existing minimum5; fixture corrected to5, negative output retained. All cited managed builds completed without warnings/errors. Native targets have not been established by these managed tests.
Native R15 source v8 compiled on exact Debian6.12.94 kernel profile with gcc Werror, both v1 and separate v2 loader/BPF objects. Archive a13c0de193f018103004133825fcdb97264b78cbab68f2d2ceaefca508383a6a. Native C encoder5 checks passed with all32 maximum-width tuples/IDs/epoch/lost, actual JSON ready2696 bytes below4096. No native module was loaded on the build host. The owned VMware R1 native gate is running separately; no acceptance claimed yet.
Manus R103 review3f569c5224192bc2adefe8f18e218fbebdc1459ae3e77bffb84cabbfda9a6ca5 retracts its earlier binary-size arithmetic and requests explicit inherited-map layout checks. Source v9 adds those four runtime layout checks and duplicate-ID rejection before provenance attachment; separate R16 build in progress. R15 artifacts remain immutable. Watched identity matches aliases and survives rename; same-path replacement requires a new closed/recovered source revision. This does not establish read/write/rename/delete hooks, earlier DAC denial, service integration, final product QA or production rollout. No live SQL migration or storage expansion performed.

### Linux controlled-v2 native R1 accepted; R2 failure gate running
R15 native R1 passed559 checks across9 cases and independent receipt334 checks. It captured38 actor executables with hashes matching the actual binary, including UID1000, across1/2/32 watched target identities, alias, rename and same-path replacement. Native archive55dc64b7305f4359434efb982d9675e0715e976470fbf05ea0a398bc1f0dbd0c. Exact owned program/map IDs absent, controller close returned, references0, module/device absent, guest off and baseline restored2026-10-03T18:43:55.0193122Z. R1 stores parsed records, not original stdout frames; do not claim raw frame bytes. Independent verifier initially rejected the intentional tar hardlink and counted the schema6 ready record as an actor; checks corrected to exact expected alias and separate control/event inventory. Original native archive unchanged, verifier negative receipt retained.
R16 source v9 adds runtime validation of all four inherited maps before provenance attachment; build passed, archive82d2b0142f3cf211486221199742c232d6b47e5b49bffaebebfa754372fe30c9. R2 is running85 owned native cases with separate explicitly injected fault library553ec0ca70db1d766cf38ec4acd73005100ba1d2c36b7f855f749b80aebbba9f; target O_PATH cleanup traced before process exit, every target pin and watch insertion index, freezes/layouts/ready output and observer/final-loss faults. No result claimed until returned. R105 actual native max ready2696 bytes parsed successfully; R106 parser fixture and server build passed zero warnings/errors. Full native fault acceptance, managed owner integration and product rollout remain pending. Altitude mailbox reread2026-10-03T18:44:59.841300Z: sent copy verified, no reply.

## 2026-10-03 Linux controlled-v2 qualification and wire compatibility
R16 native R2: 1,119 checks across 85 cases; independent 1,010 checks. All 32 target pin failure positions and 32 map insertion failure positions, map layout/freeze, ready output, attach and lost-counter errors exercised. Exact managed replay: 5 ready, 4 activated, 85 completion, 39 operation records. VM off and baseline restored 19:02:47Z.
R16 native R3: 143 checks across 5 cases; independent 213 checks. Executing actor rename/delete/replacement, four global lease slots plus retained fifth no-copy event and recovery, real/effective/filesystem credentials separately tested. 13 operation records and 12 byte/hash-verified actor copies; exact managed replay 5 ready/activated/completion plus 13 operations. VM off/restored 19:18:47Z. Archive SHA256 91c8bf4c03bf5e5672ecf518c458efed06083f9c93a671987b5e870d4dcb3238. Independent verifier first used incorrect trace field and normalized rather than native testMode name; negative scripts/receipts retained, native archive unchanged.
Added LinuxKernelTargetIdentityVersion=1 capability and receipt while retaining LinuxKernelVersion=1 for old deployed client compatibility. Schema6/normalized-v2 evidence now requires additive capability before POST and in ACK; old receipts cannot clear queued target evidence. Server build passes; actual HTTP/DB/history/SIEM and actor upload contract replay pending. Current controlled source runtime remains v1-only pending managed map validation and qualified integration. No production rollout, storage migration, full-operation coverage, or final three-pass QA claimed.

### Controlled-v2 central evidence transport accepted
Isolated transport R3 passed 443 checks: exact archived native 13 operations, 26 original/completion records plus one legacy schema5 event, two FIFO batches, 12 actual artifact uploads in bounded8+4 passes, 39 stored records including central possession. Complete event DB/API history and SIEM field equality, central artifact/manifest download SHA256, contradictory target rejection, capability/ACK failure retention and legacy compatibility passed. Source archive unchanged. This is archived native contract replay with common forensic processing, not live installed service collection. Negative R1 empty tar stream assumption and R2 single-pump12 assumption remain preserved with corrections.
Added independent parent-side read-only five-map layout/config/loss/watch-table verification in LinuxControlledMapSet; 357 injected transport checks pass, Linux native ABI gate pending. Runtime remains v1-only. API references: https://raw.githubusercontent.com/libbpf/libbpf/v1.5.0/src/bpf.h and https://raw.githubusercontent.com/gregkh/linux/v6.12.94/include/uapi/linux/bpf.h . Freeze is qualified in the pinned native loader; map-info alone does not expose a freeze bit.

### Parent map gate R1 negative retained; R2 prepared
Actual R30 managed map reader verified the five layouts and closed its read-only handles on the first1-target native source. Overall R1 failed an immediate resource-absence assertion; final wait reached native refcount0 and exact program/map/module/device absence. No activation occurred. Owned VM15011 off/restored19:49:18Z. Negative archive adb0c464ac5288ab52a8bb34a0eb3b3370bc3145dfd87b3c7d4b7740dece4e92 retained. R2 adopts the existing30-second bounded exact-ID release wait used by prior accepted native gates.
R104 Manus review received, SHA256 85535AAE783C21B5504D244B397CF769738B71AF6A8D1DCEE47ECFBD6822179A: no concrete map ABI/association blocker; native1/2/32, failure cleanup and loader-death-before-activation gates remain. Review inaccurately described initial >=40 native returned-length check as exact40. Verified pinned kernel syscall returns min(requested40,sizeof map_info); new reader now requires exactly40 and rejects oversized replies. Local R110377 checks pass. Separate versioned loader argv helper R10918 checks passes; runtime remains v1-only. R31 sealed source includes these changes.
Fresh altitude mailbox read19:44:54Z: sent copy verified, no Microsoft reply. Local development storage32.3GiB free D and1741.9GiB C; no storage migration or production change.

### 2026-10-03 qualified v2 runtime composition in progress
Parent map gate R2 passed32 native checks/3target counts (1,2,32),377 managed checks on Linux,192 independent checks and9 actual positive/negative probes. Exact archive84490bf5969165e58c53daf7113389c316ab4dc6e207521fcbaeae1087570806; owned VMoff/restored19:59:15Z. Source-map freeze assertion remains the qualified native loader responsibility.
R32 now exposes explicit controlled-v2 only through StartForQualification: independently prepared identities validated before runtime admission, source control version must equal launch version, all5 read-only map identities/config/loss/watch tuples verified before controller/activation, separate exact-ready SHA and canonical target digest persisted, owned-child liveness rechecked, map handles released on existing drain/cleanup path. Legacy v1 remains supported. R11127 launch/prepared-configuration tests passed. Installed LinuxAgent integration is still absent. Actual composed-v2 test is running on owned VM15011 under Invoke-VMwareLinuxOwnedRuntimeV2-R1.ps1 (managed R32/nativeR16).
A concrete server regression was found by an expanded HTTP test: action-filter SQL only recognized normalized Linux kernel evidence v1. It was corrected to versions1/2. The original negativeR4 is retained. Corrected isolated serverR3 transportR5 passed447 checks including exact action labels,14 OpenRequested originals,13 ForensicEvidence completions,zero fabricated completed-open events,12uploads/download hashes and39 final stored records. No production server changed.
Manus R104 corrected review stored separately (SHA256 AB23EF84CB2142D739552B66657BAC9342807C4D367005E58DC68532AF082BDA). R105 bounded runtime-wiring review pending; oversized original request was rejected without submission, accepted bounded request826899a4-d160-4f7c-8bc7-83400a65e58d.


### Actual composed Linux v2 runtime and startup-death qualification
R32 composed runtime/nativeR16 passed78 native checks and233 independent checks: five actual short-lived/renamed/replaced/deleted/unprivileged actor cases across two watched targets, five byte-exact executable copies, ten original/completion events, actual map/target/source linkage, private evidence and complete owned teardown. Archive041fd9209913832125a42750a8c03f562df04b3af8ef12bd9c1fa19e4fd4cafa; VM15011 off/restored2026-10-03T20:11:49Z. First independent checker used ordered-list comparison on role-ordered program IDs; its negative receipt remains intact. Corrected checker verifies unique exact set membership without altering native evidence.
Those actual composed-runtime records subsequently passed71 isolated authenticated server checks: ten original/completion records, five artifact/manifest uploads and downloaded hashes, fifteen stored records including central possession, API/history/SIEM equality and five OpenRequested history entries with final I/O result explicitly unknown. This is actual native evidence delivered to an isolated server; no installed production sensor activation or rollout.
ManusR105 review EBC103BFCA2BB7EE4AD0A77B282F70B6B87503AA540F2B0F196207D406AFE40A confirms qualification-only wiring and calls for preactivation loader-death gates and six-parent-map-descriptor accounting. R33 adds an instance-scoped optional qualification callback (no environment/global switch) at map-proof saved, separate lost-map opened, and linked prewrite. A native fixture stops the exact owned child through its retained pidfd, awaits exit and both drains, rejects ACTIVE/write/ACK/work, verifies actual descriptors before/after teardown, and checks stopped recovery using journal ready with diagnostic sidecar removed from its known name. The gate is running; no pass claimed yet. R33 payload298f1b70457944b1f9bd8ad84b8062ad4a43d3426610b67e4785fc03a8fe0268 builds without warnings/errors. R106 Manus review request667e193c-8d8c-4e67-97a9-b56516b5b0cd pending.
Development storage currently31.0GiB D and1741.9GiB C. No SQL relocation, VM resize or production change. Full operation coverage, installed integration, Windows latest-package version gates, final three product QA passes and qualified all-sensor rollout remain pending.


### Linux v2 preactivation child-death qualification accepted
R33 actual native gate passed32 outer checks across three deterministic pidfd-owned child-exit cuts: MAP_PROOF_SAVED (five map descriptors), LOST_MAP_OPENED (six) and LINKED_PREWRITE (six plus actor controller). Managed assertions19/19/24; independent saved raw/journal/descriptor/receipt review116 passed. Archive b26cc63ca59b41d8d1562dd2f14aeacc728597995bbfc186a92e45c33950e40e. Zero activation writes/ACKs, observed operations, canonical work, native selections or uploads. Pre-controller final counters remain null; linked final counter0 is an actual native completion sample. Linked OPEN/CLOSE returned, source closed, stopped recovery succeeded with diagnostic map-proof sidecar renamed out of its known path; exact journal ready independently reconstructs target digest. All owned native IDs and module/device absent; VM15011 off/restored2026-10-03T20:39:10Z.
Descriptor inventories were observed before and after child completion and empty after teardown; snapshots alone do not prove uninterrupted open-file-description continuity. Current code has one owner awaiting the callback, with no close/reopen path during that await. ManusR106 original review FE619116B436352E5A072D3130FA9203D4FDBF7C8DC17909EAEA58553FA45D38 retained; separate recalibration7BEB7F94649C55F598D3EEE988E38CA46E9FF7E85DC00C7BA3A1422BE4B6CF52 confirms no reachable current defect, additional dup/kcmp witness optional and no finite gate repeat required. No such optional syscall instrumentation was added.
Windows R48 remaining-version sequence has started, with unchanged sealed package12D644559A69A113450E615D40C337742829D990D76B51F1A78743867D01878E. Windows11 passed native, independent evidence and isolated server replay; archive1D56601BC6953AB116FD2079EC5F5EBB5B3D3783B2A4CD1763936D866A14B454, restored/off20:47:30Z. Server2019 is now active, DC queued. Scope remains delayed-first-touch/proactive retention, accessing-thread identity and ordinary-build diagnostic-command rejection, not full latest-package operation matrix or production deployment.
R107 Manus review requested for minimal Linux native SHA256 whitelist integration: existing held write exclusion/private actor snapshot evidence, exact event/process/exec linkage, path namespace/root ambiguity, versioned trust basis, attempted-open action semantics and immutable prepared-event trust evaluation. No native whitelist eligibility enabled by this request.
