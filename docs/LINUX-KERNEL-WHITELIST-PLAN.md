# Linux kernel SHA-256 whitelist integration

Status: bounded native and real server/UI qualification completed October 03, 2026; installed sensor integration and release gates remain pending. See the latest qualification entry below. Earlier sections document the original plan and are historical.

## Implemented foundation - October 03, 2026

`LinuxKernelActorMatchEvidence` now describes matching facts from a consistent original kernel event and its native work/private receipt. `ActorLease.AcquiredLinuxMatchEvidence` additionally checks the held private descriptor against that receipt. This does not construct a verified TrustActor, publish a rule, or confer live-source authority. It adds no field to existing event serialization and leaves EventTrust/TrustPolicy versions unchanged.

Local build R115 passed 108 checks against five accepted R32 native original/completion pairs plus explicit synthetic mutations, including PID/exec/tuple/source identity, exact path bytes, filesystem UID, missing or contradictory hashes, copy failures and private identity. A thousand repeated inspections preserved the original serialized evidence and disposition. These checks are consistency replay, not new native operation or suppression qualification. R35 is the sealed Linux payload prepared for actual private-descriptor verification; R34 remains retained and unexecuted after the explicit field additions.

Facts carry the raw/source device and inode separately from the private stable ID, exact strict UTF-8 path bytes and digest, initial-user-namespace credential encoding and FSUID, and explicit OPEN_REQUEST/NOT_OBSERVED semantics. The source observation, lease, receipt and native method must agree on device/inode/size. A matching hash remains evidence rather than a safe verdict.

## Live-source decision boundary - R108 review

Do not describe an out-of-lock loss-map sample as proof of zero loss through a later marker or disk commit. Evaluate the immutable policy result, obtain an Active-generation snapshot, read the actual retained loss map, then confirm the same Active generation under the short barrier. Require zero initial and sampled loss. Record the sampling bracket and its times as source health at the sample. No map access, hashing or persistence belongs under the barrier lock.

Loss or stop before the bracket completes prevents new suppression authority. A stop after the sealed historical decision does not retroactively change that decision. If the original was durably committed, replay its exact decision and policy revision. If the process crashes before original commit, stopped recovery must produce retained normal-alert evidence without evaluating a new policy. The in-memory preparation owner must not replace or upgrade a sealed decision on retry. The child evidence means exit was not observed at the sampled point; it does not promise continued life through fsync.

The versioned binding, current-source bracket, policy v3, server validation/capability and UI remain pending implementation. Manus R108 review: `89A3A5733FDEEFB0729D89F8FF6AF96CC486B526E5A2B60D76E5FD1C2D2E4319`.

## Evidence already qualified

The controlled-v2 source records the accessing task credentials and process/exec lifetime, exact actor backing-file device/inode, target device/inode and ordinary-exec association. The module holds its own file reference and write exclusion during its bounded regular-ext4 copy, verifies size and modification time, and records a separate ctime-change indication. The private snapshot is committed, reopened and verified by identity, length and SHA-256 before delivery. A copied filename or later procfs lookup is not an acceptable substitute.

The existing raw and acquisition objects remain report-only. Their `WhitelistEligible=false` means those objects alone do not grant policy authority. A separately versioned binding must state the additional validation and decision prerequisites; no historical raw object will be rewritten as eligible.

## Implementation modules

1. `RansomFree.Contracts`: add a versioned Linux kernel trust binding and EventTrust v3 basis `linux-bpf-lsm-module-backing-copy-v1`. Carry source session/epoch and exact ready/event fingerprints, process/task/exec association, snapshot receipt/hash, independently captured initial-namespace filesystem UID, exact actor-path byte digest and explicit path scope. Preserve unavailable wall-clock process start; do not manufacture ProcessCreatedUtc. Existing raw/acquisition schemas and Audit v2 remain unchanged.
2. `ActorLease`: expose an acquired Linux identity only from the already verified private descriptor and exact operation/acquisition tuple. Check descriptor identity again when constructing the binding. No PID/path reopen, no Audit correlation, no IMA hash substitution. Current normal prepared delivery reopens its committed private snapshot; that is distinct from historical stopped-source recovery, which cannot acquire new live-source eligibility.
3. `LinuxControlledSourceRuntime` and journal: construct source-health evidence only from the current owned, activated source with exact control linkage, healthy loss sample and no known interruption. The event's native-work/source identity must match that owner. A persisted OPEN row, loader PID, map ID or prior ACTIVE receipt alone is insufficient. Stopped recovery can reuse an already prepared immutable claim but cannot create a new eligible claim.
4. `ForensicPipeline`: add a narrowly scoped actor-aware original preparation callback for the controlled source. Evaluate trust once before collector.Begin and the durable original commit. Persist exact trust revision/digest/evaluation time with that original. Retry uses saved bytes; completion retains the original detection disposition. Failed evidence remains logged and unsuppressed. Existing shared capacity, raw journal, preservation and upload queues stay in use.
5. `TrustEvaluation`, `TrustPolicy` and `TrustEventEvaluation`: introduce an explicit Linux task-root path-plus-hash rule shape. Require process or account-and-process subject, SHA-256, Linux OS, ordinal path comparison and no target-path/parent/publisher/signer predicate in this first scope. Do not silently reinterpret old path-only or host-path rules. Map the new provider's open-request to policy action open only within its versioned basis; EventActivity and final outcome remain unchanged.
6. `TrustGovernance`: dispatch Linux Audit and the new kernel basis separately. Recompute tuple/path/hash/fsuid/source consistency from the stored event and acquisition evidence, then replay the exact historical policy revision. A submitted Verified flag is insufficient. A forged/mismatched claim must not suppress the underlying retained event. Keep the existing server resolution of completion/transfer classification through the original event.
7. Console and transport: expose the new matching semantics explicitly in rule creation and event-derived drafts. Use raw strict-UTF8 path text, never the quoted/truncated display. Advertise and require support for the new trust claim before sending/acknowledging it. Keep old event receipt behavior unchanged. New rule serialization needs an explicit policy version; existing v1/v2 rules and policies retain their exact meaning. Do not claim that an older sensor can enforce a new policy version; qualification and rollout must establish compatibility before enabling new rules.

## Matching limits

- Path scope is `TASK_FS_ROOT_UTF8_V1`, not a host-root identity. No Unicode normalization or case folding. Invalid UTF-8, unsupported path literals, truncation or an ambiguous trailing ` (deleted)` makes path matching unavailable.
- Mount namespace and filesystem root are not currently captured. Therefore target-path-scoped native whitelists remain unsupported until operation-time namespace/root evidence is added and qualified. Preserve the actual target path and stable identifier as forensic evidence.
- Use only the captured filesystem UID in the initial user namespace for account matching. Never substitute real/effective UID, process owner or an account from another observation.
- Require clean, equal pre/post ordinary-exec association; exact provider epoch, cookie, lease, tgid/tid, task/process start and self_exec_id; complete native copy; valid private receipt/hash; and current source eligibility. Unknown, tainted, incomplete, stale, interrupted or failed evidence remains logged and ineligible.
- A ctime-only change may describe rename. The current native COMPLETE result separately establishes size/mtime stability under write exclusion. Do not interpret an arbitrary changed-metadata flag as that guarantee without the qualified status tuple.
- A valid actor hash is a matching attribute, not proof of safe execution, unchanged process memory or benign intent.

## Caching and races

Reuse current private snapshot identity/hash validation and its strong change marker. Do not add a source-path or device/inode-only hash cache. The current native ABI does not export source mtime/ctime as a reusable cross-process cache key. Any broader hash-cache optimization needs a separately justified immutable executable identity contract; it cannot weaken this initial matching gate.

Preserve the existing single-owner native drain, actual controller return, raw retention and immutable prepared-event semantics. A policy refresh cannot change a previously committed original. Source exit during preparation must prevent creating new suppression authority, while already captured metadata/artifacts remain recoverable. The prepared-original callback must not hold a journal lock during descriptor/hash I/O or attempt to recreate a historical source capability.

## Required qualification

- Exact path plus hash match; same-name different bytes; same-path replacement; process/PID/exec-key mismatch; source epoch/cookie/lease/raw digest mismatch.
- Invalid UTF-8, ambiguous deleted suffix, path scope/namespace mismatch and unsupported target-path restrictions.
- Filesystem UID distinct from real/effective UID; unavailable credentials; unknown/tainted provenance; native no-copy/copy-failure; changed or replaced private snapshot.
- Provider interruption/loss before decision; missing activation; closed-source recovery cannot create eligibility; already prepared replay uses identical bytes and policy decision.
- Log-only retains originals/completions and matched rule while suppressing alerts/responses; no target-file hashing/preservation introduced.
- Client capability and receipt failure retains queued evidence; actual authenticated server/API/history/SIEM and evidence-upload consistency; tampered claims cannot suppress.
- Existing Windows, Linux Audit, v1/v2 policies and historical events remain valid under their original contracts. Finish the product-wide three-pass QA after implementation.

## Research and review

Manus R107 review SHA-256: `B19ACD76BB78A67EEDDEDF1BF03954B501A521DDF5A16AC0155FE7C533E27EA9`. This plan adopts the narrow task-root path-plus-hash boundary and records unresolved integration/compatibility gates rather than treating review as implementation acceptance.

Primary kernel references checked:

- [Linux 6.12.94 executable-file BPF kfuncs](https://raw.githubusercontent.com/gregkh/linux/v6.12.94/fs/bpf_fs_kfuncs.c)
- [Linux 6.12.94 write-access exclusion](https://raw.githubusercontent.com/gregkh/linux/v6.12.94/include/linux/fs.h)
- [Linux 6.12.94 d_path root and deleted-name semantics](https://raw.githubusercontent.com/gregkh/linux/v6.12.94/fs/d_path.c)


## Linux actor matching and source health qualified - October 03, 2026

R35 actor-match R2 passed 104 native and 264 independent checks on five actors, ten events and five exact actor copies. R36 source-health R1 passed 121 native and 290 independent checks on the same bounded case structure. Actual owned source/map/activation linkage, private descriptors and hashes, monotonic sample ordering, closed-source refusal, cleanup and safe VM restore were checked. All owned qualification guests are now restored and off. The R36 archive is `0f8664bcbe9e3416311f258dac38edbfeb4ad8cc7221957424fb76038532fdaf`; restored/off at 22:02:01.5678667Z.

The R35 R1 harness failed on an omitted nullable Trust property; the actual captured events were retained and the corrected R2 run passed. The first R2 independent checker compared equivalent timestamp strings; the corrected verifier uses exact 100 ns instants and tests a one-tick mismatch. Original failure artifacts remain intact.

Local R120 additionally passed 410 map checks including exact admitted ready-frame comparison. This comparison was added after the frozen R36 payload and has not yet had another native run. No native ABI changed. The source-health sample means zero loss at the sampled point within the same active generation, not continuous zero loss through disk commit. Its current qualification samples completed events; the pending policy integration must sample before the original decision commit.

Native Linux whitelist suppression remains disabled. Versioned binding, immutable prepared decision, policy/server/capability/UI integration, installed sensor integration and final product-wide QA remain pending. Manus R109 recalibration found no current ownership/race defect in the supplied source-health code; its remaining gate is the future exact provisional-to-final mutation guard and crash/replay qualification. Review SHA-256: `0DC63CB0679E3F5A80C03F5F096296BA64C2DE2BB4DC866DEA9EFBCDA4A106E0`.

Altitude mailbox checked read-only at 21:58:34 UTC: no reply. Production storage remains unchanged: approximately 13.12 GiB free, SQLite database approximately 189 MiB. No production deployment, SQL migration or VM resize in this continuation.


## Native Linux trust and server/UI integration qualified - October 03, 2026

R37 passed 142 native checks and 320 independent checks against five actual actors on Debian kernel 6.12.94+deb13-amd64/local ext4. All five original events and five completions were retained. Two path/hash (one also filesystem UID) rules produced log-only decisions. Three unmatched actors, including a familiar name with the wrong SHA-256, remained alerting and produced three preserved executable artifacts. All five actor bytes were acquired privately for hashing; only the three alerting actors were retained in the preservation store. No target-file hash or copy was introduced. Archive: `a230b0a26c0067a18872ad71ea41dcba4e9d6ab310133cec232c132be5dc4cd2`. Native resources were verified released and the owned guest restored/off at 22:55:12.0657307Z.

Shared EventTrust/TrustPolicy v3 adds exact process/task/exec identity, private actor receipt and SHA-256, filesystem UID, source/activation/target linkage, sampled source-health ordering and a digest of all nondecision original fields. The policy decision is frozen before original commit; retries cannot evaluate a new decision. Disk/crash-cut checks passed 25 cases, binding/mutation/compatibility checks passed 149, strict map admission 410. These local checks complement the actual native run; they are not new kernel operations. Existing raw/acquisition WhitelistEligible flags remain false because those objects alone confer no authority.

Server publication checks parser readiness and applicable active Linux source support. Native events need a new explicit durable receipt. Isolated SQLite/server tests passed 28 checks; existing whitelist regressions passed 214. The immutable R37 events passed 85 real HTTP/history/SIEM/actor-transfer checks, including all three central artifact/manifest hash-verified downloads. After a UI correction, server R5 plus the actual signed-in browser passed 86 transport checks and 15 browser checks: manual hash rule creation without an event, readiness refusal preserving a draft, successful publication, unchanged historical classifications, actual user/process/PID and hash visibility, and an event-derived disabled sensor-specific draft. Desktop/tablet/mobile layouts (1440/768/390) passed; the 390 layout was visually inspected. The first browser run exposed a generic-error message; its failure is retained. Only recognized readiness codes now receive specific UI messages. Unknown errors retain generic handling. A scoped local notification change permits v3 log-only suppression only when its event binding matches; changing PID prevents suppression.

Remaining: installed Linux source/service and capability lifecycle, broader kernels/operations and sustained-volume qualification; SQL Server execution of the additive capability migration; Windows assigned altitude/signing; distinct final three product-wide QA passes and all-sensor deployment/verification. The native source observes OPEN_REQUEST with outcome NOT_OBSERVED. It does not establish full Linux write/rename/delete or DAC-before-hook denial coverage. Production storage is unchanged and not a blocker (server approximately 13.12 GiB free; SQLite database about 189 MiB). No production deployment or storage move in this continuation.
