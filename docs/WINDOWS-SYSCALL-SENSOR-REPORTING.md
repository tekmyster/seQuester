## October 11: preservation-priority regression complete

All 23 release regression groups passed after the bounded ready-page acquisition priority change. The full staged actor/store/recovery fixture passed 349 checks; the dedicated priority mode passed 46 checks, including six new acquisition checks. Native all-nine live capture/preservation and central delivery remain unqualified for this change; production unchanged. A copied executable must remain tied to the original process PID plus creation time and verified SHA-256. Missing copies remain explicit evidence failures, not complete forensic events.

Receipt: regression-r6/results-after-ready-priority-r1/REGRESSION.json under the October 11 diagnostic root. Earlier invocation errors and failed live evidence are retained. The private test VM remains restored and powered off; no administrative sessions were closed before independent fresh restoration proof.

## October 11: actor executable preservation remains the minimum acceptance requirement

A process identifier alone is insufficient. Required evidence is an actor-executable copy tied to the native PID and process creation time, independently verified SHA-256, immutable source-event linkage and verified central receipt. Filename or later PID/path lookup cannot substitute for this binding. R8 remains a failed minimum-preservation run; its unavailable state is retained.

Implemented bounded acquisition prioritization in WindowsProcessAcquisitionStore.DrainReady: request the existing maximum 16-row native page, preserve currently retrievable snapshots first (newest first), then materialize every unavailable/expired discovery. The sequential cursor advances only after all page records are committed. Operation event ordering and identifiers are unchanged. This addresses old discovery records delaying collection of expiring bytes; it does not establish the cause of the missing R8 process snapshot or resolve native capture boundaries.

New controlled transport tests prove byte capture precedes older unavailable-record disk work, all records remain retained, exact PID/start binding survives, artifact SHA-256 matches independently, full-page cursor commitment and no recopy/reacknowledgement after fresh restart. Targeted mode --ready-priority passes 46 checks (40 existing thread-context checks plus six new acquisition checks). Full native-identity/store/recovery fixture passes 349 checks using its apphost. The first full invocation through dotnet/DLL failed before changed acquisition code because its owned crash-child launcher uses Environment.ProcessPath; failure log is retained. No product change was made for that invocation error.

Evidence: ready-priority-r1/{priority.log,full-fixture.log,full-fixture-apphost.log} under the October 11 diagnostic root. Production unchanged. Live qualification is pending; the previously restored private Win10 evaluation installation expired. Do not claim consistently preserved actor binaries or full rollout from controlled transport tests. Release regression after this acquisition change is running in results-after-ready-priority-r1.

## October 11, 19:49 UTC: restoration and current regression complete; live gaps remain open

All 23 release regression groups passed after the initial-scope readiness correction (results-after-startup-scope-r1/REGRESSION.json). The private live fixture builds with zero warnings/errors. The correction is not live qualified or deployed. Targeted diagnostics checks remain 103 decoder / 298 reporting-recovery / 55 actual native intake replay; authenticated retained-event HTTP replay remains 65 checks for four pairs and four actor binaries.

Added a reproducible read-only retained-archive verifier. Both guest manifests match every archived file byte count and SHA-256: R8 37 files, R6 56 files. Whole archive hashes match authenticated collection receipts and remain unchanged. Only explicitly listed transient SQLite shared-memory indexes are omitted. Receipts: each retained collection directory/archive-integrity-r1.json. Neither integrity acceptance nor native comparison establishes full live reporting acceptance.

Fresh independent restoration succeeded at 19:45:54 UTC. Administrator authentication, protected read/write, original minifilter image/hash, original boot flags, absent owned boot files/service and stopped baseline minifilter were checked after a normal reboot. The private zero-NIC guest was then shut down normally; original CPU limit/shares, 4096 MiB and nested-HV=false were restored. Diagnostic snapshot remains retained. VMware Guest Operations is the applicable access path; network paths are not applicable to this zero-NIC guest. Original controller 89988 was closed only after this separate fresh-session and exact restoration proof. Production unchanged.

Open: live reporting latency; repeat-use actor acquisition for R8 PID 1160 (no verified actor preservation); a fresh all-nine live publication and executable-transfer run; broader kernel/version and sensor qualification. The failed runs remain immutable. Windows evaluation expiry caused the planned shutdown and must be addressed through a valid evaluation/licensed test environment before more lengthy qualification; it does not explain the earlier missing executable or queue delays.

Restoration evidence: fresh-recovery-after-r8-r1/{withdrawal.json,cleanup.json,fresh-restored-access.json,final-restoration.json}. Integrity and partial native receipts are in boot-trace-managed-package-r6/lab-7f90b1958b754f2988661166cb59a2e5 and boot-trace-managed-package-r4/lab-d6d639b018824214927fd18d07a0203d under the October 11 diagnostic root.

## October 11, 19:46 UTC: failed-run evidence independently inspected; startup readiness repaired

The retained R6 and R8 archives include source databases/WAL and artifacts; only the transient SQLite shared-memory index was omitted. Independent read-only comparison passed all nine native truth records in each run, including process birth/PID, thread, owner/effective token, impersonation, operation, result, target and raw digest. R6 has eight spooled records with eight verified actor preservation records (four pairs). R8 has two spooled records and zero verified actor preservation records. R8 explicitly reports actor-image-or-verified-hash-unavailable. Neither run passed full live acceptance or central receipt.

R8 contains retained acquisition records for older processes, not a captured creation snapshot for producer PID 1160. The exact reason the new snapshot was not acquired remains under investigation. This is an evidence-capture failure, not permission to assign the older process's executable to the new PID.

Fixed a source readiness race: WindowsKernelSource installs its initial watched-file scope successfully before announcing connection, and initializes its acquisition-provider workers before that announcement. The private actor harness can no longer use that announcement to launch before the initial scope is installed. Current fixture build passed with zero warnings/errors; live qualification is pending and regression is rerunning. This does not establish the cause of the R8 acquisition failure.

Windows System event 1074 establishes that WLMS initiated the private guest shutdown because its evaluation license expired. This explains the shutdown only. Fresh R8 task cleanup and new-boot verification succeeded. Normal restoration has withdrawn callbacks, stopped the ordinary minifilter, restored its original image, disabled the boot observer and removed its extension; normal reboot requested. Post-reboot cleanup, fresh baseline verification and shutdown/resource restoration are pending. The original administrative session stays open. Production unchanged.

Evidence under the October 11 diagnostic root: package-r6/lab-7f90b1958b754f2988661166cb59a2e5/independent-partial-r1.json; package-r4/lab-d6d639b018824214927fd18d07a0203d/independent-partial-r1.json; package-r6/lab-6868a7491696417fac3a2c4460fb7f9b/guest-shutdown-events.json; fresh-recovery-after-r8-r1/withdrawal.json. Package names above abbreviate boot-trace-managed-package-r6/r4.

## October 11, 19:33 UTC: current reporting diagnostics and regression verified

Added queue writer stage diagnostics that can be read without the queue lock. They distinguish connection open, transaction begin, queue reads, payload insert, durable commit and connection close. Event bytes, FULL durability and conflict rejection are unchanged. Targeted checks passed: 103 decoder, 298 reporting/recovery and 55 actual native intake replay. This diagnostic change is not yet live qualified.

All 23 release regression groups passed in results-after-write-diagnostics-r2/REGRESSION.json (1,920 PASS output lines, including summaries; not a distinct-test count). The earlier r1 invocation incorrectly passed the server EXE to DLL-based test launchers; its three BadImageFormatException failures are retained. Correcting the test argument required no server code change.

The current client build also passed 65 authenticated HTTP replay checks for eight unchanged retained native events and four preserved actor executables. Server downloads match SHA-256 and ten source database/WAL/artifact/manifest files remain unchanged. Receipt: http-retained-current-r1/acceptance.json. This is retained-evidence transfer qualification, not fresh live delivery or all-host deployment.

The private test VM remains in Windows recovery. Its original administrative controller remains open. Evidence collection and removal of the temporary boot configuration are pending. Production is unchanged; the failed live reporting timeout remains unresolved.

## October 11, 19:20 UTC: live trial failed; guest requested shutdown; recovery underway

Retained producer output confirms all nine R8 operations passed with zero native loss (PID 1160, TID 3144, process birth 134362186857733250). The reporting gate failed after one original/completion pair. Source progress shows intake and reporting stopped; subsequent cleanup finished naturally. Fresh downloaded exit/result files at 19:11 UTC agree on the timeout exception exit and NoTerminationUsed=true. This is not all-nine publication or central receipt acceptance.

The VMX log records guest-requested PM Soft Off at 19:15:27 UTC and cleanShutdown=true. No forced reset/power-off or boot-observer unload was used. The underlying Windows shutdown cause is still unknown. Both durability-probe attempts failed before command dispatch and therefore changed no filter state. The archive attempt rejected collection while owners were still active; no archive success is claimed. A normal power-on was requested once at 19:19 UTC for evidence collection and restoration; original administrative controller remains retained.

Measured host CPU use is 43,894/43,900 MHz; resources were not increased. A longer private reporting window (60 seconds default, explicit maximum 900 seconds) and per-event publication times were added to the qualification harness and built successfully, but are not live qualified or deployed. Existing strict timeout failures remain retained. Product queue durability remains FULL.

## October 11: HTTP replay integrity gate passed; fresh live reporting still fails

The final retained R5 HTTP replay passed 65 checks across four native original/completion pairs. The isolated packaged server rejects contradictory PID and native-record-digest linkage, preserves all eight event payloads byte exactly, receives all four preserved executable artifacts, returns matching SHA-256 downloads, and honors verified receipts on restart. SHA-256 of ten source DB/WAL/artifact/manifest files was unchanged before/after replay. Receipt: http-retained-r5-r3/acceptance.json. This is actual-evidence authenticated HTTP replay, not fresh live HTTP delivery or production rollout.

The managed-live-r8 runtime was verified (422 files) in a separate protected directory and a new administrator session proved read/write access. The nine-case owned worker launched once. Actual progress records show original durable-spool publication taking over 25 seconds and completion publication over 18 seconds; the all-nine 60-second reporting gate failed. Retained WAL alone has not resolved live performance. All raw/native truth and failed-run files remain retained. Collection, independent comparison, safe restoration and further diagnosis are pending. No production change or whole-specification completion is claimed.

## October 11: unchanged native evidence passed authenticated HTTP replay

Added tools/WindowsSyscallHttpReplay using the existing ManagementClient and EvidenceUploadQueue. The fixture seeds a new isolated endpoint with the original sensor ID and a new private credential; no production or old credential is read or changed. It replays immutable retained native publications without rewriting identity or evidence fields. The only client change is a fixture friend-assembly declaration; the frozen live R8 runtime remains unchanged.

The retained R5 run's four complete pairs passed 53 checks: all eight event records persisted byte exactly, all four actor artifacts and manifests uploaded through authenticated HTTP, fresh authorized downloads matched the recorded executable SHA-256, anonymous access failed and restart honored verified receipts. This is replay qualification of actual retained native evidence. It is not fresh live HTTP delivery, all-nine capture acceptance or a production deployment pass. Receipt: http-retained-r5-r1/acceptance.json under the October 11 diagnostic root. The preparation power request is active; all-six callback/raw-queue preflight passed and the R8 runtime is still staging.

## October 11, 18:42 UTC: private guest standby diagnosed and normally resumed

The actual VMX log records ACPI S1 standby at 18:31:35 UTC. Tools error 3016 was observed after standby; it is not evidence of a capture-driver crash. The managed-only R8 attempt had dispatched only an owned input-directory command, not an actor test. Its original response and files remain retained; the next attempt uses a distinct input directory and does not repeat that command.

A fresh console image was inspected and one Enter key was delivered through the VMware keyboard API. Tools returned to guestToolsRunning at 18:42:38 UTC. No reset, power-off, boot-observer unload or production change was used. A bounded system-required preparation request is being established for staging and testing without changing the power policy. The original administrative controller remains open; the full live reporting and central executable-receipt gate is still pending.

## October 11: managed-only retest preflight corrected

Two read-only preflights stopped before staging or launching another actor: one referenced a missing manifest property, and the next treated the legacy diagnostic mirror queue as the managed raw intake queue. The control executable SHA is now read from the immutable Files entry. The actual 56-byte SQ_SOURCE health reply is queried separately, with its version/size, raw queued count and loss count verified. Legacy mirror records remain preserved and are not destructively consumed.

All 23 release regression groups passed after the retained event-spool change. Targeted counts are 103/294/55. The managed-only candidate changes four assemblies in a new protected runtime directory; old runtime/evidence and the original admin controller remain retained. No second actor has been launched by the failed preflights, and production remains unchanged.

## October 11, 18:15 UTC: live reporting still fails; event-spool lifetime fix prepared

The managed-live-r6 controlled trial captured all nine native cases and independent producer truth, but the 60-second all-pairs reporting gate failed. Final diagnostics show eight events (four pairs) and a durable event-spool write taking over 18 seconds. Raw journal lifetime alone did not establish acceptable publication latency. Central receipt remains unverified. Failure logs, all original files and the original administrative controller are retained.

The event spool already had an explicit retained-WAL option for Linux owners. The option now permits Windows owners without changing default behavior, synchronous=FULL, operation connections, deduplication or normal checkpointing. Only the private live fixture opts in; production Windows service ownership/disposal has not been changed. Seven additional tests verify exact committed bytes from a fresh connection, stable polling/deduplication, disposal and restart. Totals passed: 103 decoder, 294 reporting/recovery, 55 actual native intake replay. Managed-live-r8 / package-r6 is built but live qualification remains pending.

Failed-run compression also encountered a locked SQLite shared-memory cache file; this is a collection-tool failure, not permission to discard the original databases or WAL files. The failed event logs and producer truth remain independently retained. The release regression gate is running again after the spool change. Production unchanged.

## October 11: regression rerun after shared shutdown change passed

All 23 release groups passed again after the shared shutdown drain change. Targeted totals remain 103 decoder, 287 reporting/recovery and 55 actual native intake replay. Immutable managed-live-r7 / boot-trace-managed-package-r5 contains the new drain; it is built but not live-qualified. The current retained lab controller uses managed-live-r6 / package-r4 to isolate the WAL lifetime performance fix. All 422 files were verified and a separate fresh administrator session confirmed protected read/write and primary hashes before boot installation. Production remains unchanged.

Evidence: regression-r6/results-after-shutdown-r1/REGRESSION.json, fresh-staged-access-r3/fresh-staged-access.json and boot-trace-managed-package-r5/manifest.json under the October 11 diagnostic root.

## October 11: shared shutdown drain added; frozen live candidate unchanged

WindowsSyscallSource now reuses the existing AsyncDisposeOnce component. Repeated/concurrent callers await the same intake/reporting completion before journal and cancellation resources close; failures retain the original producer error for all callers. Ten additional checks cover both producers, 32 callers, journal access during drain, final closure/reopen, and failure cleanup. Targeted totals: 103 decoder, 287 reporting/recovery and 55 actual native intake replay.

The active lab still uses immutable managed-live-r6. The shutdown change is isolated in the next managed-live-r7 candidate and has not been deployed. The earlier 23-group release regression receipt predates this final lifecycle change; a follow-up gate is required. Live all-nine publication/central receipt and general coverage remain pending.

## October 11, 17:50 UTC: release regressions and actual event UI verified

All 23 existing release regression groups passed (1920 PASS lines, including fixture summaries). Native forensic fixture passed 95 checks using its unsigned apphost. Evidence transfer passed 313 checks; async native-source disposal passed 9 checks with 32 concurrent callers. Managed deferred-token contracts passed 4 positive and 15 negative cases. These do not qualify the new native source on every supported kernel.

The UI replay of an actual retained R5 event passed 10 checks. Screenshots at 1440, 768 and 390 pixels show effective User SID, actor Process path and PID, separate owner/effective tokens, impersonation=true, denied NTSTATUS, raw digest, actor SHA-256 and preservation linkage. This is actual native evidence rendered in an isolated DOM, not a signed-in production UI check.

Initial supplementary commands used an inappropriate signed dotnet launch for the unsigned apphost test and omitted required UI seed/output arguments; failed setup logs remain retained. Corrected forensic and syscall UI invocations passed. Other seed-dependent supplementary browser checks remain unexecuted correctly, rather than being marked green.

Two staging attempts encountered intermittent VMware API InvalidState responses; no boot callbacks were installed. Fresh authenticated administrator baseline validation and normal shutdown/resource restoration completed before old controllers were closed. The revised lab controller writes durable command responses and polls the exact owned process. Only pre-upload API initiation may retry; actual HTTP upload or command execution is never blindly repeated. Current live integration acceptance remains pending; production unchanged.

Evidence: regression-r6/{verified-summary-r1.json,results/REGRESSION.json,ForensicFixture.apphost-r1.log,EvidenceTransferFixture.log,syscall-ui-actual-r1/} under the October 11 diagnostic root.

## October 11, 17:29 UTC: nine native cases verified; reporting bottleneck under repair

Independent comparison of the R5 live trial confirmed all nine controlled native operations, exact PID/process birth/accessing TID, process-owner and effective-thread tokens, target/result and zero native loss. Four original/completion pairs reached the durable sensor spool and reference correctly hashed actor executable copies. Five native intake records remained pending. The strict 60-second all-pairs publication gate failed; no central receipt or deployment pass is claimed.

The dedicated receiver completed every raw acknowledgement. Stage diagnostics identified slow reporting persistence. The new journal lifetime connection retains WAL files between polling operations while keeping synchronous=FULL, separate operation connections, and normal checkpoint policy. Disposal follows producer shutdown. Targeted checks passed: 103 decoder, 277 reporting/recovery and 55 actual native intake replay, including committed independent reads, retained WAL, disposal and restart recovery. Live performance improvement remains to be verified by immutable managed-live-r6 / boot-trace-managed-package-r4.

A separate fresh administrator session verified restoration of the previous trial, protected read/write, original driver image/hash and boot configuration, removed owned boot components, normal shutdown and original VM resources at 17:29 UTC. Only then was its original controller closed. The current trial remains isolated; production is unchanged. General thread/target coverage, denied-open qualification, authenticated HTTP delivery, new-source trust matching, other Windows versions and deployment remain open.

Evidence: boot-trace-managed-package-r3/direct-file-read-0aa1f8637eec4bdb9a6b61d8b16b22a1/extracted-r1/candidate-r5-partial-live-inspection-r1.json and fresh-controller-restoration-r6/final-restoration.json under the October 11 diagnostic root.

# Windows syscall reporting and executable evidence

## Implementation

The existing architecture is retained. The experimental syscall source adds a
separate observation alongside the minifilter, rather than claiming a syscall
return is a filesystem completion.

* `WindowsSyscallObservation` carries native source UUID, raw record SHA-256,
  PID, thread ID, process creation FILETIME, separate process/effective tokens,
  entry/return ordering and raw NTSTATUS. A retained-object target name is
  explicitly a later query. Missing metadata remains unavailable.
* The native device exposes source health, nondestructive peek, exact UUID and
  sequence acknowledgement, and retained target-name query. Target references
  survive through acknowledgement. Native loss counters remain visible.
* `WindowsSyscallJournal` commits the original raw bytes and validated
  observation before acknowledgement. FULL SQLite transactions protect intake
  and the immutable original/completion pair. Retries preserve IDs and payloads.
  Capacity is 8,192 pending records with a 128 MiB reservation limit; 4,096
  recent completed observations prevent repeated native acknowledgements from
  causing repeated collection. Finished pairs are removed from this journal
  only after both events reach the durable management spool.
* `WindowsStagedActorStore.CaptureSyscall` links only an independently committed
  proactive executable snapshot from the current minifilter provider and epoch
  with the exact PID and process creation FILETIME. It does not reopen a later
  PID or executable path. Source file identity and copy identity remain separate.
* Actor acquisition version 2 records the syscall source UUID/raw hash and
  existing acquisition provider, epoch, generation, candidate, source identity,
  copy interval, private snapshot identity and hash. Snapshot verification is
  cached; every reopened descriptor is checked against its stable identity,
  size and change marker. The forensic collector checks the acquisition hash.
* The source gives the independent snapshot receiver up to five seconds to
  commit first-use bytes. If unavailable, it still emits the original tokens,
  process lifetime, operation and an explicit hash/preservation failure.
* The existing forensic collector supplies SHA-256, Authenticode, PE metadata,
  protected actor preservation, matching preserved hash and chain linkage.
  The existing upload queue transfers executable bytes and manifest centrally.
  Target bytes are neither hashed nor preserved by this integration.
* Server capabilities and every delivery receipt must explicitly acknowledge
  `WindowsSyscallVersion=1`. Acquisition version 1 remains compatible. Older
  servers cannot cause these records to be removed from the sensor queue.
* Agent integration is opt-in with `windows-syscall.enabled`. It requires an
  enrolled spool and installs no driver, changes no boot setting and modifies
  no security policy. Proactive snapshot flags must also be enabled to provide
  actor bytes. An absent source produces a reporting-health failure.

## Verification completed

### October 11 follow-up: recovery fixes and live qualification in progress

The follow-up candidate rejects damaged or misplaced actor index records
individually, retaining valid committed records and reporting rejected recovery
records. Process creation FILETIME is range checked. Unusable native target names
retain their raw bytes and reply SHA-256 with an explicit unavailable display
name; historical serialized observations remain compatible. Native target paths
are mapped only through known device prefixes or absolute DOS paths. Source
startup diagnostics identify the failed acquisition stage and raw HRESULT.

Software verification passed 103 decoder, 269 reporting/recovery/negative,
55 actual transport replay, 64 actor fixture, 10 UI fixture and 156 server
regression checks (657 total). Actor acquisition in these fixtures is synthetic;
the counts do not establish live acquisition or production deployment.

The first simultaneous live trial failed before the operation producer started.
The private guest's older baseline minifilter supported health command 3 but
rejected binding, staging and acquisition capability commands 20, 12 and 35
with HRESULT `0x80070057`. Its original image and settings were retained;
normal restoration and fresh privileged access passed. The second private trial
uses the already qualified capture driver in a separate protected directory,
retains the original driver image, and will restore its original service path.
Live qualification remains pending until the actual operation/token truth,
process lifetime, source executable identity, command line, parent identity,
preservation hash and isolated central download all pass.

Trial artifacts are under the owned local
`sequester-windows-syscall-observer-20261011-r1` directory. First trial:
`boot-trace-managed-package-r1/lab-d68a1ab5357843b1a90070dc5d0da0cd`.
Second trial:
`boot-trace-managed-package-r2/lab-fa5a556a680c4eeaacd36e8c00985baf`.
The original administrative session remains open for the second trial.

The second trial also exposed a controller defect: the original service image
uses a `\SystemRoot\...` path, which must be expanded before hashing. This is
corrected, and nonterminating hash errors are no longer accepted as baseline
data. The capture continuation passed fresh privileged authentication, protected
directory read/write and loaded-driver hash checks. VMware subsequently lost
its dispatch response during Tools heartbeat timeouts. Retained worker files
prove that dispatch occurred despite the missing response. The newer controller
records uncertain dispatch before waiting, forbids duplicate dispatch, and can
resume a directory-access check without repeating driver selection.

The capture driver was normally unloaded and its original service path and
original binary hash were verified through a fresh privileged session. The
worker is still extracting its runtime; no live acceptance result exists.
The boot session remains retained until worker completion and full restoration.
Windows boot time and system events plus the VMware log show no new reboot or
crash during the Tools timeout. Host CPU was 43,561 MHz of 43,894 MHz at the
resource check, so the private VM's 1,000 MHz limit was not raised. CPU pressure
does not establish the timeout's complete cause. Future staging should finish
runtime extraction before callback attachment.

The original nine independently captured Windows 10 native operation/token
records pass 103 decoder checks and 182 reporting checks. Reporting checks cover
restart recovery, immutable retry, wrong PID/user/birth, native lifetime keys,
unavailable target metadata, failed-operation outcome, missing executable and
linked original/completion spool entries. These target replies are synthetic
transport inputs, explicitly distinguished from native records.

The separate actor integration fixture passes 62 checks using actual signed
Windows `cmd.exe` bytes and actual captured token records, with synthetic
acquisition transport. It checks exact process-generation linkage, PID reuse,
provider epoch mismatch, source/copy identities, real signature validation,
matching preservation hash, unchanged-byte caching across 32 operations,
replacement rejection, restart recovery, old-server receipt rejection, local
server persistence, central artifact download, and real candidate server HTTP
capabilities, upload worker and event-history identities.

## Remaining qualification

These fixture results do not establish complete production integration. The
new native queue and retained-name transport passed nine live Windows 10 cases, including exact peek, wrong-key rejection, retained target names, correct acknowledgement and zero loss. The actual transport output passed 55 additional managed replay checks.
The native source remains limited to one explicitly armed owned thread and
registered handles. General honeypot targeting, unowned/multiple-thread
coverage, unattended boot compatibility, lifecycle/resource qualification,
live proactive acquisition plus syscall reporting, and qualification/deployment
across the four production Windows sensors remain open. No production sensor or
management server has been updated by this integration work.

## Final acceptance and restoration

The private native trial is safely restored with fresh privileged access and original resources verified. UI token details passed 10 fixture checks, Windows OS/action filters and old action-index migration passed candidate API checks, and 156 server regression checks passed. The new source does not yet participate in hash-based whitelist/trust validation. Simultaneous live managed intake and proactive acquisition remains an explicit qualification gate. No production deployment or production UI verification is claimed.

## October 11: simultaneous live test failed; standby diagnosed

The R3 continuation ran the actual syscall and proactive acquisition sources with the qualified capture minifilter. Independent producer truth records show denied read and write controls acknowledged, followed by a denied append whose acknowledgement timed out. The producer exited with failure. The initial failure artifact contained no published events. This does not qualify native token matching, executable preservation or central receipt for this simultaneous live run. No production deployment was made.

The later management outage was traced to Windows standby, independently supported by the VMware ACPI S1 log at 15:25:51.134 UTC and the preserved memory image: its guest clock is 15:25:51, CPU 0 stack candidates include HalpAcpiPreSleep/HaliAcpiSleep/PopTransitionToSleep, and KiBugCheckData is zero. The retained disk/memory snapshot and downloaded memory SHA-256 are recorded under the October 11 diagnostic directory. This explains the management outage, not the earlier failed reporting test. Console wake restored VMware Tools; guest process starts and uploads were still rejected at the next check. Both original administrative controllers remain retained pending actual restoration and fresh privileged checks.

New candidate diagnostics expose receiver and dispatcher stage, sequence/event linkage and monotonic elapsed time. The private harness retains incremental health/progress logs through source disposal and holds a thread-owned system-required power request for its test lifetime, then releases it. No permanent Windows power policy is changed. The updated fixture builds with zero warnings/errors; the new diagnostics and power request still require a live trial. Original 657 software/fixture checks retain their previously documented scope.

### October 11 additional evidence and scheduling repair

Completed failed-run artifacts were retrieved after console wake. Read-only inspection of the durable intake independently matched all three attempted operations against producer truth: exact PID/start time, thread ID, operation/result, owner token, effective impersonation token, target path, raw hash and zero native loss. One original/completion pair was eventually delivered to the sensor spool. Both linked event records identify the preserved executable whose bytes match the recorded SHA-256 and exact version-2 proactive acquisition binding. The other two records remain pending. This is partial failed-run evidence, not all-nine acceptance or central receipt.

The syscall receiver previously used a shared thread-pool task despite synchronous native calls and SQLite commits. It now uses a dedicated receiver thread and synchronous cancellation-aware poll waits, matching the existing minifilter scheduling approach. The raw commit-before-ACK order and immutable publication pairing are preserved. New scheduling checks passed; targeted counts are 103 decoder, 271 reporting/recovery and 55 actual native transport replay checks. Debug and published Release fixture builds are clean. This addresses a concrete scheduling weakness; the live delay has not yet been proven resolved.

The guest stopped during recovery and a normal power-on entered Windows recovery/startup options. At 16:42 UTC a separate fresh recovery controller completed normal reboot, cleanup, fresh privileged protected-directory access and exact driver/boot/resource baseline checks, followed by normal shutdown. The diagnostic snapshot remains retained. Stale controllers were closed only after that external proof, without treating their internal flags as successful restoration. Candidate managed-live-r5 is packaged as boot-trace-managed-package-r3; its new controller stages and verifies all runtime files before boot installation/callbacks. A new live acceptance test remains pending. Production is unchanged.
