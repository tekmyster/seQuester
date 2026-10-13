## October 12: decoy-job History UX cleanup deployed

## October 12: response, whitelist and Wazuh integration in progress

The user authorized completion of Active response, Additional whitelist controls, Linux hash-based whitelisting and Wazuh integration. This supersedes older entries deferring Wazuh discussion. New server/sensor capabilities are not yet deployed. The owned Wazuh TLS receiver, Filebeat input/index and rule feed are active for manager-local controlled tests only. Production seQuester senders are not enabled.

Verification: 66 advanced trust/policy checks; 218 whitelist checks; 130 Linux evidence checks with synthetic source frames and actual held descriptors; 16 response journal/Windows process/capability checks; 19 receiver tests on Linux; 18 loopback TCP/TLS receipt checks; 22 desktop/mobile browser checks. All 28 release groups passed before the last transport-only candidate change. Owned-child Windows termination passed through the legacy adapter; native file-event response remains unqualified. Manager-local Wazuh detection, suppression and indexing passed. Cross-host forwarding still stalls after TLS negotiation, including under the actual NetworkService account. Temporary source grants were rolled back, tasks/files cleaned and fresh privileged access checked; production export remains disabled.

Open: live native hash-pairing qualification, native Windows response acceptance, remaining response execution/recovery adapters, production Wazuh sender routing, operational logs, interruption/replay and response routing, final release regression and rollout. EDL-style filtering/progress feedback follows the four integrations and is not yet implemented. Details and exact evidence: [RESPONSE-POLICY-INTEGRATION-20261012](RESPONSE-POLICY-INTEGRATION-20261012.md).


UI revision decoy-history-20261012-r2 replaces the ordinary JSON dump with an ordered, labelled history for approvals, delivery, user-session results, native checks and administrator review. Recorded result, resource/policy revision, Windows SID, session/logon identity, check time and review notes remain readable. Original API sequence order is retained. Diagnostics is explicit and closed by default; opening it reveals the original payload string unchanged. Download raw history preserves every API event field. Sensor/action terminology is mapped explicitly; API keys and business logic are unchanged.

The screen now has loading/selection/empty/failure/retry states, keyboard disclosure and focus on loaded history. Malformed payloads remain visible as unavailable evidence without hiding other records. Zero-valued identifiers/results are retained. Text-only rendering protects against executable markup. Reader roles retain history without approval/review controls; expired authentication clears the history, rows and busy state. Mobile jobs use labelled rows rather than narrow wrapped columns. Existing creation-disabled and queue-review safety information remains.

Acceptance: 45 existing decoy-job functional checks, 24 actual browser checks and all 24 release regression groups passed. Desktop/tablet/mobile layouts were inspected at 1440/768/390 pixels against the packaged runtime and CSP. Browser job responses were explicitly mocked from inspected existing contracts; this is presentation/interaction acceptance, not new native-job execution or production-history data qualification. The first mobile layout was rejected during visual review and corrected before final packaging. All 17 console JavaScript files plus decoy-jobs.html passed the mechanical UX scan; the earlier raw-dump finding is now resolved. No material unresolved issue was identified within this history cleanup.

Deployment changed exactly twelve UI assets: decoy-jobs.js, decoy-jobs.html, console.css and the main index cache reference, plus their .br/.gz copies. Runtime remains 0.6.45. Whitelist script and unrelated assets are byte-preserved; previous stylesheet contents are preserved as a prefix with scoped #decoy-jobs additions. Installed manifests, served history script/page/stylesheet and existing whitelist cache reference were checked. All 33 inventory IDs and callback receiver remain unchanged; previous release/task/launcher/database backups were retained. No decoy job or trust policy was published, and no client, ACL, credential or firewall change was made. Separate fresh administrator authentication from the same authorized source verified the writer and launcher before closing the original session.

Evidence: C:\Users\dmessana\AppData\Local\Codex\sequester-decoy-history-20261012/{browser-r2/RESULTS.json,decoy-functional.log,regression-r2/REGRESSION.json,deployment-r2.json,fresh-administrative-access-r2.json,COMPONENT-DELTA-r2.json}. Native forensic, canary and Wazuh work remains separate. Signed-in production visual review was not performed; deployment serving/integrity checks and isolated authenticated browser acceptance are distinct.

## October 12: permanent Product UX Contract and whitelist refinement deployed

The final user-authored DEX DEFAULT PRODUCT UX CONTRACT is saved in docs/PRODUCT-UX-CONTRACT.md and required by root and repository AGENTS.md. The release runner now includes deterministic UX checks with positive/negative controls. It checks changed/staged/untracked console JavaScript and HTML for obvious raw-object rendering, internal field labels and generic placeholder/disclaimer copy. Visual and editorial review remain mandatory; automated checks do not certify design quality.

Whitelist UI revision whitelist-20261012-r6 is deployed on unchanged 0.6.45 runtime. Rule summaries use names and short outcomes. Creation actions precede the editor; redundant all-sensor target selection is hidden. Optional signer/publisher/parent constraints, scope approvals, receipt/readiness tables and history use progressive disclosure. File operations use a consistent responsive grid, aligned scope/schedule fields, concise presets and contextual consequences. SID/UID, domain/sensor and target-file labels are explicit. Required alert-suppression, binary-verification and platform-coverage information remains accessible. Loading, request failure and retry behavior were checked. APIs, internal rule identifiers, authentication, existing rules and matching behavior are preserved.

Acceptance: 218 functional/boundary checks, 34 actual authenticated packaged browser checks, 21 focused UX/runtime checks and all 24 release regression groups passed. Actual desktop/tablet/mobile screens were inspected at 1440/768/390 pixels. Keyboard disclosure, optional controls, hidden-field validation, Linux Open-only constraints, loading, retained drafts after request failure and successful Refresh recovery passed. These are UI tests using isolated/synthetic events, not new native operation qualification on production hosts.

The first layout attempt used inline styles that the existing CSP correctly blocked. They were moved into console.css without weakening CSP; final acceptance verifies computed flex/grid layout and no authenticated-screen browser/security-policy errors. The expected anonymous auth/me 401 is excluded before authenticated review. Earlier fixture preparation failures (wrong PowerShell runtime, guarded seed directory and existing receipt filename) remain recorded and are not product failures or passes.

Deployment changed exactly nine assets: trust-policy.js, index.html and console.css, each with .br/.gz counterparts. Every runtime/other asset is byte-preserved; the entire installed stylesheet is preserved as a prefix with scoped #trust additions. Cache references and served script/stylesheet hashes were verified. All 33 inventory IDs, the callback receiver and database location remain unchanged. Previous release/task/launcher/database backups were retained. Separate fresh administrator authentication from the same authorized source verified the launcher and writer before the original session closed. No production rule, credential, ACL, firewall or client was changed.

Evidence: C:\Users\dmessana\AppData\Local\Codex\sequester-whitelist-20261011/{browser-product-ux-r6/RESULTS.json,ux-review-r6-final/REVIEW.json,regression-product-ux-r6/REGRESSION.json,whitelist-functional-product-ux-r6.log,deployment-r6.json,fresh-administrative-access-r6.json}. Product-wide forensic, Wazuh and canary gaps remain unchanged. Signed-in production visual review was not performed; the exact deployed UI/runtime candidate was reviewed in an isolated authenticated browser, and production delivery was verified independently.

Material legacy UX issue outside this whitelist scope: the unchanged Operations/decoy-job History view in decoy-jobs.js renders JSON directly. The all-console mechanical scan flags it; it is recorded rather than silently exempted. Future edits to that screen must replace the ordinary raw view with structured history and optional diagnostics. This whitelist pass does not claim application-wide UX compliance.

## October 11 EDT / October 12 UTC: action-specific whitelist creation deployed

The management server now serves UI revision whitelist-20261011-r3 on unchanged server runtime 0.6.45. Administrators can create a disabled whitelist draft without an existing event, select user, process or user-and-process, scope and exact target path, choose individual operations, review and publish. New process drafts default to exact path plus SHA-256; explicit path-only matching remains labelled as lacking binary verification. Existing rules and all other UI/runtime files were preserved.

Additional unblocked policy features completed: Read/Edit/Delete operation presets; an explicit Create alert rule workflow using existing always-alert precedence; required identity/path/hash validation and correct validation when hidden fields or matching modes change. Edit selects only write/append/truncate. Matching whitelist activity remains logged with matched rule IDs; always-alert rules override simultaneous whitelist matches. User-and-process is AND; equivalent OR behavior uses separate scoped user and process rules as documented in docs/WHITELIST-ADMINISTRATION.md.

Feature QA completed: 218 whitelist functional/boundary checks, 34 actual Chromium checks against the exact production-runtime UI package, and all 23 release regression groups. Browser acceptance includes no-event authenticated publication of user/process/AND rules, restart/reload persistence, retained allowed reads, alerting writes, same-path wrong/missing-hash controls, always-alert precedence, exact matched rule IDs, and 1440/768/390-pixel layouts. UI replay events are explicitly synthetic; this is not fresh native operation qualification on every host.

Two UI-only activations completed (r1 and final r3); intermediate r2 was not deployed. Final release: F:\Sequestor\Server\releases\20261008-linux-audit-evidence-0.6.42-r1\release-candidates\w0645-whitelist-r3. Each activation verified the complete installed manifest, permitted only six whitelist/index/compressed asset changes, retained previous release/launcher/task/database backups, preserved all 33 sensor inventory IDs and the callback receiver, and checked served code and cache reference. A separate fresh SSH administrator session from the same authorized source verified the active writer and launcher before closing the original session. No production trust rule was published by this work; no client, management ACL, credential or firewall change was made.

Evidence: C:\Users\dmessana\AppData\Local\Codex\sequester-whitelist-20261011\{whitelist-functional-r2.log,browser-production-component-r3/RESULTS.json,regression-r3/REGRESSION.json,deployment-r3.json,fresh-administrative-access-r3.json}. Native capture/executable-preservation gaps, all-type consumer canary acceptance, and Wazuh decisions remain separately open. Wazuh remains deferred for the requested end-of-work discussion. This does not complete the entire forensic specification or AR-01 through AR-08.

## October 11: active response planning requested

The user requested stopping access, terminating the responsible process and disabling its responsible account. The [active response plan](ACTIVE-RESPONSE-PLAN.md) records AR-01 through AR-08, identity and impersonation checks, scoped privileges, independent effect verification, recovery requirements and three-pass QA. AR-08 adds per-user and per-process allowlists/blocklists with selectable read, edit, delete and related operations: verified allowlist matches produce visible notices; everything else produces alerts. It specifies explicit AND/OR matching, blocklist precedence and PID-plus-process-start binding. This is planned work; no response policy was enabled and no process, account or access rule changed. Existing process-stop code requires current qualification before reuse.

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

## October 11, 16:42 UTC: failed live trial restored; reporting retest prepared

The failed R3 simultaneous trial has been restored by a separate fresh recovery controller. Fresh authenticated administrator access verified protected-directory read/write, original capture driver path/hash, stopped filter, original boot settings and absence of the owned boot driver/forwarder. Normal reboot and shutdown completed, then original 4096 MiB RAM, CPU limit -1, reservation 0, normal/2000 shares and nested virtualization false were verified. The diagnostic snapshot and failed-run evidence remain preserved. Only after this proof were stale original controllers closed; their internal flags are not acceptance evidence.

Partial evidence independently matches all three attempted native operations to producer truth, including exact process lifetime, owner/effective impersonation tokens and zero native loss. One original/completion pair reached the sensor spool and links to the correctly hashed preserved executable. Two intake records remained pending. All-nine operation acceptance and central receipt are still unproven for this trial.

Candidate managed-live-r5 is packaged immutably as boot-trace-managed-package-r3. Its dedicated intake worker, live progress diagnostics and private system-required power request need runtime verification. The new retained controller stages and verifies all 422 runtime files before installing/attaching callbacks, and obtains a fresh connection for each reviewed guest command. Targeted checks passed: 103 decoder, 271 reporting/recovery, 55 actual native intake replay. No production deployment or all-host completion is claimed.

Evidence: fresh-controller-restoration-r5/{withdrawal.json,cleanup.json,fresh-restored-access.json,final-restoration.json}, partial-live-inspection-r1.json and boot-trace-managed-package-r3/manifest.json under the October 11 diagnostic root.

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

# Open work after the October 10 Linux deployment

## October 10 late Windows qualification checkpoint

- The owned Windows 10 DTrace fixture passed seven additional denied operations
  on successfully opened handles (read, write, append, truncate, rename, delete,
  direct-system-call read). Fourteen kernel entry/return records matched actor
  ground truth. This adds to two earlier denied-read cases; it does not supply
  thread tokens, cover older Server kernels, or integrate with production.
- DTrace uninstall and restoration of the original boot setting succeeded, but
  the normal `/r /t 0` restart stalled. The Win10 lab is suspended with memory
  preserved, its original administrative connection retained, and fresh guest
  access/resource restoration still outstanding. Cleanup has not passed.
- Callback lab r6 failed native Win11 qualification with bugcheck 0x18.
  The minidump places the fault in IopCompleteRequest/ObfDereferenceObjectWithTag
  during completion of the handcrafted kernel read, reached from the lab driver.
  Exact corrupt-object ownership requires further analysis; do not describe
  this as a qualified token-capture result. Production was not updated.
- Revision r7 removes the handcrafted IRP and its IOCTL. A fresh noncached file
  and ordinary mapped page access let Windows create its own paging request.
  It builds with warnings as errors; runtime qualification is still pending.
- Earlier restart scripts used a positive timeout, which implicitly forces
  application closure on Windows. Corrected requests use `/r /t 0`; historical
  claims that positive-timeout requests were nonforcing are incorrect.

## Follow-up native diagnostics, October 10, 23:49 EDT

- The preserved Win10 lab resumed, a console SPACE key was accepted, the queued
  normal restart completed, and a fresh authenticated administrative guest session
  confirmed DTrace absent, original BCD setting restored and baseline filter stopped.
  Kernel-Power event 42 precedes the lost access. The original CPU limit restoration
  and final lab shutdown remain pending; do not call all cleanup complete yet.
- Callback r8/r10 each matched 64 ordinary/forced-reference reads. For the mapped
  page, r10 recorded zero reads anywhere while armed, including target/path/owner
  diagnostics. A cache path is an inference, not proof of missing callback threads.
  Both probes were removed and fresh admin/baseline checks passed. Neither revision
  passed the required natural APC callback test. r9 was discarded before native
  testing because it compared potentially pageable names under the spin lock.
- Revision r12 builds a separate upper test filter (temporary order 409801.925)
  and uses FltAllocateCallbackData/FltPerformSynchronousIo for a bounded 4 KiB paging
  read through the lower observer (.924). Both APIs are documented through APC.
  FltFreeCallbackData owns associated MDLs; the build fixes that ownership and uses
  rundown protection. No hand-built filesystem IRP remains. Native test is running;
  compilation does not qualify this mechanism or the production collector.
- Static named-export controls passed on all four deployed Windows hosts.
  TraceRegisterEngine/TraceInitSystem are absent from ntoskrnl.exe on ALL four,
  including Win10 where the official DTrace binary actually captured syscalls.
  Export absence alone therefore cannot establish engine incompatibility.
  The public source's standalone TraceRegisterEngine returns STATUS_NOT_SUPPORTED.
  Do not treat a build of that standalone source as equivalent to the official
  binary or as a qualified older-Server syscall source.

## Revision r12 native progress

Windows 10 passed 96 real reads, including 32 actual APC-entry callbacks from the
upper Filter Manager sender. Both probes were normally removed and fresh admin
restoration was verified. Refer to WINDOWS-CALLBACK-TOKEN-NATIVE-WIN10-20261010-R12.json.
Metadata was queried at PASSIVE from the token object retained at callback entry;
mutable token fields are not asserted to be historical snapshots. Qualification on
other OS builds and production integration remain pending. The 24 deployed missing
insufficient-rights failures remain open. Original Win10 normal shutdown and CPU
rollback are being completed before running the same revision on other platforms.

## Original Win10 lab restoration completed

Final fresh admin, original boot setting, DTrace removal, callback probe removal,
normal guest shutdown, original CPU unlimited/Normal 2000 shares and 4 GiB RAM
were verified. VM 15009 is PoweredOff; original administrative connection was
retained through these gates. Final restoration has its own receipt:
WIN10-DTRACE-LAB-FINAL-RESTORATION-20261010-R1.json. The original controller ended
with an older callback-root cleanup lookup error; this is retained and does not
invalidate the separate, measured recovery gates. R12 Win11 qualification starts
only after the Win10 lab is off.

## Verified deployment

All 26 Linux sensors passed seven synchronous write/append variants under UID 0
and UID 1000, first-use actor capture with immediate process exit and unlink,
central evidence verification, normal source restart, and final live readiness.
Receipt: diagnostics/windows-token-20260930/LINUX-IO-DEPLOYMENT-ACCEPTANCE-20261010-R10.json.
There were 364 operation cases, 1,456 linked central events and 364 authenticated
executable/manifest download pairs. This does not close the entire forensic specification.

## Linux engineering and qualification gaps

1. **Additional I/O paths:** mmap-backed changes, io_uring, splice and
   copy_file_range are outside the qualified synchronous hooks. Implement and
   qualify their attribution, operation result and ordering before claiming coverage.
2. **Capture capacity:** actor capture is limited to 4 MiB and four concurrent
   leases. Larger executables and burst concurrency need a resource-bounded design,
   explicit failure telemetry and tests without losing the immediate-exit guarantee.
3. **Hash-based whitelist integration:** controlled-v4 events remain ineligible
   for hash whitelist matching. Integrate verified actor identity and operation
   permissions, preserving the log while suppressing only the allowed alert.
4. **Complete operation acceptance:** this deployment qualifies synchronous
   writes/appends. It does not establish fresh denied-open, rename, delete and
   truncation acceptance across all 26 sensors. Earlier read/denied tests retain
   their recorded scope and do not replace this missing matrix.
5. **Filesystems and future kernels:** current native admission is tied to exact
   qualified kernel/BTF/binary profiles and local ext4 targets. Other filesystems,
   network targets and kernel upgrades need explicit qualification.
6. **Maintainable release process:** the module and BPF/loader sources and kernel
   Makefile are in the repository, but deployment relied on dated diagnostic
   build/package scripts. A repository-owned build entry point, locked toolchain
   and dependency inputs, per-kernel build manifests, reproducibility checks,
   CI qualification gates and a documented upgrade/rollback workflow remain open.
   Imported SOURCE-PROVENANCE records describe the original candidate, not current
   deployed binaries. Do not silently replace that historical provenance.

## Other work not closed by this Linux deployment

- **Windows status correction:** the minifilter is already deployed on all four
  current Windows hosts. October 9 central acceptance passed 60 actual deployed
  cases and 64 independently hashed executable/manifest download pairs. Tests
  include impersonated reads, changing impersonation after opening a handle,
  and six DAC-denied opens per host. Process-primary, thread-effective SID,
  impersonation state, PID, process birth and thread ID matched actor ground truth.
  October 10 read-only checks confirmed the same admitted driver and agents running
  on all four hosts. Earlier statements that rollout or all denied-open acceptance
  were pending were based on an older summary and were incorrect.
- **Windows existing-handle retest, October 10:** all four hosts performed eight
  actual failed operations after successful opening. All eight byte-range locked
  read/write cases reached the server with full tokens matching independent actor
  truth. All 24 insufficient-rights read/write/append/truncate/rename/delete cases
  returned Access Denied but lacked failed-operation events. All 32 opening cases
  were independently confirmed; they do not substitute for missing failures.
  Full failed-operation coverage remains open. See
  [the retest report](WINDOWS-EXISTING-HANDLE-RETEST-20261010.md).
  Missing callback threads or unsupported IRQL remain explicitly unavailable.
  Thirty synthetic decoder/contract checks passed; native universal availability
  is not established. No production driver/agent update was made by this retest.
- **Windows resolution prototype:** the current r7 supplemental API observer
  passed 32 normal failed-operation cases and four native-call controls across
  all four hosts, with matching tokens. Four direct-call negative controls
  bypassed it. Production integration is not complete. The separate APC token
  reference probe passed 64 cases each on Windows 10, Windows 11, Server 2019,
  and Server 2012 R2: 256 native cases plus mutation and failure controls.
  Fresh administrative access, normal probe unload/shutdown and CPU restoration
  were checked. This qualifies the lab reference mechanism, not real filesystem
  callbacks or production integration. The r3 actual-read callback probe passed
  64 owned Windows 10 reads: 32 PASSIVE callbacks and 32 forced APC reference
  controls, plus explicit absence of impersonation. The probe was removed and
  fresh administrative access and the original filter state were verified.
  No naturally elevated callback was exercised by that revision. Revision r4
  builds a kernel-generated APC read test but has not passed native qualification.
  The WDK-versus-documentation IRQL discrepancy and
  historical full-token guarantee remain unresolved. The PID-scoped DTrace
  investigation passed two native Windows 10 denied reads, including a direct
  syscall: PID/TID, handle, length, status and entry/return ordering matched
  independent actor truth. Receipt:
  diagnostics/windows-token-20260930/WINDOWS-DTRACE-NATIVE-DENIED-READ-WIN10-20261010-R1.json.
  This does not collect thread tokens or constitute production integration.
  Earlier failures are retained: an unsupported option, incorrect PowerShell
  argument grouping, and a stalled scheduled worker. The passing invocation used
  the owned elevated Guest Operations process and explicit argument grouping.
  Original boot/install/resource restoration is still pending in the open session.
  A seven-operation denied-handle fixture was built with warnings as errors;
  that build is not a native acceptance result. Its installer cannot be used on these older Server
  kernels. See
  [the resolution investigation](WINDOWS-CAPTURE-RESOLUTION-20261010.md).
- Signed-in production UI acceptance for the new Linux evidence and operation
  filters. Packaged UI tests and API acceptance have different scopes.
- Application-opening tests for all 14 canary file types. Earlier binding/HTTPS
  callback tests do not prove that every application/file type makes a callback.
- Wazuh log forwarding and the user-requested discussion of syslog versus agents
  and active response integration.
- Plex media availability: CIFS returns BAD_NETWORK_NAME for
  //10.81.60.190/media/media. The CIFS module is present and loaded; the Plex service,
  port and sensor are healthy. The share path and credentials were not changed.

## Implementation rules

Extend the existing kernel module, BPF collector and managed evidence pipeline
where practical. New kernel code belongs in the repository with versioned
contracts, source/dependency manifests and regression tests. Expensive hashing
and upload must stay outside critical file-I/O callbacks. Hash and preserve actor
executables, not every target file. Keep unavailable evidence explicit. A build,
successful module load or health reply alone does not establish operation coverage.
