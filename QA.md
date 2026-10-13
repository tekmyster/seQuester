# Source layout migration - October 13, 2026

Renamed 17 source/test directories and 16 managed project files to the seQuester prefix in the published repository and current local development checkout. Preserved assembly names/root namespaces and existing deployed service/API/data identities. Updated project references, static and dynamic packaging paths, documentation, test runner output resolution and UX file selection.

Verification: all 90 project files parse and every ProjectReference resolves; all 16 renamed projects explicitly preserve their prior assembly/namespace identity. Eight principal application/test builds passed. Locked server/receiver publication passed. Isolated server tests produced 156 PASS lines and canary tests 260, with successful exit status. Sensor/event/presentation DOM fixtures passed 20/51/95 cases; UX checker controls and its 19-file selection passed; PowerShell tools syntax passed. The rebuilt isolated server passed 20 browser checks and 18 captures with unchanged web-root hashes. The primary development-checkout server also builds successfully; all 91 current guide links resolve. Native capture, driver qualification and production deployment were not rerun by this source-layout change. Historical private diagnostic links remain outside the public source snapshot.

# Documentation review — October 13, 2026

Added nine guides covering user and administrator workflows, deployment/recovery, architecture/evidence, APIs, capabilities, development and screenshots. Updated the root README and permanent contract from the latest user-supplied text, preserving the repository enforcement appendix.

Screenshot capture: 18 actual desktop/mobile images and 20 automated browser checks against an isolated authenticated 0.6.45-dev server with synthetic data. The web-root files matched the published source by SHA-256 comparison. All images were visually inspected; credentials and production data are absent. No policy, response, external callback or production integration was activated. This is documentation/presentation verification, not a new native forensic or all-host deployment pass.

The first capture run failed because its isolated state directory was absent; the tool now creates it before SQLite identity startup. An early sensor screenshot was taken before rows loaded; capture now waits for populated sensor/event rows. Overview revisit produced a real caught UI error: incidents.js removes overview-informational while console.js still updates it. This remains documented in CAPABILITIES.md; the Overview image shows the successful initial load.

Documentation verification: all 89 local links and image references resolve; the capture script syntax and Product UX checker positive/negative controls pass. Documentation-only changes do not alter APIs, runtime behavior or accepted deployments. Historical acceptance records follow.

## October 12: decoy-job History UX cleanup deployed

## October 12: response, whitelist and Wazuh integration in progress

The user authorized completion of Active response, Additional whitelist controls, Linux hash-based whitelisting and Wazuh integration. This supersedes older entries deferring Wazuh discussion. New server/sensor capabilities are not yet deployed. The owned Wazuh TLS receiver, Filebeat input/index and rule feed are active for manager-local controlled tests only. Production seQuester senders are not enabled.

Verification: 66 advanced trust/policy checks; 218 whitelist checks; 130 Linux evidence checks with synthetic source frames and actual held descriptors; 16 response journal/Windows process/capability checks; 19 receiver tests on Linux; 18 loopback TCP/TLS receipt checks; 22 desktop/mobile browser checks. All 28 release groups passed before the last transport-only candidate change. Owned-child Windows termination passed through the legacy adapter; native file-event response remains unqualified. Manager-local Wazuh detection, suppression and indexing passed. Cross-host forwarding still stalls after TLS negotiation, including under the actual NetworkService account. Temporary source grants were rolled back, tasks/files cleaned and fresh privileged access checked; production export remains disabled.

Open: live native hash-pairing qualification, native Windows response acceptance, remaining response execution/recovery adapters, production Wazuh sender routing, operational logs, interruption/replay and response routing, final release regression and rollout. EDL-style filtering/progress feedback follows the four integrations and is not yet implemented. Details and exact evidence: [RESPONSE-POLICY-INTEGRATION-20261012](docs/RESPONSE-POLICY-INTEGRATION-20261012.md).


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

## October 11, 16:42 UTC: live-trial recovery complete; next candidate under test

Separate fresh administrator access verified original capture image/hash, stopped filter, original boot settings, protected-directory read/write and removal of the test boot components. Normal reboot/shutdown and exact original VM resources were verified. The diagnostic snapshot and all failed evidence were retained; stale controllers were closed only after external proof.

Read-only independent comparison matched three actual attempts to native producer truth, including PID/start time, accessing thread, process-owner and effective impersonation tokens, target and result. One original/completion pair was durably spooled and linked to an accurately preserved executable. Two records remained pending; all-nine acceptance and central receipt are not established by this failed run.

The new immutable candidate uses dedicated syscall intake, incremental stage diagnostics and a private test-lifetime power request. It stages and verifies 422 runtime files before boot callback installation. Targeted checks passed: 103 decoder, 271 reporting/recovery and 55 actual native intake replay. New live acceptance remains pending; production is unchanged. General thread/target coverage, denied-open qualification, trust matching and deployment remain open.

Evidence: fresh-controller-restoration-r5/final-restoration.json, partial-live-inspection-r1.json and boot-trace-managed-package-r3/manifest.json under the October 11 diagnostic root.

## October 11: simultaneous live test failed; standby diagnosed

The R3 continuation ran the actual syscall and proactive acquisition sources with the qualified capture minifilter. Independent producer truth records show denied read and write controls acknowledged, followed by a denied append whose acknowledgement timed out. The producer exited with failure. The initial failure artifact contained no published events. This does not qualify native token matching, executable preservation or central receipt for this simultaneous live run. No production deployment was made.

The later management outage was traced to Windows standby, independently supported by the VMware ACPI S1 log at 15:25:51.134 UTC and the preserved memory image: its guest clock is 15:25:51, CPU 0 stack candidates include HalpAcpiPreSleep/HaliAcpiSleep/PopTransitionToSleep, and KiBugCheckData is zero. The retained disk/memory snapshot and downloaded memory SHA-256 are recorded under the October 11 diagnostic directory. This explains the management outage, not the earlier failed reporting test. Console wake restored VMware Tools; guest process starts and uploads were still rejected at the next check. Both original administrative controllers remain retained pending actual restoration and fresh privileged checks.

New candidate diagnostics expose receiver and dispatcher stage, sequence/event linkage and monotonic elapsed time. The private harness retains incremental health/progress logs through source disposal and holds a thread-owned system-required power request for its test lifetime, then releases it. No permanent Windows power policy is changed. The updated fixture builds with zero warnings/errors; the new diagnostics and power request still require a live trial. Original 657 software/fixture checks retain their previously documented scope.
## October 11: recovery fixes verified; simultaneous live trial pending

Damaged or misplaced executable snapshot indexes are rejected individually and reported without hiding valid committed records. Process birth timestamps are validated, unusable target names retain raw bytes and reply hashes, native display paths use verified mappings, and capture startup failures now report the acquisition stage and raw HRESULT.

Software checks passed: 103 decoder, 269 reporting/recovery, 55 actual transport replay, 64 actor fixture, 10 UI fixture and 156 server regression checks (657 total). Fixture actor transport remains synthetic. A new private harness runs both actual drivers and sensor sources together, checks independent operation/token truth plus executable identity and creation metadata, and verifies preserved executable bytes through an isolated central receiver.

The first live attempt failed at source startup because the private baseline minifilter lacked the acquisition commands. It was restored with fresh privileged access and original resources verified. The corrected second trial uses the previously qualified capture driver in an owned protected directory and retains the original driver image and administrative session. Acceptance and final restoration are still pending. No production deployment is claimed. General thread/target coverage, startup compatibility, new-source trust matching, platform qualification and deployment remain open.

## October 11: reporting integration verified; private lab restored

The candidate build now integrates durable syscall intake, exact process-generation snapshot linkage, actor hashing/signature verification/preservation, existing central binary upload and event-history token details. Native evidence is separately labeled from minifilter evidence. Windows OS and action filters were tested: six denied-rights cases, two operation-failure cases and the successful read control are classified correctly. Existing SQLite action indexes are replaced transactionally when their definition changes; migration retains original event payloads.

Acceptance: nine live native cases with zero loss; 103 decoder checks; 182 reporting checks; 55 actual native-intake replay checks; 62 actor/API/index/filter checks; 10 UI checks; and 156 server regression checks. The actor acquisition transport is synthetic, while executable bytes, signature verification, preservation, HTTP upload and downloaded hash verification are real. UI tests use a fixture and do not establish production UI acceptance.

The private VM was restored and powered off. Callbacks were withdrawn, owned driver/forwarding files and registration removed, original boot/filter settings restored, fresh separate privileged authentication passed, and original 4096 MiB RAM, CPU limit -1 and nested-HV state were preserved. The original administrative session closed only after validation. Receipt: WINDOWS-BOOT-TRACE-INTAKE-RESTORATION-20261011-R1.json.

Production is unchanged. The source still covers an explicitly owned thread and registered handles. Simultaneous live managed intake plus proactive actor acquisition, general target/multiple-thread coverage, trust/whitelist matching for the new source, lifecycle/resource qualification, unattended boot compatibility and qualification/deployment across the four Windows sensors remain open. This is a verified integration milestone, not completion of the full specification. Details: docs/WINDOWS-SYSCALL-SENSOR-REPORTING.md.

## October 11: live native intake and reporting replay passed

The new Windows 10 native intake interface passed all nine actual cases with zero loss. Repeated peek returned identical records, wrong sequence acknowledgement left the record queued, retained target-name queries identified the actual owned files, and correct acknowledgement drained only the matching record. Separate full process-owner/effective-thread tokens again matched independent user-mode truth. Raw SHA-256: 49fd704419ed20f9b53cc8f06b2792f2a50d52dd3606f9cec7427acdb1819dec.

Managed verification passed 103 decoder, 182 reporting, 55 actual native-intake replay and 55 actor integration checks (395 checks). The candidate server API received actor-acquisition-v2 manifests and preserved executable bytes, returned a matching downloaded hash, and retained separate owner and impersonated-user identities in history. Actor acquisition transport remains synthetic; simultaneous live proactive acquisition and the managed device receiver are not yet qualified.

The private guest is being restored with the original session retained. General target/multiple-thread monitoring, unattended boot compatibility, lifecycle/resource qualification and deployment across the four production Windows sensors remain open. Production has not been changed. Receipts: WINDOWS-BOOT-TRACE-INTAKE-RAW-ACCEPTANCE-20261011-R1.json and WINDOWS-SYSCALL-INTAKE-INTEGRATION-20261011-R1.json.

## October 11: syscall reporting integration QA

Functional pass: exact-generation actor acquisition, native token separation, SHA-256, real signed Windows executable verification, protected preservation and matching central artifact download; 55 actor fixture checks including actual candidate HTTP capabilities/upload/history. Acquisition transport is synthetic, not a live driver-to-sensor result.

Edge pass: 103 checks against actual independently captured native records and 173 reporting checks for wrong identity/birth, unavailable fields, immutable retries, journal restart, failed operation outcomes and duplicate acknowledgement. Actor checks cover PID reuse, wrong acquisition epoch, 32 cached operations, stable-identity replacement rejection and missing server schema acknowledgement.

Runtime pass: managed agent and server builds have zero warnings/errors; candidate API stores both records, acknowledges syscall-v1, existing upload worker transfers actor-acquisition-v2 manifests, and authenticated history returns separate SYSTEM owner and LOCAL SERVICE impersonated identity. No production UI acceptance or production deployment is claimed. Live native intake qualification remains in progress; restoration must pass before closing its original administrative session.

## October 11: full-token private qualification restored safely

The nine-case Windows 10 full-token proof is complete and its private VM is restored: callbacks withdrawn, verified owned driver and forwarding registration/files removed, original boot/filter settings restored, fresh independent privileged access passed, normal shutdown completed, original 4096 MiB RAM and CPU limit -1 restored, and nested virtualization unchanged. The original administrative session was closed only after those checks succeeded. Receipt: WINDOWS-BOOT-TRACE-TOKEN-RESTORATION-20261011-R1.json.

The token proof and 103 managed decoder checks establish prototype progress, not production completion. General target monitoring, actor binding/preservation, central publication, resource/lifecycle qualification, unattended boot compatibility and deployment/testing across the four Windows sensors remain open. Production was unchanged in this trial.

## October 11: Windows 10 full accessing-thread token proof passed

The private boot-time syscall source passed all nine actual Windows 10 19045.6456 cases: insufficient handle rights for read, write, append, truncate, rename and delete; byte-lock failures for read and write; and a successful read control. Independent raw verification matched operation, NTSTATUS, PID 1796, TID 3896 and process creation identity. Process-owner and effective-thread tokens matched separately: SYSTEM owner, LOCAL SERVICE impersonation in eight cases, and SYSTEM effective identity in the non-impersonating control. All five token collection groups succeeded, including SID, token/authentication/modification IDs, type, impersonation level, session, integrity and elevation. No records were lost and targets remained unchanged.

The managed decoder passed 103 checks against the actual raw records. Raw SHA-256: e3e509fc2cb7699e9ad51d959605d215f4e7d706943149767de5c04729c51f74. Receipt: WINDOWS-BOOT-TRACE-TOKEN-RAW-ACCEPTANCE-20261011-R1.json. Restoration is in progress with the original administrative session retained; it is not yet a completed restoration result.

This qualifies the controlled one-thread native prototype on this exact kernel. It does not establish general honeypot monitoring, actor-executable acquisition, central integration, resource/lifecycle qualification, unattended boot compatibility, deployment or consistent coverage across the four production Windows sensors. Those remain unfinished. Whole-product acceptance is not complete.

## October 11: Windows 10 nine-operation callback proof passed; full-token test running

The boot-start tracing source captured all nine controlled operations on Windows 10 19045.6456: six failures caused by insufficient handle rights (read, write, append, truncate, rename and delete), two byte-lock failures, and a successful read control. Independent raw verification matched PID, thread ID, process creation identity, operation and NTSTATUS, with no lost records and unchanged targets. Every tested entry/return callback ran at PASSIVE_LEVEL with interrupts enabled and APCs available. Receipt: WINDOWS-BOOT-TRACE-CONTEXT-RAW-ACCEPTANCE-20261011-R1.json. That context test passed exact restoration and fresh privileged access.

The full-token build reuses the sensor token helper and separates process-owner and effective thread tokens. Callback-depth guards prevent nested token queries from completing an outer operation's record; seven focused contract cases passed. Actual full-token collection is now under private runtime test. User-mode token truth from the earlier context trial is not kernel token evidence.

Production remains unchanged. General monitored-target and actor binding, central transport, resource qualification, four-host deployment and fresh production operation tests remain open. The private boot source also has a per-boot signature-enforcement dependency; unattended deployment is not established. Whole-product acceptance is not complete. See docs/WINDOWS-DTRACE-TOKEN-ADAPTER-PLAN.md.

## October 11: Windows 10 boot activation repaired; native qualification running

The r1 boot test returned DEVICE_NOT_READY before callback registration because the boot tracing initializer was not invoked. It is restored: fresh privileged login, verified original filter/boot state, driver removal, normal shutdown and exact CPU/RAM/nested-virtualization restoration. Receipt: WINDOWS-BOOT-TRACE-R1-RESTORATION-20261011-R1.json.

The r2 driver corrects syscall registration names and the 64-bit TEB-offset layout. The retained test controller installs a verified Microsoft-signed API-set forwarding DLL and a previously absent owned registry entry, and tracks their exact removal. The one-time Startup Settings screen was inspected and option 7 selected for this private test boot. No production protection setting was changed. This boot extension requires per-boot signature-enforcement handling for the private proof; unattended production compatibility is not established.

The separate guarded token-capture build compiles using the existing sensor token helper. Actual callback context, independent full-token comparison, general target/actor binding, evidence upload, resource qualification and four-host production deployment are still pending. Compilation and boot-menu selection are not capture passes. Whole-product regression acceptance remains pending.

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

## 2026-10-11 deployment checkpoint

Server 0.6.45 and all four Windows sensor packages 0.6.26 are deployed and freshly checked. Full driver passed 132 APC reads across four Windows versions. Windows 10 production driver is enabled; its 15-case native operation rerun passed and restored settings. Central token and binary evidence acceptance is running before the remaining driver rollout. Signed-in isolated token UI passed 24 checks. Pre-filesystem insufficient-rights failures (24 previously missing cases) are still unresolved. See docs/WINDOWS-DEFERRED-TOKEN-INTEGRATION.md for exact scope and receipts.

## 2026-10-11 Windows token qualification update

Integrated token worker: 132 APC read cases passed on four Windows versions (128 impersonating, four non-impersonating). Native raw replay survived managed persistence and isolated server API readback. Full executable-staging driver compiled and Windows 11 native test passed; cleanup checks and remaining full-pipeline OS tests are pending. Server 0.6.44 and sensor 0.6.26 packages built; deployment is in progress, not complete. The 24 pre-filesystem insufficient-rights failures remain unresolved. See docs/WINDOWS-DEFERRED-TOKEN-INTEGRATION.md and immutable diagnostics receipts.

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

## Windows callback checkpoint - October 10, 23:54 EDT

Revision r12 passed 96 actual Windows 10 reads: 32 PASSIVE callbacks, 32 forced
reference controls and 32 real APC-entry callbacks from a separate Filter Manager
paging sender. Actor PID/TID/start time and effective SID/token identity matched
independent truth after thread reversion. No-impersonation control passed. Both
probes were normally removed; fresh administrative access verified restoration.
Other Windows versions and production integration remain pending. This does not
close the 24 missing insufficient-rights failures or assert immutable historical
token privileges/groups. See WINDOWS-CALLBACK-TOKEN-NATIVE-WIN10-20261010-R12.json.

Win10 DTrace cleanup recovered from guest standby via preserved resume/console
wake, then completed the queued normal restart. Fresh admin, original BCD setting,
DTrace removal and task cleanup passed. Final normal shutdown/CPU rollback pending.

## Windows qualification checkpoint - October 10, 23:35 EDT

- Seven additional Windows 10 denied-operation cases passed native syscall
  entry/return matching; thread-token capture and production integration remain
  outstanding. Two earlier denied-read cases retain their separate receipt.
- Callback probe r6 failed in the isolated Win11 guest with bugcheck 0x18.
  Minidump analysis places the fault in completion of its handcrafted read IRP.
  Revision r7 removed this path and matched 64 ordinary/forced-reference cases;
  cold mapped-read attribution failed. Neither revision passed full qualification.
- Win11 probe removal, fresh admin login, normal shutdown and exact CPU/RAM
  baseline were independently verified. The earlier null memory assertion was
  corrected: Config.Hardware.MemoryMB is the real SDK field; baseline is 8 GiB.
- Revision r8 binds observations to the caller-owned file object and reports
  absent/different callback threads explicitly. Build passed; native test pending.
- Win10 guest log reports standby sleep. Preserved resume and one keyboard wake
  were requested; restored fresh guest access and original CPU rollback pending.
- No production driver or sensor release was deployed by these investigations.

## October 10 Windows capture checkpoint (22:47 EDT)

- Kernel syscall proof: two owned Windows 10 denied reads passed, including direct syscall; actor PID/TID, handle, length, actual error and ordering matched independent truth.
- Thread-token collection and production integration from this source remain open. Older Server kernels are outside this installer's admission.
- Actual-read callback r3 passed 64 Windows 10 cases (32 normal, 32 forced-reference controls). Kernel-generated APC callback r4 is built, not yet qualified.
- Seven-operation denied-handle fixture compiled with warnings as errors; native expanded acceptance is in progress.
- Original administrative session remains open; final lab boot/install/CPU restoration is pending.

## Windows capture checkpoint - October 10, 2026 21:43 EDT

The APC token-reference lab passed 256 native cases across Windows 10, Windows 11, Server 2019 and Server 2012 R2, plus mutation and failure controls. Fresh administrative guest access, probe unload, normal shutdown and exact CPU restoration were verified. The mutable-token control proves a reference is not a historical snapshot. Actual-read minifilter callback qualification and DTrace denied-operation qualification are in progress; neither is deployed or accepted. The 24 missing insufficient-rights operation events remain open. See docs/WINDOWS-CAPTURE-RESOLUTION-20261010.md.

## Windows attribution qualification checkpoint - 2026-10-10 evening

- Supplemental observer r7: 32/32 ordinary failure cases across four hosts; four direct-call bypass controls remain. Final four-host package/service/filter checks passed. Not a production collector feature.
- Isolated kernel token-reference probe: Windows 11 26300.9457 and Windows 10 19045.6456 each passed 64 APC reference/revert/query cases plus mutation, absence, buffer and cleanup controls. Fresh admin access, normal unload/shutdown and CPU restoration verified. Actual filesystem APC callbacks and full historical token state remain unqualified; Server 2019 qualification is running.
- Guest transfer certificate PEM/DER normalization and Windows file-attribute selection corrected; signature checks, exact pins and guest isolation retained.
- Microsoft DTrace syscall source is under investigation for pre-dispatch failures. Official installer authenticated and bounded fixture compiled; runtime and server integration pending. Current Server 2012 R2/2019 builds are below its stated minimum.

## Windows capture resolution prototype - October 10, 2026

An isolated API observer matched 32 normal failed-operation cases and full primary
and effective token comparisons on four Windows hosts. Four direct-system-call
negative controls bypassed the observer. This is supplemental QA evidence, not a
production sensor feature or a completed collection fix. An APC token-reference
probe compiled only; historical full-token capture remains unqualified. All
production sensors remained unchanged and healthy with zero pending uploads.
See [the investigation](docs/WINDOWS-CAPTURE-RESOLUTION-20261010.md).

## Windows existing-handle failure retest - October 10, 2026

Fresh four-host tests: 32 failed calls after successful opens. Eight locked-byte
read/write failures reached the server with matching user, process, PID, thread
and full process/effective tokens. The other 24 insufficient-rights failures
remain uncaptured. All 32 opening cases were confirmed independently; opening
success is not failed-operation coverage. Full failure coverage is NOT passed.
Thirty synthetic unavailable-context checks passed; native missing-thread or
unsupported-context token availability remains unqualified. Test harness fixes
and a new decoder regression fixture were added; production binaries unchanged.
See [the bounded retest report](docs/WINDOWS-EXISTING-HANDLE-RETEST-20261010.md).

## Windows status correction - October 10, 2026

The previous statements that the minifilter had not been deployed and that
accessing-thread/impersonation or all denied-open acceptance were still pending
were incorrect. October 9 actual deployed acceptance passed 60 cases on all four
Windows hosts, with 64 independently verified central executable/manifest pairs.
Cases include impersonated reads, impersonation changed after opening a handle,
and six DAC-denied opens per host. Primary and effective identities, impersonation,
PID, process birth, thread ID and OS status matched actor ground truth. October 10
fresh read-only checks confirm the admitted driver and agents running on all four
hosts with zero pending executable uploads. These are service checks, not a new
operation retest.

Remaining Windows coverage gap: failed I/O on handles previously opened successfully.
Denied-write/rename/delete test labels in the prior matrix describe rejected opens
requesting those rights. Callback-thread absence or unsupported IRQL remain explicit
unavailable states. CPU delay is not established as a cause of attribution failure.
Earlier HTTP 507 upload quota rejections, quota correction and later passed central
acceptance are retained. Receipt: WINDOWS-TOKEN-STATUS-CORRECTION-20261010-R1.json.

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
# QA status

## Linux write/append deployment qualification update (2026-10-10)

- Ops package R10 / managed R12 passed installed pressure R7: 28 root/UID1000 cases, immediate exit/unlink, exact PID/birth/inode/credentials, verified executable preservation, 528 ordered raw records and two rotations. The same native PID remained ready after final restoration.
- Production central R3 verified 112 exact events and all 28 downloaded binary/manifest pairs. Native-v4 probe R4 passed with the collector running. Normal restart R1 closed normally, verified nine rotated-history files unchanged and restored a fresh ready native instance. Ten seconds of idle observation used 0.887757 CPU seconds; this is a bounded sample, not a whole-product performance claim.
- Failure-path review then corrected active-segment emergency receipt locking and its version marker. Final managed R14 / package R12 is the candidate under qualification. Linux rotation fixture R3 passed 404 checks: rotation 79, physical preparation 20, frozen source policy 48, owner receipts/migration 110, native pin ordering 60, stopped recovery 87. Packaged runtime R12 passed 39. Fresh final installed acceptance is pending; earlier results remain tied to their exact builds.
- Wider staging of R10 succeeded on ten of fifteen hosts; five rejected an inventory-name/OS-hostname mismatch before release staging. No wider activation occurred. Final executors validate the exact known hostname and sensor ID together.


## Active Linux I/O qualification — October 10, 2026

- Retention module qualification R2 passed 14 operations, 35 executable hashes and 70 observations on Ops; first START was deliberately delayed twelve seconds after actor exit/unlink, exact retries did not renew the copy deadline, all hooks detached, normal module unload and installed-service restoration passed. Manifest 4 pins the exact new artifact bundle with sixty-second retention and a separate ten-second copy budget; prior manifests remain supported.
- Current definition/capacity/worker fixture passed 96 + 9 + 108 checks. Installed Ops pressure R6 passed all 14 cases and central R2 verified 56 events plus 14 binary/manifest pairs. The following source-health check found RAW_BACKLOG_EXHAUSTED at 256 records; the native service closed and must not be called ready. Native-v4 probes R1/R2/R3 failed after that closure and do not prove a running module. The new rotating-log candidate passed 76 Linux rotation checks plus 20 legacy preparation checks; package R10 and fresh installed continuity remain separate gates.
- Native R7 passed on Ops Debian 6.12.94: 14 scalar/vector/positioned/append operations in two credential contexts, 35 SHA-256 verified executable copies after immediate exit/path removal, zero loss, normal detach/unload and original sensor restoration.
- LinuxIoFixture passed 49 ABI, contract, operation-pair, PID/exec identity, loader-control and server-history checks, including RWF_NOAPPEND override.
- Owned managed runtime R2 passed all 14 live cases, saved 70 originals/70 completions and linked each write return to its exact entry actor capture. Normal shutdown and original .42 restoration passed.
- Actual managed evidence through the isolated release server passed 502 checks, including 35 binary/manifest upload/download pairs with hash verification. Signed-in packaged UI passed 48 checks. Existing server suite and 465 history regression checks passed using the release snapshot.
- Corrected Linux 0.9.43 package passed 39 relay/parser/runtime checks. Ops staging verified 277 files. Server 0.6.43 is deployed and authenticated capability/UI checks passed. Installed Ops R11 passed all fourteen cases; production verified 56 exact linked events and fourteen executable/manifest downloads. A further native scheduling correction awaits installed pressure validation; other kernels and wider rollout remain pending. Existing 0.9.42 installation does not provide the new features.

<!-- CURRENT-SEQUESTER-QUALIFICATION-START -->
## Current qualification snapshot - October 04, 2026

Full production rollout remains pending. These are bounded results for the recorded qualification packages.

| Area | Latest verified state | Remaining gate |
| --- | --- | --- |
| Windows accessing-thread identity | R49: 84 controlled cases across four Windows builds, including 24 denied cases; native identity, actor copies and isolated server checks passed. | Assigned altitude/signing, final QA and deployment. Unavailable background evidence remains explicit. |
| Linux native attribution/whitelists | R4 installed capture passed 73 actual/85 independent; InstalledServerTrustR3 passed 102 actual/118 independent, including manual rules created before events. | Release-native R18 passed 144 actual/216 independent; installed R73/R18 gate accepted. Other kernels/operations and sustained volume pending. |
| Linux delivery and policy IPC | InstalledServerR4 accepted actual enrollment, signed policy relay, cap-free LinuxWorker delivery, exact server event persistence and five central hash-verified executable downloads. | Installed manual whitelist publication/classification accepted; production rollout pending. |
| Native package and targets | R71 installed service activation/drain/unload and dedicated-group journal ownership verified. Existing package/target/lifetime and R69 lifecycle gates remain accepted. | Exact 6.12.94+deb13-amd64/local ext4/preopen/4MiB scope. Ten other hosts unqualified; eight lack required actor APIs, including Ubuntu6.8. |
| Central evidence and UI | Server R5: 86 HTTP checks, ten native records and three actor uploads/downloads; 15 authenticated browser checks. Server R6: 14 signed-policy HTTP checks. | Final product QA and production rollout; current production database is SQLite; no migration needed for measured capacity. |
| Release dependencies | Windows R49 four-build qualification; Microsoft reply absent09:47Z. Linux release-installed whitelist R3 accepted, off/restored09:40:07Z. | Corrected Ubuntu v11 build passed70 independent checks; actual verifier R3 passed44 and independent54. ManusR133 confirms the correction. R74 installed Debian and Ubuntu server/whitelist gates accepted102/118 each. Atomic native candidate full-object verifier accepted146/160; live lifecycle and root integration pending. Broader qualification, altitude/signing, final three QA and rollout pending. |

Storage is not blocking: production SQLite database about189 MiB and server C about13.12 GiB free at last read; VMware datastore about3515.02 GiB free at04:47:50Z; host CPU contention observed. D build drive latest read:49,859,538,944 bytes free. No resize or database move. Historical entries below apply to their recorded packages and times.

<!-- CURRENT-SEQUESTER-QUALIFICATION-END -->


## Historical qualification status - October 02, 2026, 22:39 UTC

**Windows 11 R31 delayed impersonated-read acceptance is now complete for the isolated test.** Independent archive/raw-token/Win32-original-identity checks passed: one controlled first read after the configured 34-second delay, three observations/completions, two verified preserved artifact pairs, four committed process snapshots/ACK intents, eight identical ACK replays and 40 contradictory-claim rejections. The exact original executable volume/file ID and accessing-thread versus process-primary tokens matched independent ground truth. The updated isolated server passed 53 checks, including event-history token fields and matching central binary/manifest downloads. Archive `0882FE131610C54EB64A9F0492323975F5DC75583E5C16CBED6C0655EA27C94D`, package `1BBDC2E61BABCF1646535BDEE6D453FCD6E94E2DA5D6165E4C2CEDF9C1A6F432`, source manifest `BF24C2254F1FA9C494B092C49D6C1E39399C56B240B13DE4481612A2D7F61C66`. Baseline restored and powered off at 21:56:24 UTC. This one-case result does not cover denied opens, the full matrix or production deployment.

The revised observer removes repeated in-test Task Scheduler enumeration and uses exact-file VMware completion recovery without new PowerShell/CIM processes. R29 symbols resolve repeated `ScheduledTask_EnumerateInstances`/recursive folder enumeration/task XML/account lookups in competing WMI stacks. R31's loss-free 73.607-second trace measures main actor Ready 3.499 s, Wait 37.634 s (including 34 s sleep), CPU 1.977 s; R29 measured Ready 45.575 s and CPU 2.191 s. This supports substantial observer overhead, without proving a sole cause or excluding sensor overhead. Traces have different durations; whole-trace CPU totals are not normalized rates. Different boots/rebuilt binaries and a failure-diagnostics refactor prevent a clean causal A/B claim. Manus R43 agrees that completing the corrected-controller matrix is the next proportionate engineering gate.

Analysis integrity: the first R31 WPA export was aggregate-only; its initial comparison incorrectly displayed absent thread measurements as zero. It is retained with an `INVALID-SUPERSEDED` companion. The corrected export and `R29-R31-scheduling-comparison-r2.json` contain 85,229 individual R31 switches and 1,071 actor-main switches. The analysis now rejects missing individual actor rows. No native/server acceptance depends on the invalid comparison. The general proactive verifier now explicitly recognizes the traced variant and additionally requires its sealed trace marker, ETL and stopped-WPR evidence; all existing token/hash/accounting gates remain.

**R32 original-source-identity matrix status** (each PASS includes independent raw/token/bytes checks, restored/off guest and isolated-server replay):

| Windows lab | Result | Cases | Raw observations | Token checks | Server checks |
| --- | --- | ---: | ---: | ---: | ---: |
| WIN10 | PASS | 21 | 73 | 1068 | 577 |
| WIN11 | PASS | 21 | 60 | 990 | 511 |
| 2019 | PASS | 21 | 55 | 969 | 489 |
| DC | PASS | 21 | 51 | 945 | 469 |

Every accepted platform passed 20 immediate-exit cases plus the delayed second-read case, including six denied-access cases, 21 committed snapshots, 42 identical ACK replays and 210 contradictory-claim rejections. Controlled actors' original volume/file identities and actual operation-time tokens matched independent Win32 ground truth. Unavailable background/system actor bytes stay explicit; this is not universal actor availability. Package `259C25B75E0235CE29A5C19B3FA25159493738068BDD29888F4BF0A26B9040E7`; source manifest `CDCF55F4590AE3DB1FD92FBF39DFF8047B55901669431390500D1E04D059AEF1`; driver `66AA55EF2AACF36184BA4CB63DB4FA22D8EE537BD73D6CAA945BA745BE31885C`. R32 is not a CPU-traced experiment; its sealed controller policy does not establish trace-level absence of every unrelated guest process. Failed R29/R30 receipts remain failures.

**Subsequent managed recovery correction:** an older `StableId == null` condition discarded valid historical original-volume/file metadata after private-snapshot replacement. The replacement must still fail usable-image/hash/preservation checks, but historical source identity, snapshot hash and operation-time tokens must survive. `WindowsStagedActorStore.RestoreForDelivery` now uses the same validated original-source predicate as normal recovery; the contract rejects null/corrupt source status safely. The saved before-fix fixture fails as expected. New event-bound/proactive replacement, contradictory index/null status and real HTTP event-history cases pass: **256 checks**, zero build warnings/errors (`source-volume-recovery-r3.log`, artifacts `actor-intake-fixture-cd4daf3f96cb45d0a394b2bae97eec76`). HTTP history retains the explicit failure, original identity/historical hash and thread token with no usable current hash or invented artifact. This correction is later than sealed R32 and is not described as contained in its native package.

Microsoft's altitude mailbox was checked read-only at 22:08:55 UTC: no reply, original sent copy verified, no resend. No production changes, physical desktop reboot, deadline relaxation or protection changes occurred. Native crash/load/recovery, retention/process-drain, bounded publication, remaining process metadata, Linux operation-time hash binding, altitude/signing, final product QA and rollout remain pending. Production readiness remains false.

## Qualification checkpoint - October 02, 2026, 21:54 UTC

The native minifilter remains **not production ready**. No production sensor/server changes were made in this continuation. Earlier R24 full-matrix acceptance on four isolated Windows versions and Windows 10 R27 original-source-identity/proactive/server acceptance remain valid for their exact packages; they do not qualify the later changes or the four production Windows hosts.

* **Windows 10 R30 failed:** ten completed cases (read, impersonation/context-switch cases, six denied-access cases) preceded a write actor's unchanged 15-second exit timeout. Independent failed-run component checks verified the archive, sealed runner, 180 token-field comparisons against raw OS records and independent actor measurements, original executable identity and preserved byte hashes for those ten cases. There are 42 published observations and 42 completions. This is component evidence only, not full native accounting, remaining-case coverage, or a server replay pass. Baseline restoration and power-off were verified at 21:36:15 UTC. Archive `8404B304D614AE7D99984A8D1B47D08BC3D826503758E492AF928EEC29AA5CF5`.
* **Windows 11 R29 failed:** it passed the ready marker and proactive snapshot commit, then missed the unchanged 45-second exit gate. The actor later completed its impersonated read, but the probe published zero observations/completions. Source snapshot/Win32 identity checks passed only as failed-run components. Baseline restoration/power-off verified at 21:26:02 UTC. Archive `38953D3175D16172C1AB31D32BE8ED3B550B42E4EBB8B3873D9F6FC7BA047EA8`.
* **Measured scheduling delay:** R29's 152.819-second ETL has zero reported event/buffer loss. Main actor thread spent 45.575 seconds Ready, 37.580 seconds Wait (includes configured 34-second sleep), 2.191 seconds CPU. The first WPA CSV export had 4,570 identical duplicate individual rows. Analysis v2 compares full-row digests before deduplication, retains one distinct same-tick zero-duration pair, and confirms zero remaining positive-duration CPU overlaps. Earlier uncorrected competition totals are superseded by `R29-unique-analysis.json`; the actor totals are unchanged. Competing PowerShell/WMI/services are measured, but a single trace does not establish their causal role. Switch-in priority is not assumed to be the priority throughout a Ready interval. Public-symbol resolution is ongoing.
* **Controller change / R31:** completion recovery now transfers the exact atomic completion file through VMware Guest Operations instead of launching repeated PowerShell/CIM queries. The guest wrapper queries task state only after its output file exists. Host/VM/isolation checks, package/run identity validation, deadlines and Driver Verifier remain. Both scripts pass PowerShell parsing. A newly sealed R31 Windows 11 trace run is in progress, with no extra guest progress probes. It also contains the earlier shared owned-child failure-diagnostics refactor, so it is an exploratory comparison, not a clean binary-identical A/B trial or a root-cause proof. The physical desktop has not been rebooted.

Manus R42 (`windows-defensive-sensor-r42-scheduler-diagnosis-plan.md`) agrees that Ready time demonstrates runnable delay, recommends resolved stacks and matched observer-control traces, and keeps a bounded asynchronous WCT check conditional on an actually waiting Windows 10 actor. No WCT or dump has been taken in this continuation. No deadline, capture check, admission limit, or protection was relaxed. The Microsoft altitude mailbox was checked read-only at 21:17:47 UTC: no reply; original sent copy is verified and the request was not resent.

Pending: original-source-identity matrix on all required versions; reproducible Windows 11/10 delay cause and correction; native crash/load/recovery qualification; bounded publication and retention/process-drain design; parent/command-line metadata; Linux operation-time hash binding; assigned altitude/signing; final three-pass product QA and rollout. Detailed evidence, prior successes and failures remain below.

## Qualification checkpoint - October 02, 2026, 21:13 UTC

Original executable volume/file identity has its first complete native-and-server acceptance: Windows 10 R27 passed its controlled first impersonated read after 34 seconds, with exact process-primary/accessing-thread token matches and preserved actor bytes. Independent verification checked the raw 224-byte source reply against the process acquisition key and the independent Win32 original-file query. Four observations/completions, two verified artifact pairs, three committed process snapshots/ACK intents, six identical ACK replays and 30 contradictory-claim rejections passed. Updated isolated server replay passed 58 checks and central artifact/manifest download. Archive `7FECD24E9E83681E9F8632D7599FADEEE108C81E514F396E873CAB2148D262CD`; baseline/off verified at 21:08:27 UTC. This one-case proactive acceptance does not replace the 21-case matrix or qualify all Windows versions.

Windows 11 R27 again FAILED before its ready marker. The retained diagnostic snapshot shows actor PID 3532/start FILETIME 134354483085889333 alive, main TID 2500 Ready, 1,734 ms total CPU, and no managed-entry breadcrumb or stderr at the missed gate. One thread-state snapshot does not establish scheduling history or root cause. Archive `077BAA2447F299747FBD99816890CC094B520AB113136E1849945A6AB6E7BE60`; baseline/off verified at 21:00:54 UTC. A separate component analysis confirms this failed run nevertheless captured the actor snapshot with matching hash and original source identity. Zero controlled file operations occurred; it remains failed, with no native acceptance receipt.

The real updated server also passed all 511 checks replaying the earlier Windows 11 R24 archive, preserving backward compatibility. Twenty independent source-reply/identity verifier checks passed against the retained synthetic fixture; local fixture remains 245 checks. The same R24 21-case matrix has all-four-platform acceptance recorded below. None of these results constitutes production rollout or universal Windows coverage.

Manus R41 startup review is saved as `windows-defensive-sensor-r41-windows11-startup-starvation-review.md`. It recommends loss-checked WPR scheduling/CPU evidence before changing polling or blaming verifier/runtime/VMware; a Ready sample alone cannot diagnose causality. The R29 Windows 11 diagnostic uses the detected CPU profile in bounded memory mode, caps configured buffers at 512 MiB, checks required scheduling events/stacks, preserves ETL and status output, and retains existing 15-second gate/Driver Verifier. It is running. Its sealed receipt's generic Scope string incorrectly describes a matrix; its Mode is `proactive-trace` and actual probe is one proactive attempt. The receipt is retained unchanged; the future build-label switch is corrected. This metadata issue must not be interpreted as matrix acceptance.

A harness failure-path defect was fixed separately: on a matrix actor's 15-second exit timeout, stderr was previously awaited while the child could keep the pipe open indefinitely. Shared owned-child diagnostics now capture the failure; only that exact spawned child is terminated and waited for before stderr collection. The gate is unchanged. Matrix build passes with zero warnings/errors; R28 is superseded before native use and the corrected matrix is being sealed as R30. The controller now takes its guest runner from the sealed source manifest, validates that file's digest, and newer runners record their own digest. R27 Windows 10 used the live wrapper copied by its original controller; no trace marker was present, so its test stayed in the normal path. It does not receive a retrospective sealed-runner claim.

No production changes were made. Pending: new source-volume matrix on all versions, Windows 11 proactive startup cause and correction, native recovery/load/fault qualification, process-drain/retention, reserved raw capacity and bounded classification/delivery, parent/command-line metadata, Linux operation-time hash binding, altitude/signing, final three-pass product QA and rollout. Historical evidence and failures remain below.

## Qualification checkpoint - October 02, 2026, 20:56 UTC

The same sealed R24 matrix package passed native, independent raw/token/artifact verification and isolated real server replay on all four lab Windows versions. These are isolated VMware qualifications, not a deployment to the four physical Windows sensors.

| Platform | Controlled cases | Observations / completions | Verified artifact pairs | Supplemental token checks | Server checks |
| --- | ---: | ---: | ---: | ---: | ---: |
| WIN10 | 21 | 73 / 73 | 44 | 1068 | 577 |
| WIN11 | 21 | 60 / 60 | 44 | 990 | 511 |
| 2019 | 21 | 55 / 55 | 45 | 969 | 489 |
| DC | 21 | 72 / 72 | 45 | 1071 | 576 |

Each matrix includes six denied-access cases, 20 immediate-exit actors, the delayed second read, distinct process-owner/accessing-thread/CREATE contexts, 21 verified snapshots, 42 identical ACK replays and 210 rejected changed claims. Native resource/loss accounting passed; unavailable background acquisition remains explicit. All four guests restored baseline and powered off. The Windows 10 VMware transport failure was recovered through the exact atomic completion receipt without rerunning its test. Package SHA-256 `59B224EC720361AE9BB36E1791AA6F00E0B0A328B9E3F6377FE437C51C9AFA57`.

Dedicated proactive delayed-first-touch R25 passed Windows 10: four observations/completions, two verified artifact pairs, three committed process snapshots/confirmed ACK intents and 58 isolated server checks. Server 2012 R2 has separate recovered R22 proactive acceptance and 48 server checks. Windows 11 R25 FAILED its unchanged 15-second ready-marker deadline, before any controlled operation; no ready marker or operation report was produced. PID 2692/start FILETIME 134354470486625248 identifies the owned actor. This is not a token-capture pass, nor evidence establishing the cause. Archive `78F0B5020F57B37C6A50BDBD5107623C7E7359D63F13B2CF2C169DA2AE3A219F` is retained; baseline/off verified at 20:40:03 UTC. The batch correctly stopped; Server 2019 R25 was not started.

The next candidate adds bounded owned-child thread/CPU/error diagnostics and managed startup phase markers while retaining the same startup deadline. It also captures the original NTFS executable volume GUID at minifilter instance setup and combines it with the source file index. The additive 224-byte companion reply is tied to the full provider/process/candidate/operation key. Raw operation v4 stays 3,800 bytes. Original source identity and private copy identity remain separate. A failed volume query retains its native status and does not fabricate an identifier. Proactive acquisition saves the raw reply in the checksummed process WAL; replay validates its linkage. Existing versioned forensic fields transport this metadata to the server.

Independent native ground truth uses GetFileInformationByHandle and GetFinalPathNameByHandleW(VOLUME_NAME_GUID) on the original executable. Controlled cases must match the original volume/file index and must not reuse the private copy ID. A volume GUID plus file index is a volume-scoped descriptor, not perpetual identity or proof of executed memory; NTFS identifiers may eventually be reused. The executable SHA-256 and exact process generation remain required.

Local source-volume/recovery/HTTP fixture PASSED 245 checks, including 16 malformed source replies, unavailable native status, proactive restart/linkage, source-vs-copy distinction, and real server upload/download of original source identity and exact actor bytes. Evidence: `source-volume-fixture-r2.log`, artifacts `actor-intake-fixture-186bea9a539243df9b30911a4a58f940`. Both native probes and the new server replay build compile with zero warnings/errors. Prior recovery tests remain included. The immutable R27 proactive candidate is sealed: package `831280D0A86501230921A7521450A3387BC1DA1BBEA8B836535E26021BFF65CA`, source manifest `C2235AED95459BEBB615383C8FBFFBB744CE33B05B08C57A4BFB289C5C4A6BA8`, signed lab driver `4E3323424972DA33F716D42A8E54D85BBC0F5A4B607B011A0D299E1AE8651352`. Its Windows 11 native run is in progress; these local checks do not establish native acceptance. R26 was sealed but not deployed.

No production changes were made. Pending: native source identity and recovery qualification, Windows 11 proactive startup investigation, process-drain/retention and raw capacity reservation, bounded raw delivery/classification, parent/command-line metadata, Linux operation-time hash binding, Microsoft altitude/signing, final product-wide three-pass QA and rollout. Latest altitude check at 19:58:06 UTC found no reply; the original request was not resent. Manus R40 retention advice remains documented; deletion/GC behavior is not implemented.

API references: [FltGetVolumeGuidName](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/fltkernel/nf-fltkernel-fltgetvolumeguidname), [FILE_INTERNAL_INFORMATION](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/ns-ntifs-_file_internal_information), [GetFileInformationByHandle](https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-getfileinformationbyhandle), [GetFinalPathNameByHandleW](https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-getfinalpathnamebyhandlew).

## Qualification checkpoint - October 02, 2026, 20:23 UTC

The identical sealed R24 matrix package now has independent native/token and real isolated server acceptance on three Windows versions:

| Platform | Controlled cases | Observations / completions | Verified artifact pairs | Supplemental token checks | Server checks |
| --- | ---: | ---: | ---: | ---: | ---: |
| WIN10 | 21 | 73 / 73 | 44 | 1068 | 577 |
| WIN11 | 21 | 60 / 60 | 44 | 990 | 511 |
| 2019 | 21 | 55 / 55 | 45 | 969 | 489 |

Each matrix includes six denied-access cases, 20 immediate-exit actors, the delayed second read, distinct process-owner/accessing-thread/CREATE contexts, 21 snapshots, 42 identical ACK replays and 210 rejected changed claims. Resource/loss accounting passed; background acquisition failures remain explicit. These counts do not assert universal OS coverage or capture of every memory-mapped access. All three guests restored baseline and powered off. Windows 10's VMware transport failure was recovered using the exact durable completion receipt without redispatching the test. The Server 2012 R2 R24 matrix is running, followed by the three remaining R25 proactive delayed-first-touch tests. Its R22 proactive test already has independent native and 48 isolated server checks, as recorded below.

R24 package SHA-256 `59B224EC720361AE9BB36E1791AA6F00E0B0A328B9E3F6377FE437C51C9AFA57`; source manifest `39FF0024F46929684C7FAE02F53194018178C9BF5C67102950397EE99E54132A`. These native results qualify that sealed source. Subsequent recovery changes below have separate local evidence and are being packaged as R26.

The managed acquisition recovery path now validates committed JSON semantics before dereferencing Ready/provider and retains the actual INVALID_PARAMETER HRESULT when Marshal returns ArgumentException. Terminal ACK records are checked for linkage, state, attempt history and exact saved claim. Invalid originals are retained; an immutable corruption marker is flushed before any retry, and a separate repair outcome links the damaged original's SHA-256. This prevents a later successful ACK from retroactively validating an earlier false confirmation. A recovered in-memory index has at most 256 pending intents and avoids rescanning historical control records on every retry tick. Metadata is validated on index reconstruction and intent use; this is not continuous tamper monitoring or a new framed control journal.

Local recovery/real-HTTP fixture PASSED 218 checks (`outbox-recovery-fixture-r5.log`, artifacts `actor-intake-fixture-443b7deff0e84dec8aa832936da499de`), including malformed but checksummed COMMITs, real HRESULT mapping, five damaged-outcome scenarios, deadline preservation, restart, 16 historical claims and 100 idle retry ticks with a historical intent exclusively locked. Build has zero warnings/errors. The preceding r4 fixture exposed the retroactive-confirmation bug and remains preserved as a failure. The earlier r3 no-restore build lacked assets; the restored build and 181-check fixture passed. New native failure-mode qualification remains pending.

Manus R40 retention review is saved as `windows-defensive-sensor-r40-retention-raw-reserve-review.md` (its supplied title says R39). It recommends native process-drain proof, durable snapshot pins and reserved raw capacity before temporary-copy reclamation. None of that proposed deletion/reservation behavior is implemented yet. The report's FltSendMessage timeout discussion concerns the kernel API; our user-mode FilterSendMessage call still has no timeout parameter. Latest altitude check at 19:58:06 UTC found no Microsoft reply; the original request was not resent.

No production deployment was made. Remaining work includes native recovery/load qualification, process-drain/retention, raw reserve and bounded classification, original volume identity and parent/command-line metadata, Linux operation-time hash binding, signing/altitude, final product-wide three-pass QA and rollout. Historical sections below retain their recorded results and failures.

## Qualification checkpoint - October 2, 2026, 19:54 UTC

Server 2012 R2 R22 PASSED the dedicated first impersonated read after a 34-second delay. Independent verification confirms two observations, two completions, two exact executable/manifest pairs, two committed process snapshots, and two durable ACK intents/outcomes. The one controlled case matched the operation-time accessing thread token, process owner, PID/start identity and snapshot committed before the first touch. Five background process acquisitions were explicitly unavailable and 35 background read failures were reported; this does not assert successful acquisition for every background process. Native resource/loss accounting passed. Denied-open and the full matrix are outside this dedicated test. Isolated server replay passed 48 checks, including database history, token details, central binary/manifest upload and independently hashed downloads (`integration-c0c6281423834017852ff48391be4fb8`).

The original R22 VMware controller failed its transport call at 19:27:25 UTC; the guest test completed at 19:28:03 UTC before the original shutdown. Its passing original archive was recovered without rerunning or modifying the test, SHA-256 `9DC6E4D5C6F5577FB97140571B5F0E43FF9A7111FAF452632CA69F7A26D52D49`. The original controller failure and two unsuccessful recovery helpers remain recorded. Independent native acceptance is `dc-intake-r22-recovered-final/INDEPENDENT-PROACTIVE.json`; receipt `INTAKE-RECOVERED-DC-R22.json` explicitly records transport recovery. Actual baseline ImagePath/hash and stopped service were checked; isolated guest powered off with zero NICs at 19:44:24 UTC.

Windows 10 R21 remains FAILED. Its ACK mutation test expected COMException, but the actual INVALID_PARAMETER HRESULT maps to ArgumentException. The uncaught expected rejection disconnected the diagnostic reader; only the first case matched. The initial receipt had two successful replays and five expected rejections before that exception. Archive `0F66611879799672E158080C72C95FBAE5A0DF2E86A9FE11F08323CAF307D0A3` is preserved; baseline restored/off at 19:21:42 UTC. R23 fixes this qualification harness catch without relaxing the accepted HRESULTs. The self-test verifies the three actual Marshal exception mappings and rejects an unrelated failure. R24 includes that fix and the controller changes below; its Windows 10 full matrix is running. R23 was not deployed.

The controller now persists a unique run ID before dispatch, and the guest writes an atomic completion receipt after its original results archive is sealed. If VMware transport fails, the controller reads only that exact completion path; it never redispatches the test. It validates run ID, package and driver hashes before accepting completion. If baseline restoration is unverified, it records deferred cleanup instead of interrupting the guest test. These helper changes are undergoing native runtime qualification with R24/R25. R25 is the sealed proactive package, not yet deployed. The earlier saved failures are not converted into passes.

Manus R39 reviewed Linux operation-time hash binding. Its report is retained as `linux-operation-time-hash-binding-r39.md`. Current Linux audit enrichment uses a later executable handle and cannot prove that an intervening exec did not change the image after the earlier operation. Linux SHA-based whitelist eligibility remains disabled. The proposed separate kernel provider still requires API verification and implementation; no Linux behavior was changed on the basis of the report alone.

This is isolated VMware development qualification. No production services, deployed sensors or physical desktop protection settings were changed. Current-code qualification on all four Windows versions, native failure injection, ready-feed rollover, retention/GC, full metadata, Linux hash binding, production signing/altitude, final three-pass product QA and rollout remain incomplete. Historical progress sections below retain the status at their recorded time.

## Latest actor intake evidence - October 2, 2026, 19:18 UTC

Windows 10 R18 passed the dedicated FIRST impersonated read after a 34-second pre-operation delay, exceeding the native executable-byte TTL of 30 seconds. Its immutable process snapshot was committed before the monitored operation. Independent validation matched actual raw operation-time tokens, PID/start/thread identity, prior process acquisition WAL, executable bytes, manifest and durable ACK. Four observations/completions, two preserved artifact pairs and one committed process snapshot verified. All native resources released; zero operation/diagnostic loss. Baseline restored and guest powered off at 18:43:58 UTC. This establishes one controlled delayed read, not the full operation matrix or production acceptance.

The dedicated server replay passed 58 checks through isolated HTTP, database, executable/manifest upload and independently hashed downloads. A first replay correctly failed the default matrix's denied-open prerequisite; an explicit --proactive mode now requires a successful dedicated native receipt and reports denied-open coverage excluded. The default full-matrix gate is unchanged. Failed replay log retained.

Earlier raw-first matrix results: Server 2012 R2 R16 passed 21 cases and 469 isolated server checks; Windows 11 R17 passed 21 cases and 511 isolated server checks. Both restored baseline/off. Windows 10 R17 matched all 21 cases but FAILED because 220 supplementary association journal records were dropped. Raw operation drops were zero and references released. The negative is retained. R18 adds bounded adaptive diagnostic draining; a full-matrix rerun is required. Windows 10 R19 matched all 21 cases (59 observations/completions and 44 preserved artifact pairs), then FAILED its final command-21 retry with element-not-found. The earliest snapshot was 325.744 seconds old at the final result, outside the five-minute native tombstone window; this supports a test-ordering problem, but the older failure did not name its receipt. Baseline restored/off at 19:10:11 UTC. R21 checks each receipt while retained and saves counters before final proof validation. Its Windows 10 matrix is running. No failed result is promoted to acceptance.

Local proactive recovery/HTTP fixture now passes 165 checks, including committed-WAL recovery without an index, lost ACK reply/re-entry, corrupt COMMIT and ACK rejection, PREPARE-only failure, retained-floor gap persistence, cursor restart/provider mismatch, raw queue priority, exact process keys and explicit unavailable bytes. The gap test exposed a long-path MoveFileExW failure, corrected with extended Windows paths; original failure retained. Agent opt-in compiles with zero warnings/errors. A durable 256-intent ACK outbox now persists exact claims before cursor advancement, uses four attempts with 1/2/4-second backoff in a 30-second local retry window, records terminal outcomes and retries on an independent joined worker. Synthetic restart-after-cursor-advance, exhaustion, deadline, provider-change and clock-rollback checks passed. Raw priority now allows one discovery opportunity after nine deferrals. R22 packages this for native delayed-read qualification. Native outbox/crash, ready-feed rollover/readiness-inversion, retention/GC, bounded classification, complete metadata and four-platform current-code qualification remain pending. No production deployment was made. Latest Microsoft altitude reply check at 18:56:06 UTC found no reply; original request was not resent. Manus R38 review requested.


## Actor intake progress and current qualification boundary - October 2, 2026

Exact operation-bound snapshots now feed hashing, signature inspection, actor preservation, central upload and a server-validated Windows hash-whitelist basis. Recovery failures retain tokens and validated historical metadata without reopening a later PID/path image. Additive acquisition version 1 preserves the existing raw protocol-4 token layout. Target files are not hashed or preserved by this change.

Server 2012 R2, Server 2019 and Windows 11 each passed the 21-case intake matrix in R2; Server 2019 also passed R4 durable ACK retry/rejection tests and 489 current isolated server replay checks. Windows 10 R8 matched all 21 cases but failed due to 46 capacity refusals. R11 now PASSED all 21 cases with zero capacity refusals and zero operation/lifecycle journal loss: 73 raw observations and completions, 21 snapshots, 44 preserved artifact pairs, 42 identical ACK retries and 210 rejected mutations. Its isolated central replay passed 577 checks. R7's missing-byte failure and all other failed receipts remain preserved. R6 was never deployed. Earlier staging R12 acceptance does not qualify the later intake changes.

Current regressions: 64 staged-intake/HTTP checks, 214 whitelist checks, 95 forensic checks, 56 evidence-transfer checks and 33 trust-cache checks. Agent build including command-22 and admission telemetry is clean with zero warnings/errors. Command 22 now retrieves bytes retained by the exact queued operation after candidate-table expiry; its dedicated 36-second delayed-impersonation test passed on Windows 10 and Server 2019 (R10), with independent raw-token/byte validation and 48 isolated central-server checks per platform. R11 now separates 32 header-qualification slots from 16 full-copy slots under the unchanged 32 MiB byte cap; its Windows 10 matrix passed (peak 28 header checks, two full copies, 9,545,392 bytes). The identical R11 package also passed Server 2019 (21 cases, 489 central checks). Windows 11 failed its first 15-second process deadline: the saved report places startup at 15.36 seconds and the read succeeded afterward. That negative is retained. A Windows 11 repeat with the same R11 payload and original deadline also failed (20.123-second startup) while running alone; its baseline was restored and VM powered off. Server 2012 R2 R11 also failed its first child deadline (17.178-second startup). Its incomplete wrapper cleanup was recovered: evidence archived, driver unloaded normally, baseline restored and VM off. The wrapper now uses GlobalMemoryStatusEx instead of optional WMI performance counters. Windows 10 passed a separate R12 deterministic command-22 ACK/STOP race test, independently verifying two native token identities, byte slices, eight rejected invalid ranges and zero resource/loss failures. Windows 11 R13 startup measurements completed and remain diagnostic only. R14 moves supplementary diagnostic draining to a separately joined, bounded worker on the existing connection; 69 local intake/HTTP checks passed. R14 then passed the full 21-case native matrix on Windows 11 (60 observations, 44 preserved artifact pairs, 511 isolated central checks) and Server 2012 R2 (51 observations, 45 artifact pairs, 469 central checks). Both independently verified 21 snapshots, 42 ACK retries and 210 changed-claim rejections; zero native resource/loss failures. Both restored baseline and powered off normally. R15 adds explicit earlier CREATE ground truth and token ModifiedId checks to the two principal-switch fixtures. Windows 10 and Server 2019 both passed 21 cases and independent verification, with both earlier CREATE contexts matched and no skipped CREATE ground truth. Windows 10: 82 observations/completions, 44 artifact pairs, 1,122 supplemental token assertions and 623 isolated server checks. Server 2019: 62 observations/completions, 45 artifact pairs, 1,011 token assertions and 525 isolated server checks. Both restored baseline and powered off. Windows 11 R15 matched the first 20 cases but FAILED the final long-lived child; the saved error did not distinguish timeout from nonzero exit. Baseline restored/off at 17:55:51 UTC. R17 adds child read/sleep timelines and parent wait/exit status, retaining the original deadline; product source matches R16. R16 raw-first intake changes passed 84 local fixture checks, including real isolated HTTP transfer, blocked actor collection, exhausted actor quota, lost native ACK, raw capacity/collision, recovery ownership and abrupt owned-collector termination with exact raw/token recovery; Server 2012 R2 R16 subsequently passed (see latest evidence above). This does not complete production or all-platform qualification. Supplemental raw-token checks passed on Windows 10 and Server 2019, including impersonation levels and 24/25 CREATE authorization comparisons; earlier CREATE ground truth for the two context-switch/read cases was not separately recorded. Proactive first-touch-after-expiry capture, crash recovery/retention, capacity qualification, Linux hash-whitelist work, production signing/altitude, final product QA and rollout are still incomplete.

See `docs/WINDOWS-ACTOR-INTAKE.md` for the current modules, schemas, sealed evidence, explicit limitations and remaining implementation plan. Manus R33/R34 are design reviews, not acceptance evidence. Production services and driver installations were not changed in this continuation.

## Exact operation binding accepted in the lab - October 2, 2026

R12 passed on Server 2012 R2, Server 2019, Windows 10 and Windows 11. The sealed receipt `STAGING-COMBINED-ACCEPTANCE-R12.json` records 116 independently hash-verified executable copies: 104 standalone fixtures and 12 real read/write/rename actors retrieved after exit. The 28 linked operation records preserve the expected SYSTEM user, process and PID. Full candidate identity mismatches (60), companion/event mismatches (195), and legacy invalid requests (416) were rejected. The four byte-budget, idle-expiry and publication/STOP tests passed; 7,384 lifecycle rows reconciled with zero capacity drops or journal loss. All process references and operation pins were released. Baseline drivers were restored; all four guests are off. Fifty-six background read failures remain explicit.

Package SHA-256: `E4C7B5C7ECE5A4EB941565032DF88C8FEB0801E1041E393975BAA720F0948904`. Source manifest: `66A57A29BFE50FEF13BA92D50B1EF2137B44ABC8423681601501DC55ACABCA04`. R10's failed capacity result remains preserved. Diagnostic association IDs and staging candidate IDs are separate namespaces; independent verification correlates their observed PID/start and event ordering, and never assumes the numeric IDs are equal.

This is native laboratory acceptance. These new cases do not establish the full impersonation/denied-access matrix or sensor-to-server integration. The existing product immediate-exit result remains 57/60 preserved actors. Work now connects the exact operation binding to private durable snapshot intake, separate original/snapshot identities, forensic enrichment and existing central upload. Production signing, Microsoft altitude assignment, sustained-load/recovery qualification and rollout remain pending. Provider UUID local-only status is retained; backing bytes are an interval read, not an atomic snapshot or executed-memory proof.

## Capacity correction accepted; operation binding in qualification - October 2, 2026, 09:08 EDT

**R11 passed the controlled four-platform gate.** Server 2012 R2, Server 2019, Windows 10 and Windows 11 each verified 26 backing-byte copies, six access-admission cases, four overlapping actor lifetimes, idle expiry, publication/STOP ordering and six held 7 MiB unbound opens against the unchanged 32 MiB limit. Combined: **104 verified copies, 416 rejected invalid requests, 24 byte-pressure admissions, 5,730 reconciled lifecycle records, zero capacity drops and zero journal loss**. All bytes/references released, baseline restored, Driver Verifier active, guests off. Eight unsupported background candidates per build remain explicit (32 total). This is bounded fixture acceptance, not sustained-load or full product acceptance. Sealed receipt: `STAGING-COMBINED-ACCEPTANCE-R11.json`; R10's 41/28-drop counterexamples remain sealed separately.

R11 package: `903522A20A689331B9DEB2C11BE1FEB0AEB864BE1674CDCB75EE963736128ACC`; signed driver: `D134DEDC29DDEC23E9FC7FA84B58E1C11EBD1D15E03CECEDCC63E4D14AFFACB7`; source manifest: `A27632CB93B2458EB39F7D105C28767586EA436CDB5CC85FA3A0FDE3EBA3CC64`. Functional and edge checks passed; native runtime passed under Verifier on all four versions. No UI changed. Whole-product QA and production rollout remain pending.

Candidate R12 now compiles a separate version-1 operation-binding companion, a bounded 256-entry live process registry, provider UUID with raw local-only status, monotonic process/candidate generations, operation-held byte references, and full-key fetch/ACK checks. Protocol-4 event/token bytes remain unchanged. New real read/write/rename fixtures check post-exit actor-byte retrieval, SYSTEM user/PID/process fields, missing parent-generation evidence, and mismatched provider/generation/candidate/event rejection. R12 native qualification has started; compilation is not acceptance. The user-mode production snapshot receiver, central promotion/upload and the 57/60 immediate-exit product preservation gap are still unfinished.

Manus R31 withdrew the reserved kernel FileIdInformation recommendation and supports a separately labeled volume-GUID/file-reference locator. No reserved query was added. Full operation binding and byte-pinning changes are opt-in laboratory code only.

## Lifecycle qualification and capacity counterexample — October 2, 2026, 08:42 EDT

R10 payload / R11 native receipts independently verified **104/104 fixture backing-byte copies**, 416 invalid requests rejected, 24 access cases, 16 overlapping fixture processes, four 33-second idle-expiry cases and four deterministic publication/STOP cases. The 6,325 lifecycle rows reconcile to candidate admissions and terminal outcomes with no journal loss. All four isolated VMware guests restored their baseline and shut down. **Overall qualification failed:** Windows 10 recorded 41 capacity drops and Windows 11 recorded 28, despite all fixture copies matching. Server 2012 R2 and Server 2019 had zero capacity drops. Preserve `STAGING-COMBINED-RESULTS-R10.json` as a negative result; it is not an acceptance receipt.

The implementation now includes a PASSIVE expiry worker, a bounded no-overwrite lifecycle journal, publication rundown that makes STOP wait for claimed transfers, and callback-root removal before final teardown. The pressure failure exposed completed unbound buffers consuming byte credit before slot eviction. Candidate R11 reclaims the oldest completed **unbound** buffer when byte credit is exhausted; bound actors and unfinished reads are not evicted. It also emits an individual status/reason when the 16-reader limit rejects an open. A new native test holds six 7 MiB files open against the unchanged 32 MiB budget. R11 qualification is in progress, not yet accepted.

Manus R30 reviewed alert integration. Next: opaque driver process-generation linkage, durable snapshot recovery and ACK, separate original-source versus stored-copy identities, and actual honeypot/server replay. Its proposed kernel FileIdInformation query is not adopted: Microsoft's current documentation also marks it reserved for system use. See `MANUS-WINDOWS-R30-SOURCE-NOTES.md`. Production remains on the audit source; product immediate-exit preservation remains 57/60, and this new byte path has not been deployed to production.

## Windows access and overlap qualification — October 2, 2026, 07:56 EDT

Resumed on the user's instruction after migration. Sealed R8 package/native R10 receipts passed on Server 2012 R2 9600, Server 2019 17763.9020, Windows 10 19045.6456 and Windows 11 26300.9457: **104/104 backing-byte copies and exact process-generation associations; 416 invalid retrieval/generation/ACK requests rejected; 24/24 native access-admission cases; 16 processes with independently proven overlapping lifetimes**. Each guest passed a compiled native regression over 11 requested/mapped-access combinations plus unresolved-generic rejection. All baseline paths restored, Driver Verifier active, references/bytes released and guests powered off. Receipt: `STAGING-COMBINED-ACCEPTANCE-R8.json`.

Fixed generic-execute selection in both `DiagWantsCreate` and post-CREATE byte admission using shared `ExecutableAccess.h` predicates. Original IRP access, mapped access, qualification version and CREATE status now survive in diagnostic metadata. Diagnostic reply/table/health schemas are explicitly version 2 (120/4104/168 bytes); product event protocol remains 4 and ordinary builds exclude this experiment. Native tests use generic read+execute, generic all, explicit read+execute, execute-only, read-only and MAXIMUM_ALLOWED. Win32 request masks and original IRP masks are separate observations: the explicit native case additionally reported FILE_READ_ATTRIBUTES. Native generic opens were already mapped before minifilter observation; the shared C regression directly tests unresolved generic inputs.

Four apphost children per platform waited behind ready/release events. Independent raw callback QPC records prove all four creations preceded release and all four exits followed it. This establishes overlap for these four-child fixtures, not sustained concurrent-I/O stress. The earlier four grouped cmd launches remain distinct. All 26 fixture actors per build had verified copies. Each run also reported eight unavailable background candidates (32 total), no pool drops, and 28 skipped opens; aggregate last-reason data cannot establish each unavailable candidate's exact cause. These counts are retained, not silently treated as clean or dropped events.

Default and experimental drivers compiled with warnings as errors; native reader compiled and ran on all four platforms. No UI changes or fresh product-wide acceptance claim. R7 and all negative artifacts remain intact. Product immediate-exit preservation remains **57/60** until the staged-copy path is integrated with actual honeypot operations and final server delivery. Production sensors still use audit capture. Idle expiry, per-candidate terminal records, failure/race/load qualification and production signing/altitude remain open. A new idle-expiry/lifecycle revision is next; Manus R29 review is in progress.

R8 package SHA-256: `2B0C46678351E085A6D41D3D7CE41160A848603E638EB63105F5801A50816887`; signed driver `073A56116839F19B6196A3A873BC1C6DD30947D0CB10C8ED5837DCE30C9EDE9E`; source manifest `23C3DD06654B6F02EF2E1617E474B76DAEF3140177BFEC55C1A8D922684B241E`. Microsoft altitude mailbox was successfully read at 07:50:15 EDT: submitted Sent message verified; no reply. No duplicate submission.

## Current checkpoint — October 1, 2026, 17:42 EDT

**Experimental qualification passed; production accessing-thread capture and the full forensic specification remain incomplete.** The same sealed R7 byte-diagnostic package passed on Server 2012 R2 9600, Server 2019 17763.9020, Windows 10 19045.6456 and Windows 11 Enterprise Evaluation 26300.9457. Each produced 22/22 verified executable copies and exact file-object/process-generation associations: **88/88 total**, with **352 rejected invalid generation/ID/retrieval/ACK requests**. Independent raw-trace decoding, archive hashes, saved-byte SHA-256, baseline restoration, active Driver Verifier and guest shutdown were verified. All resources released; zero read failures or pool drops in these four runs. Sealed receipt: `STAGING-COMBINED-ACCEPTANCE-R7.json`; native receipts use revision R9, payload revision R7.

The per-platform fixture is 12 immediate-exit launches, six renamed executable launches and four launches collected as a group. The four grouped launches do not prove overlapping process lifetimes or sustained concurrency. These are original-open **backing-byte** copies, not immutable image, loaded-memory or executed-byte proof. Only explicitly qualified read-and-execute opens are admitted. Each run recorded 22 skipped candidate opens; aggregate last-reason telemetry cannot classify every skipped open.

The Windows 11 VMware guest is built and qualified in test mode. Its standard token matrix adds 20/20 cases to the existing three-platform baseline: **80/80 standard USER/PROCESS/PID/thread/security-context cases**, 198 observations plus 198 completions, 164 verified artifact/manifest pairs and **1,379 isolated server checks** across four builds. Denied opens without Security auditing are included. The standard fixture has a 750-ms dwell. The separate product immediate-exit result remains **60/60 token cases but only 57/60 fixture executables preserved**; the byte diagnostic has not yet been integrated to fix those three failures.

Manus R28 passed its narrow laboratory review and identified a generic-right false negative: the post-CREATE path still rechecks raw `FILE_EXECUTE` after pre-CREATE mapped access. Correct and qualify this in a new package; do not alter the sealed R7 source. Inspection confirms the actual R7 source already retains/returns the mapped access mask and independently limits 64 metadata slots to 16 active readers. Add the maxima and qualification version/final status to future telemetry. Per-candidate terminal records, idle expiry, load/latency/STOP/oplock/mutation tests, honeypot-operation promotion and final artifact integration remain pending.

Active test signing, Secure Boot/VBS settings and Driver Verifier were read back in the isolated guests. The driver is self-signed for testing; it is not a literally unsigned kernel image. No production boot/security settings were changed. The ordinary product build excludes the byte experiment. UI was unchanged; no fresh full product-wide or production UI acceptance is claimed.

At 17:42:23 EDT, the production API reported server 0.6.15.0 with one writer and **30/30 current deployed sensors active and reporting within five minutes** (four Windows, 26 Linux). Four Windows decoy setup/sync attention states remain unresolved. Demo/revoked enrollment rows are excluded. Production continues using audit capture, so it still lacks the deployed minifilter's accessing-thread evidence. Microsoft altitude assignment was still absent at the 17:20:51 EDT mailbox readback; the existing submitted request must not be resent.

For the requested 6 p.m. boot-disk migration checkpoint, all five owned VMware qualification guests were confirmed **powered off with zero NICs**, and no owned local qualification workers remained. The desktop was not rebooted. Resume only after migration completion is confirmed. See `docs/WINDOWS-ATTRIBUTION-DELIVERY-PLAN.md`, `docs/WINDOWS-EXECUTABLE-STAGING-DIAGNOSTIC.md` and `diagnostics/windows-token-20260930/MIGRATION-RESUME-20261001.md`. Older sections below are historical snapshots.

## Windows 11 qualification and byte-copy experiment — October 1, 17:06 EDT

The new disconnected VMware Windows 11 Enterprise Evaluation guest (26300.9457) passed **20/20 controlled USER/process/PID/thread/token cases**, including a denied open without Security audit events. All 20 fixture process instances had verified executable copies. Native evidence totals: 55 observations, 55 completions, 42 verified artifact/manifest pairs, zero integrity failures, and 13 explicitly unavailable completions. Forty copies are fixture executables; two are Windows Defender actor copies, validated against their own evidence rather than the fixture hash. **366 isolated server checks** and independent persisted-evidence comparison passed. Receipt: `VMWARE-WIN11-ACCEPTANCE-R7.json`. This is standard 750-ms fixture-dwell qualification, not an immediate-exit or production pass.

Active guest settings were read back: test signing enabled, Secure Boot false, VBS inactive, hypervisor launch off, and Driver Verifier flags `0x001209bb`. The self-signed test driver loaded and unloaded successfully. Windows 11 uses `Parameters\Instances` minifilter registration. The guest was normally powered off after testing. The four production Windows sensors were not rebooted or changed.

The separate bounded executable-byte diagnostic is now implemented as an explicit compile-time opt-in. Its first Server 2019 byte run verified **19/22 copies** (all 18 sequential/renamed launches and one of four concurrent launches). The missing three copies are failures. All 22 file-object associations matched; all 54 provisional references and all byte buffers were released; no pool drops occurred. Negative receipt: `STAGING-DIAGNOSTIC-2019-R4.json`, using the retired R2 payload. Independent raw-trace and saved-byte checks confirmed that result.

Manus R24 narrowed the design to read-capable original opens. R25 identified an unsupported post-CREATE filename-buffer read and missing explicit rundown protection. The R3 diagnostic replaces the name read with Filter Manager name querying/parsing, adds `EX_RUNDOWN_REF` guards and an unload wait, requires a candidate ID for byte reads/ACK, rejects generation wrap, and separates provisional/ready counters. Duplicate admission now permits older bound generations while refusing another unbound candidate for the same file object. The revised native run and Manus R26 review are pending. **This has not fixed the product's 57/60 immediate-exit preservation result.**

The ordinary driver still builds with the experiment excluded. Full integration, failure telemetry, idle expiry, concurrency/race qualification, policy/performance tests, central delivery and production rollout remain pending. See `docs/WINDOWS-EXECUTABLE-STAGING-DIAGNOSTIC.md`. Existing production decoy setup/sync attention states remain unresolved. The 6 p.m. migration checkpoint applies.

## Earlier actor association qualified — October 1, 16:26 EDT

The successful post-CREATE no-I/O probe now passed **66/66 exact main-executable file-object associations**: 22 each on Server 2012 R2, Server 2019 and Windows 10. It covered immediate-exit, renamed and concurrent `cmd.exe` launches. All 250 published references were released, with zero candidate-pool drops, zero ring loss, independent binary/JSON trace agreement, baseline driver restoration and normal guest shutdown. Receipt: `POSTCREATE-DIAGNOSTIC-COMBINED-R1.json`.

This qualifies a conditional earlier **identity association** on those tested builds. **It does not capture bytes or fix the 57/60 immediate-exit preservation result.** Both probes remain compile-time opt-ins; the normal product build excludes them. The sealed payload SHA-256 is `FC106DFB966D4B40FA15B69F632CFFAB0107CD2D949F1A512966E1B107FAFD4A` and the signed diagnostic driver SHA-256 is `4E4172CC221117A02D8B9F63F7FCE3C7F0E5A5D4A9F1F0BB4400CF5D3BAE51A6`.

Manus R23 supplies the next section/copy ownership design, honoring PASSIVE_LEVEL, fixed metadata slots and a separate byte budget, exact process-instance binding, one close owner, explicit close failure, expiry and unload rundown. A matched lease must survive process exit. Later raw file-backed bytes cannot be called an immutable executed-image or process-memory snapshot. The design is research, not implemented byte transfer. R23 SHA-256: `58CD518DA59084638AF6E2BFA5D7696F323A05A0D5CD6494BBDFCD4952F0D635`.

A read-only production API check at **16:23:43 EDT** found server 0.6.15.0 with one writer and **30/30 deployed sensors reporting within five minutes and active** (four Windows, 26 Linux). The four Windows sensors separately report decoy setup/sync attention states. Preserve these warnings as unresolved; active monitoring is not proof that every decoy setup job is healthy. The stale demo and revoked lab enrollment rows are excluded from the deployed-sensor count. No production service, boot setting or driver was changed by this qualification work.

Windows 11 first-run setup has completed; VMware Tools bootstrap and native qualification remain pending at this entry. The 6 p.m. migration checkpoint still applies.

## Native image-order counterexample — October 1, 16:13 EDT

The no-I/O image/process diagnostic ran on Server 2012 R2, Server 2019 and Windows 10. All **66/66 child processes** had process-create **before** image callbacks; the image-first association route achieved **0/66 exact matches**. Of 484 image callbacks for those children, 483 reported `FO_CLEANUP_COMPLETE`. The result rules out relying on this callback order for the proposed earlier byte acquisition on the tested runs.

All 1,750 published file-object references were released, with no remaining live entries or ring-record loss. Server 2019 reported 47 candidate-pool drops and Windows 10 reported 83, so their diagnostic accounting gates correctly failed. Server 2012 R2 had no drops and passed accounting, while still finding zero image-first matches. All 22 children per platform had one create and one exit record, independently checked against raw binary traces and process-start ground truth. Baseline driver paths were restored and all three guests were shut down.

The corrected harness uses an NT namespace driver ImagePath and retains a process handle before waiting for the diagnostic reader's exit code. The original failed load and later negative diagnostic results remain sealed. Receipts: `IMAGE-DIAGNOSTIC-{DC,2019,WIN10}-R2.json`; independent comparisons are `INDEPENDENT-DIAGNOSTIC.json` under each receipt's output directory.

Manus R22 uses that counterexample to recommend a bounded successful post-CREATE lease, bound only by exact live FileObject equality in process-create. A separate compile-time **no-I/O post-CREATE association probe** now builds; native results are pending. It uses typed file-object references, a fixed 128-slot table, releases candidates on match/cleanup/stop/disconnect/unload, and cannot create sections, hash bytes or preserve executables. The default product build excludes both probes. No new actor-byte retention is claimed.

R22 also preserves a key limit: a file-backed data-scan section is not documented as an immutable snapshot of the executable image or loaded memory. Local WDK 26100 headers require PASSIVE_LEVEL for section create/close; apply that stricter requirement even where the public documentation lists APC_LEVEL. R22 SHA-256: `4BC709F85D1DFFF7457B8DEE136E107D797E5C7C15171634EAEC0686F562AAB9`.

## Windows immediate-exit qualification expanded — October 1, 15:59 EDT

The zero-dwell tests now cover Server 2012 R2 9600, Server 2019 17763.9020 and Windows 10 19045.6456. All **60/60 controlled USER/PROCESS/PID and token cases passed**. The server retained 143 native observations and 143 linked enrichment completions, with **985 isolated server checks** passing. Including the earlier standard matrix, 120 controlled token cases have passed. These are disconnected VMware qualification results, not production deployment.

| Platform | Immediate-exit cases | Fixture actors with copies | Verified binary/manifest pairs | Missing actor | Server checks |
|---|---:|---:|---:|---|---:|
| Server 2012 R2 | 20/20 | 19/20 | 38 | ACL change | 325 |
| Server 2019 | 20/20 | 19/20 | 39 | Asynchronous write | 335 |
| Windows 10 | 20/20 | 19/20 | 38 | Delete | 325 |

**Full actor preservation remains failed:** 57/60 fixture actors were copied. All 115 available artifact pairs matched their manifest and independent fixture image hash. The 28 unavailable completions remain recorded; they include image-less system observations and the three missed fixture actors. No target-file hashing or preservation was added. The source receipts and archive/server hashes are sealed in `IMMEDIATE-EXIT-COMBINED-ACCEPTANCE-R1.json`.

Manus R21 corrected R20: synchronous data-scan section creation in an image/process callback is not established as safe by the documented callback context. The new compile-time `ImageDiagnostic.h` branch performs only bounded reference bookkeeping and exact live FileObject comparison; it performs no callback byte I/O, creates no sections and emits no kernel pointers. The default build retains protocol 4 and excludes the diagnostic. Both variants compiled with warnings treated as errors. Native diagnostic qualification is pending; its first Server 2019 attempt failed with error `0x8007007b` from a harness ImagePath namespace error. The baseline driver path was restored and the VM shut down. That failed receipt is retained and a corrected harness run uses a new receipt revision.

An additional Windows 11 evaluation VM is being installed in VMware with no NIC, one new disk and a virtual TPM. Test boot/security settings will be verified before qualification. The evaluation ISO hash and Microsoft setup signature were checked. No Windows 11 native pass is claimed yet. The new VMware key provider has an encrypted, access-restricted backup; the previously unset default provider was restored after this VM was created.

The altitude submission's Sent copy remains verified; no Microsoft assignment reply existed at the 15:26 EDT readback. Production still uses the Windows audit source. See `docs/WINDOWS-ATTRIBUTION-DELIVERY-PLAN.md` for the implementation sequence and outstanding release gates. The older entries below are historical snapshots and do not supersede this section.

## Windows immediate-exit attribution — October 1 UTC

The additional **Server 2019 / 17763.9020** test removed the operation fixture's 750-ms post-operation wait and recorded actual process exit timestamps from the parent process. It used the accepted R7 intake collector and the unchanged test-signed minifilter in an isolated, zero-NIC VMware guest.

**20/20 operation-time USER/PROCESS/PID and token comparisons passed**, including the six denied-access cases and changes between the process owner and accessing-thread impersonation context. A separate denied read with no SACL and failure auditing disabled also passed. All 49 native observations and 49 linked forensic completions were retained. Native lifecycle checks passed and the driver unloaded normally.

Executable preservation was **incomplete**: 19/20 test processes had copies, with **39 verified actor binary/manifest pairs**. Two asynchronous-write observations retained correct identity/token evidence but no actor hash or executable copy. The remaining eight unavailable outcomes were image-less PID 4 observations. Available copies matched both their manifests and the independently built fixture executable's SHA-256. No target files were hashed or copied by the forensic collector.

The missing asynchronous-write actor exited at **10:08:04.2147261 UTC**; its first capture was stamped **10:08:04.3308473 UTC**, about **116 ms after exit**. Native error 31 and the unavailable preservation reason remain stored. This is direct evidence that a dedicated receive thread does **not** eliminate first-acquisition-after-exit failures. Missing bytes did not discard or replace the native user/process/thread evidence.

The actual mixed result passed **335 isolated central server checks**, including HTTP ingestion, database field comparison, preserved-artifact upload/download, and explicit unavailable outcomes. All 98 original/completion records survived database comparison; six retained-image provenance records remained linked correctly. The first acceptance script attempt completed the server tests but failed receipt selection because a PowerShell automatic variable was used as a path variable. That harness defect was corrected, the failed attempt was retained, and acceptance was rerun successfully. It is not a sensor or server runtime failure.

The guest was confirmed **PoweredOff at 10:12:14 UTC**. The guest-tools shutdown call was interrupted while the guest was shutting down; final power state was independently read. No production deployment, host restart, driver activation or boot-policy change occurred.

Acceptance `IMMEDIATE-EXIT-2019-ACCEPTANCE-R1.json` explicitly sets **AttributionPassed=true**, **FullPreservationPassed=false**, and **ProductionReady=false**. The immediate-exit matrix has only been run on Server 2019; it does not establish zero-dwell qualification on the other Windows versions. Together with the three-platform standard matrix, there are **80 passed token scenarios**, while executable capture remains a separate, incomplete capability.

Manus R20 and primary Microsoft documentation identify `FltCreateSectionForDataScan` as a potential earlier raw-byte retention mechanism. Section lifetime, callback context, main-image binding, cleanup/conflict handling and bounded worker behavior need separate native proof. No data-scan section implementation has been added to the product. Research report SHA-256: `45698BD63635A3D44EB9EE13CFD915292F6C9164B38CF52D81FDF6A94132E009` (`MANUS-WINDOWS-IMAGE-LEASE-R20.md`). Microsoft altitude allocation, production signing and certification gates remain pending; production still uses the audit source, which cannot supply accessing-thread tokens.

Receipts: `IMMEDIATE-EXIT-2019-ACCEPTANCE-R1.json`, `WINDOWS-TOKENS-2019-IMMEDIATE-EXIT-R1.json`, `DENIED-WITHOUT-AUDIT-2019-IMMEDIATE-EXIT-R1.json`, `VMWARE-2019-ARTIFACTS-IMMEDIATE-EXIT-R1.json`, `IMMEDIATE-EXIT-PACKAGE-R1.json`, and `IMMEDIATE-EXIT-LOCAL-CHECKS.json` in workspace diagnostics. The new immediate-exit fixture and scratch directory preserve the prior qualified fixture and collector files.



## Windows dedicated intake receiver — qualified R7, October 1 UTC

The native receive loop now stays on one dedicated thread, including idle and reconnect waits. Slow shared-pool work can no longer delay its continuation after a polling wait. Durable journaling still precedes acknowledgment, and existing bounded executable retention remains in place. This change reduces a scheduling risk; it does not guarantee first acquisition before every process exits.

The accepted R7 candidate passed the standard controlled NTFS matrix on all three Windows builds:

| Platform | Operation/token cases | Test processes with executable copies | Verified binary/manifest pairs | Server checks |
|---|---:|---:|---:|---:|
| Server 2012 R2, 6.3.9600.18734 | 20/20 | 20/20 | 41 | 334 |
| Windows 10, 19045.6456 | 20/20 | 20/20 | 40 | 336 |
| Server 2019, 17763.9020 | 20/20 | 20/20 | 41 | 343 |

Combined: **60/60 operation/token cases**, **122 verified actor copies**, **143 original observations / 143 completions**, and **1,013 real isolated server checks**. The 21 image-less PID 4 observations remain explicitly unavailable. Each platform also passed denied-open capture with no file SACL and Security failure auditing disabled. Process-owner, accessing-thread effective context and CREATE authorization remained separate. Native lifecycle tests and normal driver unload passed; all three zero-NIC guests were confirmed off before acceptance was sealed.

The Windows 10 run used retained-image provenance in four event records; that provenance survived actual HTTP upload and database persistence. All native copied binaries/manifests were independently hash-verified after central download. Three QA passes for this change are recorded: (1) native operation/token/image behavior and persisted evidence; (2) **95 local forensic checks**, including deliberate shared-pool starvation, cancellation and fault propagation, plus **23 product regression suites / 1,809 PASS lines / zero failed suites**; (3) packaged native runtime, reconnect/queue lifecycle, and real isolated server startup/ingestion/download. No UI code changed; fresh DOM tests passed, and earlier visual screenshots remain historical rather than claimed as rerun.

**Timing boundary:** the standard operation fixture waits 750 ms after writing its operation report. It is not a zero-dwell process-lifetime guarantee. The earlier Server 2019 packaging failure is retained in `DRIVER-QUALIFICATION-NOGO-20261001.json`; its exact process exit time was not logged. For the rename case, minimum acquisition delay changed from 1,323.9 ms in that failed run to 43.5 ms in the R7 run. These separate runs do not prove the original scheduling cause or a worst-case delay. A separate immediate-exit fixture removes the dwell and records parent-observed exit times; its native result is tracked independently.

Acceptance was sealed at **10:05:25 UTC** in `INGRESS-R7-COMBINED-ACCEPTANCE.json`, with an immutable snapshot of **13 unique source files**. Test payload SHA-256: `FF787C41A6BF85A7FB5CB9989882F0CCE5F5605307B7A4F6BF33325C4792EB26`. It is a qualification payload, not a production installer. Kernel driver/protocol and standard operation fixture were unchanged. The initial R7 setup attempt failed to resolve a relative service driver path; the harness was corrected, that attempt remains retained, and it is not counted as a native test pass.

**Production remains on the audit source and cannot supply accessing-thread tokens.** At **10:00:06 UTC**, all **30 expected sensors** were active/current, including four Windows hosts; the 33 enrollment IDs were unchanged and server **0.6.15.0** had one writer. No production restart, driver activation, service replacement, or boot-security change was performed. Microsoft had not replied to the submitted altitude application at the **10:00 UTC** mailbox check. The assigned altitude, applicable signing/HLK/HCK qualification, clean signed installation and live-host rollout remain pending. Existing audit monitoring remains active throughout this qualification work.

Manus R18/R19 and independent Microsoft documentation review identified a documented image-load reference route through `IMAGE_INFO_EX.FileObject`. A retained object reference alone does not make a file safe for delayed reads. Notification correlation, an owned open and an independent verified file-ID read remain research, not an implemented or qualified preservation guarantee. First image acquisition still uses process/path checks unless an earlier retained handle is available; it is not yet bound to a kernel-retained main-image file object. Its disk-image provenance remains explicit, and loaded-memory verification is not claimed.

Primary receipts: `INGRESS-R7-COMBINED-ACCEPTANCE.json`, `INGRESS-R7-SOURCE-SNAPSHOT.json`, `VMWARE-*-ACCEPTANCE-INGRESS-R7.json`, `LOCAL-WINDOWS-FORENSICS-INGRESS-R7.json`, `INGRESS-R7-PRODUCTION-INVENTORY.json`, `R7-2019-CAPTURE-LATENCY-COMPARISON.json`, and `WINDOWS-IMAGE-RACE-REVIEW-20261001.md` in workspace diagnostics. Historical stages below remain preserved.



## Windows altitude application and package qualification — October 1 UTC

**Production remains on the audit source; it cannot supply accessing-thread tokens.** The replacement kernel provider passed the controlled token tests, but the complete driver package is **not approved for rollout**.

The altitude application for Tekmyster Industries, LLC / seQuester / `SeQuesterActor.sys` was submitted from `daniel@tekmyster.com` to Microsoft's `fsfcomm@microsoft.com` at **08:32:02 UTC**. The mail relay accepted it and the Sent copy was verified. No Microsoft assignment has been received. `385200.923` remains a test altitude, never an assigned production altitude. Relay acceptance does not establish final recipient delivery or allocation.

New packaging under `packaging/windows-kernel` and `tools/build-windows-kernel-package.ps1` produces legacy server and Windows 10 INF/catalog candidates with pinned driver bytes and manifests. WDK INF and catalog validation passed without warnings; **38 packaging/refusal checks passed**. Packaging never sets production readiness, signs a release, installs a driver, or enables kernel capture. The builder refuses existing output, changed inputs, invalid altitude ranges and relabeling the test altitude as Microsoft assigned.

Fresh isolated VMware qualification used the current Windows builds, the exact previously accepted test-signed driver, and no guest network adapters:

| Platform | Build | Operation/token cases | Fixture processes with preserved executable | Verified artifact/manifest pairs |
|---|---|---:|---:|---:|
| Server 2012 R2 | 6.3.9600.18734 | 20/20 | 20/20 | 41 |
| Windows 10 Enterprise | 10.0.19045.6456 | 20/20 | 20/20 | 40 |
| Server 2019 | 10.0.17763.9020 | 20/20 | **19/20** | 38 |

All three also passed a denied-open test with Security failure auditing disabled. Compared fields included PID/start identity, accessing thread, effective security context, process primary context and CREATE authorization context. These are the captured token evidence fields, not an atomic serialization of every possible token property. Installation was verified without reboot. The legacy test began with an existing stopped test-driver setup; it does not establish a clean production installation. All three guests were shut down normally after qualification.

**Release-blocking preservation race:** Server 2019's rename actor image was unavailable at its first user-mode acquisition, consistent with process exit before capture. Three observations retained the correct native actor/token metadata but no executable bytes or hash. First acquisition was approximately **1.324 seconds** after the first observation; the cause of that delay is not yet established. The fixture records operation completion and then waits 750 ms; its exact process exit time was not logged. Combined result: **60/60 token cases**, **59/60 fixture processes preserved**, 144 observations and completions, 119 verified artifact pairs, 25 explicit unavailable outcomes (22 image-less PID 4 events plus the three rename-actor events). This is not a complete preservation pass. The original failed evidence and hashes are retained. The qualification wrapper now explicitly rejects incomplete actor preservation and refuses overwriting prior receipts. Gate replay accepts the Windows 10 and 2012 R2 receipts and rejects the 2019 receipt.

Product regression passed **23 suites / 1,809 PASS output lines / zero failed suites**; PASS lines are not a count of independent test cases. No product UI changed in this packaging continuation. Previously recorded R6 central transport and UI checks remain historical evidence; they do not erase this newly observed race or establish production deployment.

Production API readback at **09:15:35 UTC** showed **30/30 expected sensors active**, 33 retained enrollments and server **0.6.15.0**. The four Windows hosts remained on sensor **0.6.13.0**, with kernel opt-in disabled and no product driver installed. No production reboot, driver installation, signing-policy change or service replacement occurred in this continuation.

Remaining gates: correct early executable acquisition and regression qualification; Microsoft altitude reply; production signing/account prerequisites and applicable HLK/HCK tests; final signed package, clean installation, broader I/O/load/coexistence qualification and production receipts. The existing source labels unsupported contexts and missing evidence explicitly. Neither a later same-path file nor PID alone may substitute for the actor executable. Manus R18 is reviewing a supported earlier acquisition design; no undocumented process-image export has been adopted.

Primary receipts in `diagnostics/windows-token-20260930`: `ALTITUDE-REQUEST-STATUS-20261001.json`, `DRIVER-QUALIFICATION-NOGO-20261001.json`, `ARTIFACT-ACCEPTANCE-GATE-20261001.json`, `DRIVER-INSTALL-*-R2.json`, `WINDOWS-TOKENS-*-INSTALL-R2.json`, `VMWARE-*-ARTIFACTS-INSTALL-R2.json`, and `SERVER-DRIVER-PACKAGE-20261001.json`. The historical Server 2019 wrapper's `Passed=true` covered installation/token execution only; the separate artifact receipt failed, and the combined decision is explicitly **no-go**.



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

## Current candidate — ingress r6, October 1 UTC

The unchanged test driver and final user-mode retention candidate passed the controlled native matrix on all three current Windows OS variants:

| Platform | Native scenarios | Verified actor binary/manifest pairs | Native records, including completions | Server checks |
|---|---:|---:|---:|---:|
| Server 2012 R2, 6.3.9600.18734 | 20/20 | 41/41 | 94 | 337 |
| Windows 10, 19045.6456 | 20/20 | 40/40 | 96 | 336 |
| Server 2019, 17763.9020 | 20/20 | 41/41 | 98 | 343 |

Each platform also passed a separate denied-open test without Security failure auditing. User/process/PID and distinct accessing-thread/process-owner tokens matched independent fixture ground truth. All **122 image-bearing observations** have verified executable copies; **22 image-less PID 4 observations** remain explicitly unavailable. Real HTTP/database/upload/download checks total **1,016**. A separate database comparison verifies the actor, process, operation and preservation fields for all **288 original/completion records**.

The three verification passes are complete for this candidate's tested scope:

1. **Functional:** the native matrix above, **94 Windows forensic checks**, **54 Linux forensic checks**, exact byte/hash checks and central evidence persistence.
2. **Edge/regression:** PID reuse, process exit, renamed/replaced executables, cache capacity/expiry, token separation and **23 suites / 1,809 pass lines**. Driver queue/reconnect/ACK/overflow tests pass on each guest. Earlier failed harness/capture attempts remain retained.
3. **UI/runtime:** **52 console** and **21 native-token UI checks** passed with the final Windows 10 records. Phone/desktop screenshots were inspected; user/process/PID and separate token panels are visible. All three Windows VMware guests and the owned preview are stopped. Five builds completed without warnings/errors.

Executable retention is bounded to **64 exact process instances and a fixed 30-second reuse window**. R6 adds expiry during provider reconnect failures. The retained object is reopened using its file handle, never inferred from a matching name/path. Each event keeps its own tokens and records the original binding event/time. The prior r5 Windows 10 run exercised this native post-exit fallback; r6's 94 forensic checks exercise it again. An actor exiting before the first successful image capture can still lack bytes.

Production is unchanged: the API readback at **05:42:13 UTC** verified **30/30 expected sensors active**, 33 retained enrollments and server 0.6.15.0. This is **isolated qualification, not production kernel deployment or full-spec completion**. Assigned production altitude, Microsoft signing, broader I/O/load coverage and Linux trusted hash eligibility remain open. Disk-image evidence does not establish loaded-memory integrity, and separately queried token fields are not an atomic serialization of every token property.

The sealed package, 12-file source snapshot and per-platform receipts are linked by workspace diagnostic `INGRESS-R6-COMBINED-ACCEPTANCE.json`. Historical entries below retain their original stage-specific results.

## Historical candidate: ingress r4, September 30 evening

1. **Functional:** native Server 2012 R2 6.3.9600.18734 and Server 2019 17763.9020 each passed 20/20 token/path scenarios, all six denials and a separate unaudited denial. All 20 fixture processes on each platform now have preserved actors. Each run produced 41 independently verified binary/manifest pairs; five DC and eight Server 2019 PID 4 records explicitly lack executable images. All 92 DC and 98 Server 2019 observations/completions survived real HTTP/DB replay, with every native artifact pair uploaded and independently download-hashed: 334 and 343 checks respectively. Prior partial preservation evidence is retained.
2. **Edge/regression:** 71 native Windows forensic checks (including deferred metadata after process exit, ownership/queue cleanup and a genuinely locked retry file), 54 native Linux forensic checks, and all 23 regression suites passed. Native Driver Verifier load/unload succeeded on both VMware guests; 2,063 DC and 2,062 Server 2019 lifecycle assertions passed, with deliberate bounded overflow reported as 352 and 354 drops respectively. Old Verifier formatting, prior harness-manifest differences and administrator-context LocalService logon failures are retained and corrected without relaxing identities. The final r4 source and package hashes are saved separately.
3. **UI/runtime:** Windows agent builds without warnings/errors. All 52 packaged-console checks passed on a fresh isolated seed; a previous aged seed correctly changed to offline and is retained as a test-harness failure. All 21 native token-panel checks passed using the r4 DC records; phone and desktop screenshots were inspected. SYSTEM process owner and LocalService accessing identity remain distinct. Both VMware test guests are confirmed off; the final owned UI preview is stopped. Production readback at 01:37:50 UTC October 1 verified 30/30 active required sensors and 33 retained enrollments. Windows 10 kernel qualification is pending; 71 user-mode checks passed on that host. No production update occurred. Earlier entries below preserve the results at their recorded stage.

## October 1 UTC: Linux BPF research qualification

The r9 instrumented provider repeated the nine-case matrix. The r10 owned-map fault tests then passed **64 execs with a full map**, **64 with a saturated generation counter**, and **64 after fresh-map recovery**. Actor hashes remained correct, raw capacity errors stayed visible and no failed identity became known/eligible. This proves bounded failure behavior, not uninterrupted production capacity or preexisting-process continuity across reload. All hooks detached and the r10 source/native archive was downloaded and hash verified (`LINUX-PROVENANCE-FAULT-ACCEPTANCE-R10.json`, `LINUX-PROVENANCE-ARCHIVE-R10.json`).

The corrected four-hook LSM prototype passed **nine native scenarios** (including **64 distinct successive exec generations**) with independently matched actor hashes, child/parent PID ground truth, failed-rewrite taint and zero observed ring loss. A separate r9 test proved a successful cross-TGID executable-association rewrite fully overlapped the hash interval; the original actor hash was correct, but post-hash taint rejected identity eligibility. All owned programs detached. Source/native bundles were downloaded and independently hash verified. Receipts: `LINUX-PROVENANCE-ACCEPTANCE-R8.json`, `LINUX-PROVENANCE-RACE-ACCEPTANCE-R9.json` and their archive receipts in workspace diagnostics. The 24 MiB race actor took approximately 363 ms to hash: live-endpoint performance and cache freshness are not accepted. No product UI, production provider or whitelist policy changed; integration, exhaustion and restart gates remain open.

Additional native edge case: a different-TGID `CLONE_VM` peer successfully rewrote the parent's executable association; two observed hashes matched the original/replacement bytes with the same parent PID/start time. The original write barrier was released and the new association remained protected; zero executable bytes were written. `LINUX-MM-REWRITE-ACCEPTANCE.json` records the independent assertions and complete probe detach. The first provenance-tracker attempt failed admission (`fentry/__mmput`, `EBUSY`); it released every owned BPF program and did not emit an eligible event. This is a retained failed qualification, not a pass. No product UI or deployed sensor changed.

The optional Linux provider is a research prototype; no production sensor code or policy was replaced. Five positive attribution scenarios and one negative coverage-boundary scenario passed on 6.12.94+deb13-amd64: short-lived actor, same-PID exec with distinct actor hashes, renamed executable, replaced pathname, unprivileged credentials and the absence of this hook on a DAC-denied open. Six captured hashes matched independent actor SHA-256 values. Every event remained ineligible for whitelist suppression. The first raw inode-version comparison failure is retained; kernel source established that IMA's query-bit change was not a content revision, and the corrected provider records both values and filesystem flags. Actual load/attach, zero loss in this bounded run, and independent detach verification passed. No product UI changed; server/UI integration and full provider qualification remain pending. See `docs/LINUX-KERNEL-ATTRIBUTION.md` and workspace receipt `diagnostics/windows-token-20260930/LINUX-BPF-ACCEPTANCE-R4.json`.
## 2026-09-30 evening: Server 2019 native acceptance and early-capture candidate

1. **Functional baseline:** Server 2019 Datacenter Evaluation **17763.9020**, isolated VMware with zero NICs, passed 20/20 token/path cases and a separate denied read without audit configuration. Thirty-five binary/manifest pairs cover all 20 fixture processes; zero integrity mismatches. Fourteen remaining completions explicitly report unavailable preservation. Receipt: `diagnostics/windows-token-20260930/VMWARE-2019-ACCEPTANCE.json` at workspace root.
2. **Edge/runtime baseline:** 2,062 lifecycle assertions passed, including reconnect, wrong ACK and explicit overflow (2,048 queued, 354 dropped). Verifier reports one driver load/unload and zero pool allocation failures. The first 17/20 test window failure is retained separately. Hypervisor independently confirmed power off after the guest shutdown API disconnected. No production driver or boot policy changed; fresh readback verified 30/30 sensors and 33 retained enrollments.
3. **New candidate, not deployed:** native intake/publication separation, bounded early executable retention and deferred optional Windows metadata. All 69 native forensic checks pass, including process exit, immutable original/completion records, optional metadata failure and ownership cleanup. Windows agent build passes without warnings. Candidate native VMware acceptance, release regression and packaged runtime checks are in progress. Driver/protocol unchanged; no new UI fields. Windows 10 native kernel qualification and full broader-load coverage remain pending.

## 2026-09-30 later: native Server 2012 R2 VMware qualification

Only the isolated test fixture/runner and documentation changed in this continuation; deployed product binaries remain the previously verified releases.

1. **Functional:** NIC-free VMware copy of the actual DC, Server 2012 R2 Standard 6.3.9600.18734, passed 20/20 independent operation/token comparisons: 47 observations and 47 forensic completions. SYSTEM process ownership and LocalService accessing-thread identity remained distinct. A separate denied read passed with no SACL, failure auditing off, and zero Security 4656 events. A stricter comparison of the same saved capture also matched executable paths for all 20 cases; it is not a new native run. See `diagnostics/windows-token-20260930/WINDOWS-TOKENS-2012R2-WITH-IMAGE-CHECK.json` and `DENIED-WITHOUT-AUDIT-2012R2.json` at workspace root.
2. **Edge/regression:** all six denied operation cases, identity transitions between open/read, async and mapped operations, rename/delete/ACL, queue/reconnect/ACK/overflow lifecycle checks ran on that native build under Driver Verifier. Initial pre-reboot load, disconnected AD setup and administrator service-logon failures are retained separately. Reboot verification now checks actual boot time and active startup flags; unique archives preserve each attempt. The fixture gained an opt-in documented LocalService logon for disconnected DC tests; default account behavior remains supported.
3. **Runtime:** driver loaded/unloaded under Verifier; the DC copy was confirmed powered off at 22:56:08 UTC with zero NICs. Production readback at 22:51:18 UTC verified 30/30 active sensors, all four Windows clients and 33 retained enrollment IDs. No production driver or boot-security change occurred. There was no new product UI change; the previous packaged-console/browser checks remain the UI basis.

**Open gates:** actual Server 2019 17763.9020 and Windows 10 19045.6456 driver qualification, production signing, assigned altitude and broader I/O/load coverage. The 2012 R2 run's 47 completions include 20 hash-verified executable/manifest pairs and 27 explicit preservation-unavailable results; only 15 of 20 fixture processes had a preserved actor. This is token acceptance, not complete executable-preservation acceptance. The Blue Iris hot clone failed without changing its production configuration. A fresh VMware Server 2019 evaluation guest is in preparation and is not yet a pass. Company/email/URL are filled in the unsent altitude request. These passes are not HLK certification or universal file-touch coverage.

## 2026-09-30 17:42 EDT: accessing-thread integration, denied coverage and user-mode rollout

Server **0.6.15-dev** and all four Windows sensors **0.6.13-dev** are deployed. The 26 Linux sensors remain **0.9.17-linux-dev**. Final inventory at 21:38:41 UTC passed 30/30 required sensors and retained all 33 enrollment identities and callback listener PID 1416. **The kernel driver remains isolated and is not enabled on any production host.** [Acceptance and exact boundaries](../../diagnostics/windows-token-20260930/RESULTS.md).

1. **Functional:** final protocol-4 driver passed 20/20 native Server 2022 scenarios with 68 original events and 68 forensic completions, including six denied operations, separate CREATE/thread/process token identities and identity changes between opening and reading. A separate denied read with no SACL and failure auditing disabled produced exact kernel PID/TID/token evidence and zero Security 4656 events. Actual sensor journal/spool, HTTP, database, history and whitelist integration passed 240 checks; native actor preservation passed 59 and transfer passed 56. Production audit tests matched User/Process/PID for all 40 original cases; accepted 40 cases (one recorded rename repeat) and four denied reads verified central binary/manifest downloads.
2. **Edge/regression:** all 23 regression suites passed, including 391 history checks; audit parser/SACL checks cover failure auditing. Native queue tests cover exact-path exclusion, peek/ACK, disconnect, invalid ACK, bounded capacity and drain. Stress deliberately reported 353 drops at 2,048 queued records, rather than hiding loss. Integration checks cover process exit/PID reuse, conflicting identities, missing token fields, clock rollback, immutable retry labels/paths, reload gaps and legacy receipt rejection. Compatibility edits replace newer push-lock imports with legacy Filter Manager APIs and remove ExAllocatePool2; the final corrected binary repeated the native matrix under Driver Verifier. Compatibility does not establish native qualification for older OS versions.
3. **UI/runtime:** 52 packaged-console and 21 token-panel browser checks passed, including separate token identities, denied outcome, mobile layout and retained User/Process/PID/OS/status presentation. User-mode deployment preserved enrollment/configuration and matched 30 server assets. Central pending receipts were independently re-read until all accepted artifacts downloaded correctly. Blue Iris and desktop health warnings were cleared by a scoped sensor restart only after zero outstanding uploads. The isolated VM's prior driver was restored, its network-adapter count stayed zero and it was powered off.

**Retained failures/limits:** the first 0.6.12 Blue Iris burst had two enrichment-capacity failures; the fresh 0.6.13 matrix had one rename enrichment-capacity failure. Original observations and unavailable evidence remain; separate successful repeats do not repair old events or prove lossless volume. The upload health string can remain latched after recovery; no automatic health-clearing behavior was added. Windows audit still lacks an accessing-thread token. Production driver signing/assigned altitude and Server 2012 R2, Server 2019 and Windows 10 native qualification remain open; null-thread/high-IRQL/paging/SMB/other-filesystem coverage is not certified. These tests do not establish live external notification delivery, new Linux acceptance or a fresh remote callback matrix.

## 2026-09-30: deployment and per-operation attribution acceptance completed

The user authorized deployment to the server and all existing sensors, and required accurate User/Process/PID checks after deployment, especially on Windows. Final acceptance at **2026-09-30 13:55:05 UTC (09:55 EDT)** confirms server **0.6.14-dev**, all **four Windows 0.6.11-dev** sensors and all **26 Linux 0.9.17-linux-dev** sensors. All 30 required sensors were fresh and actively monitoring; all 33 endpoint records were retained. [Inventory, immutable package hashes and all 274 operation results](../../diagnostics/deploy-all-20260930/FINAL-ACCEPTANCE.json). Saved live API snapshots contain **317 unique native audit events across these 274 cases, with zero missing User/Process/PID display fields**; repeated retrievals were deduplicated by endpoint/event ID. Linux displays captured numeric identities. Windows preserves the native account label and SID; SYSTEM SID S-1-5-18 can carry a machine-account label. [Display-field proof](../../diagnostics/deploy-all-20260930/DISPLAY-FIELD-VERIFICATION.json).

1. **Functional:** new Windows 0.6.11 binaries passed 59 native forensic checks; real HTTP actor transfer passed 56 checks against server 0.6.13 and again against 0.6.14. All four Windows sensors passed **40 controlled cases** with independently recorded actor identity, process start, owner SID and accessing SID, exact server event matching, and downloaded binary/manifest SHA-256 verification. A SYSTEM impersonation case on each host distinguishes the administrator process owner from the SYSTEM event subject. All 26 Linux sensors passed **234 established-process cases**, nine per host: read, write, append, truncate, copy, mapped read, rename, permissions and delete. Every one of the 274 cases has matched User/Process/PID, durable process identity and independently downloaded central actor/manifest hashes. Linux's 53 native forensic and 56 transfer fixture checks were September 25 qualification; the 234 installed-service cases are fresh September 30 evidence.
2. **Edge/regression:** all 23 regression suites passed on the initial candidate and again after the server request-budget correction. Nine additional capacity checks prove that saturated artifact traffic cannot exhaust the reporting budget, both budgets remain bounded, and lookalike routes do not create extra pools. The first Linux archive retained a 0.9.16-only launcher guard and failed the Plex pilot. Monitoring was restored on the old release, a corrected immutable archive was sealed, audit enablement restoration was added to upgrade/rollback, and the corrected native pilot passed. Both failed and corrected archive hashes and receipts are retained. No audit/PID identity safeguard was weakened.
3. **UI/runtime:** 8 transfer, 13 forensic, 16 whitelist and 52 whole-console checks passed against 0.6.13; all 52 packaged console checks passed again against 0.6.14. Each server deployment preserved all 33 endpoint IDs and the event high-water mark, matched 30 served assets and retained callback listener PID 1416. The final API inventory gate passed **30/30**, with exact expected versions/OS, active monitoring and heartbeats within 90 seconds. Owned preview processes were stopped. Target file contents and permissions were restored and checked; original failed probes and pending-transfer results remain alongside their successful reruns.

**Retained limitations and failed probes:** all nine immediate-fork Linux operations retained accurate core user/executable/PID, but seven could not safely bind a process instance and actor image because audit/procfs start ordering was ambiguous. They retain explicit unavailable evidence; only two produced full preserved/uploaded actor evidence. A separate established-process run passed all nine. The original Windows mapped-read test had a PowerShell null-string argument defect and was corrected and rerun. An anonymous denied-open probe produced no watched-target event and is not a coverage pass; successful SYSTEM impersonation is separately verified. Windows audit does not expose the full accessing-thread token. Linux attributed opens do not establish completed byte counts or prove a complete copy/truncate; Windows access-right events likewise do not prove completed rename/delete semantics. Existing production whitelist policies, boot security and kernel providers were preserved. Live external SIEM/mailbox delivery and a new 14-type callback matrix are not claimed by these local file-operation checks.

## 2026-09-25: Manus follow-through on token identity and central executable transfer

**Candidate/prototype QA completed for the scope below; no production deployment. Linux event-time hash whitelist matching remains unfinished.** Detailed implementation, research conclusions, evidence paths and remaining release gates: [RESULTS.md](../../diagnostics/forensic-gaps-20260925/RESULTS.md).

1. **Functional:** report-only Windows minifilter protocol 3 passed **15/15** native scenarios with **37** captured events and independent token comparisons. CREATE authorization, requesting thread and primary process identities remain separate across impersonation/reversion. Global name-query failures **2,344** remain visible; zero queue drops does not mean universal coverage. Existing actor forensics passed **59 Windows / 53 Linux** checks. Real sensor upload client plus isolated HTTP server and SQLite passed **56 transfer checks on each OS**, including durable receipts and exact binary/manifest downloads.
2. **Edge/regression:** **23/23 existing suites passed**. Transfer cases cover authentication/revocation, cross-sensor denial, altered/duplicate-key manifests, offsets/retries, size/quotas, restart and final-file-before-DB recovery, corrupt stored artifacts, local retention, bounded pumping and rotation past eight persistent failures. Both native transfer suites were rerun after the final SQL-provider count conversion; broad regression/UI preceded that isolated scalar change. SQL Server native rehearsal and physical power-failure injection were not performed. A native Linux exec counterexample held PID/start/pidfd constant while the executable hash changed; this proves the binding gap, not implementation of Linux hash whitelisting.
3. **UI/runtime:** **8 upload, 13 forensic, 16 whitelist, 52 whole-console** browser checks passed, using the actual published console and authenticated APIs. Artifact and manifest bytes downloaded through the browser matched recorded SHA-256. Local-only evidence showed no central download. Desktop/mobile screenshots inspected; Sensors labels, OS logos, colors and User/Process/PID remain present. Test-harness errors (relative API URL, stale whitelist fixture path, fixed total count after additional seed events) were corrected and affected suites rerun. Earlier failed outputs are retained. Linux verified all **1,118** reconstructed package files before execution.

The new upload flow only queues newly preserved artifacts; no historical backfill/retention cleanup is added. Windows prototype continuous integration, OS/I/O coverage, production signing/altitude, Linux operation-time content binding, and production pilot/all-sensor acceptance remain open. The isolated Hyper-V VM was restored to its prior driver file and powered off. The owned preview is stopped after acceptance. No production service, policy, canary, boot-security setting or firewall rule was changed.

## 2026-09-25: forensic capture robustness and additive metadata candidate

**Implementation and isolated three-pass QA completed; production rollout has not occurred for this increment.** Reused ActorLease, ForensicCollector/Pipeline, EvidenceStore, the existing schema and SIEM delivery. Added actor access/change timestamps, parent/session collection status; retained an already bound executable through optional metadata loss; separated SHA-256 collection from preservation size limits; cached immutable PE metadata; retained overflow observations and emitted linked enrichment failures with explicit operation/status/reason codes.

1. **Functional:** final native Windows run passed **59 checks**, followed by **53 native Linux checks** on ops01. Includes the requested PID/reuse/exit, renamed/replaced executable, signed/unsigned/tampered/catalog, owner versus audit-subject and unavailable actor-thread, preservation/failure/hash, rename/local-network, unavailable metadata and volume/cache cases. Added historical schema compatibility and a real controlled executable over the configured copy limit: SHA-256 still matched while preservation failed visibly. Linux ran in an isolated same-user QA directory, not through the deployed rfclient service.
2. **Regression/SIEM:** all **23 suites passed**, including **359 EventHistory checks**. Added parent/session/timestamp fields survive actual HTTP ingestion, DB persistence and TCP SIEM JSON output. Native bounded-queue test retained all 81 observations, completed 32 enrichments and marked 49 capacity failures. Worker failures produced valid immutable linked failure records rather than only a pending observation.
3. **UI/runtime:** **13 forensic**, **16 whitelist**, **52 whole-console** checks passed on the actual isolated candidate with 390/768/1440 layouts. Mobile policy screenshot inspected; OS logos, colored status indicators and User/Process/PID remain visible. The whitelist UI fixture's old date-specific directory guard initially stopped test seeding; the new exact QA prefix was added and the complete fixture passed on a fresh isolated database. Owned QA preview processes were stopped. No production service, policy, canary or immutable prior artifact was modified.

Evidence and remaining limits: `../../diagnostics/forensics-20260925/RESULTS.md`, `SOURCE-RECEIPT.json`, `VALIDATION.json`, and `D:/Codex/RansomFree/forensics-20260925/`. Production still runs the previously deployed server/sensor versions. No new external SIEM/native Office/PDF acceptance, central executable upload, Linux hash-whitelist integration or actor-thread impersonation coverage is claimed.

## 2026-09-24 21:27:38 EDT: correct required Windows coverage to four sensors

The user's named-host correction exposed a deployment coverage error: the prior 28-host checks covered installed sensors but omitted CPTNYC_DC01 and DESKTOP-6U8VLDH. Neither had an endpoint sensor. The intended set is four Windows plus 26 Linux = 30. Historical 28-host receipts below are retained as historical tests, not represented as full intended coverage.

1. **Functional/persistence:** installed the unchanged sealed Windows 0.6.10-dev package on the domain controller and Windows 10 workstation. Each was enrolled through a single-use server API enrollment code and the normal agent CLI, with a distinct identity and DPAPI-protected credentials. Provisioned three new dedicated local files each using the sealed CanaryMonitor.Deploy method. Controlled PowerShell readers (DC PID 1072, workstation PID 47400) generated four completions whose user/SID, PID, process start, executable path/hash/stable identity, catalog signature/timestamp, source-event links, binary and manifest hashes exactly match the live server. Protected SYSTEM/admin evidence ACLs and unchanged canary hashes passed.
2. **Edge/preservation:** retained all 31 earlier endpoint identities and added exactly two, for 33 records. Server PID 6356 and receiver PID 1424 remained unchanged. The new coverage manifest requires CPTNYC_NVR, CPTNYC_DC01, CPTNYCSTR01 and DESKTOP-6U8VLDH by name plus the 26 verified Linux hosts. Negative cases reject a missing domain controller and a same-count inventory that substitutes another host for Blue Iris. The installer refused existing target paths and verified the sealed archive and full payload manifest; its first attempt stopped before installation because PowerShell required `-Force` when inspecting hidden ProgramData. Corrected that inspection and completed the native deployments.
3. **Installed runtime/API:** normal trusted TLS diagnosis succeeded on both new hosts; both automatic LocalSystem services run 0.6.10-dev. At 01:27:38 UTC, all 30 required sensors were fresh/active with expected versions. Live API rechecks also matched the prior two Windows hosts' four artifacts and 26 Linux artifacts, yielding 34/34 selected completions across 30 sensors. Prior host reads were not repeated or reported as new reads. There was no product binary/UI change, so the sealed package's existing 23 regression suites and UI acceptance remain the code-level basis; this run adds native Windows Server 2012 R2 and Windows 10 installed-service coverage.

Evidence: `../../diagnostics/forensics-20260924/THIRTY-SENSOR-VERIFICATION.json`, `SERVER-THIRTY-SENSOR-SNAPSHOT.json`, `EXPECTED-SENSORS.json`, `COVERAGE-GUARD-TESTS.json`, both new Windows installation/native receipts, and `RESULTS.md`.

Limits: the earlier 392 callback cases cover the previous 28-host set; this correction does not certify callbacks or native Office/PDF readers on the two new hosts. The new hosts' optional session-decoy configuration reports “Decoy setup pending” while all three local files are monitored. Existing thread-impersonation and short-lived-process limitations remain explicit. Local maintenance-secret backups are DPAPI LocalMachine encrypted and restricted to SYSTEM/admin in Agent/maintenance-password.dpapi.

## 2026-09-24 13:14–13:19 EDT: fresh post-access host-file retest

User requested new honeypot/canary tests after callback access was available. Evidence was written to a separate R2 directory. This run reused registered QA artifacts but established a pretest callback sequence boundary of **965**; every accepted callback receipt exceeded that boundary and matched the new test time, source IP, token and protocol detail.

1. **Functional/persistence:** Windows first: all 6 reads on both sensors matched fresh stored account, executable and PID. All 81 reads across 26 Linux sensors then matched exact event ID, host, path, process, PID and UID/EUID/FSUID. Every configured Windows file and every active Linux file was checked; hashes were preserved. The complete 14-type callback matrix passed **392/392** with fresh server records, including all eight previously blocked DMZ sensors. All 28 QR artifacts decoded to their correct registered URLs.
2. **Preservation/health:** all 28 deployed sensors remained fresh and actively monitoring, with all 31 retained endpoint IDs preserved. Product versions and firewall policy were unchanged. Existing Windows managed-decoy warnings and Netbox clock skew remain documented. New test evidence is separate from the earlier pass; no prior receipt was counted as a new activation.
3. **Native application/runtime:** copied/extracted artifacts opened in installed Edge on NVR again produced five server callbacks (SVG, web image, web bug, JavaScript clone and CSS clone), without certificate bypass. PDF opening timed out without a callback. Native Office/PDF acceptance across Windows/Linux remains incomplete because required readers are absent or the attempted reader did not trigger. The 392 protocol passes do not substitute for those native-reader gates. No owned QA browser process remained after the run. No new product-code change occurred, so the previous full release gate was not repeated for this read/access retest.

Evidence: `../../diagnostics/honeypot-canary-retest-20260924-r2/RESULTS.md`, `SUMMARY.json`, `ALL-SERVER-ACTOR-PROOF.json`, `CALLBACK-VERIFICATION.json`, `CALLBACK-BASELINE.json`, `QR-DECODE-VERIFICATION.json`, `FINAL-INVENTORY-VERIFICATION.json`, `HOST-RESULTS.csv`, `ACTOR-EVIDENCE.csv` and `CALLBACK-EVIDENCE.csv`.

## 2026-09-24: all-sensor honeypot and canary retest

**Local attribution and callback protocols passed: 87/87 file reads and 392/392 callback cases across all 28 sensors. Native document-reader acceptance remains incomplete.** After the initial approval block, the user explicitly authorized temporary firewall rules because the server will move. `TEMP-DMZ-SENSORS-CANARY-CALLBACK` and `TEMP-SEQUESTER-CALLBACK-7444` were committed (job 263104, FIN/OK) for only the eight deployed DMZ source IPs to 192.168.1.10:7444, application ssl. All 206 existing rules and 127 services were preserved; 19 scope/reporting policy checks passed. Remove both temporary objects when the server moves; no automatic expiry is configured. Product versions remain server 0.6.11-dev, Windows 0.6.9-dev and Linux 0.9.15-linux-dev. No product-code change was made.

1. **Functional/persistence:** all 87 controlled reads of existing monitored files across 28 sensors (6 Windows, 81 Linux) preserved file hashes and matched exact persisted host/file/user/executable/PID events. Initial callback results were 280/392, with 112 blocked by the missing DMZ callback-port permission. After the temporary rule was committed, all 26 Linux sensors reran the 14-type matrix successfully. Combined with the two Windows results, **392/392** cases matched fresh registered tokens, source IP and protocol details in the receiver database. All 28 generated QR PNGs decoded to the registered URL.
2. **Edge/preservation:** final API inventory shows 28 fresh active sensors and all 31 retained endpoint IDs unchanged. Records with incomplete attribution remain supported by the existing deployed package. The first combined Linux callback run timed out; the corrected runner retained per-host results and marked failed connectivity preflights explicitly. Netbox's approximately 30-second clock lag was independently verified through an HTTPS Date header (`NTPSynchronized=no`); raw timestamps and the bounded matching tolerance remain documented. The existing NVR/Storage managed-decoy warnings remain unresolved.
3. **Native application/runtime:** actual Edge opening on NVR generated stored callbacks for SVG, web image, web bug, JavaScript clone and CSS clone without a certificate bypass. PDF opening timed out without a callback. No Office/LibreOffice executable was found at the inspected Windows paths or Linux PATHs; native document-reader acceptance across all sensors remains pending. MCP/kubeconfig/WebDAV were protocol-level tests, not native client workflows. QR decoding was local artifact validation, not camera scanning. Email/SIEM delivery and authenticated production console workflows were not tested. QA browser processes were cleaned up.

Evidence: `../../diagnostics/honeypot-canary-retest-20260924-r1/RESULTS.md`, `ALL-SERVER-ACTOR-PROOF.json`, `CALLBACK-VERIFICATION.json`, `QR-DECODE-VERIFICATION.json`, `FINAL-INVENTORY-VERIFICATION.json`, `HOST-RESULTS.csv`, `PALO-TEMP-FIREWALL-VERIFICATION.json` and `TEMPORARY-FIREWALL.md`. Original failures remain in `*-BEFORE-TEMP-FIREWALL` files. The prior 22-suite / 52-browser-check product gate remains the most recent release gate; these live retests do not turn missing native-reader gates into passes.

## 2026-09-24: Linux 0.9.15 cold-start correction

The 0.9.14 package inherited the 0.9.13 launcher release guard. Native reads passed while the old relay continued running, but fresh auditd starts were rejected on www-legacy and netbox. The earlier native proof did not establish restart reliability. The corrected package replaces the launcher, normalizes Unix line endings and derives reported sensor version from assembly metadata. One candidate with CRLF shebang was rejected by native preflight before deployment; rejected archives are retained.

1. **Functional/persistence:** the exact 0.9.15 package passed native CLI version, launcher startup, collector health and a real auditd restart on Plex. The running relay executable resolved to the new release. The controlled read preserved its canary hash and matched server event sequence 18694, PID 186802, `/usr/bin/cat`, and UID/EUID/FSUID 0. Both Windows hosts also matched fresh native actor proofs to stored server events.
2. **Edge/regression:** the final reusable release run passed all **22 suites**. This includes the original 19 suites plus Linux audit health/loss (25 cases), status parsing (17) and rule planning (23). The exact Linux package passed 10 native bootstrap checks: current version/valid package, unsafe arguments, non-root caller, writable launcher/relay/release, mismatched release/hash, and restored package. The isolated fixture left production service PIDs unchanged. Source and packaged shell line endings are explicitly constrained.
3. **UI/runtime/deployment:** the 0.6.11 R2 published UI retained its 52 passing package/browser checks. All 26 Linux sensors completed the upgrade, real auditd restart, new-release relay identity, healthy collector and native controlled read with unchanged canary hash. Final reinspection showed enabled audit and zero reported audit loss on all 26. Netbox initially failed because its disabled audit prerequisite was addressed too late in the upgrade sequence; rollback could not start that dependency. Explicit prerequisite recovery restored it and the subsequent upgrade passed. The failed attempt is retained. Final server verification matched exact user/process/PID evidence on all 28 Windows/Linux hosts; all are fresh and actively monitoring, with 26 Linux/2 Windows OS metadata and all 31 retained endpoint IDs preserved. Final event high-water sequence 18892 exceeded baseline 18663. Callback listener PID 1424 was preserved across the server deployment. The isolated QA server was stopped after testing; evidence remains available.

Evidence: `../../diagnostics/ui-regression-20260924/RESOLUTION.md`, `LINUX-BOOTSTRAP-FIXTURE.json`, `REGRESSION-COMPLETE.json`, `LINUX-0915-RECEIPTS.json`, `ALL-0915-SERVER-ACTOR-PROOF.json`, `FINAL-INVENTORY-VERIFICATION.json`. `FEATURES.md` is the current feature/verification register. The production authenticated browser and external/native-platform limits below remain explicit; this runtime upgrade bundle is not certified as a fresh-install package.

## 2026-09-24: Sensors / actor visibility release 0.6.11-dev

The current feature register is `FEATURES.md`. `tools/test-release.ps1` runs the available feature suites, `tools/console-package-dom.mjs` exercises a real published QA server, and `tools/verify-web-package.mjs` checks compressed asset consistency. Future changes must update this register, execute the suites, inspect packaged UI output, and record live readback after deployment.

1. **Functional/persistence:** all 16 backend/native-parser suites passed: management/identity/reports (156 assertions), canary artifacts and receiver protocols (260), history and server integration (345), activity contracts (197), service decoys (40), managed jobs (45), trust governance (51), service delivery (32), session ledger (69), endpoint health (40), Windows protection (13), Windows process capture (9), Windows audit parser (14 pass lines), Linux audit packet (16), trust cache (33), and TLS/server startup (10). The fresh controlled production reads on CPTNYC_NVR (PowerShell PID 6696, Administrator) and plex01 (`cat` PID 185160, UID/EUID/FSUID 0) matched exact persisted server records 18667 and 18676. File contents were preserved. These are production audit paths, not prototype kernel collectors.
2. **Edge/regression:** 20 Sensors DOM, 21 History DOM and 95 presentation checks passed. Partial/missing actor events remain visible. Timeout/recovery/session expiry, filtering, ordering, paging, policy/response evidence boundaries, duplicates and restart preservation remain covered. Unknown status is gray; degraded is yellow; active green; offline/stopped red. Tests cover source-aware evidence without guessing joins between watcher and audit events.
3. **UI/runtime/package:** 52 whole-package browser checks passed with normal QA sign-in and real local APIs, all 13 navigation screens, decoded Windows/Linux logos, computed status colors, actor values and layouts at 390/768/1440px. Screenshots were inspected. A duplicate legend/actor caption was found and fixed during candidate inspection. Rebuilt R2 passed the same 52 checks and all 54 compressed assets decode byte-for-byte to their matching uncompressed files. Its server/contracts DLL hashes match the backend-tested code.

The first deployment attempt rolled back when the HTTP verifier requested an internal compressed asset that is not a public route (404). Corrected the verifier to request public asset types, republished to a separate R2 directory, and retained the rejected archive/release. The corrected deployment result and post-deployment integrity checks are recorded in `../../diagnostics/ui-regression-20260924/DEPLOYMENT-RECEIPT.json` and the change report.

**Limits:** production authenticated browser inspection remains pending a signed-in session. Production assets and admin API evidence are verified separately from the authenticated synthetic QA UI. External SSO/directory providers, SQL Server migration, actual external mailbox/SIEM receipt, all native document readers, native macOS, tray/virtual-drive acceptance and continuous production kernel collectors were not newly certified by this UI change. Compilation, navigation, and protocol callbacks do not count as those passes.

## Linux 0.9.10 reporting recovery — 2026-09-18

- Functional pass: **partial**. The corrected Linux agent compiled with .NET 10 (zero warnings/errors). The 39-case endpoint summary fixture passed. The isolated ops01 native fixture verified the same agent DLL, audit and reconnect behavior. The successful policy refresh transition has not been exercised against a live management assignment.
- Edge and regression pass: **partial**. The isolated fixture passed 23 rule planner, 17 audit status, 25 heartbeat/loss, and 39 endpoint summary cases. The 0.9.10 support01 controller copy passed 37 base and 21 DEV offline tests; its exact package check accepted the archive. The archive passed 513-file checksum/inventory verification. An isolated Debian Docker clone ran the exact 0.9.8 and 0.9.10 archives through pending upgrade, rollback, failure after selector switch, and corrupt-queue refusal. Its service/process lifecycle was simulated; no live 0.9.10 service was exercised.
- UI and runtime pass: **pending**. The exact 0.9.10 archive passed a read-only live support01 preflight and a newer central 0.9.8 heartbeat. No 0.9.10 endpoint service, tray, central protection report, or controlled canary event was tested on a live host. No 0.9.10 package was installed on the fleet or Windows servers.

Package release: `ransomfree-client-0.9.10-dev.20260918T205829Z-85d5365c8406-linux-x64`; archive SHA-256 `3EE80B6B9ACCB15EEE13F9985AF1F42F8BB9C72DAF008ED6B494FA215F47B0E4`. Native-tested agent DLL SHA-256 `91FFEE8C51E9604587080BC0E384216A3718F4D69752A0FC50B2459CED9B7765`.

## Windows structured reporting candidate — 2026-09-18

- Functional pass: **source and fixture only**. The agent now derives deployed count from completed local integrity states. An unverified item leaves the structured report absent. A complete inventory reports its observed count and active, degraded, stopped, or not-configured monitoring state. Heartbeats explicitly identify Windows.
- Edge and regression pass: **partial**. The 13-case Windows protection fixture passed, including unknown evidence, missing/changed files, audit and watcher disconnect, policy warning, and wire serialization. `RansomFree.Agent` compiled with zero warnings and errors with NuGet auditing disabled because the vulnerability metadata feed was unavailable during the first build.
- UI and runtime pass: **pending**. No new Windows MSI, native Windows guest installation, service upgrade, or central report readback has run. The two active Windows servers remain on 0.6.3.

## 2026-09-23/24: restore accepted Sensors and Event History in server 0.6.9-dev

User reported Fleet returning after Sensors rename. Retained release inspection confirmed September 23 reporting builds used older UI and EventHistory.cs, dropping accepted September 16 changes. Integrated those changes into the current reporting source and kept actor-retention/callback work. Restored the project-derived management package version builder.

1. Functional: PASS, 177 EventHistoryFixture checks (SQLite, 1,100 synthetic rows, filters, sorting and stable paging).
2. Regression: PASS, 156 packaged server checks, including complete/incomplete actor records surviving restart, duplicate prevention, authorization, reports and callback labels. Fixed a stale restart-test expectation of one record when the test now deliberately sends four. Final run passed.
3. UI/runtime: PASS, 19 Sensors + 13 Event History + 90 presentation browser fixture checks. Live server 0.6.9.0 verified serving Sensors, filters and automatic refresh; host/action history query succeeds. 29 endpoint IDs match saved prior inventory, Plex reports fresh active 0.9.13-linux-dev, event high-water sequence retained, callback receiver unchanged. Authenticated live browser interaction was not performed; fixture rendering and live HTTP/API checks are distinct evidence.

Deployed under the user's explicit instruction to correct the regression. Immutable package and prior release preserved with data/configuration/launcher backup. Original receipt's endpoint count of 1 was a wrapped-array counting bug, superseded by independent inventory verification of 29 matching IDs. Exact evidence: C:/Users/dmessana/Documents/ChatGPT/seQuester/diagnostics/sensors-ui-regression-20260923/RESOLUTION.md.

Manus kernel-attribution collaboration is complete and documented separately. No new minifilter/BPF collector was installed or claimed tested; remaining Windows parser and Linux audit-inbox partial-record gaps remain recorded for correction.

## 2026-09-24: native attribution pilots and deployed audit-retention fixes

The later explicit user instruction authorized building, testing Windows first, then Linux, and deploying qualified updates. This supersedes the historical deployment deferral above for this work.

1. Functional: Windows minifilter prototype passed 34/34 actor cases, repeated under Driver Verifier. Revision 2 captured 1,147 events with zero reported queue drops in the normal matrix. Linux eBPF prototype on Plex passed 38/38 cases twice, including inherited/duplicated handles, hard links, FSUID changes, denied access, exec transition and parallel short-lived processes. Repeat capture: 3,209 events, zero reported ring drops. Live server spool ingestion/readback matched every compared actor field for both captures; full replay created no duplicate records. This was captured-evidence replay, not continuous production kernel integration.
2. Edge/regression: Windows collector disconnect before acknowledgment redelivered the exact durable event. Intentional saturation retained 2,048 records, counted 3,952 drops and drained to zero under Driver Verifier. Added native Linux AuditInbox fixture passed 9 cases in a private mount namespace, including partial detections, exact malformed-byte quarantine, outbox refusal, cursor restart and capacity backpressure. Windows audit parser 13/13 and Linux packet normalization 16/16 passed. Contract checks and packaged server/agent, history SQL filtering/sorting and authorization checks passed; exact counts and paths are in QA-COUNTS.json. Kernel queues are not claimed lossless through reboot, unload or overload.
3. UI/runtime: 20 Event History and 19 Sensors browser fixture checks passed. Server 0.6.10-dev was deployed with backup/rollback; Sensors UI, inventory, history and callback listener were preserved. Windows audit sensor 0.6.9-dev deployed to both existing Windows hosts; Linux audit sensor 0.9.14-linux-dev deployed to all 26 existing Linux hosts. All 28 have fresh central heartbeats and active monitoring. A controlled canary read on each of the 28 hosts was independently matched to the live server's stored user, executable and PID. File hashes were preserved. Authenticated live browser interaction and desktop tray behavior were not newly tested.

Audit packages contain the partial-record fixes, not the kernel prototypes. The prototypes remain pending continuous collector integration, broader kernel/object coverage, and Windows Server HLK/dashboard signing plus assigned minifilter altitude. Production boot security was not relaxed. Actual pilot and rollout evidence, package hashes, backup paths, per-host event IDs and remaining boundaries: C:/Users/dmessana/Documents/ChatGPT/seQuester/diagnostics/kernel-attribution-implementation-20260924/IMPLEMENTATION-STATUS.md and ALL-SERVER-ACTOR-PROOF.json.

## 2026-09-24: actor executable forensics and action whitelists

Implementation: versioned forensic envelope, process/start correlation, separate event subject and later owner, Windows signature/catalog/PE evidence, Linux procfs credentials, actor SHA-256 cache, restricted actor-copy preservation with independent artifact/manifest hashes, bounded asynchronous completion and SIEM JSON. Target hashing/copying is not added. Process/user/both action whitelists retain logs and suppress only allowed alert/automatic-response actions; the server independently replays policy decisions and requires compatible evidence/policy receipts.

1. **Functional pass:** 45 native Windows forensic checks and 39 root-run Linux checks on ops01 passed. Coverage includes actual retained descriptors, command lines, file identity, preserved actor bytes and manifest hashes, unsigned/signed/tampered/catalog Windows images, synthetic event subject kept separate from native owner, native current-thread impersonation not misrepresented as an actor TID, short-lived controlled child captured before exit, renamed apphost and preservation failures. 214 whitelist functional/boundary checks passed on each native platform. Root-run Linux success does not certify the deployed rfclient service's cross-user privileges.
2. **Edge/regression pass:** all 23 suites in `D:/Codex/RansomFree/forensics-20260924/regression-final/REGRESSION.json` passed. Includes 359 history checks, actual HTTP/database/TCP SIEM forensic delivery, old-server receipt refusal, old-sensor policy-ack refusal, authoritative linked-completion log-only classification, identity mismatch/PID-age rejection, replaced/in-place-modified executable invalidation, 100 cache hits after one hash, and bounded queue overflow retaining 81 originals with 32 completions and 49 explicit unavailable-enrichment states. PID reuse is tested through start-key distinction and stale-event rejection, not a claim that the OS was forced to recycle a PID during the fixture.
3. **UI/runtime pass:** 11 forensic, 16 whitelist and 52 whole-console checks passed against the published server using ordinary login, CSRF, reauthentication and database-backed publication/reload. Screenshots inspected at phone/tablet/desktop sizes; Sensors labels, OS logos, status bubbles and User/Process/PID retained. No mocked API results in the whole-console suite. The production authenticated browser is not newly certified; exact production web assets and admin API are separately verified.

### Live rollout and acceptance

- Server **0.6.12-dev** deployed with immutable archive and rollback backup. All 31 endpoint IDs preserved, 30 served web assets matched, event high-water snapshot retained, callback PID 1424 unchanged.
- Both Windows sensors **0.6.10-dev** deployed. Native controlled readers on NVR (PID 6528) and Storage (PID 1312) produced **4/4** matching live server forensic completions. Exact account/SID, PID, process start, instance key, executable SHA-256, catalog signature/timestamp, source-event linkage, preserved artifact hash and manifest hash were independently compared. Both stores have protected SYSTEM/admin DACLs; target canaries unchanged.
- Linux Plex **0.9.16-linux-dev** upgraded, relay release/cold start and audit identity passed. **Installed-service actor-copy acceptance failed** for root-owned Python PID 194286: rfclient has empty capability sets and cannot access another user's executable descriptor. The server retained the correct audit user/process/PID and explicit unavailable image/preservation states. This is a real failure, not counted as a pass.
- The proposed per-service `CAP_SYS_PTRACE` + `CAP_DAC_READ_SEARCH` correction was rejected by automatic approval review pending exact user approval. No capability change ran. Remaining **25 Linux upgrades are paused** pending that approval and successful pilot evidence. At 20:54:58 UTC, all **28/28** deployed sensors remained fresh/active; this monitoring-health result does not imply Linux executable preservation works across users.

Evidence: `../../diagnostics/forensics-20260924/RESULTS.md`, `LIVE-VERIFICATION.json`, `PACKAGE-RECEIPT.json`, per-host native receipts and server snapshots. Native/UI/regression artifacts are under `D:/Codex/RansomFree/forensics-20260924/`. The Linux whitelist runner's `passLines: 0` is a counter-format defect (`PASS ` versus `PASS:`); its exit 0 and terminal `214 whitelist functional and boundary checks` summary are retained, not altered.

Limits: Windows audit does not supply actor TID, so effective thread token/impersonation cannot be asserted. Exit before live capture, mandatory access controls, missing target I/O fields, protected/locked images and queue pressure remain explicit unavailable states. No live external SIEM/mailbox delivery or new native Office/PDF acceptance is claimed. The kernel prototypes were not shipped. Linux rollout was incomplete at this initial checkpoint; the approved completion follows.

### Approved Linux correction and full rollout — 2026-09-24 20:47:55 EDT

The user explicitly approved the two Linux capabilities and the Plex-then-25-sensor scope. Applied `CAP_SYS_PTRACE` and `CAP_DAC_READ_SEARCH` to `ransomfree-client.service`, keeping rfclient, NoNewPrivileges and ProtectSystem=strict. The exact source drop-in hash matched all deployment receipts: `24D2F34E33927C1889ADA0E9343CF1C77D8D6F32A44BA5DCE64B163CF95204A4`. The sealed binary package was not modified; this approved persistent service configuration is separately recorded.

- **Installed-service functional pass:** Plex captured a root-owned Python reader after the permission correction. The native preserved-copy and server comparisons passed before wider rollout. Then all remaining 25 Linux sensors upgraded successfully in batches of two. Every host passed native relay cold-start identity, retained audit-rule checks and a held-reader actor-preservation test. The helper captured independent boot/start key, process correlation, executable device/inode and SHA-256; artifact directories were 0700 and files 0600 owned by the service account. Existing canaries were unchanged.
- **Final API comparison:** 26/26 Linux artifact records exactly matched native PID, executable, UID/EUID/GID/EGID, boot/start key, process-instance ID, executable stable ID/SHA-256, preserved binary hash, manifest hash and source-event linkage. Both Windows hosts' four earlier controlled-read artifact records were rechecked through exact endpoint/PID API queries and still matched their native proof. Total: **30/30 selected forensic completions across 28/28 deployed sensors**, with zero comparison failures.
- **Runtime/inventory pass:** at **2026-09-25 00:47:55 UTC**, server 0.6.12-dev, both Windows sensors 0.6.10-dev and all 26 Linux sensors 0.9.16-linux-dev were verified. All 28 sensors were fresh/active, all 31 retained endpoint IDs matched the predeployment inventory, and callback receiver PID 1424 remained unchanged. No legacy 0.9.15 sensor remains among the deployed 26.

Final evidence: `../../diagnostics/forensics-20260924/ALL-SENSOR-VERIFICATION.json`, `LINUX-ALL-SERVER-PROOF.json`, `LINUX-REMAINING-UPGRADE.json`, `LINUX-CONFIGURATION-RECEIPT.json` and `RESULTS.md`. Earlier failed/blocked receipts and the before-approval report were retained. All 23 binary regression suites and the three UI suites remain the sealed-package QA basis; the later change was service configuration, verified through the actual installed service on every Linux host. The provider limitations above remain; controlled success is not a claim of complete metadata for every short-lived process or actor thread.

## Process creation metadata implementation — 2026-10-02T23:01:15.039533+00:00

R32 completed the same 21-case native matrix on WIN10, WIN11, Server 2019 and the Server 2012 R2 domain-controller clone. Each has independent raw/token/source-identity verification, an isolated server replay, baseline restoration and powered-off receipt. Server checks: 577 / 511 / 489 / 469 respectively. This is qualification of the sealed R32 package, not production deployment or full-specification completion.

### Narrow implementation plan and changes

- `src/seQuester.WindowsKernel/ProcessCreationMetadata.h`, `ExecutableStagingDiagnostic.h`, `Driver.c`: copy creation-notification command line and image-open name before callback return. Distinguish reported parent PID from actual creator PID/TID/start. Match the candidate under the existing short lock, copy/lookup outside all locks, then revalidate candidate ID plus callback-owned file object before publishing. No entry pointer survives an unlock. Candidate removal during capture discards the provisional metadata; it cannot attach to a reused slot.
- Metadata is per process/candidate, immutable before publication, reference-counted by candidate and queued blob. Process exit, TTL and ACK do not retarget a record. All detach paths release their metadata reference outside locks. A separate 256-object cap bounds metadata pool use to about 1.28 MiB plus allocator overhead; refused allocation yields explicit unavailable evidence. Health operation 28 exposes allocations/frees/refusals/live count.
- Command line cap: 2,048 UTF-16 code units (4,096 bytes); image name cap: 512 code units (1,024 bytes). Keep original/stored byte lengths, absent/invalid/truncated status and raw UTF-16 proof. Do not split a trailing surrogate pair. Invalid UTF-16 is retained in the private proof and unavailable for display. These are notification values, not authenticity verdicts or a promise of complete command lines.
- Exact parent start is captured only for the reported-parent-equals-creator case with matching creating PID/TID, using a referenced creator process outside locks. A different designated parent remains PID-only. No current-PID lookup is used to guess designated-parent history, and no parent image path is invented. Notification creation status is recorded without claiming it is the final result of all callbacks.
- `WindowsProcessCreationProtocol.cs`, `WindowsStagedActorStore.cs`, `WindowsProcessAcquisitionStore.cs`, ready/staged protocols: companion operation 27 carries a 5,304-byte, version-1 record bound to provider, generation, candidate, PID/start and query event. Raw v4/3,800-byte operations are unchanged. Raw metadata and its SHA-256 are committed in the existing bounded acquisition record/journal before ACK. No new sidecar, pathname cache or live-process fallback. Existing 32-KiB index/WAL frame caps remain.
- `WindowsProcessCreationEvidence.cs`, `ForensicEvidence.cs`: optional versioned `Process.Creation` separates creator and reported parent, retains image-name exactness/status/byte counts, capture time, monotonic value, callback status and proof digest. Existing command-line and parent fields are populated from the validated proof. SIEM forensic envelopes containing this extension have an explicit 32-KiB bound; legacy envelopes retain 16 KiB. Raw proof stays in the protected sensor journal; parsed evidence travels with the existing event/preservation manifest.
- `ManagementClient.cs`, `EventSpool.cs`, `Contracts.cs`, server `Program.cs`: negotiate and acknowledge `ProcessCreationVersion=1`. An older server cannot silently drain events containing the new evidence. No new executable-upload route or trust verdict is introduced. Actor SHA-256, signature cache, exact snapshot verification, preservation and upload behavior remain integrated with the existing acquisition flow. Target files are not hashed or copied by this feature.
- `WindowsStagedActorFixture`, `WindowsActorFixture`, `WindowsActorIntakeProbe`: add PID reuse, per-process command separation, proactive commit/restart/TTL, parent split/context mismatch, absent/empty/truncated/malformed text, oversized/contradictory/full-key mismatch, corrupted durable metadata, capability receipt and real HTTP history checks. Native actor truth includes `Environment.CommandLine`; the creating process retains its PID/start and immediate creating TID. Existing USER/PROCESS/PID/token and artifact checks remain gates.

### Evidence and current qualification

Local managed fixture: **307 checks PASS**, including actual isolated HTTP server history and executable transfer. Build: zero warnings/errors. Artifact root `D:\Codex\RansomFree\windows-token-20260930\actor-intake-fixture-b8c81ddcb14640b884043f29213714dc`; logs `process-metadata-managed-r3-build.log` and `process-metadata-managed-r3.log`.

Failures are retained: r1 found the ready-request operation allow-list omission; r2 found optional malformed metadata escaping its failure boundary and discarding otherwise valid snapshot bytes. Both were corrected and the affected regression suite passed in r3. Invalid metadata now becomes explicit failed/unavailable creation evidence while preserving operation tokens and valid executable bytes.

R33 sealed matrix package: `091959411DE6EE24D1E3E5836AB028E9D233811E3D93661235EA4460170F8C04`; signed driver `670094952822AB987C813A0D70EF1584B924CAE142548A2EE8B6D4B9B8FF4A07`; source manifest `F771E736CA344967296347B3383E81014040176930039FC5D477CBE10833D108`. Windows 10 native run is in progress. R33 adds the managed recovery fix and process metadata; R32 acceptance does not qualify these additions.

Pending: R33 native matrix and independent process-metadata/server gates; native designated-parent and callback publication/pool/fault cases; native crash/outbox recovery and sustained load; command-line completeness beyond the explicit cap; Linux operation-time executable binding; all previously recorded production signing/assigned-altitude/deployment gates. The Linux provider and production sensors are unchanged. Three final product-wide QA passes and all-host retests remain pending. No reboot of the physical desktop.

References: Manus R44 review in `diagnostics/windows-token-20260930/windows-defensive-sensor-r44-process-metadata-review.md`; Microsoft `PS_CREATE_NOTIFY_INFO`, `PsSetCreateProcessNotifyRoutineEx`, `PsGetCurrentProcessId`, `PsLookupProcessByProcessId`, and process-callback best practices. The implementation deliberately uses the narrower existing schema cap rather than Manus's suggested larger command-line budget.

<!-- PROCESS-CREATION-CURRENT-START -->
## Current process-creation companion status

Updated 2026-10-03T00:01:11.554615+00:00.

| Package | Windows 10 qualification | Package SHA-256 |
| --- | --- | --- |
| R33 | FAILED (retained test result) | `091959411DE6EE24D1E3E5836AB028E9D233811E3D93661235EA4460170F8C04` |
| R34 | native + independent evidence + server PASS (960 server checks) | `5ADE6140A4C97DD49FC47541A9068F9BBFCC4F2ADCF7E317054928C42F4CE489` |
| R35 | native + independent evidence + server PASS (923 server checks) | `76EA3A7BA1045C1B7DB333D92C157D1E65197235B8048DDA7B98F11D5521C2CC` |

R35 same-package matrix:

| Windows target | Acceptance | Native archive SHA-256 |
| --- | --- | --- |
| WIN10 | PASS (923 server checks) | `3ED37383DEACE2BE0567B38669BC27E37D08134FE02485B5A4CE3AA805E4DE58` |
| WIN11 | PASS (796 server checks) | `948300526DA39003C58CBE297C545A50C7BB372FA96D5AA907FE5731D56B7FCB` |
| 2019 | PASS (756 server checks) | `4A49F23D34B534F7FF1BE283072A09CE10523DFFE4EDFF736D56736220B2A13C` |
| DC | PASS (720 server checks) | `C7F327F7D434043E297C0B6C4C3F7F9AAFD6E049174A5A4204FA7D00253D5A66` |

R35 is now the fully accepted same-package four-OS matrix (21 cases on each OS): native capture, independent raw/token/creation proof, isolated server replay, baseline restoration and powered-off receipts all passed. The matrix finished at 2026-10-02T23:58:27Z. This qualifies the controlled cases on the recorded Windows builds, not all workloads or production deployment. R33's first-read comparison failed because the fixture compared `.NET Environment.CommandLine` (managed DLL launch) with the kernel's native EXE command line. R33 stays failed; the archive and first two observation/completion pairs remain intact. R34 retains the managed string but compares the native creation command with the actor's `GetCommandLineW` result. It does not rewrite the captured native evidence or relax the gate.

Latest local result: **318 checks PASS**, zero build warnings/errors, including actual HTTP ingestion/history, upload/download, skipped-versus-failed creator lookup, per-key memory failure, and rejection of a recomputed manifest whose creator metadata differs from its committed event. Artifact root `D:\Codex\RansomFree\windows-token-20260930\actor-intake-fixture-55c1921b3fc74184a7e982998d74d34b`; logs `process-metadata-managed-r5-build.log` and `process-metadata-managed-r5.log`.

R35 adds the reviewed failure-state refinements after R34 was sealed: explicit capacity/allocation outcome per candidate/blob; no fabricated OS lookup code when creator lookup was skipped; explicit nonzero process-generation guard before metadata attachment/readiness; manifest/event process equality. `Apply` is restricted to a baseline containing only operation-time identity/token evidence and no independently enriched parent/command fields. Manus R46 withdraws the conditional ID-reuse, zero-generation exposure, destructive-baseline and version-receipt findings after reviewing the existing omitted invariants. The accurate skipped-lookup status correction is implemented and tested locally. R34 cannot qualify later R35 changes.

Windows Agent and Linux Agent compile with the shared schema changes: zero warnings/errors in `process-creation-windows-agent-build-r1.log` and `process-creation-linux-agent-build-r1.log`. Native STOP/reference-balance, injected binding/memory failures, designated-parent cases, high-volume/fault/recovery coverage and the remaining specification/deployment gates are still explicit pending work. No production readiness or all-sensor deployment is claimed. Latest read-only altitude check: 2026-10-02T23:53:29Z, sent copy verified, no reply; no duplicate email sent.
<!-- PROCESS-CREATION-CURRENT-END -->

<!-- PROCESS-LIFETIME-CURRENT-START -->
## Process metadata lifetime qualification

Updated 2026-10-03T02:13:25.811550+00:00. These are diagnostic qualification packages; no production deployment or production-readiness claim.

| Package | Target | Acceptance | Package SHA-256 |
| --- | --- | --- | --- |
| R38 | WIN10 | native + independent PASS | `09719CB65BF17225A7B8FCEF2E3C80F09DD26A401342EAAF42922A50CE78CEC4` |
| R38 | WIN11 | native + independent PASS | `09719CB65BF17225A7B8FCEF2E3C80F09DD26A401342EAAF42922A50CE78CEC4` |
| R38 | 2019 | native + independent PASS | `09719CB65BF17225A7B8FCEF2E3C80F09DD26A401342EAAF42922A50CE78CEC4` |
| R38 | DC | native + independent PASS | `09719CB65BF17225A7B8FCEF2E3C80F09DD26A401342EAAF42922A50CE78CEC4` |
| R37 | WIN10 | native + independent + server PASS (77 checks) | `C619D5867C733D4CEFC1E9C86F3CCD3C01A41ED6CD4E4D1F1A91283A4353CEEA` |
| R37 | WIN11 | FAILED; negative result retained | `C619D5867C733D4CEFC1E9C86F3CCD3C01A41ED6CD4E4D1F1A91283A4353CEEA` |
| R37 | 2019 | native + independent + server PASS (68 checks) | `C619D5867C733D4CEFC1E9C86F3CCD3C01A41ED6CD4E4D1F1A91283A4353CEEA` |
| R37 | DC | FAILED; negative result retained | `C619D5867C733D4CEFC1E9C86F3CCD3C01A41ED6CD4E4D1F1A91283A4353CEEA` |
| R39 | WIN11 | native + independent + server PASS (68 checks) | `72155F51419C824F354AA7E1D1DB1D0E7A5A54132E75BC5F3BE144712B4EE0E7` |
| R42 | DC | native + independent + server PASS (68 checks) | `BDF845C90B4E07C5A6AC0953C64DE661ADBC5584569076EFFD7922DF23E3514A` |
| R43 | WIN10 | FAILED; negative result retained | `026697FEDA0FFCB2D2FE793A2E342CA4183D6C3CC8CEDE1AF01C9B97909CC16D` |
| R44 | WIN11 | native + independent + server PASS (68 checks) | `4A88018D4681F5BC904ACE64BAFAAF916041520C7903401288FA9D9896CCCED1` |
| R45 | WIN10 | native + independent PASS | `D68ED5C1DEF3366A4828ED5E3EFCC7232D71E05128D72F2385EC5C230680CD5A` |

R38 extends the existing deterministic operation-pin ACK/STOP publication tests. An owned actor reports an impersonated read, stays alive through a bounded release handshake, and exits only after STOP resource accounting. Each retained operation must provide exact creator PID/start/TID and native command evidence. New retrieval of metadata and bytes must fail after ACK or STOP, while an already admitted byte publication returns the original bytes. Metadata allocations and private process/byte references must balance before actor exit. Cleanup is bounded and records its own failures. R36 was sealed but not run; R38 supersedes only its cleanup error handling so a stalled stderr reader cannot conceal cleanup failure.

R37 extends the existing proactive process acquisition test. The actor's first honeypot read occurs after the 30-second native byte TTL (34-second fixture delay). The earlier committed eventless creation proof, command/creator data and actor bytes must survive into the real operation and its forensic manifest. The original ready/exit/acquisition deadlines are unchanged. Server replay must retain the same typed process evidence through upload, download and history.

R38 Windows 10 accepted: 506 native checks, two ACK/STOP races with the actor alive, exact raw creation/token/byte verification, one metadata allocation/free and zero live objects. Archive `97B86BAC54E7005A7DB9605B72007F67AE68B75275CF00B659A7DBBA6FD7C54C`. The R37 Windows 11 run FAILED the unchanged 15-second ready gate; zero controlled file events were accepted. Its actor's managed-entry marker was 10.72 seconds after creation and readiness timestamp 16.55 seconds after creation; the failure snapshot recorded 2,531.25 ms actor CPU. Those values do not establish the cause. Archive `718F51060F82E676961BF71B864081496201133CBF7F27A2EBD27B4D8C01BEFA` and `FAILED-PROACTIVE-COMPONENTS.json` verify retained archive/source/cleanup integrity only. The VM was restored and powered off at 2026-10-03T00:17:30Z. The sequential cross-version lifetime batch stopped on this failure; remaining cases are pending.

R39 adds diagnostic phase timestamps kept in memory until test end, post-failure read-only native counters, and the existing bounded Windows 11 CPU/scheduling trace. The 15-second ready, 25-second acquisition and 45-second exit gates plus 34-second actor delay remain unchanged. R39 is not a correction to the native collector and cannot erase R37's failure; a trace is needed to investigate runtime/driver/competing-work intervals. No causality or universal latency claim is made.

R38 Windows 11 also accepted after restoration/power-off at 2026-10-03T00:44:57Z: two live-actor ACK/STOP races, eight invalid-range rejections, exact raw token/creation proof, two metadata allocations/frees and zero live objects. Archive `B7DF6B6B801C93E4F0872B2E278CD483285FE9EA8BF63B4E8572F95F05FA159A`. The five previously unrun lifetime cases continue via `Run-RemainingLifetimeCases.ps1`, one isolated VM at a time; the original failed batch remains intact.

R39 Windows 11 accepted one delayed first impersonated read, three observations/completions, two exact actor artifacts/process commits and balanced metadata objects. Archive `F4C62CA91ACB2E6A0E18E646D5DE78628098776F01FC2CB1F472F9D7A59FFA15`; independent proof `INDEPENDENT-PROACTIVE.json`. Actual HTTP/server replay passed 68 checks in `integration-cfaf489ff17543caa7ca4e26aed1d7ba`, including process/creator evidence, binary and manifest upload/download and event history. Two orchestration errors are retained: the first independent check ran before shutdown receipt existed; the first server invocation omitted the existing `--proactive` mode and correctly failed its full-matrix denied-open precondition. Neither is a product failure or a pass. The corrected r2 invocations succeeded; batch invocation now supplies the required mode. No denied-open coverage is claimed by this one-read test.

R39's 100.693-second trace reports zero lost events/buffers. `R39-scheduling-analysis.json` clips unique context-switch rows to actor creation-to-ready: 12.398 seconds total, 5.257 Ready, 4.684 Wait, 2.429 running CPU, 28.15 ms initial unaccounted. The collector used 7.199 CPU-seconds and Defender 6.894 during this two-vCPU window. Resolved sampled leaf functions include stack unwinding, Verifier-associated routines and runtime/JIT work; those totals do not establish inclusive driver cost, actor-file scanning, or the cause of untraced R37. `windows-defensive-sensor-r49-startup-latency-review.md` recommends interval-specific stacks and a finite repeatability investigation, while correctness cases retain unchanged gates. Startup performance remains open.

R38 is now independently accepted on all four Windows versions. The continuation accepted R37 Windows 10 (77 server checks, `integration-8eff913f82844818aaac6f6a0dd18b4b`) and Server 2019 (68 server checks, `integration-f22bb1d999c449ff84355b0df13f828a`). R37 DC FAILED final acknowledgement accounting after its controlled read checks passed. Archive `5511C4695241BFA173908313A8033FE02506BAED0A0A61DAB9869312F70572D3`; restored/off 2026-10-03T01:14:10Z. `FAILED-PROACTIVE-ACK-DIAGNOSIS.json` verifies archive/source integrity and identifies seven valid durable intents, six confirmed receipts, and one pending background GoogleCrashHandler process snapshot. The controlled actor's ACK is confirmed. The pending executable bytes and WAL/hash are intact; first ACK returned 0x80070490 and source disposal preceded retry completion. Exact native expiry-versus-stop cause is not established by the retained lifecycle journal. No final native resource-health gate or server replay pass is claimed for this failed run. The misleading 'intent missing' message is corrected to report both counts; no acceptance condition changed. R51 review concerns recovery and the mismatch between durable pending-outbox behavior and the fixture's all-background-ACKs-confirmed requirement. Original failure is retained. R40 Windows 10 designated-parent acceptance is recorded below. No fault diagnostic package has been loaded at this point.

Modified qualification modules: `tools/WindowsActorFixture/Program.cs`, `tools/WindowsPinnedRaceProbe/Program.cs`, `tools/WindowsProactiveActorProbe/Program.cs`; existing driver/client/server architecture and raw event v4 remain unchanged by these harness additions. Standalone compile checks passed with zero warnings/errors for the two diagnostic readers. These compile checks are not native passes. Independent Python checks compare saved raw wire data and actor truth, source/package/archive integrity, and balanced metadata counters. One VM runs at a time; restoration and powered-off receipts are prerequisites to acceptance.

R35 is the accepted 21-case, same-package four-OS matrix (completed 2026-10-02T23:58:27Z). R38 does not claim server transport (it intentionally exercises port ownership directly); R37 has a separate server replay gate. Native injected allocation/binding failure, sustained volume, crash/recovery, Linux operation-time binding, signing/altitude, production rollout and final product-wide QA remain open unless independently documented elsewhere. Read-only mail check at 2026-10-03T01:09:46Z verified the existing sent request and found no altitude reply; no request was resent.

Manus R47 has returned a finite qualification plan (`windows-defensive-sensor-r47-native-qualification-plan.md`). After the real STOP-live and proactive tests: one real designated-parent API scenario, two explicitly synthetic creator-state branches, an allocation-return-null branch, a two-object logical-capacity test with retained pins, and one forced-zero binding test. A 257-live-actor test would confound the separate process-registry cap and is not required to establish the metadata failure branch. Simulated failure handling must not be reported as a naturally reproduced OS failure.

The isolated `tools/WindowsDesignatedParentProbe` compiled with zero warnings/errors (`process-designated-parent-managed-r2-build.log`) and subsequently passed the R40 native Windows 10 case. It uses documented `STARTUPINFOEX`/`PROC_THREAD_ATTRIBUTE_PARENT_PROCESS` with held parent and child handles, validated x64 layout, bounded child cleanup and exact launcher thread truth. Expected collector result: actual creator PID/start/TID plus the different reported parent PID; parent start/correlation/path explicitly unavailable. Actual APIs were checked against Microsoft documentation and the installed 10.0.22621.0 Windows SDK headers. This adds no production driver behavior.

The designated-parent harness is sealed as R40, package `C7845D65B136989779B7655CD06E0432E919AE1146B103C8EEAED1220EC24010`, source manifest `D628B21C0007556347B9EE69B9D343F0E1D81DDFDF47FA57E15486A3CEE94860`, signed diagnostic driver `A8434F997B8D0AD05DFC9746C3FA664F8C7D51A571C2ECFC0D3685967934CD1D`. Native Windows 10 acceptance passed: archive `86A151EEC7E3E2D1A8C8EA26F5CA59A86A85A77D8B04F1CF2CB00ACBC60ABD1B`, independent raw-byte proof, restored/off at 2026-10-03T01:24:51Z. The actual creator PID/start/TID differs from the designated parent PID; unavailable parent start/correlation/path remain explicit. Three observations/completions, two exact actor artifact pairs, and two balanced metadata allocations were verified. `WindowsKernelFixture` supports a dedicated `--designated-parent` replay mode with explicit native schema/parent preconditions and no implied denied-open coverage; `process-creation-server-replay-r5` compiled with zero warnings/errors. The actual server replay passed 69 checks in `integration-a5e12d62387d492396a34121d19b68f9`, retaining those fields through event history and binary/manifest upload and download. This case was qualified on Windows 10; it is not a separate four-version designated-parent claim.

Manus R48 reviewed the later fault-hook design: epoch/generation-checked selection outside existing locks; normal cleanup paths; the actual global live-object counter with a selected-invocation limit of two; a fixed non-overwriting scenario journal retained after CLEAR/STOP. An implementation now exists in `CreationFaultDiagnostic.h`, with narrow compile-gated integration in `Driver.c`, `ExecutableStagingDiagnostic.h`, `ProcessCreationMetadata.h` and `Build-Prototype.ps1`. Commands 29-32 require `SQ_CREATION_FAULT_DIAGNOSTIC`; ordinary staging builds do not include the hook. Both ordinary and fault configurations compiled under /W4 /WX (`process-creation-ordinary-compile-r1.log`, latest `process-creation-fault-compile-r3.log`). This is compile-only: no fault package has been sealed, loaded or qualified. R50 actual-code review completed and its two concrete corrections are implemented: uninitialized reserved journal slots return explicit STATUS_NOT_FOUND, and an explicit terminal field controls completion/accounting rather than a timestamp sentinel. Bound-then-STOP and bind-failed-then-STOP have distinct outcomes; pending underflow becomes an explicit diagnostic inconsistency. Mutation identity lookup and reply-buffer copying occur outside locks. No real OS failure is claimed from injected outcomes.

The new `tools/WindowsCreationFaultProbe` compiled with zero warnings/errors (`process-creation-fault-probe-r2.log`). It specifies seven owned immediate-exit actors, exact operation-time owner/effective tokens, six verified executable copies, five explicitly injected modes, exact unavailable metadata, invalid strong retrieval/ACK after zero binding, A/B metadata retained by raw pins after process exit and candidate ACK, C capacity refusal, and balanced counters after normal draining. `verify-creation-fault.py` independently checks archive/source identity, raw wire fields, actor truth, bytes and journal linkage; syntax check only so far. Build helper has an explicit `creation-fault` selector but it has not been invoked. Ordinary-build native command rejection and a deterministic pending-callback STOP race remain separate uncovered gates; no delay/wait was inserted into process callbacks to force that race. The report's illustrative two operation pins must not be confused with two metadata objects: the actual fixture normally emits CREATE plus READ, so pin counts are derived from raw events. Existing Linux qualification is separately recorded in `LINUX-KERNEL-ATTRIBUTION.md`; this Windows continuation does not replace that implementation.
R41 actual restart recovery accepted: package `CE7321178D19826885F3981880BB26CC38BD05F2AC4A493F5595B284913AAB1B`, archive `2D2338B3B3F2CDF8E0DB4F0DCEF39DE690D86FED5F10F6A4C8B231B6D76C8C98`; restored/off 2026-10-03T01:35:20Z. The new `WindowsAckRecoveryProbe` uses the exact prior private guest outbox, preserving the original NTFS identities. All 57 original files and seven saved executable identities/hashes remained unchanged. An actual reloaded provider caused existing product recovery to append exactly one `ACK_PROVIDER_CHANGED` non-confirmed terminal. A second store restart preserved that terminal. Zero native ACK RPCs and zero new confirmed receipts were recorded. The original immutable failed archive remains unchanged and failed. Independent proof is `INDEPENDENT-ACK-RECOVERY.json`. Copies in the new archive are comparison artifacts, not rebased operational snapshots. No named ACK_OUTBOX retention-pin/GC subsystem exists; private files currently remain under the existing quota.

Manus R51 recommends correcting the qualification contract rather than redesigning shutdown solely to satisfy an all-background-ACKs-confirmed assertion. R42 implements that limited harness correction in `WindowsProactiveActorProbe/ProactiveAckProof.cs` and `Program.cs`. It keeps the controlled process's native ACK mandatory, verifies every captured snapshot, actual NTFS identity, exact WAL commit, claim, attempts and native error, then explicitly separates confirmed receipts, supported non-confirmed terminals and `PERSISTED_PENDING_AT_SHUTDOWN`. That last value is a local test classification, not a native acknowledgement. Missing/orphan/corrupt records still fail. Original resource, loss and timing gates are unchanged. The independent checker requires the new proof only when the sealed source contains the new helper, preserving the historical gates for older packages. Compilation passed with zero warnings/errors. R42 package `BDF845C90B4E07C5A6AC0953C64DE661ADBC5584569076EFFD7922DF23E3514A`, source manifest `564B9DBF3EF73756C3D7CF88EB2C211B19CD490C8437BCD58513F243BDC43D58`; native and server status appear in the table. This does not retrospectively pass R37 DC or resolve the Windows 11 startup issue.

R42 accepted after restoration/off at 2026-10-03T01:48:32Z: archive `9FE3E6EB1B340A1BE4914209907D15BA6DA0C8AB0AB276B361724E54F98CB308`, three observations/completions, two verified artifact pairs, six confirmed process snapshots, zero pending/non-confirmed intents, and 11 metadata allocations/frees. Two background executable-read failures are explicit; they do not remove the controlled actor's exact preservation evidence. Actual HTTP/server replay passed 68 checks in `integration-702743e97f014280b68cf2f7ff553124`. R41 covers the observed pending restart branch. The first independent R42 invocation failed because PowerShell rendered nested UTC timestamps with the controller's local offset. The corrected verifier compares only the documented timestamp fields as exact 100-ns instants and retains strict equality for all other values and archive bytes. Original log `DC-R42-independent.log` is retained; corrected `DC-R42-independent-r2.log` passed. No native evidence was changed.

R43 fault package is sealed: `026697FEDA0FFCB2D2FE793A2E342CA4183D6C3CC8CEDE1AF01C9B97909CC16D`, signed diagnostic driver `F7C10A1962926DF734D0A432CCE6E559BFC105A3360DDE6F2679DEA998828D54`, source manifest `BBEE5FC410F4D7334EAC2525B7DD5966586895F2D97C1AB5512E6CE084159CC7`. The first isolated Windows 10 run follows completed R42 acceptance; current independent status is in the table. Earlier compile-only statements describe preparation before this sealing. No production driver is changed.

R44 ordinary proactive package is sealed: `4A88018D4681F5BC904ACE64BAFAAF916041520C7903401288FA9D9896CCCED1`, source manifest `FC674992D3074DD17BA96011BBD49428035372B23333E451BAD82D9988A86D11`. The new qualification helper `OrdinaryCommandsProof.cs` sends structurally valid commands 29-32 and requires exact invalid-parameter errors with zero returned bytes, proving laboratory dispatch is absent in the ordinary build when run. This is a native gate, not established by compilation. It also provides one untraced Windows 11 startup/proactive repeat with unchanged gates; a repeat pass alone will not be called a latency fix. R52 asks Manus for a finite, honest pending-callback STOP qualification without inserting a callback wait or mislabeling a synthetic interleaving.
R43 Windows 10 FAILED its fixture assumption that every scoped access must be a selected actor: all seven owned actors completed, then a thirteenth raw observation from System PID 4 interrupted draining after 12 controlled operations. Archive `25CEA4816A4C688F91F1D98D72624B68F4ED48F58EA698875ACD3E7F24CA2F1F`; restored/off at 2026-10-03T01:56:12Z. `FAILED-FAULT-BACKGROUND-DIAGNOSIS.json` independently verifies archive/source/cleanup and the extra memory-mapping request (major 255), PID/start/TID, owner/effective SID S-1-5-18 and explicit missing executable path (image-unavailable flag). Which kernel subsystem initiated it is not established. Final resource accounting was not reached; this run stays failed. Missing image evidence is retained, never invented or silently dropped.

The corrected R45 diagnostic harness preserves every scoped raw record and binding, including bounded background observations, and separately counts the same 14 controlled CREATE/READ operations from seven exact actor instances. Only controlled events receive fixture user/token/command truth assertions. The independent verifier checks all background fields against the raw wire record, including unavailable tokens/path, but does not invent independent process ground truth for those background observations. The original metadata capacity, actor-byte, zero-binding and resource gates are unchanged. No collector behavior changed. Compile passed without warnings/errors; package `D68ED5C1DEF3366A4828ED5E3EFCC7232D71E05128D72F2385EC5C230680CD5A`, source manifest `E99EF49CC39FF396B8D309610065CC48016D10EAB34A99CF7ECD40EFBB486A79`; native acceptance is shown above.

Manus R52 returned `windows-defensive-sensor-r52-pending-callback-stop-qualification.md` (SHA-256 `41C6D9776CA674F0AE2A7F38558576CD2C42419CBE729FA024D1541DA16072F1`). Its concrete concern was whether selected diagnostic callbacks can finish outside rundown or skip finalization. Source inspection confirms `StProcess` acquires rundown across `StProcessCore`, and `CfFinish` runs after provisional metadata release but before the enclosing rundown release; every ordinary early return precedes `CfSelect`. Static diagnostic state remains resident until callback roots are removed and final rundown completes. Microsoft documents that process-callback removal waits for in-flight callbacks: https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntddk/nf-ntddk-pssetcreateprocessnotifyroutineex . One report detail needs care: this code's `StQuiesce` alone only stops new acquisitions/joins the expiry worker; callback removal and `StFinishShutdown` establish the later lifetime boundary. A pending-callback overlap has not been reproduced; the suggested synthetic state tests/eight real attempts remain unrun and must not be called native proof or a demonstrated production defect. No callback sleep or forced pause was added.
R44 Windows 11 ordinary-build run accepted after restoration/off at 2026-10-03T02:04:09Z: archive `C0173C62B9DC39C87C84210E97CC42AF6AB37B189052BBA9F93B83ECE3031B12`, three observations/completions, two exact preserved artifact pairs, four confirmed process snapshots and balanced metadata. All four laboratory commands were rejected with exact invalid-parameter status and zero returned bytes. Independent acceptance and 68 actual server replay checks passed in `integration-c02cc1f62fdd4f618f11b000bbcce4a4`. Actor creation-to-ready was 6.283 seconds, under the unchanged gate; this repeat does not establish the cause or fix of R37's timeout. Four background executable-read failures remain explicit. The first independent check again encountered controller timezone rendering, this time in populated snapshot file timestamps on Windows 11. `WIN11-R44-independent.log` is retained; the corrected exact-100-ns timestamp comparison includes those four documented file-time fields, and r2 passed without modifying native artifacts.
R45 Windows 10 native and independent acceptance passed: archive `D012F805EB61F22FECE7A9AD98E0895E51950EB688CA6B9ED2DCF95CA9D43FBE`, seven owned actors, 14 exact CREATE/READ truth matches, six byte-exact executable copies and six separately retained background observations. Five metadata allocations/frees and the two deliberately injected allocation/capacity refusals reconciled. Correct zero-binding behavior published no actor generation and rejected strong byte/metadata/ACK requests. All six nonzero bindings retained their exact actor copies despite the selected metadata branch. Baseline restoration and powered-off/zero-NIC proof precede independent acceptance. This direct-port fault package does not claim HTTP/server replay or natural OS failures. Ordinary-build diagnostic-command rejection was separately accepted in R44. The old R43 failure remains intact.
<!-- PROCESS-LIFETIME-CURRENT-END -->


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

## 2026-10-03 Windows callback STOP qualification preparation
- Added opt-in diagnostic command 33: exact provider/scenario/creator PID+start binding, STOP prerequisite, PASSIVE/APC wait-context check, existing callback-root removal followed by scalar final pending/selected/finalized/STOP/inconsistency/QPC health. Commands 29-32 retain their layouts. Diagnostic-only mutex serializes root removal with ordinary unload; callbacks never take it. API removal failures now propagate before a registered-root flag clears.
- Actual CF scalar-function model R5 passes 78 checks across six modeled callback orders plus negative owner/PID-reuse, wait-context and removal-failure/retry cases. This uses stubbed OS primitives and does not establish native scheduling/overlap. Header SHA256 EF95603DEF2DB0B5C3ED8B256B40334312AFEAEE0BE83FD1EC1A9F4A76AD9874.
- New WindowsCreationStopProbe/creation-stop package mode prepares exactly eight real one-actor attempts, fresh driver load for each on owned Windows 10 VMware clone. No callback pause, no actor storm, no relaxed actor deadline. Overlap requires selected.Started < STOP.Started < selected.Finished; eight nonoverlap results must remain explicitly not observed. Native run pending; no production change, no full product acceptance.
- Manus R53 affirmed root-removal sequencing but incorrectly reported missing armed-creator start equality; transmitted source already had it. Recalibration sent with stronger actual-header PID-reuse negative test. Original review retained.
## Windows R46 bounded STOP gate - 2026-10-03
Eight fresh-load Windows 10 19045.6456 attempts completed, each with a finished selected process callback, actual callback-root removal, one immutable STOP row, and balanced native references/queues. 244 per-attempt native assertions and 385 independent archive assertions passed for the raw evidence subset. Sixteen controlled CREATE/READ events independently match exact PID/start/TID, process-primary SID/token and accessing-thread effective SID/token, logon/session/integrity/elevation/impersonation level. Two background observations retained separately. Natural pending-callback STOP overlap was NOT OBSERVED in these eight bounded attempts; no pause/storm or ninth retry added.

The original guest aggregate remains FAILED: Windows PowerShell could not Measure-Object the ordered dictionary Matches field while writing the combined summary after all eight attempts. Archive 486852B421BD2B5B610FE2102035AAE5A658555F2B7529166D8932F75407A06B and original negative receipt are unchanged. INDEPENDENT-WINDOWS-CREATION-STOP-R46.json explicitly accepts only raw native evidence and records GuestAggregatePassed=false. The exact corrected summary block passed two Windows PowerShell5.1 local cases (eight saved results and empty failed run), without native rerun. Owned VM15009 restored and off at2026-10-03T17:37:31.1200113Z.

Actual callback-removal function model passed15 checks: process removal failure preserves both flags; partial success/image failure preserves the image flag; later retry touches remaining roots; worker-quiesce failure never claims callback removal. This uses stub OS returns and is distinct from native synchronization. Actual CF model78 checks remains accepted. Manus corrected review B4AA97817665EEAD5186FD53C8F73F6396FF88EA17573339E485FE340322B38C retained separately from its original incorrect creator-generation finding.

Next finite Windows gate: R47 ordinary proactive build must reject diagnostic commands29-33 (including new quiesce) with invalid parameter and zero bytes; ordinary callback removal and actual delayed-first-touch preservation/server replay remain subject to existing unchanged gates. Preparing this package; no production changes or full product acceptance. Storage still not blocking; no SQL migration or VM expansion performed.
### R47 ordinary-build negative and R48 correction in progress
R47 Windows10 retains a failed overall result, archive90A9AFB41E1C72237EFEB92D6C6311343A093B8808782B7339E20AD5C9D71979. The controlled actor passed13 delayed-first-touch/token/preservation/creation assertions, but the ordinary-command29 helper threw before final health acceptance. Its error omitted HRESULT and returned-count details, so the exact trigger cannot be reconstructed. Driver object inspection contains no Cf diagnostic symbols. Original artifacts remain negative; no server replay acceptance.
The helper incorrectly required lpBytesReturned==0 after a failed FilterSendMessage. Microsoft specifies that output only when the call succeeds (https://learn.microsoft.com/en-us/windows/win32/api/fltuser/nf-fltuser-filtersendmessage). New helper journals each exact request/HRESULT before validation, requires exact invalid-parameter errors for all29..33, and marks error byte-count explicitly undefined/null while retaining the raw caller slot as diagnostic-only. Historical verifier gates remain bound to their frozen sources; new source uses the documented failure-output contract. R48 ordinary package12D644559A69A113450E615D40C337742829D990D76B51F1A78743867D01878E is running with unchanged actor timing/attribution/preservation/accounting gates. R47 guest restored/off17:51:42.9572407Z.
Post-R47-freeze diagnostic-only command33 wait-context guard moved before pageable owner lookup; modelR6 passes78 checks including no owner lookup on invalid context. Diagnostic driver compiles; prior R46 archive remains exact earlier revision, no native rerun or overlap claim.
Manus Linux R101 installed plan archived193D79B67909EAB3CDF167E66988F67BF37D069ED3B056286DA9E444DBB06CB2. Its single-target initial proposal does not finish multiple-canary coverage. A bounded immutable1..32-target watchset/control-v2 and explicit event-time target device/inode schema6 review has been requested before Linux implementation. Existing audit/fanotify remain separate; file_open scope does not imply read/write/rename/delete or earlier denial coverage. No Linux source edit or production activation yet.
### R48 ordinary Windows driver and actual server replay accepted - 2026-10-03
R48 Windows10 19045.6456 native + independent acceptance PASSED. Immutable archive34FE0E25B71E3F673048DC477510286EC100D772B74CFAC80DDFF8CB9BAD65A8; package12D644559A69A113450E615D40C337742829D990D76B51F1A78743867D01878E. Four original/completion pairs, two exact actor artifacts, four process snapshots/confirmed ACKs,16 metadata allocations/frees and zero live/refused metadata. Three background executable-read failures are explicit. All five ordinary-build commands29..33 returned exact invalid-parameter errors; error byte-count remains explicitly undefined by the documented API contract. No callback quiesce diagnostic is exposed in the ordinary build.
Actual isolated HTTP/server replay passed77 checks in integration-54e55af5962842039f0944a2171edcad: exact event-time user/process/PID and accessing-thread token, creation/command evidence through SQLite/history, two binary+manifest uploads and independent hash-verified downloads. VMware baseline restored and owned VM15009 off2026-10-03T18:00:43.2945210Z. This is one delayed-first-touch case plus retained background observations; it does not establish new denied-open/all-operation/all-version or production rollout acceptance. R47 negative archive remains negative and unchanged. Windows bounded STOP overlap remains not observed in eight attempts. All owned qualification VMs now off.
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


## Current Windows matrix R49 and Linux matching foundation - 2026-10-03T21:37:07.349697+00:00

R49 passed the complete controlled matrix on all four recorded Windows builds, with zero-dwell actors and delayed first access: 84 cases including 24 denied cases. Exact accessing-thread vs process-primary contexts, independent user/process/PID and source-file identity, actor bytes, durable receipts and isolated server history/transfer were checked. Package `0983821DA8DF4F68CCF7C803E8C415AA7AD8113491E93463225E84653F248205`; source manifest `21DC2C71725ECF6D8CC577E6BB886518DDC7A3D87822FA3C3FDD849CF7520275`. All owned Windows guests were restored and powered off before Linux qualification started.

| Windows lab | Cases | Denied | Observations | Preserved pairs | Token checks | Server checks |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| WIN10 | 21 | 6 | 75 | 44 | 1080 | 933 |
| WIN11 | 21 | 6 | 60 | 44 | 990 | 796 |
| 2019 | 21 | 6 | 62 | 45 | 1011 | 820 |
| DC | 21 | 6 | 72 | 45 | 1071 | 910 |

Each full receipt preserves unavailable background actor observations and read failures. A controlled-case pass does not mean every background system process yielded a private executable snapshot. Per-target archive hashes, off/restored times and counts are in `diagnostics/windows-token-20260930/WINDOWS-MATRIX-R49-SUMMARY.json` in the outer workspace.

Linux actor matching foundation R115 passed 108 consistency checks on five accepted native pairs plus deliberate metadata mutations; 1000 repeated inspections retained identical serialized input. The matching helper does not confer TrustActor.Verified or enable suppression. The separate R116 short active-observation barrier passed 44 coordination checks, including real task blocking, terminal transitions and retained historical observations. Current-source sampling, trust v3, policy/server/UI integration remain pending. Sealed R35 is being tested natively for held private-descriptor matching; R34 is retained unexecuted. R35 predates the unused R116 barrier helper.

Live storage measured read-only at 21:13-21:14 UTC: server C volume 39.66 GiB, 13.12 GiB free; no local Microsoft SQL Server service/instance; live SQLite management file 198258688 bytes, data directory 3.14 GiB, retained backups 2.68 GiB. No storage expansion, database move, production deployment or physical-host reboot was performed. Development D has 30.0 GiB free and C has 1741.9 GiB free.

Microsoft altitude request remains awaiting reply (verified 21:05:56 UTC). R108 Manus review SHA-256 `89A3A5733FDEEFB0729D89F8FF6AF96CC486B526E5A2B60D76E5FD1C2D2E4319` adopted for source-health sampling semantics. Final product-wide QA and qualified deployment remain pending.


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


## Installed Linux boundary implementation in progress - October 03, 2026

Manus R111 recommends a root-owned immutable event/artifact inbox consumed by the existing unprivileged worker, retaining one upload and readiness reporter. The earlier direct-root-sender proposal was superseded. Root policy input must be independently authenticated. `docs/LINUX-NATIVE-SERVICE-INTEGRATION.md` records the architecture, module changes, admission and restart constraints, and finite qualification cases. Existing Audit continues to cover operations not observed by the native source.

The new signed policy contract uses a fixed RSA-PSS/SHA-256 scheme and domain prefix, canonical bounded payload, pinned SPKI digest, exact server/sensor/root challenge, common trust and monitoring assignment, and short expiry. The server reads both assignments in one serializable transaction. Signing-key creation is an explicit local maintenance command; repeated initialization preserves the existing key, and a missing key fails without regeneration. The ordinary ManagementClient only relays the envelope. No production signing key has been created.

Local verification passed 32 real signature/context/codec checks. Server R6 passed 14 actual isolated HTTP/local-key-initialization/ManagementClient relay checks. Local root-policy admission passed 25 checks: fresh/consumed/replaced challenge, monotonic timeout/regression, trust and per-group monitoring revision floors, conflicting same-revision contents, journal restart, failed commit/unknown return, and expiry during commit. Admission stores bounded current policy and revision floors as an optional version1 component in the existing protected Linux forensic journal; established forensic schema12 is unchanged. This has not yet been wired to an installed source, its policy cache, or its bridge. Root descriptor/config checks and single-owner admission enforcement remain integration work. Verification alone cannot activate a native source.

Server native-source readiness now expires after 120 seconds independently of the 24-hour parser compatibility window. The focused SQLite checks passed 31, including stale active readiness. Existing whitelist regressions also passed 214 after the notification changes. The ordinary Linux agent builds cleanly; this is compilation, not installed native acceptance.

R38 is sealed for actual VMware Linux verification of the signed-policy and root-journal components. Managed raw tar SHA-256: `c48857a7963f9d401eef629749e5d233644bf1b57ecc35000242dee17c72fca5`. That run is in progress. It starts no module, BPF program, controller or installed service. The existing R37 native capture and R5 UI/server results remain the latest completed native/UI acceptance.

Altitude mailbox checked read-only at 23:15:09 UTC: no reply. Production storage and deployment remain unchanged. Manus R110 recalibration SHA-256 `1E34F66379A9A2ADB4EB933DAA6C87C475817ABBE9D2CE48738E51BE862DCD88` withdraws its earlier record-equality finding. R111 review SHA-256 `F2C4EBE236EE66089C4497884F1E5684082DF227B84B9F71B83137E5A7687D5F`. R112 focused root-policy code review was sent, request `7451e1ea-f37c-4059-bea7-2b7ece6f21de`; result pending.

## October 03, 2026 - signed policy ownership and immutable bridge continuation

The R112 exclusive-owner correction is implemented: one volatile policy admission lease per owned Linux forensic journal; release is refused during runtime/native/recovery ownership and journal close is refused while a policy owner remains. Local and actual Linux admission checks passed 32 cases. Actual Linux signed-envelope checks passed 32 more cases. Independent archive verification confirmed the real Linux-generated RSA-PSS signature using Python cryptography, SQLite integrity/schema12, exact pinned server/key and revision6 history, and no source/native work. R39 archive: 73953908c8890c3ca7959b7dce877f322a1a3c21e26d186a1ac34e8eb6d18c3a. The whole R39 run remains FAILED because the descriptor test incorrectly required all pathname replacements to reject, even though the open descriptor safely returned original bytes. That assertion is corrected; no failed run is relabeled passed. R38 had 57 guest checks but its archive export failed on root directory permissions; it has no independent acceptance. R39 VM off/restored: 23:37:43.1051693Z.

New LinuxProtectedDirectory reads use held openat/statx descriptors, reject unsafe ownership/modes, symlinks/hardlinks, nonregular and oversized files, and compare the same file identity after bounded reads. The bridge packet retains exact original/completion bytes, process/attribution/trust linkage, actor bytes and manifest hashes. Local NativeBridgeChecks passed 54 checks against all five actual R37 native pairs, including three preserved actors, six interrupted-import boundaries, replay, contradictory PID/hash and retained-file conflict. The ordinary worker's existing event/upload queues are reused; no policy reevaluation or PID/path reacquisition occurs. Root publication now uses explicit group ownership, 0640 nonexecutable files, renameat2 NOREPLACE, fsync and bounded inventory/bytes. It is being qualified; no installed source/bridge is enabled.

R113 review's FileStream-disposal finding was withdrawn in R114 after checking C# using-declaration scope. The statx output buffer is now explicitly [Out]. R41 immutable payload beca2c2a3c944a23b35d5ed38887396b902a998698fc356c2a93f359b17dd8c9 is running in owned VMware vm15011: signed policy32, owner32, descriptor23, actual unprivileged bridge24 expected. R40 was sealed but not run; it predates the [Out] declaration. No Windows VM is running. Review hashes: R112 B43178079956D2D47F7E7C5F5A80715DD53E66F2A34D73BFA93AA4F726E70F12; R113 7CDC6EF712E26E3C55E29B16EE947D007078CA45DED6C2C391A75357AE954C5E; R114 E7B51E2A8219CAC88785A9FAE9A6CDAC767373DE9F4866913C16D70AAE724952.

An additional volatile admitted-policy lifetime component passed 18 local RSA/SQLite checks: monotonic expiry despite a frozen or backwards wall clock, invalidation that cannot revive, immutable returned policy contents, replacement/disposal revocation, and failed/unknown replacement commits. This change follows R41 and is not yet in the active native package or installed runtime. Service/configuration admission, source-bound health and policy refresh, root journal/export handoff/acknowledgment, installed lifecycle and final product QA remain outstanding. No production signing key, rollout, protection change, storage expansion or database migration occurred. D build drive free about25.18 GiB; C fallback1741.87 GiB; server storage not blocking.

## October 04, 2026 - root journal delivery and policy lifetime qualification

R42 passed 162 checks in the owned Linux VMware guest and 83 independent archive checks. Signed policy32, exclusive policy owner32, protected descriptor23, actual root/unprivileged bridge57 and monotonic policy lifetime18 all passed. The root delivery ledger binds a local import receipt to the exact published packet and committed event pair. Four interrupted retirement boundaries recover through the full acknowledgment procedure. Only redundant delivery copies are retired: all 18 source journal tables, all original/completion bytes, and all three actor copies/manifests are retained unchanged. Actual UID/GID65534 imported ten events and could not publish or modify root packets. The independently verified archive SHA256 is 72cf3d870f71670939be8fd0ca6bf16cae00b34c000f9c5572b63709574e7405. The VM was restored and powered off at 2026-10-04T00:12:54.5801031Z. This run activated no native module/source or installed service.

The first independent verifier failed because it required an empty directory that the regular-files-only archive intentionally does not include. The corrected verifier requires the guest's descriptor-based empty-directory assertion and independently confirms no corresponding file in the archive. The failed extraction remains; the successful independent-policy-r4-rev2 directory and receipt contain all results. R41 previously passed111 native and52 independent checks; R39 and R38 remain partial/failed as documented. Manus R115 found no concrete new authority/retention defect in the submitted ledger and policy lease; source policy use must still be bound to live work/drain ownership, and recovery must replay the complete acknowledgment procedure.

Current next work is installed Linux service integration: authenticated root/ordinary sensor policy and status exchange, validated installation configuration, and owned source lifecycle. Current installed Linux Audit behavior is unchanged. Windows R49 remains qualified in the four recorded test builds, not deployed to production; Microsoft altitude assignment has no reply at 2026-10-04T00:00:15.791511Z. Final three product QA passes and all-sensor deployment remain pending. No production signing key, protection change, resize, database migration or rollout occurred. Storage is not blocking this work.

## October 04, 2026 - authenticated policy relay and signed source binding

R43 passed214 actual Linux checks and93 independent checks. This includes52 actual Unix-socket checks: UID/GID65534 relayed signed policy, root verified the configured peer UID, the client verified root, two valid exchanges committed and nine malformed/context/signature exchanges were rejected. Independent Python cryptography verified both relayed RSA-PSS signatures, exact root journal envelopes, all prior bridge/source tables and actor artifacts. Archive9d93c1f62d8b5fa55af006051fecbf82c8c8a724724cea485c552e79d7092fcb; VM restored/off2026-10-04T00:44:04.9794343Z. Guest Operations briefly rejected/timed out read-only progress requests under high VM memory/CPU demand; the main test completed and archive export succeeded. VMware datastore had3540.95GiB free, so no storage resize or database migration was needed.

Manus R116 found that .NET socket disposal suppresses pathname deletion errors. The code now reconciles through the held protected parent, accepting committed absence or removing/fsyncing only the exact expected socket inode; changed/unsafe nodes report failure and remain. Listener disposal cancels its own pending exchanges. R44 adds actual retained-socket, wrong-inode and replacement-file cases and signed source lifetime checks; its245-case VM run is active, not yet accepted. R44 immutable raw tar3fb6326a4b85bd2fbfd7c16f858d2957ce559372b223549500448fc06ad6eeff.

LinuxNativeSourcePolicy now binds an actual admitted signed lease to the fixed sensor and monitoring/group/forensic assignment. Trust-only refreshes are serialized with observation; changed monitoring/group/revision requires stop and revalidation. The runtime holds its existing drain barrier through rule evaluation and source sampling, rejects a superseded/expired observation, and uses its actual stop/drain path on expiry. Local RSA/SQLite source binding tests passed23; actual native runtime qualification is pending. The normal installed Audit service is unchanged. The R117 group-binding finding was withdrawn because mandatory signed-snapshot validation already requires Trust.GroupId==Monitoring.GroupId, and the complete monitoring assignment is pinned. R116 review SHA CDE245E9F9CB8693934C9D0566070E772AEEC33C5E909D7BCEB0DA56F85DC790; R117 original5EC8419B7D84938D50E7BA5561135C8416DFBB7AF395F750434B45598EDAD904; recalibrationE7DDCB3996948D843C6AFA926A66B8A04DCF7612443BFA34172304174DE7BC69.

R45 is sealed and prepared, not run: actual signed-policy native source with five short-lived/renamed/replaced/deleted/unprivileged actors, expected147 checks. Raw tar5213fb49755c33cb4a43e96be0bb04afe1ad3b168d9b87092a4e283ec7750e0c. It must wait for the current owned VM run to finish and restore. Installed package/configuration admission, source health reporting, acknowledgment IPC and service lifecycle remain pending, followed by final product QA and all-sensor rollout. Windows R49 test qualification remains84 controlled cases/24denied across four builds; assigned altitude/signing and production deployment remain outstanding. No production key, protection change, deployment, volume resize or database move occurred.

## October 04, 2026 - signed native source, actual expiry and delivery shutdown

R44 completed 245 actual Linux checks and 95 independent checks, including protected socket cleanup and signed source lifetime. It restored/off at 00:57:04.9587786Z. Archive4c1deb692967f52d9dae06f4c33fe4829c792ef3b87f63e99578c2d52d31346e. No native source/module was activated by that component run.

R45 actual native run failed its 45-second managed startup deadline before any actor cases. Ready arrived during cleanup; the runtime closed with no errors, but the old harness did not positively check all map IDs. Its negative archive e0be715c2e8e32108a2b7019fd3ed9a7da953a5cdda113655be33ed521d6099f is retained. R46 was sealed but not run. R47 added measured startup stages, a 180-second initial readiness deadline, explicit aborted-qualification cleanup and persisted ready-frame identity reconciliation.

R47 ran all151 assertions on five real actors. Source activation took13.676 seconds. Exact SHA/path/filesystem-UID rules yielded two log-only originals; wrong-hash renamed, replaced-path and deleted actors still alerted. All ten original/completion events retain matching observed user/process/PID, five private actor copies, and three alert-preservation copies. The actual source accepted a second signed two-second policy, expired it, drained five raw records and returned the controller close with no pending work/errors. Independent Python cryptography verified both signed envelopes, exact root SQLite policy sequence2, raw native bytes, original/completion decisions, preserved-copy hashes and source cleanup (334 checks).

The R47 complete-run receipt remains FAILED because its new cleanup assertion incorrectly required exactly five maps while the actual program map inventory correctly contained eight (five named ready roles plus three additional maps). All eight were checked absent by the harness. A separate read-only live reconciliation checked all five exact program IDs and all eight map IDs, module/device absence and absence of exact loader/probe processes; only then did the controller restore/off the owned VM at01:27:33.7808802Z. The archive remains ef7a16c4675694b46f744a38f9f4f0a5e2b104bb54d7c46aeae04027093c2597; original negative receipt was not changed. Independent acceptance is INDEPENDENT-NATIVE-TRUST-R4.json and reconciliation is LINUX-NATIVE-TRUST-R4-RECONCILIATION.json. Chronology clarification: exact map absence was sampled after module unload and again live before VM shutdown/restore; the inherited prose in the independent receipt incorrectly says before module unload. The first independent extraction failed on a verifier field typo (Nonce instead of actual Challenge); corrected rev2 passed, preserving both directories.

LinuxNativeBridgeSocket now accepts only bounded, canonical local-import receipts from the configured ordinary service UID and exact sensor/server context. Existing root ledger validation binds each receipt to its published packet and completed pair; only redundant private queue/export copies retire. Source journal, raw bytes and actor artifacts remain. No request carries a path, native handle, policy or deletion authority. Manus R118 found a reachable stop race: synchronous disposal did not drain an accepted exchange. Both policy and delivery channels now stop admission, cancel listener I/O and await exclusive exchange ownership before releasing their protected parent. Concurrent stops share one result. Actual test cases block inside a committed acknowledgment/admission and require shutdown to remain pending; cancellation after signed admission must revoke that lease. R118 review SHA625DA41D17507D78E92C041AB1CB55DC0F6553C35B54974DF79521F9B4DF6349.

R48 delivery qualification failed before any IPC case because fixture packet files were omitted from its package; no native activation occurred. Negative archive4d0d7775ef56a0718f466177021b986d05ba6972b1413c02ef82622a1a05cf05 is retained; VM off/restored01:34:47.7784361Z. R49 includes all seven hash-verified fixture inputs and a host-side sealed-manifest preflight before VM startup. Expected actual checks195 (delivery128, policy socket67), currently running. Raw payload ddd6762b594bc154ce03c90992a66df1a1a45dc60b71c42485379afdfb84fc78. This component run does not activate a native source, module or installed service.

Installed configuration/package admission, readiness and service lifetime integration remain incomplete. Linux native source scope remains the one qualified kernel and pre-open operations, not arbitrary denials/writes/renames/deletes. Windows R49 and server/UI results are lab qualification, not full deployment. Three final product QA passes and all-sensor rollout remain pending. No production key, rollout, protection change, physical-host reboot, volume expansion or database migration occurred. Production uses SQLite; storage is not the blocker.

## October 04, 2026 - delivery completion and native package admission

R49 first controller R8 exceeded its180-second fixture deadline after10 invalid and4 valid delivery exchanges. VMware Guest Operations then lost the result response. A read-only recovery confirmed no owned test processes/module/device and8.4GiB available memory. All available partial fixture evidence was rescued before restore: archive39ffa5d00d0520c01eae5a564ad469f8148cd5e4886ec5338fe78a852fce77e8; LINUX-NATIVE-POLICY-R8-RECOVERED.json. Off/restored01:54:56.1241117Z. It remains a negative run.

The same immutable R49 source/payload ran with a600-second fixture deadline under controller R9. It passed195 actual checks (delivery128, policy socket67) and90 independent archive checks. The source's18 original journal tables, ten exact user/process/PID events and three actor artifacts/manifests stayed unchanged; only acknowledged delivery duplicates retired. Actual in-flight root commits blocked disposal until returned, and canceled policy admissions revoked the lease without a false success response. Archiveec394abd5bf64f5262662bc143f354f18d6a4f1eb28d60f2ea2fe421368cb1a2; INDEPENDENT-NATIVE-POLICY-R9.json; off/restored02:09:15.3350715Z. No native module/source or installed service activation in this component run. Manus R119 accepted the drain correction; review7FFFF167FF84F8AC467ED0AE767FFF006921BED0C3AE449B8C8F09E1F17F089B.

LinuxNativeInstallation now validates explicit root-owned configuration, exact qualified kernel/BTF/protocol, public policy pin and bounded manifest. LinuxNativePackageAdmission retains configuration and package update leases, verifies SHA256 from each held readable descriptor, rejects unsafe ownership/modes/links and same-path replacement, and preserves descriptor ownership until actual disposal. It grants no target/module/source activation. The protocol is explicitly status schema2/160 bytes, control2/native6, four leases, actor bound4MiB.

R50 controller R10 passed36 definition and24 actual retained-file/lock checks, then the negative changed-manifest test raised InvalidDataException outside the fixture's rejection catch. The product correctly refused the changed pin. No full-suite pass is claimed. Archiveaf1853dbd13c5b1252cc553a4d72718a9213cb68f5e29871e7279dbd1f64d806 retains logs/results; off/restored02:20:39.4954939Z. Partial package-case files were not copied by that old harness on failure; R51 now copies them before asserting process success.

Manus R120 identified one additional admission requirement: qualify the actual lock filesystem. Review8C0D36950D4186C47C7E2C6E08C65C89111D7C5C5897B692BC9C209B33F73A56. R51 uses fstatfs plus STATX_MNT_ID on held descriptors and exact /proc/self/mountinfo identity, requiring local ext4 for both roots, every update lease and every package member. It retains mount/device/fsid evidence and refuses a real unsupported procfs mount. This is the trusted, cooperating root-updater contract, not protection against hostile root. Definition retrieval remains nonactivating. The fixed fixture catches InvalidDataException explicitly. Local R142 build and Linux publish succeeded with zero warnings/errors (an initial no-restore build lacked a fresh assets file and was rerun with restore).

R51 immutable raw payload38993abd9f9aac494d9d586b540e2974463b78529ba381a67597394d3911750a is active under controller R11, expected77 actual checks (36/24/17). This is not an accepted result yet. Next work: independently verify package/filesystem gate, admit held target identities, implement owned module/source lifecycle and ordinary-worker bridge/health integration. Three final product-wide QA passes and all-sensor deployment remain pending. No production signing key, rollout, protection change, physical-host reboot, volume expansion or database migration occurred.

## October 04, 2026 - package/target qualification and native closure evidence

R51 passed77 actual Linux checks and29 independent archive checks. Root definition syntax36, retained package handles/locks24, and actual package admission17 all passed. The local ext4 admission records held-descriptor filesystem magic, statx mount ID, device and filesystem ID, and matches the exact current mountinfo entry; remote/unsupported filesystems cannot supply lease authority. Archive7c4d0a552ca84aecbcbec06e450f0dd05baf3e4d2d048d98582202ca57b4ac5b; INDEPENDENT-NATIVE-PACKAGE-R2.json; off/restored02:36:00.0498222Z. No native source/module or installed service activation.

LinuxMonitoredTarget and LinuxNativeTargetAdmission now resolve every target path component with no-follow O_PATH handles. They compare actual local ext4 device/inode against the root-installed expected tuple and retain that handle. Target contents are never read, hashed or copied by this admission. Ordinary user ownership and changes to size/mtime do not change the identity. A missing/replaced path, unexpected symlink, hardlink, nonregular file or changed mount rejects/requires stop and revalidation; a sampled check is not an instantaneous rename notification. The frozen target table never retargets itself to a replacement. R52 passed22 actual and73 independent checks against32 real files, independently statted by Python. Archive6a45dd6c16c84f07062e9d590cae9002deb17cf404eedbda5c340b3b0adf11d2; INDEPENDENT-NATIVE-TARGET-R1.json; off/restored02:45:30.4434087Z.

R53 qualified exclusive volatile native-lifetime holds for package and targets: disposal refuses while held, a second owner cannot acquire, failed disposal retains handles/locks, and actual hold return permits explicit later release. It also qualified an actual owned bind-mounted ext4 file, distinct mount identity/same backing inode, refusal of duplicate ordinals/wrong expected inode, and source-path replacement retaining the original bound inode. Normal unmount returned only after admitted handles closed; no lazy/force unmount and no owned mounts remained. All53 actual checks and86 independent checks passed. Archivee0b7350e141df88ef857b0db1779bf0957f979c9f887d2404ec7ac8086b23ab2; INDEPENDENT-NATIVE-ADMISSION-R1.json; off/restored02:55:51.5478673Z. No native module/source or installed service activation. R53 raw payloadd8687e464e852177997a7df70b51a543f384141c51e0d8a46058015f449fa189.

Manus R121 found no concrete target-admission identity/disposal defect and requested the now-qualified bind case (reviewC6E019CAA7D0B282D4FAEA9E8ECD9059FECA9072E8CE4A62CE730F0694E07D21). R122 advises an owned module wrapper around registered-before-start runtime construction, exact held-FD finit_module with flags0, nonblocking delete_module without force, and a distinct UnloadReturned state so a successful unload is never repeated after a verification failure (review7124885AC1879203670A64E19B1361429D0AC50DA2AE26855A55B56212B5C2EF). That wrapper/installed factory is NOT implemented or deployed yet.

The next implemented gate is actual runtime-derived NativeClosure evidence. The controller records whether its actual open returned a descriptor and whether failed-admission cleanup returned. Unknown/failed closes or constructor cleanup aggregates cannot produce a positive closure. Source evidence requires actual native work/barrier drain, successful controller close or positive no-descriptor state, completed owned child and both pipes, successful map/map-set disposal, and positive input/pidfd close receipts. Lost-map constructor cleanup now surfaces native close error. Optional evidence delivery remains separate. Serialized closure is diagnostic only: a future module owner must inspect its own registered actual runtime and successful Completion, not accept a caller boolean/task or disk receipt. Manus R123 found no concrete false-positive path in the supplied code (reviewC01F32119673E73F6A9E72FD1532F982204A52BBB89F6616B638B90851F722CB).

R54 local build/publish succeeded and immutable payload a7a620164f792de294c215e6c449fcf867bfddb8c0cd7f0302d2deffd3cd4ebe is active in the sole owned Linux VM. Expected153 actual native source/actor/signed-expiry/closure checks; not accepted yet. Controller Invoke-VMwareLinuxNativeTrust-R5.ps1; next verifier verify-linux-native-trust-r5.py. The old five-map cleanup assertion is corrected to require the actual program-derived map inventory, and exact map/program absence is sampled before module unload as well as afterward. R47's original negative/reconciliation receipts remain unchanged.

Latest altitude read was read-only, no resend: no reply at02:58:23.719975Z; sent-copy verified, Microsoft assignment remains external. Next work is owned module load/unload state and registered-before-start installed source factory, ordinary-worker policy/bridge/health wiring, service packaging, three final product-wide QA passes and all-sensor rollout. No production signing key, rollout, protection change, physical-host reboot, volume expansion or database migration occurred.

## October 04, 2026 - actual native closure and owned module lifecycle

R54 completed153 actual native source checks and336 independent evidence checks. Five actual actors produced ten events, five private actor copies, three alerting actor preservation copies and two log-only originals. User/process/PID and SHA evidence matched, both signed policies verified, and real two-second policy expiry drained capture. NativeClosure is derived only after issued work, controller, child/pipes, all exact program-derived maps and child input/pidfd handles return. Exact program/map absence was sampled BEFORE module unload and afterward. Archive18968522aeea0ba7278418a5fcb5a2aca622a1581944f2d24ff984466a28b647; raw payloada7a620164f792de294c215e6c449fcf867bfddb8c0cd7f0302d2deffd3cd4ebe; INDEPENDENT-NATIVE-TRUST-R5.json; VM off/restored03:06:47.4370170Z. That run used the qualification harness for module loading, not installed service activation.

LinuxNativeModuleOwner now pins the exact qualified R16 module SHA B4B01D465ED31065FEB09FB36732CC399A04202EB4FBDCE63D89C73812CED783 to fixed kernel name sq_actor_lease before native ownership. Root package/config locks and target handles remain held through actual finit_module on the same hashed descriptor and non-forced O_NONBLOCK delete_module. Successful load/unload state precedes fallible evidence work; hash-chained receipts retry exact bytes; successful delete is never repeated after verification failure. Busy/unknown states retain ownership. Prepare/dispose cleanup attempts each resource and retries only unfinished releases. Manus R125 accepted this bounded pre-source primitive (60504A19BAA42D697F9576E49BBB419F4D08B09D776332CB2BFD9E1908261DEE), following R124 corrections.

R55 actual pre-source module qualification passed50 checks in the owned guest: unqualified bytes refused, real load, injected post-load receipt/query failures, preexisting non-owner refusal, real busy unload with controller held, successful unload, injected post-unload query failure with verification-only retry, independent cleanup and unfinished-only release retry. Raw payload3abc139e3b4475031f6397c2781f4a00c2bb45a84f5b5c8d1977a3c51c7b7542; archive de884b627f0f16212896363925b628b76eff35c1d535c38aeeac2d6553f10bae. Controller Invoke-VMwareLinuxNativeModule-R1.ps1 is exporting/restoring; independent verifier pending. No source/BPF or installed service started in R55.

Post-R55 working changes add side-effect-free runtime preparation and explicit BeginRegistered. The module owner stores the exact runtime before receipt/start calls, derives launch paths from admitted root manifest, and checks live package/target identity during startup and sampling. StopSourceAndUnloadAsync awaits the actual owned Completion outside its transition lock and requires the same runtime's positive NativeClosure before unload. Root policy owner must match installed server, sensor, public key and journal. Journal must match the configured private directory. BuildR152 passed; these registered-source changes have NOT yet been natively qualified or published. Next payloadR56, local buildR153. Ordinary-worker bridge/health and installed service packaging remain pending.

Windows R49 remains84 controlled cases including24 denied cases across four Windows builds; no production claim. Assigned altitude still awaiting Microsoft (last read02:58:23.719975Z, no resend). Final three product-wide QA passes and all-sensor rollout remain pending. Storage is not blocking and no volume resize/database move was needed; production database is SQLite. No protection change, physical-host reboot or production deployment occurred.

## October 04, 2026 - registered source integration and readiness sampling

R55 module lifetime is accepted:50 actual checks and83 independent archive checks, archive de884b627f0f16212896363925b628b76eff35c1d535c38aeeac2d6553f10bae; INDEPENDENT-NATIVE-MODULE-R1.json; off/restored03:37:10.8105043Z. Both actual load scenarios retained correct ownership through post-load failures, real busy unload, successful unload followed by verification failure, and independent resumable hold release. No BPF source or installed service ran in that gate.

Registered module/source integration is implemented but not yet accepted natively. Runtime construction is side-effect free and the module owner retains the actual instance before any receipt/start operation. Journal admission occurs inside the owned run; failed admission cannot release a different owner. Stop awaits the actual registered Completion outside the module lock and requires the same in-memory NativeClosure before unload. Source paths/targets/kernel/hashes derive from admitted installation. Signed policy owner must match configured server/sensor/public key and the exact journal object; journal private root must match configuration. Package/target identity is checked at startup and during active sampling.

Manus R126 identified three bounded improvements (8B4A4E304747D977B2F7DF5B78DD57BBEE0DE1CF99131B4A0BA49A57B4EDACE0). They are implemented: committed callbacks finish the same pending source-close/unload-verified receipt once, including recovery after publication; a synchronous task-submission failure has explicit NOT_STARTED_NO_NATIVE_EFFECTS outcome/NoRunEntered closure, while failures inside Run cannot use it; the SOURCE_REGISTERED qualification callback was removed. Three actual failure scenarios are prepared with28 assertions, including a failure after source-close publication. There is no installed callback selector.

ServiceHealth now samples the actual owned loss map, child, generation, target table and current signed policy under an observation-only drain hold. Such a hold cannot authorize actor selection and shares the four-entry capacity bound; stop waits for its real return. Local source-work-barrier fixture passed50 checks, including6 health hold cases (buildR155). BuildR156 passed with zero warnings. This health sample is historical evidence only; it does not grant event suppression. Authenticated root health IPC, ordinary-worker reporting and installed service wiring are still pending.

R56 remains FAILED: test fixture guessed a libbpf staging path which does not exist. No module or source was started, no actor assertions passed. Actual failure logs and43581byte archive5ecad8c740646e86df915571e355b275e366169a173ac984f682f932ec109878 retained; LINUX-NATIVE-TRUST-R6.json; off/restored03:57:57.7313377Z. The test installer now runs dependency inspection only after verifying the exact qualified loader SHA, stages actual resolved libraries as regular root-owned package members and pins their hashes. This corrects test installation without changing live services.

R57 is sealed and ACTIVE in the sole owned Linux VM. Raw payload930ffaabc6f322d63b36f19edefbea244818916ec5104b114fad715903d7fab4; controller Invoke-VMwareLinuxNativeTrust-R7.ps1, expected160 main assertions and28 registered failure assertions, followed by independent verify-linux-native-trust-r7.py. It uses managed finit_module/load and registered native source, five actor cases, actual signed-policy expiry, live/stopped readiness samples and managed non-forced unload; no external insmod/rmmod. Manus R127 follow-up/readiness review is pending. Next unused payloadR58/local buildR157. R54 remains the latest accepted full capture run (153 actual/336 independent), R55 the latest accepted lifecycle primitive.

Production rollout and three final product-wide QA passes remain pending. Windows R49 retains84 controlled/24 denied cases across four builds; assigned altitude remains external, last checked02:58:23.719975Z. Storage is not blocking; no resize, database migration, protection change, physical-host reboot or production deployment occurred.

## October 04, 2026 - protected installer corrections and health socket

R57 and R58 remain negative qualification runs, with no native activation: R57 correctly rejected a writable /var/tmp ancestor; R58 correctly rejected the evidence parent created as0755 by the test installer. The fixture now uses /var/lib and explicitly creates the root evidence parent0700 before opening its journal. Package guards were not weakened. Negative archives e6423c5cd88b6827e08a0f1d22a73a1b8862e666684e240bd0d926c937fded9c and2e06975a8cf838eef8ea17a97d6cb838827f385a7597d210e08b489fdfbae5c5 retained; both owned VMs restored/off (R58 at04:17:59.6869354Z).

R59 corrected combined registered-source run is active, raw payload ec12f46e7183dbd7af379b08181a4c5b8b74e49e9bad2ac8bb0bfad3d91fbbac. Expected160 main checks plus28 owner failure checks; not a pass yet. R54 remains accepted full native capture153actual/336independent; R55 module lifecycle50actual/83independent. A concurrent read-only guest progress probe was rejected by VMware at04:29:59Z; the primary run remains active and no forced cleanup was attempted.

LinuxNativeHealthSocket and LinuxNativeHealthTracker now implement exact UID/peer PID/start/boot identity, pidfd liveness, nonce, monotonic reply interval, volatile sequence ordering, explicit unavailable state and ten-second freshness. Local readiness/ordering fixture passed28 checks. BuildR160 succeeded with zero warnings. Real root/UID65534 health-socket tests are implemented and sealed as R60 (raw7afc374ba64b86ce3f0b87a4517a06123ccfe481e270fea16d2f2884c614920f), not yet run. Their source samples are synthetic; actual source readiness is independently exercised by R59. No installed worker/companion is activated.

Manus R127 accepted the corrected registration and historical source readiness code (02DDFD19552592515282F3AA71F2A92BC66D58C6F5575587A0D2B4C7F7C24426). R128 health review840B8DA6F41099BC197BBBBD80808490D33D1D655D3852A934C73A4D9F27F36B found no new authority defect; it emphasized that the five-second socket deadline cannot forcibly cancel synchronous source/map reads. CloseState explicitly remains CLOSE_DRAINING until the actual sample returns. The new socket fixture requires client timeout without readiness, retained in-flight exchange, pending shutdown, and exact socket retirement only after return.

Storage remains adequate; no volume expansion or production database move occurred. Last production database inspection identified SQLite, not an SQL Server instance. Microsoft altitude reply still absent at04:04:50.325571Z; no resend. Windows four-build R49 qualification is retained. Ordinary-worker integration, installed root companion, three final product-wide QA passes and all-sensor deployment remain pending.

## October 04, 2026 - ordinary client and root companion composition

R59 full capture gate remains FAILED: first actor completion49.317seconds exceeded the unchanged45-second durability limit. Its kernel actor copy finished1.06seconds within the native2-second deadline and retained the correct16552bytes/SHA/user/process/PID. All28 registered-owner failure scenarios passed. Independent bounded verification passed54 checks (INDEPENDENT-REGISTERED-FAILURES-R1.json); it accepts those failure scenarios and one recovered actor only, not the fullfive-actor capture or installed lifecycle. Recovered negative archivefcee01200aae7fa70d08ff3b5d8a372229ffb3129470384d49c44a64c3d4ab40. VMware Guest Operations failed transiently; a separate live reconciliation checked exact program/map absence, native module/device absence and no owned processes before safe restore/off04:41:18.9063383Z. Original controller failure and negative receipt are retained.

VM-PLACEMENT-R1.json: single ESXi host10.81.60.100 sampled43894MHz used of43880MHz total, datastore3515.02GiB free of7441GiB. VM-PERFORMANCE-R1.json shows high CPU scheduling wait, virtual write latency average1.89ms/max4ms and read max1ms. Guest MemAvailable8804008KiB. These observations implicate CPU contention, not a demonstrated storage or RAM capacity shortage. No storage expansion, DB migration, CPU-priority change or unrelated process termination occurred.

R60 health socket run remains FAILED: first cold root/ordinary exchange exceeded the product5-second deadline and sent no ready response. Negative archive93c4aefbfe1b6dee190608d7ceafb97802c17f9fa262aedec7ca5765fa78caf9; VM safely restored/off04:51:22.0102386Z. Fixture now records up tofour fresh attempts within the same ordinary child while keeping all product freshness/identity/nonce deadlines unchanged. Corrected R61 health run is active, raw1d0ee9364b1f35bebb57e29e87ee59c2048959a2dec30da0c6720712c02ba76f; expected87actual IPC assertions, synthetic source samples. It activates no native module/source.

LinuxNativeCompanionClient is implemented and wired into LinuxWorker, default disabled. Independent policy relay, exact root export import/ack and live health loops reuse the existing credential/network/event-spool/upload owners. Capabilities are reported only from recent authenticated readiness and OPEN lifecycle state. Status exposes native health/policy/delivery and CLOSE_DRAINING/CLOSED/CLOSE_FAILED. Shutdown invalidates readiness immediately and awaits actual durable import/network task return. Corrupt packets remain; a rotating16-item page prevents starvation within the256-entry inbox bound. Local config/delivery-order checks14 and readiness/ordering28 passed. BuildR163 LinuxAgent and R164Linux fixture succeeded, zero warnings. Actual full facade transport and blocked-import shutdown qualification remain pending.

LinuxNativeCompanionRuntime internal composition is drafted, with no installed CLI/unit activation. It admits fixed root installation/package/targets, owns root journal/pipeline, waits for root-verified signed policy, registers and owns its actual module/source, provides policy/delivery/health sockets, exports only exact completed journal pairs, and awaits actual native closure before normal unload. Pending receipt and independent release failures are retried without repeating a successful unload. Final shutdown exports remain importable; root duplicate acknowledgments may wait until the next root session. Manus R129 reviewF6B17CD75A98DE0A8D4C95E7FD3DC54F84679AE9E3B731326F7B3A1B2AFFD881 accepted authority/retention and required honest draining during blocked imports, which is now explicit. Manus R130 found no unsafe release/authority/source-deletion path and requests a finite shutdown-final-export/restart-receipt qualification case. Root composition, installer/unit, integration and finalthreeproduct QA passes remain unqualified/pending. No production deployment occurred.


## October 04, 2026 - live health and ordinary import drain accepted

R61 health socket passed87 actual and52 independent checks, using real root/UID65534 IPC and explicitly synthetic source health samples. Four transient cold-client timeouts were recorded; all successful replies still satisfied the unchanged five-second exchange bound and ten-second freshness/identity checks. Blocked sampling produced no ready reply, kept shutdown CLOSE_DRAINING, and retired its exact socket only after actual return. Archive249fcdb644cc8c6a729fa5789f0a04d62a221d73c9f8cffba5228e528cf7acb2; INDEPENDENT-NATIVE-HEALTH-R2.json; owned VM off/restored05:08:43.3988815Z. This is transport qualification, not a new native file capture result.

R62 ordinary companion transport passed24 actual and22 independent checks. A real UID65534 LinuxNativeCompanionClient held an actual root export descriptor while its independent health loop progressed. Stop revoked readiness immediately and remained CLOSE_DRAINING until import returned; exact original/completion bytes, preserved actor/SHA256, manifest, upload intent and receipt were durable before CLOSED. Retry retained exactly two events, one artifact, one upload intent and the unacknowledged root packet. No management request occurred. Native packet was replayed qualified evidence and health samples synthetic. Archive09e8eab2a19ecb96126373cd064dca7625d6cb57d19667dba87a6d0c34951dd9; INDEPENDENT-NATIVE-COMPANION-R1.json; off/restored05:26:14.0602141Z.

Root companion startup now registers channel tasks inside its finally/drain boundary. LinuxNativeCompanionService and --native-companion/--native-validate add fixed-root installation entry points without reading ordinary enrollment credentials. POSIX TERM/INT cancel into actual runtime drain; HUP does not partially reload. Native-enabled ordinary hosts use infinite managed shutdown timeout; an opt-in unit drop-in prevents SIGKILL during durable import and adds only the dedicated bridge group. Draft root unit uses mixed signal routing, no forced kill, infinite stop timeout, root-only state and AF_UNIX restriction. These entry/unit paths are not yet installed or qualified. BuildR166 passed with zero warnings/errors.

R63 was sealed but not run. R64 adds fixture cleanup for a completed startup failure and is ACTIVE under Invoke-VMwareLinuxNativeRuntime-R1.ps1, exec32126. Raw payload25d46008b38c603a4c4eecbbb6047b4b6281726dabb06343935c9c0e224d9f9b; manifest13bc142f113de3e6c4096789eabf65d44825374c23f559d2df30466eee110672. It uses the actual root companion and ordinary sensor, an ephemeral simulated management signer, real native capture, five actors and final-export/restart acknowledgement. Native capture latency remains subject to the existing45-second acceptance limit; evidence collection can continue to120seconds without changing that gate. Do not call this run passed until its receipt and independent inspection exist.

LinuxNativeInstallationPreparation and --native-prepare now compile (buildR169 zero warnings/errors), but are not in R64 and are unqualified. Explicit root requests provide only public policy key, approved member hashes and approved target paths. Existing protected-descriptor/package/target abstractions verify exact kernel/BTF/module, local ext4, permissions, size/hash and live target identities. Preparation writes new canonical root configuration/manifest using create-new durable writes, never overwrites an existing installation, and never loads a module, hashes target content or starts a service. Installer script and installed systemd lifecycle remain pending.

Manus R131 found a fresh-start unit issue: the runtime socket directory must exist before systemd applies ProtectSystem=strict. RuntimeDirectory=sequester-native now creates it first; ExecStartPre sets the dedicated bridge group before sockets bind. RuntimeDirectoryPreserve=yes retains abnormal leftover nodes for explicit diagnosis. Actual unit qualification remains pending. The review accepted the signal bridge and mixed/no-SIGKILL/infinite-drain settings in principle.

R59 full capture deadline failure is retained. R54 remains the latest fully accepted five-actor native capture run; Windows R49 remains84controlled/24denied across four builds. Assigned altitude/signing, installed Linux integration, finalthreeproduct QA passes and all-sensor production rollout remain pending. Storage does not currently block progress: datastore3515GiB free, DB~189MiB SQLite, production C~13GiB free, isolated guest~8.4GiB available RAM. Host CPU contention remains implicated by direct VMware measurements. No DB move, volume expansion, CPU priority change, protection change or production deployment occurred.


## October 04, 2026 - combined startup fixture correction and inactive installer

R64/NativeRuntimeR1 FAILED before native activation: the in-process simulated management client lacked its fixture credential, so ManagementClient refused authenticated relay before the signer was called. SignedPolicies0; no admitted native policy, source/module ownership directory, source lifecycle record or actor event. Actual root lifecycle reported waiting, draining and native-closed; the ordinary child reached CLOSED with zero events. Negative archivea68feb35f286db53b5bd565728cb0e8f3bff14096649f91ee0852fd0ce7333e1 is retained unchanged. The original conservative harness retained the VM because no native map identity had ever been created. Separate live reconciliation proved no native activation/module/device, no owned process, empty source/policy/work ledgers and closed ordinary child before restore/off05:45:25.2385148Z. See LINUX-NATIVE-RUNTIME-R1-RECONCILIATION.json; this is not a capture pass.

Fixture now supplies a test-only credential exclusively to the in-process signer. Local authenticated sign/verify and paused-signing refusal checks2 passed under buildR171, with no network contact. R65 is sealed and ACTIVE in the sole owned Linux VM via Invoke-VMwareLinuxNativeRuntime-R2.ps1, exec42611. Raw2924c36ddd0fe3fcac689fe9f64b8353e10326b843f3827ca2a7dd82eb4af859; manifestbd7b2764e24b5b7fe8cf3e0971f5939e358e4e64981dc44aa6b4aaa2f015ea79; buildR172. The harness now reports early probe exit promptly and recognizes only explicitly proven pre-policy native-free failure. Full45-second capture-latency and actual shutdown-overlap gates remain unchanged.

Inactive native installation staging is implemented in packaging/linux-client/native/stage.sh and --native-prepare. It accepts a root-private request, verifies a protected staged release, exact ordinary UID and dedicated group membership, refuses existing installation/service files, creates new protected directories and invokes descriptor-based kernel/BTF/package/target admission. It does not install/start/enable a unit or alter the ordinary sensor configuration. Partial preparation evidence is retained. Bash syntax check passed; actual preparation, first-boot RuntimeDirectory setup, HUP and systemctl stop qualification are pending. R131 review hash659D7266DAF91A5AC97AC221B57323E89CE6DCD217DFFCBCA06EC537B0BACF7B; its fresh-runtime-directory finding is addressed by systemd RuntimeDirectory creation before the root group setup command. No follow-up review is pending.

The latest accepted component gates remain R61health87actual/52independent and R62ordinary-import24actual/22independent. R54 remains the latest full native capture acceptance; R59 retains its45-second latency failure. Windows R49 and all prior accepted server/UI receipts remain bounded qualification evidence. Finalthreeproduct QA, assigned altitude/signing and all-sensor production deployment remain pending. Storage expansion and DB migration are authorized but presently unnecessary; no production infrastructure change occurred.


## October 04, 2026 - composed capture R65 negative, refresh fix and installed-agent candidate

R65/NativeRuntimeR2 FAILED the matching-whitelist assertion. Independent review83 checks verifies the bounded useful evidence: five independently matched users/processes/PIDs, ten exact original/completion byte strings in the ordinary UID65534 sensor queue, four executable copies with matching hashes and manifests, all five duplicate-delivery receipts retired after a delivery-only restart, and one actually closed native source/module lifetime. OverallAcceptancePassed remains false. Archive51101367a0126ac2a4d5018e3eb14ccabf7400146a053ceceff55fa6de14c6a1; VM off/restored05:59:35.2776051Z. The first actor took49.391543043s, exceeding the unchanged45s limit. The fifth stop arrived before native authorization: user/process/PID was retained with PIN_INTERRUPTED_PRESELECT and ACTOR_ACQUISITION_UNAVAILABLE_INTERRUPTED_BEFORE_NATIVE_START; no bytes or hash were invented.

Actual policy refresh during evaluation can invalidate the prepared lease. LinuxNativeSourcePolicy now retries the complete evaluation once against a newly admitted lease, without holding the replacement gate over evidence I/O. Changed policy decisions are discarded; stop/expiry/repeated churn cannot retain stale suppression. Local signed-admission tests31 passed, including eight new replacement/expiry/error assertions. A missing trust decision now records LINUX_TRUST_NOT_AVAILABLE in the event reason codes.

R66/NativeRuntimeR3 is ACTIVE (exec66187, Invoke-VMwareLinuxNativeRuntime-R3.ps1). BuildR174 uses ReadyToRun as a measured candidate for cold-start delay; no performance improvement is claimed before results. Raw3e312a8a83edcf6407f5f1f85a98b0a8d533c4f2a02cd530e08d89d299f9d410; manifest24c7b714773d875720a959172a3323353574ae2605d114d84e339820486dbe69. The fifth shutdown case now requires an actually started native capture before requesting stop; R65 preserves the separate pre-authorization limitation. Latency remains45s and is saved even on failure.

Actual LinuxAgent R67 buildR175 published successfully with ReadyToRun. Its source freeze includes Client, Contracts, LinuxAgent, linked root sources, template assets and native package unit/stager. Raw8f6d7dd7f331d3df8ecfb1b4f2b54deaf3aaf14f3a653436ea307d1010e23795; manifest64a8e390f48927f4e934a65c041d64bf59a582d71920b6812f79ea6c736e36e8. Installed preparation, duplicate refusal, fresh RuntimeDirectory, HUP and actual systemctl stop qualification is prepared as NativeInstallR1, not started. It deliberately provides no signed policy and claims no native capture or installed ordinary-worker/server acceptance.

Altitude reply check05:49:46.184089Z: no Microsoft reply; request not resent. Windows R49 remains four-build controlled qualification, not production rollout. Final three product QA passes and all-sensor deployment remain pending. Storage is available; no VM resize, database move, production service change or protection change occurred.


## October 04, 2026 - R66 capture/whitelist/latency verified; duplicate export race found

R66/NativeRuntimeR3 overall FAILED because one already acknowledged export packet was recreated during the delivery-only restart. Independent verification88 checks confirms five independently correct users/processes/PIDs and actor hashes; ten byte-identical events imported; exact matching whitelist log-only; other four actors alerted and preserved exact actor/manifest bytes, including the actor whose NATIVE_STARTED work completed after shutdown began. First four measured completion waits32.3948/37.3791/26.2779/30.2136s all meet the unchanged45s limit. This single ReadyToRun candidate run does not establish a general performance comparison. Exact artifact18d2ae6026802cb54e7bbc4b98a28b4b866cb61faf36484e9133f5ebe5ab275b, full native closure and VM off/restored06:19:12.6137571Z. One remaining export exactly matches its durable ordinary import receipt; the source journal and ten ordinary events were not lost or duplicated.

Root cause: PublishCommitted read a stale pending export outside the acknowledgement gate, then recreated its packet after retirement. It now serializes its entire admission/publication/ledger operation with AcknowledgeImport and first checks the durable imported receipt. An acknowledged ID returns its existing packet hash without republishing. Added stale-inventory regressions with a fresh exporter. R68/buildR176 sealed with this correction and five extra actual fresh-exporter checks in the composed runtime fixture (15 internal checks total). Raw4f309438eda8f2f0ec7dd6a359bf45ac3d8485312d801fb5c2f1ed02c9328749. NativeRuntimeR4 is prepared, not running.

R67/NativeInstallR1 is ACTIVE via Invoke-VMwareLinuxNativeInstall-R1.ps1, exec43827, actual installed LinuxAgent package built before the export correction. Its intentionally policy-less preparation/first-start/HUP/stop scope does not exercise export publication. It must finish and restore/off the sole owned VM before R68 starts. Production service, DB, VM storage and protection settings remain unchanged. Assigned altitude/signing, installed signed capture and ordinary worker/server integration, finalthreeQA and all-sensor rollout remain pending.


## October 04, 2026 - installed preparation passes; runtime directory group correction

R67/NativeInstallR1 FAILED service startup after17 successful harness assertions. Actual stage.sh and --native-prepare/--native-validate admitted the root installation; duplicate preparation/staging preserved bytes; actual target identity and protected directory modes matched; the unit passed systemd-analyze verify. At service start, LinuxNativePolicySocket refused the runtime directory ownership/group. RuntimeDirectory creation by systemd resets the group before ExecStart, undoing the ExecStartPre change. The service exited with SIGABRT before signed-policy admission or native activation. Archive1923a817f89230dcc36629d08905b664811a4e431d027c0eba3ddf27d83fffc8 retained; actual no owned processes/module/device, VM off/restored06:31:42.5540974Z. First-start/HUP/stop acceptance is not established by this negative run.

Unit corrected to User=root and Group=sequester-native with RuntimeDirectoryMode=0750; redundant ExecStartPre removed. Root-only0700/0600 private evidence permissions remain enforced independently of primary group. Dedicated service wrapper now reports NATIVE_COMPANION_FAILED and exits1 for a returned startup/runtime error, after its owned drain boundary, instead of an unhandled abort. Unresolved actual native drains still do not return. R69/buildR177 actual LinuxAgent sealed: raw7e75c8e833219ca3344c6b37a7601fe66ac4543fbedd9087bfe1e328921c00a2, manifest2a2147ded81581bbc0f1663604b5371063632eb74624100f6ddf8fa4a6a66ee3. NativeInstallR2 prepared with an early actual-failed-state check, not started.

R68/NativeRuntimeR4 is ACTIVE, exec48481, testing the duplicate-export correction with actual capture and five fresh-exporter stale-inventory checks. R66 remains independently verified88 bounded checks for capture, hashes, whitelist, latency and shutdown copy, with overall failure retained for recreated acknowledged packet. FinalthreeQA, installed signed native/ordinary-worker/server integration, assigned altitude/signing and all-sensor deployment remain pending. No production/storage changes.


## October 04, 2026 - composed runtime and installed service lifecycle accepted

R68/NativeRuntimeR4 PASSED 67 actual harness assertions, including15 component assertions, and101 independent archive/database/hash-chain checks. Five actual short-lived actors generated ten original/completion events with exact User/Process/PID, executable hashes and separate target identity. The matching actor whitelist logged without alert; four other actors retained exact executable copies in root and ordinary stores. Replacement/deletion did not substitute pathname bytes. All four timed completions met the unchanged45-second gate. The fifth native acquisition started before cancellation and completed during actual native drain. Five receipts retired duplicate exports; replaying stale inventories with a fresh exporter did not recreate acknowledged packets. Native work, child/pipes and BPF maps/programs closed before successful non-forced module unload. Archive c64e4c604cc7a84dc6f0ce7553cd4dda0147f1f13b2be443a427fa1dfeb59232; VM off/restored06:44:15.0275874Z. This used a signed simulated management server and actual cap-free ordinary bridge client, not the complete installed LinuxWorker or production service.

R69/NativeInstallR2 PASSED27 actual and16 independent checks. Actual published stage/prepare/validate commands admitted a new installation and refused duplicate staging/preparation without byte changes. Corrected systemd Group=sequester-native creates the runtime directory correctly. Actual installed root process waited for signed authority without native activation, survived HUP as the same process instance, and stopped normally through the signal bridge with sockets retired and empty policy/source/work ledgers. Archive54d3b362f6bfb04c4143ee5d1feefbb82a1e8ee03a310af0fa51111a4566cd1d; VM off/restored06:52:36.8537707Z. No signed source activation was attempted in this lifecycle case. EarlierR65/R66/R67 negative receipts remain immutable.

InstalledServerR1 is ACTIVE on the same isolated owned VMware guest, using actual R69 LinuxAgent and R70/buildR178 Linux server. The planned gate uses normal CA/hostname-verified loopback HTTPS, explicit server key initialization, actual enrollment and signed policy, installed root service plus actual ordinary cap-free LinuxWorker, five actors and real central evidence upload/download. Only the owned disconnected VM trust store is changed. R70 archive1c4992122417d53789ec5a7d1fe3ff6a53377efd85b244833e7fd3498fabdeea, manifest3dcff25de58093131f6a7f7e6561fd1790e54696193fee0568bd6388a6df3d6d. Initial local launcher encoding error occurred before any guest action; corrected launcher uses start2 log. No integration pass claimed yet.

Current native Linux scope remains qualified6.12.94+deb13-amd64/local ext4/preopen requests/4MiB actors. General write/rename/delete and earlier DAC denials retain existing audit coverage and explicit limitations. Finalthree full product QA, release/signing/assigned altitude and all-sensor rollout are pending. Storage is not a blocker; no production database move, resize, deployment or protection change was made.


## October 04, 2026 - live Linux kernel rollout inventory

Read-only uname checks completed on all 26 recorded Linux sensors, including seven established Ansible aliases. Sixteen report the current qualification kernel; ten report seven other kernel versions. No native collector was activated. A kernel-name match alone does not establish matching BTF/module bytes, filesystem support, security configuration or full installed qualification. Existing audit monitoring remains unchanged.

| Kernel | Sensors |
| --- | --- |
| 5.15.0-170-generic | netbox |
| 5.15.0-185-generic | mysql01, x-wiki |
| 5.15.0-186-generic | plex01 |
| 6.1.0-50-amd64 | freepbx01 |
| 6.12.86+deb13-amd64 | wazuhman01 |
| 6.12.94+deb13-amd64 | backup01, ddi01, ddi02, erpnext01, nginx01, openradius01, openradius02, ops01, rustdesk01, scanopy-dmz01, scanopy-iot01, scanopy-trusted01, scanopy-wireless01, socdev01, support01, webmail01 |
| 6.12.95+deb13-amd64 | openradius-witness01 |
| 6.8.0-134-generic | openconnect, plexcontainer01, www-legacy |

Evidence: LINUX-SENSOR-KERNEL-COMPATIBILITY-20261004.json, SENSOR-KERNEL-READ-20261004T0716Z.jsonl and SENSOR-KERNEL-ALIASES-20261004T0721Z.jsonl. Different kernels require corresponding module builds and qualification before native activation; do not infer universal support from the Debian qualification.

The altitude mailbox read at07:13:36Z found no fsfcomm reply. A07:22:29Z read found no matching message pending in the local outgoing queue. Historical transport-log and related-header reads timed out; external delivery remains unverified. No additional email was sent.

The initial80 MB server transfer exceeded its540-second bound before testing; VM off/restored07:11:26Z. The retry reconstructs the same sealed server from a44,409,599-byte delta and187 individually verified cached files. Raw tar SHA-256 ca3f56e5baad4973ba4eed4944ad8aed2f9d60b60f967ca49ad6eea0466a6aee; original server archive and source provenance are unchanged. A package-only owned VMware snapshot will be created only after all staged package hashes and file/directory flushes verify; original baseline remains intact. Full installed capture/server acceptance is still pending.


## October 04, 2026 - native prerequisites checked on all Linux sensors

All 26 established Linux aliases returned the read-only prerequisite query. The16 current-kernel sensors also match the exact qualified BTF SHA-256, x86_64 architecture, ext4 sensor-state filesystem, active BPF LSM and lockdown-none state. This does not replace per-target admission or full native installation/capture qualification. No native module was present or activated. Seven Ubuntu sensors have CONFIG_BPF_LSM=y but bpf is absent from the active LSM list: mysql01.tekmyster.com, netbox, openconnect, plex01, plexcontainer01, www-legacy, x-wiki. Their boot configuration must be qualified before this LSM-based source can run; no boot changes or restarts were performed. Ten sensors still require their corresponding non-current-kernel module/profile qualification. Least measured /var/lib free capacity was13.41 GiB. Evidence: SENSOR-NATIVE-PREREQUISITES-20261004T0731Z.jsonl and LINUX-SENSOR-NATIVE-PREREQUISITES-20261004.json.


## October 04, 2026 - installed integration failures and ownership correction

InstalledServerR1 failed before native installation because its owned qualification CA lacked the keyCertSign extension required by strict TLS validation. No TLS bypass was introduced. The test now verifies its chain with openssl verify -x509_strict before server start. Separate positive pre-native closure inspection confirmed no new native installation, module/device or owned process; VM off and original baseline restored at07:46:59.1400613Z. R1 remains failed.

InstalledServerR2 passed strict TLS, actual management key initialization/enrollment and signed policy relay, then failed after23 assertions before native activation. The installed root service has a dedicated non-root group; module journal creation inherited that group but the journal admission required root:root. Archive d8d6a4f0a5749c852044b9350b37111ff00a4fa17062ab7b6743b2a42ea0e9be retains the failure. No file-operation records were captured in R2. Actual closure found no module/device, owned BPF maps/programs or owned processes; VM off/restored07:54:47.5895992Z.

LinuxProtectedDirectory now creates the module journal through mkdirat/openat on its held private parent, refuses all existing nodes, applies explicit root:root mode0700 using the held child descriptor and fsyncs child/parent. LinuxNativeModuleOwner uses this helper. A dedicated Linux fixture covers creation under non-root effective GID, receipt permissions, duplicate preservation, symlink/file refusal, invalid names and held-parent pathname substitution. InstalledServerR3 is ACTIVE using corrected agentR71/buildR179, focused fixtureR72/buildR180 and unchanged real serverR70. Neither compilation nor an active test is a pass.

Readonly inventory confirms26 Linux hosts:16 match the current kernel/BTF and10 use seven other kernel releases. Seven Ubuntu hosts have BPF LSM compiled but not active in their boot configuration. Every sensor state directory is ext4; minimum free space13.41GiB. Latest VMware datastore observation found3505.61GiB free with host CPU/memory contention. No production resize, database migration or service changes were made. Microsoft altitude reply remains absent at07:13Z; request absent from local queue at07:22Z does not prove external delivery. Full implementation, finalthree whole-product QA passes, production deployment and all-host verification remain pending.


### InstalledServerR3: ownership regression passed; full integration still incomplete

R71's actual private-directory fixture passed 15 checks under root UID and dedicated GID 59000. The installed module journal was observed as root:root mode 0700. Actual ordinary LinuxWorker, verified HTTPS enrollment and signed policy relay activated the root native source. R3 then failed in its Python wait predicate after 34 harness checks: a newly received work row legitimately had no committed original yet, and the predicate attempted json.loads(None). This is a harness failure, not a complete integration pass. The unchanged products are being rerun as InstalledServerR4 with the predicate waiting through the pending state; all completion/hash/server checks and deadlines remain.

R3 archive f9f4de24653ee4b88d83638823b96e759f9ca3d234a7c06a0035607a7f52a2cd retains the exact first actor UID/PID/path and an explicit ACTOR_ACQUISITION_UNAVAILABLE_INTERRUPTED_BEFORE_NATIVE_START outcome caused by the early test shutdown. It does not claim an executable capture. Actual native drain and normal unload released all five owned programs, eight maps, module/device and owned processes. The VM was off and restored at 2026-10-04T08:13:55.7566134Z. No production or storage migration was performed.


### October 04 kernel API inventory: four older kernels need more than a boot toggle

Read-only checks at 08:21:09Z examined the ten hosts outside the current qualified profile. mysql01, netbox, plex01 and x-wiki (Ubuntu 5.15 variants) lack register_btf_kfunc_id_set in both the running kernel symbol/export inventory and installed headers/Module.symvers; the headers also lack KF_TRUSTED_ARGS, KF_SLEEPABLE and the BTF registration macros used by the current collector. Enabling BPF LSM alone cannot make this module work on those kernels. A supported newer kernel or separately engineered collector is required and must be qualified before rollout.

The three Ubuntu 6.8 hosts expose the required symbol/export and header declarations, but BPF LSM is not active and their exact module/BTF/runtime remains unqualified. The three other Debian kernels expose registration symbols/exports; missing local header files are recorded as unavailable, not inferred as API absence. Full per-host evidence is diagnostics/windows-token-20260930/LINUX-SENSOR-KERNEL-APIS-20261004.json. No production module, kernel or boot configuration was changed.

Upstream reference cross-checks: [Linux v5.15 BTF declarations](https://raw.githubusercontent.com/torvalds/linux/v5.15/include/linux/btf.h) and [Linux v6.8 BTF declarations](https://raw.githubusercontent.com/torvalds/linux/v6.8/include/linux/btf.h). Actual host findings above use the live distribution kernel and headers, not an assumption that all downstream kernels match upstream.


## October 04, 2026 - installed native sensor and actual server integration accepted

InstalledServerR4 PASSED 73 actual harness checks (including the 15-check private-directory regression) and 85 independent archive, source, signature, database, identity and hash checks. It used the published R71/buildR179 LinuxAgent, R72/buildR180 fixture, unchanged R70/buildR178 server, installed root unit, actual cap-free ordinary LinuxWorker and normal CA/hostname-verified HTTPS. The server's actual enrollment and signed policy drove source activation.

All five controlled short-lived actors retained the expected User/Process/PID, stable process/actor/target identities and actor SHA-256, including familiar renamed, replaced, deleted and unprivileged actor cases. Every actor copy and manifest passed independent root/ordinary/server-download hash comparison. Both original and completion event objects survived exact server database comparison. Targets remained metadata-only. Observed completion intervals were 31.81, 17.18, 18.95, 17.21 and 13.71 seconds; this integration harness used a 150-second collection deadline and does not replace the earlier R68 45-second runtime gate.

Five import receipts retired their root export duplicates. Normal installed-service drain preceded successful non-forced module unload; all five owned BPF programs, eight maps, the module/device and owned processes were observed absent. The VM was off and original baseline restored at 2026-10-04T08:28:48.7297518Z. Archive SHA-256:37bb81988b06160c8d23b02537d3921aff0f5613b9b1f2e98b7f4afa81a6f91c. Independent receipt:INDEPENDENT-INSTALLED-SERVER-R4.json. R1/R2/R3 failures remain immutable.

The next gate, InstalledServerTrustR1, is ACTIVE with unchanged accepted packages. It exercises real authenticated manual whitelist publication before any event, actual signed revision delivery, two intended path/hash/user log-only matches, a wrong-hash familiar name, an unapproved-action rule and an unmatched actor. Expected results require all events logged, three alerting actors preserved/uploaded, and independent server history classification. Earlier mock-signed/runtime and HTTP/UI whitelist gates are not substituted for this full installed-service test.

A package-only owned cache snapshot now retains the verified R71/R72/R70/R16 packages before any native activation: snapshot-15017, created08:19:40.8200663Z. Original baseline15012 and earlier cache15016 are retained. This uses available VMware storage to avoid repeated transfers; it is not a database migration or production VM disk resize.

The four incompatible 5.15 hosts are all Ubuntu22.04.5. Read-only package metadata shows an official HWE6.8 stable candidate6.8.0-138.138~22.04.1. Plex also has jammy-proposed enabled and prefers6.8.0-147.147~22.04.1, so any qualification must select a verified stable update/security package explicitly. Repository metadata was not refreshed and no packages or boot settings were changed. See LINUX-KERNEL-UPGRADE-CANDIDATES-20261004.json and [Ubuntu kernel lifecycle](https://ubuntu.com/kernel/lifecycle). These are upgrade candidates, not newly qualified kernels.

Remaining: installed actual whitelist gate, broader Linux kernels/operations and sustained-volume qualification, assigned Windows altitude/signing/release, distinct final three whole-product QA passes and production all-sensor deployment/verification. No claim of full specification completion.


## October 04, 2026 - actual installed manual whitelist integration accepted

InstalledServerTrustR2 passed 101 actual harness assertions and 116 independent source/archive/signature/database/identity/bytes checks. Four host-scoped rules were created through the authenticated console before any file event, with explicit administrator reauthentication and scope approval. The actual server-signed policy reached the installed root companion through the ordinary cap-free LinuxWorker. Correct path/SHA and path/SHA/sensor-scoped UID rules logged without alerts. Wrong SHA under a familiar executable name, an unapproved operation and no matching rule remained alerting. All ten original/completion events reached the real verified-HTTPS server, retained exact User/Process/PID and appeared with the expected authenticated history classification. The three alerting actors had exact executable and manifest downloads; log-only actors retained hashes/events without threshold-triggered preservation. Target files remained metadata-only.

R2 archive b1cf1dd9abe17cbd1633e217cbd90e4deb60e437734777380b4b966559d6df20; accepted packages remained agentR71, fixtureR72, serverR70 and nativeR16. Five durable imports retired export duplicates; actual normal root/ordinary stops, non-forced unload and absence of owned BPF resources/processes were verified. VM15011 was off and baseline-restored at09:00:26.908977Z. Receipt INDEPENDENT-INSTALLED-SERVER-TRUST-R2.json. The first verifier invocation reached the final shutdown check before shutdown.json existed; its failed log is retained. The final invocation used the recorded completed shutdown and passed, without a test rerun or relaxed assertion.

InstalledServerTrustR1 remains FAILED after84 checks: its final log-only original/completion pair was still in the ordinary durable delivery queue when the harness checked the server. The pair retained exact UID997/PID36960/path and was not quarantined. Root-import acknowledgement did not prove server delivery; the harness now explicitly waits for all ten exact server event IDs within180 seconds before ordinary shutdown. No product behavior or expected identity/decision was changed. R1 archive0507e9e62bdbbfcaccddc69ddb40164301dc8d54852b0ff88ff714fbcfc5bdde and negative analysis are retained; its VM was off/restored08:47:59Z.

Release preparation: the same sealed R16 module source was built as a non-root process with qualification fault controls compiled out. Actual nm/modinfo and independent local ELF inspection confirm the four fault-control symbols and all module parameters are absent, BTF is present and vermagic matches6.12.94+deb13-amd64. New module SHAa2d56043fe0f598b002070539880c905ae8394d10d4e5d3048db1af35618b24e; nativeR17 candidate archive7373ba5fc4b8e100e19ac2e6aabe08210d1b8b1d7a70b56104297b70b6c03f75. This candidate has NOT been loaded, admitted by an installed package or runtime-qualified. Existing accepted nativeR16 results are not relabeled as R17 results.

Broader kernel preparation: Guest Operations credentials for sourceVM9019 were validated read-only, without a guest command. A distinct Ubuntu qualification clone was requested at09:01:13Z as saved VMware task50781. Clone specification removes NICs/CDROM/passthrough devices atomically and leaves it powered off, with4CPU/8GiB and a thin owned disk. The production source, existing snapshots and database are retained. Clone completion/preflight is pending; no new kernel is qualified. Storage is available; no production database migration or VM resize is necessary from the measured capacity.

Remaining scope: additional Linux kernels, operations and sustained volume; new release-native runtime qualification; assigned Windows altitude/signing and release; final three whole-product QA passes; production all-sensor deployment and post-deployment verification. Current Linux acceptance remains exact qualified kernel/BTF, local ext4, pre-open requests and actor executable size at most4MiB.


### October 04, 09:07Z - complete actor kfunc preflight correction

The earlier kernel inventory checked registration infrastructure, not every actor-file kfunc. Expanded actual root symbol checks show that all three Ubuntu6.8 hosts and Debian6.1 FreePBX lack bpf_get_task_exe_file, bpf_put_file and bpf_path_d_path. The four Ubuntu5.15 hosts lack those functions and module kfunc registration. Thus HWE6.8 alone is NOT sufficient for the unchanged source, and enabling BPF LSM alone is NOT sufficient on the existing6.8 hosts. The two other Debian6.12 profiles and the current6.12.94 reference expose all four required symbols; this is prerequisite evidence, not native runtime qualification. Raw read-only receipt SENSOR-ACTOR-KFUNCS-20261004T0908Z.jsonl and parsed LINUX-SENSOR-ACTOR-KFUNCS-20261004.json retain11 actual hosts and explicit unavailable states. No production kernel or boot setting changed.

The unchanged6.12 implementation uses the functions defined in [upstream fs/bpf_fs_kfuncs.c](https://raw.githubusercontent.com/torvalds/linux/v6.12/fs/bpf_fs_kfuncs.c). A narrowly scoped module compatibility adapter for6.8 is being investigated against actual exported primitives and verifier rules, with primary-source research requested from Manus asR132. It is not implemented or qualified. Ubuntu cloneVM15019 (BIOS4228fa92-2eb9-1eec-4546-3552a5880a38) completed powered-off/zero-NIC at09:07:24Z; sourceVM9019 remained powered on. Owned clone preflight waits until current Debian release-native gate completes.

NativeR17 is now in the ControlledV2R4 runtime gate on owned DebianVM15011. It retains13 operation cases/12 expected executable copies plus one explicit four-slot-capacity unavailable outcome, and adds an actual loaded-module no-fault-parameters assertion. This is a candidate test, not installed R17 acceptance. No product source pin has yet changed.

## October 04, 2026 - release-native R18 accepted; Ubuntu exact preflight

ControlledV2R5 passed 144 runtime and 216 independent checks against nativeR18. Thirteen actual opens covered executable rename, replacement and deletion, distinct real/effective/filesystem user and group IDs, twelve exact actor copies, and one explicit four-slot-capacity unavailable copy whose event was retained. Actual loaded module parameters were absent, all owned BPF resources drained, and normal non-forced unload succeeded. DebianVM15011 was off/restored09:19:36.769056Z. Archive45f9e2f4aa37486bbf1a74f350434420758f285a15ce3a97e681277162a3f270; nativeR18 archive1675c44f0598f87d49ca35183bab20f0790a1c23587a375fde64045d9de598ee; modulea2d56043fe0f598b002070539880c905ae8394d10d4e5d3048db1af35618b24e. This is the exact6.12.94/local-ext4/pre-open/4MiB bounded gate, not broader Linux support.

ControlledV2R4/nativeR17 remains a negative packaging result. The module loaded and exposed no fault parameters, but the archive had incorrectly made loader-v2 non-executable. The VM unloaded normally and was restored. R18 preserves the original source artifact modes and the same module bytes. No failed receipt was overwritten. The installed service module pin now points to the tested release module; agentR73/build181 compiled and was immutably sealed (raw TAR de859c8ac87ca8a24d2a8ca80a2e7b57e694a58237fe7f4d888612ceba6032f5). InstalledServerTrustR3 is running against agentR73/nativeR18/fixtureR72/serverR70; it is not yet accepted.

Owned UbuntuVM15019 completed actual read-only preflight on6.8.0-134-generic, BTF4a07f657ac332a73329eb46da423c84ec37525330ea5595cf6faa01fbbdcb45c. It is Ubuntu24.04.5 with installed matching Noble headers6.8.0-134.134, no native module, BPF LSM compiled but inactive, lockdown none, and18,444,042,240 bytes free on the state volume. It was off and baseline15020-restored09:22:56.889827Z. Source productionVM9019 remains unchanged.

ManusR132 is complete. Its proposed6.8 adapter uses exported get_task_mm/get_file_rcu/mmput/fput/d_path, module-namespaced acquire/release/path kfuncs, and one LSM kfunc set. Those exports were independently confirmed on the actual Ubuntu guest and in upstream source. Distinct prototypev10 preserves the qualifiedv9 sources and existing reference/association guards. It is not compiled or runtime-qualified yet. Compiler dependencies are being resolved read-only for offline installation in the owned clone; no production packages, boot settings or protections changed. Actual load/verifier-negative tests, race/capacity tests and installed integration remain required.

Storage remains sufficient: D49,859,538,944 bytes and C1,837,437,448,192 bytes free at the latest read. No production database migration or VM disk resize was performed. Remaining gates are broader Linux kernels/operations/volume, release-native installed acceptance, assigned Windows altitude/signing, final three whole-product QA passes, and production all-sensor deployment/verification.

## October 04, 2026 - release package installed whitelist/server acceptance

InstalledServerTrustR3 passed102 actual and118 independent assertions. The exact release-nativeR18 module (fault controls compiled out) and agentR73 were installed with fixtureR72 and serverR70. Four manual rules were created before any file events. All five actors retained exact User/Process/PID/SHA: two approved path/hash or user/path/hash matches remained log-only; wrong SHA under a familiar name, wrong operation and no-rule cases alerted and preserved/uploaded their executables. All ten original/completion event IDs reached the real TLS-verified server; the three alerting executable/manifest pairs downloaded with matching hashes. No target-file default hashing or preservation was introduced.

The independent verifier checks frozen source/publish manifests, exact R18 native manifest/module bytes, RSA-PSS signed policy, native/server database integrity, operation-bound captured bytes even for log-only actors, event linkage, central downloads, and clean service/resource shutdown. VM15011 was off and original baseline-restored09:40:07.700498Z. Archiveb540c276881aa175b34beeeb36afa6ba981111f8c007c51a5d0a0352f31e5cb1; receiptINDEPENDENT-INSTALLED-SERVER-TRUST-R3.json. New package-only cache snapshot15021 preserves fsynced R73/R72/R70/R18 inputs before activation; older snapshots remain retained.

The read-only progress probe reached VMware Tools while the accepted controller was shutting down and timed out. It neither activated code nor changed VM lifecycle. Acceptance uses the completed primary controller receipt and independent archive verification, not that diagnostic probe.

Ubuntu compatibility: exact official dependency resolution returned40 new compiler/development packages, zero upgrades/removals and101,874,174 package bytes. All package SHA-256 values were checked after HTTPS download. Offline package archive3cf061bc4562f51703f1b2fbeba4d4d4b651ff2a9b84e5604c229c0d5e8e18ec; sourcev10 archive2cc75af19580c0e5f962253a7ead37f5b20958bae43e7e4e346fcbc3cb25e0fa includes seven verifier-negative variants and one positive control. Owned Ubuntu build is running after Debian shutdown. It remains unqualified until actual kernel compilation, load, verifier and runtime gates pass. No production package, boot, database or service changes were made.

## October 04, 2026 - actual Ubuntu build and first verifier result

The first offline preparation attempt failed in APT's local fetch phase after verifying all40 package hashes, before native compilation/activation. Failure recordUBUNTU-NATIVE-PREPARE-R1-FAILURE.json and controller log remain retained; VM15019 was off/restored09:44:58Z. The R2 preparation uses dpkg on the complete exact local package set, refuses replacement of an already installed package, verifies all40 final versions and requires a clean dpkg audit. This succeeded. Package-only/build-tools snapshot15022 retains the prepared owned clone, with BPF added to its existing boot LSM list and no native code loaded. Original baseline15020 is retained; no production change occurred.

Ubuntu buildR2 compiled the module, two main BPF objects, eight verifier-control variants, loaders and actors as UID65534, and passed its encoder test. Independent source/hash/ELF validation passed70 checks. Archive8c4d12c44e1837eec6fc59ccde0b99ce57fce06b3bd806e48c6098146196e127; module682e469655f15e204c02abea7122779bec23b542d285d97e2fdd9842db987298; exact Ubuntu6.8.0-134-generic/BTF4a07f657ac332a73329eb46da423c84ec37525330ea5595cf6faa01fbbdcb45c. Compiler warning only distinguished the gcc-13 executable alias; both printed Ubuntu13.3.0-6ubuntu2~24.04.1. No fault controls or module parameters were present. VM was off/restored09:52:27Z. Compilation does not establish runtime support.

Actual verifierR1 loaded that module successfully and confirmed all three compatibility functions in loaded module BTF. The positive BPF control then FAILED with EINVAL: 'R1 must have zero offset when passed to release func or trusted arg to kfunc' when passing actor->f_path (offset152). This disproves the initial nested-path assumption for this exact kernel. The five completed harness checks are not a pass for the verifier gate. No negative variant or actor capture is claimed. No BPF resources remained; module reference count was0, normal unload returned0, and VM was off/restored09:56:00Z. Negative archived2982f867c70ea1408a18ab2cbc72cd974c4fdd638f87ad3f5482459eddf540d is preserved.

Sourcev11 corrects the API boundary to sq_bpf_file_d_path(struct file *file,...), retaining KF_TRUSTED_ARGS. BPF passes the whole referenced actor or trusted hook target at offset0; the module synchronously resolves &file->f_path internally. No derived path pointer escapes, no check is disabled, and F1/F2 ownership and exec-association guards are unchanged. Source archivef87dc87226b24736919e6904f4e955fb43a0daba65910d68adc6652242d79604. Cached buildR3 is running; verifierR2 is prepared but not started. ManusR133 requests a focused correction/review using the actual rejection. No6.8 profile is admitted by the managed product yet.


## October 04, 2026 - corrected Ubuntu verifier acceptance

Corrected sourcev11 buildR3 passed all25 build steps and70 independent source/ELF checks. Module SHA25657a1bb56fefe2bf797762633abf0d12867b62cdaa8d7ca18e2874062024c83d3, exact Ubuntu6.8.0-134-generic and observed BTF4a07f657ac332a73329eb46da423c84ec37525330ea5595cf6faa01fbbdcb45c. ManusR133 withdrew its earlier nested-path assumption and confirmed passing the whole trusted file reference with zero offset.

VerifierR2 admitted the positive control, rejected all seven unsafe variants and loaded the complete five-program object, but its immediate-cleanup assertion failed during deferred kernel destruction. This was a harness assumption, not evidence of a product defect. Its failed gate remains retained. A separate bounded observation confirmed destruction and normal unload before shutdown; no forced unload was used.

Corrected verifierR3 passed44 actual checks; independent retained-evidence inspection passed54. All seven variants failed for their intended verifier reasons, the complete object loaded, bounded resource drain reached zero and normal unload succeeded. Archive904239d6aad0d3e1223594c226f6aeae3e55ef35ef2cc5cbfbc94361127f4160. Owned VM15019 was off and original baseline restored10:11:47.298337Z. This proves exact-kernel loading/verifier behavior, not file-access runtime or installed product support.

Flat candidate nativeR19 preserves the accepted build bytes and executable modes. Archive66704fb42f0a14ace7af8aae00d9c240b867f6803f11eec382612f22bca8c851. Actual controlled runtime benchmarking is now running on the owned Ubuntu clone; fixture C sources are compiled against its actual userspace as UID65534. Product profile admission, installed server acceptance, broader kernel coverage and production rollout remain pending.


## October 04, 2026 - actual Ubuntu actor runtime acceptance

Controlled native Ubuntu runtimeR1 passed144 actual and227 independent checks on exact6.8.0-134-generic/BTF4a07f657ac332a73329eb46da423c84ec37525330ea5595cf6faa01fbbdcb45c. All13 controlled pre-open observations matched independent PID/TID, six security IDs, durable process identity and target identity. Twelve actor executable copies matched expected SHA256 through actor rename, deletion, same-path replacement and distinct credentials. Four-slot exhaustion retained the fifth event with explicit unavailable copy; capacity recovered after exact lease release. No target files were hashed or copied.

Runtime archive2cbba6f9d787389647c2590aa12814b962969d1d226bbda224f8bad0ab29de90. Owned VM15019 was off and original baseline restored2026-10-04T11:24:09.6158346Z; module unload and all owned resource closure were normal. These bounded pre-open tests do not establish final denied outcomes or coverage of every operation.

The installed preparation and module owner now select an exact qualified kernel/BTF/module tuple, retaining DebianR18 and adding UbuntuR19. Manifest schema1 and existing bounds remain unchanged. Definition/module substitution tests passed45; swapped BTF or module bytes, unknown hash and adjacent untested kernel were refused. AgentR74/build182 is published and source-frozen. The real installed root/ordinary/server/manual-whitelist gate on Ubuntu is running; production support and rollout are not yet claimed.


## October 04, 2026 - installed Ubuntu server and trust acceptance

AgentR74/build182 with nativeR19 passed102 actual installed checks and118 independent checks on exact Ubuntu6.8.0-134-generic/BTF4a07f657ac332a73329eb46da423c84ec37525330ea5595cf6faa01fbbdcb45c. Real management-server enrollment, strict TLS, RSA-PSS policy signature and ordinary cap-free LinuxWorker relay reached the installed root companion. Four authenticated manual whitelist rules were created before any event. Two exact actor path/hash or UID/path/hash/open matches logged only; wrong executable SHA under a familiar name, wrong allowed action and no matching rule alerted and preserved their actors.

All ten original/completion events reached the server with exact controlled User, Process and PID. Three binary/manifest pairs uploaded and downloaded with matching SHA256. Independent verification inspected immutable source/publish/native manifests, actual signed policy, native/server DB contents, protected private directories, audit chains and five retired durable imports. No default target-file hash/copy was introduced.

Archivefcad68f00642381d90bd75158827e4c438ede183c0a0c86d19b146e674be18d6; owned UbuntuVM15019 was off and baseline-restored2026-10-04T11:35:29.3046251Z. All owned services/processes/BPF resources and the module closed normally. Installed pre-open support is qualified for this exact tuple only, not every Ubuntu6.8 kernel or every operation. Debian regression with the same R74 package is now running. Broader operation/denial/larger-actor work, Microsoft altitude/signing, final three product-wide QA passes and all-host rollout remain pending.


## October 04, 2026 - R74 Debian regression and next atomic prototype

The same source-frozen agentR74/build182 passed the existing exact Debian6.12.94/nativeR18 installed gate:102 actual and118 independent checks. Archive656c42c7fe9a52a6cd49e933d974e85a4ea260f821bac34817225f1e80df3c8d; VM15011 off and baseline-restored2026-10-04T11:48:53.7952649Z. Real manual-rule creation, strict TLS and RSA-PSS policy relay, five correct User/Process/PID accesses, all ten event deliveries, two log-only decisions and three alerting central actor/manifest downloads remained correct. Both current qualified Debian and Ubuntu tuples have now passed installed acceptance with R74; broader kernels and operations remain pending.

ManusR134 returned a detailed operation-hook/outcome/streaming design, report SHA2566d2f2a0820f42d32eef0793f56a4a6dfd057ade74347c9935f82a20ffb9cd749. Its design leaves first-use non-sleepable and DAC-denied actor capture unavailable. R135 challenges that limit and requests an earlier tracing provider with bounded atomic F2 reservation, while distinguishing current F1 flags from sleepable reserve/finalize. Primary kernel source independently confirms DAC can exit before the LSM inode-permission hook and that mmput can sleep.

Distinct sourcev12 prototype uses mmput_async, IRQ-state-preserving bounded entry spinlocks, release-only atomic reserve/finalize entry points, and separate tracing registration. Existing sleepable entry-point flags and accepted v9/v11 artifacts remain retained. All user copies, actual work drainage and expensive copy remain outside entry locks. It is candidate-only, not loaded or deployed; compilation and independent locking/API review are pending. Source archive7b57a0bf0c0de1d8a614adba163e2f05c9e328112bc4296bbf5de7eed81b1b17 includes two positive and five negative atomic verifier controls.

Microsoft altitude sent-copy verification succeeded again11:31:00Z; no assignment reply arrived. Full denied/all-operation/larger-actor qualification, remaining kernel profiles, final three product-wide QA passes and all-host deployment proof remain pending.


## October 04, 2026 - Atomic capture verifier R4

Sourcev12 was compilation-only and never loaded: primary-source and ManusR135 review identified that LSM and tracing share one kfunc registration namespace. Distinct sourcev13 corrected this with one combined set and a caller/type filter. Its Ubuntu build passed32 compiler steps and78 independent checks.

The actual exact-kernel load-only gate then passed77 actual and89 independent checks: eight legacy probes, seven atomic probes including positive non-sleepable LSM and fentry cases, and the full existing five-program provenance object. Unsafe reference, NULL, caller-type and sleepability variants were rejected for their intended reasons. Archive2af70a0b42f07536dc06db5c61a31439c230b7842c04421aca8441a7a5ce212b, build71759db1cb107654c9207831ea6590f0825674b6c3d2f1ad82fb65e423f978a1. All owned BPF resources and module references drained; normal rmmod succeeded. VM15019 was off and baseline-restored2026-10-04T12:08:30.4849401Z. No atomic program was attached.

ManusR136 report SHA256ab7d3f579d3a6d6741c8629d254174f892da54b07627256ecdb1a62647a3412f confirms security_file_permission as the actual inherited-FD tracing symbol, withdraws unnecessary kptr destructor registration for stack-only file references, and requires generation-bound atomic ownership, durable raw-before-START_COPY, and no slot reuse before actual drainage. These are implementation requirements, not runtime acceptance.

Next distinct sourcev14 must add a negotiated atomic state/status ABI, exact source-event START_COPY authorization, asynchronous abort and drainage, then full provenance/tracing verifier and actual operation/race tests. Sourcev13 still queues the old copy path and is not admitted for atomic attachment or production. Denied access, inherited first-use, full operation coverage, larger actor copies, other kernel profiles, Microsoft assigned altitude, final three whole-product QA passes and all-host deployment remain pending.


## October 04, 2026 - Reviewed atomic START component

This is authorized malware-protection benchmarking. The prior immediate resource-cleanup failure was a harness assumption; actual bounded deferred cleanup was independently accepted. Sourcev13 remains load-only qualified77 actual/89 independent checks and is not attached or deployed.

Distinct sourcev14 added a separate112-byte exact key,136-byte request and192-byte atomic status ABI. R1 fixture22/13 accepted the ABI/comparison component only. Sourcev15 added a START helper; R2 component22 ABI/28 START/18 independent checks passed but Manus review required alignment with the existing nonzero exec-identity profile and an independently pinned native active-provider epoch. Those earlier candidates remain retained and unadmitted.

Distinct sourcev16/R3 applies those constraints. On exact Ubuntu x86_64, unprivileged UID65534 compilation/runtime passed23 ABI and31 START authorization checks, plus18 independent immutable archive/source/output/ELF checks. Tests cover malformed version/size, zero exec identity, stale process/task/executable/target/operation keys, wrong or absent active epoch, missing receipt or ownership, unknown state, expired first START, exact retries and conflicting receipts. Archive3cad7c284b7fcad3401ca3495240171857b117752737b5b2edaec9d0df599bcb; source5327afcc1b68ded3220d0028abddaf3820813be033ba5fe22680c2258c402b02; VM15019 off and original baseline-restored2026-10-04T12:30:44.1579142Z.

ManusR137 report87152b9c947704e45d8729ae3128edc3f06524e366aa362594974cbc84e6fd41 also requires dispatch under the slot lock to close START/STOP races, native reaper ownership of no-START cleanup, and module-reference retention through completed-byte DROP. Actual root journal, native worker, actor lease and device abstractions were inspected and mapped in the implementation note. The existing durable raw pin/authorization/start journal will be reused.

These are isolated component results, not a native worker or denied-operation pass. The source folders still contain the v13 old atomic aliases and must not be attached. Shared bounded native slot integration, direct trusted target aliases, raw-before-copy root wiring, provider-epoch lifetime admission, actual drainage/race/recursion gates, full provenance-plus-tracing object, denied/inherited operations, broader kernels, final three whole-product QA passes and all-host deployment remain pending. Existing installed R74 behavior and production hosts were not changed by this prototype work.


## October 04, 2026 - Native atomic capture implementation and target-boundary correction

Implemented candidate native reservation/F2 ownership, exclusive source epoch registration, finalization without copy, durable-receipt START dispatch, private copy-worker identity, real reader/reference cleanup and completed-byte DROP in the existing four slots. This has not attached to operation hooks or entered the installed R74 package.

Sourcev17 compile gate passed47 steps/98 independent checks, but its first direct inode target positive failed the actual Ubuntu6.8 verifier: R2 must be referenced or trusted. The file-target positive was not reached. Failed receipts remain retained. Sourcev18 uses checked scalar target observations while keeping actor KF_TRUSTED_ARGS; compile47/98 passed, but ManusR138 required a tighter atomic helper filter. Sourcev19 failed compilation because assembler-defined BTF_ID_LIST arrays cannot use ARRAY_SIZE.

Sourcev20 corrects filtering through explicit named function membership. BuildR9 passed50 steps/102 independent archive/source/ELF checks. Archive759bdae0c1476166dfeea5fa967d20c70ba307b7a2ea48bc0ea14efabf3d24b5; module316823adeab775c8e66dfd6e156ae3ab938ee246ff1898a7d57451857c270651; owned UbuntuVM15019 off/original-baseline-restored2026-10-04T17:08:27.9487911Z. These are compilation results, not native lifecycle or denied-touch qualification.

Sourcev21 prepares a separately versioned paired inode_permission/security_file_permission object with the existing exec/shared-mm provenance, process/task lifetime, six UID/GID identities, scalar target/watch ordinal, nonces, collection errors and source-health counters. Compilation and ManusR139 review are in progress. A permission return is not final syscall/I/O success. No paths, command lines or successful hashes are invented when unavailable.

ManusR138 report82913284d5ac8bd416c044976a3178b6352959a648fa4d42bcd085ca65650cef confirms the target-boundary correction and atomic-finalizer filter restriction. Fresh altitude mailbox check2026-10-04T17:08:17Z verified the existing sent copy, no assignment reply. No email resend or production protection change occurred.

Pending: complete actual verifier gate and pairing corrections; real reservation/START/copy/DROP/expiry/STOP, blocked-reader, raw-loss and source-health tests; denied and inherited/transferred descriptor operations; durable root journal/device integration; server evidence hash readback; broader kernel profiles; Windows production altitude/signing; final three whole-product QA passes and all-sensor rollout. Installed R74/build182 DebianR18/UbuntuR19 remains the latest accepted installed package. See diagnostics/windows-token-20260930/ATOMIC-SCALAR-TARGET-STATUS.md for exact candidate boundaries.


## October 04, 2026 - Full atomic permission object verifier accepted

ManusR139 found lost-ENTRY RESULT emission and zero-correlation pairing collisions in sourcev21. Distinct sourcev22 adds successful ENTRY submission gating; a separately versioned unpairable diagnostic for correlation-allocation failures; invalid UID/GID masks; and outermost task-storage cleanup. Collected diagnostic facts remain retained but cannot authorize copy or whitelist suppression. ManusR140 reportd97c80695ff8b95c12e27ddabdb93d23039a75dd947b579c7a24989d5dac1c2a confirms those corrections.

Sourcev22 BuildR11 passed51 compile/fixture steps and105 independent source/archive/ELF checks; archive6e63c891f4b715886474a111cf8b832052e0ff54d8a125bad55c9f1301d2922c; modulef147c2b2f5b1ce4fecfce136a42cecc96e780097793dad492e29d36b2b916967. The first verifierR10 correctly rejected the tracing call to the old sleepable API by the explicit function filter, but its harness expected the sleepability message. That failed receipt is retained; independent diagnostic review verifies the real rejection and separate legacy LSM sleepability rejection.

VerifierR11 corrected those exact tracing-filter expectations without changing the source or build. All30 cases and146 actual gate checks passed. The complete new object had seven actual loaded program descriptors: three provenance programs and four paired inode/security-file permission programs. Unsafe pointer/reference/lock cases and forbidden atomic LSM/untargeted-capture imports rejected. The existing complete legacy object also loaded. Independent evidence review passed160 checks. Verifier archive2c3c0a4c328d2b977afe0514f9f51d8ee8e217388edd0948e7d9bc9daa861b4b; build6e63c891f4b715886474a111cf8b832052e0ff54d8a125bad55c9f1301d2922c; owned UbuntuVM15019 powered off and original baseline restored2026-10-04T17:29:58.4620311Z. No program attached during this gate.

Remaining before live attachment/admission: exact six-counter source-health map proof and decoder; stable durable diagnostic delivery identity; entry/result pairing only after root raw commit; native START receipt/device integration; ring/result loss, correlation failure, storage cleanup and malformed-frame tests; actual denied/inherited touch identity and actor-byte hash verification; reservation/START/STOP/expiry/DROP, blocked-reader, capacity and recursion qualification. The theoretical depth-overflow cleanup guard remains a recorded hardening item. Broader kernels, Windows production altitude/signing, final three whole-product QA passes and all-sensor deployment remain unfinished. Accepted installed package remains R74/build182 with DebianR18/UbuntuR19.

## 2026-10-04 atomic permission integration candidate

Implemented versioned schema-7 permission observations, exact lifetime/actor/target/nonce START keys, durable authorization in the existing SQLite journal, separate ENTRY/RESULT identities and strict durable pairing, read-only native metadata compatibility, six-counter source admission, and an explicit server capability/receipt.

Verification: 99 managed checks (including actual SQLite/private executable bytes with a simulated device), 8 isolated real server API/spool/history checks, 34 prior control-v2 and 410 prior map checks passed. Ubuntu native source v24 passed 52 build steps and 107 independent source/ELF checks. Compilation and simulated device tests are not installed sensor acceptance.

Pending: actual native attachment/live operation gate is running in the owned zero-NIC Ubuntu clone; integrated installed runtime and evidence upload acceptance, Debian qualification, other supported kernels, UI acceptance, full canary regression and all-sensor rollout. Windows production altitude/signing remains separate and has not been declared complete. No production deployment performed in this candidate.

### 2026-10-04: atomic permission integration attachment correction

- Actual Ubuntu probe R13 failed before actors ran: op_health counter 2 (nested operation) reached 12 after fentry hooks were attached before corresponding fexit hooks. All links detached, module reference count returned to zero, and normal unload succeeded. VM baseline restored; this is a failed qualification, not a deployment pass.
- Frozen native candidate v25 attaches provenance first, exit hooks next, entry hooks last; teardown reverses the actual attachment order. Control-v3 admission rejects entry-before-exit acknowledgments.
- Managed integration: 100 checks passed, including rejection of unsafe hook order. Legacy control-v2 parser 34 and map admission 410 checks passed.
- Real isolated server API/SQLite/spool: 10 checks passed using synthetic native records. History filter and presentation distinguish Permission Check Requested / Permission Check Returned, never imply a completed read from a permission hook.
- Native v25 Ubuntu build R16: all 52 compilation/encoder steps passed. Live native and actual managed composition qualification remain pending. No production deployment in this candidate phase.
### 2026-10-04: live atomic permission integration findings

- v25 R15 still failed startup health (nested-call counter 1); attachment order alone did not resolve it. No counters were reset and no nonzero baseline was admitted.
- v26 R16 standalone native capture PASSED: six real ENTRY/RESULT records across successful read and denied open; three exact actor executable copies; event-time UID/EUID/FSUID/GID/EGID/FSGID and PID/TID matched independent actor output; denied permission result -13; normal seven-link detach and zero health. This is a scoped native pass only.
- R16 full managed composition FAILED: first executable capture/preservation succeeded, but a subsequent lease expired before START under cold managed intake. The source faulted and closed normally, retaining four original and four completion records. No deployment acceptance follows.
- Frozen v27 increases only atomic retention deadline from two to ten seconds; legacy deadline, four slots and four-MiB actor bound are preserved. Ubuntu build R18 passed 52 steps and 107 independent artifact checks; actual delayed-START/cold managed gate is pending.
- UI action filters and structured detail panels distinguish permission stage, nonce, access mask, target identity and explicit metadata errors. Build/syntax passed; authenticated browser gate remains pending actual accepted runtime corpus.
- Manus R141 review retained (SHA256 97920e9027e39f537af23c427f937e59e55543e49b614f20e6385e20422e3651). Its hypothesis that health[2] measured unmatched exits was challenged with source code and actual counter evidence; do not implement a health reset/baseline workaround. Actor path rendering remains an optional, unimplemented tracing candidate requiring exact verifier/runtime/latency tests, with explicit unavailable/deferred fallback.

### 2026-10-04: Ubuntu sensor-to-server evidence test passed

- Native source v27 / Ubuntu build R18 passed the live R18 test: 206 checks. It captured successful reads and denied opens with the correct PID/TID and UID/EUID/FSUID/GID/EGID/FSGID, preserved the original actor executable bytes, and closed all seven hooks and the kernel module normally. The isolated VMware guest was powered off and restored to its baseline.
- The real managed sensor runtime retained six original permission observations and six linked forensic completion events. Three ENTRY events produced protected executable copies with verified SHA-256 hashes; RESULT events did not grant separate copy permission. Denied access retained Linux error -13 (EACCES). Permission-hook return values are not final syscall results.
- Independent inspection of the downloaded archive passed 115 checks, including actual STATUS192 keys and ten-second deadlines, exact raw-to-SQLite linkage, task credentials, actor and manifest hashes, distinct short-lived process identities, and normal resource release. Archive SHA-256: 7be8b51382f45349d171f4cd1bb6a0e5e40a91968a93b8f2446f36065296362a. Receipt: diagnostics/windows-token-20260930/INDEPENDENT-UBUNTU-RUNTIME-R18.json.
- Actual authenticated HTTP/server database/history/SIEM and executable upload/download tests passed 65 checks using those captured records. Three actor executables and manifests reached the isolated server; downloaded files matched the sensor hashes. Authenticated Chromium WebUI checks passed 30 assertions for action filters, accessing user/PID and permission details. Final results: D:/Codex/RansomFree/windows-token-20260930/atomic-native-server-6401e906b82e47a9ba3f680ee3e58988/RESULTS.json and ui/RESULTS.json.
- A WebUI accessibility defect was corrected: filter controls now have explicit accessible names. New permission details use ASCII separators to avoid replacement characters in the existing mixed-encoding asset.
- Installer manifest version 2 now selects control version 3/native schema 7 explicitly, with exact tested Ubuntu kernel/BTF/module/loader/BPF-object hashes. Version 1 preserves existing Debian/Ubuntu profiles. The module owner uses the manifest control version; installer requests must select the version explicitly. Definition tests passed 56 checks including legacy compatibility and refusal of substituted binaries/protocols; installed activation has NOT been tested for this profile. Builds passed with zero warnings/errors; 100 managed atomic protocol/journal checks and legacy launch 27 / control-v2 34 checks passed.
- R17 failed because its test harness read the wrong STATUS192 deadline field; R18 corrected that index and inspected retained actual replies. No native success was inferred from the R17 failure.

Remaining work: actor executable path and command line in the new permission collector; installed companion/service acceptance; integration of validated Linux hash whitelist decisions for this source; durable ENTRY/RESULT correlation exposed beyond the local journal; qualification on Debian and other supported kernels; all-sensor deployment and canary regression; final three product QA passes. Windows production minifilter signing and assigned altitude remain pending. No production deployment occurred in this test. These results do not establish completion of the full implementation specification.


## 2026-10-04 WebUI recovery verification

- Functional/regression: exact packaged server DLLs passed 287 existing event-history checks. The 100,000-row observed-time scale run passed 291 total checks, including page boundaries and both sort directions (first+second 500-row pages: 83 ms ascending, 76 ms descending on this development host).
- Edge cases: seven real isolated-server browser checks retained authenticated workspace and loaded alerts after dashboard HTTP 500, HTTP 403 and connection failure; clearing the actual session cookie correctly required sign-in.
- UI/runtime: exact packaged app passed 52 checks across desktop, tablet and phone layouts, including Sensors name, eight columns, OS logos, status colors, User/Process/PID display and all navigation screens. These use synthetic records; they do not establish new endpoint capture evidence.
- Production: deployment receipt WEBUI-DEPLOY-20261005-R1.json is PASS. Thirty served asset hashes matched the release manifest; 33 endpoint IDs and event snapshot 39449 were preserved. Callback receiver PID 1396 unchanged. Default history API returned HTTP 200 with 50 items in 720 ms; live health and endpoint inventory also returned HTTP 200. No authentication credential or signing-policy change.
- Package: D:/Codex/RansomFree/webui-history-20261005/RansomFree.Server.0.6.16-dev.webui-r2.zip, SHA-256 54E3E7F675BFAE1E3B575F9D9FE25BE8296D15DC81F75A8D4B56EBDE5EBFCEF8. Exact packaged DLL regression tests and packaged WebUI/session tests passed. Earlier R1 package had an assembly-version regression in the test harness and was not deployed; R2 preserves Contracts assembly version 1.0.0.0.
- Evidence: D:/Codex/RansomFree/webui-history-20261005/acceptance-summary.json, session-tests.json, ui-qa-r2/RESULTS.json, packaged-fixture-results-r2.log, scale-results.log; controller receipts under diagnostics/windows-token-20260930. Production backup: C:/ProgramData/RansomFree/Server/backups/central-evidence-20261005T004233Z.
- Limitations: a signed-in production phone session was not inspected, so the client's historical logout cause is not proven exclusive to the fixed startup error path. No full product-wide three-pass acceptance, new driver rollout or universal endpoint attribution claim is made by these tests.


## 2026-10-04 fresh Windows temporary-number proof - R52

- Windows 10 build 19045.6456, the same build as the physical workstation, passed 21 actual controlled cases with the unchanged R49 driver. Six denied cases and process-owner/impersonated-thread changes were included; 20 cases exited without an artificial post-operation pause.
- Independent checks passed: 74 raw observations and 74 forensic completions, 21 snapshots, 44 hash-verified actor artifact/manifest pairs, 1,074 token checks, 26 CREATE authorization comparisons and two earlier changed-context CREATE checks. Current 0.6.16-dev server package passed 923 isolated API/spool/history/SIEM/binary upload-download checks against those native captures.
- The existing test VM registration was independently read as temporary load-order number 385200.923 before R50; the sealed R52 runner changes only the driver image path and restores it. R52 proves the same registered driver loaded and captured the cases; it is not a permanent Microsoft number assignment or a production driver rollout.
- R50 failed its first actor's unchanged 15-second exit deadline. VMware counters during that test showed approximately 51-54 percent CPU ready time across two virtual CPUs. R51 failed before guest dispatch on a VMware controller connection error. Both failures remain retained. R52 used a temporary 2,000 MHz reservation, the same driver and unchanged deadlines; it passed, unloaded the driver, restored the guest and powered off. The reservation was restored to zero.
- Receipt: diagnostics/windows-token-20260930/INTAKE-DIAGNOSTIC-WIN10-R52.json. Native archive SHA-256 46D61669EA96141912D37338E3D97CEB89531F8519E6156134C35691CDA02D5C. Independent receipts: D:/Codex/RansomFree/windows-token-20260930/vmware-WIN10-intake-diagnostic-r52-20261005T004817Z/INDEPENDENT-INTAKE.json and INDEPENDENT-TOKEN-DETAIL.json. Server receipt: D:/Codex/RansomFree/windows-token-20260930/integration-5686b68c49b04373a19cd4cf584b5a20/RESULTS.json.
- Limitations: 43 background read failures were reported explicitly, not turned into successful captures. This does not establish universal OS coverage. The newly built unsigned R50 INF/package was not installed; this run reused the existing locally test-signed R49 driver and did not perform signing work. Four-build R49 qualification remains historical evidence for identical driver bytes.

Post-native-cleanup production check WEBUI-HEALTH-20261005-R7.json: all three requests HTTP 200; health 1,829 ms, inventory 484 ms with 33 records, 50-row history 1,849 ms. Host CPU contention still causes timing variation; the 720 ms sample is not a sustained latency guarantee.


## October 4 EDT / October 5 UTC production acceptance

# Production deployment and retest - October 4 EDT / October 5 UTC

- Server 0.6.17-dev deployed at https://cptnycdc01.cptnyc.com:7443/ with combined OS, IP, hostname, date/time and notification filters.
- All 30 active production sensors report monitoring active: four Windows 0.6.13-dev and 26 Linux 0.9.17-linux-dev. No sensor binary change was required for the server filters. Periodic kernel audit health configuration version 1 installed and verified on all 26 Linux sensors.
- 93 controlled honeypot reads: server matched independently recorded User, Process, PID, target and test time. Linux parent PID and numeric credentials also checked. Existing target contents unchanged.
- Disabled kernel auditing repaired on FreePBX01 and netbox, with owned persistence rule and existing Sequester rule reconciliation. Six fresh reads verified at server after repair.
- 420 canary tests: 14 types x 30 hosts; rendered file bindings and HTTPS protocol verified against fresh server token/type/host/source-IP/time receipts.
- Final health check: 26/26 timers enabled/active, kernel auditing enabled, successful rule state, collector and sensor running. Maximum kernel status age 29.8 seconds.
- Default 50-event live query: 601 ms. Combined OS/IP/hostname/time/type sample: 4,885 ms; filtered query latency is higher than the default view.
- Server regression: 312 history fixture, 25 filter DOM, 52 packaged UI, 14 packaged HTTP/UI checks passed. Kernel health fixture: 17 checks passed.

## Limits and retained failures

Initial Windows callback requests timed out; all 56 passed on retry, maximum duration approximately four seconds. Initial timeout cause remains unproven. Original failures retained. Canary acceptance covers bindings and protocol, not opening every type in its associated application. Local honeypot acceptance this run covers reads, not a fresh write/rename/delete/denied-open matrix. Windows production still uses Security Audit; the test minifilter was not deployed, so accessing-thread impersonation tokens remain outside this production acceptance. SQL Server migration added but not executed; production uses SQLite. The periodic Linux checker depends on its timer running; the existing collector does not independently detect timer stoppage. Historical dropped/rejected counters retained.

## Evidence

- Controller records: diagnostics/windows-token-20260930/ACTOR-SERVER-VERIFICATION-20261005-R2.json, FINAL-FILTERS-SENSORS-20261005-R2.json, LINUX-KERNEL-HEALTH-FINAL-20261005.json, DEPLOY-ALERT-FILTERS-20261005-R1.json.
- D artifact directory: D:/Codex/RansomFree/filters-20261005; CALLBACK-VERIFICATION.json records all 420 matches.
- Server archive SHA-256: F713583FAF4E4527F1667C15F6D1A3ED9BD74205C8747CB6FD9A2759B8E66A46.
- Production backup: C:/ProgramData/RansomFree/Server/backups/central-evidence-20261005T013546Z.
- First final-sensor verification failed PowerShell array enumeration in the test harness; corrected R2 passed. This acceptance does not establish completion of the entire native forensic specification or full product QA.


## October 5 Windows reliability diagnosis

# Windows callback and attribution diagnosis - October 5, 2026

## Confirmed Windows attribution cause

All four production hosts have no Sequester driver service/filter and no windows-kernel.enabled marker. The production integration is disabled. The source remains Windows Security Audit 4656/4663. It reports event subject SID/account/logon plus process name/PID; it does not supply the complete accessing-thread token snapshot. Looking up a process token later cannot recover an earlier impersonation token. Existing core-field read acceptance did not establish full accessing-thread token capture.

Production OS builds: domain controller Server 2012 R2 build 9600; NVR and storage Server 2019 build 17763; desktop Windows 10 build 19045. Qualified R49 kernel tests were isolated: 84 cases, 24 denied cases across recorded builds. This is an unfinished installation/integration rollout, not proof of production token capture. Source integration gate: src/seQuester.Agent/Program.cs windows-kernel.enabled; kernel capture: src/seQuester.WindowsKernel/Driver.c pre-operation request thread and CREATE authorization snapshots.

## Callback delay evidence

Original client timeouts: 28. Of these, 15 already had receiver records before the successful retry. A client response timeout must remain a transport failure even if delayed server detection succeeded. Other timed-out requests had no recorded callback before retry; delivery of those original requests is not established.

The historical ESXi host CPU usage was 100% throughout the available five-minute samples from 21:45 through 22:10 EDT. In the 21:50-21:55 failure interval, CPTNYCDC01 CPU Ready was 330,606 ms summed across four vCPUs over 300 seconds: approximately 27.55% average wait per vCPU. This is direct evidence of CPU scheduling contention at the time. It is a strong contributor to endpoint/receiver delays, not proof of the sole cause of every original timeout. No original per-request DNS/TCP/TLS/SQLite trace exists.

The management VM currently has a shared CPU limit of 2393 MHz across four vCPUs and a 1,000 MHz reservation. This is current configuration evidence; the query does not establish when the CPU limit was set. CPU limit removal and reducing/moving workloads on the saturated host are corrective candidates. No VM CPU allocation, services, boot settings or security protections were changed by this diagnostic run.

## Fresh measurements

- DNS and direct TCP succeeded on all four Windows hosts. Receiver-health HTTP requests initially took 3.6-6.6 seconds in the generic PowerShell probe, then milliseconds; this cold-client overhead is smaller than the original three-minute interval.
- 24 instrumented requests passed, using a fresh TLS connection each time and the same trusted certificate pin/hostname/validity checks. Controlled callback and non-persisting health requests were compared. Certificate validation callback took milliseconds.
- Four new controlled callback receipts independently matched host and source IP. Repeat same-token/source requests inside 60 seconds intentionally deduplicate; absence of a second row is expected.
- Receiver certificate is self-signed with no CRL or authority-information-access download URLs. Certificate URL retrieval is not supported as the cause by this evidence.
- DNS-Client and CAPI2 operational logs were disabled during the original failure. Historical System warnings did not identify a DNS/TLS cause. Server syslog IOException warnings in that interval are retained; they are a separate observation, not proof of a callback cause.
- New stage probe records request creation, certificate-validation entry/exit, response headers, body completion and failure timing; it aborts failed requests and avoids stale stage values. Tests do not change application behavior.

## Evidence and sources

RELIABILITY-DIAGNOSIS.json contains raw correlated request and receiver results. HISTORICAL-VM-PERFORMANCE-R4.json retains historical CPU samples and current configuration. Earlier R2/R3 artifacts retained; R4 corrects physical/logical core labels and explicitly separates current allocation from historical utilization. Original failures remain in controller diagnostics.

API definitions verified against Microsoft: https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4663 ; https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/fltkernel/ns-fltkernel-_flt_callback_data ; https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-psreferenceimpersonationtoken . CPU Ready conversion: https://knowledge.broadcom.com/external/article?legacyId=2002181 .

## 2026-10-05 Windows alert filter acceptance - 0.6.20-dev

- Functional and regression: EventHistoryFixture 320 checks PASS; DOM 27 checks PASS. Covered Windows Alert mapping, legacy normal alias, host wildcard escaping, pagination/cursor behavior and existing history cases.
- Packaged UI/runtime: whole UI 52 checks PASS; HTTP/UI 19 checks PASS. Local previews used isolated data and were stopped by verified executable path and process creation time.
- Production: exact package SHA256 AB42F167535EF084A56FF6EE39E9667D371D74781256DF222DD3CFB1F2D9066D; 30 served assets matched; health and Windows Alert filter gates PASS. Live count 2538 before fresh post-deployment tests.
- Fresh Windows read acceptance: 3 controlled reads per host on all 4 Windows sensors, 12/12 PASS. Independently recorded process identity matched server User/Process/PID; OS windows and notification alert verified. Raw severity normal preserved. Receipt: diagnostics/windows-token-20260930/WINDOWS-POST0620-FILTERED-ACTORS-20261005.json.
- Performance: actual production backup query improved from about 370 ms to 9 ms locally using the notification expression index. This is a local measurement; no blanket production latency claim. Plex action-sort timeout remains unresolved and excluded from this Windows filter acceptance gate explicitly.
- Storage recovery/migration receipts and immutable package/test logs retained under D:/Codex/RansomFree/filters-20261005. No existing evidence discarded, VM CPU allocation unchanged, and callback receiver unchanged.
- This acceptance covers the Windows filter repair and controlled reads; full product-wide three-pass qualification and Windows accessing-thread token rollout remain pending.
### Windows thread-token integration - 2026-10-05, in progress

Local staged actor/HTTP fixture: PASS 348 checks, log minifilter-context-v5-http-fixture-r6.log. Covers distinct thread owner, attached requestor and impersonated principal; unavailable token states; exact raw reply pairing; durable duplicate refusal; version-5 receipt requirements; typed server persistence.

Latest native R56 package qualification, production activation, four-host full operation and denied-open validation: PENDING. Intermediate R55 Windows 10 native matrix passed 21 cases, including six denied opens; it does not qualify the changed final candidate. First R56 run failed before test dispatch because VMware Tools was unavailable during overlapping shutdown. Failure retained; same bytes being tested in R57.

Storage test-signing boot option is configured, not yet effective through a reboot. No production minifilter is claimed loaded. Server/sensor package versions prepared: 0.6.21-dev / 0.6.14-dev. Deployment receipts, not preparation, determine installed acceptance.

2026-10-05: Windows minifilter integration remains IN PROGRESS. Server .21 and four .14 sensors deployed; three OS native R56 matrices passed. Storage live token identity matches, but executable preservation failed because health/reconnect permanently stopped capture. R60 lifecycle/connection correction and fresh native/live tests are pending. Windows 11 R57 timed out, retained as FAILED. Full operations and denied-open tests across four Windows hosts remain pending after integration; no completion claim.

2026-10-05: the intermediate reconnect matrix R65 passed 21/21 native cases. Independent replay of saved raw packets, token ground truth and artifacts passed: 53 observations/completions, 44 verified artifact/manifest pairs, 21 snapshots, 210 invalid ACK claims rejected, 1,199 supplemental token checks including 26 CREATE contexts and two open/read identity changes. Archive ED5465298042646DD5BEADDBFD2B793628AD23BFB92F2B97BBC07533B65B3608. Maximum short-case completion wait 17,868 ms. This qualifies preceding R63 driver bytes, not final R66 and not production. Final R66 command race/full OS matrices are running; live four-host acceptance remains pending.

2026-10-05 final-driver progress: R66/R68 native ACK/STOP races passed on Windows 10 with independent raw identity/byte verification (two races, eight invalid-range rejections, live-actor metadata release). Archive 7371D07C94A207C1E6B21C52B8B56B08D2C5FAF257CFCE254E33768EA5636961. The first batch controller wrongly checked LASTEXITCODE after a PowerShell script; native pass/off receipts remained intact. Receipt-based reconciliation fixed this orchestration check and continued without redispatching the race. R70 final R66 Windows 10 full matrix passed 21 cases, 85 observations/completions, 44 artifact pairs, 1,423 token checks; archive 7E9499DBC38C583F50027DE6F8884CD13B36142EB663CFB78EF7E7A192124478. Maximum controlled short-case completion wait 34,186 ms. Server replay passed; exact Win10/6456 qualification sealed. Server 2019 and Server 2012 R2 final matrices remain in progress.

Desktop test mode is configured for the next boot only, after confirming all encrypted-volume protection states are off and Secure Boot is false. Original BCD backup SHA256 1C26693B3F6101042A8977733178721D1AAA6CDA71A4780465F7938BA3144244 retained. No restart yet. One-time SYSTEM boot worker staged at C:\ProgramData\RansomFree\QA\minifilter-desktop-r66-fe73380475a946ef97744f01e8e24b4a; it verifies sealed files, actual boot policy, activates qualified R66 and executes the 16-case local operation matrix, saves results and disables its task. Local results do not imply server acceptance. The other three production hosts are unchanged by this preparation.

2026-10-05 final R66 qualification and live integration update:
Exact deployed candidate SHA256: 2DEB84A68116647D1A3A9902C2AF25A15A0014133A11870FC05DBC3CE0D649C0. Final native qualification passed Windows 10 19045.6456, Server 2019 17763.9020, and Server 2012 R2 9600.18734. Each completed 21 cases including 6 denied CREATE cases. Independent token checks: 1423 / 1222 / 1341; isolated server checks: 1025 / 758 / 912. The same candidate passed native ACK/STOP races and health-only / active-epoch / pending-operation disconnect-reconnect checks. This qualifies those controlled cases on those exact builds; it is not universal Windows or Windows 11 coverage.
Storage R66 installed with an explicitly recorded driver maintenance gap. Live read/token gate passed 4/4 with 4 independently downloaded central actor/manifest pairs. Full live matrix has FIFTEEN cases (4 read/token, 5 change, 6 denied), correcting earlier orchestration notes saying 16. Storage local filesystem checks passed all 15; server matching passed 15/15 with 16 actor/manifest pairs (multiple observed writes can produce more than one pair). Initial central download returned 404 while upload was pending; the retained failure is not a pass. Bounded polling subsequently verified actual downloaded bytes and event/process/manifest linkage. The verifier now requires the exact case list, independent before/after file state, exact access-denied statuses, exact successful status, and completed read/write byte counts.
NVR firmware original Secure Boot and boot options retained; only Secure Boot changed for the authorized test. BCD test mode configured, reboot active test mode verified, and R66 installed. Its local 15-case matrix and settings restoration passed; central verification still in progress. DC final native qualification passed but production restart/install/tests remain pending. Desktop test mode is pending next boot; owned one-time bootstrap is staged but has not run. Previous bootstrap revisions remain disabled and immutable. Main integration is not complete across all four hosts yet.
Manus follow-up review: windows-minifilter-denied-operation-completion-review.md. Capture actual callback thread tokens early and carry them to the outcome; never substitute a completion worker identity. Denied coverage established only for observed failed CREATE callbacks with actual STATUS_ACCESS_DENIED and independent ERROR_ACCESS_DENIED. A higher filter that completes an open before this filter is invoked is outside this source's visibility. Share violations, reparse chains, asynchronous historical submitters and remote SMB principals are not established by the controlled local DACL cases. Delete disposition is a request; the owned fixture separately checks name absence after completion. Truncation fixture verifies 8192 -> 1 byte, not a no-op. Full rename destination flags, held-handle delete-on-close, reparse/share-denial and universal fast-I/O coverage are not claimed by this matrix.
2026-10-05 sensor 0.6.15 capacity correction:
Fresh NVR production matrix on .14/R66 failed combined acceptance (9/15). Raw operation/status/thread-token evidence was present, but relevant originals explicitly recorded ENRICHMENT_QUEUE_CAPACITY_EXCEEDED and lacked a successful matching completion. Original failed receipts and the exact burst are retained. This is separate from the resolved driver disconnect lifetime.
The correction retains the existing 32-job limit. Only the Windows durable minifilter producer requests typed capacity deferral before any original/completion emission or actor ownership transfer. Dispatch keeps the exact early actor descriptor, asynchronously retries the same durable raw event, and removes its inbox record only after admitted publication. It does not reopen PID/path or block native receive/ACK. Non-durable producers retain their existing explicit overflow behavior. Cancellation closes the retained descriptor; disk snapshot/raw inbox remain for recovery. This does not prove crash recovery after asynchronous worker admission or infinite resource retention.
Deterministic saturation test actually occupied all 32 permits, verified zero false emissions and a live retained descriptor, returned capacity, and delivered exactly one original/linked completion for the same deferred event. Managed staged-actor fixture: 341 checks. Including actual isolated server compatibility: 355 checks. Package SHA256 61DBC0FBC50F7CDCF3191332AAB5E700E4633353032F998EE8956E10F2BC38FE. All four Windows sensors now .15; server remains .21 and qualified native driver R66 bytes unchanged.
NVR and Storage fresh .15/R66 local operation matrices each passed all FIFTEEN cases and independent file state checks. Actual central acceptance is pending; no server pass inferred from local execution. Desktop latest bootstrap receipt is MINIFILTER-DESKTOP-BOOT-WORKER-STAGED-20261005-R5.json; it will install the .15-compatible R66 driver, execute 15 cases, and run the same authenticated central download/token acceptance from a PowerShell 7 executor after boot. Earlier boot workers are disabled, retained and unexecuted. Desktop restart has not been requested. DC restart/install/live acceptance remains pending while other server checks finish.
2026-10-05 01:18 UTC live acceptance update (UTC date 2026-10-06):
Fresh .15/R66 actual central acceptance PASSED on CPTNYC_NVR and CPTNYCSTR01: 15/15 cases each, 16 independently downloaded actor/manifest pairs each; NVR history 401 records, Storage 502. Every qualifying read/write had exact successful NTSTATUS and expected completed byte count; all six denied attempts had independent Win32 error 5, final observed native C0000022 and unchanged file state. All selected primary/thread-owner/effective token values, user, PID/start/TID, executable SHA, manifest and source-event linkage matched. Previous NVR .14 failure remains retained, not overwritten. Driver R66 and all four .15 sensors remain installed; server .21 unchanged. DC restart requested only after both central gates passed; its boot/startup/minifilter/live tests and Desktop activation remain pending.
Manus clarified review windows-minifilter-deferred-admission-recalibration.md confirms single-dispatcher/one-retained-lease/shared-permit/source-before-pipeline-close invariants. Earlier generic multi-dispatcher/unbounded-deferred-slot recommendations were withdrawn for this actual architecture. Existing durable-original-only crash gap after asynchronous admission remains explicitly outside this capacity correction; no exactly-once or universal-lossless claim.
2026-10-06 01:27 UTC: DC reboot confirmed new boot 01:20:53.498054Z; actual CI options 3/test mode active. Server .21 and callback receiver .6.5 restarted on their existing tasks, authoritative E: data/configuration unchanged and an earlier Storage central evidence receipt still readable. Initial post-boot checker used an incorrect receiver filename; corrected to the actual exact installed RansomFree.Receiver.exe release path. That was a verifier defect, not a server failure. R66 driver installed successfully on DC (native load error 0). DC .15 local matrix passed all 15 operations and restored settings; actual central token/artifact acceptance is running. Desktop R5 bootstrap staged and other bootstrap revisions disabled; restart remains unrequested until DC central gate passes.

2026-10-06 final host handoff: three live Windows hosts have PASSED actual 15/15 local and central acceptance on .15/R66. DC receipt: MINIFILTER-R66-0615-LIVE-FULL-DC-SERVER-20261005-R1.json. Latest Windows 10 worker: Sequester Desktop Minifilter Once f94e0b1dbd184880a3a4007ec4017b8f, root C:\ProgramData\RansomFree\QA\minifilter-desktop-r66-f94e0b1dbd184880a3a4007ec4017b8f, plan SHA256 549342031D821A3444EC83C776E82A8429F5BA314BBFCA92885160AD0E0AC5B8. It runs 15 local and central cases and appends its actual outcome here. Windows 10 restart about to be requested; no final-host pass inferred before RESULTS.json and CENTRAL-ACCEPTANCE.json. Detailed handoff: diagnostics/windows-token-20260930/MINIFILTER-LAST-HOST-HANDOFF-20261005.json.


2026-10-06T01:48:45.4088217Z Desktop post-boot acceptance: PASSED: Windows 10 installed R66/.15, 15/15 actual local and central cases, token/user/PID/operation/byte-count matching and downloaded actor/manifest verification. Results: C:\ProgramData\RansomFree\QA\minifilter-desktop-r66-47ccdf45991e46ae8212cca51c664ede\RESULTS.json. Full controlled four-host acceptance does not establish universal higher-filter/remote/IRQL coverage or asynchronous-work crash recovery.


2026-10-06 final four-host Windows minifilter acceptance: PASSED.
CPTNYC_DC01, CPTNYC_NVR, CPTNYCSTR01 and DESKTOP-6U8VLDH each passed 15/15 fresh local and actual central cases on sensor .15 / native R66 / server .21: 60/60 total, including 24 denied attempts. All four sensor and driver services are Running, with exact installed driver SHA verified. Reads (including impersonation before/after open), writes, append, rename, delete and 8192-to-1 truncation were verified against independent actor/token truth and filesystem outcomes. User, process, PID/start/TID, process-owner and effective accessing-thread identity matched; denied CREATE C0000022 matched independent Win32 error 5 and unchanged file state. Central downloads verified 64 executable/manifest pairs and source-event/process linkage. Test settings were restored; Desktop one-time boot task is disabled after successful execution. Driver disconnect and durable-source enrichment-capacity failures are corrected; prior failed receipts remain retained. Test mode and temporary load-order number 385200.923 remain active. Controlled local tests do not establish visibility above this filter, remote SMB identity, arbitrary unavailable token contexts, universal fast-I/O/reparse/delete-on-close coverage, or asynchronous-work crash recovery. Full product-specification completion is not claimed.
Authoritative consolidated receipt: diagnostics/windows-token-20260930/WINDOWS-MINIFILTER-FOUR-HOST-ACCEPTANCE-20261006-R1.json (SHA256 BC51B7AABF0D70D29FC4D707A728773971A3FB634D47CC827749F114BAF6B952).

## 2026-10-06 Windows visibility boundaries - qualification in progress

Controlled higher-filter test: Windows 10 native denial was captured when the test blocker ran below Sequester, absent when the blocker ran above it, and captured again after Sequester was moved above that blocker. The two visible denials passed central token, actor and evidence-download checks. Original settings, load order 385200.923 and R66 were restored. This proves relative filter ordering, not universal interception of all higher filters.

SMB server evidence: additive WindowsShare v1 collects actual Security event 5145 authenticated SID/account/logon, source IP/port, share and relative target, and share authorization outcome. Remote application/PID are explicitly unavailable. Granted share authorization is not a completed NTFS operation. Detailed File Share auditing is opt-in; parser limits published records to configured exact watched files. Sensor .16 is deployed on Storage only. Managed parser/spool tests (22 checks) and history fixture pass. Central SMB acceptance is pending: server .22/.23/.24 activation gates hit live history timeouts and rolled back to .21, preserving authoritative data and backups.

Actual remote-volume properties were probed on all four Windows hosts. All expose MUP filesystem type 13/device type 20. A LANMAN-only selector was disproved and corrected with Manus. Private Windows 10 MUP probe matched open/read, share-denied open and NTFS-denied open with independent PID/start/TID. The full candidate reused R66 pre-operation token capture and local actor snapshot acquisition. All three CREATE cases passed independent primary/effective/create-authorization/thread-owner token comparisons, user/process/PID/start/TID, actor SHA-256, preserved actor bytes, and manifest integrity/linkage. Windows remote evidence is version 6 and explicitly identifies the client network-filesystem completion boundary; remote provider identity is unavailable. Candidate is opt-in at build time. Accepted Desktop driver R66 and agent were restored after an explicit maintenance gap. These local results are not central acceptance or deployment across Windows hosts.

Receipts: WINDOWS-FILTER-BOUNDARY-CENTRAL-20261006-R2.json; WINDOWS-FILTER-BOUNDARY-ABSENCE-20261006-R2.json; WINDOWS-VOLUME-PROBE-{DC,NVR,STORAGE,DESKTOP}-20261006-R3.json; WINDOWS-SMB-ROUTING-PROBE-DESKTOP-20261006-R1.json; WINDOWS-REMOTE-ACTOR-ACCEPTANCE-DESKTOP-20261006-R2.json, under diagnostics/windows-token-20260930.

Remaining gates: live history timeout diagnosis and server activation; central 5145 acceptance; remote candidate reads/writes/renames/deletes/truncation/async/mapped-path and impersonation qualification on the supported Windows builds; supported MUP provider identification; production remote scope configuration; central binary acceptance; affected sensor upgrades and regression tests. No authoritative cross-host SMB request join is claimed.
### 2026-10-06 boundary follow-up: Windows 10 network operations and live server diagnosis

- Windows 10 MUP candidate: 12/12 actual operations matched independent PID, process start, request thread, process-primary/effective/thread-owner token fields. Includes read, duplicate-token impersonated read, write, append, rename, delete, truncate, async read/write, share-denied CREATE and NTFS-denied CREATE. Remote operation completion remains a client-filesystem observation, not proof of remote server completion.
- Separate CREATE acceptance: 12/12 cases matched actor identity and preserved executable/manifest hashes. Receipts: WINDOWS-REMOTE-ACTOR-MATRIX-{CREATE,OPERATIONS}-ACCEPTANCE-DESKTOP-20261006-R1.json. Accepted R66 sensor baseline restored and private SMB mappings removed. Other Windows OS and central remote-binary receipt remain pending.
- Remote schema regression: 226 checks on 32 real captured operations passed; unsupported server acknowledgment retains queued remote evidence.
- Added duplicate-token-read to the owned WindowsActorFixture using documented DuplicateTokenEx, with independently recorded primary and actual effective token evidence. Existing fixture behavior preserved.
- Added a separate 80 GiB VMware backup disk to CPTNYCDC01; verified BIOS UUID and new RAW disk identity, initialized only the new disk as F: Sequestor Backup, protected backup permissions. Existing C:/E: disks, data, snapshots and backups preserved. Receipts: VMWARE-DC-BACKUP-DISK-ADDED-20261006-R1.json and WINDOWS-DC-BACKUP-VOLUME-20261006-R1.json.
- Confirmed native byte admission already requires BOTH FILE_READ_DATA and FILE_EXECUTE in immutable R66 source. Earlier research prompt saying OR was incorrect and was corrected with Manus; no admission change made.
- Sensor unload initially improved an existing history request, but repeated deployment isolation with the driver unloaded did not resolve the history failure. Driver root cause is NOT established.
- Reproduced Windows PowerShell 5 NativeCommandError when diagnostic stderr is redirected under ErrorActionPreference Stop. Start-Process with private independent stdout/stderr files passed the owned launcher regression and now exposes history timing without stopping the server.
- Live .24 timing localized the remaining timeout after count-complete, before reader-open. Added a direct indexed path for sequence-only exact-sensor pages in .25; general filtered query behavior retained. History fixture passed, including fixed-snapshot paging, exclusion of other sensors/later arrivals and invalid cursor rejection. .25 deployment/central receipt gates still in progress; no successful production upgrade claimed in this note.

### 2026-10-06 live server and Windows sensor rollout

- Server .25 deployment PASS: DEPLOY-WINDOWS-SMB-SERVER-0625-20261006-R1.json. Pinned package SHA256 BA7E23526271E78A9BC142AA2777B75302F8B252E5C219A9491042170A21C37B; backup on F:, receiver PID unchanged, 33 endpoint inventory records preserved, 30 served assets matched, Windows alert filters returned 6,051 records. Inventory records include qualification enrollments; this is not a 33-active-sensor claim.
- Storage/DC/Blue Iris/Windows 10 sensors are .16 with connection-file hashes preserved and rollback directories retained. R66 driver remains installed. Remote MUP candidate is not production-enabled.
- Fresh 15-case local operation execution passed on all four upgraded Windows hosts; settings restored and services Running. Independent execution includes six denied opens per host and three distinct impersonation scenarios. Fresh central token/artifact acceptance is still pending; execution-only is not counted as end-to-end acceptance.
- Storage first execution attempt failed before changing settings because Windows PowerShell 5 did not accept a decoded UTF-8 BOM. QA helper R2 trims that marker only for parsing and restores exact original settings bytes; rerun passed.
- Large/scoped history responses still time out; .25 small-page deployment gates do not establish resolution of every history query. Managed response-streaming checks with 25 and 500 rows timed out before headers. Active investigation with private managed-stack sampling; no driver root-cause claim.
- SMB central acceptance remains pending: both path-scoped and indexed sequence API attempts timed out. Original API/trace receipts retained. No fabricated remote application PID or guessed SMB identity is accepted.

### 2026-10-06 server console logging blockage identified and repaired

- Managed-stack evidence captured the live server without a memory dump or process replacement: WINDOWS-HISTORY-MANAGED-STACKS-20261006-R2.json. First sample contained 192 ConsoleLoggerProcessor.Enqueue frames, with the console writer blocked in StreamWriter.Flush. Server process identity unchanged during collection.
- Repaired the launcher to let cmd.exe perform direct native stdout/stderr file-handle redirection, with hidden window, disabled AutoRun, unique private log names and preserved inherited server configuration. Removed the PowerShell/.NET redirected-output reader pipes from the server logging path. Unchanged .25 server binary, authoritative database, callback receiver and sensors. Original launcher/task retained.
- Live repair verification PASS: WINDOWS-SERVER-LOGGING-REPAIR-20261006-R1.json. History responses of 1, 25 and 500 records returned HTTP 200; 500 records were 3,030,342 bytes and completed in 12.73 seconds. This establishes the repair on those queries; ongoing scoped acceptance and sustained-runtime checks remain required.
- All four .16 Windows sensors now have complete fresh 15-case execution/restoration receipts. Central verification remains in progress and is not implied by execution success.

## 2026-10-06: SMB authorization evidence correction and fresh Windows qualification

- Server 0.6.26-dev and Windows sensors 0.6.17-dev deployed on DC, NVR, Storage, and Desktop. Existing sensor connections, R66 minifilter, canaries, server data, and callback receiver retained.
- Fixed Windows Security 5145 AccessReason validation: native tabs/newlines are retained exactly; path controls, other control characters and oversized reasons remain rejected. Regression fixture passed 38 checks including three actual captured Windows records; existing Windows audit fixture passed 17 checks.
- Fresh SMB qualification passed all three cases through the deployed Storage sensor and server: allowed read, share-denied write, and share-granted but NTFS-denied read. Verified authenticated SID and independently observed source TCP address/port. NTFS denial separately matched a server minifilter CREATE with STATUS_ACCESS_DENIED. Receipt: WINDOWS-SMB-CENTRAL-ACCEPTANCE-20261006-R6.json.
- Storage's 20 MiB Security log currently rolls over in roughly 12 seconds under backup activity. Live source capture proved the records existed. Retrospective absence is not evidence of no access.
- Before the multiline correction, fresh 0.6.16/0.6.25 Windows qualification passed 60/60 operation cases across four sensors with 64 centrally verified executable/manifest pairs. Includes full primary, effective, CREATE-authorization and thread-owner token comparison, denied operations, process-instance matching and exact artifact hashes. Receipts WINDOWS-0616-OPERATIONS-*-CENTRAL-20261006-R2.json.
- All four fresh 0.6.17 local operation suites passed; their central verification is in progress. General path-filtered history queries can still time out on the current host. Indexed sequence queries are used for bounded verification; this does not establish resolution of every UI/filter performance issue.
- MUP client candidate on Windows 10 already passed 12/12 CREATE and operation cases with token and preserved actor verification. Qualification on Server 2012 R2/2019 and production client-side MUP integration remain pending. Server event 5145 does not report a remote application's PID or thread token, and no automatic client/server operation join is claimed.
- The controlled higher-filter test proved a denial below our observation point is visible, while a denial completed above it is not. Moving the observer above the controlled blocker recovered full attribution. This is a filter-order boundary, not universal coverage of arbitrary higher filters. No unsupported guarantee is made.
### 2026-10-06: Windows denied-open and network-boundary progress

- Server 0.6.26 / sensor 0.6.17 fresh local acceptance: 60/60 operations across DC, NVR, Storage and Windows 10; 64 independently downloaded actor executable/manifest pairs. Receipt: diagnostics/windows-token-20260930/WINDOWS-0617-FOUR-SENSOR-CENTRAL-20261006-R1.json. Includes requesting-thread effective, process-primary and thread-owner tokens, PID/start identity, actual denied status and preserved actor linkage. UI presentation is not asserted by this raw API gate.
- Corrected MUP opened-name selection qualified on all four Windows hosts: 12/12 CREATE cases and 12/12 operation cases per host. Candidate SHA-256 80B647264664701DB9A44AC68FF53FBF7E3FCFDB5FF2779857248910E950C995. DC required temporary disabling of its exact outbound TCP 445 block to 10.81.60.200; rule was restored. The previous R66 driver was restored after each isolated qualification.
- Server 0.6.27 deployed with explicit WindowsKernelVersion=6 acknowledgment. Desktop sensor 0.6.18 and MUP driver deployed for installed-service qualification. Desktop execution passed 15 local cases and 12 UNC cases; central matching/upload acceptance remains pending. Native wire protocol remains 4 with existing thread-owner extension; structured MUP evidence is version 6. No provider identity or exact client/server SMB request join is claimed.
- 306 actual-MUP ingress/roundtrip/queue checks passed. Older version 5 acknowledgment retains version 6 evidence. First fixture receipt omitted forensic capabilities and was corrected; initial driver deployment assertion used invalid fltmc syntax and rolled back, then corrected. Failed receipts are retained, not counted as passes.
- Manus report: diagnostics/windows-token-20260930/manus-mup-provider-review-20261006.md. Supported provider query is FsRtlMupGetProviderInfoFromFileObject level 2 after a successful completed CREATE; copy bounded data and optionally cache in a stream-handle context. Failed CREATE provider identity stays explicitly unavailable. This provider enrichment is not yet implemented.
- Higher filters can complete a denied open before Sequester receives it. Controlled placement above the owned blocker proved capture restoration; arbitrary filters above the current load-order number remain an explicit coverage boundary. No universal denied-open capture claim.
### 2026-10-06: installed Windows network capture integration

- Server 0.6.27 and sensor 0.6.19 deployed to all four Windows hosts with driver 80B647264664701DB9A44AC68FF53FBF7E3FCFDB5FF2779857248910E950C995. Live inventory confirmed all four report 0.6.19-dev. The old hardcoded 0.6.16-dev enrollment/heartbeat/console string was corrected.
- Fresh installed-service execution: 60/60 local cases and 48/48 UNC cases completed; settings restored on all hosts and the DC outbound SMB block restored. See WINDOWS-0619-INSTALLED-SERVICE-EXECUTION-FOUR-HOSTS-20261006-R1.json. Execution is not a substitute for central token/artifact acceptance.
- Initial service fixture registered only nine intended paths plus one accidentally concatenated string. R2 requires exactly twelve distinct paths and retains watched-paths.json. R1 central rejection retained. No missing observation was counted as a pass.
- Central metadata matched the corrected desktop twelve CREATE cases; full acceptance waited for binary uploads and the eight-minute deadline expired. Three owned central validators were interrupted for server maintenance; null JSON outputs are explicitly rejected in CENTRAL-VALIDATION-MAINTENANCE-INTERRUPTIONS-20261006-R1.json.
- Evidence receiver unnecessarily reapplied identical inheritable DACLs at every artifact path access. Source now checks canonical protected rule equality, rewrites only when different, and still rejects linked paths. 158 transfer checks passed, including 100 repeated downloads with unchanged NTFS identity/change marker, repair of an added Everyone rule, preserved bytes, corrupt-copy rejection, resume, failed-upload fairness and actual API receipt. Server 0.6.28 deployment/central reruns pending at this entry.
- Filter placement qualification plan from Manus saved as manus-filter-placement-plan-20261006.md. Prefer one qualified observer route; simultaneous upper/lower instances need distinct route metadata and cannot be deduplicated solely by PID/time/path. A temporary position above the controlled blocker does not prove visibility above arbitrary future filters or bindflt.
## 2026-10-06: Windows 0.6.19 / server 0.6.28 acceptance

- All four current Windows hosts passed fresh raw-server-API acceptance: 60 local operation cases, 48 MUP CREATE cases and 48 MUP operation cases. Independent actor PID/start-time/thread/token truth, native operation outcomes, preserved executable bytes, manifest hashes and source-event linkage were checked. Receipt: diagnostics/windows-token-20260930/WINDOWS-0619-FOUR-HOST-CENTRAL-ACCEPTANCE-20261006-R1.json in the outer workspace.
- Server 0.6.28 is deployed. The evidence directory ACL fast path passed 158 fixture checks, including repeated downloads and repair of modified permissions. The deployment retained database data, callback receiver and UI assets.
- Acceptance helpers now honor HTTP 429 Retry-After without disabling server rate limits. Failed/interrupted runs remain retained and are excluded from acceptance.
- Still pending: capture of denials completed above the observer; MUP provider identity enrichment; exact automatic client/server SMB operation correlation; higher-position stress and teardown qualification. General notification history query timeouts and sensor health warnings remain separate unresolved issues. Raw API acceptance does not establish signed-in UI presentation.
- A temporary single higher observer is under qualification on the Windows 10 desktop, using the existing driver and restoring its original position. No permanent filter number or universal denied-access coverage is claimed.
## 2026-10-06: Higher observer qualification follow-up

The controlled Windows 10 blocking filter at 409800.923 hid its denied CREATE from the baseline observer at 385200.923. Moving the same deployed driver temporarily to 409801.923 captured that denial. Two positive denials passed full raw API token/process matching and independent central executable/manifest hashing. Receipts: WINDOWS-HIGHER-BOUNDARY-CENTRAL-20261006-R1.json and WINDOWS-HIGHER-BOUNDARY-ABSENCE-20261006-R1.json. Original placement, settings and blocker removal were verified. This is a controlled placement proof, not universal coverage or a permanent Microsoft-assigned number.

The first higher-position 15-operation tests passed independent actor execution on all four hosts, but are NOT accepted capture passes: native queue teardown occurred before all observations reached durable sensor evidence. Failed/interrupted central runs are retained, including null results from terminated owned validators. Fresh tests now require exact PID/start-time/operation records in durable sensor storage before restoring settings or unloading the observer; their final central acceptance remains pending.

Acceptance verifier retries also exposed a PowerShell case-insensitive variable collision between AfterSequence and afterSequence. Corrected helpers use cursorSequence, preserve the original watermark for every retry, and save intermediate mismatch reports. Previously completed 60 local / 48 remote CREATE / 48 remote operation acceptance remains supported by its full final event and artifact receipts; incomplete higher-position tests are excluded.
### Higher-position Windows 10 central acceptance

The corrected durable-drain run passed all 15 local cases, with 16 actor executable/manifest pairs downloaded and hashed from the live server. User, owner/effective token, PID/start-time, thread, operation result and source-event linkage matched independent actor truth. Receipt: WINDOWS-HIGHER-LOCAL-DESKTOP-CENTRAL-20261006-R3.json. Temporary placement and original settings were restored. Higher-position network qualification and remaining host central acceptance are still pending; no permanent position change is claimed.
### Higher-position acceptance progress (continued)

- NVR: corrected durable-drain local run passed 15 cases and 16 centrally downloaded/hash-verified executable/manifest pairs. Receipt: WINDOWS-HIGHER-LOCAL-NVR-CENTRAL-20261006-R2.json.
- Windows 10 desktop: higher-position MUP CREATE acceptance passed all 12 cases; MUP operation acceptance passed all 12 cases, including real share/NTFS denied opens and asynchronous reads/writes. Full independent token and central actor evidence gates passed. Receipts: WINDOWS-HIGHER-REMOTE-DESKTOP-CREATE-CENTRAL-20261006-R1.json and WINDOWS-HIGHER-REMOTE-DESKTOP-OPERATIONS-CENTRAL-20261006-R1.json. The original filter position, settings and owned SMB mappings were restored.
- Other higher-position network platforms, stress/teardown qualification and permanent placement remain pending. Provider identity and exact general SMB client/server request correlation remain explicit limitations.
### Higher-position Windows Server 2019 NVR network acceptance

NVR passed all 12 remote CREATE and all 12 remote operation cases with full server token/process/native status matching and independently hashed central actor executable/manifest pairs. Receipts: WINDOWS-HIGHER-REMOTE-NVR-CREATE-CENTRAL-20261006-R1.json and WINDOWS-HIGHER-REMOTE-NVR-OPERATIONS-CENTRAL-20261006-R1.json. Two-host higher-position local/network acceptance is aggregated in WINDOWS-HIGHER-TWO-HOST-CENTRAL-ACCEPTANCE-20261006-R1.json. Storage and DC higher-position qualification and bounded burst acceptance remain pending. Original placement/settings/mappings restored.
### 2026-10-06 higher Windows observer and burst qualification update

- Immutable receipt `diagnostics/windows-token-20260930/WINDOWS-HIGHER-FOUR-HOST-CENTRAL-ACCEPTANCE-20261006-R1.json` passes 60 local operations, 48 remote CREATEs and 48 remote operations across Windows 10, two Server 2019 hosts and Server 2012 R2. Full native token/process truth and 170 independently downloaded actor-executable/manifest pairs were checked. Each temporary single-observer test restored the original driver position and settings. This does not establish universal coverage above all possible filters or a permanent Microsoft-issued filter number.
- The separate 64-short-lived-process burst failed forensic preservation for two actors. Native CREATE/READ records exist for both; acquisition is explicitly unavailable, not silently replaced with a later PID/path lookup. The original driver and sensor settings were restored. Pool-pressure counters are aggregate evidence and do not establish either actor's precise failure cause.
- A bounded candidate expands executable snapshot metadata from 64 to 128 entries and byte credit from 32 to 64 MiB. Individual-image, concurrent-copy and lifetime limits remain unchanged. Diagnostic table command 14 has explicit version 3/8200-byte output; the diagnostic client retains exact version 2/4104-byte support. Fourteen table codec checks and native compilation passed. This candidate is undergoing isolated Windows 10 burst qualification; it is not accepted or deployed across the four hosts.
- Manus review (`diagnostics/windows-token-20260930/windows-minifilter-snapshot-pool-pressure-review.md`) confirms capacity expansion only raises a bounded threshold. Per-candidate terminal failure attribution and ACK/read/STOP/restart/TTL resource-balance qualification remain necessary before claiming the broader pressure boundary solved. SMB provider identity and an exact general client/server operation join remain unavailable.
### 2026-10-06 bounded snapshot candidate: Windows 10 qualification progress

The 128-entry / 64 MiB candidate (SHA-256 E1128F2A69659DE6AFDDC6AFC89733F51396BDFD8694F2AF59AD5A4800422CB1) passed the owned 64-short-lived-read-actor local execution/durable-evidence gate. The server verifier matched all 64 operation-time token/identity/preservation records; independent central artifact/manifest downloads are still running. No central acceptance is claimed until every download and linkage check completes.

The isolated native lifetime rerun passes 26/26 actor associations, the 11-admission byte-budget/eviction fixture, idle expiration, reader/STOP race and complete byte/process/operation-reference balance. Immutable receipt: `diagnostics/windows-token-20260930/WINDOWS-SNAPSHOT-PRESSURE-DESKTOP-NATIVE-LIFETIME-20261006-R3.json`. No diagnostic trace loss occurred; post-drain held bytes are zero and all six operation pins were released. Sequester services, the original driver image/position, sensor settings and connection configuration were restored.

Two earlier native fixture runs are failed gates, retained as R1/R2: R1 incorrectly used an administrator instead of its required SYSTEM actor; R2 correctly used SYSTEM but overflowed the separate 2048-row diagnostic trace during its no-query idle interval and incorrectly expected the 32-header-capacity field to equal the 16-full-copy limit. The updated fixture drains only independent command-7 image trace rows during expiry (native handler does not invoke staging sweep or acquisition) and independently verifies command-24 header/full-copy limits and reference accounting. This qualifies idle expiry without staging queries or ACKs, not the stricter completely silent-port interval on a busy host.

Seventeen parsing/epoch/STOP consistency checks pass. Fresh candidate burst executions on the other three Windows hosts are running. The larger pool remains a bounded improvement; exact diagnosis beyond its capacity and a universal no-loss guarantee are not asserted.
## 2026-10-06: snapshot-pressure recovery and upload diagnostics, in progress

The E1128F2A69659DE6AFDDC6AFC89733F51396BDFD8694F2AF59AD5A4800422CB1 candidate remains temporary qualification code, with 128 snapshot slots and 64 MiB total byte credit. All four hosts restored the original 80B647 driver and 385200.923 position after the owned tests. Desktop and DC completed their 64-read local preservation drain. NVR and Storage executed all 64 reads, but failed the 20-minute preservation drain deadline; their settings were restored. These failures remain recorded, not converted to passes.

The R2 raw server verification matched all 64 Desktop and all 64 DC reads, including PID/start/thread identity, primary and effective token truth, and preservation linkage. Central download subsequently returned HTTP 500 on both; the complete central acceptance gate therefore failed. R3 retries bounded 404/409/500/503 download failures while retaining every attempt, still requiring independently matching binary and manifest hashes and linkage. NVR/Storage recovery validation is pending. No complete four-host snapshot-pressure acceptance is claimed.

EvidenceUploadQueue/EvidenceUploadWorker now report bounded transfer phase, validated evidence ID when known, actual HTTP status when supplied, and exception type. Capability failures explicitly lack an evidence ID. Diagnostics omit credentials, raw responses and file paths. The development EvidenceTransferFixture passed 164 checks at D:\Codex\RansomFree\forensic-gaps-20260925\fixture-87d2661e738e4737bb39801476c20f4d, including corrupt local evidence, real revoked-sensor capability refusal, controlled HTTP 500 event replay, receipt persistence and fairness. This telemetry change is source/development tested, not deployed. Program.cs also contains an undeployed numeric SQLite error-code logging change.

Manus confirmed the negative-association design correction: detach under the staging lock, then securely clear/free outside it after the final reference; a full process registry cannot imply a later process-create retry. The bounded exact-file-object negative association and per-operation failure companion remain implementation work. Their absence is explicit; aggregate pool counters do not prove individual failure causes.
## 2026-10-06: evidence intake and atomic contact deployment

Runtime exception observation (WINDOWS-SNAPSHOT-PRESSURE-SQLITE-EXCEPTIONS-20261006-R1.json) confirmed SQLite primary code 5/database-locked on the unchanged .28 process. The bounded diagnostic retained 128 matched samples, counted 897 matching exceptions/769 local output overflow, and reported zero EventPipe loss; it does not associate every exception with a particular HTTP request or identify the holding writer.

Server .29 joins server-observed contact updates into the existing heartbeat/event transaction, avoiding the previous second writer transaction and a possible failure after event commit. Public Store two-argument overloads remain present, API fields and schema unchanged. Thirteen isolated SQLite atomic-contact tests passed, including forced trigger failure/rollback, immutable replay, mapped IPv4 and revocation; SQL Server runtime is not qualified by these tests. The frozen .29 package passed 164 transfer checks. DEPLOY-WINDOWS-EVIDENCE-RECOVERY-SERVER-0629-20261006-R1.json records PASS, PID 4724, 33 endpoints unchanged, 30 matching web assets, receiver PID 1408 unchanged, authoritative E: data and F: backup preserved. Package SHA256 63E9BD264BBA36FC3DB62A0E916B74363F749CEAFBECD22AD938A0B549640199. This reduces contention opportunities; universal resolution of database contention is not claimed.

Read-only quota measurement found the repeated 10k-file intake sum taking NVR 3544/2821 ms and Storage 2643/1837 ms using separate FileInfo queries. DirectoryInfo enumeration supplies current pre-populated file sizes in NVR 33/25 ms and Storage 36/18 ms. WindowsStagedActorStore now uses this enumeration, still rescanning all current files and counting failed temporaries/WAL, without a global byte cache, raised quota, deletion or weaker identity checks. Microsoft documents pre-populated FileInfo.Length for DirectoryInfo.EnumerateFiles. The staged-actor fixture passed 343 checks, including 10,000 historical failed files, a subsequent grown file exhausting quota, retained evidence and withheld ACK.

Sensor .20 includes that intake improvement and bounded upload failure diagnostics. Its frozen package SHA256 is 0CA68C424176B8EF9B73FAB656D15F1BADD21C51D7BA6D39AA6844357820F0B1. UPGRADE-WINDOWS-INTAKE-RECOVERY-{NVR,Storage,DC,Desktop}-0620-20261006-R2.json records all four upgrades with connection/settings/driver placement and present-or-absent markers preserved. The first NVR preflight refused an absent optional proactive marker before mutation; R2 correctly preserves absence instead of requiring activation.

Fresh .20 64-process candidate qualification is running on all four hosts; native candidate remains E1128F2A... and temporary 409801.923, with restoration in finally. The older failed NVR/Storage drain runs cannot establish complete snapshot retention. Fresh central token/hash/manifest acceptance and the candidate's complete operation/SMB regression gates remain pending. Larger-pool candidate is not permanently deployed. Broad history/UI timeout and per-candidate negative association remain open.
## 2026-10-06: bounded SQLite request admission and demonstrated preservation quota

The .29 runtime continued to return SQLite 5/5 errors. A read-only .29 managed stack snapshot (WINDOWS-EVIDENCE-RECOVERY-SERVER-STACKS-20261006-R3.json) showed concurrent heartbeat/event/policy/response requests in the provider's synchronous busy retry, including the audit write required before an evidence download. This confirms contention, not the identity of a unique holding writer. The resource snapshot showed about 5.4 GiB free RAM, 37 management threads and a 126 MiB WAL; it does not establish that larger storage alone fixes contention.

Server .30 adds SqliteWriteAdmission: one admitted API mutation with a bounded FIFO queue of 128 asynchronously waiting requests, cancellation support and retryable 503/Retry-After on queue refusal. SQL Server bypasses this queue. Read-only GET/HEAD/OPTIONS requests bypass admission; the existing evidence-download audit write independently joins the same queue and releases admission before returning its executable download stream. Existing authentication, authorization, request limits, transactions, immutable event conflict checks and schemas remain in place. Background writers and other processes do not participate, so total elimination of SQLite contention is not asserted.

Twelve isolated admission checks passed with 64 actual SQLite event/contact/heartbeat commits, FIFO/exclusive execution, full-queue refusal, cancellation, exception cleanup and SQL Server bypass. The sealed .30 runtime passed 166 EvidenceTransferFixture checks, including 64 concurrent HTTP heartbeat/event pairs persisted unchanged and authorized exact-byte audited artifact download. Sealed fixture root: D:\Codex\RansomFree\forensic-gaps-20260925\fixture-9b3e9c5c9b1a4a0a8967191ab288fa60. Package SHA256 D8214CECE393A5B82973FE40F226644EED7854897C74CAD401B16552CD78FE05; source manifest 4837BA1674F9A346177DC41960480F1AB3429707E80BA2A62D3C421D21758814. DEPLOY-WINDOWS-EVIDENCE-RECOVERY-SERVER-0630-20261006-R1.json records PASS, PID 5480, 33 unchanged enrolled IDs, 30 matching web assets, receiver PID 1408 unchanged and stopped-writer backup F:\Sequestor\Server\backups\write-admission-20261006T195638Z. Live sustained contention reduction remains a gate.

Fresh .20/E112 candidate 64-read local drains passed on NVR, Storage and DC; their baseline driver/settings/connection/position were restored. Receipts WINDOWS-SNAPSHOT-PRESSURE-{NVR,Storage,DC}-0620-EXECUTION-20261006-R1.json. Their first new central NVR/Storage verification attempts failed during the server restart and remain failed immutable receipts. Fresh central retries use bounded transport/500/503 retry and at most 50,000 raw rows; exact token, event, binary and manifest mismatches never become retry success. The original .19 Desktop burst separately passed 64 exact server cases and 64 independently verified central executable/manifest pairs in WINDOWS-SNAPSHOT-PRESSURE-Desktop-CENTRAL-20261006-R4.json. This is not acceptance of the fresh .20 Desktop run.

The fresh .20 Desktop drain stopped at 50 preserved read actors. Read-only measurement found its protected evidence/actors directory holding 1,073,660,523 bytes in 5,720 files, exhausting the default 1,024 MiB forensic preservation quota. Retained local read enrichment explicitly reports evidence-store-quota-exceeded for later owned cases. Local activity rotation and PID reuse mean this partial activity inspection cannot establish every original event; the actual preservation failures, not aggregate intake counters, establish the quota cause. The host has about 1.8 TB free on C:. No evidence was deleted and no immutable failure was changed to success.

The guarded EvidenceQuotaMaintenance tool uses existing audited Store group/policy methods to clone an endpoint's complete assigned settings while changing only the forensic evidence capacity. Its isolated and packaged tests cover nondefault settings, shared policy isolation, unassigned defaults and persisted assignment. WINDOWS-EVIDENCE-QUOTA-POLICY-20261006-R1.json confirms only Desktop's quota was raised from 1,024 to 4,096 MiB through a dedicated policy group, with the .30 management process unchanged. Other endpoints/shared policies were not modified. Sensor policy application and a fresh preservation rerun remain required. The existing owned Desktop test still drains/restores under its original deadline; later policy cannot retroactively repair already recorded preservation failures.

Remaining qualification includes fresh Desktop recovery, all four new central burst sets, complete operation/SMB and higher-blocker tests for E112, per-candidate negative association, MUP provider evidence and broad UI/history latency. Current results do not establish permanent deployment of E112 or completion of the entire specification.

### 2026-10-06: central evidence capacity and measured request throttling

- Read-only central reservation accounting (`WINDOWS-CENTRAL-EVIDENCE-CAPACITY-0630-20261006-R1.json`) established that Windows 10 had used 1,073,715,248 bytes of its 1 GiB central per-sensor allowance, including unfinished reservations and 64 KiB overhead per artifact. The local 4 GiB policy alone could not fix central upload refusal.
- `WINDOWS-CENTRAL-EVIDENCE-QUOTA-20261006-R1.json` records a successful same-binary .30 restart with central per-sensor capacity set to 4096 MiB; the global 10240 MiB bound, data, evidence and callback receiver were preserved. Available E: space was checked (>2 GiB); a larger configured limit is not a guarantee of equivalent physical free space.
- The fresh Windows 10 .20 / E112 candidate burst now passes 64 independent short-lived read actors (`WINDOWS-SNAPSHOT-PRESSURE-Desktop-0620-EXECUTION-20261006-R2.json`); 15 local operations including denied opens and impersonation changes also pass (`WINDOWS-0620-Desktop-CANDIDATE-FULL-OPERATIONS-EXECUTION-20261006-R1.json`). Both wrappers restored the original native image, filter position, settings and connection. The earlier quota-failed burst remains a failure; local passes do not establish central acceptance.
- NVR .20 upload telemetry exposes actual HTTP 429 during event replay. DC local telemetry exposes the full outbound management queue. These are separate bounded capacity failures, not proof that native accessing-thread tokens are missing.
- .31 adds explicit `RequestLimits:ReportingPerMinute` and `RequestLimits:ArtifactPerMinute` configuration, retaining defaults of 600 for both globally bounded pools. Invalid values (<1 or >10000) fail startup. The existing 128-entry SQLite writer queue remains unchanged. Deployment intends reporting=2400/minute and artifacts=1200/minute for this installation; no limiter is removed.
- `request-limit-fixture-r3.log`: 17 checks pass, including defaults, overload rejection, configured pool independence, saturation, invalid configuration, and lookalike paths. `server-0631-packaged-transfer-r1.log`: 166 actual HTTP evidence-transfer checks pass against the sealed .31 executable. Package SHA-256: `9D14F7A45EB21DBE7AA6D40CD79A39A17383DB13FA66F24E55C11D325AD0C3DA`; source manifest: `DFB6BB7DC41E2AD35CF62C8ABF6D9F333B222A45B13767AD6495E0DDB6AA9AA1`.
- The first .31 deployment attempt rejected a stale expected file-version string before stopping the running server. Its failed receipt is retained. The corrected guarded deployment and fresh central acceptance are pending at this checkpoint.
- Storage's current 15-operation local drain has 14 matches, with successful truncate still unmatched; DC's corresponding drain was blocked by the management queue. Both are pending/failing gates until independently verified; rotated activity logs cannot establish absence of historical raw events.
- Manus delivered `windows-minifilter-operation-acquisition-outcome-companion.md` and `windows-acquisition-outcome-companion-source-notes.md`. The reviewed design uses immutable per-operation scalar outcomes, exact executable FILE_OBJECT binding, a separately bounded 128-entry failure association pool, and unattributed overflow health. No negative-association implementation or deployment is claimed by this documentation checkpoint. Existing 88-byte binding and raw operation ABI must remain unchanged.

### 2026-10-06: capability queue correction and supported Windows token-session qualification

Server 0.6.32-dev is deployed (DEPLOY-WINDOWS-EVIDENCE-RECOVERY-SERVER-0632-20261006-R1.json). Exact POST /api/v1/agent/capabilities now bypasses SQLite writer admission because its authentication performs only a SELECT and its response contains fixed capabilities. All neighboring mutation routes remain admitted; no authorization bypass was introduced. The isolated admission fixture passed 18 checks, including valid/invalid credentials and a capability request completing while a writer permit is held. The sealed executable passed all 166 EvidenceTransferFixture checks. Package SHA256: 383737CBD8CD6ED661A7C5773672DD590A36BC31F46729E9A5C6E50C4824B29C; source manifest: 6C7E21710E26701E6188A78F3900A4ABF351DA3B77397293110F834C43A2EEC3. Deployment preserved 33 enrolled IDs, all 30 checked web assets, the authoritative E: database, callback PID 1408, 4 GiB per-sensor central allowance, and reporting/artifact request budgets of 2400/1200 per minute. Backup: F:\Sequestor\Server\backups\capability-admission-20261006T210534Z. Writer PID 7500. Broad history/UI latency and all central upload completion remain pending, not inferred from health.

Three authenticated capability probes per Windows host returned HTTP 200 and EvidenceUploadVersion 1. Initial connection times were 120..348 ms; subsequent responses were 4..23 ms (WINDOWS-CAPABILITY-{DC,NVR,Storage,Desktop}-0632-20261006-R1.json). Upload diagnostics have advanced past capability checking but still show event-replay/reservation timeouts. The DC outbound queue fell from 9981 pending at 20:41:59Z to 7359 at 20:47:35Z and 4967 at 21:10:12Z. This is delivery progress, not complete acceptance.

Storage's earlier missing truncate result is no longer an unobserved native operation: WINDOWS-0620-Storage-TRUNCATE-QUEUE-20261006-R1.json finds retained raw event f29311b169a031642d83b40c154febb1, PID 8060, creation 134357908675605167, thread 1184, IRQL 0, SET_INFORMATION class 20, all token fields captured (31), and exact operation-bound independently hash-verified executable bytes. Thus this case does not establish an APC-level token limitation or failed kernel truncate capture. Its enrichment/preservation/server delivery still needs diagnosis and acceptance. The earlier 14/15 teardown failure remains immutable. The diagnostic selected the exact owned target without assuming an actor PID; rotating-log absence is not absence of capture.

Driver candidate AF2C27706C3CD8A6B2EE3FFEA85F233DC2BE54B0C756C8F91B68C7A0EF534958 replaces the reserved-for-system-use SeQuerySessionIdToken with documented SeQueryInformationToken(TokenSessionId). Frozen native source manifest 600D275063A48C929F87C9FBBC0EAF5DA36227A78A9FC388DB725625A99C1C46. WDK /W4 /WX build and import inspection passed. Windows 10 local strict acceptance passes 15/15 operations and 16 independently hashed executable/manifest pairs, matching SID, token ID, authentication ID, modification ID, token type, impersonation level, session ID, integrity and elevation to independent actor truth; PID/start/thread IDs, byte counts and denied status are also checked. Receipts WINDOWS-SUPPORTED-SESSION-Desktop-0620-EXECUTION-20261006-R1.json and WINDOWS-SUPPORTED-SESSION-Desktop-LOCAL-TOKENS-20261006-R1.json. Baseline driver, load order and settings restored. Other Windows version qualification and central receipt are pending. This candidate is not permanently rolled out.

Manus review and Microsoft API documentation confirm PsReferencePrimaryToken, PsReferenceImpersonationToken and SeQueryInformationToken require PASSIVE_LEVEL. Do not reference/query the accessing-thread token at APC_LEVEL, backfill it from a later worker, or substitute the process owner. Existing unavailable evidence remains explicit. Taking a token reference does not freeze token contents; the separate-query modification check is retained. Storage's observed truncate ran at PASSIVE_LEVEL and must not be attributed to this API restriction.

The private immutable operation-acquisition outcome contract/managed codec passes 108 validation checks and native compile-time layout assertions. It remains preparation only: commands 34/35, per-operation snapshots, bounded exact-file-object negative associations, journal/ACK durability, and SIEM attachment are not integrated or advertised. MUP provider enrichment, general SMB client/server correlation and final product-wide three-pass QA remain pending.

#### Supported token-session candidate: four-host local gate

WINDOWS-SUPPORTED-SESSION-FOUR-HOST-LOCAL-ACCEPTANCE-20261006-R1.json records PASS on Windows 10, Server 2012 R2 and both Server 2019 hosts: 60 strict independent operation/token matches, including 24 failed-open scenarios and 64 local executable/manifest pairs verified by hash and event/process/principal linkage. All four baseline driver images, load orders and settings were restored. Candidate AF2C27706C3CD8A6B2EE3FFEA85F233DC2BE54B0C756C8F91B68C7A0EF534958 uses the supported TokenSessionId query. Central verifiers run separately for each exact owned run; Desktop already has all 15 strict server matches but its complete central binary/manifest download set remains pending. This local gate does not claim every possible I/O context, permanent rollout, SMB/provider completion or full specification completion.

WINDOWS-ACTIVE-REQUEST-TIMING-0632-20261006-R1.json inspects 950 finished agent requests from the actual running .32 server log. Its sample has 286 capability responses, all HTTP 200, median 0.6914 ms and P95 8.5836 ms. Events and evidence request P95 were 8736 and 8503 ms respectively, with one cancelled request (499) in each category. Bounded active .32 stdout/stderr tails contain no observed SQLite failures. Central uploads have started advancing; the earlier NVR 64-process run has 4 complete central artifact/manifest pairs at 21:16Z, with others still pending. No claim of complete queue recovery or absence of all contention is made.

#### Four-host server record checkpoint

At the subsequent exact-run central progress checkpoint, all four supported-session candidate runs have 15/15 strict authenticated server record matches (60 total), with zero matching errors. Receipts: WINDOWS-SUPPORTED-SESSION-{NVR,Storage,DC}-CENTRAL-PROGRESS-20261006-R1.json and WINDOWS-SUPPORTED-SESSION-Desktop-CENTRAL-PROGRESS-20261006-R2.json. These matches include the independently verified process/thread/token evidence and preservation metadata. Only Desktop's first new central executable/manifest pair has been downloaded at this checkpoint; the complete central download gate is still running for all four runs. Database metadata or reported artifact hashes are not substitutes for downloaded-byte verification. The candidate remains a temporary qualification build and all baseline drivers are restored.

### 2026-10-06: upload retry persistence and supported-session verification

The corrected aggregate receipt is WINDOWS-SUPPORTED-SESSION-FOUR-HOST-LOCAL-ACCEPTANCE-20261006-R2.json: 60 cases, 24 denied-open cases and 64 local artifact/manifest pairs. R1's aggregate pair count was incorrectly calculated as zero; individual local receipts were retained and R2 sums their validated integer counts. The earlier paragraph naming R1 is superseded by R2 for this aggregate.

NVR, Storage and DC exact-run central receipts WINDOWS-SUPPORTED-SESSION-{NVR,Storage,DC}-CENTRAL-20261006-R1.json each pass 15 independent operation/token matches and 16 centrally downloaded and hash-verified executable/manifest pairs. Desktop's earlier central gate remains pending at this checkpoint. No complete four-host central gate is claimed yet.

EvidenceUploadQueue now persists a bounded versioned retry cursor across restarts so the first eight failed entries cannot indefinitely starve later entries. Corrupt cursor state is retained with an explicit recovery failure; a subsequent pump resumes without modifying evidence records. This cursor is only a scheduling hint, never an acknowledgement. The transfer fixture passes 176 checks (upload-cursor-fixture-r2.log); the initial fixture compile failure is retained in R1. No Windows power-loss atomicity claim is made for the cursor rename.

Windows sensor 0.6.21-dev was deployed on all four current hosts with settings, connection, native baseline and evidence retained. Pinned package SHA-256: C72DC1F9DB2E03712827DBE30274D8BF94C3AEB7C754BC5F0F375A70F9707E81; source-manifest SHA-256: BA506E6615C020C787A5093180236A13F94EDF87B8625CFED71F8CE6F33068CF. UPGRADE-WINDOWS-UPLOAD-CURSOR-{Desktop,NVR,Storage,DC}-0621-20261006-R1.json all pass. Fresh Desktop 0.6.21 operation execution and strict local token/artifact verification pass; the other three fresh operation runs and all fresh central gates remain pending. Desktop's temporary candidate/placement was restored. Linux has not yet received this shared queue change.

Manus's new decision memo and Microsoft source notes are saved as windows-minifilter-apc-attribution-decision-memo.md and windows-apc-attribution-decision-source-notes.md in the outer diagnostics folder. Documented token-reference/query APIs require PASSIVE_LEVEL; pended/synchronized/safe-post processing cannot guarantee an earlier APC accessing-thread token snapshot. APC events must retain explicit token-unavailable evidence. A separate SQ_APC_PIN_DIAGNOSTIC build now permits only the nonpaged immutable blob pin at APC and adds command 36 for a synthetic IRQL-branch test. The WDK warning-as-error build passes (apc-pin-compile-r1.log). It is not deployed or runtime-qualified and does not establish actual filesystem APC coverage. Ordinary builds retain the prior PASSIVE-only pin gate. No token API IRQL guard was relaxed.

Remaining: fresh four-host central and canary acceptance; APC runtime branch/callback qualification; per-operation acquisition-outcome integration; MUP provider/correlation work; qualified permanent driver rollout; Linux deployment/regression; UI and three-pass product regression. Evidence receipts reside in the outer diagnostics/windows-token-20260930 folder. These checkpoints do not establish complete implementation.

### 2026-10-06: APC branch runtime qualification and acquisition diagnostics

WINDOWS-APC-PIN-{Desktop,NVR,Storage,DC}-0621-EXECUTION-20261006-R2.json all pass and record baseline restoration. Each exact host performed 64 synthetic APC resident-blob pins and 64 releases, independently hash-verified a live actor executable copy, rejected an incorrect process start key and over-limit iteration request, and refused absent, acknowledged and stopped-provider bytes. No token query runs in the raised-IRQL helper. Actual filesystem APC coverage remains APC_CALLBACK_NOT_OBSERVED. Candidate SHA-256 278893B983998329282C85D7EB1F00735AC3E477789E648EEFCBA313F261224D; source manifest 40B5E7BAC2F411D8C97CB914D7D5863F7F13D17FA0C5375D769D381466993F4A. R1 remote tests failed before reader execution because PowerShell 5 treated the JSON manifest array as one pipeline item; their original receipts and successful baseline restoration remain retained. R2 also fixes APC missing-byte refusal reason to avoid incorrectly calling it an unsupported IRQL. Reader's initial build error and corrected builds are retained.

New acquisition diagnostic source now includes a 128-entry no-byte negative FILE_OBJECT association pool, exact process-create equality binding, one-attempt capacity handling, cleanup/TTL/shutdown reference release outside locks, mutable private process acquisition summaries and immutable per-operation outcome copies. Existing SB_BINDING remains 88 bytes. Commands 34/35 compile in an explicit AcquisitionOutcomeDiagnostic build; capability flags remain zero pending complete qualification and managed raw-first journal/ACK integration. Both native warning-as-error builds acquisition-native-compile-r1/r2 pass. This development source is not deployed. Native forced refusal/lifetime tests, stage contract edge cases and managed receiver/SIEM integration remain unfinished. No causal reason is inferred from global health counters.

All four fresh .21 local 15-operation token/artifact verifiers pass. Fresh central validators run independently; earlier Desktop central verification has advanced to 13/16 downloaded pairs at 22:08Z with no mismatch and three earlier hosts have all 16. Pending and failed gates retain their original status.

### 2026-10-06: completed four-host central checks and fresh callbacks

Both exact supported-session matrices have now passed all four hosts' central gates: WINDOWS-SUPPORTED-SESSION-FOUR-HOST-0620-CENTRAL-ACCEPTANCE-20261006-R1.json and WINDOWS-SUPPORTED-SESSION-FOUR-HOST-0621-CENTRAL-ACCEPTANCE-20261006-R1.json. Each separate matrix has 60 independently matched operation/process/thread/token cases and 64 executable/manifest pairs downloaded from the live server and independently hashed/linked. The .21 gate follows all four managed sensor upgrades. Original native baseline, placement and settings were restored. These are controlled PASSIVE-context operation tests, including actual failed opens and impersonation changes; they do not establish universal APC principal attribution, new private outcome support, MUP provider completion or product-wide completion.

WINDOWS-CALLBACKS-FOUR-HOST-0621-ACCEPTANCE-20261006-R2.json passes all 56 fresh callbacks (14 types on each of the four Windows hosts), with rendered artifact bindings, actual HTTPS requests, fresh server time/sequence, host/type/token and source-IP matching. No certificate bypass or response-status-only acceptance. This is protocol/receiver validation, not every artifact opened in its native application. R1's failed verifier receipt is retained: PowerShell's automatic JSON DateTime conversion lost UTC offsets when values were coerced back to strings. R2 explicitly preserves ISO offsets before parsing; server receipts were already present.

Manus revised the unpublished operation-outcome contract in windows-minifilter-operation-acquisition-outcome-companion-r3.md. Full-copy-capacity stage 3 remains valid after binding; source FileStandard/Basic/Internal query failures have distinct stages 7/8/9. An unbound failure is negative association evidence; only an already bound failure is state 3. The diagnostic native source now records exact source-query failures, immutable operation snapshots, copy-pending transitions, retained diagnostic origin IDs, and sticky bound terminal failures even if an in-flight entry expired before completion. The updated codec passes 123 checks (acquisition-outcome-codec-r2.log), and WDK acquisition-native-compile-r4 passes. Capability remains unadvertised (flags zero); the diagnostic build has not been loaded. Forced native state/lifetime qualification, durable companion journal/ACK, SIEM schema and central support remain required.

## 2026-10-06 — operation acquisition journal and qualification (in progress)

- Development schema adds `WindowsAcquisitionObservation`: explicit legacy/unavailable provenance or the exact immutable 128-byte native acquisition snapshot, provider/epoch/operation linkage, reason/stage/status, and validated SHA-256. Historical null containers retain their serialized bytes. It does not assert that an executable is safe or that it was preserved.
- Mandatory acquisition requirements are committed before raw intake; a valid companion is flushed and committed before native ACK. Missing or corrupt required companions retain raw evidence and withhold scheduling/ACK. Recovery does not silently relabel them as legacy.
- Fixture `acquisition-transport-r2.log`: 144 codec checks, 14 journal/restart/ACK checks, and 10 transport/queue/database checks passed. R1 compile failures are retained. Transport tests exercise capability/receipt rejection and isolated database persistence; they are not a deployed server HTTP acceptance claim.
- Native candidate D341A63C5C601E0ECB5F13B53D6B8201666F841BC9A4E0FFE50ACDEE6EC72E04 compiled from frozen source manifest A81B683725D386C2BCA4C4F5DEDE0F95375E0F1CD0C8C613451F44262218574D. Acquisition capability remains disabled.
- Actual NTFS read qualification passed on Desktop, NVR, and Storage: no fabricated preexisting-process association; exact pinned actor copy with matching SHA-256; queued observation unchanged after actor-copy ACK; later operation explicitly reports bytes unavailable; wrong provider/epoch/operation keys and acknowledged keys rejected; references drained; baseline driver restored and sensors resumed.
- DC qualification R1 failed before execution because C: lacked space during package extraction. Baseline restoration passed. Do not count the DC run as qualified. Capacity remediation and a fresh rerun are required.
- Remaining gates include negative association/failure and pool lifecycle qualification, actual filesystem APC coverage, managed/server deployment, Linux deployment, native-application canary activation, and final UI/product regression. New schema/journal source is not deployed by this checkpoint.

- Acquisition health extension: command 37 adds fixed 88-byte provider/epoch-qualified negative-association counters, live/reference balance, one-attempt associations and coalesced capacity gaps. Managed collection validates invariants and exposes gaps rather than guessing affected identities. Native and Client builds passed; this newer source is not in sealed D341 candidate and remains undeployed.
- `acquisition-health-fixture-r2.log` passes 156 codec/health checks plus the 14 durable journal and 10 transport/database checks. R1 deliberately corrupted a still-valid nonzero QPC and was an incorrect rejection expectation; retained R1 failure, corrected test requires zero gap time to reject a positive gap count.
- DC E: and F: expanded from 80 to 160 GiB with existing snapshots and OS disk unchanged; guest partition expansion verified. Completed QA archive migration retains hashes, permissions and original paths via junctions. R1/R2 hit Windows path-length handling and retained copies; R3 cleanup/recovery remains in progress. DC runtime test will use the expanded F: QA volume.

- Acquisition controlled read qualification is now PASS on all four Windows hosts: `WINDOWS-ACQUISITION-FOUR-HOST-0621-ACCEPTANCE-20261006-R1.json` aggregates 12 cases and 20 rejected keys. DC fresh R2 ran from F:, superseding only the disk-space-blocked R1 qualification; original R1 failure retained. All four restored the original driver and resumed sensors. Capability remains disabled; six-state failure qualification and managed deployment remain outstanding.
- DC capacity remediation completed: E:/F: expanded to 160 GiB; 13 completed QA directories archived to F: with every file SHA-256 verified, root permissions checked and original paths retained via junctions. `WINDOWS-DC-QA-ARCHIVED-20261006-R3.json` passes; R1/R2 path-length failures retained. No forensic evidence was discarded. Current capacity is recorded in that receipt.
- UI adds a Windows executable collection detail panel with availability, immutable reason/stage/status, exact source identity and raw operation/companion hashes. It does not imply safety or preservation success. Offline Event History DOM tests pass 48 cases; presentation regression passes 95 cases. Source change is not yet deployed.

- Server 0.6.33 deployed with R17 package SHA51DB269F33256E68984C378A2E7263ECCF0A1B87352F5D1F20A83F6B7806E6E6, frozen source B5519A87770ADEFF8A2004CB5D7EAC67EB4290AED4F109369D030BBF8A5CAD58. `DEPLOY-WINDOWS-ACQUISITION-SERVER-0633-20261006-R2.json` PASS: authenticated observation capability1, inventory/history retained, 30 web assets match, callback listener retained. R1 rolled back after the PS5 postflight lacked System.Security; R2 explicitly loads that assembly. Both backups and failure receipts are retained.
- Sealed R17 fixture passes156 codec/health,14 journal/recovery/ACK and15 transport/database/real authenticated HTTP checks. Packaged transfer regression passes176 checks (`acquisition-transfer-sealed-r17-r2.log`); initial parallel builds collided on shared obj output and were rerun sequentially. No runtime result was inferred from that compile failure.
- Windows 0.6.22 managed package is sealed, SHA FEF0C3B75A94E6005AAF33C998492857DB5FC69C4F62D6539BAA9BAA7666EADE, not yet deployed. Running Windows sensors remain0.6.21 with baseline driver80B647.../385200.923.
- Manus R4 qualification plan: public contracts do not establish process-create/post-CREATE ordering. Native states2/3 require an observed real nonterminal bind and an actual operation under that state; synthetic scalar transition checks do not establish callback acceptance. Passive phase instrumentation and private one-shot collection faults add no wait, actor selector or fabricated process callback. Faults never rewrite caller IoStatus and propagate explicit flag8.
- Native fault candidate07B5304CC08067D276B95B47997D3AD9171F8A4A886B80D4D70813B8E4540337 (source7A86ECDE64B1D8E8664D2D8DBD6D5F60A1FEED50AD96CD3FAABD4497B3057C78) is a qualification-only build. Desktop R1 passed nine actual owned process/read cases for collection failure stages1..9, exact real negative associations, no byte selector or hash claim, full SYSTEM tokens, caller success unchanged and reference drain. Baseline restored. Expanded R2 with natural ordering probe is running; other hosts remain pending.
- Independent object symbols verify private fault controls absent in a build without `AcquisitionFaultQualification`, present only in the opt-in test build. Neither build advertises acquisition capability yet. This is not a production fault-control deployment.

### 2026-10-06 Windows acquisition deployment and native failure qualification

Server 0.6.33-dev and all four Windows sensors 0.6.22-dev are deployed. UPGRADE-WINDOWS-ACQUISITION-{Desktop,NVR,Storage,DC}-0622-20261006-R1.json each records a passing upgrade with native state, settings, connection and existing evidence preserved. The native production baseline remains SHA-256 80B647264664701DB9A44AC68FF53FBF7E3FCFDB5FF2779857248910E950C995 at load order 385200.923; operation companion capability remains disabled.

WINDOWS-ACQUISITION-FAULT-FOUR-HOST-0622-ACCEPTANCE-20261006-R5.json passes 36 actual owned process/read collection-failure cases across Desktop, NVR, Storage and DC. Nine one-shot collection stages per host retain independently checked SYSTEM tokens, process PID/start and exact negative associations while the caller's successful I/O status remains unchanged. Each host also fills 128 distinct live FILE_OBJECT associations, observes explicit health-only overflow without fabricated actor attribution, and drains references on cleanup/STOP. All four original drivers were restored and sensors resumed. Qualification candidate F312EC41E35A8170AD28672AAFC4C1E89E97739F7E2F99EE219DFA87AA9E7FCC is never a production release: its fault controls are compile-time qualification controls.

NVR's earlier R2 global ordering sample failed; that receipt is retained. The R5 reader uses the exact provider/epoch/candidate/generation/PID/start query rather than a global latest sample and retains raw inputs before validation. Natural ordering probes do not establish native in-progress or post-bind failure coverage. Actual filesystem APC token coverage is still unqualified.

A separate candidate excludes fault controls (object symbols checked), SHA-256 8A5A48D2E87CB1E21AA13AAAA7A521D3D7BAF29BDD53103340037A3F2044A67C, source-manifest 290A50C7FD5F1702B362E173EE7C7E57FC79A5F04D1BF3D7A1408B5745A7DB06. Its fresh 0.6.22 operation/token and central evidence qualification is pending. No complete-product or all-sensor acceptance is claimed.

### 2026-10-06 Fresh 0.6.22 Windows operation and central evidence acceptance

WINDOWS-ACQUISITION-RELEASE-FOUR-HOST-0622-CENTRAL-ACCEPTANCE-20261006-R1.json passes all 60 independently validated file operations across the four Windows hosts and 64 centrally downloaded executable/manifest pairs. Each host covers four read/token contexts, write, append, rename, delete, truncate, and six denied-operation opens. Complete process-owner, thread-owner and effective-thread token facts match independent actor truth; core User/Process/PID and PID/start identity match. Preserved actor executable hashes and central artifact/manifest linkage match. Candidate 8A5A48D2E87CB1E21AA13AAAA7A521D3D7BAF29BDD53103340037A3F2044A67C excludes fault controls; original drivers and settings were restored after every run. This is controlled supported-version acceptance, not permanent driver rollout or actual APC coverage.

The release reader passes on Desktop/NVR R2 and Storage/DC R3. Its R1 Desktop failure was a test error reading undefined FilterSendMessage byte counts on failure; Microsoft specifies the count only on success. Storage R2 was held before driver change for evidence capacity; no files deleted. DC central R1 rejected the new F: QA root; R2 had a helper transfer path mismatch. R3 uses a pinned read-only locator accepting only the exact DC sensor for F:\Sequestor\QA\kernel-operations-* and passes. Original failed diagnostics retained.

WINDOWS-STORAGE-DC-EVIDENCE-QUOTA-0633-20261006-R2.json increases local evidence capacity to 4096 MiB. Storage retains its existing group assignment; the shared group also raises NVR's quota, retaining every other monitoring setting. DC receives an otherwise identical dedicated quota policy. Desktop already has 4096 MiB. The server process is unchanged and historical evidence/failures remain intact. R1 refused to reassign Storage's existing group; that guard failure is retained. The R2 receipt's short Scope string omits the NVR shared-group effect; its Changes.AffectedHosts and this checkpoint identify it explicitly.

Linux 0.9.18 managed package B2B64554292563B4F6B63B0672401D27A2EA8E80C0E4C00CF9B0009972303DA8 carries the shared delivery cursor. All 26 sensors pass read-only preflight. Backup, Plex and FreePBX pilots pass installed main/collector process identity, root-owned launcher/relay checks and exact configuration preservation; existing audit configuration/evidence remain intact. LINUX-MANAGED-0918-PILOT-SERVER-ACTORS-20261006-R2.json verifies 12 controlled read events with exact host/PID/parent/path/UID/EUID/FSUID and full core actor fields. R1's strict high-resolution timestamp lower bound rejected valid coarse Linux audit times; R2 bounds both ends by 50 ms and retains exact identity predicates. It does not prove durable process-start or operation-time hash binding for Linux Audit. The remaining 23 Linux upgrades and fresh callback/regression acceptance are pending.

Windows retirement recovery is in development: explicitly unavailable version-2 metadata retains the original raw operation/provider/epoch/hash and a newly observed local provider/epoch. Prior native query attempts remain null/unknown. Same-provider reconnect never downgrades mandatory companion evidence; corrupt or conflicting proofs remain held. A separate WindowsAcquisitionRecoveryVersion capability/receipt preserves compatibility with existing sensors. Development tests pass 156 codec/health, 21 journal and 16 transport checks; actual isolated HTTP, new package deployment and live recovery remain pending at this checkpoint. This new source is not in the deployed .33/.22 or Linux pilot package.

### 2026-10-06: recovery transport deployment and managed acquisition qualification

Server 0.6.34-dev and Windows sensor 0.6.23-dev are deployed on Desktop, NVR, Storage and DC. Recovery package source manifest: 22E9398DEB292C73CD3A275E2BC22A235401DE29EF5FE7A6BCFE09FA537CA77E. Server SHA-256 C38B9C8D00F92132BFB87482AF40397A487EE945DA14B4F282801386E7FCF15A; sensor SHA-256 3C7FDB41A2C9B410B3321CF3409E165B628F5550C3988D79BC96461268C7670F. Deployment receipts preserve settings, connection state, native image, load order, data, inventory and callback listener; 30 served web assets match. Existing broad history timeouts remain unresolved.

Recovery checks against the sealed server DLL passed: 156 codec/health checks, 21 journal/restart/ACK checks, 24 transport/database checks including authenticated HTTP. Retired-provider recovery retains the original operation and records native acquisition as unavailable with unknown prior query attempt, rather than inventing a native outcome. Live provider-restart qualification remains pending.

Three Linux 0.9.18 pilots passed 12 controlled honeypot reads with exact host/PID/parent/path/account matching and 50 ms bounded audit clock tolerance. Pilot callback acceptance matches all 42 cases at the server by fresh timestamp, source IP, host, type and token. The first callback verifier incorrectly expected the Windows test User-Agent version; its failed receipt is retained and R2 matches the actual Linux test User-Agent without weakening other checks. Callback tests use rendered artifact links and HTTPS protocols, not native opening of every file type. These audit reads do not establish executable hash/start identity or preservation. Remaining 23 managed upgrades and complete retests are running.

A separately frozen no-fault-control Windows driver candidate explicitly advertises acquisition companion V1 for managed qualification: SHA-256 3553B6211B2A6A246BEECA25A16CA15717DAA0C5035DD70AC441BAA89E9C5380, source manifest 60449A7EBE8A96A84F5DAA10D42DE80E13C82CEF326267450208256955ADC508. Default builds continue to disable discovery; advertised builds reject qualification fault switches. The deployed native baseline remains 80B64726... at load order 385200.923. Temporary managed qualification restores this baseline; permanent rollout and actual filesystem APC token coverage are not claimed.

### 2026-10-07 UTC: all Linux managed upgrades and fresh reporting acceptance

All 26 Linux sensors now run managed 0.9.18-linux-dev with existing native relay/configuration/evidence retained. Remaining-host receipt LINUX-MANAGED-0918-REMAINING-20261006-R1.json passes 23/23 upgrades after three accepted pilots. Fresh exact-list honeypot run R2 records 81 controlled reads; LINUX-MANAGED-0918-ALL-SERVER-ACTORS-RAW-20261006-R1.json passes all 81 authenticated raw API matches across 26 independently read enrollment IDs, PID, parent PID, path, executable, UID/EUID/FSUID and bounded audit timestamp. Zero missing core actor fields; largest absolute clock delta 21.053 ms. This does not establish audit executable SHA/start identity or executable preservation. Linux native kernel integration remains open.

LINUX-MANAGED-0918-ALL-CALLBACK-ACCEPTANCE-20261006-R2.json matches 364/364 fresh artifact/protocol callbacks to server host/type/token/source-IP/time records. R1 used the wider Ansible all inventory, which included ten machines outside the deployed sensor set; its failures are retained and it is not a pass. R2 uses exactly the 26 deployment targets. The first Linux history verifier used hostname rather than enrollment ID; the next exact-ID history request timed out. The raw API acceptance uses a hash-pinned read-only SQLite helper only for sequence/event-ID locators, never for evidence attribution. Broad history/UI performance remains unfinished.

All four Windows .23 managed acquisition local matrices pass 60 operations, with baseline driver/placement restored. Candidate 3553B621... advertises native outcome V1 and actual sensor records carry companion evidence. Central binary/manifest acceptance is still running because uploads are pending/time out. Do not treat local hash-verified preservation as central transfer completion. Desktop central R1 was stopped by the old helper hash pin; R2 pins the exact .34 helper. Full operation record hashes cover the extended record and must not be compared directly with the base-record-only hash.

Two completed DC agent upgrade staging roots were archived to F: with all hashes/ACLs checked and original paths retained as junctions: WINDOWS-DC-UPGRADE-EVIDENCE-ARCHIVED-20261006-R1.json, 179286052 bytes, live sensor retained. No actor evidence was removed.

Development server .35 adds an exact PID/endpoint/sequence index to avoid wide-payload scans for actor filters; PID remains an ephemeral filter, not process identity. History regression R2 passes 359 checks including query-plan selection, both directions, global/endpoint scope, null PID and snapshot paging. The initial fixture failed compilation on a local variable name collision; corrected R2 is retained. New package/deployment and live performance remain pending. No broad history or logout fix is claimed.

Manus APC subject-capture memo and Microsoft API contracts confirm that SeCaptureSubjectContext[Ex], token locking/querying and PsReferenceImpersonationToken require PASSIVE_LEVEL. Actual APC-level full token capture remains unsupported/unqualified; delayed worker identity must never replace the operation-time effective identity. Existing exact PASSIVE operation/token and denied-CREATE tests remain valid within their tested contexts. Documentation: diagnostics/windows-token-20260930/windows-minifilter-apc-subject-capture-implementation-memo.md and windows-apc-subject-capture-source-notes.md.

### 2026-10-07 deployed Windows reporting and recovery checkpoint
- Server 0.6.35 deployed with the exact PID history index; deployment retained 33 enrolled sensor records, authoritative data, callback receiver, and all 30 served assets. Broad history/action performance is still open.
- Windows sensor 0.6.24 deployed on Desktop, NVR, Storage and DC. Enrollment/heartbeat now use the assembly build version, replacing the incorrect hardcoded 0.6.21 value. Read-only packaged `--version` reports 0.6.24-dev; live inventory independently reports that version for all four sensor IDs.
- Actual native reads on all four hosts were interrupted before acquisition companion collection, then the driver was unloaded/reloaded and the real deployed sensor restarted. Each retained original raw evidence and dispatched the journal record. Baseline driver and settings were restored on all four hosts. Central recovery acceptance remains a separate gate.
- Fresh managed candidate Windows operation evidence is present locally for all 60 cases. Central artifact verification is still waiting for real upload receipts; no local-preservation-only pass is claimed.
- Controlled recovery probe first attempt failed because the sensor had already started the driver session. That failed receipt is retained; the corrected test leaves the sensor stopped during its private capture.

### 2026-10-07 history action index and central acceptance checkpoint
- All four Windows actual provider-retirement events passed authenticated raw API verification with original user/process/PID, process/thread start correlation, original raw hashes, and explicit version-2 unavailable companion evidence. Four live heartbeat versions verified as 0.6.24-dev. Exact PID page queries completed in 40 ms Desktop, 517 ms NVR, 64 ms Storage and 141 ms DC (see per-host receipts for authoritative timings).
- Fresh managed-candidate Desktop and NVR central verification completed: each 15 operation cases and 16 executable/manifest pairs received and independently hashed. Storage/DC gates remain running; no rollout completion claim.
- History action classification is now reused by query and SQLite derived indexes. Existing action labels and raw events are retained. History fixture passed with 10,000 wide events (8 KiB target path), exact counts, ascending/descending next-page ordering, five action filters, endpoint scope, reopened indexes and query-plan checks with no temporary action sort. Local ingest 44,838 ms; first+second 500-row pages 219 ms ascending/188 ms descending. Production performance remains a deployment gate.
- Retained failed verifier attempts: PowerShell array pipeline handling and console endpoint authentication were corrected; raw evidence was never changed to satisfy tests.

### 2026-10-07 installed native Windows and fresh callbacks
The no-fault advertised Windows driver 3553B621... is deployed on all four Windows sensors with managed 0.6.24 and the previously qualified temporary development load order 409801.923. Each upgrade preserved enrollment/settings and retained the prior driver image for rollback. Permanent Microsoft allocation and universal APC token capture are not claimed.

Fresh installed-version tests pass all 60 local durable operation cases with independently captured actor truth; settings restored. Central verification of these new cases remains pending. Prior managed-candidate qualification passes all 60 cases and 64 executable/manifest download pairs across all four hosts. Fresh Windows artifact/protocol callbacks pass 56/56 exact server matches after the upgrade (four hosts x14 types); native application opening of every type is a distinct pending gate.

Server .36 sealed HTTP tests pass, including manual action whitelists, log-only reads, unsuppressed writes, persisted actor evidence, source-event linkage and role restoration. Production deployment is processing its action-index migration and is not marked accepted yet. The source snapshot contains a documentation timing typo: the Storage PID query was 64 ms, corrected in the working QA document, not 264 ms. Per-host receipts are authoritative.

Linux native production preflight passes read-only inventory across 26 hosts: all current sensor units active, no native companion installed, 16 exact Debian 6.12.94/BTF matches and 3 exact Ubuntu 6.8.0-134/BTF matches. All inspected installation/target mounts are ext4; no monitored canary symlinks. Seven other kernel builds still need separate qualification. These admission observations do not establish native deployment readiness. Ten Debian native source files imported byte-for-byte from the qualified R18 archive into src/seQuester.LinuxKernel/Lease, with provenance manifest. No binary behavior changed.

### 2026-10-07 production history and Linux native checkpoint

Server 0.6.36 deployment passed: management healthy, 33 inventory entries retained, 30 served assets verified, callback receiver unchanged. Actual production action-history acceptance R1 FAILED three 90-second Windows/Linux broad queries; Plex action sorting returned 25 records in 35,215 ms and Windows denied-action filtering returned 25 in 2,278 ms. Index installation is not proof of acceptable production performance. A follow-up fix projects indexed values in the table branch and excludes a provably nonmatching service-evidence UNION branch; broad-query production verification remains required.

Production browser reaches sign-in without a TLS interstitial. Existing signed-in session was unavailable; signed-in presentation/session continuity has not passed. Hardcoded server display labels found at 0.6.20-dev; development source now reads actual server assembly informational version from /health/live, leaving unavailable explicit on failure. Static asset revision remains independent.

Fresh .24 Desktop central raw API matches all 15 independently recorded cases; actual executable/manifest downloads remain in progress. No fresh four-host central completion claim yet.

Exact deployed Linux .18 executable and libraries sealed for native installed-service qualification (optional desktop branding excluded): LINUX-MANAGED-0918-NATIVE-PAYLOAD-20261007-R2.json, raw tar SHA dbd008f0eaea2dd3197c6b39c684791d909b35eb92c917f38bdfdea4a99a9732. Owned isolated VMware Debian kernel/BTF verified, all four cached inputs hash checked, new raw tar reconstructed from 191 hash-verified runtime files. Native installed-service test remains running; no production Linux companion activated. Failed first package attempt retained because desktop Branding subdirectory violates the flat native qualification archive contract; corrected R2 excludes only desktop assets, preserving sensor/runtime file bytes.

Manus follow-up sent on Linux actual-operation hooks, DAC/LSM denied-open ordering, existing descriptor operations and effective credentials. Reply and implementation remain pending. Final three product-wide QA passes remain pending.

History projected-value R3 regression passed, including the wide 10,000-event fixture with real service-evidence storage, OS filtering, source exclusion, both sort directions, next-page snapshot/tie handling, exact action labels and combined-source totals. console.js syntax check passed. Server 0.6.37 source labels read live assembly version; package and production performance verification remain pending.

Fresh installed Windows central acceptance complete: WINDOWS-INSTALLED-FOUR-HOST-0624-CENTRAL-ACCEPTANCE-20261007-R1.json passes 60 independent full-token operation cases and 64 actual downloaded executable/manifest pairs across Desktop, NVR, Storage and DC, zero mismatches. Exact tested PASSIVE contexts and denied CREATE-open attempts only; universal APC/effective token and failed existing-handle operations are not established.

Server .37 deployed on F: with protected service read-only permissions, previous .36 retained and complete state backup. Management healthy, 33 inventory entries/30 assets retained; browser visibly shows actual 0.6.37-dev version. Production history performance still under validation. Server trace places long delays in SQL count/page paths. Follow-up .38 keeps counts on the covering endpoint index for scoped action sorting and retrieves received timestamps only for selected page rows; diagnostics emit count/page EXPLAIN plans without event data or parameter values. Covered-page regression and sealed HTTP acceptance remain pending.

Linux .18 owned VM controller lost Guest Operations process status (VMware InvalidState). The actual qualification continued: root/ordinary services active, native loader present, no failure.log observed; native work/server event counts were zero at last read. VM retained powered on; no forced unload/shutdown/revert performed. Recovery of exact test result and independently verified cleanup required. Production preflight now confirms BPF LSM present on 19 of 26 hosts; seven require supported boot/profile preparation before native activation. Manus R142 source-backed operation coverage design downloaded; no production deployment follows from its recommendations.


## October 07, 2026 - fresh deployed acceptance

All four installed Windows .24 sensors passed fresh local and protected server API tests: 60 operation cases and 64 actual executable/manifest download pairs. Each case matched independent process lifetime, PID, accessing thread, account/SID, owner and effective security context. This covers the tested PASSIVE-level contexts and denied CREATE/open attempts. Universal APC token capture and denied operations on already granted handles remain unqualified. Receipt: WINDOWS-INSTALLED-FOUR-HOST-0624-CENTRAL-ACCEPTANCE-20261007-R1.json.

Server .38 deployment passed with rollback retained. Five actual protected production history queries passed in 6771 ms (Plex action sort), 8270 ms (Windows action sort), 363 ms (Linux action sort), 4023 ms (Windows alerts), and 2841 ms (Windows denied actions). Earlier .36/.37 timeout receipts remain failures. PRODUCTION-ACTION-HISTORY-0638-20261007-R1.json retains timings and protected raw response locations. The browser displayed Server version: 0.6.38-dev. Authenticated browser filtering and session continuity remain separate pending checks.

The exact Linux .18 installed-service run against historical server R70 FAILED at check 88. The short-lived actor's locally correct log-only decision was rejected by the older server schema. All five events matched native source/actor facts; the complete-DTO policy input digest differed after older-schema deserialization. Tests of these same five captured events passed binding/digest checks with .18 and .38 contracts and failed with R70 contracts. See linux-trust-contract-probe-r3.log. A fresh .18/.38 installed-service run is in progress; no acceptance is claimed yet. The failed archive, actual native cleanup and restored VMware baseline remain retained.

The registration reply check verified the original Microsoft filter load-order request sent copy and found no allocation reply at 2026-10-07T01:44:02Z. Temporary filter number 409801.923 remains the tested deployment value. Final three whole-product regression passes and complete all-sensor native deployment remain pending.


## October 07 - server native policy setup

PRODUCTION-NATIVE-POLICY-ENABLED-20261007-R1.json passed: first policy identity initialized under the existing Network Service account, private key retained encrypted in the existing server data store, public key API verified, callback receiver PID unchanged. This enables server-signed Linux native policy transport; it does not establish sensor native deployment. The .18/.38 rehearsal R2 failed before native activation on a VMware 300-second upload timeout; VM powered off and baseline restored at 01:57:52Z. R3 uses the existing authenticated certificate-pinned guest upload method. The failed transfer receipt remains retained.


## October 07 - Linux pilots staged and live policy transport verified

LINUX-NATIVE-PILOT-STAGED-20261007-R1.json passed on ops01 and backup01: exact .18 executable/client bytes, Debian 6.12.94/BTF/module, root-protected native package, three existing target identities, and service group 59000 were admitted. Ordinary configuration remains unchanged; no native service or module was activated. Existing Audit monitoring remains active.

LINUX-LIVE-NATIVE-POLICY-20261007-R2.json passed on both enrolled pilots: normal certificate/hostname validation, exact request challenge and sensor/origin binding, current expiry, pinned public-key digest, and independent OpenSSL RSA-PSS/SHA256 signature verification. R1 did not reach the server because the generated probe contained a null source byte; its failure is retained. This policy transport test is distinct from native capture and executable upload qualification, which remains pending the .18/.38 VMware rehearsal.


## October 07, 2026 - exact Linux .18/.38 installed integration R4

The isolated Debian installed-service integration passed 102 actual assertions using the exact deployed .18 managed payload and .38 server payload. Manual whitelists were created before file events through the authenticated server interface. Two hash/path/user matches logged without alerts; three nonmatches alerted and preserved actor executables with actual central uploads and hash-verified binary/manifest downloads. All five short-lived actors matched User, Process and PID in both original and completion server records. Executable replacement and disappearance cases retained the original bytes. Targets were not hashed by the forensic collector.

Receipt: LINUX-INSTALLED-SERVER-TRUST-0918-SERVER38-20261007-R4.json. Archive SHA-256: d4a97c018d31ae494ca9ba2c1cb293bed552c89f280eee4283a6d4a7a2f16aca. Actual native cleanup confirmed five owned programs and eight maps absent, module/device absent, owned processes exited, and test server exited successfully. The R3 missing-import launcher failure remains retained separately; R4 reused and reverified the already transferred packages.

This is exact installed-service acceptance for Debian 6.12.94, local ext4 preopen/read coverage. Independent archive acceptance and VMware off/baseline confirmation follow separately. Production pilots are staged but have not been activated by this checkpoint. Full Linux operations, additional kernels, seven hosts without BPF LSM, native application canary activations, signed-in browser/session acceptance, and final three whole-product QA passes remain outstanding. Windows APC-level full token collection and failed operations on already granted handles remain explicitly unqualified. This is not a full product completion claim.


## October 07, 2026 - two production native pilots accepted

Exact installed-service Linux .18/.38 integration passed on both Debian 6.12.94 and Ubuntu 6.8.0-134: 102 actual checks and 580 independent checks on each kernel. Both isolated VMware guests shut down and restored their owned baselines. Debian archive d4a97c018d31ae494ca9ba2c1cb293bed552c89f280eee4283a6d4a7a2f16aca; Ubuntu archive 3f3cd8357f85d6f1cd6e48a7c6cdd08e30939ed025383970e9624c94560dd827. This qualifies local ext4 preopen/read, signed server policy, and hash/path/user whitelist cases; it does not qualify every Linux operation.

Production native collectors are now active on ops01 and backup01 alongside the existing ordinary/Audit collectors. Twelve real reads (three existing honeypots per host, root and rfclient) matched User, Process, PID, process lifetime and actor executable hash. The actual protected management API matched all 24 original/completion events. Twelve actor executables and twelve manifests were downloaded and their hashes verified. Twelve original events have alert notification types, alert disposition, detection rule IDs and reason codes. No target hashing or preservation was enabled by these tests.

Production trust remains the existing audit-only policy; original classifications are PolicyUnknown, and forensic completion records are Informational. This is explicit policy state, not a clean verdict. Enforced manual whitelists were proved separately in both isolated installed-service integrations. No production allowlist or enforcement mode was changed for these pilot tests.

The first activation helper failed because it sampled a not-yet-created status file. A fresh readiness check passed without a second activation; the helper now waits through that transient state. The first central validator excluded forensic completion events with its source filter and was canceled after the corrected validator passed. Its null output is not a pass. The Windows operation wrapper now rejects empty/null results. All original receipts remain retained.

Expansion to fourteen additional matching Debian hosts is undergoing fresh read-only admission checks. Other kernels, seven hosts without BPF LSM, full Linux operations and denied access, native application canary activations, signed-in browser/session verification, Windows APC full-token coverage, failed operations on existing Windows handles, Microsoft filter load-order registration response, and final three whole-product QA passes remain outstanding. No full-project completion is claimed.


## October 07, 2026 - sixteen production Debian native sensors accepted

Fourteen additional Debian 6.12.94 sensors now run the qualified native preopen/read collector alongside the existing ordinary/Audit sensor. All fourteen passed fresh kernel/BTF, executable, enrollment, target, service and signed-policy admission checks, then actual activation/readiness checks. Each host passed six real reads: three existing honeypots, root and rfclient (UID 999 on nginx01; actual per-host IDs retained). All 84 cases matched User, Process, PID and process lifetime locally. The protected production server matched their original/completion events, alert notifications, rule IDs and reason codes; all 84 executable/manifest pairs were downloaded and their hashes verified. With ops01 and backup01, sixteen Debian hosts have passed 96 real reads, 192 corresponding central events and 96 downloaded actor/manifest pairs.

The first staging attempt failed before native activation because an artifact-loop variable replaced a host admission record. Its failed receipt remains. The corrected recovery verified existing root-owned staged bytes and finished staging; the R2 stage and R1 activation/read/central receipts passed. The current server trust policy remains audit-only/revision zero: PolicyUnknown is explicit, not a clean verdict. Target files were read only; no target hashing/preservation was enabled.

Acceptance scope is local ext4 preopen/read on this exact Debian kernel. Ten other Linux sensors still need exact kernel/profile preparation and native deployment. Full Linux operation/denied-access coverage, Windows APC full-token collection and failed I/O on existing handles, genuine native application activations for all canary mechanisms, signed-in production console/session and whitelist publishing, Microsoft filter load-order registration response, and three final product-wide QA passes remain outstanding. No full-project completion claim.


## October 07, 2026 - native policy expiry failure and recovery work

A fresh readiness check after the .39 server deployment found all sixteen production Debian native companions failed. Ordinary/Audit sensors remained active. The saved native outcomes establish LINUX_NATIVE_POLICY_EXPIRED_OR_REVOKED on all sixteen: complete work drain, zero pending work, no outcome errors, successful controller/child/map closure, absent module/device and independently absent known BPF resources. The previous 96-read/192-event acceptance remains historical; it did not prove recovery after a server outage. Do not interpret the earlier active wording as current readiness.

Guarded recovery starts only the unchanged admitted .18 collector after verifying those actual closure records, executable/unit hashes, installation admission and retained ordinary configuration. New file operations and central evidence must be tested after recovery. Recovery is not itself new detection acceptance.

Linux .19 adds a reserved service exit (75) only for fully closed policy-expiry outcomes with complete raw recovery and no pending/error state. The packaged systemd unit uses RestartForceExitStatus=75 while retaining Restart=no for all other failures; crashes, startup failures and unresolved native ownership cannot authorize automatic restart. A fresh process still requires newly signed policy admission. Compilation and thirty classification/configuration checks passed. Actual installed VMware outage/expiry/recovery qualification is running; .19 is not production-qualified or deployed at this checkpoint.

Server .39 includes the Excel callback workbook fix: an external worksheet background was rejected by real Excel, so generation now uses a linked DrawingML image relationship. A twenty-check document fixture and the packaged receiver suite (260 checks) passed. Real Word and Excel opens produced fresh production callbacks with matching token/host and source IP; Excel was also tested using the exact packaged server DLL. These successes do not qualify all fourteen native document/application mechanisms. Live protected Windows/Linux filter queries passed; signed-in production browser/session acceptance remains pending.

Remaining product gates include .19 outage recovery deployment and fresh server evidence, the ten other Linux kernel profiles/deployments, full Linux operations/denied access, Windows APC-level full token capture and failed I/O on granted handles, all native canary mechanisms, genuine signed-in production console/whitelist publication, Microsoft filter load-order registration response, and three final whole-product QA passes. No full-project completion is claimed.


## October 07, 2026 - server .40 policy renewal correction

The Linux policy-expiry failure repeated after manual restart. Actual authenticated native-policy requests timed out behind SQLite writer admission. Server .40 moves the exact read-only signed-policy POST out of writer admission, prepares trust storage before listening, and obtains its consistent SQLite snapshot in a deferred read transaction. Authentication, nonce, origin, RSA-PSS signing and bounded policy expiry remain enforced. A real held-writer regression reproduced the old failure and passed twelve fixed checks; eighteen SQLite admission checks and 260 packaged receiver checks passed.

The .40 server package deployed with all 33 enrollment identities preserved, all thirty served assets matching and the callback process unchanged. Two real Linux sensors independently verified signed responses in 0.213 and 0.313 seconds within the ordinary fifteen-second deadline. Guarded restart succeeded on all sixteen affected native sensors after confirming prior native resource closure. Fresh 96-read local and protected central evidence tests are running; restart alone is not detection acceptance. Linux .19 automatic clean-expiry recovery remains under actual installed VMware qualification and is not deployed.

The latest four-host Windows matrix against .39 passed sixty operation cases and verified 64 downloaded executable/manifest pairs. This covers primary/impersonated read variants, writes, append, rename, delete, truncate and denied CREATE/open variants with independent process/token truth. It does not establish failed operations on already granted handles or APC-level full-token capture. The server .40 deployment follows that matrix, so final post-update product acceptance is still pending.

Manus reviewed the proposed deferred PASSIVE worker query of a referenced APC request thread. It preserves object lifetime but observes query-time security state, which can change after interception. Microsoft documents PsReferenceImpersonationToken at PASSIVE_LEVEL, SetThreadToken can change another permitted thread, and deferred work cannot post paging or unsafe top-level operations. The supported query is not a historical token snapshot and must not backfill operation-time evidence or authorize whitelist suppression. Source-backed memo: diagnostics/windows-token-20260930/windows-minifilter-apc-deferred-thread-query-review-20261007-r1.md. No universal Windows token guarantee is claimed.

All previously recorded remaining gates and three final whole-product QA passes remain open. Current receipts are immutable; failed helper/qualification attempts remain available with their corrected successors.

## October 07, 2026 - fresh server .40 Linux evidence acceptance

All sixteen recovered Debian native sensors passed six actual honeypot reads each: root and the ordinary account across three existing targets. The protected server API matched all 192 original/completion event records for 96 cases, including exact User/Process/PID and process-instance evidence. Ninety-six executable/manifest pairs were downloaded from the central store and verified against the independent actor and local preservation hashes; all 96 original operations carried alert notification, rule and reason evidence. A later readiness sample found both ordinary/native services active and signed policy accepted on all sixteen. Two real signed-policy requests during the reads independently verified TLS/RSA-PSS in 0.222/0.228 seconds. This qualifies local preopen/read and central evidence for these exact hosts; other operations and the other ten kernel profiles are not included.

Installed .19 recovery qualification R2 failed before active readiness: policy expired during source startup, and the service propagated a startup exception after cleaning up instead of taking its reserved recovery exit. The archived failure and actual module/device/BPF closure are retained; the owned VMware guest returned safely to its baseline. A typed policy-expiry startup unwind now returns only a strictly recovery-qualified closure outcome, and leaves unrelated errors, missing outcomes, pending work and uncertain resources as failures. Thirty-two portable checks passed. New .19 R2 package and the exact .40 Linux server are under installed outage/recovery qualification R3. The recovery package remains undeployed and not yet accepted.
## October 07, 2026 - actual Windows existing-handle denial coverage

Six direct Win32 operations were attempted on insufficient-access existing handles on each of the four current Windows hosts: read, write, append, truncate, rename and delete. Each independent actor successfully opened under SYSTEM, then attempted the operation while impersonating LOCAL SERVICE. All 24 returned native ERROR_ACCESS_DENIED (5) and left the owned files unchanged. Sensor settings were restored and services remained running on every host. Protected raw server API checks confirmed all 24 opening events with the opening token, but observed zero matching failed-operation events with the attempted-operation token. DetectionPassed is explicitly false on every host. Opening records are not evidence of the later LOCAL SERVICE attempts.

This narrows the previously unconfirmed gap to actual existing-handle failures on the tested Windows builds and paths. It does not prove every possible filesystem-generated denial is absent, nor does it qualify APC token capture. Manus reports that 4656 concerns handle requests, 4663 has no failure events, 4658 records close, and the public ETW/object-callback contracts do not provide the full operation-time owner/effective token evidence for a rejection that never reaches a filter. The source-backed reports are retained as windows-existing-handle-failure-coverage-review-20261007-r1.md and windows-existing-handle-failure-source-notes-20261007-r1.md in diagnostics/windows-token-20260930. No later token query, successful open or invented record fills this gap. Further filesystem-failure and synchronous/overlapped qualification remains pending.

The prepared www-legacy Ubuntu 6.8.0-134 host rebooted gracefully with BPF LSM enabled and all five preexisting security LSMs retained. Initial immediate acceptance observed Docker still starting and failed; a later guarded check found Docker, Apache, SSH, audit and the ordinary sensor active and all four prior Chatwoot containers running, requiring no service or configuration changes. This is boot-prerequisite acceptance only; native module activation and detection acceptance remain pending.
## 2026-10-07: failed existing-handle operation qualification

Eight real byte-range-lock read/write failures passed across Desktop, DC, NVR and Storage. Independently observed native Win32 error 33; production server records matched the exact PID/start time/thread and all nine captured primary/effective token fields, query success codes and impersonation state. The process owner was SYSTEM and the accessing thread was LOCAL SERVICE. Receipts: WINDOWS-DESKTOP-LOCKED-GRANTED-HANDLES-CENTRAL-20261007-R1.json and WINDOWS-OTHER-THREE-LOCKED-GRANTED-HANDLES-CENTRAL-20261007-R1.json. All four sensor configurations restored exactly.

This does not qualify insufficient handle-permission rejections: six real error-5 calls on each host produced 24 successful-opening records and zero corresponding failed-operation records. Opening evidence must not substitute for the identity of a later rejected call. Independent ETW qualification is in progress. No blanket denied-access or APC-level token completion claim is justified.

Ubuntu www-legacy now runs its unchanged qualified 6.8.0-134 kernel with BPF enabled and all five previous security LSMs retained. Fresh preflight confirms the exact BTF, local ext4 targets, protected .18 package, existing enrollment and ordinary services. Native staging/activation and fresh central evidence acceptance remain separate pending gates.
## 2026-10-07: independent Windows file-I/O ETW experiment

WINDOWS-DESKTOP-EXISTING-HANDLE-ETW-MEASUREMENT-20261007-R1.json: actual Windows 10 trace, 234,660 events, zero events lost, successful same-target read control. Sequential IRP begin/completion correlation clears pointer reuse and binds exact fixture PID. All six insufficient-rights operations returned native access denied but had no failed file-I/O ETW completion. This independently confirms the missing class on this Windows version; it does not establish the exact rejection component or prove other event sources cannot work. ETW contains no operation-time token; opening identity is never reused as a failed-operation identity. Raw protected ETL/XML, independent fixture truth, decoder summary and correlated owned rows retained. Failed helper attempts remain retained separately.

Ubuntu www-legacy staging initially failed because its qualified BUILD.json has a different metadata schema from the Debian build. Exact-byte resume passed before activation. UBUNTU-WWW-NATIVE-STAGE-20261007-R2.json and UBUNTU-WWW-NATIVE-ACTIVATION-20261007-R1.json now pass: exact qualified Ubuntu R19 native module, managed .18 package, existing enrollment and signed policy accepted. Fresh local reads and central artifact verification remain pending.

Server process-history performance work is in development: a compact actor-process expression index preserves raw event evidence and avoids repeated wide-payload JSON decoding for process filters. Not deployed; correctness, query-plan and packaged regression gates remain pending.
### 2026-10-07: server .41 deployment and Linux policy handoff qualification
- Deployed exact 0.6.41-dev package R26 (SHA256 7F750F7138C01E4D95E2E3636CBFA8DE079738471E0140803A2700FB5A74A26C). Protected signing key and existing authoritative E: database retained; 33 endpoint identities preserved, event watermark advanced, all 30 served web assets matched, callback receiver PID 1408 unchanged. Deployment receipt DEPLOY-WINDOWS-PROCESS-HISTORY-SERVER-0641-20261007-R1.json.
- Frozen package gates passed: EventHistory 378, canaries 260, server 156, SQLite admission 19, native policy 12. These isolated gates do not establish every native canary application or complete product acceptance.
- Actual authenticated production processContains queries passed across all four Windows sensors: correct actor evidence, counts, stable snapshots and nonoverlapping cursor pages. First requests took 5.068-24.508 seconds; second pages 306-375 ms. Slow initial requests remain visible rather than being described as uniformly fast. SERVER41-LIVE-PROCESS-FILTERS-20261007-R1.json.
- Newly activated www-legacy Ubuntu sensor passed six actual root/ordinary-user honeypot reads, six server alerts and six exact central executable/manifest download pairs. UBUNTU-WWW-NATIVE-READS-20261007-R1.json and UBUNTU-WWW-NATIVE-CENTRAL-20261007-R1.json. Scope remains qualified local ext4 preopen/read.
- Linux installed recovery R3 failed before source registration. Policy exchange cancellation invalidated startup authority; no monitored reads occurred. Actual cleanup verified module/device/BPF/process absence before VMware shutdown and baseline restoration. LINUX-INSTALLED-POLICY-EXPIRY-RECOVERY-0919-SERVER40-20261007-R3.json is a failed qualification, not a pass.
- Corrected startup publication so it occurs only after the accepted policy reply is written successfully; failed unconfirmed bindings can be replaced by a newly verified exchange. Dedicated native-policy HTTP budget 60 seconds, IPC exchange budget 90 seconds; challenge expiry, signature verification and policy expiry remain enforced. New .19 R3 build SHA256 9f343a430609091c2a41f90acd227cfc6a8789f622fef93569b22a032305f314 remains UNQUALIFIED and undeployed pending installed lifecycle QA.
- Actual isolated Linux socket fixture R75 passed 79 checks, including cancellation after durable admission never publishing revoked startup authority. Production native service unchanged. LINUX-POLICY-SOCKET-R75-20261007-R2.json. Installed outage/recovery qualification R4 is separate and still running.
- Server index initialization caused native policies to expire on deployed .18 collectors; ordinary clients remained active. Read-only first readiness gate failed. Closed-resource verification and controlled restart are in progress; no force unload or automatic-recovery completion claimed.
- Separate legacy desktop selftest failed its watcher/integrity attribution assertion. Root app.manifest is also absent. Neither failure is suppressed or counted as a pass; investigation remains open.
- Full Windows accessing-thread token capture outside qualified PASSIVE callbacks and insufficient-rights existing-handle rejected-call coverage remain unresolved. Corrected Manus report corroborates the scope: independent ETW qualification is Windows 10 only, while minifilter rejection/lock tests cover all four hosts.- Follow-up: all 16 Debian collectors and www-legacy restarted only after exact previous closure/BPF/module absence checks (LINUX-NATIVE-SERVER41-CLOSED-SESSION-RECOVERY-20261007-R1.json and UBUNTU-WWW-NATIVE-SERVER41-CLOSED-SESSION-RECOVERY-20261007-R1.json PASS). Later readiness sample found one transient ops01 health timeout with both services active and signed policy accepted; not a universal readiness pass. Fresh read tests are running.
- All four Windows .24 sensors passed fresh local 15-operation matrices after server .41, with original settings restored. Actual central token/acquisition/download validation remains a separate running gate.
- Legacy desktop build manifest restored with standard asInvoker behavior; no elevation/security policy changed. Outdated self-tests corrected to retain partial detections with explicit unavailable actor fields and validate now-supported generated DOCX/XLSX/PDF callbacks. Actual GUI process was explicitly awaited and exited 0; DESKTOP-SELFTEST-R4-20261007-R1.json and isolated test-results/latest.txt retain the pass. Earlier failure receipts remain preserved. Isolated render validation is not native external callback acceptance or a production desktop deployment.
- Fresh .41 Linux acceptance completed: all 102 actual reads, 102 server alerts and 102 independently downloaded central actor-executable/manifest pairs passed across 17 native hosts. LINUX-SERVER41-NATIVE-CENTRAL-20261007-R1.json. Post-read readiness also passed all 17 (LINUX-NATIVE-SERVER41-POSTREAD-READINESS-20261007-R3.json). Prior failing samples retained; no broader operation/profile coverage claimed.
- Installed recovery R4 stopped during package reconstruction because immutable server delta cache references pointed at r3 while the controller extracted files to r4. No native activation occurred. Owned VM gracefully powered off and original baseline restored 06:30:50Z. Corrected R5 preserves the plan's exact cache path, omits encoded source in future error displays and saves a verified package-only powered-off cache before native activation. R5 qualification remains pending; .19 is not deployed.
- Production browser UI rechecked through the existing in-app browser: reload displays 0.6.41-dev and the genuine sign-in form. There is no signed-in production console session; authenticated manual whitelist/UI acceptance remains pending, with no guessed credentials, account creation, password reset or session bypass.
- Windows central batch R1 encountered a test-helper filename collision with the simultaneous Linux validator. It stopped without passing Windows central acceptance. R3 uses a Windows-specific immutable helper pathname and a corrected explicit artifact counter; raw protected API/token/download validation is rerunning. Linux central acceptance had already completed with its intended validator.
- Windows .41 central R3 acceptance PASS: all 60 independently executed operations across the four .24 Windows hosts matched exact raw server process/thread token and immutable acquisition evidence; 64 central executable/manifest download pairs verified. WINDOWS-SERVER41-FOUR-HOST-MANAGED-CENTRAL-20261007-R3.json. Original settings restored on every host. Qualified PASSIVE callbacks and denied CREATE are covered; APC historical token snapshots and the separately measured pre-IRP insufficient-rights rejection gap are not implied by this pass.
## 2026-10-07 native browser and client canary qualification

- Actual native browser consumers triggered seven of eight selected mechanisms on DESKTOP-6U8VLDH: SVG, embedded web image and bug URLs, copied JavaScript, copied stylesheet, fast redirect and slow redirect. Raw receiver records 2716-2722 match exact original token IDs, HTTPS and source 10.81.200.250. NATIVE-BROWSER-CANARY-ACCEPTANCE-20261007-R1.json retains original artifact hashes, activation basis and the negative PDF result. Plain URL text requires embedding/use; plaintext opening is not an automatic callback. Redirect callbacks arrived before the deliberate example.invalid destination failed DNS; the browser error page was blocked from further inspection.
- Opening the exact PDF artifact in the in-app browser produced no new receiver record. No PDF security setting was disabled. That reader/opening scenario remains unqualified; this does not establish the behavior of Acrobat or other PDF readers.
- Three further actual consumers passed local execution and raw receiver confirmation: QR independently decoded with zxing-cpp 2.3.0 and followed in the browser (2724); unchanged kubeconfig used by official SHA-verified kubectl v1.35.0 returns expected Forbidden; unchanged MCP configuration used by official Python MCP SDK 1.26.0 initializes protocol 2025-06-18, lists zero tools and pings. NATIVE-SDK-CANARY-ACCEPTANCE-20261007-R1.json records exact receiver sequences 2723-2725 and source IP. Initial MCP attempt using OpenSSL trust failed certificate validation; final attempt uses Windows CryptoAPI through truststore, preserving hostname/certificate checks and existing trust stores. No receiver change was required.
- This is one Windows host, not native acceptance of every mechanism on all Windows/Linux hosts. Installed Linux .19 R3 policy-expiry recovery R5 remains running; no production .19 deployment or recovery acceptance is claimed yet.

- Windows native WebDAV consumer PASS: first attempt returned 67 with WebClient stopped. Temporarily starting the existing Manual service allowed WNetAddConnection2W to connect with only the canary decoy credentials, read the exact synthetic inventory, and disconnect successfully. Receiver callback matched source 10.81.200.250. All connected resources were independently enumerated as zero, then original WebClient Stopped/Manual state restored. No persistence, trust, authentication policy or security setting changed. WINDOWS-NATIVE-WEBDAV-CENTRAL-20261007-R1.json. PDF browser screenshot showed a blank surface: actual PDF rendering was not established in the in-app browser, so that opening is unqualified rather than proof of an Acrobat failure.

- Fourteen-mechanism native consumer matrix now records 13 qualified mechanisms on the development Windows desktop, with PDF unqualified (blank in-app browser surface). Existing native Word/Excel receipts are explicitly distinguished from today's browser/SDK/WebDAV receipts. CANARY-FOURTEEN-NATIVE-CONSUMER-MATRIX-20261007-R1.json has Passed=false; no claim of 14/14 or all-host native qualification. These copied-and-used canaries do not report User/Process/PID through callback HTTP alone; local sensor evidence and callback source IP are distinct evidence sources.

- PDF source check: the renderer emits a documented page additional-action O URI action (Adobe PDF Reference table 8.39: https://opensource.adobe.com/dc-acrobat-sdk-docs/pdfstandards/pdfreference1.5_v6.pdf). Reader internet-access restrictions remain material (https://www.adobe.com/devnet-docs/acrobatetk/tools/AppSec/external.html). The blank in-app browser test does not justify changing the PDF action or disabling those protections. Acrobat native viewer acceptance remains pending.

- Installed Linux recovery R5 preparation advanced: all four exact packages fsynced/hash-verified, guest gracefully powered off and package-only snapshot VirtualMachineSnapshot-snapshot-15024 created. VMWARE-PACKAGE-CACHE-0919R3-SERVER40-R5.json records no native activation at that snapshot. Installed qualification has not yet produced acceptance; .19 remains undeployed. Read-only concurrent guest inspection R2 returned operation not allowed in current state; independent vCenter hardware check showed the owned VM PoweredOn with VMware Tools running. No unsafe shutdown or source detachment used.

- Installed recovery R5 FAILED, retained exact archive SHA256 04f411e750caebf6b77a71a417d6c9c70e0e16a73924f07b5ffb3d8bb7c1893c. It passed 32 setup/source checks, including actual installed BPF program/map identities, root module journal ownership and cap-free ordinary worker signed policy relay. It stopped before monitored operations because the isolated admin-creation HTTP client timed out at 30 seconds. Server log subsequently shows account/role/audit writes completing (0-2ms SQL commands) and response cancelled at 48.520 seconds. The split between cold-start/password computation and host scheduling is not yet established; no production performance fix is claimed. Actual native program/map resources fully closed, module/device absent, all owned processes exited, VM gracefully powered off and original baseline restored 07:30:20Z. R6 reuses the exact verified package-only snapshot and changes only bounded QA identity client budgets to 90 seconds with request timing logs. Cryptographic challenge/policy expiry, native capture, cleanup and production binaries remain unchanged. R6 installed qualification is running; .19 remains undeployed.

- Permanent filter number registration mail remains pending. Targeted reply query at 07:14:16Z succeeded, sent copy verified, no Microsoft reply. Additional read-only transport check failed/timed out; delivery is not asserted from the sent copy or absence of reply. Failure outputs retained; no duplicate registration email sent.


- Installed recovery follow-up: R6 remains running, not accepted. Review found a QA counter defect: the six-operation matrix contains two LogOnly decisions and four alert evidence pairs, including post-outage; old final check incorrectly expected three pairs. Prepared immutable R7 worker/controller with exact evidence-ID set comparison and progress metadata. Frozen sensor/server/native packages and cryptographic/lifecycle gates unchanged. Python/controller syntax checked; installed rerun remains pending. Independent archive validator prepared to verify raw server User/Process/PID, exact four actor/manifest hashes, real expiry/resource closure, fresh process and VM baseline restoration before any .19 deployment. Read-only concurrent guest progress inspection R2 failed with VMware operation-not-allowed; main controller still reports owned process alive, which is not acceptance.
- Registration queue-only check succeeded at 07:46:36Z: no pending daniel-to-fsfcomm message, no message sent. This does not establish external delivery or a permanent number. MICROSOFT-FILTER-REGISTRATION-QUEUE-CHECK-20261007-R3.json.


- Read-only VMware counters 07:52:00-07:53:20Z establish scheduling contention during R6: CPU-ready summation divided by four vCPUs and 20-second intervals gives average per-vCPU 40.60-50.09 percent (mean44.60). VMware swapped/ballooned memory both zero in sampled intervals. LINUX-INSTALLED-RECOVERY-VMWARE-PERFORMANCE-20261007-R1.json and READY-ANALYSIS receipt. No guest command or configuration mutation. This establishes current scheduling delay, not the exact historical R5 identity-request latency split. Vendor interpretation: https://knowledge.broadcom.com/external/article/387750/understanding-the-cpu-ready-values-in-th.html .


- R6 read-only VMware R2 confirms host CPU use 43894MHz /43880MHz, no VM CPU limit (limit -1), normal4000 shares, zero maxlimited time; aggregate co-stop4406-7590ms per20sec across4vCPUs. Prepared R8 for the same powered-off owned VM:2vCPUs/2cores per socket, custom aggregate4000 shares retained, reservation0/unlimitedCPU/memory16GiB unchanged. Exact original4vCPU baseline restoration required after fully verified closure. Installed PowerCLI Set-VM parameter/SDK types checked and controller syntax passes. No running VM or production configuration changed; R8 remains dependent on actual R6 safe closure. Uses R7 artifact-count correction and same four frozen packages, TLS/challenge/lease/deadlines.


- Later production readiness check FAILED:17 records received,15 native services failed while ordinary workers remained active; native health UNAVAILABLE:Win32Exception on stopped hosts. LINUX-NATIVE-SERVER41-DURING-RECOVERY-READINESS-20261007-R1.json. Earlier17/17 pass remains historical only. Current shutdown causes/resource closure under investigation; no restart or new .19 deployment claimed.


- Repeated production loss diagnosed:15 stopped native sources recorded COMPLETED, pending0/errors0, LINUX_NATIVE_POLICY_EXPIRED_OR_REVOKED following07:04-07:05Z root policy EndOfStreamException. Ordinary sensors stayed active. Readiness had passed06:28Z; no sustained uptime is inferred. Transport interruption/expiry is established, exact underlying endpoint delay cause remains unconfirmed. Guarded recovery R3 PASS15 hosts: all prior closed sources/known programs/maps/module/device absence and exact .18 executable/unit/installation checked before start; fresh signed relay and module ready afterward; ordinary configuration unchanged. Active scanopy_trusted01 and ddi01 excluded. Ubuntu prior clean manual stop preserved; latest session required expiry. LINUX-NATIVE-SERVER41-REPEATED-EXPIRY-CLOSED-RECOVERY-20261007-R3.json.
- Installed .19R3 recovery R6 reached112 passing checks and6 actual operations,2LogOnly/fouralerts, exact central User/Process/PID, and4 independently hash-verified actor/manifest pairs. New process64247 replaced31637 only after actual policy expiry/native closure; signing key unchanged. Overall remains FAILED at known QA count3 instead4. Archive fee1890f7485f03634416152fc298e41e50c76a130fd5f7e58fbd9082f36fd28; independent read-only archive review saved. Account creation42.48s/login36.54s/manual policy39.14s succeeded with90s QA budget. All owned10programs/16maps/module/device/processes returned; original VM baseline restored and PoweredOff08:07:01Z. R8 corrected full installed run started with exact packages on owned2vCPU VM after safe closure; .19 not yet deployed.


- Production native recovery follow-up17/17 ready PASS: LINUX-NATIVE-SERVER41-REPEATED-RECOVERY-POSTREADINESS-20261007-R1.json. This is a sample after guarded15-host recovery, not sustained uptime.
- .19 upgrade preparation: immutable candidate staging and gated graceful source/ordinary shutdown helpers drafted; syntax only, not executed. Independent exact delta reconstruction using the actual deployed .18 app cache passed191 reused members and232 .19 member hashes, raw tarSHA9f343a430609091c2a41f90acd227cfc6a8789f622fef93569b22a032305f314. LINUX-MANAGED0919-PRODUCTION-CACHE-RECONSTRUCTION-20261007-R1.json. No links/services/installation/keys/evidence updated. .NET apphost bytes alone are unchanged across .18/.19, so helper guards require exact Client.dll hashes as well as full candidate manifest. Current .19 activation draft depends on installed runtime PASS and independent review; fresh upgraded-host operation/callback tests remain required.


- R8 installed qualification FAILED before enrollment/native activation:4 checks,0operations, server did not become ready within300s. Archive beb2a81b66adfadcb1c838557afc33ef33bf31c75e73caf5fdad5064aa61685d independently hash-checked. Server log shows role schema initialization followed by Kestrel startup cancellation during harness finally SIGTERM; exit-6 does not establish a spontaneous startup crash. No source programs/maps/module/device or owned processes remain. Two-vCPU experiment did not establish an improvement; next run returns to original4vCPU configuration used by R6 and changes only the QA artifact-count error. Production17-host post-recovery readiness pass remains separate. .19 not deployed.


- R8 graceful OS shutdown timed out while native ownership was already conclusively clear (no native activation,4setup checks,0operations/no sensor enrolled/all owned IDs/processes absent). Exact archive hash and zero-NIC owned clone UUID/disk guards checked before disposable-clone power-off and original baseline restoration. LINUX-R8-NO-NATIVE-OWNED-CLONE-CLEANUP-20261007-R1.json PASS08:34:41Z; original4vCPU/16GiB/unlimitedCPU/4000shares restored, production unchanged. This special cleanup is excluded for any unresolved native ownership or drain failure. Corrected R7 run now starting with the original R6 resource configuration and unchanged four packages.


- Exact .19R3 candidate staging PASS on real ops01/support01, serial source-hash and enrolled-ID guards. Each reconstructed frozen raw9f343a... from191 verified installed .18 cache members, verified232 .19 members, retained native installation/config hashes and existing current links. LINUX-MANAGED0919-TWO-HOST-CANDIDATE-STAGING-20261007-R1.json. Candidate remains root-inaccessible to ordinary execution until gated activation; running .18 services unchanged. .19 activation and graceful rollback helpers drafted with full candidate hashes, unchanged identity/config checks, root source/lease/program/map/module closure before link change, saved original links/unit and no forced unload/evidence deletion. Syntax only for activation/rollback; actual upgrade and fresh tests still pending R7 runtime plus independent archive acceptance.


## 2026-10-07 installed Linux R7 startup failure and R9 qualification

R7 is FAILED: 27 setup checks, zero monitored operations. The preserved SQLite source_control completion explicitly reports CONTROLLED_ACTIVATION_REJECTED, nativeError -110 (ETIMEDOUT), activated false, observerAttempted false, three retained links destroyed, drainResult zero and lost zero. The managed activation write arrived after the native loader 60-second deadline. This is not proof of a policy-expiry restart defect or a stale package; the exact frozen Client.dll includes the startup recovery marker. The underlying delay remains unconfirmed; independent VMware evidence shows a fully loaded single host and 41-50 percent per-vCPU ready time. Source/controller/maps/module and owned processes returned; the disconnected owned VM shut down and original baseline was restored at 09:01:40Z. Evidence: LINUX-INSTALLED0919-R7-ACTIVATION-TIMEOUT-REVIEW-20261007-R1.json.

R9 is running on the same owned VMware clone with one vCPU and unchanged aggregate CPU shares, memory, packages, cryptographic policy deadlines and native loader deadline. Only QA server startup waits increased from 300 to 900 seconds after the observed cold-start timeout. Original four-vCPU baseline restoration remains required. This is an experiment, not acceptance.

Production ops01 and support01 have verified .19 R3 candidate directories staged, with all 232 file hashes, exact archive hash and existing sensor/configuration identity preserved. Neither candidate has been activated. Installed qualification, independent archive review, pilot activation, fresh operation/evidence tests and sustained recovery remain required before rollout. All-product completion and three final QA passes remain pending.


## 2026-10-07 ReadyToRun Linux candidate (build/read-only runtime checks only)

The separate .19 R4 ReadyToRun candidate was published successfully for Linux x64 with locked restore and unchanged source hashes. Read-only PE/CLR verification confirms RTR headers in LinuxAgent, Client and Contracts assemblies. Runtime configuration (self-contained .NET 10.0.12) and ELF launcher remain byte-identical to .19 R3. Frozen raw package SHA256: de709ef96a8f830de217088e1ff3cff274334624209209de4fdf54917e7310bc. All 232 members were reconstructed/verified on ops01 using 187 independently hashed cached members, in /opt/ransomfree-client/releases/20261007-managed0919-r4-readytorun-stage-r1. Version and configuration validation CLI calls passed; current service PIDs/state, configuration and sensor identity stayed unchanged. Single-sample version timings: prior IL 1.229 s, candidate 0.706 s; configuration validation 1.773 s versus 1.498 s. These short CLI results do not establish native activation improvement, installed policy-expiry recovery, or fleet rollout. R9 still tests the frozen R3 package on the isolated one-vCPU VMware clone.

Manus R144 reviewed the actual no-observer activation timeout and recommends preparing expensive non-native storage/journaling before the activation window, or a separately versioned staged native handshake. Its proposed protocol number 3 conflicts with the existing atomic operation prototype control 3 and cannot be reused unexamined. Current v2 completion lacks the proposed per-link ID teardown fields; count-only completion is insufficient for its proposed one-time retry gate. No automatic loader-timeout retry or new handshake has been enabled. R144 review SHA256 be68a90f204717c7829eba41f6c9afcd57a75d71cd9d0a02e2c9bfeed862e159.

A new production readiness sample passed on all 17 admitted Linux native hosts, with the same root PID and root instance IDs as the prior recovery readiness sample. This is two sampled observations, not continuous operation acceptance. Permanent Microsoft filter ordering number remains pending; Message-ID-related mailbox query returned no matching headers and cannot prove external delivery. Browser security policy blocked local file URL navigation for the remaining PDF native test; no bypass was attempted.

### 2026-10-07: upgrade stop/restart race guard (draft only)

The R2 .19 activation draft inventories native ready frames again after systemd confirms the root service has no main process. It includes any session created during a restart race in the closure checks and program/map absence proof before switching current links. Changed original ready frames and unqualified control versions block the upgrade. LINUX-MANAGED0919-UPGRADE-OWNED-FRAME-RACE-20261007-R1.json passes four isolated inventory cases. This is a deployment-script test, not an installed upgrade or product acceptance pass. No production service was changed by this test.
### 2026-10-07: failed R9 activation and .20 startup preparation candidate

R9 failed installed readiness after 27 setup checks and zero file-operation cases. The archived native completion confirms CONTROLLED_ACTIVATION_REJECTED/-110, activated=false, observerAttempted=false, zero loss, three retained links destroyed and normal drain. The later QA stop is not policy-expiry acceptance. LINUX-INSTALLED0919-R9-CLOSED-STARTUP-REVIEW-20261007-R1.json independently verifies actual native closure, closed journal, zero pending/raw work and returned owned programs/maps/module. Guest OS shutdown timed out; only after that independent closure proof, the isolated zero-NIC disposable clone was powered off and its original four-CPU baseline restored. Receipt LINUX-R9-CLOSED-NATIVE-OWNED-CLONE-CLEANUP-20261007-R1.json. No production system changed.

Linux .20 now prepares the root-private raw storage before spawning the native loader. It retains the same held descriptor, exact size and stable identity, transfers it once, and binds the provider epoch only from real ready evidence. Failed unbound attempts are retained, never interpreted as native sources. The preparation receipt explicitly has null provider epoch and session. Fresh policy/admission and stop checks follow preparation. Existing map proof, durable source/control linkage, signed-policy/nonce expiry and loader deadline remain enforced. The immutable .19 R3/R4/R5 candidates are preserved and have not been promoted to deployment.

The .20 ReadyToRun publish completed with zero errors and unchanged source during compilation. Sixteen layout preparation checks and 47 existing raw-ingress regression checks passed on Windows, including actual child process interruption and corrupt/uncertain-write retention. Physical Linux allocation and installed lifecycle remain pending. Both .20 managed and R76 fixture sealed deltas independently reconstructed exactly from the frozen R3 cache and verified every member SHA. Installed .20 qualification R1 is started on the same isolated VMware clone, using the unchanged native R18 bundle and .40 management server. It includes physical preparation checks, six real actor operations, whitelist nonmatches, actual central executable/manifest verification, normal policy expiry/recovery and owned teardown. A started qualification is not a pass or a production deployment.
### 2026-10-07: quota completion and local build storage recovery

Review of the moved allocation identified a concrete storage-accounting gap: policy expiry before source binding leaves an unbound buffer outside the journal's bound-bank quota. Linux .21 adds a pre-allocation check over retained bound and unbound raw files in the exact source parent while the existing runtime owner is held. It enforces the same 512MiB source-bank budget, retains prior files, rejects foreign quota parents and stops before loader startup when full. Twenty Windows layout tests now pass, including retained-unbound quota, exact remaining capacity and rejection before allocation. Physical Linux and installed .21 qualification remain pending. The earlier frozen .20 qualification still tests the original startup change and cannot authorize .21 deployment.

D: filled during a later build, which failed copying dependencies; that build is not a pass. Seven explicitly owned rebuildable intermediate directories were moved to C: fallback, with every file size and SHA verified before/after. Canonical app publishes, sealed packages, source freezes, logs, test evidence and production files were preserved. Move receipt C:/Users/dmessana/AppData/Local/Codex/sequester-storage-recovery-20261007-r1/RESULT.json records 516026368 freed bytes. D: has no partition exposed by the available Storage cmdlets, so no speculative volume resize was attempted. Further builds use the approved C: fallback while D: remains the location for existing controller/evidence outputs.

A fresh read-only readiness sample LINUX-NATIVE-SERVER41-SUSTAINED-READINESS-20261007-R2.json passed all seventeen production native sensors at 10:10 UTC. Each has the same root instance as the 09:08 sample, active ordinary/native services, fresh accepted policy and native module present. This is sampled readiness, not uninterrupted operation capture or fresh file-operation acceptance. Both .20 candidates are staged on ops01/support01 with 232 member hashes and 187 cache hashes verified, enrollment/configuration unchanged and no service/current-link activation. Receipt LINUX-MANAGED0920-TWO-HOST-CANDIDATE-STAGING-20261007-R1.json. These candidates remain unqualified for deployment.
### 2026-10-07: .20 setup failure and corrected .21 qualification

The .20 R1 installed controller failed before launching the native test worker: sequential reconstruction shared globals, so the first helper replaced the outer target directory with agent.tar and the second attempted agent.tar/fixture.tar. The first managed archive reconstructed and verified all 232 members, but no installed runtime or operation test ran. LINUX-0920-R1-NO-NATIVE-SETUP-FAILURE-REVIEW-20261007-R1.json verifies the actual pre-launch failure location, absent async launcher and no-module preflight; this is not native qualification. After the guest OS shutdown timeout, only the exact no-native disposable zero-NIC clone was powered off and restored to its original four-CPU baseline. Cleanup receipt LINUX-0920-R1-NO-NATIVE-OWNED-CLONE-CLEANUP-20261007-R1.json.

The corrected reconstruction uses independent Python globals for each helper. LINUX-QUALIFICATION-DELTA-ISOLATED-EXEC-20261007-R1.json exercises the actual two-step shape and verifies both exact archives with unchanged outer variables. The .21 managed and R77 fixture publishes are sealed on the C: storage fallback. Managed raw SHA 3680d3fc600931d614d3b42fc0ed91d44c355693635004c6ebfb7366ef63e76b; fixture raw SHA a080890d104134eb8d0f3f90a86c88138073f7ae9d8afaf7431456f67c8dcdd7. The .21 installed qualification uses one combined 6860800-byte transfer to reduce repeated Guest File Manager overhead, verifies each input and reconstructed archive, then runs the twenty physical preparation/quota tests and unchanged six-operation/recovery/central-evidence matrix. This qualification has started; no installed pass or .21 deployment is claimed.

## 2026-10-07 - APC token retention review and Linux .21 deployment preparation

Manus completed the focused CREATE authorization-context review. Microsoft SECURITY_SUBJECT_CONTEXT members are reserved; SeQuerySubjectContextToken requires PASSIVE_LEVEL; ObReferenceObject does not authorize accessing a reserved token pointer. No documented APC-safe transfer was identified. Later token-object queries cannot reconstruct operation-time thread impersonation. Full APC thread tokens and pre-minifilter existing-handle rights rejection coverage remain unresolved. This is research evidence, not a new runtime qualification or a completed feature. Exact review files/hashes are recorded in MANUS-WINDOWS-CREATE-APC-RETENTION-REVIEW-20261007-R1.json.

The production browser currently shows the legitimate sign-in page for server .41; signed-in production UI acceptance remains pending. No account or authentication state was changed. Exact Linux .21 stage/activate/rollback tools were generated with the frozen package and client hashes. The .21 qualification controller is running after its verified combined transfer. Activation requires the actual installed pass and independent archive review; .20 staging cannot satisfy that gate.


## 2026-10-07 - .21 setup retry and remaining Debian profile work

The .21 R1 installed rehearsal failed before sensor/server startup: update-ca-certificates exceeded its 150-second setup budget. Actual result: three setup checks, zero file operations, no native module/device/program/map ownership, server not started. Its downloaded archive was hash verified; the independent acceptance review correctly rejects the failed run. The owned VM shut down normally and returned to its original baseline at 11:17Z. R2 changes only that certificate-store setup command budget to 900 seconds and records elapsed time; TLS validation and native activation/nonce/policy deadlines remain unchanged. R2 is running, not passed. .21 package staging passed on ops01 and support01 with 232 members and 187 reused members; both remain on running .18.

Read-only checks identified three other Debian profiles with BPF LSM active but missing exact kernel headers. FreePBX runs 6.1.0-50-amd64; private authenticated package downloads and SHA-256 checks supplied exact 6.1.176-1 headers without installing packages or changing dpkg state. The original R18 source failed compilation due to absent newer timestamp/kfunc macros. A bounded Linux 6.1 compatibility source uses the actual inode mtime member, noinline kfunc declarations and SET8 registration, retaining trust/sleepability flags, owner checks, ABI and deadlines. Its candidate build passed with exact vermagic/BTF and no fault controls or module parameters; no module was loaded. Independently reconstructed source hashes match the actual build. BPF verifier/attachment, real operation attribution, preservation/upload and isolated runtime qualification remain pending. Witness 6.12.95 and Wazuh 6.12.86 exact headers are absent from their cached APT metadata; Manus was asked to verify authoritative archive sources. No kernel upgrade or service change was made.

## 2026-10-07 - Correction to Linux 6.1 BTF build evidence

The FreePBX compatibility R2 compiler pass is insufficient for activation. Independent parsing of the downloaded ELF found .BTF_ids but no actual .BTF section. The earlier textual build check matched the wrong section name and incorrectly recorded BtfPresent=true. The immutable compiler/archive receipts are retained; LINUX61-NATIVE-CANDIDATE-ARCHIVE-INDEPENDENT-REVIEW-20261007-R1.json records Passed=false and blocks promotion. The archive SHA-256 and source/module hashes match; no module was loaded. Linux 6.1 Kbuild ignored the newer VMLINUX_BTF override and skipped metadata generation because its local vmlinux file was absent. R3 supplies the exact captured running-kernel BTF through that private Kbuild path and checks the exact .BTF PROGBITS section. R3 build and all runtime qualification remain pending. The previous BTF-present statement is superseded by this independent result.


## 2026-10-07 - Historical Debian input verification and BTF resolver prerequisites

DEBIAN-HISTORICAL-KERNEL-INPUTS-INDEPENDENT-20261007-R1 verifies both 6.12.95-1 and 6.12.86-1 historical security InRelease signatures against the installed archive keyring, both signed package indices, and all six exact header/kbuild package hashes, sizes and dpkg identity fields. Historical Valid-Until expiration is explicitly retained; no APT expiration check was disabled, live source configured, package installed, kernel upgraded or module loaded. DEBIAN-HISTORICAL-KERNEL-BUILD-TREES-20261007-R1 privately extracted both profiles and adjusted only their private architecture Makefile includes. GCC 14 exists on ops01; this is not proof of the compiler that built the target kernels or a runtime pass.

FreePBX candidate R3 failed BTF generation because its private Kbuild inputs contain no resolve_btfids executable. The rejected R2 module is still blocked by the independent exact-section check. Authenticated Debian 6.1 source and userspace library packages are staged privately to build the genuine resolver. Resolver R1 extraction failed on an unrelated device-tree symlink; R2 narrowed the source inputs and reached compilation but requires the official scripts/bpf_doc.py helper. R3 includes that generator and its original executable permissions; its result remains pending. No native module has been loaded on FreePBX. Successful build-tool or module compilation alone will not satisfy verifier, attachment, attribution, evidence-upload or operation tests.


## 2026-10-07 - Three Debian kernel candidate builds independently checked

FreePBX resolver R6 built the genuine resolve_btfids from authenticated Debian linux-source-6.1 6.1.187-1 and private library inputs. The exact 6.1.0-50-amd64 module R4 then compiled with captured running-kernel BTF, actual .BTF metadata, correct vermagic, no fault controls and no module parameters. Its archive SHA-256, frozen four source hashes, module hash, ELF/BTF header, embedded vermagic and license were independently checked in LINUX61-NATIVE-BTF-CANDIDATE-ARCHIVE-INDEPENDENT-REVIEW-20261007-R4. The missing-BTF R2 rejection remains valid and preserved. No module has been loaded on FreePBX.

The 6.12.95 and 6.12.86 exact header/kbuild packages and actual target BTF/compiler/image identities were verified privately. Compiler R2 produced modules, but it did not prove the local Kbuild BTF input matched the captured target bytes. R3 correctly rejected that mismatch before compilation. R4 preserved the original private packaged vmlinux and supplied the exact captured raw BTF to the actual local Kbuild path, then compiled both modules with exact vermagic and real .BTF sections. HISTORICAL-DEBIAN-NATIVE-ARCHIVES-INDEPENDENT-REVIEW-20261007-R4 verifies both downloaded archives, frozen original R18 source, executable ELF/BTF structure, captured BTF identities, retained original package input and absence of fault controls/parameters. Existing native monitoring on the build host was recorded separately and unchanged; neither new candidate was loaded. Verifier load, attachment, live operation attribution, central actor upload and isolated runtime qualification remain pending for all three profiles.

LINUX-NATIVE-SERVER41-SUSTAINED-READINESS-20261007-R3 passed one additional actual readiness/policy sample on all 17 installed native sensors. This does not prove continuous uptime. The .21 installed VMware R2 worker remains pending. A read-only 12:13Z hypervisor sample reports full host CPU use, test VM red heartbeat and running VMware Tools; guest operations have become intermittently unavailable. This observation does not prove a sensor defect or authorize force shutdown with unresolved native ownership. No production CPU/memory priority or service was changed.


## 2026-10-07 - Installed Linux activation failure retained; .22 diagnostics qualification

The .21 R2 installed qualification failed at activation acknowledgement after linking the actual source. It ran zero file operations; it is not a runtime pass or deployment candidate. The downloaded runtime archive SHA-256 is 4e7fb3c21cc5175e5f2871dee7e375d1d88358b909a741c866a758242fb9978c. Its actual outcome reports FAILED_AFTER_LINK and CLOSE_RETURNED_OK. All owned module/device/program/map/process resources were proven absent, the server exited normally, and the owned zero-NIC guest shut down normally and restored its original baseline at 12:29:07Z. No forced shutdown was used. The previous statement that this run remains pending is superseded by this failed final receipt.

Actual physical Linux raw-preparation tests passed 20 checks, and source raw preparation took 0.329 seconds. This is useful diagnostic evidence, not a complete runtime pass. The specific activation/root-policy failure remains unconfirmed. Host CPU contention is an observation, not established causality.

Managed .22 adds at most 64 actual startup timing records in memory, with sequence, wall-clock and monotonic time, serialized only into the existing final outcome. Native, policy, nonce and acknowledgement security deadlines remain unchanged. Linux compilation and the 34 controlled-protocol-v2 checks passed. Recovery fixture R78 compiled with new startup trace checks; those native checks have not yet run. Immutable package/preparation receipts are LINUX-MANAGED-0922-NATIVE-PAYLOAD-20261007-R1, LINUX-RECOVERY-RECONSTRUCTION-R78 and LINUX0922-STARTUP-TIMING-QUALIFICATION-PREPARATION-20261007-R1. The .22 installed recovery qualification is running in the owned zero-NIC VMware guest; no .22 production activation or pass is claimed. Strict independent archive review was prepared before receipt acceptance.

The four Windows .24 sensors passed a fresh read-only service, driver hash, enabled-marker and C: filter attachment sample at 12:19:59-12:20:24Z. This does not replace operation tests or establish continuous uptime. Windows APC-level historical impersonation tokens and pre-IRP denied operations remain unavailable; there is no supported API identified that repairs those boundaries.

Manus R146 was downloaded with exact source hashes recorded. Its task-pointer lease discussion reflects an inaccurate description in our request, not the actual R18 file-taking interface. R147 sent the correction and actual current-file adapter implementation for 6.1 review. The independently built FreePBX module remains unloaded and unqualified. The current-file adapter used by the separate Ubuntu profile must receive its own exact 6.1 source, verifier, attachment and runtime qualification; no task-pointer casts or weakened verifier flags are authorized by that research.


## 2026-10-07 - exact-kernel qualification preparation and installed .22 investigation

- Linux 6.1.176 current-executable adapter R2 built using the actual 6.1 boolean get_file_rcu(file) API, get_task_mm/mmput_async and the existing acquired-file lease. Added explicit path-buffer bounds, error handling and NUL checks. No lease ABI or trusted/sleepable verifier flags were relaxed.
- Linux 6.1 R2 module/source archive passed independent 15-member review; complete BPF/loader/module archive passed 26-member independent SHA-256, ELF and target-BTF checks. Actual split module BTF was resolved with the installed libbpf API: all five function prototypes and the file-path buffer__sz parameter matched actual source. The first review expected two incorrect finalize parameter names; that review failed and was corrected against frozen source in a new R4 receipt, preserving the failure. None of these checks load a kernel module or qualify file operations.
- Exact target-BTF BPF and loader cross-builds passed for Debian 6.12.95+deb13-amd64 and 6.12.86+deb13-amd64. Both complete candidate archives were independently checked for member hashes, ELF/BTF, imports, executable permissions and exact kernel module identity. Runtime verifier, attachment and operations remain pending.
- Prepared three new immutable minimal native qualification bundles for 6.1.0-50, 6.12.95 and 6.12.86, using reviewed target-specific module/BPF inputs and the unchanged hashed R18 actor test fixture. Existing accepted release artifacts were preserved. These are qualification inputs, not production releases or passes.
- Exact Debian 95/86 kernel images were privately downloaded against verified historical signed index records (their historical Valid-Until expiry is recorded; no APT expiry or authentication setting was disabled). FreePBX 6.1.176 image was privately downloaded and verified against APT-authenticated package metadata. No kernel package installation, boot change or production restart was performed.
- Read-only VMware inventory matched the three source hosts and confirmed owned datastore capacity. Large production VM clones were not created; exact-kernel boot testing on the existing isolated owned qualification VM is being prepared after its current native ownership is conclusively closed.
- Installed .22 qualification remains running and unaccepted as of this entry. Its worker PID/start identity was repeatedly matched. VMware guest-script inspections returned operation-not-allowed faults. A separate documented process-list API successfully observed the root worker, but subsequent calls also failed. These transport observations do not establish startup, closure, actor capture or operation success.
- Actual owned-VM CPU ready measurements averaged 24.74 percent before a separately recorded temporary 2000 MHz CPU reservation and 1.7908 percent afterward. No swap activity or ballooning was observed. CPU scheduling improved; sensor failure causality remains unconfirmed. The VM remains one CPU/16 GiB/zero NIC during this run. Sensor ACK, source policy and native security deadlines are unchanged.
- An independent baseline checker is prepared to require normal powered-off state, original four CPUs/16 GiB, reservation zero, limit -1, shares 4000 and zero NICs after native closure and snapshot restoration. The .22 independent acceptance checker now requires this resource verification and records the scheduling intervention. Restoration is still pending while the current worker is active.
- Production console remains signed out; user sign-in was requested for UI acceptance while independent sensor/API work continues. No account reset, temporary production user or authentication bypass was attempted.
- Full additional Linux profile/operation rollout, fresh Windows 11 .24 qualification, native PDF callback, production signed-in UI and final three product-wide QA passes remain pending. Existing Windows APC/pre-IRP attribution limits and permanent Microsoft minifilter load-order number remain unresolved; build checks do not establish their completion.

Evidence: LINUX61-CURRENT-FILE-BPF-ARCHIVE-INDEPENDENT-REVIEW-20261007-R2.json; LINUX61-CURRENT-FILE-KFUNC-BTF-REVIEW-20261007-R4.json; HISTORICAL-DEBIAN-BPF-ARCHIVES-INDEPENDENT-REVIEW-20261007-R1.json; LINUX-EXACT-KERNEL-QUALIFICATION-BUNDLES-20261007-R1.json; HISTORICAL-DEBIAN-QUALIFICATION-IMAGES-20261007-R3.json; FREEPBX-QUALIFICATION-KERNEL-IMAGE-20261007-R1.json; OWNED-LINUX-QUALIFICATION-CPU-RESERVATION-20261007-R1.json; OWNED-LINUX-QUALIFICATION-SCHEDULING-20261007-R2.json. Receipts are in diagnostics/windows-token-20260930 in the task workspace.


## 2026-10-07 - .22 first installed result, verified custody and fresh replay retest

- The first .22 worker completed with 117 checks and six real controlled reads but FAILED the final empty-root-export assertion. Original failure and controller result-collection timeout remain recorded; independent acceptance remains failed.
- Independent review of archive SHA-256 070d8430468592a05ff461b2211153367e169c4bd4b2bb7de9b187071c4878bc matched all twelve server events against executed actors' User/Process/PID, two log-only whitelist decisions and four exact downloaded actor/manifest hash pairs. Both actual native sources reached STARTUP_READY, then completed normal closure. Their activation-to-durable-ACK intervals were about five seconds under the unchanged thirty-second ACK deadline. Total startup including earlier phases was about65/73 seconds, not the ACK interval.
- Actual root journal integrity was valid. Five exports had durable root import receipts and were retired. The last post-outage export had no root receipt and remained unretired, while the ordinary sensor retained all six local import receipts and central delivery was independently verified. The test had deliberately stopped the root receipt listener before central delivery checks. An offline listener could not accept the last local receipt; the retained duplicate is not evidence loss.
- Native closure independently rechecked module/device absent, ten owned programs and sixteen maps gone, no owned live executable processes, server exit0. Evidence archive was downloaded and hash verified. Normal guest shutdown completed, baseline snapshot restored, and the temporary CPU reservation was explicitly reconciled2000->0. A subsequent independent read confirmed off/fourCPU/16GiB/reservation0/limit-1/shares4000/zeroNIC.
- Fresh .22 replay qualification is running with the SAME managed/native/server package bytes. It requires an actual third root restart after the deliberate shutdown, exact local import receipt replay for all six unchanged packet hashes/event pairs, complete duplicate retirement and another normal native shutdown. Sensor, ACK, policy and native deadlines are unchanged. Only the controller's guest-transport result collection bound is ninety minutes and the owned scheduling reservation is2000MHz from the start. A prepared independent checker requires all three source outcomes and real receipt-replay linkage, plus a fresh post-run resource baseline observation. No pass or production activation is claimed yet.
- Three exact additional-kernel input bundles and authenticated kernel images were assembled into a read-only ISO. Independent ISO9660 directory/dimension checks and all seven payload hashes passed. Full datastore upload/download roundtrip SHA-256 matched6c893b7aa4b408ceca95c88704b915b9d99424e170063167f8cadb12df7aa732. No VM attachment, boot, kernel install or extra-profile qualification occurred.
- Eight negative verifier cases per additional kernel compiled (24 total): nullable pointer without guard, leaked acquisition, double release, use after release, forged pointer, wrong BTF type, nonzero file offset and sleepable call from a nonsleepable program. They remain unloaded/unattached; actual kernel rejection and normal resource closure are still required.
- Manus R149 was sent the verified results, replay design and unchanged Windows APC/pre-IRP limits for primary-source review. The production console was rechecked and is still signed out; earlier user sign-in handoff remains pending.

Evidence: LINUX0922-R1-EVIDENCE-AND-RETIREMENT-DIAGNOSTIC-20261007-R1.json; LINUX0922-R1-INDEPENDENT-ACCEPTANCE-20261007-R1.json; OWNED-LINUX-CPU-RESERVATION-RESTORATION-20261007-R1.json; OWNED-LINUX-QUALIFICATION-BASELINE-20261007-R1.json; LINUX0922-RETIREMENT-REPLAY-QUALIFICATION-PREPARATION-20261007-R3.json; LINUX-EXACT-KERNEL-QUALIFICATION-ISO-INDEPENDENT-REVIEW-20261007-R1.json; LINUX-EXACT-KERNEL-QUALIFICATION-ISO-DATASTORE-20261007-R1.json; LINUX-EXACT-KERNEL-NEGATIVE-VERIFIER-FIXTURES-BUILD-20261007-R1.json. Whole-product completion and the final three QA passes remain pending.


### 2026-10-07 installed .22 R2 health failure and .23 diagnostics

- Installed .22 R2 failed the ordinary-sensor readiness gate before file tests (zero operations). The archived privileged source did reach STARTUP_READY, then closed normally on NATIVE_COMPANION_STOP. Health exchanges failed/timed out; the exact failing call is unconfirmed because old logs retain exception type only. Failure archive SHA-256 b93c5f5878ae895e1d627de71961642883a779b470c5d96d8b986f8bd8aeace7.
- Independent archive and native resource closure checks passed. Fresh original owned VMware baseline independently verified: powered off, four CPUs, 16 GiB, CPU reservation zero, 4000 aggregate shares, unlimited CPU, zero NICs. This is failure/cleanup evidence, not installed-service acceptance.
- New .23 candidate adds actual health exchange side/stage/elapsed time and raw OS error code, and slow source-sample phase timings. Arbitrary exception messages, credentials, paths and nonces are excluded. Original exception types and strict five-second health freshness, authentication, PID lifetime, policy and native activation requirements remain. First compilation error was fixed; separate R2 build passed. Readiness/diagnostic checks: 31 passed. Installed-service recovery/replay retest is running, not yet qualified or deployed.
- Three exact-kernel negative archives independently verified: 24 compiled BPF negative cases, none loaded or runtime qualified. Additional read-only test ISO full datastore readback hash 05981f9cbad974f1ca97526c46e60a4e1776433b16b0bf10fd4685d2663055eb. Exact-kernel runtime and isolated one-boot workers prepared; no new kernel boot yet.
- Manus R149 received and reviewed. Documented Windows thread token/subject-context acquisition requires PASSIVE_LEVEL; APC historical accessing-thread identity and pre-IRP insufficient-handle-rights coverage remain unavailable. No unsupported token layout read or fabricated user identity.
- Whole-product completion, native qualification for remaining Linux profiles, full operation validation, remaining native canary/UI acceptance and final three QA passes remain pending.


### 2026-10-07 - measured installed health failure and fresh journal candidate

- Installed .23 FAILED ordinary readiness before file tests (zero operations). The native source reached STARTUP_READY and closed normally. Actual health diagnostics identify client REPLY_READ five-second cancellation and root SOURCE_SAMPLE/REPLY_WRITE failures. Thirty-two slow source samples recorded package/target admission 1588-6332ms and journal validation 1265-13717ms; these are phase durations, not proof of underlying disk/CPU/lock causality. Archive SHA-256 cf862ffc8564ce03787c06f5e68f32c83ce46ae9426a9f0cd0776132231d0efb independently verified.
- Actual native cleanup verified all owned programs/maps gone, module/device absent, no owned live processes and server exit0. Normal VMware shutdown/snapshot restoration completed. Fresh independent baseline R3 passed: off/fourCPUs/16GiB/reservation0/limit-1/shares4000/zeroNIC. Strict installed acceptance remains FAILED.
- Linux .24 candidate replaces repeated health journal connection opens with one fresh connection while reusing source-link, activation sample and actual write/EOF validators. No health/source/policy evidence is cached and the five-second health window is unchanged. Compiled separate managed/fixture packages; 151 activation/corruption/transaction/migration checks passed, including fresh rejection of altered receipts and corrupted ready frames. Installed .24 qualification is starting; no production deployment or runtime pass yet.
- Manus R150 received: fresh protected byte/identity reads could permit immutable parse reuse, but caching readiness/policy/source samples is prohibited by the design. Linux5.15 current-mm Kprobe route remains an exact-build candidate requiring provenance, loss and drain qualification; not implemented or deployed.
- Read-only Microsoft reply check at15:18Z found no permanent minifilter load-order number reply. No duplicate request sent.
- All remaining Windows APC/pre-IRP limits, extra Linux profiles/operations, fresh Windows11 validation, native PDF callback, signed-in UI acceptance and final three whole-product QA passes remain pending.

Evidence: LINUX0923-HEALTH-FAILURE-ARCHIVE-DIAGNOSTIC-20261007-R1.json; LINUX0923-INDEPENDENT-ACCEPTANCE-20261007-R1.json; OWNED-LINUX-QUALIFICATION-BASELINE-20261007-R3.json; LINUX-HEALTH-JOURNAL-PORTABLE-REGRESSION-20261007-R1.json; LINUX0924-HEALTH-JOURNAL-QUALIFICATION-PREPARATION-20261007-R1.json; MANUS-R150-RESEARCH-RECEIVED-20261007-R1.json.


### 2026-10-07 - fresh four Windows host server acceptance

- Fresh fifteen-operation matrix passed on Desktop, domain controller, Blue Iris and storage sensors running .24. Original sensor settings restored after normal worker completion.
- Server .41 raw API verification independently matched all 60 expected cases and verified 64 exact actor executable/manifest artifact pairs. PID, process start, process owner, effective accessing identity and CREATE authorization evidence were compared to the actual fixture ground truth.
- Scope remains qualified PASSIVE-level operation callbacks and denied CREATE. Pre-IRP insufficient-handle-right failures and unavailable accessing-thread tokens at unsupported IRQL remain limitations; this result does not claim universal denied-access coverage.
- Windows 11 current-driver package built and sealed (SHA-256 1C7514F15BA5A142F9C282CF8124661D9536E91F0864F13A721E52C6C74E1ED8). It reuses exact deployed driver 3553B621... with no driver rebuild, new signature or security setting changes. Twenty-one native operation/intake cases are prepared, not executed. Runner retains native ownership until normal closure; deadlines remain failure gates.
- Linux .24 installed recovery qualification remains running. No runtime pass or additional Linux rollout is claimed.

Evidence: WINDOWS-SERVER41-FOUR-HOST-MANAGED-CENTRAL-20261007-R4.json; WINDOWS-SERVER41-{Desktop,DC,NVR,Storage}-0624-OPERATIONS-20261007-R2.json; WIN11-CURRENT0624-QUALIFICATION-PAYLOAD-20261007-R1.json.


### 2026-10-07 - protected definition reuse candidate and actual Linux progress

- Installed .24 reached all five initial real honeypot read cases and 78 lifecycle/attribution/whitelist/hash checks. An actual management-server outage is underway to validate policy expiry and recovery. This is progress, not a completed runtime acceptance result.
- Fresh .24 source phase logs show journal validation reduced to roughly 1-1146ms in the observed tail, with remaining package/target admission roughly 2596-4807ms. No claim of complete latency or underlying resource causality. Owned VM scheduling observation R6 recorded approximately 100 percent guest CPU usage, zero observed swapping and 2-6ms virtual disk latency.
- Added LinuxNativeDefinitionPin: each health admission reopens protected configuration/manifest paths and reads complete current bytes, verifies local ext4 mount, complete file identity and exact byte/hash equality against previously validated canonical definitions. It avoids repeated JSON decoding and public-key import; no readiness, policy, source, map, target or nonce evidence is cached. Lock/member/target validation remains in place.
- Candidate .25 and fixture R81 compiled with source hashes unchanged. All 91 portable definition/key/identity/mutation checks passed; 1000 exact-byte checks completed in 2ms on the Windows development machine. This is not a Linux endpoint benchmark. Five additional actual Linux protected-file mutation cases are prepared, not run.
- Separate .25 installed expiry/recovery/replay qualification prepared with exact frozen payloads and unchanged security deadlines. Independent checker R2 corrects a pre-execution count error and explicitly requires all five actual filesystem mutation test labels. Candidate .25 is not deployed.

Evidence: LINUX-DEFINITION-PIN-PORTABLE-REGRESSION-20261007-R1.json; LINUX-MANAGED0925-DEFINITION-PIN-BUILD-20261007-R1.json; LINUX-RECOVERY-DEFINITION-PIN-BUILD-R81.json; LINUX0925-DEFINITION-PIN-QUALIFICATION-PREPARATION-20261007-R1.json; LINUX0925-INDEPENDENT-VERIFIER-PREPARATION-20261007-R2.json; OWNED-LINUX-QUALIFICATION-SCHEDULING-20261007-R6.json.


### 2026-10-07 - installed Linux recovery runtime and Ubuntu 5.15 build facts

- Installed .24 worker PASSED 130 checks: six actual local honeypot reads, two published exact hash/path/user whitelist matches logged without alert/preservation, four alerts with exact actor preservation and central upload/download, original and completion User/Process/PID, full policy-expiry close, automatic fresh-root recovery, and actual third-source restart to replay all six durable import receipts.
- Final native ownership receipt confirms all fifteen owned BPF programs and twenty-four maps returned, module/device absent, no owned live processes, server exit0, SafeToShutdown=true. Archive SHA-256 830799bbe41fc4e583b4c0b903738e102e0ff063ca90811e18aece0042bac32f. VMware normal restoration and independent archive/baseline acceptance are being verified separately; no production rollout yet.
- Read-only Ubuntu 5.15 prerequisite inventory R2 verified mysql, Netbox, Plex and x-wiki existing sensors active, exact installed headers and exported probe/reference APIs. Initial R1 inventory matched only Plex because three inventory aliases differed; R1 remains a failed four-host inventory, corrected R2 covers all four.
- Added activation-disabled compat515/sq_actor515_api.c to validate exact headers for current-mm RCU nonzero actor file reference, subjective credential IDs, process/thread start scalars and kretprobe frame APIs. Plex kernel5.15.0-186.196 compilation PASSED, exact module vermagic5.15.0-186-generic, module SHA-256 94205cca467a86980946defcfc05040b9e778c9a9c710f71e9f0037e21e5f8c7. Existing sensor PID/state, installed headers and dpkg database unchanged. The module deliberately refuses activation: no probe attachment, provenance, capture, preservation or runtime coverage is claimed.
- No Sequestor console credential entry was found in the authorized local credential metadata inventory. Production signed-in UI acceptance remains pending; no credential reset/account creation or password values read.

Evidence: LINUX-INSTALLED-POLICY-EXPIRY-RECOVERY-0924-SERVER40-20261007-R1.json; UBUNTU515-KPROBE-BUILD-PREREQUISITES-20261007-R2.json; UBUNTU515-CURRENT-MM-API-BUILD-20261007-R1.json; SEQUESTOR-CONSOLE-CREDENTIAL-METADATA-20261007-R1.json.


### 2026-10-07 - installed Linux .24 independent acceptance

- .24 archive independently PASSED all 108 checks, including exact package/source identity, all three actual source completions, six real operation identities, twelve central records, four downloaded actor/manifest pairs, all six replayed receipts with unchanged packet/event linkage, and actual native closure.
- Normal VMware shutdown and original snapshot restoration completed16:51:06Z. Fresh independent baseline R4 PASSED16:51:24Z: powered off, four CPUs/16GiB, reservation0, unlimited CPU, shares4000 and zero NICs.
- This qualifies the owned installed local preopen/read, manual hash/path/user whitelist and actual policy-expiry recovery/replay scope. It does not qualify additional Linux kernels, all operation types or production deployment. .25 protected definition optimization remains a separate pending candidate.
- Current .24 Windows 11 native qualification is now starting on the owned zero-NIC VMware guest; current deployed driver bytes reused, no new signature or security configuration change.

Evidence: LINUX0924-INDEPENDENT-ACCEPTANCE-20261007-R1.json; OWNED-LINUX-QUALIFICATION-BASELINE-20261007-R4.json; WIN11-CURRENT0624-QUALIFICATION-PAYLOAD-20261007-R1.json.


### 2026-10-07 R151 follow-up, .25 staging, Windows 11 harness correction

- The exact .25 candidate was staged on ops01 and support01: 232 managed members and 187 unchanged cached members verified; both ordinary/native current links and all configurations remain .18. Receipt: LINUX0925-TWO-PILOT-STAGING-20261007-R1.json. No activation pass is claimed.
- Netbox exact 5.15.0-170.180 header/API compilation passed alongside the prior Plex 5.15.0-186.196 compilation. Both prototype modules refuse activation; no 5.15 provenance, runtime collection or preservation is qualified by compilation.
- Manus R151 returned an exact-build kprobe provider design requiring observed exec provenance, shared-mm/PR_SET_MM taint tracking, direct-open framing, durable raw admission/START, retained loss telemetry and normal reference drain. Existing PASSIVE Windows token and pre-IRP limitations remain unresolved.
- Windows 11 R1 stopped before candidate ImagePath/load-order mutation or driver loading: harness assumed an old registry instance name. The R2 sealed harness resolves the existing DefaultInstance under Parameters/Instances or legacy Instances. Native Windows 11 acceptance remains pending. VMware Tools connectivity was intermittent after preflight; normal guest shutdown was requested, not a forced reset.
- Product-wide three-pass QA remains pending after implementation and deployment; these scoped results do not close the full specification.

## 2026-10-07 ongoing qualification update

Linux 5.15: the successful-exec provenance state passed 30,295 assertions on each of Plex and Netbox. The direct-open correlation state passed 50,111 assertions and 10,000 operation cycles on each host. Exact lifecycle API builds passed on both running kernels. These are component checks; no new 5.15 capture module has been activated or qualified. Scheduler registration, retained actor copy, unresolved-target lease integration and end-to-end events remain pending. Exact Plex kernel packages were independently checked against signature-verified Ubuntu indexes and downloaded for isolated VMware qualification.

Linux .25: actual installed qualification completed 132 checks, six native opens, manual whitelist log-only decisions, preserved executable central uploads/downloads and policy-expiry recovery/replay. Native module/device and all owned BPF objects and processes closed normally. The downloaded archive SHA256 is 6fd31bfb375aaf0563ba646d93a584cebec9c1418233c8ebed2fd9ba3ccb667e. Original VM restoration and independent archived acceptance must complete before the staged two-pilot candidate is activated. No .25 production deployment is claimed by this entry.

Windows 11: R1 preflight failed before driver load because the harness addressed an obsolete instance registry path. Normal guest shutdown was independently confirmed; no forced power-off or driver unload occurred. R2 resolves the existing registered default instance under Parameters/Instances, with legacy fallback. Its runtime result remains pending. This does not resolve APC-level historical thread-token or pre-IRP failure limitations.

## 2026-10-07 resource incident

New heavy qualification runs and broader Linux deployment are held. The owned Linux qualification VM was shut down normally and its original snapshot and CPU reservation restored. Its failed exact-kernel bootstrap never launched native capture. VMware host CPU was saturated, but several other workloads were among its largest consumers; this is not attributed entirely to Sequester.

Windows: a live managed stack identified EvidenceUploadQueue.Pump repeatedly reading acknowledged upload metadata. Four hosts had zero outstanding transfers but 2,688-4,432 pending records with receipts. Version .25 archives only exactly validated received records to immutable .uploaded.json metadata, retaining artifacts, manifests and receipts. Inspection is bounded to 64 records per pass; idempotent replay does not reactivate completed work. The actual transfer fixture passed 313 checks, including bounded migration, restart, byte preservation, receipt mismatch and transfer failures. The managed source disposal fixture passed nine checks; no driver changed.

Windows .25 deployed to Desktop, domain controller, NVR and Storage with identity/configuration and driver hash preserved. Each host passed 15 fresh operation cases and independent central attribution/evidence verification: 60 cases and 64 actual artifact/manifest download pairs. DC's initial observer failed when a pending record was atomically archived between enumeration and reading; its 15 worker cases and separate central verification passed. The failed observer receipt is retained, not relabeled. The later observer accepts only the exact archived sibling for this FileNotFound race.

CPU denominator matters. Before the fix, DC/NVR/Storage consumed approximately 99/75/103 percent of one core (25/6/6 percent of total machine capacity). Later 15-second samples measured Desktop/DC at 0 percent of one core, NVR at 1.13 percent, and Storage at 9.97 percent (0.62 percent of total capacity). Samples immediately following restart or operations are not steady idle measurements. Storage's remaining variable cost is not fully explained. Windows sensor resident memory was approximately 92-111 MiB.

Linux .26 replaces repeated 1 MiB mount-inventory allocations with bounded reusable buffers, preserving current mount/descriptor checks. Eight local checks and nine checks on each pilot passed; 1,000 small reads allocated 160,000-162,400 bytes instead of approximately 1 GiB. The baseline .25 installed qualification (132 checks) separately passed 112 independent archived checks; it is not represented as a fresh full .26 qualification.

Only ops01 and support01 received .26, using normal native closure and exact package/configuration gates. Each passed six fresh native honeypot reads as root and an ordinary account, independent process birth/device/inode/credentials checks, and separate central event plus actual artifact/manifest download verification. Twelve cases passed. The forensic collector did not hash target files. Native CPU remains excessive: subsequent samples were 41.33/43.47 percent of one core on ops01/support01 (5.17/10.87 percent of total machine capacity), with 118/115 MiB resident memory. The resource incident is open, with further profiling required before wider deployment.

Receipts: diagnostics/windows-token-20260930/RESOURCE-RATES-*-20261007-R1/R5/R8; WINDOWS-RESOURCE-*-CENTRAL-0625-20261007-R3; LINUX0926-TWO-PILOT-RESOURCE-ACTIVATION-20261007-R1; LINUX0926-TWO-PILOT-RESOURCE-NATIVE-READS-20261007-R1; LINUX0926-RESOURCE-*-CENTRAL-20261007-R1; RESOURCE-RATES-LINUX-20261007-R2. The first Linux stack profiler could not start because no global runtime is installed; this is a diagnostic failure, not a capture pass. An isolated hash-verified official runtime is being staged for diagnosis without altering sensor runtime or system settings.

Whole-product completion, broader Linux rollout, Windows 11 runtime qualification, APC token coverage, remaining operation/canary consumers and final three product-wide QA passes remain pending. Windows 11 R2 failed its actor deadline before qualifying operations; original VM restoration completed. No failure is recorded as a pass.

Follow-up: LINUX-RESOURCE-STACKS-20261007-R2 contains three successful managed stack captures per pilot using an isolated SHA512-verified official .NET runtime. Ops01 stacks identify repeated QualifiedMount work from SampleLoss and ObserveServiceHealth, along with SQLite export polling. Support01's three snapshots caught its worker threads waiting; its earlier CPU measurements still stand, and those waiting snapshots do not establish zero ongoing cost. No runtime was installed globally and no sensor runtime/settings changed.

The .27 candidate scans unrelated mount lines without splitting their fields; it still reads a fresh inventory for each check, validates the exact matching mount and rejects duplicates/malformed entries. Health frequency, package checks, held descriptors, locks and security rules remain unchanged. Local checks passed 20 cases; each Linux pilot passed 21 userspace fixture cases, including allocation limits, fragmented reads, oversize/read failures and matching-mount consistency. One thousand parses of an inventory containing 1,000 unrelated mount rows allocated 528,000-533,184 bytes total. Immutable .27 staging and activation are separate receipts; deployment and lower live CPU must not be inferred from these fixture passes.

Subsequently .27 deployed successfully on both pilots, preserving identity/configuration. Twelve fresh native accesses and separate central event, credential/process identity and artifact/manifest download checks passed. RESOURCE-RATES-LINUX-20261007-R3 still measured native CPU at 38.13/41.66 percent of one core (4.77/10.42 percent of total machine CPU); the parser allocation improvement did not resolve live CPU consumption.

The .28 candidate adds a synchronous, bounded mount validation pass to package and target admission. Every held descriptor still receives live fstatfs/statx and existing identity/path/permission checks. Mount inventory is read fresh before and after the pass; every observed mount's selected entry is revalidated before success. No inventory is retained across passes, no health interval or loss/policy check is relaxed, and validation failures still stop source admission visibly. Scope is exactly five source files relative to .27 (LinuxQualifiedFileSystem, LinuxMountValidationPass, LinuxNativePackageAdmission, LinuxNativeTargetAdmission and the LinuxAgent version).

Local userspace checks passed 31 cases. The initial Linux descriptor fixture failed when OpenRoot was given a path beneath the shared temporary directory; its failed result remains LINUX-RESOURCE-MOUNT-FIXTURE-20261007-R3. The corrected harness runs the identical frozen fixture in its existing protected /var/lib input directory. R4 passed 33 checks on each pilot, including actual held-descriptor mount validation and rejection of removed, substituted, duplicated and changed-device entries during the pass. No native module or live service changed for these fixture runs.

.28 staging R1 refused an inherited old archive byte count before creating a release or changing services. R2 derives the exact 91,688,960-byte size from the sealed plan and retains all plan/member/full-archive hashes, including raw SHA256 00c32cbf189089a615143184f8812da7039c50f439d1c47d9d3c4378c5499f6d. The R1 rejection is retained. Successful staging, activation, fresh capture/central evidence and CPU measurements remain separate required receipts; no .28 runtime/resource success is inferred from compilation or fixtures.

Subsequently .28 R2 staging, normal activation, twelve fresh native reads and both central event/executable download checks passed. Repeated post-test samples (RESOURCE-RATES-LINUX-20261007-R5) measured native CPU at 26.00/18.27 percent of one core on ops01/support01 (3.25/4.57 percent of machine capacity); ordinary workers remained at 1.59/3.40 percent of machine capacity. The initial sample after restart was higher and is retained as R4. The resource incident remains open.

Latest Windows samples (Desktop R6, DC R7, NVR R6, Storage R9) measured sensor CPU at 0.03/0.66/0.69/0.95 percent of total machine capacity respectively, with 94-110 MiB resident memory. DC management server measured 0.84 percent CPU and 65 MiB. These are 15-second samples, not long-term idle or maximum-load certification.

The .29 candidate keeps one unused, transaction-free SQLite connection for the exclusively owned Linux forensic journal lifetime. Actual operations still create fresh unpooled connections; schema, FULL synchronization, foreign-key checks, automatic checkpoint threshold and unresolved-owner disposal guards are unchanged. Normal final disposal closes that connection before releasing the owner lock. This addresses repeated last-connection WAL/index teardown during idle polling; it does not cache evidence or health decisions.

ResourceJournalLifetime checks in tools/ResourceMountInventoryFixture passed 13 local checks and 14 on each Linux pilot. They cover schema preservation, empty inventories, WAL/index lifetime, unchanged checkpoint threshold, FULL synchronization/foreign keys, visibility of committed external changes, rollback, no fabricated file events, exclusive ownership, normal close/reopen and integrity. The exact installed .28 DLL was separately used as a baseline in isolated fixture directories (12 common checks, explicitly baseline-only). One hundred idle poll pairs wrote 13,107,200 bytes on each baseline and zero on each candidate. CPU time was 3,800.678 to 2,286.760 ms on ops01 and 1,698.531 to 1,210.114 ms on support01. Timing varies with runtime/host load; this is a userspace comparison, not a deployed CPU certification. No sensor or native source changed during these fixtures.

.29 scope is exactly LinuxForensicJournal.cs and the LinuxAgent version relative to .28. Immutable staging passed on both pilots. Normal activation, fresh native attribution/central evidence and live resource measurements are separate pending receipts at this entry. Installed .25's 132 checks remain baseline qualification, not a falsely repeated .29 recovery gate. Wider Linux rollout remains held.

Subsequently LINUX0929-TWO-PILOT-RESOURCE-ACTIVATION-20261007-R1 passed on both hosts. Twelve fresh native honeypot reads, root/ordinary-user credentials, independent PID/birth/device/inode attribution and preservation hash checks passed. LINUX0929-RESOURCE-ops01-CENTRAL-20261007-R1 and its support01 counterpart both passed all six cases, including actual executable/manifest downloads. These are read-operation acceptance, not full operation/recovery/canary or whole-product certification.

RESOURCE-RATES-LINUX-20261007-R6 measured zero native-process idle physical write bytes on both pilots after the journal fix; native CPU remained 3.27/4.55 percent of total machine capacity and ordinary workers 1.65/4.03 percent. R7 repeats resource collection after the fresh operation tests and is retained separately. The Linux CPU issue is not declared resolved. Further CPU profiling and broader performance acceptance remain necessary before wider rollout; source and evidence checks were preserved rather than removed to reduce load.


## Linux resource investigation resumed — 2026-10-08

User authorized careful continuation, staged wider deployment and VM qualification. RESOURCE-RATES-LINUX-20261008-R1 measured 15-second combined CPU of 3.76% on ops01 and 5.94% on support01 (native 2.68/3.92%, ordinary 1.08/2.02%). RSS totals were 199.57/194.87 MiB. These are samples, not sustained acceptance. Plex unchanged .18 measured 0.37% ordinary CPU.

LINUX-RESOURCE-STACKS-20261008-R1 collected five bounded native managed stack snapshots per pilot, with process-birth/release checks. Active frames on both pilots again showed mount inventory generation inside package/target admission in the 100 ms loss sampler. Ordinary snapshots mostly caught waiting threads and do not establish its remaining CPU cause.

LINUX-MOUNT-READ-COST-20261008-R1 independently measured actual /proc/PID/mountinfo reads: 100 native-namespace inventory reads used 482–628 ms CPU on ops01 and 212–238 ms on support01. Larger userspace read sizes did not eliminate the kernel's repeated sequence-file reads. LINUX-DIRECT-MOUNT-QUERY-20261008-R1 verified Linux x86-64 statmount syscall 457 and STATX_MNT_ID_UNIQUE on kernel 6.12.94. One thousand targeted calls took 15.866/16.713 ms CPU, returning ext4 and matching old/unique mount IDs, device and magic. This prototype ran outside sensors; it is not deployment acceptance. No capabilities or syscall filters were changed.

Candidate .30 adds LinuxDirectMountQuery.cs and modifies LinuxQualifiedFileSystem.cs/LinuxMountValidationPass.cs plus the LinuxAgent version. It queries the exact held descriptor's unique mount, validates all returned identity/type fields, memoizes only inside a synchronous owned validation pass, and rechecks each queried mount at pass completion. Unsupported API/privilege retains the mountinfo validation path. Missing/malformed response or changed identity fails. Package/path/byte ownership, target identity, loss/health/policy timing, kernel code, configuration and service permissions remain unchanged. ABI verified against upstream v6.12 linux/mount.h and statx/statmount manual pages, not a guessed API.

Local fixture passed 45 checks. LINUX-DIRECT-MOUNT-FIXTURE-20261008-R1 passed 147 checks per pilot, including 100 repeated live held-descriptor checks; this count includes repeated assertions, not 147 distinct scenarios. Parser field corruption, truncated responses, old inventory boundary/duplicate/device/mutation checks and lazy fallback checks passed. These were isolated userspace tests with no native activation or live service changes. The first local fixture failed because its size-corruption test changed the size to another valid bound; corrected test uses an out-of-bounds size. Original failed log retained. LINUX-MANAGED0930-RESOURCE-FIX-BUILD-20261008-R1 passed ReadyToRun/self-contained compilation with source-before/after equality. Pilot activation, fresh sensor events/central downloads and resource gates remain pending at this entry.

VMWARE-LIVE-RESOURCE-USE-20261008-R1 shows qualification VM powered off and host CPU 43894/43880 MHz, RAM 431.01/447.89 GiB. Heavy VM qualification remains held for headroom; no unrelated VM or production workload was stopped or changed.


.30 deployment follow-up: LINUX0930-TWO-PILOT-RESOURCE-STAGING-20261008-R1 and ACTIVATION passed on ops01/support01, exact previous .29 client hash and 232 package members verified. Normal native drain/unload absence checks and service startup preserved identities, configuration, target and module bytes. Backups are unique root-owned paths in activation receipts. Only these two pilots were upgraded.

LINUX0930-TWO-PILOT-RESOURCE-NATIVE-READS-20261008-R1 passed twelve fresh real honeypot reads (root and ordinary user on three existing targets per host). Both LINUX0930-RESOURCE-<host>-CENTRAL-20261008-R1 receipts passed all six cases, including original/completion identity fields and actual downloaded actor/manifest SHA equality. This validates reads; it is not a new write/rename/delete/truncate/denied/canary/expiry recovery pass.

First post-upgrade 15-second RESOURCE-RATES-LINUX-20261008-R2 native CPU measured 1.28% on ops01 and 1.75% on support01, versus 2.68/3.92% before upgrade. Ordinary CPU was 1.86/2.75%, combined 3.14/4.50%, RSS totals 246.40/243.71 MiB. This initial sample is not sustained acceptance and ordinary CPU is not resolved. Wider rollout and heavy VM qualification remain held; bounded ordinary-process tracing is underway.


Additional Oct 8 measurements: RESOURCE-RATES-LINUX-20261008-R3 measured native CPU 0.89/1.78% and ordinary CPU 1.43/1.38% on ops01/support01 (combined 2.32/3.16%). This sample overlapped bounded diagnostic work and is not an idle soak acceptance. Native physical writes were zero in that interval. LINUX-PILOT-STATUS-COST-20261008-R1 confirmed both .30 native companions ready with zero queued events, pending syslog or pending exports; status JSON sizes were 41,824/160,115 bytes. Empty queues do not establish resource acceptance.

LINUX-ORDINARY-RESOURCE-TRACE-20261008-R1 collected 10-second EventPipe thread-time traces with official dotnet-trace 10.0.750501, 8 MiB buffers, stable process identity and exact .30 release guards. Trace sizes were 6.16/6.47 MB. Samples mainly show waiting threads; they cannot be interpreted as CPU percentages or proof that semaphore waits consume CPU. LINUX-RESOURCE-STACKS-20261008-R2 no longer caught mountinfo reads; one ops01 active snapshot caught SQLite preparation in journal.Open/ExportPass. These are observations, not complete quantitative CPU attribution.

A separate isolated fixture is testing the runtime timer/thread-pool spin hypothesis on the actual endpoint runtime, using default and DOTNET_ThreadPool_UnfairSemaphoreSpinLimit=0 in new fixture processes only. Runtime source verified against dotnet/runtime v10.0.0 PortableThreadPool.WorkerThread.cs and LowLevelLifoSemaphore.cs; upstream issues 103812/93234 discuss unnecessary spin cost. No live runtime option, service permission or timing has been changed. Fixture results and any consequent candidate remain pending.


LINUX-TIMER-SPIN-FIXTURE-20261008-R1 passed isolated 15-second measured timer activity comparisons after 5-second warmup per process. Default versus zero-spin CPU was 545.965/283.341 ms on ops01 (48.10% lower), and 695.894/311.496 ms on support01 (55.24% lower). First three 50/100/100 ms callback counts were equal or higher with zero spin. This does not establish the cause of all live CPU or qualify file detection. The outer receipt retained a copied mount-fixture Scope label; each actual host/result Scope correctly identifies timer-only testing. No sensors or services changed in that fixture.

.31 source change is only LinuxAgent.csproj, adding numeric runtime config System.Threading.ThreadPool.UnfairSemaphoreSpinLimit=0 and incrementing its version. Linux .30 filesystem checks, native code, permissions and polling/deadline windows are unchanged. Build passed source freeze. Packaged runtimeconfig was explicitly inspected and contains numeric zero. The first .31 sealing attempt failed before staging because a version-string replacement also changed the historical cache-directory name to a nonexistent path. Its partial local payload is retained; R2 corrected the directory reference and produced the sealed candidate. No endpoint changed due to the failed sealing attempt. .31 pilot staging/activation and fresh runtime acceptance remain pending at this entry.


## Linux .31 pilot acceptance and remaining resource cost — 2026-10-08

LINUX0931-TWO-PILOT-RESOURCE-STAGING-20261008-R1 and ACTIVATION passed on ops01/support01 only, preserving configuration, sensor identity, native package and service units. Both runtime configurations contain numeric zero for ThreadPool.UnfairSemaphoreSpinLimit. Normal native drain and absence checks completed. LINUX0931-TWO-PILOT-RESOURCE-NATIVE-READS-20261008-R1 passed twelve fresh native reads; both LINUX0931-RESOURCE-<host>-CENTRAL-20261008-R1 receipts passed all six original/completion identity and actual actor/manifest download checks. This remains read-operation acceptance, not full operation/canary/recovery certification.

The first .31 15-second sample (RESOURCE-RATES-LINUX-20261008-R4) measured combined ordinary/native CPU of 2.22/4.15% of machine capacity. That does not establish a clear live improvement from the runtime setting. The subsequent quiet one-minute RESOURCE-MINUTE-LINUX-20261008-R1 measured ordinary/native CPU 0.57/0.78% on ops01 and 1.08/1.52% on support01, combined 1.35/2.60%. Both services remained active with stable PID/start ticks. Per-process RSS was 142.36/141.58 MiB and 147.46/138.04 MiB respectively; adding RSS double-counts shared pages. Ordinary physical writes were 4,743,168/4,448,256 bytes per minute, native 32,768 bytes each. Longer soak/load limits remain unqualified; resource issue stays open.

LINUX-ACTUAL-CPU-PROFILE-20261008-R1 and R2 both explicitly failed capture because CONFIG_USER_EVENTS is disabled on the pilots' actual kernels. R2's tracefs mount occurred only in a temporary private mount namespace; parent/PID1 mount namespaces stayed unchanged. No successful CPU profile is inferred from wrapper exit zero. LINUX-PERF-AVAILABILITY-20261008-R1 confirms CONFIG_PERF_EVENTS=y, no installed perf/strace/bpftrace, and unchanged perf_event_paranoid=3. Private diagnostic tool staging is underway without installing system packages or changing sysctls.

LINUX-NATIVE-SQL-COSTS-20261008-R1 opened actual journal databases read-only/query-only. Ops01 has 66 work/export rows, support01 60, all completed and retired. Query plans scan historical work/retirement rows, but 100 reused-connection query executions used only 7.41/22.62 ms CPU for exports and 3.15/3.50 ms for retirements. This excludes connection/setup costs and is not proof SQL explains the remaining live CPU. No indexes/schema/service changes were made.

LINUX-ROLLOUT-BASELINES-20261008-R1 collected non-secret baseline identity, versions, native configuration hashes and exact kernel/profile details for all 26 Linux sensors. Only the two pilots are .31; remaining 24 are .18. Wider activation remains gated on acceptable resource and detection results. Heavy VM work remains held while the VMware host is saturated; no unrelated workloads were stopped.


## Linux queue lifetime candidate .32 — 2026-10-08

LINUX-PERF-CPU-PROFILE-20261008-R1 succeeded for both ordinary/native .31 processes on both pilots. Process-specific CPU-clock sampling ran for 15 seconds at 99 Hz each, stable PID/start/release guards, no lost samples; traces 159-196 KiB are retained in unique private directories. LINUX-PERF-COMPACT-REPORT-20261008-R1 contains full compact reports (39/86 samples on ops01, 160/77 on support01). Samples include path/mount/syscall checks and SQLite schema parsing, with fsync/block writes in the ordinary worker. These small samples are not precise attribution of all resource cost. Managed symbols are unresolved; do not infer method names from raw addresses. Private Debian perf 6.12.111 package/dependencies were downloaded and checked against apt repository SHA256 metadata, then extracted locally; no system packages installed or sysctls/security/service settings changed. The first tool run lacked libraries and is retained as failed staging. A copied outer ReadOnly label refers to diagnostic access, but staging/capture created private tool/trace files; it does not mean no filesystem writes anywhere.

Candidate .32 changes exactly EventSpool.cs, LinuxWorker.cs, LinuxNativeCompanionRuntime.cs and LinuxAgent.csproj relative to .31. The original two-argument EventSpool constructor is preserved. Linux owners explicitly opt into one unused WAL-lifetime connection and use normal disposal after producer/delivery/source drain. Every queue operation remains a fresh unpooled connection with FULL durability/foreign keys, same schema/counters/receipts/FIFO/capacity and no evidence cache. Other platforms retain the original constructor behavior; opting into the Linux feature on another platform is refused. .31 mount validation/runtime settings and native modules remain unchanged.

QueueLifetimeChecks passed 22 local checks (Linux-only retention checks unavailable locally, explicit non-Linux refusal tested). LINUX-QUEUE-LIFETIME-FIXTURE-20261008-R2 passed 23 candidate and 21 retention-disabled control checks on each Linux pilot. Both isolated runs used the candidate implementation with retention disabled versus enabled, not the installed .31 DLL. Tests cover exact byte/counter visibility, idempotency/conflict, invalid/valid receipts, FULL/FK/checkpoint settings on actual operation connections, independent-owner commits/rollback/close, concurrency, disposal refusal, normal restart persistence and integrity. One hundred idle status/peek poll pairs wrote 6,553,600 bytes with retention disabled and zero enabled on each host. CPU was 915.557 to 298.636 ms on ops01 and 354.779 to 179.525 ms on support01. These are isolated queue costs, not whole-sensor live acceptance.

The first queue fixture input preparation used a nonexistent local publish-directory name and stopped before any endpoint upload. R2 corrected the source; its receipt was first written to the workspace root by the generator invocation, then copied intact to diagnostics, and worker/sender preparation was completed before hash-frozen upload. Partial R1 directory and root receipt retained; no service changes resulted from those preparation errors. ReadyToRun .32 build passed source-before/after equality. LINUX0932-TWO-PILOT-RESOURCE-STAGING-20261008-R1 passed all 232 members on both hosts with identities/configuration unchanged. Normal activation and fresh honeypot/central/live resource acceptance remain pending at this entry.

VMWARE-LIVE-RESOURCE-USE-20261008-R2 again measured 43894/43880 MHz CPU and 431.05/447.89 GiB RAM, owned qualification VM still off. Heavy VM work remains held for host headroom. Other 24 Linux sensors remain .18; no wider activation has occurred.


## .32 live acceptance and self-generated audit activity — 2026-10-08

LINUX0932-TWO-PILOT-RESOURCE-ACTIVATION-20261008-R1 passed normal source closure and activation on ops01/support01 only, identities/configurations preserved. Twelve fresh native reads passed in LINUX0932-TWO-PILOT-RESOURCE-NATIVE-READS-20261008-R1. Both LINUX0932-RESOURCE-<host>-CENTRAL-20261008-R1 receipts passed six cases each including original/completion attribution and actual executable/manifest downloads. No full operation/canary/recovery completion is inferred.

Quiet minute measurements remained mixed. RESOURCE-MINUTE-LINUX-20261008-R2 combined CPU was 1.43/3.69% of machine capacity; ordinary physical writes 3,272,704/5,128,192 bytes. R3 measured combined 1.34/3.92%, ordinary writes 2,367,488/5,304,320 bytes and native writes 36,864 bytes each. Stable active PIDs; resource issue remains open. Isolated idle queue retention worked, but ongoing real audit intake is not idle queue polling.

LINUX-ORDINARY-STATE-CHANGES-20261008-R1 showed audit cursor advancing 869/1077 packets over approximately 30 seconds, with WAL and cursor changes. LINUX-AUDIT-SELF-ACTIVITY-20261008-R1 inspected the most recent 128 packets per pilot: every packet was openat by the current root native sensor PID, on the three monitored target files, approximately one group each 100 ms. LinuxMonitoredTarget.RequireCurrent reopened the final target using O_PATH on every admission sample. O_PATH does not read target contents but still produces audit opens; this creates continuous sensor-originated evidence traffic. These samples establish the specific self-generated activity; they do not prove every historic resource symptom has one cause.

Candidate .33 replaces final-target pathname reopening with a fresh AT_SYMLINK_NOFOLLOW statx observation. The original target descriptor stays held and receives unchanged regular-file/link/device/inode and qualified filesystem checks. Parent directories still use the original no-follow traversal. Current pathname device/inode/type/link and mount ID must match the held admitted target/mount. No process-name filtering, audit-event suppression, content hashing or policy/timer/privilege/module changes. A shared byte-description parser is extracted without changing its field offsets. Exactly LinuxMonitoredTarget.cs, LinuxProtectedDirectory.cs and LinuxAgent.csproj changed relative to .32.

LINUX-TARGET-STATX-FIXTURE-20261008-R1 passed 11 checks per pilot, including 100 repeated fresh pathname checks, unchanged write/permission semantics, different-inode replacement, final/ancestor symlink, disappearance, extra hardlink and same-device/inode bind-mount refusal, normal unmount restoration and new admission. Bind mounts were inside verified temporary private mount namespaces, parent/PID1 namespaces unchanged. No source/native module/service was activated by fixtures. ReadyToRun .33 build passed source freeze. Actual activation, fresh detection/server evidence, new audit-source-rate and resource acceptance remain pending at this entry.

The initial .33 staging-input generator failed before endpoint uploads because its identifier substitution changed the historical diagnostics directory name. R2 explicitly restored that path, generated guarded frozen inputs, and retained R1. No service change resulted from the preparation failure. LINUX0932-WIDER-ROLLOUT-READINESS-20261008-R1 is a plan only: 26 baseline identities, 2 pilots, 14 other same-kernel native hosts and 10 separate profile/kernel gates. Candidate version must be refreshed to .33 after acceptance. No wider activation or heavy VM qualification is claimed.


## 2026-10-08 — Linux .33 pilot activation, central evidence and quiet resources

- Exact .33 resource candidate activated only on ops01/support01 by normal owned-source drain and absence checks. Installation/configuration/sensor identity retained. Activation receipt per-host version/hash/release fields are authoritative; its inherited outer scope still says .32 and is a historical labeling defect, not evidence of .32 deployment.
- Fresh 12 native read cases (six per pilot) passed independent user/process/PID/process birth/security IDs/executable identity and preservation checks. Both central verification receipts matched all six host cases, original/completion events, and actual actor binary/manifest downloads. These are read tests, not complete operation/canary/expiry recovery acceptance.
- Read-only 30-second audit observation on both pilots: zero native self-opens and zero new packets, with fresh running collectors and no increased dropped/rejected counts. Combined with the real read tests, this validates removal of the identified 100-ms metadata-open audit feedback without suppressing actor events.
- RESOURCE-MINUTE-LINUX-20261008-R4: stable PIDs/start ticks, 60 seconds each; ops01 ordinary/native CPU 0.36/0.74% of eight-core machine (2.85/5.90% of one core), RSS 142.85/131.64 MiB, physical writes 4096/36864 bytes. support01 CPU 0.60/1.18% of four-core machine (2.38/4.72% of one core), RSS 137.46/127.66 MiB, writes 4096/28672 bytes. RSS values are per process and may include shared pages. Ordinary writes previously measured several MiB/minute. Longer warm-state measurement remains pending; no claim of zero native overhead.
- Fourteen exact-kernel .18 hosts: immutable .33 pre-staging underway with exact host/sensor/kernel/prior release/client/config guards and >=1 GiB free space. No wider activation acceptance. Inventory contains failed native services requiring diagnosis; a present native installation is not proof of active native monitoring.
- VMWARE-LIVE-RESOURCE-USE-20261008-R3 at 22:20 UTC: host 10.81.60.100 reports 43894/43880 MHz and 431.02/447.89 GiB used. Owned Linux qualification VM remains powered off. Heavy VM qualification held for capacity; no unrelated workload changes. This is pending, not a test pass.
- Receipts: LINUX0933-TWO-PILOT-RESOURCE-ACTIVATION-20261008-R1; LINUX0933-TWO-PILOT-RESOURCE-NATIVE-READS-20261008-R1; LINUX0933-RESOURCE-{ops01,support01}-CENTRAL-20261008-R1; LINUX0933-AUDIT-SELF-ACTIVITY-20261008-R1. Final three product-wide QA passes remain pending.


## 2026-10-08 — .33 longer resource sample and broader immutable staging

- RESOURCE-SUSTAINED-LINUX0933-20261008-R1: 180-second stable-process sample. ops01 ordinary/native CPU 0.30/0.66% of machine (2.38/5.29% one core), RSS 143.85/131.80 MiB, physical writes 12288/98304 bytes; support01 CPU 0.62/1.18% (2.48/4.71% one core), RSS 138.41/127.14 MiB, writes 12288/98304 bytes. Ordinary physical reads were 1400832/618496 bytes. This is quiet pilot evidence, not a heavy-load or long-duration memory qualification.
- LINUX0933-FOURTEEN-HOST-RESOURCE-STAGING-20261008-R1 Passed=true: all 14 exact 6.12.94/native-profile hosts staged the sealed archive, verified 232 members, 187 reusable runtime member hashes, prior .18 release/client hash, sensor/config identity, and >=1 GiB available. Unit states/PIDs remained identical before/after; no activation/current-link/configuration changes. Candidate SHA-256 dcd05bf4ad11b1f745c3ddd51b3d78fe3c52fafae5f93e90e1147a90eb2edc3e. Staging is not deployment acceptance.
- LINUX-NATIVE-READINESS-20261008-R4 refreshed all 26 Linux hosts. Ten existing .18 native services are failed (nine within the 14 staging hosts, plus www-legacy). Latest source outcomes consistently show LINUX_NATIVE_POLICY_EXPIRED_OR_REVOKED with completed normal closure, no pending delivery/canonical backlog/unindexed raw records and no errors. This identifies the last shutdown reason; the interrupted policy relay's original infrastructure cause remains unconfirmed. Native module metadata alone does not imply monitoring.
- Diagnostic R2 failed because its status variable was reused while parsing journal entries; R3 retained outcomes but filtered some status strings incorrectly. Corrected R4 is authoritative for status messages. No services changed by these reads.
- LINUX0933-SUPPORT-POLICY-RECOVERY-20261008-R1 is FAILED: the quiet controlled ordinary-relay interruption reached verified policy expiry, normal native closure and restart, and the finally block restored the ordinary service, but the fixture read the recreated runtime status file too early (FileNotFoundError). LINUX0933-SUPPORT-AFTER-RECOVERY-20261008-R1 confirms both .33 services active and the completed expiry outcome. This failed fixture is not a pass. R2 fixes missing-file startup waiting and requires live native PID to match status before acceptance; it and fresh post-recovery reads remain in progress.
- LINUX0933-VM-QUALIFICATION-PREPARATION-20261008-R1 records an exact .33 installed lifecycle worker and pending heavy qualification phases (idle, disposable target operations, bounded load/cache/ordering, recovery, normal cleanup). Preparation is not execution. Capacity gate unchanged; the owned VM remains off and other workloads retained.


## 2026-10-08 — rollout halted on retained raw-bank capacity; .34 restoration candidate

- Corrected LINUX0933-SUPPORT-POLICY-RECOVERY-20261008-R2 FAILED genuinely: native monitoring was not ready after ordinary relay restoration. Follow-up LINUX0933-SUPPORT-FAILED-RECOVERY-20261008-R2 identifies NATIVE_COMPANION_FAILED:IOException:RAW_BANK_QUOTA_EXHAUSTED. The ordinary sensor stayed active; native was failed. No wider activation permitted by these results.
- LINUX0933-SUPPORT-RAW-BANK-CAPACITY-20261008-R1: 15 retained raw banks, each 33722496 logical bytes; total 505837440 bytes. Next reservation exceeds the fixed 512 MiB bound despite 465025011712 free bytes. Evidence retained, not deleted/moved. This is cumulative retention capacity, not a full disk or proof of a memory leak.
- .34 adds an optional root-private /var/lib/sequester-native/raw-bank-capacity.json with exact canonical fields Version (1), SensorId, QuotaBytes. Allowed whole MiB range 512 MiB–8 GiB; omitted file keeps the original 512 MiB limit. It is read once from protected descriptors at native startup and logged as NATIVE_RAW_BANK_CAPACITY_BYTES. Native module/source authority, signed policy expiry, actor/target hashing, admission and all retained-bank counting remain unchanged. No automatic evidence discard/archival.
- Exact five source changes against frozen .33: LinuxNativeRawStorageCapacity.cs (new), LinuxNativeCompanionRuntime.cs (read setting), LinuxNativeModuleOwner.cs (pass bounded quota), LinuxControlledSourceRuntime.cs (use passed quota), LinuxAgent project version .34. Existing canonical installation.json shape remains unchanged. Windows untouched.
- LINUX-MANAGED0934-RESOURCE-FIX-BUILD-20261008-R1 build/source-freeze passed; sealed raw archive 10dc3693d4a1afd8ffdd1ec75e65267dd70f5c2fa66b69d0b7e5ce818ba4ae5b; Client DLL 6b19300dba5eac0f82bcdfd109c2aa4df397563b7f5a6e923f50ec767115478a. Build is not installed qualification.
- Pure capacity fixture R1 failed because its expected-refusal catch omitted InvalidDataException; R2 corrected it and passed 19 checks. LINUX-RAW-CAPACITY-FIXTURE-20261008-R1 actual pilots each passed 27 isolated checks: canonical/bounds/sensor/unknown/duplicate/type refusals, root-private permission and symlink refusals, original quota exhaustion, explicit budget physical reservation, historical bank metadata preservation. No native activation or live evidence edits in fixtures.
- .34 staged only on support01 (LINUX0934-SUPPORT-RECOVERY-STAGING-20261008-R1). Activation now in progress using explicit 2 GiB capacity, >=3 GiB free-space gate, guarded source drain/module/BPF absence, original unit/installation/sensor pins, and all 15 prior raw bank identities plus SHA-256 before/after. This is storage restoration, not a completed archival/retention feature or heavy/load qualification. Fourteen .33 packages remain staged/inactive.
- All-26 read-only 15-second intake LINUX-ALL-SENSOR-RESOURCES-20261008-R1: .18 native-active sensors observed 27.20% machine CPU on scanopy-iot01, 25.90% on scanopy-trusted01, 19.58% openradius02, 17.59% openradius01, 10.73% socdev01. These short samples establish rollout prioritization, not quiet steady-state qualification. support01's 0.92% entry covers only the ordinary sensor while native was FAILED, and must not be compared as total healthy sensor CPU against prior pilot samples.


## 2026-10-08 — .34 journal budget failure corrected by .35, support restored

- LINUX0934-SUPPORT-RAW-CAPACITY-RECOVERY-ACTIVATION-20261008-R1 FAILED its readiness deadline. .34 ordinary sensor remained active, native failed with a second RAW_BANK_QUOTA_EXHAUSTED at source journal registration. Physical reservation honored the explicit 2 GiB setting; journal.PrepareControlledSource still received a hardcoded 512 MiB. This integration omission was fixed; .34 is not accepted.
- .35 changes exactly LinuxControlledSourceRuntime.cs plus agent project version against frozen .34: the registered journal now receives the same validated config.RawBankQuotaBytes as physical reservation. No quota guard removed, evidence evicted or historical failure converted into a functional pass.
- Expanded LINUX-RAW-CAPACITY-FIXTURE-20261008-R2 passed 30 checks on each real Linux pilot, adding actual journal quota refusal at 512 MiB and acceptance at the same explicit 2 GiB budget using isolated synthetic historical-accounting rows and a physically reserved fresh bank. Fixture no-controller completion returned; no module/loader activated. Synthetic rows are accounting tests, not proof of historical native evidence or end-to-end rollout.
- Sealed .35 archive 8451ca022308e0bf49f573df9d5ef234d877ac3e9dbc5d0b3185c80b3a24983d; Client DLL de59c0fca6f34c6d80f2a6abd12298c18264f614a6c80dac85a205e5152f2dd4. Build/source-freeze passed. Stage receipt LINUX0935-SUPPORT-RECOVERY-STAGING-20261008-R1 passed.
- LINUX0935-SUPPORT-COHERENT-CAPACITY-RECOVERY-ACTIVATION-20261008-R1 PASSED: support01 ordinary/native active with PIDs 3787617/3787613 at acceptance and live native status tied to current PID. Capacity remains 2147483648 bytes; its root-private canonical file hash ddf863082051686c2031a96cb8352a8978743d3e0c12cab6b4aa6431be646b4f. All 16 prior raw bank bytes, lengths, device/inode identities verified unchanged before/after. Original installation, sensor identity, unit and ordinary configuration retained.
- Safe upgrade closure checks distinguish actual normal controller close from the known .34 failed-before-controller startup: the latter requires session null, NOT_OPENED, FAILED_NO_CONTROLLER, NOT_ATTEMPTED, NOT_APPLICABLE recovery, exact retained startup error, all actual work/child/map closure booleans, and module/device/owned BPF absence. It is an absence proof for safe upgrade, not a successful source/operation verdict.
- .35 support policy-expiry/restart/recovery and six fresh actor read plus central download tests are pending/in progress. ops01 remains .33. Fourteen other hosts retain inactive staged .33 packages; no wider activation. Complete VM load/operation/retention qualification and final product-wide QA remain pending.


## 2026-10-08 — .35 repeat recovery, post-recovery evidence and quiet resources

- LINUX0935-SUPPORT-POLICY-RECOVERY-20261008-R1 and R2 both PASSED. Actual ordinary signed-policy relay was interrupted, native policy expired, the source drained with CLOSE_RETURNED_OK and no pending/canonical/unindexed evidence or errors, owned resources closed, service restarted automatically, and fresh signed policy restored native readiness. Restart times were 129.98 and 117.81 seconds. Finally restored ordinary service. Current accepted R2 native/ordinary PIDs 3792239/3792259; configuration, installation, units, current release and explicit 2 GiB storage setting unchanged.
- Post-recovery read receipts R1 and R2 each PASSED six fresh native reads of three existing targets as root and ordinary user. Each actual short-lived actor's independent PID/birth/credentials/path/hash/stable executable identity matched original and completion. Central receipts R1 and R2 each PASSED six matched cases and six actually downloaded actor/manifest pairs with verified hashes. Twelve fresh reads total across two recoveries. Target files were not automatically hashed. This establishes read attribution/evidence delivery for support01, not all operation types or every host.
- LINUX0935-SUPPORT-AUDIT-SELF-ACTIVITY-20261008-R1 PASSED: 30.63 seconds, native self-open count zero, new packets zero during quiet sample, collector fresh/running/failure null, drops and rejects zero. Fresh actual detections above prove the quiet result is not collector shutdown.
- LINUX0935-SUPPORT-MINUTE-RESOURCES-20261008-R1: 60 seconds, both process births/PIDs stable and services active. Ordinary/native CPU 2.58/3.63% of one core, 0.65/0.91% of four-core machine; total 1.56% machine CPU. RSS 133.84/127.29 MiB per process (shared pages may overlap); physical reads zero; disk writes 4096/32768 bytes, total 36864 bytes. Quiet sample, not heavy-load or long-duration memory acceptance.
- VMWARE-LIVE-RESOURCE-USE-20261008-R4 at 23:10 UTC: host CPU 43559/43880 MHz (99.27%), memory 431.04/447.89 GiB (96.24%). Owned qualification VM remains powered off, four vCPU/16 GiB; no other workloads changed. Heavy VM qualification cannot be accepted from live quiet tests and remains capacity-gated.
- LINUX0935-VM-QUALIFICATION-PREPARATION-20261008-R1 records exact .35 installed-lifecycle worker hash, payload, pilot recovery and the pending idle/operations/bounded-load/cache/order/recovery/cleanup phases. Prepared only, not executed or qualified. The first local preparation assertion expected the wrong version string and stopped before creating output; corrected enrollment string is 0.9.35-qualification.
- Wider .35 immutable staging is in progress for fourteen exact 6.12.94/native-profile hosts, with original sensor/config/release pins and unit PID/state equality checks. No activation or default capacity-setting changes. ops01 remains .33; support01 .35 only. Retention/archival remains outstanding: the explicit budget is bounded capacity, not automatic evidence disposal or unlimited restart recovery. Other kernels and full operation/load/long-duration qualification remain pending.


## 2026-10-08 — fourteen-host raw-evidence capacity preflight

LINUX0935-WIDER-RAW-BANK-CAPACITY-20261008-R1 completed read-only checks on all 14 exact 6.12.94/native-profile wider rollout candidates. Each host sensor identity and exact kernel matched the frozen rollout intake. Each uses the original 536870912-byte budget with no capacity setting; 12 retain five banks (168612480 bytes) and scanopy-trusted01/ddi01 retain four banks (134889984 bytes). Headroom is ten or eleven additional 33722496-byte raw banks under the existing limit, not unlimited retention. All have >400 GiB free disk. No capacity file, service, target or evidence changed. This preflight reduces startup-capacity risk but does not qualify wider activation or replace operation/load/recovery tests.


## 2026-10-08 — .35 wider staging completed, activation remains pending

LINUX0935-FOURTEEN-HOST-RESOURCE-STAGING-20261008-R1 PASSED on all fourteen exact-kernel hosts. Each reconstructed and verified sealed archive 8451ca022308e0bf49f573df9d5ef234d877ac3e9dbc5d0b3185c80b3a24983d, all 232 published members and 187 reusable runtime member hashes; Client DLL de59c0fca6f34c6d80f2a6abd12298c18264f614a6c80dac85a205e5152f2dd4. Original prior .18 release/client, ordinary config, native installation, sensor and kernel pins passed. Before/after running unit PIDs and states were identical. No service/current-link/enrollment/capacity/evidence change. .33 inactive candidates retained alongside .35. This completes safe wider preparation only: support01 is live .35 and ops01 live .33; the fourteen still run .18. Wider activation, fresh per-host native operation/evidence/resource/recovery checks and heavy owned-VM qualification remain pending. VMware capacity gate is the latest 99.27% CPU/96.24% RAM sample; no heavy VM was powered on and no unrelated workload altered.


## 2026-10-08 — Linux evidence mapping, audit parser lifecycle and denied-open diagnosis

- VMWARE-LIVE-RESOURCE-USE-20261008-R5 measured 43894/43880 MHz CPU demand and 431.065/447.890 GiB RAM use. No physical CPU headroom for raising resources or heavy VM qualification. The DC guest has four logical CPUs, about 8 GiB RAM, about 6.5 GiB free. No resource allocation or unrelated workload changed; owned qualification VM remains off.
- Native completeness inventory of six centrally accepted .35 read cases confirmed actual accessing-task credentials, task birth/exec correlation, actor hashes and preservation. Native parent process, command line, POSIX session and post-operation results/bytes remain unavailable. Audit/procfs fields must not be attached to historical native records by PID alone.
- .36 added audit filesystem GID, preserved event-time parent PID/proctitle when enrichment encounters an exited actor, kept audit login session distinct from POSIX process session, and cleared provisional current-PID instance metadata when audit image binding fails. Final metadata fixtures passed 22 checks locally and 25 on Linux; actual libauparse metadata fixture passed 10 checks. Signed/native source ABI unchanged; target hashing/preservation defaults unchanged.
- Final .36 R2 sealed raw archive 863590cf1d23ce45cdc05732ab7d98d666fc7b38f60bcbe1e055088bd7942d05. Support-only staging/activation passed, all 19 previous raw bank hashes and identities retained. Six fresh .36 native reads and six actual central executable/manifest download pairs passed. This does not establish native parent/command-line capture or full operation coverage.
- .37 replaced unconditional 16 MiB parser destruction with maintenance only when both pending native events and a partial input line are absent. Recoverable partial events flush before gap resets. Normal shutdown drains already queued input and flushes on the parser OS thread. Disposed handles reject native calls. It does not establish lossless cancellation of producer in-flight frames under backpressure.
- LINUX-AUDIT-METADATA-PARSER-20261008-R3 passed 23 checks using real libauparse, including fragmented sets, partial flush status and disposed handles. .37 build and source freeze passed; sealed raw archive 242f4d5aad8884acdb934c6bab194c4b445c1d03cc4ae4ab9aaee39c4d3171df; Client DLL a77359e9b3c729e35b51fd5aac3896dd15b2c49cb07d37aa9cbcd395090b8a9c. Support staging and activation passed with all 20 old banks hash/identity retained.
- Found root audit collector still running .18 although ordinary/native services had been upgraded. LINUX0937-SUPPORT-AUDIT-COLLECTOR-UPDATE-20261008-R2 upgraded it through normal SIGTERM/start and enabled only existing Audit.CaptureCommandLine. Ordinary/native PIDs unchanged. Cumulative counters rose by two dropped records and one rejected boundary during the actual relay gap; retained totals 340/276, not zero. Follow-up read-only status was fresh/running, CollectorHealth.Failure null, TransportFailureCount zero. Normal service update has a coverage interruption; this is not a lossless live update claim. Earlier collector update attempts failed their pre-mutation guards and are retained as failures.
- LINUX0937-SUPPORT-FRESH-NATIVE-READS-20261008-R1 passed six actual root/user reads with independent PID/birth/credentials/path/stable image/hash; corresponding CENTRAL receipt passed six original/completion pairs and six actually downloaded binary/manifest pairs.
- LINUX0937-SUPPORT-DENIED-OPEN-20261008-R1 is FAILED acceptance, retained. The actor actually received errno 13 and the sensor retained matching audit PID, accessing UID/EUID/FSUID and GIDs, parent PID, target inode and failed result -13. Exact command-line assertion failed because Linux kernel PROCTITLE caps at 128 bytes. Actual target permissions, inode, size, owner/group and mtime restored in finally. The failure is not converted to a denied-open evidence pass.
- .38 correction adds nullable CommandLineTruncated to attribution, marks kernel proctitle at 128 raw bytes potentially truncated, reports partial metadata for exited actors, and keeps longer independently bound procfs text when the capped audit title is its prefix. Historical audit text remains in attribution; later procfs text keeps its later-observation provenance. Primary API source: https://github.com/torvalds/linux/blob/master/kernel/auditsc.c (MAX_PROCTITLE_AUDIT_LEN), https://github.com/linux-audit/audit-userspace/blob/master/auparse/auparse.c (feed state/flush).
- .38 source scope is exactly ActorLease.cs, EventAttribution.cs, AuditParser.cs and LinuxAgent project version against frozen .37. Build/source freeze passed. Real parser R4 passed 26 checks; Linux metadata R5 passed 28, including actual procfs long-command retention. Client fixture first build failed internal-access compilation, corrected through public ActorLease.Capture; first Linux R4 executor refused stale .35 cache-source guard before execution. Both failures retained. .38 raw archive af1024af3454aed6cc91628279d25d1d6c0904f994f7e61772d45404ca45c1c3, Client DLL 526e01265cc1204a44089a4ca762484eed203efba4dfc00544c1d13707482145.
- .38 support staging R1 failed before creating a release: encoded controller still referenced prior .37 staging input. Corrected controller R2 verified the frozen .38 inputs and passed staging. No running service changed in the failed staging attempt. Activation, fresh actual denied-open central preservation, post-update native regression and quiet resources are in progress, not accepted from build/fixture success.
- Remaining: short-lived audit-denied actor image acquisition, native parent/command/session/post-I/O expansion, in-flight/full-queue shutdown qualification, other Linux kernel profiles, wider live activation and heavy VM/long-duration validation. Windows accessing-thread APC boundaries/denied coverage and current VM qualification remain separate unfinished gates. No final product-wide three-pass acceptance claimed.


## 2026-10-08 — .38 support live denial and regression acceptance

LINUX0938-SUPPORT-PROCTITLE-LIMIT-ACTIVATION-20261008-R1 passed: ordinary/native .38 active, all 21 previous raw banks (708172416 bytes) verified byte hashes and filesystem identities unchanged, explicit 2 GiB setting and configuration/enrollment unchanged. The copied activation receipt Scope text still says .37/.35 from its historical template; actual package/version/hash/PID gates establish .38, not a fabricated new .35 test.

LINUX0938-SUPPORT-AUDIT-COLLECTOR-UPDATE-20261008-R1 passed and matched status DispatcherPid/start ticks to actual .38 collector. Configuration unchanged. Normal relay interruption registered three dropped input records and one rejected boundary, cumulative totals 343/277; these failures remain visible. No force action or unrelated service change.

LINUX0938-SUPPORT-DENIED-OPEN-20261008-R1 passed actual EACCES; LINUX0938-SUPPORT-DENIED-OPEN-CENTRAL-20261008-R2 passed protected live API plus actual binary/manifest downloads and hashes. Independent user/groups/PID/start ticks/parent/POSIX session/full command matched. Historical audit login session remains separate. This is a living ordinary-user DAC denied-open, not every failed operation or short-lived process preservation. Initial central verifier R1 mistakenly counted both completion and Evidence transfer records, waited and failed its timeout; corrected R2 selects the actual Forensic enrichment completion. All three real events were already present; verifier timeout is not delivery loss.

LINUX0938-SUPPORT-FRESH-NATIVE-READS-20261008-R1 and CENTRAL R1 passed six root/ordinary-user native reads, six original/completion pairs and six actual actor/manifest downloads with matching hashes. Quiet self-activity R1 passed a 32.95-second sample: no new packets/self opens/drops/rejects, fresh running collector, health failure null. Quiet resource R1 sampled all three service PIDs/births stable for 60 seconds: ordinary/native/audit CPU 0.54/1.09/0.09% of four-core machine, total 1.72%; RSS 141.68/128.00/79.63 MiB (shared pages may overlap); physical reads zero; writes 4096/32768/49152 bytes, total 86016. Not heavy/long-duration acceptance.

Server .41 drops the two newly added EventAttribution fields on deserialization: FileSystemGroupId and CommandLineTruncated absent from actual management API despite present on sensor. Existing Forensics.EventSubject filesystem GID and independently captured full command were preserved and centrally accepted. Preparing .42 on a separately copied, hash-verified qualified .41 source; exactly EventAttribution.cs plus server project version changed. Build passed, sealed 502-member package SHA256 879C94FB5DC70227A71BCDB392B637DC4D22522691155EBA8AD6F3066F1F0C52. New ingest/SQLite reopen/history/web-export contract fixture passed 15; isolated EventHistory plus published HTTP checks passed 465; packaged server suite passed 156. Native/sensor/signing/whitelist logic unchanged. Server deployment and fresh wire-field acceptance remain in progress, not inferred from local fixture passes. Final product-wide QA, wider activation, full operation/load/short-lived-denial gates remain pending.


## 2026-10-08 — server .42 deployed, fresh additive fields accepted

DEPLOY-SERVER-LINUX-AUDIT-EVIDENCE-0642-20261008-R1 PASSED. Exact sealed package 879C94FB5DC70227A71BCDB392B637DC4D22522691155EBA8AD6F3066F1F0C52, release F:/Sequestor/Server/releases/20261008-linux-audit-evidence-0.6.42-r1. Stopped only the pinned existing server writer for a complete backup (about 13.5 GB); retained existing E: authoritative data, launcher configuration, signing keys, all 33 enrollment identities, callback receiver PID 1416 and all 30 served assets. Live health/version .42 and sensor capability versions passed; history watermark advanced 363020 to 363037. Planned management interruption was 02:12:22–02:14:37 UTC. Backup F:/Sequestor/Server/backups/linux-audit-evidence-20261009T021222Z. No database migration or server/host CPU/RAM allocation change.

Fresh LINUX0938-SUPPORT-SERVER42-DENIED-OPEN-20261008-R1 and CENTRAL R1 PASSED: independent UID/EUID/FSUID/GIDs/PID/parent/start ticks/POSIX session/full command, computed sensor+PID+birth correlation SHA, stable executable inode and source binding, preserved actor SHA and actual downloaded actor/manifest hashes. Both raw audit FileSystemGroupId=987 and CommandLineTruncated=true now survive actual .42 ingestion/history. Login session and later process/session/owner remain separately sourced. Existing historical .41 rows remain exact older evidence; missing new fields are unknown, not fabricated or rewritten.

Fresh SERVER42-FRESH-NATIVE-READS R1 PASSED six actual root/user operations; CENTRAL R2 PASSED six pairs and six actual binary/manifest downloads after the .42 update. CENTRAL R1 failed because one actual binary upload metadata record had not reached received state yet; its original verifier accepted any HTTP 200 as finalized. Corrected R2 waits boundedly for pending/receiving to become received and still rejects other states/hash or linkage mismatches. Failed R1 retained; events were already delivered, pending artifact transfer is not a completed upload.

The two added contract fields are nullable and omitted for older events without those observations. .42 application source is exactly the qualified .41 baseline with EventAttribution.cs plus server version changed; no unrelated UI or sensor architecture replaced. Feature list updated. Wider .38 immutable staging of fourteen matching-kernel hosts and additional actual denied-open targets are in progress; not yet per-host activation/complete operation/VM load acceptance.


## 2026-10-08 — .38 wider immutable preparation and three-target Linux denial coverage

LINUX0938-FOURTEEN-HOST-RESOURCE-STAGING-20261008-R1 PASSED on all 14 pinned 6.12.94/native-profile hosts. Each verified raw archive af1024af3454aed6cc91628279d25d1d6c0904f994f7e61772d45404ca45c1c3, all 232 payload members, 187 reused member hashes, new Client DLL 526e01265cc1204a44089a4ca762484eed203efba4dfc00544c1d13707482145 and original .18 client/config/native installation/enrollment/kernel. Before/after service PIDs/states identical. New inactive release alongside retained .33/.35 candidates, no running service/current-link/config/target/evidence change. Wider activation and host-specific runtime attribution/resource/recovery/load gates remain pending; prepared is not deployed or qualified.

Added real EACCES tests for second and third existing support honeypot paths. LINUX0938-SUPPORT-SERVER42-DENIED-TARGET2/3-20261008-R1 and corresponding CENTRAL R1 receipts each PASSED. Together with SERVER42-DENIED-OPEN R1, all three monitored production targets had a fresh ordinary-user denied read-open, independent user/PID/birth/parent/session/executable truth, actual .42 additive fields, target stable inode, bound full command, actor SHA/preservation and downloaded binary/manifest match. Exact original mode/ownership/size/inode/mtime verified after every temporary denial permission test. No default target hash/copy. Scope remains living-user DAC denied read-open on this pilot, not the full Linux write/rename/delete/truncate/denied operation matrix or short-lived denied-executable collection.

Fresh Windows .25 operation regression against server .42 is running sequentially on the four existing Windows boxes, using the unchanged guarded owned actor/15-case fixture, pinned installed driver and temporarily registered isolated test paths. Desktop and DC local execution currently passed 15 each and exact settings restoration; NVR/Storage execution and protected central token/acquisition/artifact verification remain in progress. No driver update, filter placement change, signing/protection change or heavy VM qualification in this phase.


## 2026-10-08: server .42 four-Windows acceptance and Linux .39 audit shutdown

### Actual Windows/server acceptance

WINDOWS-SERVER42-FOUR-HOST-MANAGED-CENTRAL-20261008-R1 PASSED: actual unchanged .25 sensors on DESKTOP-6U8VLDH, CPTNYC_DC01, CPTNYC_NVR and CPTNYCSTR01 each passed 15 independent actor operations, exact settings restoration, protected server API identity checks and 16 downloaded executable/manifest pairs. Total 60 operations, 64 pairs; binary and manifest hashes/linkage matched. Read, write, append, rename, delete, truncate, impersonation and denied CREATE cases covered. Scope remains the qualified PASSIVE operations/denied CREATE paths; this does not establish APC accessing-thread-token coverage, insufficient-existing-handle-rights/pre-IRP failures or Windows 11 VM qualification. NVR durable drain was delayed but all 15 records arrived before normal settings restoration. Final receipt is the authority, not interim progress.

### Linux .39 code and installed pilot

Exactly AuditTransport.cs, AuditDispatcher.cs and LinuxAgent project version changed against frozen .38. Transport keeps a bounded shutdown tail for a completed frame blocked on queue space; captured bytes from interrupted authenticated type-1 payloads precede an explicit gap/loss marker. Empty accept cancellation returns normally. Dispatcher drains the channel before the completed producer's tail on the parser thread, updates byte/time counters and still drains captured input when input join reports failure. This does not imply lossless relay-to-collector delivery.

Actual frozen transport fixture reused Native.cs, AuditLossCounter.cs and exact Paths.NoLinks/AuditHealth.StartTicks functions; only production socket constant became a required private fixture path. Windows channel checks passed 6; actual root Linux Unix socket and SO_PEERCRED tests passed 175, including 20 repeated full-queue cancellations, complete/partial headers and payloads, heartbeat, loss counters, bounded tail, ordering and graceful idle cancellation. Production socket, auditd and services untouched by that fixture. Full self-contained ReadyToRun build/source freeze passed. Sealed .39 raw archive SHA256 200fdf6528512df45a6197e246aa768b267010dd709169619189e77e91283c72; Client DLL 23dbef59f874b2fd4cb0ae850613f5df01076ccdde99b872c7fe2d6d390d62dc. Native module/schema unchanged.

LINUX0939-SUPPORT-AUDIT-SHUTDOWN-STAGING/ACTIVATION-20261008-R1 PASSED. Release /opt/ransomfree-client/releases/20261008-managed0939-r1-upgrade-r1; ordinary/native PIDs 3953836/3953832 at activation. All 23 prior raw banks, 775617408 bytes, verified hashes, size, device and inode unchanged; original enrollment/configuration and explicit 2 GiB capacity preserved. Root collector separately upgraded normally; config unchanged, ordinary/native PIDs unchanged. Update cumulative counters rose by 4 drops and one rejected boundary; do not call those counters zero. Initial activation-upload sender referenced wrong metadata filename and refused before upload/execution; corrected immutable R2 sender used.

LINUX0939-SUPPORT-FRESH-NATIVE-READS/CENTRAL-20261008-R1 PASSED six actual root/ordinary-user preopen/read accesses on three production honeypot paths, independent PID/birth/credentials/executable identity/hash and six central executable/manifest downloads. DENIED-OPEN/CENTRAL-20261008-R1 PASSED actual living ordinary-user EACCES, accurate event credentials including filesystem GID, parent, process start/session, capped historical title explicitly partial and separately captured full image-bound procfs command, plus actor/manifest download hash verification. POST-RESTART-DENIED-OPEN/CENTRAL-20261008-R1 also PASSED after the failed restart-loss gate; target permissions and metadata restored exactly. Target files not hashed/copied. Neither test establishes full Linux operation matrix or short-lived denied-image acquisition.

### Resource and capacity evidence

LINUX0939-SUPPORT-AUDIT-SELF-ACTIVITY-20261008-R1 PASSED 31.83 seconds: zero self opens/new packets/drop or rejection delta, fresh running collector with health failure null. MINUTE-RESOURCES R1 sampled all three stable service PIDs for 60 seconds: ordinary/native/audit machine CPU 0.46/0.91/0.16%, total 1.53% on four logical cores. RSS 145.02/128.18/75.66 MiB, with shared pages possibly counted more than once; reads zero, writes 4096/32768/49152 bytes, total 86016. Quiet sample only; not heavy or long-duration qualification.

VMWARE-LIVE-RESOURCE-USE-20261008-R6: physical host 10.81.60.100 CPU 43894/43880 MHz (approximately 100%), RAM 431.029/447.890 GiB (96.24%). Owned Linux qualification VM remains powered off at 4 vCPU/16 GiB. No resource allocation increase, power-on, migration or unrelated workload change; host capacity does not support heavy VM qualification now.

LINUX0939-FOURTEEN-HOST-RESOURCE-STAGING-20261008-R1 PASSED 14 exact 6.12.94+deb13-amd64 hosts, 232 payload/187 cache members verified. Immutable .39 candidate staged alongside retained older candidates. All live services/configurations/enrollments/native installations unchanged. Wider activation has not occurred; these hosts still use their previous installed version.

### FAILED live restart gate and remaining handoff repair

LINUX0939-SUPPORT-AUDIT-GRACEFUL-RESTART-20261008-R1 FAILED its zero-new-loss assertion. Normal collector exit/restart returned; ordinary/native untouched, new collector PID 3956673 at readback, fresh/running, health failure null. Preserved before/after statuses in /root/sequester-audit-collector-update-f29a3bdbd20d44fda438e40744c4b674 show cumulative drops 347 to 352 and rejects 278 to 279. Transport failure count remained zero; this failed gate is retained and is not a pass.

Code inspection establishes two mechanisms: AuditTransport initializes priorDrops=0 on every connection, so relay cumulative losses are counted again; AuditRelay removes a chunk from its queue before sending and increments dropped/discards it if sending fails. The first mechanism inflates reported deltas; the second can lose an in-flight chunk during collector handoff. The failed receipt cannot identify the missing chunk's contents, so no claim that all increments are false or that lost chunks could not contain canary records. Follow-up actual denied-open and central artifact acceptance passed, but full lossless restart is outstanding.

Next repair requires relay-instance-scoped cumulative-loss tracking and acknowledged delivery with bounded retention/replay of in-flight chunks, explicit sequence/version compatibility, duplicate handling and durable ownership. Qualification must restart collector/relay with actual queued canary operations, compare every independent operation to server evidence and downloaded actor bytes, test counter/peer/PID reset and overflow, and expose every unavailable/gap state. Avoid restoring an executable/PID from a different process instance. Heavy VM/load qualification and wider activation remain gates; final product-wide three QA passes are not claimed.

## 2026-10-09 — Wazuh routing and informational export

Read-only live Wazuh inspection verified 34 active enrolled clients, including all four Windows hosts. Dedicated manager 10.81.100.10 accepts TCP syslog on 514 but presently authorizes only the firewall source 10.87.5.1/32; non-alert archives are disabled. Agent activity alone does not establish collection of seQuester service logs.

Source now supports an optional server-side IncludeLogOnlyEvents setting and Notifications checkbox. Whitelisted originals and linked forensic results can be forwarded at informational severity with server-validated NotificationSuppressed=true, without changing enforcement. Locked build and 472 EventHistoryFixture checks passed, including real HTTP ingest/protected settings/TCP evidence export; ten actual Chromium module checks passed with synthetic APIs. Source changes are not deployed. Live receiver authorization, decoders/rules, non-alert retention, service-log collection, manager persistence/search and delivery-failure acceptance remain pending. No Wazuh-triggered response was enabled. See docs/WAZUH-INTEGRATION.md. Linux acknowledged relay replay and Windows remaining collection boundaries are unchanged and unfinished.
## 2026-10-09 — Linux acknowledged replay collector candidate (not deployed)

Root-private bounded raw replay journal passed 28 actual Linux checks on support01. Protocol-v2 Unix transport passed 36 actual checks: durable admission before ACK, torn-frame reconnect, collector reopening, duplicate suppression, loss counter reuse and stream-identity validation. Current managed LinuxAgent build has zero warnings/errors. Candidate dispatcher now retains unfinished raw input across shutdown, retires only after durable output at an empty parser boundary, and exposes parser collection failure as degraded health. Exact receipts: LINUX-AUDIT-REPLAY-JOURNAL-20261009-R1.json and LINUX-AUDIT-REPLAY-TRANSPORT-20261009-R1.json. No live services/current links changed. Native AOT build image is available on ops01; no extra VM allocated.

The deployed relay remains protocol v1 and unchanged. Native AOT sender/retention across relay restart, actual dispatcher/libauparse replay, existing regressions, package provenance, pilot activation, fresh independent server/artifact matching and resource acceptance remain pending. The 64 component checks are not a live zero-loss restart or whole-product pass. See docs/LINUX-AUDIT-REPLAY.md for exact design, bounds and ordered gates. Wazuh remains deferred to the end-of-work discussion.
## October 9, 2026 — Linux audit relay restart candidate

Linux managed 0.9.40 and Native AOT relay 0.9.2 are built and sealed for qualification, not deployed. Durable sender/collector raw ownership, matching acknowledgements, stream sequencing, explicit loss counters, queue telemetry and retained parser failures are implemented. Current-source journal/transport fixtures passed 28/37 checks; actual native runtime passed 73; actual dispatcher/libauparse fixtures passed 19 graceful and 28 interrupted/failure checks using synthetic audit records. The pilot .39 selector lacks audit launcher/hash-binding files; .40 includes them. Exact package launcher/runtime, migration, real host/server attribution and resource acceptance remain pending. Windows boundary gates and Wazuh end discussion remain open. Details: docs/LINUX-AUDIT-REPLAY.md.

October 9 update: support01 managed 0.9.40 pilot is active; auditd relay permission failure corrected to 0750, 24 retained banks verified unchanged. Six fresh real native read cases and six actual central executable/manifest downloads passed. Relay 0.9.2 open-idle stdin SIGTERM test FAILED; 0.9.3 repair/build qualification in progress. Wider rollout, resource/restart acceptance and final product three-pass QA remain pending. Details and exact receipts: docs/LINUX-AUDIT-REPLAY.md.

October 9 live qualification: .93 relay passed 89 isolated/39 package checks, but real auditd reload/queued access acceptance FAILED. Canonical normal auditd restart restored input; a masked-signal defect was independently identified. .94 signal-mask repair is building; actual queued operation and final .94 acceptance pending. No wider rollout/full product acceptance claimed. See docs/LINUX-AUDIT-REPLAY.md.

October 9 correction: .94 cold pilot activation/native read/server artifact checks passed, but actual queued sender SIGTERM FAILED. Inherited SIG_IGN is now reproduced and explained by primary .NET source. .96 ignored-disposition repair is building; wider activation/restart/resource and final product QA remain pending. Original failures preserved; details: docs/LINUX-AUDIT-REPLAY.md.


2026-10-09 Linux audit relay 0.9.6: isolated Native AOT 882 checks and packaged launcher/collector 39 checks passed. Repairs inherited ignored TERM/HUP dispositions; live pilot, central evidence and wider rollout still pending. See docs/LINUX-AUDIT-REPLAY.md. Manus research stopped on exhausted credits; no completed report claimed.


2026-10-09: support01 Linux relay 0.9.6 pilot accepted: normal 0.103-second termination, durable denied-open replay, central executable/manifest verification and six fresh short-lived native read actors. Quiet combined CPU 1.91% of four-core VM, RSS 375.74 MiB. Fourteen older Debian hosts still require activation and acceptance; native services were failed at preflight. RejectedRecords includes stream boundary resets; historical drops were retained. Entire specification and final product-wide QA remain incomplete.


### 2026-10-09 Linux denied-open recovery — in progress

The 13-host 0.9.40 cohort passed 78 actual fresh reads with central actor metadata and artifact-pair checks. A fresh queued denied-open failed on scanopy-dmz01 despite a complete kernel audit record; wider denial acceptance is not passed. Candidate 0.9.41/relay 0.9.7 is being qualified for explicit pathless actor delivery and exact protected-log recovery. Initial isolated checks: protected reader/parser 28, durable inbox 11, collector/restart/failure 21. Bounded-retry final build and live central validation remain pending. Final full-product three passes and Windows operation/minifilter qualification remain pending. See docs/LINUX-AUDIT-REPLAY.md for immutable receipts and actual scope.


2026-10-09 update: 0.9.41/relay0.9.7 passed actual scanopy-dmz01 activation, fresh restarted DAC-denied attribution and central actor executable download, plus six native reads with central artifact checks. Quiet RSS374.31MiB/VM CPU4.315%; sustained-load and wider denial acceptance remain pending. Full details and receipts: docs/LINUX-AUDIT-REPLAY.md.


2026-10-09: managed0.9.41/relay0.9.7 deployed and live read/queued-denied accepted on 17 existing Linux sensors (16 qualified Debian companions, Plex audit-only). Protected central validation:102 actual read cases +17 actual denied-open cases,119 actor binary/manifest pairs downloaded and verified. Other kernels, Windows gates, all-operation/canary and sustained-load/product-wide QA remain pending. Full scope, failure receipts and resource measurements: docs/LINUX-AUDIT-REPLAY.md.

### 2026-10-09: remaining Linux activation and fresh Windows operation tests

All 26 existing Linux sensors now run managed 0.9.41 and audit relay 0.9.7: 17 native companions (16 qualified Debian kernels and www-legacy's existing Ubuntu manifest v1) and nine audit-only sensors. Across the 26 sensors, 156 actual reads and 26 controlled DAC-denied open attempts passed server metadata and executable/manifest download checks (182 pairs). Six additional www-legacy native reads passed after a real policy-outage recovery (188 case pairs including that retest). Audit-only living-process attribution does not establish short-lived denied-access or native early-capture qualification on those kernels.

All 17 native units now have the special exit-75 restart rule with a 10-second delay. The 14 newly changed units retained the same processes during daemon reload, and the follow-up inventory found all 17 monitoring. www-legacy passed actual signed-policy expiry, complete driver closure/unload, restart, policy restoration, and six fresh reads. Fresh Debian outage qualification remains pending. Quiet www-legacy measurement: combined RSS 375.17 MiB, 2.425% of its four-core CPU; sustained workload qualification remains pending.

The four Windows hosts completed 15 fresh controlled operations each on existing 0.6.25 sensors, restoring their original settings. The matrix covers read and impersonation transitions, write/append/rename/delete/truncate, and DAC-denied open attempts for each operation. Central metadata is present, but fresh executable download acceptance is blocked by the management server's exhausted 10 GiB global evidence quota. The server has about 72 GiB free; a guarded same-release quota increase to 32 GiB is in progress. HTTP 507 reservation failures and HTTP 404 download failures are retained; local preservation is not central binary acceptance. Already-granted-handle failed operations remain a separate gate.

Receipts are in diagnostics/windows-token-20260930: LINUX0941-REMAINING-READS-CENTRAL-20261009-R2, LINUX0941-REMAINING-DENIED-CENTRAL-20261009-R3, LINUX0941-WWW-DENIED-CENTRAL-20261009-R1, LINUX0941-WWW-POST-RECOVERY-READS-CENTRAL-20261009-R1, LINUX0941-DEBIAN-POLICY-RECOVERY-CONFIG-20261009-R1, LINUX0941-NATIVE-RECOVERY-UNITS-20261009-R2, and WINDOWS-SERVER42-{Desktop,DC,NVR,Storage}-0625-OPERATIONS-20261009-R1. Earlier failed harness revisions are preserved. Full Linux operation matrices, all callback file-type application tests, broader kernel/load qualification, and final product-wide three-pass QA remain incomplete. Wazuh integration remains an end-of-work discussion item.

2026-10-09 follow-up: central quota repair passed on the unchanged server 0.6.42. Global capacity is now 32768 MiB, with per-sensor capacity still 4096 MiB; 33 endpoint IDs were preserved and the separate callback receiver PID did not change. Backup, binary hash, launcher hashes and the exact stop method are recorded in SERVER42-EVIDENCE-QUOTA-20261009-R2.json. The first restart harness checked termination too early; its failure is retained, configuration was unchanged, and the corrected bounded stop wait passed. This used the existing scheduled-task deployment method with an exact process identity guard; graceful console shutdown was unavailable and is not claimed.

All four Windows hosts now passed the fresh central validation: 60 operations, independently compared user/process/PID and process-owner/effective-thread token truth, target-operation results and state changes, and 64 actual actor executable/manifest download pairs with SHA-256 and event linkage verified. Receipts: WINDOWS-SERVER42-{Desktop,DC,NVR,Storage}-0625-OPERATIONS-CENTRAL-20261009-R2.json; summary WINDOWS-FOUR-HOST-CENTRAL-ACCEPTANCE-20261009-R2.json. Desktop pending uploads reached zero. Controlled DAC-denied open attribution is qualified; failure after an already-granted handle is not covered by this matrix.

NGINX01 passed the fresh Debian policy-outage recovery test in 135.93 seconds, retaining its configurations and closed banks; six fresh short-lived native reads and six actual server executable/manifest downloads also passed. Receipts: LINUX0941-DEBIAN-POLICY-OUTAGE-20261009-R1 and LINUX0941-DEBIAN-POST-RECOVERY-READS-CENTRAL-20261009-R1. Counting the two additional recovery retests gives 194 Linux case artifact pairs; this is 182 baseline cases plus 12 retest cases, not 194 different host/operation combinations. All-host Linux resource sampling is in progress. Full Linux write/rename/delete/truncate validation, all-type native canary consumer acceptance, broader load/kernel qualification and final three-pass product QA remain pending.

2026-10-09 resource follow-up: all 26 current Linux sensors completed 60-second read-only samples covering the ordinary agent, audit collector and relay, plus the native companion on 17 hosts. Maximum observed combined CPU was 3.55% of a sensor VM (scanopy-wireless01); summed process RSS ranged from 255.14 to 444.00 MiB. These are observations without injected sustained workload, not a high-volume qualification or a promised resource ceiling. RSS sums can double-count shared pages. Raw samples and summary: LINUX0941-ALL-MINUTE-RESOURCES-20261009-R1 and LINUX0941-ALL-MINUTE-RESOURCE-SUMMARY-20261009-R1.

A fresh five-operation Linux pilot (write/append/truncate/rename/delete) is being prepared on NGINX01. Test-only byte backup and a protected hard link preserve the original canary inode for restoration, including delete. The first admission rejected the incorrect root-owner assumption before touching any target; actual folders are owned by the verified sensor service account. No operation acceptance is claimed until the pilot and central evidence checks pass.

## 2026-10-09 Linux operation follow-up

The corrected NGINX01 in-place operation pilot restored original canary bytes, metadata and inode. Exact write/append operation acceptance failed: only write-opens were emitted by the kernel audit source. Audit permission filters deliberately omit individual read/write calls. The original hard-link backup was incompatible with native single-link admission; that native source closed and drained. Normal native service restoration and six fresh central read/actor-download retests passed. All 17 native companions subsequently reported active/ready (LINUX0941-NATIVE-RECOVERY-UNITS-20261009-R4).

Immediate first-use truncation reached the server with explicitly unavailable actor binding/hash/preservation and failed full acceptance. A separate truncate actor with a documented 100 ms birth delay passed exact process identity, command line, event credentials, SHA-256 and actual central executable/manifest downloads (LINUX-OWNED-TRUNCATE-CENTRAL-20261009-R5). Do not generalize that result to immediate or short-lived operation capture.

Typed Linux collection failure reasons are implemented in source, with 10 component checks and 57 actual Linux forensic regression checks passing. They retain existing PID/image binding guards and raw OS errors. This diagnostic change is not deployed and does not fix missing operation hooks. Actual installed kernel BTF prototypes for native operation integration are recorded in LINUX-OPERATION-KERNEL-PROTOTYPES-20261009-R1. Integration/acceptance details and remaining gates are in docs/LINUX-OPERATION-CAPTURE.md. Full Linux I/O operation coverage, broader qualification/load testing and final product-wide three-pass QA remain pending; the owned qualification VM remains off while ESXi is at approximately full CPU use. Wazuh remains deferred for discussion at the end.

2026-10-09 deployment in progress: Linux diagnostics release 0.9.42 was sealed and passed 39 packaged runtime/launcher checks, following 10 binding-status checks and 57 actual Linux forensic regression checks. The launcher explicitly accepts the new release version without changing its ownership, permissions, architecture, SHA-256 or process protection checks. The initial immutable package was rejected by its old version allowlist before any installation; the corrected package is LINUX0942-BINDING-PACKAGE-20261009-R3.

Twenty-five Linux sensors are activated, with 102 fresh read/actor-artifact pairs centrally accepted across 17 hosts so far. The four Windows sensors remain current at 0.6.25 with running drivers and zero pending evidence uploads; management server remains 0.6.42, with global evidence capacity 32 GiB. Failed test host-guard and early Plex status-file polling receipts are retained; the corrected host tests passed and Plex was verified without an additional restart. The final legacy web-host deployment and remaining read/server gates are still pending. This update supplies precise Linux collection-failure reasons; it does not add missing write/append hooks or complete the broader specification.

## 2026-10-09 Linux 0.9.42 deployment completed

All 26 existing Linux sensors now run 0.9.42-linux-dev. The live management API confirms those exact sensor identities and the four Windows sensors at 0.6.25; the management server remains 0.6.42. All 17 native Linux companions were independently checked active and ready after rollout; the other nine retain their existing audit-only mode. No new kernel/module profile was deployed.

Fresh read acceptance passed six cases on each Linux sensor: 156 cases, with independently checked user/process/PID, process-instance and executable identity, and 156 actual server executable/manifest download pairs with hashes and event linkage checked. Two additional living-audit denied-open retests (Ops and Plex) passed actual central actor artifact checks. Those two tests are representative checks, not a new denied-operation qualification on all hosts. The existing Windows build retains its separately recorded 60-operation/four-host central acceptance and 64 artifact pairs.

The final web-host activation harness initially assumed the native service was still failed; its pre-installation assertion stopped before changing services or selectors. Read-only diagnosis confirmed the recovered native service was healthy. The corrected active-service lifecycle passed, including clean shutdown, BPF/module closure checks and unchanged retained raw evidence. The earlier failed receipt is retained. Normal audit relay transitions had measured intervals; no lossless transition claim is made. Measured rejected-record increments remain visible in activation receipts rather than being reported as zero.

After deployment, all 26 Linux hosts completed read-only approximately 10-second resource samples. Maximum observed combined CPU was 3.85 percent of a sensor VM; summed process RSS ranged from 218.16 to 424.68 MiB. This was not injected sustained-load testing. RSS sums may double-count shared pages and are not a resource ceiling.

This release adds stable Linux actor collection failure reason codes while retaining process birth/image validation and raw OS errors. It does not add exact Linux write/append hooks or solve immediate first-use actor capture. Full Linux operation matrices, broader kernel/load qualification, all consumer callback file-type acceptance and final product-wide three-pass QA remain pending. Wazuh remains an end-of-work discussion item.

Immutable acceptance: diagnostics/windows-token-20260930/LINUX0942-ALL-DEPLOYMENT-ACCEPTANCE-20261009-R1.json. Release ransomfree-client-0.9.42-dev.20261009T200141Z-fd4fa98b0ae0-linux-x64, archive SHA-256 b60f2fcca24cfe494248c78bc13735a84bbe2d834b13e03e49e41e200cf0e79e. Supporting receipts: LINUX0942-SERVER-INVENTORY-FINAL-20261009-R1, LINUX0942-NATIVE-READINESS-FINAL-20261009-R1, LINUX0942-ALL-POST-DEPLOYMENT-RESOURCES-20261009-R1, LINUX0942-REMAINING-ROLLOUT-20261009-R4, and all read/denied central receipts linked by the acceptance summary. Previous in-progress entries above are historical checkpoints.

### October 11 additional evidence and scheduling repair

Completed failed-run artifacts were retrieved after console wake. Read-only inspection of the durable intake independently matched all three attempted operations against producer truth: exact PID/start time, thread ID, operation/result, owner token, effective impersonation token, target path, raw hash and zero native loss. One original/completion pair was eventually delivered to the sensor spool. Both linked event records identify the preserved executable whose bytes match the recorded SHA-256 and exact version-2 proactive acquisition binding. The other two records remain pending. This is partial failed-run evidence, not all-nine acceptance or central receipt.

The syscall receiver previously used a shared thread-pool task despite synchronous native calls and SQLite commits. It now uses a dedicated receiver thread and synchronous cancellation-aware poll waits, matching the existing minifilter scheduling approach. The raw commit-before-ACK order and immutable publication pairing are preserved. New scheduling checks passed; targeted counts are 103 decoder, 271 reporting/recovery and 55 actual native transport replay checks. Debug and published Release fixture builds are clean. This addresses a concrete scheduling weakness; the live delay has not yet been proven resolved.

The guest stopped during recovery and a normal power-on entered Windows recovery/startup options. Original administrative sessions and the diagnostic snapshot remain retained. Current restoration and a new live test are pending.
