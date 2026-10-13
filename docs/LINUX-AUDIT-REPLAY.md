# Linux audit restart repair — October 9, 2026

## Deployed problem

The .39 live collector restart zero-loss test failed. The original relay removes
a chunk before sending and discards it on send failure. The collector also
reinitializes its cumulative relay-loss baseline on every connection. These are
distinct mechanisms; historical loss increments are not all proven false.

## Collector candidate implemented

- `AuditReplayJournal.cs`: bounded root-private durable raw-frame storage,
  integrity hashes, stream instance/sequence identity, explicit sequence and
  counter validation, atomic checkpoint replacement and directory fsync.
- `AuditTransport.cs`: protocol-v2 announcement/acknowledgement, authenticated
  Unix peer checks, durable admission before ACK, same-instance replay without
  a fabricated gap, duplicate admission suppression and idle heartbeats without
  disk writes. Existing protocol-v1 decoding remains available when no retained
  v2 input would be bypassed. Legacy in-process reconnect loss accounting is now
  scoped to PID + process start time; v1 collector-restart accounting is not
  qualified as repaired.
- `AuditDispatcher.cs`: ordered raw replay, durable output before raw
  retirement, cumulative replay-loss checkpoint, preservation of unfinished
  v2 record sets across shutdown, and explicit degraded health/blocked raw
  retirement following parser collection failure.
- `AuditParser.cs`: collection-error state retained rather than implying that
  native callback rejection means raw input was successfully collected.

Protocol-v2 frame types: 6 announcement (16-byte stream GUID), 4 data
(GUID + 64-bit sequence + 64-bit cumulative lost-chunk count + up to 8192 bytes),
7 idle heartbeat, 8 bounded queue telemetry (pending frames/bytes and unreported
lost chunks). Announcement ACK echoes the GUID; data ACK echoes GUID and
sequence. Loss totals count relay chunks, not independently proven file
operations. No process credentials or actor identity are inferred from this
transport stream ID.

Journal bounds: 4096 retained frames, 64 MiB logical record bytes, 256 stream
identities. Full storage refuses admission and preserves existing records.
Corrupt or missing retained records are explicit failures, not skipped input.
Stream-identity archival remains a maintenance requirement at the finite bound.

## Actual component acceptance

1. Journal fixture: **28 passed checks** on support01, including actual file
   flush/directory fsync, protected ownership checks, duplicate/lost-ACK
   handling, reopening, interrupted admission, missing/corrupt records,
   sequence/counter errors and the full 4096-entry capacity.
2. Transport fixture: **36 passed checks** on support01, including actual root
   Unix peer authentication, announcement/data ACK, durable raw ownership,
   torn-frame reconnect, restart replay, duplicate suppression, explicit new
   loss boundary and rejection of an unannounced stream identity.
3. Current-source journal rerun: **28 passed** (`...JOURNAL-20261009-R3.json`).
   Current-source transport rerun: **37 passed**, including queue telemetry
   bound to the authenticated peer/stream (`...TRANSPORT-20261009-R2.json`).
   These supersede the earlier 28/36 source snapshots for this component scope.
4. Native AOT relay 0.9.2 build passed from eight hashed source files. Actual
   isolated runtime passed 50 checks: inherited kernel MDWE with empty child
   environment, exact-byte retransmission after a lost ACK, raw retention and
   recovery across relay process restart, distinct process stream IDs, protected
   evidence permissions, no idle checkpoint rewrite and graceful EOF/TERM.
   Short idle CPU sample was 0.67% of one core under a 0.25-core container limit;
   this is not a live sensor resource acceptance result.
5. Extended native runtime: **73 passed checks**, including the 4096-frame
   queue boundary, durable overflow loss notes, recovery of interrupted loss
   sidecar replacement, loss-only frames, retained queue after shutdown, and
   explicit corruption failure without overwriting retained evidence.
6. Actual dispatcher + libauparse + native relay: **19 passed checks** for
   graceful collector restart with a denied-open record split mid-line; **28
   passed checks** for interrupted collector exit, loss counted once across
   restart, and callback rejection preserving raw evidence. These use synthetic
   audit records inside isolated containers, not real kernel file operations.
   Interrupted-exit fixture models systemd's removal of the dead collector's
   private runtime socket. The collector intentionally refuses an existing
   socket; it never deletes another possible owner's socket automatically.

Dispatcher receipts: `AUDIT-REPLAY-COLLECTOR-RUNTIME-20261009-R2.json` and
`AUDIT-REPLAY-COLLECTOR-RUNTIME-20261009-R5.json`. Failed runtime-image and
unmanaged socket-lifecycle attempts are retained and do not count as passes.

Native source now uses `RelaySpool.cs` for durable sender ownership, bounded
loss sidecars with interrupted-write recovery, and explicit storage failures.
Expensive parsing/enrichment remains outside the auditd plugin. Source-generated
JSON supports Native AOT. Unacknowledged frames survive process shutdown;
matching collector ACK is required before sender retirement.

Native receipts: `NATIVE-AUDIT-RELAY-092-BUILD-20261009-R1.json` and
`NATIVE-AUDIT-RELAY-092-RUNTIME-20261009-R4.json`. Binary SHA-256:
`f015699898ef7768ecb5522b5c9e0c199bbe8115812dc03e851041680e6ebda9`.
The first two runtime attempts failed to launch the test interpreter, before
application testing. Those failed receipts are retained; they are not passes.

Exact receipts are under diagnostics/windows-token-20260930:
`LINUX-AUDIT-REPLAY-JOURNAL-20261009-R1.json` and
`LINUX-AUDIT-REPLAY-TRANSPORT-20261009-R1.json`.
Tests used isolated root-private directories; no audit subscriptions, service
changes or current-link changes. Transport fixture redirects only its socket
and root paths and uses the actual ownership/framing/journal source. Its apphost
is a JIT fixture, not a qualified auditd Native AOT relay.

Native AOT builder preflight found the existing pinned SDK/build image on ops01
(sha256:fa624bbc2e6bc5dac23ab4132261cdacb6520b4f8ab0ab395d8bd02fd4f15431),
with approximately 19 GiB available VM RAM and 105 GiB disk. This establishes
builder availability only; physical host CPU remains constrained. Use a bounded
CPU/memory build container rather than allocating another VM.

## Remaining implementation and gates

This is an **undeployed collector candidate**. The production relay still
speaks protocol v1 and has not received this change.

Managed 0.9.40 ReadyToRun build passed with unchanged source before/after the
build. A frozen package now includes `audit/launch-relay.sh`, native relay,
three-line `LAUNCHER_IDENTITY`, all eight native source hashes, current component
receipts and a complete file manifest. Exact package runtime and pilot gates
remain pending. Package receipt: `LINUX0940-AUDIT-REPLAY-PACKAGE-20261009-R1.json`.

Read-only pilot inspection found `.39`'s selected release lacks the audit
launcher/hash-binding files referenced by the existing auditd plugin. This is a
restart defect even while an already-running old relay continues. The `.40`
package repairs that layout; do not restart auditd through the broken selector.

1. Complete output/storage-failure and sustained-input resource qualification.
   Native overflow/corruption/loss-sidecar and dispatcher restart/counter/error
   checks passed within the scopes above; production ownership is unchanged.
2. Update package provenance and launcher hash bindings for all added source
   files. Native build and isolated inherited MDWE startup passed; installed
   auditd/plugin qualification is still pending.
3. Run actual libauparse/dispatcher tests with fragmented record sets, graceful
   and interrupted collector exit, callback/output failure, persisted counter
   replay, and exact stable event IDs. The 64 component checks do not establish
   full parser lifecycle correctness.
4. Rerun existing v1 parser/transport regressions and prove migration/rollback
   behavior while preserving all previous evidence. Never switch to a v1
   collector that cannot recover retained v2 raw input without an explicit
   migration plan.
5. Stage a new explicit managed/relay candidate version. Only after isolated
   qualification, normally activate support01 with a preserved backup.
6. Repeat controlled queued canary and denied-open operations across collector
   and relay restarts; independently match every operation, principal, PID,
   process birth, actor hash and downloaded binary/manifest through the server.
7. Measure quiet CPU, resident memory, writes, overflow behavior and sustained
   input. No wider activation before these gates. Additional-kernel and heavy
   VM qualification remains separate work.

Windows accessing-thread/APC and pre-IRP denied-operation boundaries are
unchanged. Wazuh routing and response decisions remain on the end-of-work
discussion list. Full product acceptance is not established by this repair.


## October 9 live pilot recovery and remaining relay shutdown defect

The support01 ordinary sensor and native companion are now running managed
0.9.40. The actual auditd-child Native AOT relay 0.9.2 is connected with
protocol v2. `LINUX0940-PILOT-RECOVERY-20261009-R1.json` independently verified
all 24 previously closed raw evidence banks, their byte hashes, sizes and
filesystem identities. `--audit-health` returned zero with the same live
collector/relay identities and an advancing heartbeat. This is not wider
rollout acceptance.

The first activation failed because auditd 4.0.2 rejects a plugin launcher
whose permissions are 0755; it requires exactly 0750. The installed launcher
was tightened to 0750 without changing its bytes, the normal plugin path was
restored and auditd reloaded. An earlier normal auditd restart was part of the
diagnosis. Protections were not disabled. Retain the original failed activation
receipt and the permission-recovery receipt. The legacy v1 migration had an
audit relay gap from approximately 12:15 to 12:36 UTC; do not claim a lossless
migration. Historical collector counts remain visible (352 dropped input,
280 rejected records); kernel audit lost=0 and v2 replay loss=0 at recovery.

Fresh real accesses passed on this pilot: six root/ordinary-user native read
cases across three honeypot files, independently matched process birth and
executable identity, plus actual server original/completion events and six
downloaded executable/manifest pairs with matching SHA-256. Receipts:
`LINUX0940-SUPPORT-FRESH-NATIVE-READS-20261009-R1.json` and
`LINUX0940-SUPPORT-FRESH-NATIVE-CENTRAL-20261009-R1.json`.

Native relay 0.9.2 still has a proven shutdown defect: SIGTERM hangs if stdin
remains open and idle (`NATIVE-AUDIT-RELAY-092-RUNTIME-20261009-R5.json`).
The 0.9.3 candidate replaces console ReadAsync cancellation with nonblocking
stdin and a bounded poll/read loop. Consumed bytes are admitted to durable
storage even when cancellation races the read. Linux poll/read behavior was
checked against https://man7.org/linux/man-pages/man2/poll.2.html and
https://man7.org/linux/man-pages/man7/pipe.7.html. Native build and fresh
runtime qualification are pending; no 0.9.3 activation is claimed here.
Installer, staging and launcher preflight now require launcher mode 0750.
The sealed old archive remains unchanged; the corrected package must bind
and validate Unix modes as well as content hashes before wider deployment.

Remaining: qualify the repaired relay, denied-open central evidence, queued
live restart tests, quiet/sustained resource use, and then wider activation.
Windows operation/APC/pre-IRP qualification and additional Linux kernels
remain separate unfinished gates. Wazuh remains an end-of-work discussion.


## October 9: real auditd qualification exposed reload-only failures

The 0.9.3 Native AOT relay passed 89 isolated runtime checks including open-idle
stdin SIGTERM, repeated shutdown, retained data, and inherited kernel MDWE.
The corrected archive binds Unix modes (package schema v2), and 39 packaged
launcher/parser/relay checks passed. Immutable archive SHA-256:
01c9edd7cf76e5d0961cd0f72be00cf0708bfaaa7fc8e26d8e2f90a4c5974bda.

Pilot R2 activated the .40 workers and .93 binary, but its auditd reload gate
FAILED. A subsequent reload connected the .93 child and all 25 closed banks
verified unchanged, yet a real queued denied-open test still FAILED: the kernel
record existed in audit.log but no sender raw record arrived. A connection
heartbeat alone did not establish data flow. Keep both failed receipts.
Normal auditd restart with the canonical plugin restored actual data flow
(InputBytes 10983 after the owned probe). No protections were disabled and
there was no forced process termination. The audit plugin/reload intervals
are not claimed lossless. Fresh actual queued operation and central acceptance
must pass after this restart.

Independent /proc evidence showed the reload-created child and its threads
inherited a blocked mask including SIGTERM and SIGHUP; startup-created children
after the normal auditd restart had zero blocked mask. Audit-userspace v4.0.2
source confirms its outbound worker blocks those signals and safe_exec does
not clear the mask before exec. The .94 candidate registers handlers, then
unblocks only TERM/HUP in its own calling thread before starting workers.
It does not change auditd or host protections. This new candidate's build and
masked-signal/real auditd socketpair runtime acceptance remain pending.

Sources:
https://raw.githubusercontent.com/linux-audit/audit-userspace/v4.0.2/audisp/audispd.c
https://man7.org/linux/man-pages/man3/pthread_sigmask.3.html

A quiet 60-second pilot .40/.92 sample measured approximately 1.63% of the
four-core VM CPU and 427 MiB total RSS across four main processes. This is not
sustained/high-volume acceptance or a measurement of the final .94 candidate.
Receipts: LINUX0940-SUPPORT-MINUTE-RESOURCES-20261009-R1.json,
LINUX0940-PILOT-ACTIVATION-20261009-R2.json,
LINUX0940-SUPPORT-QUEUED-DENIED-OPEN-20261009-R1.json,
LINUX0940-AUDITD-CANONICAL-RESTART-20261009-R1.json,
LINUX0940-AUDIT-SIGNALS-20261009-R2.json.
Wider activation remains pending; final product three-pass QA is not complete.


## October 9: masked-signal repair qualification and real queued evidence

The .94 Native AOT candidate passed 92 isolated runtime checks using a real
AF_UNIX/SOCK_STREAM stdin pair, an empty exec environment, actual inherited
kernel MDWE, and auditd's blocked TERM/HUP/USR1/USR2/CHLD/CONT mask. TERM/HUP
were unblocked; the other four inherited blocks remained. Open-idle shutdown,
five repetitions, HUP, exact retained replay, overflow and corruption checks
passed. The .93 binary reproduced the blocked-mask failure in a separate
negative fixture. An initial .94 overflow-sidecar test observed the raw file
before transaction cleanup completed; the corrected fixture waits up to five
seconds for the durable transaction to finish. Source bytes were unchanged.
Keep that initial failed fixture receipt; do not treat it as a runtime pass.

After the canonical normal auditd restart, a fresh real denied-open record
was proven present in protected relay raw storage while the collector was
stopped. After restart, the actual original/completion event and executable /
manifest downloads matched on the server. DroppedInputRecords stayed 352;
ReplayLossReported stayed zero. This establishes one living-actor denied-open
queued collector-restart case, not short-lived actor or full operation coverage.
Six additional real root/ordinary native read cases and central binary /
manifest downloads also passed on the .40/.93 package.

Receipts: NATIVE-AUDIT-RELAY-094-RUNTIME-20261009-R2.json (92 checks),
NATIVE-AUDIT-RELAY-093-MASKED-NEGATIVE-20261009-R3.json (expected old-version
failure), LINUX0940-SUPPORT-QUEUED-DENIED-OPEN-20261009-R2.json,
LINUX0940-SUPPORT-QUEUED-DENIED-CENTRAL-20261009-R2.json,
LINUX0940-SUPPORT-FRESH-NATIVE-CENTRAL-20261009-R2.json.

The .94 package is now sealed, with ten source files in native provenance and
Unix modes bound in package schema v2. Archive SHA-256:
8c2ebd59d602fa412b97acbb14d2c3502db06afea766283511f376861a970d74.
Packaged acceptance and actual .94 deployment are pending at this entry.
Future pilot controller uses normal auditd restart with the canonical plugin,
preserves sender/collector journals, reconciles rules, and requires actual
input bytes in addition to a connection heartbeat. It records the daemon PID
change and migration interval rather than claiming an unchanged daemon or
lossless restart. Wider activation and final three-pass product QA remain open.


## October 9: .94 live signal failure, inherited SIG_IGN reproduction

Pilot .40/.94 cold activation passed, actual input was observed, and 26 closed
raw banks retained exact hashes/identities. Activation reported zero new
DroppedInputRecords, zero replay loss, and one additional RejectedRecord;
that rejection is not a zero-loss pass. Native .40 fresh read/server evidence
passed again (six cases, six artifact/manifest downloads).

The owned queued sender+collector test FAILED: raw denied-open evidence was
persisted, but SIGTERM did not stop the sender within three seconds. Target
permissions and the collector were restored. A separate ordinary kill(SIGTERM)
also failed; input/heartbeats continued. Signal dispositions were ignored,
not blocked. No forced termination occurred. Do not claim .94 live restart
acceptance from its 92 earlier isolated masked-signal checks.

A separate .94 negative Native AOT fixture reproduces the failure immediately
when TERM/HUP are inherited as SIG_IGN. Public .NET pal_signal.c
InstallSignalHandler deliberately respects SIG_IGN and returns success without
installing the OS handler. This is a confirmed missing fixture/profile, not
proof of garbage collection. Earlier registration-finalizer speculation is
unconfirmed. An intermediate .95 build retains registrations explicitly but
has not been deployed or claimed to solve ignored dispositions.

The distinct .96 candidate resets only the two signals this relay owns to
SIG_DFL before managed registration, registers handlers, then unblocks only
TERM/HUP. Other dispositions and masks, auditd, capability dropping, MDWE and
host security are untouched. Its Native AOT build is running; new qualification
includes inherited ignored AND blocked TERM/HUP, actual socketpair/empty env/
MDWE, bounded 2 MiB input memory pressure, handler disposition verification,
PIDFD shutdown, durability/corruption and the exact failed live test.

Manus private task 7GMHDzxWuucJccGzQnPLJf is independently researching the
same sanitized technical facts. The confirmed SIG_IGN primary-source finding
was sent as a correction so it does not assume GC is established.

Receipts: LINUX0940-PILOT-ACTIVATION-20261009-R3.json,
LINUX0940-SUPPORT-QUEUED-RELAY-DENIED-OPEN-20261009-R2.json (failed),
LINUX0940-RELAY094-DIRECT-TERM-20261009-R1.json (failed),
NATIVE-AUDIT-RELAY-094-IGNORED-NEGATIVE-20261009-R3.json (expected old-version
failure), LINUX0940-SUPPORT-FRESH-NATIVE-CENTRAL-20261009-R3.json (passed).
Wider deployment remains pending.


## 2026-10-09: ignored lifecycle signals, candidate 0.9.6 qualification

The deployed 0.9.4 relay inherited SIG_IGN for TERM/HUP from auditd. The .NET runtime respects that disposition and can report successful registration without installing a handler. Both exact-PID live SIGTERM tests failed without forced termination; retained raw evidence and target permissions were preserved. Garbage collection was not established as the cause.

Candidate 0.9.6 resets only its owned TERM/HUP dispositions before managed registration, retains a static registration owner, then unblocks those two signals. Other dispositions, auditd itself, capabilities, MDWE and host protections remain unchanged. Native AOT binary SHA-256: `4d36c5d40a5f77ade1819fa568e6a0c44c5778fd32fc2735fefe0ef51808bc6d`.

`NATIVE-AUDIT-RELAY-096-RUNTIME-20261009-R1.json` passed 882 checks: inherited ignored and blocked lifecycle signals, actual MDWE, socketpair stdin and empty environment, bounded 2 MiB input/ACK pressure, caught-handler checks, pidfd SIGTERM with open input, retained journal recovery, bounded overflow and corrupt-state visibility. These isolated checks do not establish live pilot or wider rollout acceptance.

The immutable R6 package uses actual seal UTC (`20261009T135241Z`) and keeps managed version 0.9.40 unchanged. Archive SHA-256: `bf86a67c82bf817633a32c99fff0fe5651ef9aa3734ec02833cf42ebc4c94ff5`; manifest SHA-256: `9b3b5ea0992035a49bc59d439a9de609b274abad480ead98735f05b3f4c05c4c`. Exact remote reconstruction passed; packaged launcher/collector runtime passed 39 checks. Live pilot activation, queued denied-open recovery, central evidence and resource sampling remain pending at this entry.

Manus task `7GMHDzxWuucJccGzQnPLJf` acknowledged the reproduced inherited-SIG_IGN cause, then stopped with quota_limit. No completed independent research report is claimed. Source review and measured qualification continue locally.


## 2026-10-09: 0.9.6 live pilot accepted, wider preflight

Support01 R6 activation passed with 27 closed raw banks verified unchanged. Live exact-PID pidfd SIGTERM returned normally in 0.103 seconds while stdin remained open; the queued DAC-denied record survived sender and collector restart and was attributed on the server. Actual server binary/manifest download verification passed. Fresh six native read accesses also passed local and central User/Process/PID, process birth, actor SHA-256 and six artifact-pair verification. Receipts: LINUX0940-PILOT-ACTIVATION-20261009-R4, LINUX0940-SUPPORT-QUEUED-RELAY-DENIED-OPEN-20261009-R3, LINUX0940-SUPPORT-QUEUED-RELAY-DENIED-CENTRAL-20261009-R3, LINUX0940-SUPPORT-FRESH-NATIVE-READS-20261009-R4 and LINUX0940-SUPPORT-FRESH-NATIVE-CENTRAL-20261009-R4 (all JSON). This establishes these exact pilot operations, not all operations or short-lived denied-image preservation.

DroppedInputRecords remained 352 and ReplayLossReported remained zero. RejectedRecords changed 282 -> 283 at activation and 283 -> 284 at the sender restart. This counter includes explicit parser boundary resets: AuditTransport emits a Gap on a new stream's first frame and AuditDispatcher increments rejected even with zero loss; the actual status message was `Relay input gap; recoverable partial evidence flushed before parser reset`, with CollectorHealth.Failure null. Do not describe these increments as proven malformed-record failures or claim a lossless daemon migration interval. The historical dropped count remains visible.

Quiet 60-second sample on the four-core support01 VM: ordinary sensor 1.72% of one core / 141.74 MiB RSS; native companion 3.62% / 130.18 MiB; collector 1.03% / 88.64 MiB; relay 1.27% / 15.18 MiB. Combined machine CPU 1.91%, RSS 375.74 MiB. This is a quiet sample, not sustained high-load acceptance.

The 14-host Debian preflight found ordinary versions still 0.9.18 and all native services failed, while ordinary reporting and audit collectors remained connected. Erpnext01 source closure and journal review showed policy EndOfStreamException/InvalidOperationException failures followed by completed native closure, no loaded module/device and no outstanding source delivery. All 14 have the exact qualified Debian kernel and sufficient disk/memory/raw-bank admission room. Upgrade/attribution qualification proceeds first on erpnext01, then sequentially; no wider completion claim at this entry.


## 2026-10-09: wider rollout and a reproduced missing denied-open event

Managed 0.9.40 / native relay 0.9.6 were activated on 17 Linux sensors: 16 exact Debian 6.12.94+deb13-amd64 hosts with native companions, plus Plex audit-only (kernel 5.15.0-186). Unsupported kernel companions were not loaded. The 13-host cohort passed 78 fresh native accesses and central User/Process/PID, actor hash and actual binary/manifest downloads. Erpnext and ops each passed six fresh reads and controlled queued denied-open local/central checks. Closed raw banks were retained. Old v1 migration reported 15 added dropped chunks across the 16 Debian hosts; no lossless migration claim is made.

Ops initially failed native capacity admission because the newly generated quota JSON had noncanonical whitespace. The protected policy was corrected to canonical bytes, the rejected form retained, and normal service startup and subsequent actor/evidence tests passed. Its quota is 2 GiB; 15 older banks remained unchanged. Plex still requires fresh audit-only access/central qualification.

The wider denied-open run stopped at scanopy-dmz01: an actual actor with PID 1644202, UID/fsuid 997 and GID 987 returned EACCES (-13), but the collector published only the surrounding chmod events. The exact complete kernel record audit(1791556686.887:1421547) was found in auditd's protected log and saved under /root/sequester-dmz-denied-kernel-b00c991baf794e66827f88aa7aa7c8c6/actor-audit.json. Historical receipts remain unchanged: LINUX0940-WIDER-QUEUED-DENIED-20261009-R1/R2 and LINUX0940-DMZ-DENIED-EVIDENCE / DENIED-KERNEL-EVIDENCE. This is a genuine missing production event; the full 13-host denied-access acceptance remains incomplete.

Candidate managed 0.9.41 retains monitored SYSCALL actor evidence even without usable PATH records, emits an explicit target-unavailable observation, and blocks raw replay retirement until exact protected-log recovery succeeds. Recovery compares the kernel boot/timestamp/serial, PID/executable, parent, operation, outcome, UID/GID variants, login/session and syscall identity. It uses descriptor ownership checks, no symlinks, three bounded 8 MiB log tails and a global attempt limit. Missing or mismatching evidence remains visible and retained; no target path or actor bytes are invented. Candidate relay 0.9.7 drains available input for a bounded interval on normal shutdown; delivery may resume from protected raw on restart.

Initial isolated candidate checks passed: 28 actual libauparse/protected-reader cases, 11 durable inbox cases, and 21 actual collector/native-relay recovery/restart/failure cases. Those receipts are synthetic isolated qualification, not live deployment acceptance. Final bounded-retry build, relay qualification, packaged startup, deployment and fresh failed-host/central retests are pending. Earlier failed harness receipts (post-TERM immediate delivery assumption, missing long-argv fixture prerequisite) are preserved.


### 2026-10-09 final candidate qualification

Managed 0.9.41 final build R3 is frozen with bounded protected-log recovery (one attempt per five seconds globally). Exact final collector recovery/restart/failure test passed 21 checks, prior replay/loss/rejection regression passed 28, native relay 0.9.7 passed 897 including post-TERM raw retention and replay, and packaged launcher/collector checks passed 39. Native inherited MDWE and auditd signal disposition checks remain enabled. Native binary SHA-256 6c0ae9bff64fbfb99881b7016c94e78493d50cd1a9038be0bac27bf45f7e1266.

Release ransomfree-client-0.9.41-dev.20261009T153100Z-ce74cb0b0834-linux-x64; archive SHA-256 0f305feca32bd6eac249c3c917a72541b42c03fdad350c65399a525cdcebee39; manifest SHA-256 b94c761d3268ffc754555edfea4248051996c45d5f22c6e1a20ed5b34fa1edd2. Exact remote archive reconstruction passed. Initial DMZ staging rejected the old hardcoded 265-file requirement (new package has 268); the attempted activation consequently failed before a destination or service change. Both failure receipts remain. Corrected 268-file staging R2 passed. Live activation/attribution remains pending at this entry.


### 2026-10-09 live 0.9.41 affected-host acceptance

Scanopy-dmz01 activation R2 passed: six closed native raw banks unchanged, qualified companion active, exact relay 0.9.7 executable and collector healthy. Fresh DAC-denied read-open queued while the collector was stopped survived exact-pidfd relay termination (0.212 seconds) and collector restart; target permissions/metadata were restored. Central server validation passed original plus forensic completion, UID/fsuid 997, exact PID 1647431, process start identity/parent/session, command line, EACCES, executable hash and actual preserved binary/manifest downloads. Six fresh native read accesses also passed central actor/binary verification. Receipts LINUX0941-DMZ-ACTIVATION-20261009-R2, QUEUED-DENIED-20261009-R2, DENIED-CENTRAL-20261009-R2, FRESH-READS-20261009-R1 and READS-CENTRAL-20261009-R1.

DroppedInputRecords stayed 22; ReplayLossReported stayed zero. This particular fresh live denied record arrived complete (RecoveredAuditRecords stayed zero); it proves successful restarted transport/attribution, while exact partial-record log recovery is established by the isolated actual parser/collector tests, not forced on this production endpoint. The queued raw bytes are additionally retained under the root-private queued-raw-proof subdirectory of /var/tmp/sequester-denied-open-973f1b0121da46a5ab386183717413ad.

Quiet 60-second two-core VM sample: combined CPU 4.315% of the machine; combined RSS 374.31 MiB (ordinary145.61, native125.59, collector87.66, relay15.45). Physical disk read-byte delta zero across all four. This is a quiet sample, not sustained-load qualification. Wider 14-sensor staging/activation and fresh central denial acceptance remain in progress. Plex native remains unsupported/disabled; Windows qualification and final product QA remain separate pending gates.


## 2026-10-09 completed 0.9.41 rollout acceptance for 17 existing Linux sensors

Sixteen qualified Debian companions now run managed 0.9.41/relay0.9.7: scanopy-dmz01 pilot; 14-host cohort (nginx01, scanopy-trusted01, backup01, openradius02, rustdesk01, webmail01, socdev01, openradius01, scanopy-wireless01, scanopy-iot01, ddi01, ddi02, support01, erpnext01); and ops01. Cohort activation verified 104 closed raw banks unchanged and zero added audit drops. Fresh native reads passed 84 cohort cases plus six pilot and six ops cases, with actual protected server artifact/manifest downloads. Fresh queued DAC-denied read-open passed on every one of these 16 sensors after exact-owned relay termination and collector restart; central original/completion attribution and binary verification passed. Maximum cohort sender exit 0.661 seconds. This does not establish lossless daemon migration intervals or all operation coverage.

Plex audit-only 0.9.41/relay0.9.7 is connected and healthy; its native companion remains disabled on unqualified kernel5.15.0-186. An activation verifier read the status file before startup created it; the failed receipt is retained, and separate read-only actual runtime qualification R2 passed. Its initial relay test used the newer systemctl --kill-whom argument, unsupported on Plex's older systemd; a help-verified compatible argument was used in R2, which passed local and central queued denial (UID998, exact process/birth/hash and actual artifact). Six additional one-byte reads across three active canaries, alternating living root and rfclient actors, passed authoritative audit metadata and central actor hash/binding/preservation plus all six actual binary/manifest downloads. These living-process audit/procfs checks do not qualify early native capture for short-lived processes on Plex.

Test harness corrections are retained as failures, not erased: the first read cohort runner retained the old hostname guard and stopped before support/ERP accesses; two resumed actual tests completed the 84-case aggregate. The first central denial verifier assumed device8:2 for all files; NGINX exposed the false assumption. The corrected verifier independently derives both target and actor device major/minor from recorded stat truth, checks inode and exact process instance/hash, and all 14 cohort central denials passed. Plex's first read verifier incorrectly sought forensic completions in the recent-alert snapshot; root inbox and server showed the original successful audit read. The corrected six-case runner checks original locally, then completions/artifacts through the protected server API.

Receipts: LINUX0941-COHORT-ACTIVATION-20261009-R1; FRESH-READS-20261009-R2; READS-CENTRAL-20261009-R1; QUEUED-DENIED-20261009-R2; DENIED-CENTRAL-20261009-R2. Ops activation/read/denied local and central R1 receipts. Plex STARTUP-QUALIFICATION-R2, QUEUED-DENIED-R2, DENIED-CENTRAL-R2, AUDIT-READS-R3 and READS-CENTRAL-R1 (20261009 JSON). Combined central accepted cases: 102 reads and 17 denied opens, with 119 preserved actor binary/manifest pairs downloaded and hash verified.

Quiet ops60-second sample: combined 7.4% of one core / 0.925% of its eight-core VM; RSS400.09MiB. Pilot two-core VM quiet sample RSS374.31MiB / 4.315% machine CPU. These are quiet samples, not sustained high-volume qualification. Remaining nine Linux sensors on other kernels, supported-kernel qualification, Windows operation/minifilter work, all-type canary callbacks, sustained-load/VM rehearsal and final full-product QA remain pending. Wazuh remains deferred to the requested end-of-work discussion.

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
