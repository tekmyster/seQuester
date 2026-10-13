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

# Deferred Windows callback token integration

## Deployment checkpoint (2026-10-11, 05:30 UTC)

- Server 0.6.45 is deployed. Fresh authentication, task/writer ownership, 33
  sensor records, indexed event readback, schema 8 capabilities and the unchanged
  canary callback receiver were verified. The existing full-history timeout is
  separate; indexed readback is not claimed as a full-history performance fix.
- All four production Windows sensors run 0.6.26. Initial fresh health samples
  passed with the old driver retained and the deferred path disabled.
- Full driver SHA-256
  `82B79CC6BD79D53AA07C1E3D14FB6B8EAE8354D748427F5B39E4C963EFFD5373`
  passed 132 actual APC read cases across Windows 10, Windows 11, Server 2019 and
  Server 2012 R2. All private drivers unloaded normally; separate fresh admin
  checks and exact VM resource restoration passed. These cases test the token
  worker with the existing executable-staging pipeline compiled in.
- Published sensor DLLs decoded raw full-driver records, retained separate
  identities through JSON and queue restart, rejected schema 6 acknowledgements
  and accepted schema 8. The 0.6.45 isolated API and signed-in browser passed;
  24 browser assertions cover native identity fields, independent contexts,
  collection timing and desktop/tablet/mobile widths.
- Windows 10 production now uses the full driver with deferred capture enabled.
  Its 15-case native operation run passed, including writes, append, rename,
  delete, truncate and six denied OPEN cases. Settings were restored. Central
  token comparisons and preserved executable/manifest downloads are in progress.
  Other three production driver deployments remain gated on that acceptance.
- The first production observer used the report-directory filter instead of
  the reused monitored scope. Its native worker completed normally. The observer
  was interrupted, its exact controlled settings were restored after semantic
  comparison, and the corrected rerun passed. No native actor was force-killed.
- No administrative ACL, credential or management firewall changes accompanied
  these deployments. Existing protected directories and owned test ACLs were reused.

The 24 insufficient-handle-rights failures rejected before filesystem dispatch
remain unresolved. Denied OPEN qualification does not establish capture of
later rejected operations on a successfully opened handle. Queue saturation,
immutable historical token state and unsupported callback contexts remain
unqualified. The implementation preserves explicit unavailable states.

## Qualification update (2026-10-11)

The integrated worker passed 132 actual APC-entry read callbacks across Windows
10, Windows 11, Server 2019 and Server 2012 R2: 128 impersonation cases and four
explicit non-impersonating controls. Native assertions matched PID, thread ID,
process birth, process-owner SID, effective SID, token ID, authentication ID,
modified ID and impersonation level. Every private VM completed normal driver
unload, separate fresh administrative checks and resource restoration.

Server 2019 and Server 2012 R2 exported 33 raw records each. Managed replay
validated decoding, JSON serialization, queue restart, rejection of an older
server acknowledgement and server persistence. The frozen 0.6.44 server package
also accepted 33 native records over HTTP and returned matching evidence through
the admin API in an isolated loopback test. These are replay tests, not live
production sensor ingestion.

The full driver containing both the existing executable-staging pipeline and
new token worker compiled without fault controls. Its Windows 11 native test
returned exit 0 for all 33 actual APC reads; final fresh access and VM restoration
checks are still running. Other full-pipeline OS qualifications remain pending.
The 0.6.26 Windows sensor package builds from the deployed 0.6.25 source baseline
with only Windows changes; unrelated newer Linux changes are excluded.

Production deployment and fresh host operation tests remain separate gates.
The 24 insufficient-handle-rights failed operations remain unobserved by the
production minifilter. Full token immutability, natural paging paths, queue
saturation and unsupported callback contexts are not claimed as qualified.

## Implementation plan (2026-10-11)

The private callback experiment has passed on Windows 10, Windows 11,
Server 2019 and Server 2012 R2: 96 reads each, including 32 actual APC-entry
callbacks each. All four private VMs completed resource restoration and fresh administrative access checks.
These results
qualify an entry-time token reference followed by later metadata queries, not
an immutable historical snapshot of a mutable token.

1. `src/RansomFree.WindowsKernel/Driver.c`: reference the accessing thread's
   impersonation token at callback entry, including APC-level entry; retain
   process objects for separately labeled later image/primary-token queries.
   Use a bounded PASSIVE worker before publishing enriched records. Reuse the
   existing allocation limit of 2048. Drain callbacks and pending work before
   releasing the worker during unload and failed startup.
2. `src/RansomFree.WindowsKernel/Protocol.h`: add a queue-head extension with
   reference/query timestamps, collection status and explicit metadata timing.
   Preserve version 4 operation bytes and the existing command 40 extension.
   Commands 41 through 44 are already allocated; use a distinct command.
3. `src/RansomFree.Client/WindowsKernelSource.cs` and
   `src/RansomFree.Contracts/WindowsKernelEvidence.cs`: validate event linkage
   and timing provenance before accepting deferred evidence. Preserve the
   callback IRQL. Keep process owner, accessing thread owner, effective thread
   identity and CREATE authorization separate. Carry the additive fields
   through persistence, forensic enrichment and SIEM serialization.
4. Add native tests for revert after entry, process exit, token mutation,
   absent callback thread, queue saturation, disconnect/ACK and normal unload.
   Add decoder/contract tests rejecting mismatched event IDs, inconsistent
   statuses and fabricated operation-time primary-token claims.
5. Rebuild reproducibly, qualify the integrated artifact on all four Windows
   versions, then deploy and verify actual honeypot operations against server
   records. Preserve rollback packages and administrative sessions through
   separate fresh-session checks.

## Boundaries

Only the impersonation-token reference is captured at APC entry. Primary-token
reference and metadata queries require PASSIVE_LEVEL. Pinning a process does
not freeze its primary token. Deferred primary/image metadata must explicitly
say it was collected later. Checking token ModifiedId around field queries
detects a change during those queries; it does not prove no earlier mutation.

Failed operations rejected before filesystem dispatch remain a separate
capture-source problem. The deployed minifilter misses 24 insufficient-rights
failures across the four current Windows hosts. A successful APC token test
does not close that gap. Microsoft DTrace observed the controlled failures on
Windows 10; protected integration and the older Server source remain open.

Actor executable hashing and preservation continue through the existing
forensic pipeline. This work does not enable default target-file hashing or
preservation, and does not change Linux behavior.

## Private implementation status

`DeferredTokenDiagnostic.h` now provides a dedicated PASSIVE worker, bounded by
the existing 2048-record allocation limit. It retains the actual accessing
thread's impersonation token at reference time, separately pins process objects,
queries token metadata later, checks token modification during field queries,
and releases held objects before publishing the additive evidence.

The command 45 reply has its own version 1 schema (2048 bytes) and event linkage.
The base operation and command 40 reply retain their existing formats and partial
APC-context labels. No later primary metadata is substituted for an entry-time
effective principal when the thread was observed without impersonation.

Worker shutdown drains pending references after Filter Manager has removed its
callback roots. The wake event stays signaled while draining the last pending
record during shutdown, preventing the worker from sleeping before termination.
Failed startup also drains/free records before unloading the driver.

The private build and native test compile under W4/WX. Legacy compilation and
compilation with the existing executable-staging/acquisition pipeline also pass.
The frozen-source builder is `tools/WindowsApiObserverPrototype/Build-DeferredTokenSensor.ps1`.
Private integrated native qualification, client/server schema integration,
queue-saturation and lifecycle qualification, deployment and three product QA
passes remain pending. Compilation is not a runtime pass.

The October 11 Manus research task was accepted, then failed with quota_limit
(insufficient credits); it supplied no new technical answer.
