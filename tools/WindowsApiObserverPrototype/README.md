# Windows API observer qualification prototype

This is an **owned-process experiment**, not an installed sensor source. It does
not change the server, production agents, driver, signing configuration, ACLs,
credentials or monitoring settings. Do not inject it into arbitrary applications.

It intercepts `NtReadFile`, `NtWriteFile` and `NtSetInformationFile` with Microsoft
Detours before the return to their caller. Records contain resolved target path,
native status, process PID plus birth, thread ID, monotonic ordering, and separate
primary and effective token observations. Only an explicitly configured single
target path is recorded. Unknown evidence is not upgraded to trusted evidence.

The process token is queried through the documented Windows 8/Server 2012+
`GetCurrentProcessToken` pseudo-handle, which avoids an impersonated caller's
inability to open its SYSTEM process token. Token statistics are checked before
and after collection and across the call. Equal observations are **not** an
atomic guarantee about every security check inside the operation.

## Reproduce

Clone Microsoft Detours v4.0.1, commit
`e4bfd6b03e50de46b47abfbd1e46b384f0c5f833`, into isolated build storage and build
its `src` with the x64 Visual C++ environment. The prototype build requires MSVC
14.37.32822 and Windows SDK 10.0.22621.0. Then:

```powershell
./Build.ps1 -DetoursSource C:/isolated/Detours -OutputDirectory C:/isolated/new-build
./Test-OwnedProcess.ps1 -BuildDirectory C:/isolated/new-build -ActorDirectory C:/existing/qualified-actor -QaParent C:/existing/qualified-qa-parent -ExpectedHost HOST
```

The QA parent and its `reports` child must already have the previously qualified
permissions. The test deliberately does not edit ACLs. It uses a temporary owned
SYSTEM scheduled task; each actor opens a QA file as SYSTEM, impersonates LOCAL
SERVICE, and attempts a failed operation. The separate native launcher records
the actual child PID and process birth from its process handle. Inputs are hashed,
targets remain unchanged, and unresolved owned processes are not forcibly killed.

The final two controls run a normal native denied read and a direct-system-call
denied read. The latter intentionally bypasses the instrumented ntdll entry. Its
tiny compiled test stub requires the initial expected x64 entry layout and does
not patch kernel code, allocate executable memory or disable protections. It is
a negative test, not an additional collector.

## Verified and unresolved

The immutable r6 package passed all 32 normal failed-operation cases on the four
current Windows hosts. Each matched independent actor PID/birth, TID, native
status, SYSTEM primary token and LOCAL SERVICE effective token. All four normal
read controls were seen. All four direct-call controls failed with Access Denied
and were **not seen**. This proves the source is bypassable.

Records are `in-process-supplemental`. An application can interfere with its own
instrumentation or evidence. Never use these records to suppress an alert via a
whitelist or present them as kernel-authoritative capture. They currently remain
private QA JSONL, not central server events or preserved executable evidence.

Before any production integration: qualify bounded asynchronous transport and
visible drop/error reporting, authenticated process-instance linkage, schema
validation and SIEM source separation, verified actor capture, asynchronous final
completion, token-mutation races, safe unload/lifetime, WOW64 and protected process
exclusions, and measured high-volume overhead. The prototype uses synchronous
file logging and does not pass a production performance gate.

`ApcTokenReferenceProbe.c` is a separate compile-only investigation: the installed
WDK annotates impersonation-token reference through APC_LEVEL, while Microsoft
Learn says PASSIVE_LEVEL. No token query is performed at APC. A retained token can
still mutate; a later query is not a historical full-token snapshot. The probe
has not been loaded or used to change the deployed minifilter.

Receipts: `diagnostics/windows-token-20260930/WINDOWS-API-OBSERVER-ACCEPTANCE-20261010-R1.json`
and `WINDOWS-APC-TOKEN-REFERENCE-COMPILE-20261010-R1.json` in the workspace.

Dependency: [Microsoft Detours](https://github.com/microsoft/Detours), MIT license;
the build copies its license notice alongside artifacts. The initial r6 acceptance
predates the allocation-order and dependency-manifest refinements now in source;
do not describe newer builds as qualified by that historical receipt.
