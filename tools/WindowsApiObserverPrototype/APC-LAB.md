# Accessing-thread token reference qualification

This is an isolated qualification tool, not a production collector. It tests
the installed WDK's APC-level annotation for PsReferenceImpersonationToken.
Microsoft Learn currently specifies PASSIVE_LEVEL for that function. A runtime
pass cannot, by itself, settle that API contract discrepancy.

## Inputs and scope

- `ApcLabDriver.c`: separate secured, exclusive lab device. Accepts no arbitrary
  PID, TID, kernel pointer, executable path or memory address. It references only
  the actual calling thread at APC_LEVEL. Token queries and release occur at
  PASSIVE_LEVEL. A mutex serializes commands without raising the query IRQL.
- `ApcLabTest.cpp`: owned SYSTEM fixture impersonates LOCAL SERVICE, pins the
  token, reverts, and checks the retained token's identity against independent
  user-mode TokenStatistics. It repeats 64 times, then checks token mutation,
  no impersonation, short buffers, cleanup and query without a pin.
- `Build-ApcLab.ps1`: freezes and hashes source, builds with /W4 /WX and the
  existing compiler/WDK, then reuses the already trusted lab signing identity.
  It creates no certificate and changes no boot policy.
- `ApcLabProtocol.h`: explicitly labels reference versus later query state.

The mutation control deliberately disables a privilege on the duplicated test
token after pinning. The later query must see the new ModifiedId. A successful
reference preserves token lifetime; it does not freeze mutable security state.
These observations cannot be reported as a historical full authorization token.

## Reproduction

Run Build-ApcLab.ps1 with a new OutputDirectory on C: (D: currently lacks space).
Then use the corrected direct Windows 11 R5 controller, or
Invoke-SupportedWindowsApcTokenLab-20261010-R2.ps1 for WIN10, 2019, or DC.
Earlier controllers are preserved for investigation and are not the current
reproduction entry points.

The controller admits only the exact existing zero-NIC VMware Windows 11 lab,
checks the OS build, existing test mode, stopped baseline minifilter and input
hashes, and uses a temporary CPU limit and low shares. It retains the original
administrative connection through a separate fresh authenticated administrative
device-access check. It runs an owned SYSTEM scheduled task, collects results,
normally unloads/removes its own service, verifies the baseline, normally shuts
down the guest, and restores CPU allocation. It never force powers off a guest.

The initial controller had recovery and transport defects, preserved in its
failed receipts. The direct R5 runner keeps its command host and original
connection alive during recovery and catches failed recovery commands. Its
normal path completed on Windows 11; a follow-up normally shut down the VM and
restored unlimited/low CPU allocation. The supported-Windows controller uses
the corrected certificate, Windows file attributes, Stop-VMGuest and exact
vSphere CPU restoration from the outset. Windows 10 completed that full path.

Native qualification: Windows 11 26300.9457 and Windows 10 19045.6456 each passed
64 reference/revert/query comparisons and the mutation, absence, short-buffer
and cleanup controls with the same frozen r4 driver/fixture. Server 2019
17763.9020 and Server 2012 R2 build 9600 also passed 64 each: 256 native
reference cases in total, with fresh access and baseline restoration receipts.
This is not a native filesystem-callback or whole-product QA pass.

## Acceptance boundaries

This tool does not generate a filesystem callback, capture a missing callback
thread, observe a pre-dispatch denied syscall, verify Driver Verifier coverage
for this separate driver, qualify other Windows kernels, or establish production
server ingestion. Each of those is a separate gate. Compilation is not a native
runtime pass. The r7 API observer has separate four-host receipts; those are not
APC reference qualification results.
