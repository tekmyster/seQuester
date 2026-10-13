## Revision r12 Windows 10 native result

96 actual reads passed: 32 ordinary PASSIVE callbacks, 32 clearly labeled forced
APC reference controls, and 32 actual APC-entry callbacks produced by a separate
upper Filter Manager paging sender. The lower observer retained the independently
identified LOCAL SERVICE token after RevertToSelf and queried it at PASSIVE.
PID, TID, process birth, SID, TokenId, ModifiedId, AuthenticationId and impersonation
level matched independent actor queries. Explicit no-impersonation control passed.
Both probes were normally unloaded and removed; a separate fresh administrative
session confirmed original filter state. Original outer VM CPU restoration is pending.

Sender uses FltAllocateCallbackData/FltPerformSynchronousIo (documented <= APC),
with a 4 KiB aligned nonpaged buffer and an MDL owned by the callback data.
FltFreeCallbackData releases the associated MDL; no second manual free is made.
This qualifies actual generated paging callbacks, not natural mmap coverage,
production integration, immutable historical privilege/group snapshots or future
Windows versions. Win11/Server 2019/Server 2012 R2 qualification of this revision
remains pending. Receipt: WINDOWS-CALLBACK-TOKEN-NATIVE-WIN10-20261010-R12.json.

# Current native qualification status

Revision r6 failed Win11 qualification with REFERENCE_BY_POINTER (0x18).
Preserved minidump analysis shows I/O completion reached from the handcrafted
kernel read path. Its output is crash-truncated and is not a passing receipt.
Revision r7 removes that path and IOCTL and tests cold mapped paging reads
created by Windows. Build success is not native qualification. Existing r3
results retain their original scope. No production deployment occurred.

# Actual file callback token reference qualification

This is a separate isolated qualification driver. It does not change the
deployed SeQuesterActor collector, agent, server schema, or whitelist behavior.

`CallbackTokenLab.c` registers a READ minifilter and a secured, exclusive
administrative device. The device owner can arm only its own calling thread.
There is no arbitrary PID, thread address, kernel pointer, or target path input.
An owned fixture opens its target under SYSTEM, then reads the handle while
impersonating LOCAL SERVICE. The pre callback references the token on the
actual `FLT_CALLBACK_DATA.Thread`; the post callback records the real result.
The fixture reverts before querying the reference at PASSIVE_LEVEL. It compares
SID, complete token LUIDs, PID, TID and process creation time to independent
native truth. A no-impersonation control requires explicit absence.

The modes are distinct:

- Native callback mode records the actual entry and reference IRQL.
- Forced APC control raises a PASSIVE callback only for the token reference,
  restores its original IRQL immediately, and labels the forced condition.
- The new kernel-generated APC read mode resolves the owned caller's readable
  handle with UserMode access checking at PASSIVE, builds a synchronous bounded
  read IRP, sends it at APC, restores IRQL and waits for completion at PASSIVE.
  It must actually observe callback IRQL 1 without the forced-reference flag.
  This is a deliberately generated kernel request, not an ordinary user-mode
  read or proof that all real-world callback contexts have been tested.

A forced control cannot qualify naturally elevated callbacks, paging paths,
missing callback threads, or operations rejected before filesystem dispatch.
Holding a token reference preserves its lifetime, not its historical contents.
No token query or release occurs at APC. The separate WDK/Microsoft Learn
contract discrepancy remains a production qualification issue.

The singleton is bounded to one owned thread/reference. It is deliberately
not an endpoint queue or production transport. Device cleanup during an active
callback retains the bounded reference until normal filter unload; this is a
lab lifetime design and must not be copied into a production queue.

Build with `Build-CallbackTokenLab.ps1 -OutputDirectory <new C: directory>`.
The build freezes source, compiles with /W4 /WX, records hashes, and uses the
existing trusted lab identity. Qualification uses
`diagnostics/windows-token-20260930/Invoke-SupportedWindowsCallbackTokenLab-20261010-R1.ps1`.
Its temporary filter load-order number is `409801.924` in isolated labs only;
this is not a Microsoft allocation. The controller preserves the original
administrative session through a fresh authenticated device-access check and
normal cleanup, shutdown and exact CPU restoration. Production deployment
and Driver Verifier qualification are not established by compilation.

The frozen r3 driver passed 64 actual Windows 10 read cases: 32 native PASSIVE
callbacks and 32 forced APC-reference controls, plus the explicit
no-impersonation control. SID, PID, TID, process birth, token ID and modification
ID matched independent native truth. Fresh device access, normal unload and
fresh restored administrative access passed. Its receipt is
WINDOWS-CALLBACK-TOKEN-NATIVE-WIN10-20261010-R1.json. The new r4 kernel-generated
APC-read mode is built but not yet qualified. No production integration is
claimed for either package.
