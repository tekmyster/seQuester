# Windows existing-handle failure retest — October 10, 2026

Fresh tests ran on Windows 10, the domain controller, the recorder and the storage
server using their deployed 0.6.25 agents and admitted minifilter. No production
driver or agent update was made. All original sensor settings were restored;
these tests did not change ACLs or credentials.
Final independent health checks confirmed all four agents and minifilters running
with zero pending executable uploads. The storage sensor's transient upload queue
drained to zero by 23:22 UTC; its earlier nonzero readings remain in the receipts.

| Operation after successful open | Native result on each host | Server failed-operation capture |
| --- | --- | --- |
| Read through write-only handle | Access Denied (5) | Missing on all four |
| Write through read-only handle | Access Denied (5) | Missing on all four |
| Append through read-only handle | Access Denied (5) | Missing on all four |
| Truncate through read-only handle | Access Denied (5) | Missing on all four |
| Rename without required handle rights | Access Denied (5) | Missing on all four |
| Delete without required handle rights | Access Denied (5) | Missing on all four |
| Read a locked byte range | Lock violation (33) | Captured on all four |
| Write a locked byte range | Lock violation (33) | Captured on all four |

There were 32 actual failed calls, 32 independently correlated successful opening
cases, and eight captured failed-operation cases. Full failed-operation coverage
**failed**. Opening evidence was never substituted for a missing operation.

For each captured lock failure, the protected server API matched actor ground
truth: process PID and birth time, actual callback thread, process-primary token,
thread-owner token, effective impersonation token, SID/account, impersonation
state, and native operation status. The actor opened as SYSTEM and then performed
the failed operation while impersonating LOCAL SERVICE. The token comparison
included token/authentication/modified IDs, type, impersonation level, session,
integrity, elevation and successful token query statuses.

## Interpretation and remaining work

The missing insufficient-rights calls are consistent with validation of a handle's
granted rights before filesystem dispatch. Windows documents that
[handle reference validates requested access against granted access](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-obreferenceobjectbyhandle).
This is an inference, not proof of the exact syscall call stack. Earlier October
7 filesystem ETW testing recorded zero lost events, a positive read control and
no failed completions for these six cases. No evidence here establishes CPU
delay as the cause. A minifilter cannot collect an operation that is not sent to
it; any additional collection source must be separately verified for both failed
operation visibility and operation-time security identity.

Missing callback threads and non-PASSIVE token collection remain explicit
unavailable states. Thirty synthetic production-decoder/contract/serialization
checks passed, preserving partial events and rejecting contradictory token
evidence. They are not native qualification of those execution contexts.
[Windows documents the callback execution contexts](https://learn.microsoft.com/en-us/windows-hardware/drivers/ifs/writing-preoperation-callback-routines).

## Repairs and verification scope

The test harness was repaired to use the supported, hash-verified actor package,
hold the byte-range lock, run exactly eight cases, and use the wrapper's correct
result naming. Failed harness runs remain retained with restoration evidence.
The new repository fixture prevents false attribution or false completeness for
unavailable callback context. No production collection defect with a supported
repair was established by this retest.

Functional pass: actual four-host failed calls and protected server correlation.
Regression pass: 30 synthetic unavailable-context checks. Runtime pass: restored
settings and fresh driver/agent health checks. No UI change was made; signed-in UI
acceptance was not performed. Successful-operation coverage, other failure
causes, Linux tests and the entire forensic specification are not qualified by
this bounded retest.

Aggregate receipt:
[WINDOWS-EXISTING-HANDLE-RETEST-20261010-R1.json](../../../diagnostics/windows-token-20260930/WINDOWS-EXISTING-HANDLE-RETEST-20261010-R1.json).
Individual execution, API measurement and final health receipts are retained in
the same diagnostic directory.
