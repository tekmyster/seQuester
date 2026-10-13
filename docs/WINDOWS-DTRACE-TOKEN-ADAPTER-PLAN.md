# Windows 10 tracing adapter qualification

The current production desktop is AMD with Hyper-V active and no exposed SVM.
The Intel research observer is not a compatible source there. An earlier private
Windows 10 experiment with Microsoft's DTrace package captured all nine native
existing-handle cases, including direct calls. That established syscall events,
not event-time accessing-thread tokens or production integration.

The public standalone DTrace source implements TraceRegisterEngine and
TraceInitSystem as STATUS_NOT_SUPPORTED stubs. Compiling that source cannot be
represented as a working Windows kernel tracing engine. The actual Microsoft
package's dtrace.sys exports real implementations of both functions. Offline PE
inspection of exact SHA-256
37e11e97b48fb2c6c4d53b71262cceced5e86dba56df994c78ab676477a93ea2
found exactly one 80-byte TRACE_ENGINE table at RVA 86240. Its known exported
callback pointers match the public ntdtrace.h layout. This is admission evidence,
not permission to assume compatible registration, safe callback context or tokens.

## Next implementation

Build a separate, reproducible private adapter against the actual exported
TraceRegisterEngine interface and pinned public TRACE_ENGINE declarations. Hold
an open reference to the Microsoft framework; retain its original callbacks and
forward each callback without changing probe arguments. A protected explicit
attach operation must retain the loaded adapter on any registration/rollback
failure. Dynamic unload is prohibited until rundown is qualified. Never modify
the Microsoft binary or replace a standalone stub with a fabricated API.

The first adapter test measures actual syscall ProbeFire callback IRQL,
interrupt enablement, APC state, PID/TID/process birth and entry/return pairing
for one owned test thread. Do not query token metadata solely because IRQL is
zero: interrupts may already be disabled, and the tracing engine may own locks.
Do not enable interrupts or lower IRQL to force an otherwise unsafe query.
Provider GetArgument callbacks, rather than the generic zero-returning
dtrace_getarg stub, supply arguments beyond Arg0-Arg3 when needed and safe.

Only after actual callback context permits documented token APIs should this
adapter reuse the sensor token helper and compare every field with independent
native truth. Unavailable contexts must remain explicit diagnostics. Then add
target/actor identity, preservation, central transport and loss/performance gates.
Use one existing zero-NIC VMware guest at a time with retained administrative
sessions, fresh access checks and normal cleanup. No production replacement is
qualified by the current offline findings.

Sources: [Microsoft DTrace source](https://github.com/microsoft/DTrace-on-Windows)
and [Microsoft DTrace documentation](https://learn.microsoft.com/en-us/windows-hardware/drivers/devtest/dtrace).

## First runtime result and repair

The initial adapter attached but bound zero target syscall probes. The actor and collector exited naturally; no native record was collected. Token queries remain disabled. The next immutable build adds registration, callback-size, lookup/create and fire diagnostics to establish the binding defect before adding token collection. The transferred script launch replaces the failed encoded command; its policy override is process-local.

Token APIs are not admitted simply by a PASSIVE_LEVEL observation. Both [PsReferenceImpersonationToken](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-psreferenceimpersonationtoken) and [SeQueryInformationToken](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-sequeryinformationtoken) require PASSIVE_LEVEL; paged allocation and callback lock/interrupt conditions must also be respected. No forced interrupt enablement or IRQL lowering is added.

## Boot-time callback implementation

The actual Microsoft built-in syscall provider registers directly with dtrace_register and its entry/return callbacks call dtrace_probe directly. Replacing TRACE_ENGINE does not intercept that path. The first adapter test failed with no bound probes and no records; it is not a token-capture pass. The guest subsequently passed fresh restored administrative access, normal shutdown and exact CPU/RAM/nested-virtualization restoration.

A separate BootTrace.c private implementation exports TraceInitSystem. Its protocol is verified against the actual Windows 10 kernel SHA 563F486F45853248E54B3EE800D6B19289101C6CCA15E0E3FA11A70452B5CE91 and matching Microsoft PDB (F57E740B-088E-5056-E8AF-0772F1CC5BEB, age 1). The kernel initializes nine callout slots and supplies a pointer to its 72-byte context by writing through the returned pointer address. Entry/return callouts and the service-registration function are verified by actual caller disassembly. No kernel instructions or protected runtime callback table are patched.

The private source initializes its callouts at boot, then explicitly registers ReadFile, WriteFile and SetInformationFile (without the Nt/Zw prefix) through the verified context function on a protected attach request. It rejects another kernel/context layout. It has no live unload. The first build measures only owned-thread entry/return context using a bounded single-producer/single-consumer queue without changing IRQL or interrupt state. Its memory-access helper reports unsupported. Token queries, global target monitoring, central publication and production compatibility remain unqualified.

Files: tools/WindowsSyscallObserver/BootTrace.c, Build-BootTrace.ps1, KernelSymbolAdmission.cpp and Build-KernelSymbolAdmission.ps1; shared Capture/Device/Wire and existing sensor token helper remain reused. The native fixture and control interface use the existing private context schema. After callback-context acceptance, add guarded full token capture, native raw comparison, target/actor binding, preservation/central transport and lifecycle/resource qualification. Runtime tests use the existing zero-NIC VMware guest only, with original administrative sessions retained through installation/restoration and fresh access gates. The controller creates its own previously absent boot file using CreateNew, verifies its hash, and removes only that verified file after disabling tracing and rebooting normally.

Receipts: WINDOWS-DTRACE-NATIVE-CALLBACK-DISASSEMBLY-20261011-R1.json; WINDOWS-KERNEL-DYNAMIC-TRACE-ABI-20261011-R1.json; WINDOWS-KERNEL-DYNAMIC-TRACE-CALLOUT-ABI-20261011-R1.json. Compiled boot-trace-context-r1 and boot-trace-context-package-r1 remain private and have no runtime acceptance yet.

## Boot activation repair, 2026-10-11

The r1 boot trial started the protected driver device but never invoked TraceInitSystem. Attach returned DEVICE_NOT_READY before any registration. No native actor was launched. The private guest subsequently passed a separate fresh privileged login, verified driver removal and original filter/boot baseline restoration, and normal shutdown with exact resource restoration. Receipt: WINDOWS-BOOT-TRACE-R1-RESTORATION-20261011-R1.json.

Mandiant's MIT-licensed [STrace implementation](https://github.com/mandiant/STrace), pinned at 39d2cc4a53ed6c45675bda950b1c6fabc825f6c6, identifies the additional API-set extension required to resolve the kernel boot import. Its forwarding DLL has a valid Microsoft Windows signature and SHA-256 2F45B0D73CA5613C52EDC42400A6B5D3471D64A955E6505944D4643D76ACCF72. The source also establishes that KeSetSystemServiceCallback names omit the Nt/Zw prefix and that the context offset at byte 16 is a 64-bit TEB offset. Both source defects are corrected in boot-trace-context-r2.

The r2 retained controller creates only a previously absent forwarding file and its own SqBootTraceQualification API-set registry child, records hashes, and withdraws both during restoration. It requests the documented one-time advanced boot menu, with console selection and observation recorded separately. No original STrace installer, manually mapped plugins or kernel patches are used.

Mandiant explicitly documents Windows-root signature requirements for this early boot extension: ordinary test signing alone does not qualify it; driver signature enforcement must be disabled separately for each private test boot. Therefore a private boot proof cannot establish unattended production compatibility. Actual accessing-thread tokens still require safe callback-context validation and the documented token APIs. Neither the r2 compilation nor the Microsoft-signed forwarding DLL establishes that result.

## Actual Windows 10 callback-context qualification

The system-start configuration was incorrect for the early boot extension. The next retained controller uses boot-start loading, matching the reference service configuration. The initializer also preserves slot zero's kernel-supplied extent, and distinguishes an initializer rejection from a missing initializer. The initializer contract harness passes its pointer handoff, extent, callback and invalid-input checks; that harness alone is not kernel qualification.

With boot-trace-context-package-r4 on the existing Windows 10 19045.6456 zero-NIC guest, the protected attach request returned success and registered all six entry/return callbacks. The native actor then passed all nine cases: insufficient handle rights for read, write, append, truncate, rename and delete; byte-lock failures for read and write; and a successful read control. The independent raw decoder matched PID 824, TID 472, process creation identity, operation, stage, ordering and native status. Targets remained unchanged, and no record was lost. The raw SHA-256 is 46779d29881b0042a5a76aedd956cdfb320fdd30f071078119016f8f771418b7.

Every tested entry and return ran at PASSIVE_LEVEL with interrupts enabled and all APCs available. No interrupt or IRQL manipulation was used. Receipt: WINDOWS-BOOT-TRACE-CONTEXT-RAW-ACCEPTANCE-20261011-R1.json. This is callback-context qualification only: the user-mode token truth in these pairs is not a captured kernel token.

The separate FullTokens build now reuses SqSyscallEnter/SqSyscallReturn and the sensor's existing CaptureToken helper only under the measured safe-context guards. It retains actual file objects, rejects recycled handles, and preserves owner and effective impersonation snapshots separately. Its native fixture must independently match all token fields before this becomes a token-capture acceptance result. General target monitoring, actor acquisition, central transport, production resource qualification and deployment remain pending.

The optional read-only PowerShell loader diagnostic produced no verified result; its Code Integrity collection is unavailable, not a pass. Protected attach and the raw native callback records are the runtime evidence. The selected one-time startup screen, exact package and original-session restoration are recorded independently.

The context test is fully restored with a fresh privileged session, original absent tracing/extension state, normal shutdown, 4096 MiB RAM, CPU limit -1 and unchanged nested virtualization. Receipt: WINDOWS-BOOT-TRACE-CONTEXT-RESTORATION-20261011-R1.json.

Before installing the full-token build, review identified a concrete reentrancy issue: token enrichment could cause a nested monitored syscall whose return shared the outer operation's opcode. The guarded build records callback depth and enrichment state so a nested return cannot complete the outer token record. Seven contract cases pass using the actual frozen callback bodies and controlled OS/token stubs, including same-opcode nesting, different-opcode nesting, metadata nesting, rejected target, bad ABI, unsupported IRQL and an unarmed thread. This is a contract check, not a kernel token pass. Artifact: boot-nested-contract-r1; immutable driver: boot-trace-token-r4; package: boot-trace-token-package-r3. The preceding token package was never installed and its private VM session was restored normally.

## Actual Windows 10 full-token qualification

The guarded full-token source (boot-trace-token-r4, package-r3, driver SHA-256 724B389B24ED913D038AC51F225B80834746A48DBAE383B8D002D8F90301D4C6) passed all nine actual native cases on the isolated 19045.6456 guest. Process PID 1796 / thread 3896 / process creation FILETIME 134361899441461825 matched the independent native truth. The source separately captured SYSTEM process-owner and LOCAL SERVICE effective impersonation tokens for the eight failed-operation cases; the successful control was non-impersonating SYSTEM. All five collection groups reported success, including the stable token modification-marker check. Independent raw verification passed; raw SHA-256 e3e509fc2cb7699e9ad51d959605d215f4e7d706943149767de5c04729c51f74. The managed decoder passed 103 checks on those actual records. Receipt: WINDOWS-BOOT-TRACE-TOKEN-RAW-ACCEPTANCE-20261011-R1.json.

This establishes controlled event-time token capture for the tested native operations on this exact kernel, not universal operation authorization semantics, complete token contents, final asynchronous I/O completion, global monitored-target filtering, actor acquisition, central transport or production deployment. The prototype still admits only its own armed thread and retained test file objects. Restoration is in progress with original administrative access retained.

The full-token private trial is now restored completely, including separate fresh privileged access, original boot/filter baseline, exact owned-file removal, normal shutdown and original resources. Receipt: WINDOWS-BOOT-TRACE-TOKEN-RESTORATION-20261011-R1.json. Production was unchanged.
