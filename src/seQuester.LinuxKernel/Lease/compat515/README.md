# Linux 5.15 provider integration

This directory is an implementation candidate. No module in this directory is
approved for production activation. Both current module initializers return
`-EOPNOTSUPP`; compilation and state tests do not establish runtime capture.

## Implemented components

- `sq_actor515_api.c`: actual current-task `mm->exe_file` reference acquisition
  under RCU with `get_file_rcu`, subjective UID/GID values, process/thread birth
  times and finite kretprobe data. No borrowed `active_mm` is used.
- `sq515_provenance.h`: a fixed 256-entry scalar identity table. Only a
  successful-exec tracepoint may commit an association generation. PID reuse,
  an exec-counter mismatch, shared memory, executable-reference replacement,
  missed observations, capacity exhaustion and counter overflow cannot produce
  a verified association. This is executable association, not a malware verdict.
- `sq_actor515_hooks.c`: typed successful-exec, fork and exit callbacks, dynamic
  tracepoint lookup, conservative `replace_mm_exe_file` attempt taint, missed
  kprobe sampling, partial-registration rollback and synchronized unregister.
  Startup and stop keep operation admission disabled in this candidate.
- `sq515_provenance_test.c`: actual native C state tests, including 10,000
  lifecycle cycles. No kernel hook is attached by this test executable.
- `sq515_direct.h`: bounded scalar correlation for an outer direct-open syscall
  and its inner file-open operation. Internal opens, stale operation returns,
  nested callbacks, changed lifetimes, missed observations and capacity
  exhaustion cannot become a complete paired observation. Positive kernel file
  pointers are rejected as serialized operation status.
- `sq515_direct_test.c`: 50,111 assertions on each of Plex and Netbox, including
  10,000 operation cycles. Early syscall failures are distinguished from inner
  file-open observations. Neither this test nor its correlation table attaches
  probes, collects actor bytes or establishes runtime coverage.

The successful exec callback uses the final PID, start times and exec counter.
It does not match an earlier `begin_new_exec` tuple: `de_thread` can change that
tuple during non-leader exec. A contemporaneous singleton check is conservative;
an unavailable association remains evidence and cannot suppress an alert.

## Remaining implementation

1. Add an explicitly negotiated `LINUX_KPROBE_515` source descriptor and raw
   payload. Keep controlled-v2/schema6/7 and their existing validation unchanged.
   Include provider epoch, raw sequence, operation nonce, process lifetime,
   credential values, provenance generation/loss and observation class.
2. Add bounded direct-open call frames and a preallocated raw queue. Pair
   `do_sys_openat2` with `do_filp_open`; kernel-internal opens cannot be presented
   as direct user opens. Copy only bounded kernel-owned filename bytes, never a
   deferred user pointer. A candidate name is explicitly unresolved target
   evidence; it cannot become a target whitelist match.
3. Reuse the existing four-slot actor copy worker and durable forensic journal.
   Add a source-specific unresolved-target lease capability. The existing
   `sq_atomic_request_valid` requires a target inode and must retain that rule.
   Do not route an unresolved candidate through that target-bound ABI.
4. Retain F1, independently acquire F2/write exclusion, commit raw evidence,
   then authorize copy with the exact source/operation key and durable receipt.
   Preserve actor bytes and SHA-256; do not hash or copy target files by default.
   A blocked copy retains its references until normal return and drain.
5. Extend `LinuxNativeInstallation`, controlled source admission, native journal
   and interop, actor evidence, server ingestion and SIEM serialization only
   after the new descriptor/ABI has its own validators and negative tests.
   Unknown provenance, unresolved targets and source loss remain explicit.

## Qualification

Exact running-kernel headers, symbols and exports were checked on Netbox
`5.15.0-170-generic` and Plex `5.15.0-186-generic`. Required symbols were present
and absent from the readable kprobe blacklist. That is not proof that probes can
attach or operate. `5.15.0-185-generic` still needs its own build/runtime gates.

Runtime qualification must separately cover scheduler registration/unregistration,
leader and non-leader exec, exec failure, process exit/PID reuse, CLONE_VM,
PR_SET_MM success/failure, startup-existing processes, credential changes,
actor rename/replacement/deletion, unresolved direct opens, early failures,
inherited descriptors/io_uring, raw queue loss, missed probes, no START,
preserved-copy hash equality and blocked-worker normal drain. Actual monitored
file events and server evidence must be checked after component qualification.

The exact Plex kernel image and modules packages were downloaded and compared
with hashes from signature-verified Ubuntu package indexes. This prepares an
isolated VMware runtime test; no production kernel, boot configuration or sensor
was changed by the package download.

The Linux .25 installed test is a separate qualification of the existing
controlled-v2 local preopen/read profile. It does not qualify this provider.

Primary source references: [Linux exec](https://raw.githubusercontent.com/torvalds/linux/v5.15/fs/exec.c),
[scheduler tracepoints](https://raw.githubusercontent.com/torvalds/linux/v5.15/include/trace/events/sched.h),
[tracepoint registration](https://raw.githubusercontent.com/torvalds/linux/v5.15/include/linux/tracepoint.h),
[kprobes](https://docs.kernel.org/5.15/trace/kprobes.html).
