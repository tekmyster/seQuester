## Runtime and installed acceptance, 2026-10-10

R4 isolated runtime passed 14 cases, 35 actor copies and normal closure.
FreePBX installed/central/restart/readiness gates passed; receipts are linked
in LINUX-IO-DEPLOYMENT-ACCEPTANCE-20261010-R5.json. The 134-check definition
fixture rejects the old verifier-failed sleepable object and cross-profile
substitutions. Exact artifact hashes are pinned in managed admission.

## Linux 6.1 runtime correction, 2026-10-10

The first isolated exact-kernel runtime attempt rejected the sleepable
`task_alloc` program because Linux 6.1 does not allow `bpf_spin_lock` in a
sleepable program. The failure receipt and loader stderr remain preserved in
`LINUX-IO-EXACT-KERNEL-61-RUNTIME-20261010-R3.json`. Normal module removal,
guest shutdown and restoration of the original VMware baseline passed.

The explicit 6.1 candidate now selects `lsm/task_alloc`; modern profiles keep
`lsm.s/task_alloc`. The task hook performs bounded spin-locked map work and does
not call the executable-copy helpers. A Debian 12 build of the loader and its
exact libbpf 1.1.2 dependency is used for this candidate. The sealed hashes are
in `LINUX-IO-FREEPBX-CANDIDATE-20261010-R3.json`. Build success is separate from
runtime qualification; this change does not admit or deploy the 6.1 profile.

# Linux 6.1 atomic I/O compatibility candidate

This profile is selected explicitly with `SQ_KERNEL61_ATOMIC_ONLY=1` for the
module and `-DSQ_KERNEL61_ATOMIC_ONLY` for the BPF object. It is not automatically
admitted by the managed sensor and does not change the installed 6.8/6.12
profiles. A successful build does not qualify a kernel module for deployment.

## Verified API differences

The exact Debian 6.1.0-50 headers implement `get_file_rcu(file)` as a conditional
reference increment on a supplied file. The slot is read under RCU and the
independent file reference is acquired before releasing RCU. The `mm` reference
is returned with `mmput_async`. Later kernels retain their pointer-slot API.

The 6.1 inode mtime field is `i_mtime`; the profile accessor uses that field.
The exact headers already provide `inode_get_ctime`. BPF's inode-permission
argument is a user namespace on 6.1 and `mnt_idmap` on the later profiles.

The 6.1 kfunc registry has no per-program filter. The candidate registers only
six non-sleepable helpers: actor reference acquire/release, observed-target
reservation, atomic finalization, atomic abort, and copy-worker identity.
Legacy, sleepable, path, and compatibility-probe helpers are excluded from the
registered set. Linux 6.1 shares the registry hook between tracing and LSM;
this candidate therefore does not claim the later per-program-type restriction.
Modern builds retain their existing filter. Verifier ownership flags remain
enabled, and the actor-copy owner, exact operation key, provider epoch, source
admission, durable START, four slots and 4 MiB limits are not relaxed.

## Build evidence, 2026-10-10

`LINUX-IO-FREEPBX-MODULE-BUILD-20261010-R3.json` records an exact-header build
with the actual kernel BTF, a real `.BTF` section, and authenticated private
pahole/BTF resolver inputs. No package, service, boot or module-load change was
made on FreePBX for these builds. The two earlier failed build receipts remain.

`LINUX-IO-ADDITIONAL-CANDIDATES-20261010-R1.json` records matching BPF/loader
builds and captured target hook prototypes for 6.1.0-50, 6.12.86 and 6.12.95.
The synchronous iterator hook has five arguments on all three captured kernels.

Runtime verifier/attach, exact write/append and first-use capture, loss counters,
normal drain/unload, packaged admission and central evidence verification are
separate gates. They must pass before a new trusted installation profile or
deployment is claimed. This candidate has no hash whitelist eligibility.
