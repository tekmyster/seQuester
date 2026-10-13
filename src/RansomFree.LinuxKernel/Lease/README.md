# Linux actor executable acquisition sources

These are the exact source bytes from the qualified R18 archive. `SOURCE-MANIFEST.json` records their hashes, the archive identity, and the tested Debian kernel/module pair. No binary or runtime configuration is changed by this source import.

The BPF source takes operation-time process and credential evidence and references the actor executable file. The kernel module retains that file reference while copying executable bytes asynchronously. It does not read, hash, or preserve the monitored target contents. The managed companion hashes actor bytes, records acquisition failures, preserves evidence, applies server-signed whitelist policy, and exports committed events to the existing ordinary sensor.

## Build boundaries

- Build the module against the exact target kernel headers using the included Makefile. Fault injection is disabled by default. `SQ_QUALIFICATION=1` is exclusively for isolated qualification and must not be used in a deployed artifact.
- Generate `vmlinux.h` from the exact target BTF and build the BPF object/loader with the qualified libbpf toolchain and the controlled V2 protocol. A rebuild is a new artifact requiring verification; source similarity does not make its hash interchangeable with the tested binary.
- The existing managed admission code checks the exact kernel, BTF, module, package members, target identities, protected directories, policy key, and service account. Do not bypass those checks to activate another kernel.
- The qualified module admits four concurrent actor copies of at most 4 MiB. Unsupported storage, larger actors, capacity exhaustion, changed files, permission errors, and expired work produce explicit unavailable/failure evidence. Preserve metadata; do not treat these failures as clean actors.
- Copying backing-file bytes is not an atomic snapshot of executing memory. Credential snapshots and process identity remain separate from executable acquisition evidence.

## Qualification and deployment

The existing installed-service tests cover actual root and ordinary services, authenticated manual whitelist creation before an event, signed policy transfer, matching/nonmatching process hashes and users, actor preservation, and central upload/download. Their receipts are `LINUX-INSTALLED-SERVER-TRUST-R4.json` and its independent review. They establish the tested kernel/local pre-open scope only.

Production readiness still requires package admission, deployment and fresh host-specific tests. Current Linux sensors retain their working Audit source until native integration is accepted. Other kernel/BTF pairs require their own build and VMware qualification. Ubuntu's separately qualified protocol uses different sources and artifacts; this Debian source directory must not be substituted for them.
