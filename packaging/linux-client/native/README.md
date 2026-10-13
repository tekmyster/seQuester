# Linux native companion package

## Current deployment status — October 10, 2026

The controlled-v4 Linux capture source is deployed on all 26 Linux sensors.
Acceptance `LINUX-IO-DEPLOYMENT-ACCEPTANCE-20261010-R10.json` records 364 installed
operation cases, 1,456 linked server events, 364 authenticated executable/manifest
download pairs, normal source restart checks and final readiness on all sensors.
The actual source is maintained in `src/RansomFree.LinuxKernel/Lease/Atomic`.
Installation metadata uses manifest version 5, control version 4 and event schema 8.
Qualified kernel profiles include Debian 6.12.94, 6.12.95 and 6.12.86, Debian 6.1.0-50,
and Ubuntu 6.8.0-134 and 6.8.0-138. Each profile requires its exact admitted kernel,
BTF and binary hashes; this is not permission to activate on arbitrary kernels.

Current capture bounds are four concurrent actor leases and 4 MiB per executable.
The seven synchronous write/append variants are qualified; mmap, io_uring, splice
and copy_file_range are not. Controlled-v4 hash whitelist eligibility remains
disabled. See `docs/CURRENT-OPEN-WORK.md` for unfinished work.

The instructions below describe the earlier staging and qualification workflow.
Their version-1 request and pending-qualification wording are historical; use the
current versioned implementation and passed per-host receipts for this release.
Do not use a component test receipt as an installed-service deployment pass.

The ordinary sensor owns credentials, HTTPS delivery, event spool and executable upload. The root companion owns native collection and exports immutable event pairs with preserved actor executables. The root request contains only a policy verification **public** key. Target file contents are not hashed or copied by installation.

## First installation staging

Stage a root-owned, private release directory at `/opt/sequester-native/releases/RELEASE`. It contains the matching published Linux agent in `app/` and admitted native package files in `native/`. Every ancestor must be root-owned and not writable by an ordinary user. The native profile currently requires Linux x64 and an exact qualified kernel/BTF/module tuple: Debian `6.12.94+deb13-amd64` with nativeR18, or Ubuntu Noble `6.8.0-134-generic` with nativeR19. Both require their recorded BTF and exact module SHA-256, local ext4, and 1–32 root-approved honeypot identities. Other kernels require qualification before activation.

Supply a root-private JSON request with explicit `Version: 1`, `SensorId`, canonical HTTPS `Server`, `PublicKeyBase64`, numeric `ServiceUid` and `ServiceGroup`, `PackageDirectory`, `Members` and `TargetPaths`. `Members` lists exact `Name`, `Role` (`loader`, `object`, `module`, `library`), `Size` and uppercase `Sha256`. `PackageDirectory` must equal this release's `native` directory. The UID must be the installed `rfclient` account; the GID belongs to the dedicated `sequester-native` group, with no other ordinary accounts. The public key must come from the corresponding server's explicit native-policy signing setup; staging never generates a private signing key.

Run `stage.sh RELEASE REQUEST` as root. It creates new protected state/channel/export directories, verifies package descriptors/hashes and live target identities, and writes canonical installation metadata with create-new durable writes. It refuses an existing installation, does not replace metadata, does not modify the ordinary sensor configuration and does not install, enable or start units. Partial failure is retained for diagnosis; do not erase it as evidence of a successful installation.

## Pending activation qualification

Before release activation, qualify the exact root and ordinary packages with the included unit and drop-in. The first boot must create `/run/sequester-native` through `RuntimeDirectory` before the strict filesystem sandbox applies; root then assigns the dedicated bridge group before binding. Normal stop sends TERM to the main root process. Source/controller/loader work must actually drain before module unload and process exit. No SIGKILL or finite service stop timeout substitutes for this completion. SIGHUP must leave policy/source identity unchanged. Ordinary import cancellation must likewise retain its actual drain and exact receipt.

After that gate, deployment must create the managed `current` link, install `sequester-native.service` and the ordinary sensor drop-in, and enable `NativeCompanion` in the ordinary sensor's validated configuration with the exact channel/export paths and group ID. Preserve the prior configuration and release for rollback. The normal Audit service remains necessary for operations outside the qualified native pre-open source. A health reply is a recent observation, not proof that every access has complete evidence.

Final packets can be imported after root capture stops. If the acknowledgement socket has already closed, retain the root duplicate until the next session accepts the same exact durable import receipt. Never delete root journals or source actor copies on a local import acknowledgement.

Systemd settings follow its documented [kill behavior](https://raw.githubusercontent.com/systemd/systemd/main/man/systemd.kill.xml) and [service lifecycle](https://raw.githubusercontent.com/systemd/systemd/main/man/systemd.service.xml). Manus R131 identified the initial missing-runtime-directory defect. Actual R67 qualification then found that an `ExecStartPre` group change was reset before `ExecStart`. The corrected unit uses `User=root`, `Group=sequester-native` and `RuntimeDirectoryMode=0750` so the manager creates the required owner/group directly. Private evidence remains root-only with directory mode0700 and file mode0600. Qualification of the corrected installed unit is pending.
