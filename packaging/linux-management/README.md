# Quiver seQuester — Linux management-server package

**Unsigned, development-only. Management server, not Linux endpoint agent.** Each package targets exactly one glibc-based Linux architecture: `linux-x64` or `linux-arm64`, identified by `RUNTIME_ID`. The systemd installer rejects a different host architecture before changing accounts or files. No deployment host was contacted or assessed by this build. These are not Alpine/musl, Windows, DEB or RPM packages. ARM64 publishing does not establish native ARM64 support acceptance.

The versioned tar.gz contains the self-contained .NET 10 management server, management WebUI, native Linux runtime/SQLite libraries, systemd unit, installer/removal scripts, environment template, deployment documentation, source-input inventory, package manifest and SHA-256 list. RELEASE_ID uniquely identifies this build. This package does **not** include the callback receiver, SQL Server installation, Windows MSI, Linux endpoint monitoring agent or a macOS client. Those have distinct deployment/security requirements. Legacy RansomFree service/path names remain stable; the product line is Quiver and the product is seQuester.

## Release state and precise blockers

1. The server explicitly rejects environments other than Development. This package preserves that gate; changing an environment variable to Production will fail. Removing the gate is not an acceptance procedure.
2. The package is unsigned. SHA-256 detects byte changes only; it does not authenticate a publisher. Verify the archive digest through a separately trusted channel before running any extracted script as root.
3. No native Linux service/startup/install/upgrade/uninstall or systemd sandbox test has been run. ELF and shell syntax checks do not prove dynamic-library resolution or Linux behavior. No cptnycdc01 prerequisite or connectivity assessment was performed.
4. TLS certificate/name/trust, identity encryption certificate and recovery custody, independent bootstrap secret, database topology/permissions, disk capacity, firewall access and operator identities must be supplied and reviewed. Templates contain placeholders, never working default credentials.
5. SQL migrations/import, Linux LDAP native dependencies and LDAPS trust, Entra/OIDC provider registration, MFA/recovery, report rendering, callback receiver linkage and actual Wazuh/SMTP delivery remain environment-dependent acceptance work. No public receiver is bundled.
6. The product's broader authorization/site/tenant boundaries, HA/worker leadership, backup/restore acceptance, migration/rollback compatibility, capacity/load acceptance, remaining feature ledger and senior UX/UI acceptance remain unfinished. This archive does not close those backlog items or establish Fortune-500 production readiness.

Keep this build on an isolated development network. Do not expose it publicly or infer production approval from a successful liveness response. See VERIFICATION-REPORT.md for exact evidence and deferred checks.

## Paths and privileges

| Purpose | Default |
| --- | --- |
| Immutable releases | /opt/ransomfree-management/releases/RELEASE_ID |
| Selected release | /opt/ransomfree-management/current, root-controlled symlink |
| Service | ransomfree-management.service, runs as dedicated rfmgmt:rfmgmt |
| Account | System account, no password/login shell, no sudo or administrative group |
| Configuration/secrets | /etc/ransomfree-management/server.env, root:root 0600 |
| HTTPS PFX | /etc/ransomfree-management/tls/server.pfx, root:rfmgmt 0440 |
| Identity-key PFX | /etc/ransomfree-management/keys/identity.pfx, root:rfmgmt 0440 |
| State root | /var/lib/ransomfree-management, rfmgmt:rfmgmt 0700 |
| Databases, identity keys, protected notifications | State root /data |
| Optional callback registry/inbox state | State root /callbacks |
| Runtime temp | /run/ransomfree-management, 0700, managed by systemd |
| Service logs | journald: journalctl -u ransomfree-management.service |
| Reserved log/export directory | /var/log/ransomfree-management, 0700; application console logs are not automatically duplicated here |

The unit grants no Linux capabilities, prevents privilege elevation, makes the filesystem read-only except systemd-managed state/log/runtime locations, isolates temporary files/devices, protects home/kernel/control-group paths and restricts address families to Unix/IPv4/IPv6. JIT-compatible memory permissions are retained. These are authored controls, not a verified sandbox assessment. SELinux/AppArmor labeling/profile changes are not installed automatically; do not disable enforcement to make the application start.

The installer is intentionally first-install only. It refuses an existing unit/current link, rfmgmt identity, target release or state/log/configuration file and does not silently adopt them. It does not install OS packages, change a firewall, issue certificates, initialize SQL Server, enable autostart or start the service. Partial failure can leave new files/account behind; examine the specific paths rather than blindly rerunning or recursively deleting state.

## Prerequisites

Choose a Linux distribution/version supported by the selected .NET 10 runtime and validate it before deployment. Self-contained publishing includes .NET, not the OS: the glibc loader, libc, libgcc/libstdc++, OpenSSL, ICU, zlib and CA trust still matter. Linux directory sign-in also needs compatible LDAP/Kerberos libraries and configuration. Consult the official .NET installation guide for the exact distribution's packages; this installer neither guesses nor installs them. A booted systemd host and bash/coreutils/getent/groupadd/useradd/curl are required for the supplied procedures. /usr/sbin/nologin must exist. Native compatibility and systemd version remain unverified.

Use an unprivileged HTTPS port (default 7443). The configuration template binds **only 127.0.0.1** and leaves RF_ALLOW_LOOPBACK_HTTP=false. For future remote clients, an administrator must deliberately select an approved private interface, certificate DNS name and AllowedHosts list, then separately authorize firewall access. Merely allowing a hostname does not create DNS or bind an interface. No certificate-validation bypass is provided.

The TLS PFX must include its private key and a valid server certificate covering the chosen management DNS name. For the supplied loopback smoke script, include localhost in the isolated test certificate. Use a separate current private-key certificate for ASP.NET Data Protection; protect and back it up. The service account needs read access to those PFX files, not permission to replace them. Changing/removing the identity certificate or key ring can make MFA and protected notification settings unrecoverable. Copying Windows DPAPI-protected keys to Linux does not make them decryptable: use an explicitly reviewed key-migration strategy.

## Verify and install (future operator action only)

Obtain the tar.gz and its .sha256 sidecar, compare the digest with the trusted release channel, then on the intended Linux development host:

    sha256sum --check RELEASE.tar.gz.sha256

Replace RELEASE with the actual complete archive basename. Extract into a new dedicated root-owned staging directory (not an existing application/data directory). Do not extract untrusted archives as root. After the archive has been independently authenticated and verified, preserve that staging tree as root-owned and remove group/other write permissions. Use the actual paths below, not the illustrative placeholders:

    sudo mkdir -m 0700 /root/rf-management-staging-RELEASE
    sudo tar --no-same-owner -xzf RELEASE.tar.gz -C /root/rf-management-staging-RELEASE
    sudo chmod -R go-w /root/rf-management-staging-RELEASE
    sudo bash /root/rf-management-staging-RELEASE/install.sh --acknowledge-development-only

The chmod target is the newly created, explicitly named staging directory only. The installer verifies the internal SHA256SUMS, rejects symlinks/untrusted staging permissions and installs root-owned immutable payload. It normalizes the server apphost executable permission; run packaged scripts through bash. No source directory, user file, existing live release or canary is deleted.

After installation, securely edit /etc/ransomfree-management/server.env. It uses **systemd EnvironmentFile syntax**, not shell syntax: never source it and never paste secrets into shell history. Generate an independent random 32-byte bootstrap secret represented by 64 hex characters through your secret-management process. Replace every active REPLACE placeholder, supply both PFX files/passwords and select database configuration. There is no default administrative password. Use the existing management bootstrap flow to create a local administrator and enable MFA in the isolated deployment.

Validate the unit, dynamic libraries and configuration on that host before startup:

    sudo systemd-analyze verify /etc/systemd/system/ransomfree-management.service
    ldd /opt/ransomfree-management/current/app/RansomFree.Server
    ldd /opt/ransomfree-management/current/app/libcoreclr.so
    ldd /opt/ransomfree-management/current/app/libe_sqlite3.so

Only run ldd on this independently verified trusted artifact. Then, after explicit approval of the isolated configuration:

    sudo systemctl start ransomfree-management.service
    sudo systemctl status ransomfree-management.service --no-pager
    sudo journalctl -u ransomfree-management.service -n 100 --no-pager
    bash /opt/ransomfree-management/current/smoke-test.sh --ca-file /path/to/test-ca.pem

Do not share unredacted journal/configuration output; systemd/root diagnostics can reveal secret-bearing environment or errors. The smoke script checks only an already running service and a trusted-TLS loopback /health/live request, with proxying disabled. It does not start anything or contact cptnycdc01 by DNS. It fails closed on TLS failure and does not use curl -k. A pass does not establish authentication, data-write or external integration readiness. Enable boot startup separately only after acceptance: systemctl enable ransomfree-management.service.

## Database selection and migrations

SQLite is the safe development template default. It stores management/identity files under RF_DATA_DIR; callbacks remain disabled. SQL Server is optional and can run locally on a supported Linux SQL host or remotely; this package neither includes nor licenses/provisions it. Choose a SQL Server version/edition and host configuration supported by Microsoft. The application targets compatibility level 150 or newer. Integrated authentication on Linux requires a reviewed Kerberos setup; do not assume Windows domain credentials will work automatically. Alternatively supply restricted SQL credentials in the protected environment file. TLS encryption and hostname/chain validation are mandatory; no LocalDB, attached database or TrustServerCertificate=true fallback.

Have the DBA create the database(s), review component-specific credentials and RuntimeRoles.sql, then run the existing --migrate-database maintenance command with temporary migration privileges while the management server AND any separate callback receiver are stopped. Keep normal runtime credentials least-privileged and remove schema privileges after migration. The executable supports --migrate-database and the documented --import-sqlite flow; it does not create database hosts or implement a globally atomic four-component import.

To load the protected configuration for a reviewed maintenance invocation, use a transient systemd service with User/Group=rfmgmt and EnvironmentFile=/etc/ransomfree-management/server.env, pointing to the selected release executable and --migrate-database. Do not source the EnvironmentFile or place a SQL password on the command line. Validate that transient unit's paths/permissions first. It must use the same protected state/key paths and correct temporary migration identity. No migration has been run for this package. Detailed existing component/migration rules are in docs/SQL_SERVER_SETUP.md.

## Callback receiver and alerts

The management server handles endpoint ingestion, policy, console, reports and configured notification workers. Embedded-canary callbacks require a **separately deployed receiver** plus reviewed shared registry/inbox access, origin, DNS/SMTP routing and restricted receiver database identity. Leave Callbacks__Enabled=false until that system exists. Never substitute the management server's private configuration/bootstrap secret for receiver credentials or expose management publicly as the callback listener.

Administrators configure outbound email and syslog in the console; the package supplies no SMTP/Wazuh destinations. Client/server syslog routing is independent of endpoint management delivery. No actual email, Wazuh receipt or remote callback is asserted here. Existing guide copies under docs may reference repository-relative files and historical acceptance status; this README and VERIFICATION-REPORT.md govern this package.

## Backup, upgrade and rollback

Before changes, record RELEASE_ID, selected current-link target, configuration checksums and database schema/component versions. Stop the management service and all writers to callback storage; verify they are inactive. This package does not detect or stop remote writers. For SQLite, take a consistent stopped copy of the **entire** state directory, including database/WAL/SHM files, identity-keys, protected notification configuration, progress checkpoints and callback state. For SQL Server, have the DBA take coordinated, verified backups of every component database, plus the local state/key files. A database-only backup is insufficient.

Back up the complete /etc/ransomfree-management configuration/certificates separately with appropriate encryption/access controls; the private identity certificate, its password and key ring are required for recovery. Capture the selected immutable release and any systemd drop-ins. Keep encrypted backups off-host according to retention policy and verify restoration in an isolated environment. Do not copy secrets into a public release archive. No backup has been taken by this build.

Upgrade is intentionally manual and stopped-service: independently verify/extract a **new unique RELEASE_ID**, check release notes/schema compatibility, preserve the prior release and all state, stop writers, back up, stage the complete new package under a new /opt/ransomfree-management/releases/RELEASE_ID directory (root-owned, never overwrite an old release), normalize file/directory permissions and executable apphost mode as the installer does, then review unit/config differences. Preserve existing secrets; do not copy the template over server.env. Atomically replace the current symlink only after validating both old/new absolute targets remain under the releases directory. Reload systemd if the reviewed unit changed, perform any explicit compatible migration with temporary credentials, then start and run the isolated smoke/functional checks. The first-install script refuses upgrades instead of silently replacing live files.

Rollback before data/schema changes may reselect the prior immutable release with writers stopped. After any new-version writes or schema changes, switching a symlink alone is **not** a safe rollback: restore the matching database/state/key backups under a reviewed recovery procedure or reconcile new writes first. Preserve failed-upgrade evidence and avoid running old/new versions against the same state simultaneously. Never delete retained queue/checkpoint files to make startup succeed. Upgrade/rollback and restored MFA/notifications remain untested.

## Uninstall without destroying evidence

After approval, run:

    sudo bash /opt/ransomfree-management/current/uninstall.sh --preserve-all-data

The script checks the exact unit identity, disables/stops only ransomfree-management.service and renames its unit to a timestamped recovery copy after confirming inactivity. It preserves all binaries/releases, current link, configuration, certificates, rfmgmt account/group, local/SQL data and logs. It does not delete canaries, revoke endpoint credentials/tokens, or stop a receiver. Reinstall/complete removal of preserved files requires a separate reviewed plan; no purge mode is supplied. Root can bypass application-level controls; this is not tamper protection.

## Build and references

The repository's tools/build-linux-management-package.ps1 publishes and packages on D: by default with explicit .NET 10 SDK and locked restore. Use `-Runtime linux-arm64` for ARM64 or `-Runtime linux-x64` for x64 (the default), and `-Role Management` (the default). `-Role Receiver` creates a separate publish-only receiver bundle, not this installer. Each invocation creates a new immutable release path. tools/verify-linux-management-package.ps1 automatically checks role/runtime markers, ELF headers and payload/archive hashes/inventory without extracting or executing the Linux binaries. Native acceptance remains pending for these artifacts. Validate PDF rendering, SQLite, SQL connectivity and LDAP dependencies on each architecture; publishing an ARM64 SQL client does not imply that a SQL Server engine can be installed on ARM64.

- Microsoft Linux hosting/systemd: https://learn.microsoft.com/en-us/aspnet/core/host-and-deploy/linux-nginx?view=aspnetcore-10.0
- .NET Linux installation prerequisites: https://learn.microsoft.com/en-us/dotnet/core/install/linux
- systemd execution sandbox/directory settings: https://www.freedesktop.org/software/systemd/man/latest/systemd.exec.html
- systemd environment-file syntax: https://www.freedesktop.org/software/systemd/man/latest/systemd.exec.html#EnvironmentFile=
