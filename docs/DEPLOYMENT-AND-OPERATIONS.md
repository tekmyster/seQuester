# Deployment and operations

## Release boundary

The current server and callback receiver require the **Development** environment. They reject other environment modes in code. This source snapshot is not a completed production release, and successful compilation does not qualify its native components or integrations.

Deployment packages, monitoring source support and acceptance differ by platform. Use the matching package instructions rather than renaming an archive or installing a driver compiled for another kernel or Windows version.

## Prepare a deployment

Confirm these items before activation:

| Area | Required preparation |
| --- | --- |
| Host | Compatible OS, architecture and runtime/toolchain dependencies. |
| Storage | Space for database growth, queue backlog, actor evidence and release rollback. |
| Management access | Approved administrative path and a separate fresh-session test procedure. |
| TLS | Certificate and private key for the intended DNS name, with client trust configured. |
| Identity | Independent bootstrap secret, operator accounts, MFA policy and recovery custody. |
| Data | Protected state directory and chosen database provider. |
| Callbacks | Separate receiver, approved origin and optional DNS/mail configuration. |
| Sensors | Approved folders, suitable capture source and credentials. |
| Recovery | Previous package, configuration and tested data/key backup. |

Do not publish certificates, passwords, sensor credentials or database connection secrets in Git. The repository includes templates, not working deployment credentials.

## Build the managed applications

Install the .NET 10 SDK. From the repository root:

```powershell
dotnet build src/seQuester.Server/seQuester.Server.csproj -c Release
dotnet build src/seQuester.Receiver/seQuester.Receiver.csproj -c Release
dotnet build src/seQuester.Agent/seQuester.Agent.csproj -c Release
dotnet build src/seQuester.LinuxAgent/seQuester.LinuxAgent.csproj -c Release
```

Windows projects need Windows targeting support. Kernel sources have separate WDK/Linux build requirements. Managed compilation alone does not validate kernel loading, callbacks or endpoint attribution.

Build and verification scripts are under `tools`. Some retain environment-specific tool paths; review parameters before running them on another machine. Prefer a dedicated artifact directory outside the source tree.

## Configure the management server

| Setting | Purpose |
| --- | --- |
| `ASPNETCORE_ENVIRONMENT=Development` | Required by the current build. |
| `ASPNETCORE_URLS` | Approved listener and HTTPS port. |
| `RF_DATA_DIR` | Pre-created protected server state directory. |
| `RF_ADMIN_KEY` | Independent random 32-byte secret encoded as 64 hex characters. |
| `Database__Provider` | `Sqlite` or `SqlServer`. |
| `Database__ConnectionString` | Protected SQL Server connection when selected. |
| `Kestrel__Certificates__Default__Path` / `Password` | HTTPS certificate configuration. |
| `IdentityKeys__CertificatePath` / `CertificatePassword` | Protected identity-key encryption configuration when used. |

Pre-create the state directory before startup. An isolated screenshot rehearsal exposed an SQLite initialization failure when that directory did not exist; the capture tool now provisions its own private state directory.

`RF_ALLOW_LOOPBACK_HTTP=true` is for isolated development on loopback only. It is not a remote HTTP deployment option. SQL Server configuration requires validated TLS; the database layer rejects trust-bypass and unsupported attachment modes.

The Linux management template is [`packaging/linux-management/server.env.example`](../packaging/linux-management/server.env.example). Read its [package instructions](../packaging/linux-management/README.md) for service identity, paths and installer behavior.

## Configure the receiver

The management server's token-authoring configuration uses:

- `Callbacks__Enabled=true`
- `Callbacks__Origin` set to the approved HTTPS receiver origin
- `RF_CALLBACK_DATA` set to protected callback state
- Optional `Callbacks__DnsZone` and `Callbacks__MailDomain`

The standalone receiver also needs its own listener, state access and protocol settings. Follow its source/package references for DNS and mail listeners. Setting an origin does not create DNS delegation, issue a certificate or open a firewall.

Validate an actual receiver transaction independently of management token creation. Keep callback request content and credentials out of general service logs.

## Install sensors

### Windows

Use the Windows sensor package and documented local configuration workflow. Keep administration password, enrollment, folder approval and remote-response permission distinct.

Native capture is a separate component from the managed service. Confirm the driver's version, load state, supported host/version and required capture capability. A green heartbeat does not establish full thread-token or failed-operation coverage.

### Linux

Use the correct architecture and glibc-compatible package. Approve monitored folders and select the source qualified for that host. Audit relay, audit collector, BPF and kernel components have separate dependencies and service boundaries.

The audit relay instructions require distribution audit dependencies and a Native AOT child process where the audit daemon's sandbox prohibits JIT execution. Do not disable the audit daemon sandbox to work around an incompatible managed plugin. See [Linux audit package guidance](../packaging/linux-client/AUDIT.md).

Kernel support is version-specific. Preserve native source/provenance manifests and reproducible build inputs. A built or loaded module is not proof that exact write/append or first-use actor capture works end to end.

## Upgrade safely

1. Record running versions, source capabilities, database location and pending queue state.
2. Back up configuration, database and identity keys consistently.
3. Build a versioned package and verify its manifest and SHA-256 inventory.
4. Stage it without deleting the accepted package or evidence store.
5. Test one representative Windows host and one representative Linux host before wider activation.
6. Activate the intended components and check service startup and management access.
7. Verify policy and capability receipts from upgraded sensors.
8. Run controlled file-operation and callback tests; match sensor, host, actor and source-event evidence on the server.
9. Record missing fields and preservation/upload failures as failures, not passes.
10. Retain the previous package and recovery data until acceptance is complete.

A UI-only asset update is different from a server runtime, managed sensor or native source rollout. Record each changed component separately. Do not report all-host deployment from a package build or one sensor heartbeat.

## Backup and recovery

Protect the management and identity databases, callback registry/inbox, identity encryption certificates and data-protection key ring, protected integration configuration, uploaded actor artifacts and manifests, and deployment selection metadata.

Use provider-appropriate consistent database backups. Copying an actively written SQLite database without its transaction state is not a reliable recovery procedure. Test a restore in an isolated instance with matching application/schema versions.

Before rollback, confirm database compatibility. Restoring an older executable onto a newer schema is not automatically safe. Preserve sensor credentials, event IDs and evidence linkage to avoid orphaning records or accepting duplicates as new incidents.

## Monitor resources

Review service CPU/RAM, database latency, disk free space, evidence quotas, upload backlog, dropped/source-loss counters and syslog queue growth. Expensive actor hashing and signature verification belong outside critical file-I/O paths.

When reports are delayed, compare observation time, server receipt time and enrichment/upload status. Increasing VM resources may help capacity but does not repair missing source evidence, incorrect correlation or a failing transport.

## Diagnose common failures

| Symptom | Check |
| --- | --- |
| Startup exits immediately | Development gate, bootstrap-key format, state directory and certificate access. |
| SQL Server connection fails | Named database, TLS trust, identity/permissions and component connection settings. |
| Sensor contacts but no events | Local service, folder approval, native source and source-loss telemetry. |
| User/process/PID missing | Source capability and field-specific collection status; do not infer from another process. |
| Wrong executable hash | Process-instance binding, file replacement and preservation race status. |
| Actor upload never completes | Artifact limits, receiver quota, chunk/status receipt and local queue state. |
| Whitelist not applied | Parser capability freshness, scope, revision/digest and sensor receipt. |
| TLS connects but Wazuh has no record | Durable collector receipt, rule feed and indexing separately; handshake alone is insufficient. |
| Overview errors after revisiting | Known DOM-field collision between Overview and Incidents; see [Capabilities](CAPABILITIES.md). |

## Access-change validation

For credential, ACL or management-firewall changes, keep the original working session open. Establish a fresh authenticated session from the affected source, verify administrative privilege and verify the intended repair. Check the target-seen source address where restrictions depend on it.

If validation fails, use the original session to correct or safely roll back the change. Record untested paths. Do not close the original session based only on an open port, banner or earlier login.
