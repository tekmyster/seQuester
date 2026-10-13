# SQL Server storage — implemented, unsigned, untested

SQL Server is selectable for management, identity/MFA, callback registry and callback inbox. SQLite remains the default for existing development configurations; changing provider never automatically copies or deletes SQLite data. This implementation targets SQL Server with compatibility level 150 or newer. Express can serve a small local installation; moving to a dedicated instance or a larger edition does not require a different application data model. Edition limits, workload sizing and licensing must be reviewed for the selected SQL Server version.

## Configuration

Set `Database:Provider=SqlServer` and `Database:ConnectionString` in protected server configuration. Environment variable equivalents use double underscores, for example `Database__Provider` and `Database__ConnectionString`. Do not supply passwords in command-line arguments or commit connection strings containing credentials.

Non-secret example shape:

```text
Server=tcp:sql-host.example,1433;Database=RansomFree;Integrated Security=true;Encrypt=true;TrustServerCertificate=false;Persist Security Info=false
```

Use the local machine's DNS name/fixed SQL port for a local Express installation, or a remote SQL host/listener later. Provision a trusted server certificate whose name matches the connection target. Named instances can also be configured, but SQL Browser/instance resolution is a deployment consideration. The application does not install SQL Server, open ports, create databases, trust a self-signed certificate or configure domain authentication. Windows/Linux hosting authentication prerequisites differ and remain acceptance work.

Overrides allow component separation:

- `Database:ManagementConnectionString`
- `Database:IdentityConnectionString`
- `Database:CallbackRegistryConnectionString`
- `Database:CallbackInboxConnectionString`

An omitted override uses the common connection string. Receiver configuration uses its own restricted credential and needs only the registry/inbox connections. Do not reuse the management credential on the public receiver. SQL connections enforce encryption and certificate validation, disable persisted security information, and reject LocalDB, user-instance and attached-file configurations. There is no plaintext or certificate-bypass fallback. RF_DATA_DIR remains required for private identity keys and delivery checkpoints; RF_CALLBACK_DATA remains a required configuration value even with SQL-backed callback tables.

## Explicit schema migration

1. Have a DBA create the empty target database(s), with compatibility level at least 150. Stop the application/receiver during migration or cutover.
2. Configure the target connections with a temporary migration identity able to create tables/indexes and acquire application locks. Keep the normal Development-only environment and required server configuration; the existing bootstrap-key configuration is still required by this development host.
3. Run `dotnet RansomFree.Server.dll --migrate-database` in the published server directory.
4. Configure normal restricted runtime credentials before starting services later. The optional `Database/RuntimeRoles.sql` helper is a separate reviewed DBA step; it does not create users or assign membership automatically.

The command starts no HTTP listeners or workers. Each component uses a transactional, application-locked version/checksum ledger. Initial management, identity and optional callback schemas are installed. It refuses newer/unexpected versions, changed checksums, and pre-existing unversioned target tables. Existing SQLite initialization remains isolated to SQLite mode. Normal SQL startup checks the required version and does not execute DDL. This is the initial SQL schema migration, not a promise that future versions can skip their own reviewed migration scripts.

Identity DDL is generated from the SQL-specific EF model and executed as separate batches in one component transaction. Composite key lengths are bounded. Do not modify/redeploy its model as version 1 after a database has been initialized; add a versioned migration. No automatic transient-command replay is enabled: explicit transactions and durable application IDs must not be blindly replayed.

## Optional offline SQLite import

First run the schema migration against empty target component tables. Keep BOTH source and target applications/receivers stopped. Preserve a complete backup before any future operator-run import. Then run, with protected SQL import credentials:

```text
dotnet RansomFree.Server.dll --import-sqlite --acknowledge-offline-import --source-data "ABSOLUTE_LEGACY_DATA_DIRECTORY" --source-callbacks "ABSOLUTE_LEGACY_CALLBACK_DIRECTORY"
```

The callback path is required only when callbacks are enabled. Source paths must be absolute and may not traverse links; linked sidecars are rejected. All required source paths and target schema versions are checked before the first import write. The tool opens SQLite read-only, copies known tables in dependency order, preserves identity values/high-water marks, converts typed values, checks row counts and fingerprints source main/WAL files. It refuses non-empty target components, mismatched columns, oversized fields and changed source fingerprints. A completed component is recorded with its fingerprint so an identical retry does not duplicate it. A different source cannot be silently merged into an already imported component.

Transactions are **per component**, not globally atomic across four databases. A later failure can leave earlier components committed; do not start the product until all required components finish and the cutover is reviewed. The acknowledgement is an operator assertion, not a remote service-stop detector. Original SQLite files are not deleted or rewritten by application import logic. No source/target was opened by this coding session.

The importer does not relocate/decrypt identity keys or copy the callback syslog checkpoint. Keep the same identity key ring and compatible DPAPI identity/machine, or perform a reviewed certificate-based key migration before changing application hosts. Database relocation alone, with the application/key ring staying in place, does not require a new key ring. Preserve the callback checkpoint when importing hit sequences to avoid replaying old notifications. Do not resume writing to both old and new backends. Rollback after new SQL writes requires reconciliation, not merely switching a connection string.

## Scaling boundaries

Local-to-remote SQL hosting and edition growth are configurable. This does not implement active/active application HA: background-worker leadership, callback forwarding checkpoint coordination, shared identity key deployment and failover orchestration remain separate work. Current application quotas still apply. Operations displays the selected provider without claiming production readiness. All live SQL, migration/import, locking/deadlock, permission, restore, scale and Windows/Linux acceptance checks remain pending in QA.md.

References: [Microsoft SQL Server EF provider](https://learn.microsoft.com/en-us/ef/core/providers/sql-server/), [multiple-provider migrations](https://learn.microsoft.com/en-us/ef/core/managing-schemas/migrations/providers), [EF SQL Server 10.0.12 dependencies](https://www.nuget.org/packages/Microsoft.EntityFrameworkCore.SqlServer/10.0.12).
