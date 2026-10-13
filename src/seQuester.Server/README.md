# Management server foundation — development only

Current feature and verification register: [FEATURES.md](../../FEATURES.md). The dated build notes below include historical deferrals; use that register and the latest QA.md entry for current acceptance status. Full regression commands are documented there; native platforms and external integrations remain separate gates.

The 2026-09-25 candidate adds authenticated actor-executable uploads, private server storage, verified receipts and authorized attachment downloads. See [the forensic transfer contract](../../docs/FORENSIC-EVIDENCE.md#candidate-central-transfer-contract) for limits, migration, retention and deployment status. It is not yet deployed; native SQLite acceptance does not certify SQL Server migration.

This repository is the seQuester development environment. The current web console provides local sign-in, Sensors, Alerts, and account MFA; agent/tray IPC is still unfinished. Keep iterative deployments confined to the reviewed development environment.

## Local accounts and console

### Unsigned feature increment (QA deferred)

Administrator Sensor controls now issue a private single-use enrollment code, show its expiry, invalidate an unused code, and display the latest 100 management audit entries. Hiding a code does not revoke it. Sensor access can be revoked after typing its displayed name in the confirmation dialog; local monitoring and retained event records remain unchanged. Code and confirmation fields clear when leaving the view or signing out.

Added administrator/CSRF-protected POST routes: `/api/v1/console/enrollment-codes/cancel` with `{code}`, and `/api/v1/console/endpoints/{id}/revoke`. GET `/api/v1/console/management-audit` requires Administrator. Cancellation does not undo an enrollment that has already completed. Audit subjects contain actor/target identifiers, not enrollment secrets.

Account security includes self-service password change through POST `/api/v1/auth/password` with `{password,newPassword,code?,recoveryCode?}`. Current password, CSRF, and a fresh second factor when MFA is enabled are required. A successful password change updates the security stamp, audits the action, and signs out the current session. Other sessions are rejected on their next stamp validation. Administrator reset/account-recovery workflows are separate and remain unimplemented. Full acceptance tests are deferred.

Open the configured server origin after startup. Provision development accounts through `POST /api/v1/admin/users` using the development admin bearer key and `{userName,password,role}`. Roles currently accepted: Administrator, Operator, Reader. Passwords require at least 14 characters (maximum 256). There is no public registration or default user. Human users sign in through the console; do not place the bootstrap key in the browser.

Browser sessions last 30 minutes, are HttpOnly/SameSite Strict, and require CSRF tokens on mutations. Secure cookies are required outside the explicit loopback HTTP lab mode. Five failed password/second-factor attempts lock further sign-in attempts for 15 minutes. Account security supports authenticator-app setup, proof before activation, ten random single-use recovery codes, and disable with password plus second-factor proof. Activation/disable invalidate sessions. Save recovery codes when issued; they are not shown again.

Identity tables are separate from endpoint telemetry. Passwords use ASP.NET Core Identity hashing with 600,000 PBKDF2 iterations. Authenticator secrets are protected by Data Protection; Windows protects persisted key material with DPAPI. Linux key-at-rest protection and key-ring deployment/rotation are not yet completed in this development environment. Recovery codes are stored as hashes, and MFA-code replay markers persist. Development schema additions are additive; reviewed deployment migrations are still required.

Human APIs: `/api/v1/auth/csrf`, `/login`, `/logout`, `/me`, `/mfa/setup`, `/mfa/enable`, `/mfa/disable` (paths after the first share `/api/v1/auth`). Read-authorized console routes provide `/api/v1/console/endpoints` and `/events`; Administrator additionally gets `/enrollment-codes` and `/identity-audit`. Console mutations require the `X-CSRF` header and anti-forgery cookie; retrieve a new request token after signing in.

The endpoint inventory is administrative context only. It never gates, suppresses, downgrades, or qualifies monitoring, health, alerts, readiness, or event visibility. Overview and reports aggregate structured protection reports actually submitted by clients: monitoring state and deployed canary/honeypot-file count. Older clients and absent reports display `Not reported`; they are never inferred as zero or healthy. Alerts show retained endpoint evidence with machine name, bait path or label, user, process/PID, activity, and client-observed timestamp.

The Sensors view presents no aggregate endpoint-count KPIs. Each row shows the reporting host, OS, a short monitoring status, reported monitoring state and bait-file count, version, last contact and access state. Missing older structured status is shown as yellow `Status unavailable`, never inferred as healthy. Raw client health text is available only under `Technical details`. Every Sensors column is sortable and has its own filter; filters combine and can be cleared together.

Alert classification is fail-visible and replays the stored decision through the server's authoritative trust governance using the stored policy revision, digest, assignment group, evaluation time, actor, and event context. Only an exact replayed `informational` decision is retained as lower-level whitelisted activity. An exact replayed non-informational decision counts as non-whitelisted. Stale, pending, mismatched, fabricated, missing, legacy, or invalid trust evidence stays visible as `Policy unknown / legacy` and is counted separately rather than being claimed non-whitelisted.

Event History uses the plain labels `File Opened`, `Copied/Read`, `File Changed`, `File Renamed`, `File Deleted`, `Permissions Changed`, and `Access Denied`. Linux `readlink` failures and other low-level records appear as `Technical details`; raw operations, source, attribution and policy evidence remain expandable and unchanged. `Read (confirmed)` is not shown because the current records do not contain a validated, unique callback-to-file-action match.

Event History is server-paged at 25, 50 (default), or 100 rows. It opens newest-first, uses sequence descending as the stable tie-breaker, shows total/position, and provides Previous/Next controls. Time, Host, Action, File, User, Process and PID are separate sortable columns. Filters and sorting are preserved while paging.

One Linux file action can currently produce several raw collector records. The persisted fields do not provide a safe logical-action correlation key: `EventId` identifies each raw path record, optional `EvidenceId` is not guaranteed, and endpoint/path/PID/time can also match unrelated or interleaved activity. The server therefore does not merge rows. A client-generated `ActionCorrelationId` and independently tested logical-event rules remain backlog work; raw-row counts stay truthful.

Web table inventory: the signed-in Sensors and Event History data tables use the sortable/filterable behavior described above. The following data tables are intentionally unchanged in this development revision and remain backlog work for the same controls: Canary token inventory and activation history (callback creation/download/revocation and incremental hit loading must be preserved); Accounts (security-sensitive edit/recovery selection state); Policy assignments (inline policy selectors); Operations (small diagnostic list); trust-policy previews (generated comparison tables); service-decoy hits (selection-scoped detail); and the separate `decoy-jobs.html` provisioning/repair workflow (job sequencing and review holds). This explicit exclusion avoids implying those tables already have the new behavior.

Structured protection persistence is additive. SQLite creates `endpoint_protection` only when the first compatible client report arrives. SQL Server operators must run the reviewed `endpoint-protection` migration while the management service is stopped and using the temporary migration identity. Rolling the application back leaves the table unused; do not delete it or its reports. No backfill is attempted because old health strings cannot prove deployed files or monitoring state.

## Saved executive reports

Reports creates immutable aggregate snapshots with text or formatted one-page PDF exports. Choose 7, 30, or 90 days in the console; the API accepts 1–90 days. Your saved reports lists the latest 100 owned snapshots, including after restart/sign-in. Storage is capped at 5,000 reports server-wide; capacity failure preserves existing reports. Retention administration is not yet implemented.

Authenticated console routes: GET `/api/v1/console/overview?days=7`, GET `/api/v1/console/reports`, POST `/api/v1/console/reports` with `{days:7}`, and POST `/api/v1/console/reports/{id}/export` with `{format:"txt"}` or `{format:"pdf"}`. Both POST routes require CSRF. Downloads require ownership or Administrator role; the history list always shows only the current user's reports. Creation and export generation are audited. Reports do not include endpoint credentials, file paths, usernames, or callback URLs. Server receive time defines activity windows; contact counts are point-in-time, not historical uptime.

PDF rendering uses PDFsharp and bundled Bitstream Vera fonts. The font license is distributed under `Fonts/bitstream-vera-license.txt`. This is an aggregate summary, not a general-purpose/tenant-scoped report builder or compliance attestation.

## Read-only agent connectivity diagnostic

Run `RansomFree.Agent.exe --diagnose --server https://management.example` to check the liveness/API contract without sending credentials or creating agent state. Exit 0 means a compatible liveness response over trusted TLS; exit 2 means the diagnostic reported a failure. No firewall or certificate-store changes are made. DNS, connection, TLS, timeout, redirect, HTTP, and incompatible-response outcomes are separate. Success is not proof of enrollment, database health, event delivery, or Wazuh receipt. The success contract is mock-tested; real untrusted-TLS refusal and packaged failure output are tested locally. Successful deployed TLS remains an acceptance requirement.

## Build

For repeatable local evidence on Windows, run `tools/verify_enterprise_build.ps1 -Dotnet <full-path-to-dotnet.exe>`. It produces uniquely named Windows/Linux server and Windows agent staging folders, runs the synthetic integration suite, and writes step logs plus a SHA-256 artifact inventory in `verification.json`. It never replaces the running tray, installs a service, or changes a development deployment. `-CheckOnly` checks inputs without creating output. Failed runs retain their evidence and stop before subsequent steps. This is an engineering check, not a signed installer or deployment action.

Use .NET 10 SDK:

```powershell
dotnet publish src/seQuester.Server/seQuester.Server.csproj -c Release -o dist-server
dotnet publish src/seQuester.Agent/seQuester.Agent.csproj -c Release -o dist-agent
```

Server deployment targets Windows and Linux. Agent targets Windows. Linux execution is not yet validated. Packages are pinned and restore lockfiles are checked in; use `dotnet restore --locked-mode` in controlled builds.

## Local test configuration

Set environment variables in the **test server process only**:

- `ASPNETCORE_ENVIRONMENT=Development`
- `ASPNETCORE_URLS=http://127.0.0.1:<unused-port>`
- `RF_ALLOW_LOOPBACK_HTTP=true` (lab only; non-loopback plaintext requests are rejected)
- `RF_DATA_DIR=<private isolated test directory>`
- `RF_ADMIN_KEY=<cryptographically random 32-byte hex value>`

No default secret exists. Do not commit environment files containing keys, log them, or place them in command-line arguments. The integration runner generates/disposes process-local test credentials automatically. Deployed client transport only permits HTTPS with normal certificate validation and does not follow redirects. Its successful TLS interaction with the development deployment remains an acceptance gate.

## Version 1 API

| Method/path | Authentication | Purpose |
| --- | --- | --- |
| GET `/health/live` | None; transport gate applies | Process liveness, not database or delivery health |
| POST `/api/v1/admin/enrollment-codes` | Development admin bearer key | Issue a random single-use code valid for 15 minutes |
| POST `/api/v1/enroll` | Enrollment code in body | Register endpoint and return one endpoint credential |
| POST `/api/v1/agent/heartbeat` | Endpoint bearer credential | Record version, health, last contact, and optional structured protection report |
| POST `/api/v1/agent/events` | Endpoint bearer credential | Transactional batch of 1–100 events |
| POST `/api/v1/agent/capabilities` | Endpoint bearer credential | `{ "attributionVersion": 1 }`; upgrade server before 0.9 Unix clients |
| GET `/api/v1/admin/endpoints` | Development admin key | Inventory, currently capped at 1,000 rows |
| GET `/api/v1/admin/events?after=0&limit=100` | Development admin key | Sequence-paged event history, maximum 500 rows/page |
| POST `/api/v1/admin/endpoints/{id}/revoke` | Development admin key | Revoke future endpoint requests |

Enrollment and endpoint secrets are stored only as SHA-256 hashes in the server database. The issued credential is returned once. If enrollment succeeds but the response or local credential save is lost, revoke the orphan endpoint and issue a new code; automatic enrollment recovery is not implemented. Endpoint ID is derived from authentication at ingestion, never trusted from an event body.

Identical event-ID retries are deduplicated per endpoint. Reusing an ID with different content returns 409 and rolls back the whole batch. Acknowledge only after database commit. Agent-observed timestamps are distinct from server receive time. Administrative code issuance, enrollment, and revocation have durable audit records; per-person audit attribution awaits the identity layer.

## Agent development runtime

The agent supports Windows service hosting, but **no installer or service has been installed or certified**. Test only with `--console --data <isolated-directory> --run-seconds 5`. No files are deployed automatically. It loads canary settings from that isolated directory. The installed-service data path is `%ProgramData%\RansomFree\Agent`, restricted to SYSTEM and administrators; the initial privileged-account design is subject to least-privilege review.

Enrollment uses `--enroll --server https://host:port`; supply the one-time code on standard input. Credentials are DPAPI-protected and stored in `connection.json`. Existing enrollment is never overwritten. No tray migration, service registration, ACL deployment, or live enrollment is performed by the tests. Do not run both legacy tray monitoring and service monitoring against the same files until the ownership migration is implemented.

## Known release gaps

LDAP, Entra ID/OIDC, full scoped RBAC/account lifecycle, CISO/reporting UI, PostgreSQL/multi-node persistence, retention/quotas, health probes, backup/restore, capacity-grade rate limiting, token receiver, server-side Wazuh delivery, report/PDF exports, policy distribution, service/tray IPC, installer/signing/update/recovery, and load/soak tests remain unfinished. The development bootstrap key bypasses human MFA by design and is valid only for the development environment. The global development rate limit is not a capacity design. Do not copy a live SQLite database file without its WAL; a tested backup procedure is still required.

The development build currently enforces structured protection constraints in application/storage code and in the SQL Server migration; equivalent SQLite `CHECK` constraints are backlog hardening. Report classification currently replays trust governance while scanning the selected activity window (up to 90 days); indexed/materialized classification and load evidence are backlog performance work. Neither item changes the fail-visible classification contract above.
