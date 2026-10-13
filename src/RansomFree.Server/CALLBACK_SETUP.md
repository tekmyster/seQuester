# Native callback feature build

Unsigned, Development-only, untested. Do not expose this build publicly. The receiver is a separate process and contains no management routes. These are configuration instructions for the later deployment phase, not evidence of a running service.

## Storage and process separation

The management server initializes `registry/tokens.db` and `inbox/hits.db` beneath an absolute `RF_CALLBACK_DATA` directory when `Callbacks:Enabled=true`. The receiver requires this pre-provisioned layout and opens the registry read-only. Give the receiver OS read/traverse permission on `registry` and its file, but **no write, delete, rename, or parent-directory replacement permission**. Give it write permission only on `inbox` for hits and WAL/SHM sidecars. Separate directories prevent inbox write permission from also allowing replacement of the token registry. It must have no access to management.db, identity.db, data-protection keys, agent credentials, or management configuration. The server needs read/write access to both callback databases. This initial shared-local-storage topology is not multi-host HA; do not place SQLite on a network share.

Management configuration (environment variables replace `:` with `__`):

- `Callbacks:Enabled=true`
- `Callbacks:Origin=https://callbacks.example.invalid` — separate HTTPS origin and valid certificate
- `RF_CALLBACK_DATA` — absolute private callback storage directory
- Optional `Callbacks:DnsZone=tokens.example.invalid` — delegated authoritative DNS zone
- Optional `Callbacks:Syslog:Enabled=true`, `Host`, `Port`, `Transport` (`UDP`, `TCP`, `TLS`), `Format` (`RFC3164`, `RFC5424`), `OctetCounting`, `Facility`, `Severity`

The receiver uses `RF_CALLBACK_DATA`, HTTPS Kestrel configuration, and optional `Dns:Enabled=true`, `Dns:Zone`, `Dns:BindAddress`, `Dns:Port` (default loopback 5353). Actual delegation requires both UDP and TCP on port 53 through reviewed network configuration. Nothing automatically opens ports or modifies DNS. Do not trust forwarded headers until a later trusted-proxy configuration exists; HTTPS records the direct peer and DNS commonly records a resolver.

## Token lifecycle

Administrators create tokens in Canary tokens, download artifacts, select matching tokens in group deployment plans, and revoke tokens. Rotation is create a replacement token, publish a new deployment ID, then revoke the old token. Existing files are preserved and are not silently rewritten. Tokens are 192-bit random opaque trigger IDs, not administrator credentials. Creation and audit use separate databases; cross-database atomicity is not claimed.

Word uses a linked external image, Excel an external worksheet background image, and PDF a page-open URI action. With a configured DNS zone, PDF uses a unique token hostname; the DNS receiver returns NXDOMAIN after recording it, rather than navigating to a live destination. Without a DNS zone PDF uses the HTTPS endpoint. Reader policy can suppress or prompt for access. None of these mechanisms reliably signals a plain byte copy. Generation never contacts the URL and uses no macros or JavaScript. SVG uses an external image; Web image and Web bug downloads contain the HTTPS trigger URL, not an ordinary local bitmap that can phone home.

Receiver activity coalesces the same token/source/transport for 60 seconds. The inbox cap is 100,000 records; reaching capacity returns failure rather than deleting evidence. Registry cap is 10,000 tokens. Management inventory shows the latest 1,000; hits page forward by sequence. Archive/retention administration and distributed storage remain backlog items.

Syslog forwarding is opt-in and runs on the management server. It reads the durable inbox and advances a private checkpoint after sending, with stable event IDs for duplicate handling. A crash between sending and checkpoint persistence can duplicate a send. UDP cannot establish delivery, and a TCP/TLS send does not prove Wazuh persistence. Callback metadata never grants permission to stop a process and does not claim a username or PID.

## Managed endpoint folders

Create `deployment-folders.json` in the agent's protected data directory during reviewed endpoint provisioning. Example shape: `{ "Finance": "C:\\ApprovedDecoys\\Finance" }`. The folder must already exist. Only local administrators/SYSTEM may edit the approvals file. Approvals must identify controlled local data folders, not user-controlled junction paths. Root, Windows, program-installation, UNC, reparse-point and agent-state paths are rejected. An administrator publishes filenames/types using these aliases, never arbitrary target paths. Existing files are never overwritten; partial successes remain owned and monitored; missing or modified files are preserved for investigation, not recreated.

## Source references

Current source adds QR PNG generation, fast/two-second redirects, JS/CSS clone artifacts and Streamable HTTP MCP configuration, bringing the implemented catalog to 13 mechanisms. All remain untested. Clone artifacts require an approved HTTPS origin; missing CSS referrers can produce false positives. MCP configuration points to a receiver that supports initialization, ping and an empty tool list; it executes no tools and does not log request bodies. Redirects require an explicitly configured HTTPS destination. None of these artifacts should be previewed or activated during the build-only phase.

The Canary tokens screen shows the management sender's status and last sent sequence. This is transport progress, not proof of Wazuh ingestion. Repeated sends after a crash remain possible.

- [Official Word mechanism](https://docs.canarytokens.org/guide/ms-word-token.html)
- [Official Excel mechanism](https://docs.canarytokens.org/guide/ms-excel-token.html)
- [Official PDF mechanism and source limitations](https://docs.canarytokens.org/guide/adobe-pdf-token.html)
- [Open XML worksheet picture](https://learn.microsoft.com/en-us/dotnet/api/documentformat.openxml.spreadsheet.picture?view=openxml-3.0.1)

The source catalog remains a target, not parity certification. See CANARYTOKENS_ALIGNMENT.md and the management catalog for individual implementation states. All activation and rendering checks are pending in QA.md.
