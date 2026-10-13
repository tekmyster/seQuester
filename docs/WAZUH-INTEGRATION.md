# Wazuh integration — October 9, 2026

## October 12 update

October 13: the actual management-host sender still fails after TLS negotiation. Tests under the administrator and the production NetworkService account both failed; temporary source/firewall grants were rolled back and fresh privileged sessions verified. The collector remains restricted to manager-local sources, and the production exporter is disabled. Receiver diagnostics now identify transport stage/cipher; all 19 receiver component tests pass on Linux. Session-ticket disabling was tested and rejected as a solution; defaults were restored. See the current response-policy integration checkpoint for exact failed receipts and pending gates.

The historical inspection below is superseded for seQuester-owned collector resources. The manager now runs a pinned TLS receiver on 10.81.100.10:6514, an isolated full-evidence Filebeat input/index and a bounded Wazuh JSON rule feed. Authorized sender scope is manager-local only. Actual controlled detection created one alert; a whitelisted event created none; both were indexed with the original sensor host and PID. Receiver receipts prove durable journal admission, independently of alerting/indexing.

Export waits for fresh state from the current Wazuh logcollector before appending. Earlier startup records were retained but did not alert because the collector opened after append; the readiness repair was tested with actual service-user access and a subsequent controlled detection. Interruption/restart replay under load remains a separate gate. Scoped index permissions were verified through fresh authenticated administrative and producer connections; existing Wazuh feeds and TCP 514 configuration remain intact.

Production seQuester sender routing, operational-log coverage and authenticated response execution remain unfinished. See RESPONSE-POLICY-INTEGRATION-20261012.md for exact receipts and boundaries.

## Verified live configuration

Read-only manager inspection found 34 active enrolled clients, including the
domain controller, Blue Iris NVR, storage server, and Windows desktop. The
manager VM is wazuhman01.tekmyster.com (10.81.100.10).

- Agent connection: TCP 1514.
- Direct Wazuh syslog receiver: TCP 514, bound to 10.81.100.10.
- Its configured allowed source is currently 10.87.5.1/32, the existing firewall
  source. This does not authorize a direct seQuester server connection.
- `logall` and `logall_json` are both disabled. Alert output is enabled.
- No seQuester-specific localfile entries or custom decoder/rule files were
  found in the inspected manager configuration.
- Agent connectivity does not prove that seQuester service logs are collected.
- Other UDP 514 listeners exist; their presence does not establish Wazuh
  ingestion or application-level acknowledgement.

Receipts: WAZUH-INTEGRATION-LIVE-20261009-R1.json and R2.json in
diagnostics/windows-token-20260930.

## Routing

Use the seQuester server as the single syslog exporter of endpoint events,
forensic enrichment and transfer results, callback hits and service-decoy hits.
Keep original sensor, host, event ID, PID and process-instance evidence inside
the structured JSON payload. A syslog header identifying the forwarding server
must not be mistaken for the host on which an operation occurred.

Use existing Wazuh agents to collect seQuester operational service logs on
Windows and Linux. Audit transport payloads and retained executable binaries
are evidence, not ordinary operational logs; do not forward the entire OS audit
stream or executable contents as syslog. Send artifact IDs, hashes and
collection/transfer outcomes in the event, retaining binary evidence in the
existing evidence store.

Avoid enabling both sensor and server event exporters for the same sources
unless downstream deduplication by sensor/event ID is deliberate.

## Informational export implemented in source

The server Notifications screen now has **Include whitelisted events as logs
(no alert)**. This maps to `IncludeLogOnlyEvents` in protected server syslog
settings. Existing settings default to false, preserving prior behavior.

When enabled, server-validated log-only events and their linked forensic
completions are exported at informational priority. Their JSON payload contains
`NotificationSuppressed: true`. This flag is the server's notification
disposition, not a verdict that an executable is safe. Original actor evidence
and whitelist enforcement remain unchanged. Wazuh rules must respect this flag
before notifications or responses are enabled.

Local qualification passed:

- Locked .NET build: no warnings or errors.
- Existing EventHistoryFixture: 472 successful checks, including actual HTTP
  ingest, protected settings persistence and actual TCP receipt of whitelisted
  original/enrichment records, evidence equality, default suppression behavior,
  and continued alert forwarding.
- Chromium UI fixture: 10 checks against the actual notifications module,
  synthetic APIs only. Both toggle directions, payload separation, reload and
  session cleanup passed. This is not production UI acceptance.

Build/test artifacts are under
`C:\Users\dmessana\AppData\Local\Codex\sequester-wazuh-20261009-r1`.
The first build failed because the server has its own Alert type. The field was
moved to that existing type; the subsequent build and runtime fixtures passed.
D: had less than 1 GiB free, so build output used the existing C: fallback.

## Outstanding deployment and acceptance

This source change has not been deployed. Before changing the live server,
build from the qualified .42 source snapshot with only the reviewed syslog/UI
changes, retaining existing data, keys and unrelated source behavior.

1. Add the actual exporter source IP to the receiver's explicit allowed sources
   and scoped firewall policy, preserving existing sources.
2. Configure Wazuh decoding and rules; test full nested evidence, original host
   mapping, explicit unavailable fields, detection events and log-only events.
3. Configure retention for non-alert records. Enabling global `logall_json`
   archives all existing Wazuh inputs, not only seQuester; measure capacity and
   set retention/indexing before enabling it. A Sequester-only durable receiver
   journal is another option if global archive volume is unsuitable.
4. Inventory actual sensor/server operational log destinations and configure
   existing agents to collect them without duplicate collection.
5. Verify actual manager persistence/search with controlled Windows and Linux
   events; TCP send completion alone is not evidence of manager persistence.
6. Test interrupted delivery, queue replay, destination changes, payload size
   and suppression. Current exporter advances after a successful socket send;
   syslog does not provide application-level persistence receipts.

## Response integration

Wazuh supports custom Active Response on Windows and Linux. A later integration
can request seQuester actions through authenticated, policy-checked interfaces.
It must map the original sensor to its Wazuh agent, reject suppressed events,
validate event age, make responses idempotent, and revalidate PID + start time +
actor executable identity before process termination. Server-forwarded syslog
must not cause an action on the forwarding server merely because it is the
message sender. No new automatic response was enabled by this work.

## Collection work remains open

Linux relay acknowledged retention/replay and peer-scoped loss accounting are
still the next collection repair. Windows APC-level thread impersonation and
pre-IRP denied operations remain separate unqualified boundaries. This syslog
change does not close those issues or the full product acceptance matrix.

References:

- https://documentation.wazuh.com/current/user-manual/capabilities/log-data-collection/journald.html
- https://documentation.wazuh.com/current/user-manual/manager/event-logging.html
- https://documentation.wazuh.com/current/user-manual/capabilities/active-response/custom-active-response-scripts.html
