# API guide

This guide maps the current API to application workflows. It is a developer reference; request and response models in the source remain authoritative. It does not introduce a new API contract.

## Authentication

| Caller | Authentication |
| --- | --- |
| Browser user | Session cookie after local/MFA or configured SSO sign-in; role authorization applies. |
| Browser mutation | Session plus `X-CSRF` token and, where required, administrator password/MFA proof. |
| Sensor | Enrollment-issued bearer credential scoped to its sensor identity. |
| Development bootstrap | Independently generated `RF_ADMIN_KEY`; separate from human sessions and sensor credentials. |
| External canary use | Token/protocol-specific receiver handling, not management administration. |

Use HTTPS outside the explicit loopback development exception. Never embed bootstrap or sensor credentials in links, screenshots or client-side scripts.

## Core routes

| Method and route | Purpose |
| --- | --- |
| `GET /health/live` | Process liveness and reported API/server version. |
| `GET /api/v1/auth/csrf` | Obtain the anti-forgery token for the browser session. |
| `POST /api/v1/auth/login` | Local sign-in and optional second-factor proof. |
| `GET /api/v1/auth/me` | Current identity, role and recovery requirements. |
| `POST /api/v1/auth/logout` | End the local session. |
| `POST /api/v1/console/enrollment-codes` | Authorized enrollment-code creation. |
| `POST /api/v1/enroll` | Exchange a valid code for sensor ID and credential. |
| `POST /api/v1/agent/heartbeat` | Report version, OS and available protection state. |
| `POST /api/v1/agent/capabilities` | Negotiate supported event/evidence protocol versions. |
| `POST /api/v1/agent/events` | Submit an event batch and receive capability-aware acceptance counts. |
| `GET /api/v1/console/endpoints` | Sensor inventory. |
| `GET /api/v1/console/events` | Sequence-based event retrieval. |
| `GET /api/v1/console/event-history` | Filtered, sorted and cursor-paged event history. |
| `GET /api/v1/console/evidence/{sequence}` | Evidence details for a stored event. |
| `GET /api/v1/console/event-capabilities` | History/filter capability information. |

Bootstrap `/api/v1/admin/*` routes are separate administrative entry points. Do not substitute them for human-session routes to bypass normal verification.

## Event contracts

`AgentEvent` retains its compatibility fields: event ID, observed UTC time, operation, target path, nullable user/process/PID and source. Additive members carry service context, attribution, trust and forensic evidence.

`StoredEvent` adds the server sequence, sensor identity and received UTC time. `BatchReceipt` reports accepted/duplicate counts and versioned capability acknowledgements.

Send a stable identifier when retrying the same observation. Reusing an event ID with different content produces a conflict; do not generate new IDs to conceal an unsuccessful delivery or overwrite evidence.

The forensic envelope's `Version` is 1. Native and trust evidence have their own explicit versions. Preserve null/unavailable states and collection reasons. Optional additive JSON fields are not a reason to fabricate values for older events.

## History filters

`EventHistoryQuery` defines sort, direction, limit and cursor, plus sensor/host/OS/IP, time range, notification/action, user/process, PID/UID/parent PID, provider/source/operation and target-path filters.

Use the server's supported sort and filter definitions rather than assuming every field is sortable or available for every source. Cursor handling belongs to the query that produced it. Keep observation time distinct from server receipt time.

Source: `src/RansomFree.Server/EventHistory.cs`.

## Policy and workflow routes

| Workflow | Entry points | Source |
| --- | --- | --- |
| Group policy | `/api/v1/console/groups`, `/api/v1/console/policy-status`, `/api/v1/agent/policy`, `/api/v1/agent/policy/receipt` | `Policies.cs` |
| Trust policy | `/api/v1/console/trust-policy`, `/api/v1/agent/trust-policy`, `/api/v1/agent/trust-policy/receipt` | `TrustGovernance.cs` |
| Canary management | `/api/v1/console/callbacks/catalog`, `/tokens`, `/hits`, `/delivery` under the callbacks group | `CallbackManagement.cs` |
| Incident workflow | `/api/v1/console/incidents` and its summary, assignment, linked-event and export routes | `Incidents.cs`, `IncidentAssignment.cs`, `IncidentExports.cs` |
| Saved reports | `/api/v1/console/reports`, report export and schedule routes | `Reports.cs`, `ReportSchedules.cs` |
| Response preview | `POST /api/v1/console/responses/preview` | `ActiveResponsePreview.cs` |
| Response commands | `/api/v1/console/responses`, `/api/v1/agent/responses`, `/api/v1/agent/responses/receipt` | `ResponseCommands.cs` |
| Response readiness | `POST /api/v1/agent/response-capabilities` | `ResponseCapabilities.cs`, `ResponseCommands.cs` |
| Decoy jobs | `/api/v1/console/decoy-jobs`, agent delivery/receipt/observation routes | `DecoyJobs.cs` |
| Operational status | `GET /api/v1/console/operations` | `OperationsHealth.cs` |

These entries identify route families, not identical methods or permissions for every child route. Follow the source's body records, authorization, optimistic revision checks and administrator-verification requirements.

## Actor evidence upload

| Method and route | Stage |
| --- | --- |
| `POST /api/v1/agent/evidence/start` | Register the source-linked upload. |
| `POST /api/v1/agent/evidence/{id}/status` | Query receiver progress. |
| `PUT /api/v1/agent/evidence/{id}/chunks/{offset}` | Send an offset-addressed chunk. |
| `POST /api/v1/agent/evidence/{id}/finish` | Finalize and verify the artifact. |

Authenticated evidence retrieval is implemented in `EvidenceTransferApi.cs`, including administrative actor-evidence routes. Inspect its download authorization and returned artifact kind before implementing a client. Local preservation success is not upload success.

## Error handling

| Status | Typical meaning |
| --- | --- |
| 400 | Invalid body, query, anti-forgery proof or unsupported setting. |
| 401 | Missing, invalid or expired authentication. |
| 403 | Insufficient role or action permission. |
| 404 | Missing resource or unavailable route. |
| 409 | Conflicting event content or workflow/version conflict. |
| 429 | Rate limit; retry according to the workflow without duplicating the action. |
| 500 / 503 | Server or dependency failure; retain request correlation and check persisted outcome. |

Exact outcomes are route-specific. Diagnostic codes and request IDs should be retained in logs or explicit diagnostics, not shown as raw payloads in ordinary UI.

## Integration rules

- Preserve original sensor, source event, process-instance and evidence IDs in SIEM mappings.
- Keep observation, enrichment, detection and response records distinguishable.
- Treat an acknowledged event batch, verified binary upload, collector storage receipt and indexed SIEM record as separate checks.
- Retain events lacking attribution. Missing evidence is a state to investigate, not grounds to silently discard the observation.
- Do not infer response authority from an alert's severity or whitelist name.

See [Architecture and evidence](ARCHITECTURE-AND-EVIDENCE.md) for the data model and [Development](DEVELOPMENT.md) for verification fixtures.
