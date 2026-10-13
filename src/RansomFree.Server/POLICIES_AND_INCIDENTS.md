# Policies and incidents — unsigned development increment

Implemented, compilation checked, full QA deferred by the user. Do not expose this server publicly or treat this document as deployment acceptance.

## Groups and policies

The Policies screen lets an Administrator create named endpoint groups, assign active endpoints, and publish immutable policy revisions. Reader and Operator roles can view settings, history, and receipts. All writes require CSRF protection. Concurrent publication and assignment changes use expected prior values; stale edits receive HTTP 409 rather than overwriting another administrator's changes.

The first policy setting is `integrityIntervalSeconds`: 15–3,600 seconds, in 15-second increments. Unassigned agents use 15 seconds. Group creation starts at revision 0/default settings; publishing allocates a new revision. Publishing immediately makes the revision desired for that group's endpoints. No group deletion, draft approval, or rollout ring is implemented yet.

An enrolled agent polls policy approximately every 60 seconds alongside its existing communication loop, validates and atomically caches it, and sends a receipt. File-system watchers and Windows auditing remain active independently of scheduled integrity checks. The last valid cached setting remains effective offline. Invalid cache files are preserved; a subsequent valid replacement keeps a rejected-file backup. Cache ownership is tied to the endpoint enrollment ID. A receipt describes loaded configuration, not proof that file monitoring is healthy. No files are deployed, no allowlists or syslog destinations change, and no process is terminated by this policy.

Console routes:

- GET `/api/v1/console/groups`
- POST `/api/v1/console/groups` — `{name}`
- GET `/api/v1/console/groups/{id}/history` — latest 100 revisions
- POST `/api/v1/console/groups/{id}/policy` — `{expectedRevision,settings:{integrityIntervalSeconds}}`
- GET `/api/v1/console/policy-status` — up to 1,000 active endpoints
- POST `/api/v1/console/endpoints/{id}/group` — `{groupId,expectedGroupId}`; null means unassigned

Endpoint-credential routes: POST `/api/v1/agent/policy` retrieves only that endpoint's assignment; POST `/api/v1/agent/policy/receipt` accepts `{groupId,revision}` only when it matches the current desired policy and the endpoint remains active.

## Incident workspace

Operators and Administrators can create a case from an existing collected event, link additional events, assign Low/Medium/High/Critical severity, and move between Open/Investigating/Resolved. Each update requires an analyst note and expected revision. Notes preserve the selected status/severity with actor and time. Event records are linked rather than copied or altered. Readers can inspect cases, notes, and linked evidence but cannot mutate them.

The workspace lists the latest 100 matching cases; a case shows up to 1,000 linked event references and the latest 100 notes. Counts on the overview include all cases, regardless of the selected event activity period. A case is an analyst classification, not a confirmed malware diagnosis. Evidence details preserve the distinction between endpoint-observed and server-received times. Existing aggregate PDF/text reports remain separate and do not yet export incident data.

Routes under `/api/v1/console/incidents`:

- GET root, optional `?status=Open|Investigating|Resolved`
- GET `/summary` — all-case counts
- GET `/{id}` — case, linked event numbers, and recent notes
- POST root — `{title,severity,eventSequence}`
- POST `/{id}` — `{expectedVersion,status,severity,note}`
- POST `/{id}/events` — `{expectedVersion,eventSequence}`

Writes require CSRF. Mutation conflicts return HTTP 409. Event links, updates, group changes, and policy publication create management audit entries. Site/tenant scoping, assignment to named analysts, escalation/notifications, incident exports, case retention, and high-availability storage remain future work.
