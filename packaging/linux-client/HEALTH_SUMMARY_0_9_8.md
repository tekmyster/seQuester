# seQuester 0.9.8 — concise endpoint health

The normal healthy management row now reads:

> Canary monitoring active | User/process attribution active

This is a presentation change, not a new attribution sensor or a claim of complete evidence for every event. It applies only after the existing protected audit heartbeat verifier has confirmed an advancing, healthy collector/relay report, and file monitoring is running. Per-event provider, user/process evidence and completeness remain authoritative in event details.

Waiting, disabled and degraded audit statuses remain visible rather than being mapped to an active state. Existing queue, policy, continuity and monitoring warnings are preserved. A completed/stopped monitor reader adds `Canary monitoring stopped` rather than presenting monitoring as active. No canaries configured remains distinct from active protection.

Technical provider text remains available through the protected local status (`Monitor` field/CLI status) and existing event sources. The health verifier, collector and relay protocol, privilege separation, durable queues/cursors, loss counters and audited operations are unchanged. The server API and macOS heartbeat presentation are unchanged. This package does not add an ARM64 audit relay.

## Compatibility and deployment

Unsigned development build; native fixture results and exact source/binary hashes are in the packaged `audit-relay/HEALTH-FIXTURE-EVIDENCE.json`. Fixture acceptance is not live pilot, GUI or complete operation coverage. Deployment ownership remains with the rollout task. Do not install a candidate or infer fleet acceptance from this guide.

Use the reviewed stopped-service versioned upgrade procedure with the verified 0.9.8 release. Both the endpoint and collector must select the same immutable release; the Native AOT relay remains component0.9.1/protocol1. Installer and zero-argument launcher guards now require0.9.8. Preserve enrollment, configuration, canaries, event/syslog queues, rules, audit epoch/cursor/cumulative counters and protected histories. Do not reset counters, reinstall identities or relax permissions for a wording change.

The 0.9.7 counter-scope erratum remains applicable: collector instance transport/heartbeat counters may reset on restart; persisted inbox epoch drops/rejections/retirement/sequence must not decrease. Preserve the prior snapshot. Retain the0.9.7 release for reviewed rollback; no database or configuration migration is introduced.

Pilot acceptance must verify exact installed version/DLL, healthy summary, fresh root/nonroot attribution events, protected diagnostic detail, services/rules/queues and existing warning visibility. No healthy status should conceal a real failure. Record actual native and management-row results separately in QA.md and rollout evidence.
