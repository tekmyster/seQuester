# seQuester 0.9.7 — Linux attribution health correction

## What changed

0.9.6 could display `Dispatcher executable identity unavailable` on every restricted endpoint even when the separate root collector supplied user/process evidence. The client tried to read a root process's `/proc/PID/exe`, which Linux permissions legitimately prevent. A historical continuity warning was also retained indefinitely in the current heartbeat. The first normal relay connection incremented a counter named `RejectedRecords` even with no prior parser input.

0.9.7 fixes those health-reporting defects. It does not replace Linux Audit with inotify or remove attribution. The file activity sensor and Linux Audit evidence remain separate streams: inotify cannot supply actors; Linux Audit supplies per-event actor evidence where available. An open operation establishes access intent, not proof that a file was copied or that all its bytes were read. Never equate enabled attribution with complete evidence for every possible filesystem operation.

## Least-privilege health contract

- The collector remains root:root, with no capabilities and NoNewPrivileges enabled. The endpoint remains rfclient. Auditd's per-host hardening is preserved.
- The collector validates its own executable/process identity and the Native AOT relay, fresh frames and relay ancestry. It binds the relay's parent PID/start ticks/boot to the protected successful rule-reconciler receipt, whose auditd identity came from kernel audit status. It does not require ptrace access to auditd's more-privileged executable.
- The protected root-owned status file includes a versioned CollectorHealth report, timestamped to the same heartbeat snapshot. The client validates root ownership/read-only trust boundary, report version, freshness, boot/instance/PID/start and advancing heartbeat. Missing, old, regressing, incompatible or failed reports remain degraded. Older collectors do not silently become healthy.
- Interactive root `--audit-health` retains the extra direct auditd executable check. Under rfclient the same command validates the protected report and heartbeat advancement. Failures return exit 1 normally, without an unhandled managed abort.
- This report is local root-authoritative evidence, not cryptographic remote attestation. Root compromise is outside this trust boundary. A successful rule receipt proves the last reconciliation, not continuous live-rule equality or complete kernel/auditd loss accounting.

## Current state versus historical evidence

Current heartbeat reports file monitoring and Linux Audit health. The first valid report waits for heartbeat advancement before reporting user/process attribution enabled. It never claims all events have complete attribution.

Continuity warnings are still sent through the durable management event queue. Local status exposes LastMonitorWarning and LastMonitorWarningUtc separately. Historical event records are not cleared or deleted during upgrade. `DroppedInputRecords`, `RejectedRecords`, `RetiredPackets` and `LastSequence` are persisted across collector instances and must not decrease within the same inbox epoch. `RejectedRecords` remains the cumulative legacy parser-rejection/reset counter, not a count of attacked files. An initial clean connection no longer increases it; genuine reconnects and loss boundaries still do. A zero input-drop counter alone does not prove zero kernel/auditd loss.

`TransportFailureCount`, `LastTransportFailure`, `InputBytes`, `LastInputUtc` and `HeartbeatSequence` are per-collector-instance/session diagnostics, not lifetime counters. They reset when a new collector instance starts; compare their deltas only within the same InstanceId. DispatcherPid/start ticks, relay PID/start ticks, connection/frame timestamps and UpdatedUtc are live identities/status and may change on restart. Preserve the pre-upgrade snapshot for historical diagnostics; do not require byte-identical live status after restarting either release. FirstSequence may advance as the bounded inbox retires packets, and the endpoint audit cursor may advance as events are queued successfully.

## Upgrade and acceptance

Use the existing versioned upgrade/rollback procedure from the 0.9.6 guide, substituting the verified immutable 0.9.7 release and `0.9.7-linux-dev` version. Verify the release selector and launcher guard; unchanged Native AOT relay remains component 0.9.1. Coordinate collector/endpoint restart so they both use the same release. Preserve existing enrollment, event outbox, audit cursor, historical counters, canary inventory/hashes and reviewed rules. No reinstall, counter clearing, global rule deletion or permissions widening is required.

Record each host's actual auditd MemoryDenyWriteExecute and ProtectHome baseline. Do not force ProtectHome=yes: reviewed Debian hosts may use no while Ubuntu hosts may use yes. The collector's separate ProtectHome=true remains unchanged.

Acceptance requires representative Ubuntu/libaudit3 and Debian/libaudit4 pilots followed by the supported enrolled fleet:

1. Root and rfclient health commands succeed with advancing same-instance heartbeat; protected CollectorHealth.Version=1 and Failure=null under unchanged collector sandbox.
2. Current central heartbeat no longer repeats the legacy executable-denial, inotify-only-attribution or latched historical-gap strings. Real degraded reports remain visible; historical events remain accessible.
3. Fresh controlled root and nonroot canary reads produce distinct Linux Audit events in the management console with executable, PID/PPID and authoritative user IDs; resolved account names are checked where locally available. A detection-only inotify event is not sufficient evidence.
4. Existing canary hashes, enrollment, six approved explicit-all rules where configured and process-response-disabled state remain intact. The persisted counters/sequence named above must not decrease within the same epoch; sample per-instance diagnostics only within a stable InstanceId. Session metrics may reset on upgrade/rollback, so archive the prior snapshot. New activity and real reconnects may increase persisted values; do not zero them or require them to remain byte-identical.
5. Syslog relay checkpoint/wire delivery does not prove downstream Wazuh decoding/indexing. Broader operations/users/filesystems, native GUI, reboot and excluded-host/ARM64 acceptance remain separately scoped.

Local 25-case heartbeat/loss-counter verification and compilation passed. The first native candidate caught an additional zero-loss-announcement false gap and was withheld. The corrected r2 isolated native fixture passed25health/loss,23planner,17status cases plus launcher/MDWE/capability, initial-zero, genuine-reconnect and normal-error-exit checks. It intentionally has no real auditd parent/successful receipt and correctly reports degraded health. Live healthy-report, root/nonroot attribution, current-console and fleet gates remain pending at publication. See audit-relay/HEALTH-FIXTURE-EVIDENCE.json and current root QA.md for scope and later results.
