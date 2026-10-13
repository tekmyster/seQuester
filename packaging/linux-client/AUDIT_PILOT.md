# Historical 0.9.3 Linux x64 audit compatibility pilot

**Current replacement procedure:** [0.9.5 pilot and rollback](AUDIT_PERSISTENCE_0_9_5.md). The intervening 0.9.4 native gate failed before mutation because its auditctl status parser rejected the valid three-token loginuid feature. Do not deploy 0.9.4 unchanged or use its superseded activation guidance below.

**Superseded for 0.9.4:** use [AUDIT_PERSISTENCE_0_9_4.md](AUDIT_PERSISTENCE_0_9_4.md) for the existing 0.9.3 pilot upgrade and rollback. The older loader activation/reload procedure below is historical and must not be used for 0.9.4. The 0.9.3 attributed read and management delivery subsequently passed; Wazuh host wire arrival was observed, not decoder/index acceptance. Auditd restart lost all six canary rules; manual loader restart restored them. That failure is the reason for 0.9.4.

This is a complete endpoint/desktop/relay candidate, **not a production acceptance or fleet rollout approval**. Run only on the approved pilot through its rollout owner. No instructions here were executed on plex01 by the build task. Use the archive path and SHA256 in the build handoff; read this package's exact release from RELEASE_ID. Do not substitute a relay-only directory for this package.

Prior 0.9.1 failed before any canary read: empty args was rejected by auditd; shell-rule quoting was invalid in persistent files; ProtectHome blocked /home watches in auditd's loader; and inherited relay capabilities prevented the capability-free collector from reading /proc/PID/exe. Rollout restored healthy detection-only 0.9.0. The capability failure and setpriv correction are now reproduced/passed in an isolated Docker fixture, not yet full 0.9.2 pilot acceptance. Do not retry the old archive unchanged.

0.9.2 also failed before canary read: auditd 3.0.7 permits at most TWO plugin arguments and rejected the five-token setpriv line. Six rules loaded but were removed with scoped inverses during rollback; auditd MDWE/ProtectHome stayed enabled and healthy detection-only0.9.0 was restored. 0.9.3 packages a zero-argument validated launcher and matches collector root GID to relay; native live canary/delivery gates remain required.

## Components

| Component | Identity |
| --- | --- |
| Existing endpoint service | ransomfree-client.service; rfclient; app/RansomFree.LinuxAgent --run |
| New collector | sequester-audit-collector.service; root:root; app/RansomFree.LinuxAgent --audit-collect |
| Auditd child plugin | audit/launch-relay.sh with NO plugin args; exec setpriv, then Native AOT relay; same PID/auditd parent |
| Separate rule loader | sequester-audit-rules.service; root; /sbin/auditctl -R /etc/ransomfree-client/sequester-audit.rules |
| Optional existing desktop | desktop/RansomFree.UnixDesktop; ordinary approved desktop user |
| Plugin configuration | /etc/audit/plugins.d/sequester.conf |
| Collector unit | /etc/systemd/system/sequester-audit-collector.service |
| Private transport | /run/sequester-audit/ingest.sock; root-only runtime directory |
| Persistent evidence | /var/lib/sequester-audit; root:rfclient mode 2750 |
| Endpoint state/config | /var/lib/ransomfree-client; /etc/ransomfree-client |

Management 0.6.4 attribution-v1 is unchanged. Do not downgrade management or re-enroll this endpoint for the fix. Preserve the original server origin, endpoint identity, secrets, pending queue, cursor and active canary inventory.

## Preflight and stopped backup

1. Confirm Ubuntu 22.04 x64 pilot identity and existing release/units/drop-ins. Record `systemctl show auditd.service --property=MemoryDenyWriteExecute --value` (must remain yes), `auditctl -s`, `auditctl -l`, and existing auditd/Wazuh plugin configuration. Audit immutable mode or another unresolved integration conflict is a blocker, not permission to change the security policy.
2. Ensure automated containment is disabled for the selected lab canary. This validation deliberately emits a real read event; it is not a silent diagnostic. Do not select a user document or real secret.
3. Disable only the old sequester plugin in an approved maintenance window, then use the distribution-supported auditd activation procedure. Preserve all unrelated audit rules/plugins and Wazuh configuration. Do not restore the old JIT auditd invocation at any point. Never disable auditd MDWE.
4. Stop the endpoint through its protected maintenance wrapper. Stop the sequester collector if it was previously staged/running. Verify both stopped; the new AOT relay, if previously running, must also be stopped through the approved plugin lifecycle before switching binaries.
5. Create a new root-only stopped backup of endpoint state/config, audit inbox, current symlink target, units/drop-ins and sequester plugin configuration. Record original collector/plugin enablement. Protect credentials; do not print backup contents into logs. Retain old immutable release directories. Preserve evidence created after backup too; do not later overwrite queues with this snapshot merely to roll back executable code.

## Stage the full candidate

1. Verify the handoff archive SHA256 independently. Inspect/extract to a new root-controlled staging directory, then verify `sha256sum --check --strict SHA256SUMS`. Reject links/special objects. Checksums are not publisher signatures; this build is unsigned development-only.
2. **Do not run install.sh against an existing installation.** Follow the reviewed upgrade procedure: exact RELEASE_ID in a new /opt/ransomfree-client/releases/RELEASE_ID directory; full verified payload, root:root, directories0755/files0644; set app/RansomFree.LinuxAgent, desktop/RansomFree.UnixDesktop, audit-relay/RansomFree.AuditRelay **and audit/launch-relay.sh** executable0755. Verify hashes. Do not change state/credentials/canary permissions. Launcher refuses writable release ancestors, wrong selector or release version.
3. Run the staged relay with `--version`: it must report 0.9.1 Native AOT, dynamic code disabled. `--self-test-mdwe` is an optional additional startup regression only on kernels supporting PR_SET_MDWE (6.3+); Ubuntu 22.04 older kernels may not support that test syscall. Unsupported is not a pass and is not a reason to weaken systemd MDWE.

   Relay intentionally stays0.9.1/protocol1; endpoint --version must report0.9.3-linux-dev. Confirm distribution setpriv/coreutils/shell are root-owned and not group/world writable. Do not add CAP_SYS_PTRACE or restore relay capabilities. After selecting the release, run `sudo /opt/ransomfree-client/current/audit/launch-relay.sh --check`; it validates without starting the relay.
4. Switch `/opt/ransomfree-client/current` atomically using the reviewed upgrade procedure, preserving the previous target. No automatic rollback script is included. Install/review the new collector unit from `audit/sequester-audit-collector.service`. Preserve any pre-existing unit/drop-ins and resolve conflicts explicitly; do not blindly replace them.
5. Review/update only the plugin from packaged example: active=no, direction=out, `path = /opt/ransomfree-client/current/audit/launch-relay.sh`, type=always, format=string; **omit args entirely**. All full setpriv flags live in the validated launcher. Do not retain the five-token0.9.2 configuration, empty args, direct relay, --audit-dispatch, or --check in plugin config. Keep inbox root:rfclient2750 with identity/packets/cursor intact. Updated collector unit must have User=root and Group=root with empty capability sets; remove conflicting old Group=rfclient overrides only through reviewed maintenance. Setgid inbox inheritance preserves rfclient-readable packet groups.
6. Keep Audit.Enabled=true in the existing protected configuration; enable command-line collection only if separately approved. With collector stopped, any approved config change uses protected maintenance and preserves enrollment.

## Explicit activation and acceptance

1. `systemctl daemon-reload`; `systemctl enable --now sequester-audit-collector.service`. Check `journalctl -u sequester-audit-collector.service` for libauparse/config/socket failures. Before relay activation, disconnected status is expected. No JIT process should be launched by auditd.
2. New `--audit-rules-file` emits direct persistent auditctl syntax without shell quoting. Generate to new root-private staging, require command success/nonempty expected exact paths and architectures, and review before installing as root:root mode 0600 `/etc/ransomfree-client/sequester-audit.rules`. No -D, global watches or audit-lock directives are generated. Export refuses paths containing characters beyond ASCII letters/digits/slash/underscore/dash/dot; do not strip quotes to force richer names. `--audit-rules` remains a separate shell draft, never a persistent-file source by generic string conversion.

   Review/install packaged `audit/sequester-audit-rules.service` as root:root 0644. This matches the pilot-side root oneshot loader that successfully installed six exact rules outside auditd's ProtectHome namespace. Do not put the rules in /etc/audit/rules.d or duplicate existing live rules. Files and relevant mounts must exist before loading; add approved mount dependencies where needed. Enable the plugin and activate auditd using its distribution-supported procedure, then `systemctl daemon-reload` and `systemctl enable --now sequester-audit-rules.service`, then start the endpoint. Keep auditd MDWE/ProtectHome=yes. Verify auditctl -l contains exactly the intended sequester rules and all unrelated rules remain preserved. RemainAfterExit is not proof of ongoing rule presence; after auditd restart/reconfiguration review/reconcile before a manual reload. Reboot/restart persistence acceptance for the packaged integration remains pending; no automatic duplicate/partial-load reconciliation is implemented.
3. Start `ransomfree-client.service` explicitly. Confirm no re-enrollment, server-origin change, state reset or canary redeployment occurred. Check queue/inbox retention and logs.
4. `sudo /opt/ransomfree-client/current/app/RansomFree.LinuxAgent --audit-health` must pass with the same active collector and auditd-child relay identities and advancing heartbeat over six seconds. A stale status file or a manually launched/replayed collector is not sufficient.

   Require both collector and relay CapPrm/CapEff/CapBnd=0 and NoNewPrivs=1 using their exact active /proc/PID/status files. Inspect protected status TransportFailureCount/LastTransportFailure and collector journal if disconnected. Fixed-category diagnostics include stage/errno, never record payloads. PeerExecutableRead/EACCES suggests missing capability drop; do not relax identity checks. Require advancing InputBytes and valid frames before claiming the transport recovered.
5. `sudo bash /opt/ransomfree-client/current/audit/verify-live.sh /absolute/existing/active/lab-canary` must print PASS native collector attribution only. It requires its own controlled cat PID, the expected parent PID, UID/eUID=0, executable /usr/bin/cat, Full attribution, unchanged content SHA256, advancing input bytes/packet sequence/heartbeat, no observed restart/loss, and active MDWE-protected auditd. A metadata event or partial event alone fails.
6. Record the returned EventId and actor fields. Independently require that exact attributed event in management **and** Wazuh. Preserve event-time UID/eUID, PID/PPID, executable, original timestamp/evidence identity and attribution level. Do not count a contemporaneous inotify event as attribution delivery. Syslog configurations may require decoder review but do not change Wazuh as part of a client fix without separate scope.
7. Keep the fleet held until the rollout owner records these results plus service restart/recovery and any remaining limitations. One controlled root read proves that path only, not every user, operation, platform, callback or response action.

## Rollback without reviving the broken plugin

If startup, heartbeat, attribution, preservation or receiver validation fails, retain diagnostics and stop expanding the pilot. Disable only the new sequester plugin and activate that change with the approved auditd procedure; stop/disable the new collector as appropriate to its original state. Stop the endpoint through protected maintenance before restoring the recorded previous versioned current target and reviewed unit/config state.

Also stop/disable the separate rule-loader to prevent reapplication. Preserve its protected rules file and remove only exact installed sequester entries with their reviewed -d inverses, preserving unrelated audit rules. Stopping a oneshot does not remove rules; do not rely on restarting auditd to clear them. If distribution restart reapplies its baseline, compare the before/after auditctl -l inventory and resolve only scoped differences. Retire the new loader unit/file recoverably only after recording provenance and confirming the integration is disabled; do not delete unrelated or pre-existing units/config.

**Leave the old 0.9.0 auditd/JIT plugin inactive.** Returning to the known-working detection-only endpoint is a degraded rollback, not successful attribution. Set Audit.Enabled=false through protected maintenance if returning to detection-only operation; report that loss of coverage. Never restore an active JIT plugin or set auditd MemoryDenyWriteExecute=no to obtain a green status.

Preserve new inbox packets, identity, cursor, enrollment and pending management queue; do not overwrite them with old snapshots. Reconcile an actual state-format incompatibility separately while stopped; no migration rollback is implemented by this change. Preserve all unrelated Wazuh rules/plugins and auditd security settings. Recheck original endpoint identity, canary inventory, unchanged content and ordinary event delivery after recovery. Keep new release and protected diagnostics for investigation; no recursive deletion is needed.
