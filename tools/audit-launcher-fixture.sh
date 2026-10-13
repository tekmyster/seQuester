#!/usr/bin/env bash
set -euo pipefail
[[ ${SEQUESTER_LAUNCHER_FIXTURE:-} == 1 && -f /.dockerenv && $EUID == 0 ]] || exit 2
[[ ! -e /var/lib/sequester-audit && ! -e /run/sequester-audit && ! -e /etc/ransomfree-client ]] || exit 2
launcher=/opt/ransomfree-client/current/audit/launch-relay.sh
release=/opt/ransomfree-client/releases/ransomfree-client-0.9.10-dev.20260918T000000Z-55f982667923-linux-x64
[[ $(readlink -f /opt/ransomfree-client/current) == "$release" ]] || exit 2
# Auditd 3.0.7 format subset: zero plugin args, one value per key, short lines.
awk 'length($0)>=159 {exit 1} /^[[:space:]]*(#|$)/ {next} {if(NF!=3 || $2!="=" || $1=="args") exit 1}' /fixture/sequester.conf
grep -Fx 'path = /opt/ransomfree-client/current/audit/launch-relay.sh' /fixture/sequester.conf >/dev/null
"$launcher" --check
if "$launcher" --unexpected >/dev/null 2>&1; then exit 1; fi
chmod 0775 "$release/audit/launch-relay.sh"
if "$launcher" --check >/dev/null 2>&1; then exit 1; fi
chmod 0755 "$release/audit/launch-relay.sh"
chmod 0775 "$release/audit-relay/RansomFree.AuditRelay"
if "$launcher" --check >/dev/null 2>&1; then exit 1; fi
chmod 0755 "$release/audit-relay/RansomFree.AuditRelay"
chmod 0775 "$release"
if "$launcher" --check >/dev/null 2>&1; then exit 1; fi
chmod 0755 "$release"
if /usr/bin/setpriv --reuid=65534 --regid=65534 --clear-groups "$launcher" --check >/dev/null 2>&1; then exit 1; fi
echo 'PASS: plugin zero-argument syntax and launcher checks reject unexpected args, writable launcher/relay/ancestor and non-root caller.'
/bin/bash /fixture/mask.sh
install -d -m 0750 /var/lib/sequester-audit /etc/ransomfree-client
install -d -m 0700 /run/sequester-audit /run/sequester-fixture
printf '%s\n' '{"Audit":{"Enabled":true}}' > /etc/ransomfree-client/client.json
chmod 0600 /etc/ransomfree-client/client.json
/fixture/status-fixture/AuditStatusFixture
/fixture/health-fixture/AuditHealthFixture
/fixture/summary-fixture/EndpointHealthSummaryFixture
# Missing reviewed rules is an intentional pre-mutation native command failure.
# There is no auditctl invocation and no real canary in this container fixture.
set +e
/fixture/app/RansomFree.LinuxAgent --audit-reconcile-rules > /run/sequester-fixture/command.log 2>&1
command_result=$?
set -e
[[ $command_result == 1 ]]
grep -F 'stage=DesiredRules;' /run/sequester-fixture/command.log >/dev/null
if grep -E 'Unhandled exception|^   at |SECRET' /run/sequester-fixture/command.log; then exit 1; fi
jq -e '.Success == false and .Expected == 0 and .Added == 0 and .FailureStage == "DesiredRules"' /var/lib/sequester-audit/rules-status.json >/dev/null
echo 'PASS: actual agent reconciliation missing-file failure exits 1 normally, persists failed stage/counts, no runtime abort or stack trace.'
mkfifo -m 0600 /run/sequester-fixture/input
exec 3<>/run/sequester-fixture/input
collector= relay=
cleanup() {
    if [[ -n $relay ]]; then kill -TERM "$relay" 2>/dev/null || true; wait "$relay" 2>/dev/null || true; fi
    if [[ -n $collector ]]; then kill -TERM "$collector" 2>/dev/null || true; wait "$collector" 2>/dev/null || true; fi
}
trap cleanup EXIT
/usr/bin/setpriv --bounding-set=-all --inh-caps=-all --ambient-caps=-all --no-new-privs /fixture/app/RansomFree.LinuxAgent --audit-collect > /run/sequester-fixture/collector.log 2>&1 & collector=$!
for n in {1..50}; do [[ -S /run/sequester-audit/ingest.sock ]] && break; sleep 0.1; done
[[ -S /run/sequester-audit/ingest.sock ]] || { cat /run/sequester-fixture/collector.log; exit 1; }
/fixture/native-harness/AuditLauncherFixture <&3 & relay=$!
printf '%s\n' 'type=USER_ACCT msg=audit(1700000000.001:1): pid=1 uid=0 auid=0 ses=1 msg="fixture-only"' >&3
sleep 7
[[ $(readlink "/proc/$relay/exe") == "$release/audit-relay/RansomFree.AuditRelay" ]]
for pid in "$collector" "$relay"; do
    grep -E '^(Uid|Gid|CapPrm|CapEff|CapBnd|NoNewPrivs):' "/proc/$pid/status"
    awk '/^Cap(Prm|Eff|Bnd):/ {if($2!="0000000000000000")exit 1; n++} /^NoNewPrivs:/ {if($2!=1)exit 1; n++} END {if(n!=4)exit 1}' "/proc/$pid/status"
done
jq '{Running,TransportConnected,InputBytes,HeartbeatSequence,TransportFailureCount,LastTransportFailure}' /var/lib/sequester-audit/status.json
jq -e '.Running == true and .TransportConnected == true and .InputBytes > 0 and .TransportFailureCount == 0 and .LastRelayFrameUtc != null' /var/lib/sequester-audit/status.json >/dev/null
# No real auditd parent/successful rules receipt in this fixture: root health
# MUST remain degraded, while initial connection MUST NOT create parser loss.
jq -e '.CollectorHealth.Version == 1 and .CollectorHealth.CheckedUtc == .UpdatedUtc and .CollectorHealth.Failure != null and .DroppedInputRecords == 0 and .RejectedRecords == 0' /var/lib/sequester-audit/status.json >/dev/null
echo 'PASS: root health refuses missing real auditd/rules; initial connection does not manufacture parser loss.'
set +e
/fixture/app/RansomFree.LinuxAgent --audit-health > /run/sequester-fixture/health.log 2>&1
health_result=$?
set -e
[[ $health_result == 1 ]]
if grep -E 'Unhandled exception|^   at ' /run/sequester-fixture/health.log; then exit 1; fi
echo 'PASS: actual health command fails normally without abort for unhealthy fixture.'
# Exercise a genuine connection boundary; stop/restart only our own child.
kill -TERM "$relay"
wait "$relay" || true
relay=
/fixture/native-harness/AuditLauncherFixture <&3 & relay=$!
sleep 7
jq -e '.Running == true and .TransportConnected == true and .RejectedRecords > 0 and .DroppedInputRecords == 0' /var/lib/sequester-audit/status.json >/dev/null
echo 'PASS: actual relay reconnect preserves continuity warning and cumulative counter.'
echo 'PASS: exact zero-argument launcher -> setpriv -> unchanged final relay under inherited kernel MDWE and empty environment; same PID, cap-free identities, valid frames and no transport failures.'
echo 'Scope: disposable container bootstrap/transport only. No auditd, real canary, management, Wazuh, live host or full-attribution acceptance.'
