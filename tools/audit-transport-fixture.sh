#!/usr/bin/env bash
# Run ONLY in the disposable container built from audit-transport-fixture.Dockerfile.
# No host mounts, host PID/network namespace, auditctl or auditd activation.
set -euo pipefail
[[ ${SEQUESTER_TRANSPORT_FIXTURE:-} == 1 && -f /.dockerenv && $EUID == 0 ]] || exit 2
[[ ! -e /var/lib/sequester-audit && ! -e /run/sequester-audit && ! -e /etc/ransomfree-client ]] || exit 2
install -d -m 0750 /var/lib/sequester-audit /etc/ransomfree-client
install -d -m 0700 /run/sequester-audit /run/sequester-fixture
printf '%s\n' '{"Audit":{"Enabled":true}}' > /etc/ransomfree-client/client.json
chmod 0600 /etc/ransomfree-client/client.json
mkfifo -m 0600 /run/sequester-fixture/input
exec 3<>/run/sequester-fixture/input
collector= relay=
cleanup() {
    if [[ -n $relay ]]; then kill -TERM "$relay" 2>/dev/null || true; wait "$relay" 2>/dev/null || true; fi
    if [[ -n $collector ]]; then kill -TERM "$collector" 2>/dev/null || true; wait "$collector" 2>/dev/null || true; fi
}
trap cleanup EXIT
for mode in baseline constrained; do
    /usr/bin/setpriv --bounding-set=-all --inh-caps=-all --ambient-caps=-all --no-new-privs /fixture/app/RansomFree.LinuxAgent --audit-collect > "/run/sequester-fixture/$mode-collector.log" 2>&1 & collector=$!
    for n in {1..50}; do [[ -S /run/sequester-audit/ingest.sock ]] && break; sleep 0.1; done
    [[ -S /run/sequester-audit/ingest.sock ]] || { cat "/run/sequester-fixture/$mode-collector.log"; exit 1; }
    if [[ $mode == baseline ]]; then
        /out/RansomFree.AuditRelay <&3 & relay=$!
    else
        /usr/bin/setpriv --bounding-set=-all --inh-caps=-all --ambient-caps=-all --no-new-privs /out/RansomFree.AuditRelay <&3 & relay=$!
    fi
    printf '%s\n' 'type=USER_ACCT msg=audit(1700000000.001:1): pid=1 uid=0 auid=0 ses=1 msg="fixture-only"' >&3
    sleep 7
    printf 'MODE=%s COLLECTOR=%s RELAY=%s\n' "$mode" "$collector" "$relay"
    grep -E '^(Uid|Gid|CapPrm|CapEff|CapBnd|NoNewPrivs):' "/proc/$collector/status" "/proc/$relay/status"
    jq '{Running,TransportConnected,InputBytes,HeartbeatSequence,TransportFailureCount,LastTransportFailure}' /var/lib/sequester-audit/status.json
    if [[ $mode == baseline ]]; then
        jq -e '.TransportConnected == false and .InputBytes == 0 and .TransportFailureCount > 0 and .LastTransportFailure.Stage == "PeerExecutableRead" and .LastTransportFailure.NativeError == 13' /var/lib/sequester-audit/status.json >/dev/null
        echo 'PASS reproduction: inherited-capability relay rejected by cap-free collector at executable read with EACCES.'
    else
        jq -e '.Running == true and .TransportConnected == true and .InputBytes > 0 and .TransportFailureCount == 0 and .LastRelayFrameUtc != null' /var/lib/sequester-audit/status.json >/dev/null
        echo 'PASS correction: cap-free relay authenticated by unchanged root/executable/path checks; framed bytes and heartbeat received.'
    fi
    cleanup; collector= relay=
done
echo 'Fixture scope: private transport/capability compatibility only. No auditd, real canary, management, Wazuh, production deployment or native full-attribution assertion.'
