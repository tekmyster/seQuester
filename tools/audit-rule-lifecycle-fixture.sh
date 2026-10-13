#!/usr/bin/env bash
set -euo pipefail
[[ $# == 1 && $EUID != 0 && -n ${XDG_RUNTIME_DIR:-} ]] || { echo 'Run as the approved non-root user with an existing user systemd manager.' >&2; exit 2; }
context=$(cd -- "$1" && pwd -P)
[[ $context != *[[:space:]]* && -f $context/fixture/AuditRuleFixture && -f $context/sequester-audit-rules.service ]] || exit 2
systemctl --user is-system-running | grep -Fx running
source_unit=$context/sequester-audit-rules.service
for line in 'BindsTo=auditd.service' 'PartOf=auditd.service' 'WantedBy=auditd.service' 'After=auditd.service local-fs.target remote-fs.target' 'RemainAfterExit=yes' 'Type=oneshot'; do grep -Fx "$line" "$source_unit" >/dev/null; done
work=$(mktemp -d /tmp/sequester-rules-fixture-XXXXXXXX)
prefix=${work##*/}
audit=$prefix-audit.service
loader=$prefix-loader.service
cleanup() {
    systemctl --user stop "$loader" "$audit" >/dev/null 2>&1 || true
    systemctl --user disable --runtime "$loader" "$audit" >/dev/null 2>&1 || true
    systemctl --user reset-failed "$loader" "$audit" >/dev/null 2>&1 || true
    systemctl --user daemon-reload
    echo "Fixture evidence retained: $work; own units stopped and runtime links disabled. No auditd or kernel audit changes."
}
trap cleanup EXIT
chmod 0755 "$context/fixture/AuditRuleFixture"
cat > "$work/$audit" <<EOF
[Unit]
Description=seQuester disposable user fixture dummy audit process
[Service]
Type=simple
Environment=SEQUESTER_RULE_LIFECYCLE_FIXTURE=1
ExecStartPre=$context/fixture/AuditRuleFixture --lifecycle-clear $work
ExecStart=/usr/bin/sleep infinity
EOF
# Copy actual lifecycle relationships, replacing only fixture unit names.
# Root/security/mount constraints are intentionally not emulated by a user manager.
{
    echo '[Unit]'
    sed -n -E '/^(After|BindsTo|PartOf|Before)=/p' "$source_unit" | sed "s/auditd.service/$audit/g;s/ransomfree-client.service/$prefix-endpoint.service/g;s/ local-fs.target remote-fs.target//g"
    echo '[Service]'
    sed -n -E '/^(Type|RemainAfterExit|TimeoutStartSec)=/p' "$source_unit"
    echo 'Environment=SEQUESTER_RULE_LIFECYCLE_FIXTURE=1'
    echo "ExecStart=$context/fixture/AuditRuleFixture --lifecycle-reconcile $work"
    echo '[Install]'
    sed -n '/^WantedBy=/p' "$source_unit" | sed "s/auditd.service/$audit/g"
} > "$work/$loader"
systemctl --user link --runtime "$work/$audit" "$work/$loader"
systemctl --user enable --runtime "$loader"
systemctl --user daemon-reload
verify() {
    local count=$1 added=$2
    for n in {1..50}; do [[ -f $work/runs.log ]] && [[ $(wc -l < "$work/runs.log") == "$count" ]] && systemctl --user is-active --quiet "$loader" && break; sleep 0.1; done
    systemctl --user is-active --quiet "$audit" "$loader"
    [[ $(wc -l < "$work/runs.log") == "$count" ]]
    [[ $(tail -n 1 "$work/runs.log") == "expected=2 added=$added unrelated=1" ]]
    [[ $(wc -l < "$work/mock-inventory.txt") == 3 ]]
    [[ $(sort "$work/mock-inventory.txt" | uniq | wc -l) == 3 ]]
    grep -Fx -- '-w /fixture/unrelated -p wa -k fixture_baseline' "$work/mock-inventory.txt" >/dev/null
    sleep 1
    [[ $(wc -l < "$work/runs.log") == "$count" ]]
    echo "PASS: one reconciliation per requested lifecycle transaction; count=$count; added=$added; two unique owned mock rules; unrelated baseline retained."
}
systemctl --user start "$audit"; verify 1 2
systemctl --user restart "$audit"; verify 2 2
systemctl --user restart "$audit"; verify 3 2
systemctl --user restart "$loader"; verify 4 0
systemctl --user stop "$audit"
[[ $(systemctl --user show "$loader" --property=ActiveState --value) == inactive ]]
systemctl --user start "$audit"; verify 5 2
systemctl --user show "$audit" "$loader" --property=Id --property=ActiveState --property=SubState --property=InvocationID --property=PartOf --property=BindsTo --property=Wants
cat "$work/runs.log"
echo 'PASS: user systemd actual dependency lifecycle plus production planner over mock inventory. NOT actual auditd, auditctl, service sandbox/capabilities, boot, mount ordering or pilot acceptance.'
