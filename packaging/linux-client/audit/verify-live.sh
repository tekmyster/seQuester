#!/usr/bin/env bash
set -euo pipefail
[[ $EUID == 0 && $# == 1 && $1 == /* ]] || { echo 'Usage: sudo bash audit/verify-live.sh /absolute/existing/active/lab-canary' >&2; exit 2; }
# Explicit read of ONE operator-selected active canary. No installation, rule
# changes, service activation, firewall changes or arbitrary process response.
systemctl is-active --quiet auditd.service
systemctl is-active --quiet sequester-audit-collector.service
[[ $(systemctl show auditd.service --property=MemoryDenyWriteExecute --value) == yes ]] || { echo 'This regression check requires auditd MDWE=yes; never weaken auditd to pass.' >&2; exit 1; }
echo 'Preflight: use an approved lab canary with automated responses disabled. The read emits a real event.'
/opt/ransomfree-client/current/app/RansomFree.LinuxAgent --audit-verify "$1"
echo 'Native collector check only. Independently match printed EventId/PID/UID/executable at management and Wazuh.'
