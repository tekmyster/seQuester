#!/usr/bin/env bash
set -euo pipefail
umask 077
[[ $EUID == 0 && $# == 0 ]] || { echo 'Usage: sudo bash audit/stage-audit.sh' >&2; exit 2; }
base=/opt/ransomfree-client/current
runuser -u rfclient -- "$base/app/RansomFree.LinuxAgent" --verify-maintenance
[[ -d /etc/audit/plugins.d && ! -L /etc/audit/plugins.d ]] || { echo 'Install/configure distribution auditd first; plugin directory unavailable.' >&2; exit 1; }
for ancestor in /var /var/lib /etc /etc/audit /etc/audit/plugins.d /etc/systemd /etc/systemd/system; do
    [[ -d $ancestor && ! -L $ancestor && $(stat -c %u "$ancestor") == 0 ]] || exit 1
    mode=$(stat -c %a "$ancestor")
    (( (8#$mode & 0022) == 0 )) || { echo 'Unsafe parent permissions; no changes made.' >&2; exit 1; }
done
inbox=/var/lib/sequester-audit
target=/etc/audit/plugins.d/sequester.conf
unit=/etc/systemd/system/sequester-audit-collector.service
rules_unit=/etc/systemd/system/sequester-audit-rules.service
[[ ! -e $target && ! -L $target ]] || { echo 'Existing plugin preserved. Review it manually.' >&2; exit 1; }
[[ ! -e $unit && ! -L $unit ]] || { echo 'Existing collector service preserved. Review it manually.' >&2; exit 1; }
[[ ! -e $rules_unit && ! -L $rules_unit ]] || { echo 'Existing rule-loader service preserved. Review it manually.' >&2; exit 1; }
[[ -f $base/audit-relay/RansomFree.AuditRelay ]] || { echo 'Native AOT relay missing; no audit integration staged.' >&2; exit 1; }
[[ -f /usr/bin/setpriv && -x /usr/bin/setpriv && ! -L /usr/bin/setpriv && $(stat -c %u /usr/bin/setpriv) == 0 ]] || { echo 'Distribution root-owned /usr/bin/setpriv required.' >&2; exit 1; }
setpriv_mode=$(stat -c %a /usr/bin/setpriv)
(( (8#$setpriv_mode & 0022) == 0 )) || { echo 'Unsafe setpriv permissions.' >&2; exit 1; }
[[ $(stat -c %a "$base/audit/launch-relay.sh") == 750 ]] || { echo 'auditd requires launcher permissions 0750; no changes made.' >&2; exit 1; }
"$base/audit/launch-relay.sh" --check
"$base/audit-relay/RansomFree.AuditRelay" --version
if [[ -e $inbox || -L $inbox ]]; then
    [[ -d $inbox && ! -L $inbox && $(stat -c %u "$inbox") == 0 && $(stat -c %G "$inbox") == rfclient && $(stat -c %a "$inbox") == 2750 ]] || { echo 'Existing inbox does not match root:rfclient 2750; preserved.' >&2; exit 1; }
else
    install -d -o root -g rfclient -m 2750 "$inbox"
fi
# noclobber avoids replacing an existing administrator plugin, including a link.
(set -o noclobber; : > "$target")
chmod 0640 "$target"
printf '%s\n' 'active = no' 'direction = out' "path = $base/audit/launch-relay.sh" 'type = always' 'format = string' > "$target"
install -o root -g root -m 0644 "$base/audit/sequester-audit-collector.service" "$unit"
install -o root -g root -m 0644 "$base/audit/sequester-audit-rules.service" "$rules_unit"
echo 'Inactive plugin staged. No audit rules, daemon, existing plugin, firewall or Wazuh settings changed.'
echo 'Collector service staged but not loaded/started. Review AUDIT.md for explicit activation and native --audit-health/--audit-verify acceptance.'
echo 'Separate rule-loader staged but disabled; no rule file generated/installed. Use --audit-rules-file and review AUDIT.md; never copy a shell draft to rules.d.'
