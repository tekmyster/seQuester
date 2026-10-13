#!/usr/bin/env bash
set -euo pipefail
[[ ${1:-} == --preserve-all-data && $# == 1 && $EUID == 0 ]] || { echo 'Usage: sudo bash uninstall.sh --preserve-all-data' >&2; exit 1; }
unit=/etc/systemd/system/ransomfree-management.service
[[ -f $unit && ! -L $unit ]] || { echo 'Expected owned service unit not found; no change made.' >&2; exit 1; }
grep -Fxq 'ExecStart=/opt/ransomfree-management/current/app/RansomFree.Server' "$unit" || { echo 'Unexpected unit; manual review required.' >&2; exit 1; }
[[ $(systemctl show ransomfree-management.service --property=FragmentPath --value) == "$unit" ]] || { echo 'Unexpected loaded unit location.' >&2; exit 1; }
systemctl disable --now ransomfree-management.service
[[ $(systemctl show ransomfree-management.service --property=ActiveState --value) == inactive ]] || { echo 'Service is not confirmed inactive. Unit preserved.' >&2; exit 1; }
# Recoverable removal of exactly this unit, never a recursive deletion.
saved="$unit.removed.$(date -u +%Y%m%dT%H%M%SZ).$$"
[[ ! -e $saved ]] || exit 1
mv -- "$unit" "$saved"
systemctl daemon-reload
printf '%s\n' "Service disabled/stopped; unit retained at $saved." 'All release binaries, state, keys, configuration, logs, rfmgmt identity and database content were preserved. No remote enrollment or tokens were revoked.'
