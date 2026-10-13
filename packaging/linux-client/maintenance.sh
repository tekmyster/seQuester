#!/usr/bin/env bash
set -euo pipefail
umask 077
[[ $EUID == 0 && $# -ge 1 ]] || { echo 'Usage: sudo bash maintenance.sh stop|disable|password|configure|uninstall [CONFIG_JSON]' >&2; exit 2; }
case "$1" in stop|disable|password|uninstall) [[ $# == 1 ]] || exit 2;; configure) [[ $# == 2 ]] || exit 2;; *) exit 2;; esac
base=/opt/ransomfree-client/current
runuser -u rfclient -- "$base/app/RansomFree.LinuxAgent" --verify-maintenance
if [[ $1 == configure ]]; then
    stage=$(mktemp -d /var/tmp/ransomfree-client-config.XXXXXXXX)
    "$base/app/RansomFree.LinuxAgent" --stage-config "$2" "$stage"
    # Changing server requires explicit credential migration, never reuses a bearer at a new origin.
    "$base/app/RansomFree.LinuxAgent" --same-server /etc/ransomfree-client/client.json "$stage/client.json"
fi
systemctl stop ransomfree-client.service
case "$1" in
  disable) systemctl disable ransomfree-client.service;;
  password) runuser -u rfclient -- "$base/app/RansomFree.LinuxAgent" --set-password;;
  configure)
    backup="/etc/ransomfree-client/previous-$(date -u +%Y%m%dT%H%M%SZ)-$$"
    install -d -o root -g root -m 0700 "$backup"
    cp -p /etc/ransomfree-client/client.json /etc/systemd/system/ransomfree-client.service.d/10-local.conf "$backup/"
    install -o root -g rfclient -m 0640 "$stage/client.json" /etc/ransomfree-client/client.json
    install -o root -g root -m 0644 "$stage/10-local.conf" /etc/systemd/system/ransomfree-client.service.d/10-local.conf
    systemctl daemon-reload;;
  uninstall)
    systemctl disable ransomfree-client.service
    retired="/etc/ransomfree-client/retired-$(date -u +%Y%m%dT%H%M%SZ)-$$"
    install -d -o root -g root -m 0700 "$retired"
    mv /etc/systemd/system/ransomfree-client.service /etc/systemd/system/ransomfree-client.service.d "$retired/"
    systemctl daemon-reload
    echo 'Service unregistered. Binaries, configuration, credentials, queues, identities and canary files preserved for explicit recovery/disposal.';;
esac
echo 'Service left stopped. No automatic restart or canary deletion.'
