#!/usr/bin/env bash
set -euo pipefail
umask 077
[[ $EUID == 0 && $# == 0 ]] || { echo 'Usage: sudo bash setup.sh' >&2; exit 2; }
! systemctl is-active --quiet ransomfree-client.service || { echo 'Stop through maintenance.sh before provisioning.' >&2; exit 2; }
binary=/opt/ransomfree-client/current/app/RansomFree.LinuxAgent
runuser -u rfclient -- "$binary" --set-password
runuser -u rfclient -- "$binary" --enroll
echo 'Enrolled. Start only after reviewing policy, folder access, and certificate trust.'
echo 'sudo systemctl enable --now ransomfree-client.service'
