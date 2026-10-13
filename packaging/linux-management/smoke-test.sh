#!/usr/bin/env bash
# Explicit operator-run check of an ALREADY started isolated deployment.
# This script does not start a service, modify data, or contact a non-loopback host.
set -euo pipefail
[[ $# == 2 && $1 == --ca-file && -f $2 ]] || { echo 'Usage: bash smoke-test.sh --ca-file /path/to/trusted-test-ca.pem' >&2; exit 1; }
command -v curl >/dev/null
command -v systemctl >/dev/null
[[ $(systemctl show ransomfree-management.service --property=ActiveState --value) == active ]]
[[ $(systemctl show ransomfree-management.service --property=User --value) == rfmgmt ]]
# Certificate must cover localhost. Never use -k or turn off TLS verification.
curl --fail --silent --show-error --max-time 10 --noproxy '*' --cacert "$2" --resolve localhost:7443:127.0.0.1 https://localhost:7443/health/live
printf '\n%s\n' 'PASS: HTTPS loopback liveness responded and systemd reports the restricted service account.' 'Not tested: login, MFA, database writes, reporting, callback receiver, remote clients, LDAP/SSO, syslog/email, restart, upgrade or recovery.'
