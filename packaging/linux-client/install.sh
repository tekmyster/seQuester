#!/usr/bin/env bash
set -euo pipefail
umask 077
[[ $EUID == 0 && $# == 1 ]] || { echo 'Usage: sudo bash install.sh /absolute/root-owned/client.json' >&2; exit 2; }
base=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)
for tool in sha256sum systemctl getent groupadd useradd install runuser; do command -v "$tool" >/dev/null; done
[[ $(uname -s) == Linux && -d /run/systemd/system ]] || { echo 'Native Linux with systemd required.' >&2; exit 2; }
[[ ! -e /opt/ransomfree-client && ! -L /opt/ransomfree-client && ! -e /etc/ransomfree-client && ! -e /var/lib/ransomfree-client && ! -e /etc/systemd/system/ransomfree-client.service && ! -d /etc/systemd/system/ransomfree-client.service.d ]] || { echo 'Existing installation/state preserved. Use reviewed maintenance/upgrade procedure.' >&2; exit 2; }
for account in rfclient rfclient-ui; do ! getent passwd "$account" >/dev/null || { echo 'Reserved identity already exists; manual review required.' >&2; exit 2; }; ! getent group "$account" >/dev/null || { echo 'Reserved group already exists; manual review required.' >&2; exit 2; }; done
(cd -- "$base" && sha256sum --check --strict SHA256SUMS)
[[ -z $(find "$base" ! -type f ! -type d -print -quit) ]] || { echo 'Package links/special objects are not accepted.' >&2; exit 2; }
# BEGIN desktop identity preflight: read-only, before any package/host mutation.
[[ -s "$base/desktop/RansomFree.UnixDesktop" ]] || { echo 'Managed desktop payload missing or empty.' >&2; exit 2; }
icon="$base/desktop/Branding/sequester-256.png"
[[ -s "$icon" ]] || { echo 'Required seQuester Linux icon missing or empty.' >&2; exit 2; }
icon_hash=$(sha256sum -- "$icon")
[[ ${icon_hash%% *} == ef71b9131b454d20efef21dac8fc3cc1b81e7834240ec41dc5ab65af2076d139 ]] || { echo 'Required seQuester Linux icon identity mismatch.' >&2; exit 2; }
# END desktop identity preflight
chmod 0755 "$base/app/RansomFree.LinuxAgent"
runtime=$("$base/app/RansomFree.LinuxAgent" --package-runtime "$base/manifest.json")
case "$(uname -m):$runtime" in x86_64:linux-x64|aarch64:linux-arm64) ;; *) echo 'Package architecture mismatch.' >&2; exit 2;; esac
release=$(<"$base/RELEASE_ID")
[[ $release =~ ^ransomfree-client-0\.9\.10-dev\.[a-zA-Z0-9.-]+-linux-(x64|arm64)$ ]] || exit 2
stage=$(mktemp -d /var/tmp/ransomfree-client-install.XXXXXXXX)
"$base/app/RansomFree.LinuxAgent" --stage-config "$1" "$stage"
[[ -f $base/desktop/RansomFree.UnixDesktop ]] || { echo 'Managed desktop payload missing.' >&2; exit 2; }
[[ -f $base/audit-relay/RansomFree.AuditRelay ]] || { echo 'Native AOT audit relay missing.' >&2; exit 2; }
# Root-owned immutable binaries; separate private service and read-only desktop groups.
groupadd --system rfclient
groupadd --system rfclient-ui
useradd --system --gid rfclient --groups rfclient-ui --home-dir /var/lib/ransomfree-client --no-create-home --shell /usr/sbin/nologin rfclient
install -d -o root -g root -m 0755 /opt/ransomfree-client /opt/ransomfree-client/releases
destination="/opt/ransomfree-client/releases/$release"
install -d -o root -g root -m 0755 "$destination"
cp -R -- "$base/." "$destination/"
chown -R root:root -- "$destination"
find "$destination" -type d -exec chmod 0755 {} +
find "$destination" -type f -exec chmod 0644 {} +
chmod 0755 "$destination/app/RansomFree.LinuxAgent" "$destination/desktop/RansomFree.UnixDesktop" "$destination/audit-relay/RansomFree.AuditRelay"
# auditd 4.x rejects plugin executables unless their mode is exactly 0750.
chmod 0750 "$destination/audit/launch-relay.sh"
ln -s -- "releases/$release" /opt/ransomfree-client/current
install -d -o root -g rfclient -m 0750 /etc/ransomfree-client
install -o root -g rfclient -m 0640 "$stage/client.json" /etc/ransomfree-client/client.json
install -d -o root -g root -m 0755 /etc/systemd/system/ransomfree-client.service.d
install -o root -g root -m 0644 "$stage/10-local.conf" /etc/systemd/system/ransomfree-client.service.d/10-local.conf
install -o root -g root -m 0644 "$destination/ransomfree-client.service" /etc/systemd/system/ransomfree-client.service
install -d -o rfclient -g rfclient-ui -m 0700 /var/lib/ransomfree-client /var/lib/ransomfree-client/tmp
systemctl daemon-reload
echo "Installed stopped and disabled. Private staging retained at $stage for review."
echo 'Next: grant rfclient access ONLY to approved folders; run setup.sh; then explicitly enable/start the service.'
echo 'Fanotify configuration grants broad capabilities if selected. Review 10-local.conf before starting.'
