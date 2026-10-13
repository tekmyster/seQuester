#!/usr/bin/env bash
set -euo pipefail
umask 077
fail() { printf '%s\n' "$*" >&2; exit 1; }
[[ ${1:-} == --acknowledge-development-only && $# == 1 ]] || fail 'Usage: sudo bash install.sh --acknowledge-development-only'
[[ $EUID == 0 ]] || fail 'Run as root. The installed server runs as rfmgmt, never root.'
[[ $(uname -s) == Linux ]] || fail 'This archive requires Linux/glibc.'
case $(uname -m) in
    x86_64) host_runtime=linux-x64 ;;
    aarch64|arm64) host_runtime=linux-arm64 ;;
    *) fail 'Unsupported CPU architecture; requires x86_64 or ARM64.' ;;
esac
for cmd in sha256sum getconf getent groupadd useradd install systemctl realpath stat find cp ln; do command -v "$cmd" >/dev/null || fail "Missing prerequisite: $cmd"; done
[[ $(getconf GNU_LIBC_VERSION 2>/dev/null) == glibc\ * ]] || fail 'Requires glibc; musl/Alpine packages are not supplied.'
[[ -d /run/systemd/system && -x /usr/sbin/nologin ]] || fail 'Requires a booted systemd host and /usr/sbin/nologin.'
package=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)
[[ -f $package/RELEASE_ID && -f $package/RUNTIME_ID && -f $package/SHA256SUMS ]] || fail 'Incomplete extracted archive.'
IFS= read -r release < "$package/RELEASE_ID"
IFS= read -r runtime < "$package/RUNTIME_ID"
[[ $runtime == "$host_runtime" ]] || fail "Package $runtime does not match host $host_runtime; nothing was installed."
[[ $release =~ ^ransomfree-management-[A-Za-z0-9._-]+-linux-(x64|arm64)$ && $release == *-"$runtime" ]] || fail 'Invalid or mismatched release identifier.'
[[ -z $(find "$package" -type l -print -quit) ]] || fail 'Package must not contain symbolic links.'
[[ $(stat -c %u "$package") == 0 ]] || fail 'Extract the independently verified archive into a root-owned staging folder.'
[[ -z $(find "$package" \( ! -user root -o -perm /022 \) -print -quit) ]] || fail 'Staging tree must be root-owned and not group/other writable.'
(cd -- "$package" && sha256sum --strict --check SHA256SUMS) || fail 'Package integrity verification failed.'
prefix=/opt/ransomfree-management
target=$prefix/releases/$release
unit=/etc/systemd/system/ransomfree-management.service
for path in /opt "$prefix" "$prefix/releases" /etc/ransomfree-management /var/lib/ransomfree-management /var/log/ransomfree-management "$unit"; do
    cursor=$path
    while [[ $cursor != / ]]; do
        [[ ! -L $cursor ]] || fail "Refusing linked installation ancestor: $cursor"
        cursor=$(dirname -- "$cursor")
    done
done
[[ ! -e $prefix/current && ! -L $prefix/current && ! -e $target && ! -e $unit ]] || fail 'Existing installation found. Use the documented stopped-service upgrade procedure; nothing was overwritten.'
[[ $(systemctl show ransomfree-management.service --property=LoadState --value) == not-found ]] || fail 'An existing systemd unit must be reviewed before installation.'
! getent passwd rfmgmt >/dev/null || fail 'Pre-existing rfmgmt account requires manual identity review; not reused automatically.'
! getent group rfmgmt >/dev/null || fail 'Pre-existing rfmgmt group requires manual identity review; not reused automatically.'
[[ ! -e /etc/ransomfree-management/server.env ]] || fail 'Existing configuration was preserved; review manually.'
[[ ! -e /var/lib/ransomfree-management && ! -e /var/log/ransomfree-management ]] || fail 'Existing state/log directories preserved; review manually.'
# No packages, certificates, database schemas, firewall rules or services are started.
groupadd --system rfmgmt
useradd --system --gid rfmgmt --home-dir /var/lib/ransomfree-management --no-create-home --shell /usr/sbin/nologin rfmgmt
install -d -o root -g root -m 0755 "$prefix" "$prefix/releases"
install -d -o root -g root -m 0755 "$target"
cp -R -- "$package/." "$target/"
find "$target" -type d -exec chmod 0755 {} +
find "$target" -type f -exec chmod 0644 {} +
chmod 0755 "$target/app/RansomFree.Server"
install -d -o root -g rfmgmt -m 0750 /etc/ransomfree-management /etc/ransomfree-management/tls /etc/ransomfree-management/keys
install -o root -g root -m 0600 "$package/server.env.example" /etc/ransomfree-management/server.env
install -d -o rfmgmt -g rfmgmt -m 0700 /var/lib/ransomfree-management /var/lib/ransomfree-management/data /var/lib/ransomfree-management/callbacks /var/log/ransomfree-management
install -o root -g root -m 0644 "$package/ransomfree-management.service" "$unit"
ln -s -- "releases/$release" "$prefix/current"
systemctl daemon-reload
printf '%s\n' 'Installed only: service is stopped and disabled. Configure certificates/secrets/database and review README before manual start.' 'If a step failed, partial files/account are retained. Do not blindly rerun or delete data.'
