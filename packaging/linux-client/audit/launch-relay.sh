#!/bin/sh
# Native OS bootstrap only: auditd 3.0.7 permits at most two plugin args.
# Keep the full setpriv invocation here; exec preserves auditd parentage/stdin.
set -eu
PATH=/usr/sbin:/usr/bin:/sbin:/bin
export PATH
unset ENV BASH_ENV CDPATH LD_PRELOAD LD_LIBRARY_PATH
umask 077
fail() { printf '%s\n' 'seQuester relay launcher refused unsafe identity, path, permissions or arguments.' >&2; exit 1; }
[ "$(/usr/bin/id -u)" = 0 ] || fail
check_only=no
if [ "$#" -ne 0 ]; then
    [ "$#" = 1 ] && [ "$1" = --check ] || fail
    check_only=yes
fi
safe_path() {
    node=$1
    while :; do
        [ ! -L "$node" ] || fail
        [ "$(/usr/bin/stat -c %u -- "$node")" = 0 ] || fail
        mode=$(/usr/bin/stat -c %a -- "$node")
        case "$mode" in ''|*[!0-7]*) fail;; esac
        [ "$((0$mode & 0022))" = 0 ] || fail
        [ "$node" != / ] || break
        node=${node%/*}
        [ -n "$node" ] || node=/
        [ -d "$node" ] || fail
    done
}
safe_executable() {
    [ -f "$1" ] && [ -x "$1" ] || fail
    safe_path "$1"
    mode=$(/usr/bin/stat -c %a -- "$1")
    [ "$((0$mode & 06000))" = 0 ] || fail
}
# The only allowed link is the root-maintained current selector. All resolved
# release and executable ancestors must be real root-owned non-writable nodes.
safe_path /opt/ransomfree-client
selector=/opt/ransomfree-client/current
[ -L "$selector" ] && [ "$(/usr/bin/stat -c %u -- "$selector")" = 0 ] || fail
launcher=$(/usr/bin/readlink -f -- "$0")
release=${launcher%/audit/launch-relay.sh}
case "$release" in /opt/ransomfree-client/releases/*) ;; *) fail;; esac
release_id=${release##*/}
case "$release_id" in ''|*[!a-zA-Z0-9.-]*) fail;; esac
case "$release_id" in ransomfree-client-0.9.18-dev.*-linux-x64|ransomfree-client-0.9.18-dev.*-linux-arm64|ransomfree-client-0.9.40-dev.*-linux-x64|ransomfree-client-0.9.40-dev.*-linux-arm64|ransomfree-client-0.9.41-dev.*-linux-x64|ransomfree-client-0.9.41-dev.*-linux-arm64|ransomfree-client-0.9.42-dev.*-linux-x64|ransomfree-client-0.9.42-dev.*-linux-arm64|ransomfree-client-0.9.43-dev.*-linux-x64|ransomfree-client-0.9.43-dev.*-linux-arm64) ;; *) fail;; esac
# Match the QA packager's timestamp/source identity exactly, not an open glob.
build_id=${release_id#*-dev.}
build_id=${build_id%-linux-*}
case "$build_id" in [0-9][0-9][0-9][0-9][0-9][0-9][0-9][0-9]T[0-9][0-9][0-9][0-9][0-9][0-9]Z-[0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f]) ;; *) fail;; esac
[ "$release" = "/opt/ransomfree-client/releases/$release_id" ] || fail
[ "$launcher" = "$release/audit/launch-relay.sh" ] || fail
[ "$(/usr/bin/readlink -f -- "$selector")" = "$release" ] || fail
safe_executable "$launcher"
[ "$(/usr/bin/stat -c %a -- "$launcher")" = 750 ] || fail
safe_executable /usr/bin/setpriv
safe_executable /usr/bin/stat
safe_executable /usr/bin/readlink
safe_executable /usr/bin/id
safe_executable "$(/usr/bin/readlink -f -- /bin/sh)"
safe_executable /usr/bin/uname
safe_executable /usr/bin/sha256sum
relay=$release/audit-relay/RansomFree.AuditRelay
safe_executable "$relay"
# Generated from verified native provenance by the packager, included in its
# manifest and SHA256SUMS. Never source metadata as executable shell code.
identity=$release/audit-relay/LAUNCHER_IDENTITY
[ -f "$identity" ] || fail
safe_path "$identity"
{
    IFS= read -r bound_release || fail
    IFS= read -r bound_runtime || fail
    IFS= read -r bound_hash || fail
    extra=
    if IFS= read -r extra || [ -n "$extra" ]; then fail; fi
} < "$identity"
[ "$bound_release" = "$release_id" ] || fail
case "$(/usr/bin/uname -m):$bound_runtime:$release_id" in
    x86_64:linux-x64:*-linux-x64|aarch64:linux-arm64:*-linux-arm64) ;;
    *) fail;;
esac
[ "${#bound_hash}" = 64 ] || fail
case "$bound_hash" in *[!0-9a-f]*) fail;; esac
actual_hash=$(/usr/bin/sha256sum -- "$relay") || fail
[ "${actual_hash%% *}" = "$bound_hash" ] || fail
if [ "$check_only" = yes ]; then
    printf '%s\n' 'PASS: root-owned launcher, selector, release, architecture, bound relay and OS helpers validated; no relay started.'
    exit 0
fi
exec /usr/bin/setpriv --bounding-set=-all --inh-caps=-all --ambient-caps=-all --no-new-privs "$relay"
