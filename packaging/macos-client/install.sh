#!/bin/bash
set -euo pipefail
umask 077
[[ $EUID == 0 && $# == 1 && $(uname -s) == Darwin ]] || { echo 'Usage on macOS: sudo bash install.sh /absolute/root-owned/client.json' >&2; exit 2; }
base=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)
root='/Library/Application Support/RansomFree'
unit=/Library/LaunchDaemons/com.ransomfree.endpoint.plist
for tool in plutil dscl dseditgroup install shasum; do command -v "$tool" >/dev/null; done
[[ ! -e $root && ! -L $root && ! -e $unit && ! -e '/Applications/Ransom Free Endpoint.app' ]] || { echo 'Existing installation/state preserved; use reviewed maintenance/upgrade.' >&2; exit 2; }
! dscl . -read /Users/_ransomfree >/dev/null 2>&1 || { echo 'Reserved user exists; manual review required.' >&2; exit 2; }
! dscl . -read /Groups/_ransomfree >/dev/null 2>&1 || exit 2
! dscl . -read /Groups/_ransomfree-ui >/dev/null 2>&1 || exit 2
(cd -- "$base" && shasum -a 256 --check SHA256SUMS)
[[ -z $(find "$base" ! -type f ! -type d -print -quit) ]] || { echo 'Package links/special objects are not accepted.' >&2; exit 2; }
# BEGIN desktop identity preflight: read-only, before any package/host mutation.
contents="$base/Native/Ransom Free Endpoint.app/Contents"
[[ -s "$contents/MacOS/RansomFree.UnixDesktop" ]] || { echo 'Managed desktop app missing or empty.' >&2; exit 2; }
[[ -s "$contents/Info.plist" ]] || { echo 'Managed desktop Info.plist missing or empty.' >&2; exit 2; }
icon="$contents/Resources/sequester.icns"
[[ -s "$icon" ]] || { echo 'Required seQuester macOS icon missing or empty.' >&2; exit 2; }
icon_hash=$(shasum -a 256 -- "$icon")
[[ ${icon_hash%% *} == c79d10fc312cbe22989cecabc126f8560e7c6c6ebb0dc4f8935b6958b80eb2b6 ]] || { echo 'Required seQuester macOS icon identity mismatch.' >&2; exit 2; }
for pair in 'CFBundleIdentifier=com.ransomfree.endpoint-menu' 'CFBundleName=seQuester Endpoint' 'CFBundleExecutable=RansomFree.UnixDesktop' 'CFBundleIconFile=sequester.icns' 'CFBundleShortVersionString=0.9.2' 'CFBundleVersion=0.9.2'; do
    value=$(/usr/libexec/PlistBuddy -c "Print :${pair%%=*}" "$contents/Info.plist") || { echo 'Managed desktop plist key missing or invalid.' >&2; exit 2; }
    [[ $value == "${pair#*=}" ]] || { echo "Managed desktop plist identity mismatch: ${pair%%=*}." >&2; exit 2; }
done
# END desktop identity preflight
chmod 0755 "$base/app/RansomFree.MacAgent"
runtime=$("$base/app/RansomFree.MacAgent" --package-runtime "$base/manifest.json")
case "$(uname -m):$runtime" in x86_64:osx-x64|arm64:osx-arm64) ;; *) echo 'Package architecture mismatch.' >&2; exit 2;; esac
release=$(<"$base/RELEASE_ID")
[[ $release =~ ^ransomfree-client-0\.9\.0-dev\.[a-zA-Z0-9.-]+-osx-(x64|arm64)$ ]] || exit 2
stage=$(mktemp -d /private/var/tmp/ransomfree-client-install.XXXXXXXX)
"$base/app/RansomFree.MacAgent" --stage-config "$1" "$stage"
account=$(/usr/libexec/PlistBuddy -c 'Print :UserName' "$stage/com.ransomfree.endpoint.plist")
if [[ $account == root ]]; then
    echo 'The .NET Endpoint Security adapter is pending Apple SDK binding validation. Use baseline fsevents; attributed open/process response is unavailable in this package.' >&2; exit 2
fi
[[ -f "$base/Native/Ransom Free Endpoint.app/Contents/MacOS/RansomFree.UnixDesktop" ]] || { echo 'Managed desktop app missing.' >&2; exit 2; }
# Find an unused local service UID; do not repurpose a pre-existing identity.
uid=499
while dscl . -list /Users UniqueID | awk '{print $NF}' | grep -qx "$uid"; do uid=$((uid-1)); [[ $uid -ge 400 ]] || exit 2; done
dseditgroup -o create _ransomfree
dseditgroup -o create _ransomfree-ui
gid=$(dscl . -read /Groups/_ransomfree PrimaryGroupID | awk '{print $2}')
dscl . -create /Users/_ransomfree
dscl . -create /Users/_ransomfree UniqueID "$uid"
dscl . -create /Users/_ransomfree PrimaryGroupID "$gid"
dscl . -create /Users/_ransomfree UserShell /usr/bin/false
dscl . -create /Users/_ransomfree NFSHomeDirectory "$root/Data"
dscl . -create /Users/_ransomfree IsHidden 1
dscl . -create /Users/_ransomfree Password '*'
dseditgroup -o edit -a _ransomfree -t user _ransomfree-ui
install -d -o root -g wheel -m 0755 "$root" "$root/Releases"
destination="$root/Releases/$release"
install -d -o root -g wheel -m 0755 "$destination"
cp -R "$base/." "$destination/"
chown -R root:wheel "$destination"
find "$destination" -type d -exec chmod 0755 {} +
find "$destination" -type f -exec chmod 0644 {} +
chmod 0755 "$destination/app/RansomFree.MacAgent"
ln -s "Releases/$release" "$root/Current"
install -d -o root -g _ransomfree -m 0750 "$root/Config"
install -o root -g _ransomfree -m 0640 "$stage/client.json" "$root/Config/client.json"
install -d -o "$account" -g _ransomfree-ui -m 0700 "$root/Data" "$root/Data/tmp" "$root/Logs"
install -d -o "$account" -g _ransomfree-ui -m 0750 "$root/Status"
install -o root -g wheel -m 0644 "$stage/com.ransomfree.endpoint.plist" "$unit"
cp -R "$destination/Native/Ransom Free Endpoint.app" /Applications/
chown -R root:wheel '/Applications/Ransom Free Endpoint.app'
chmod 0755 '/Applications/Ransom Free Endpoint.app/Contents/MacOS/RansomFree.UnixDesktop'
echo "Installed but not loaded/enrolled. Staging retained at $stage. Review config, folder access, TCC and service identity."
echo 'Next: run setup.sh; explicitly bootstrap launchd only when canary deployment is intended.'
