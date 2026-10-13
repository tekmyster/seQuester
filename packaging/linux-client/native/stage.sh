#!/usr/bin/env bash
# Stage a first native installation. No service start/enable, ordinary sensor
# configuration change, module load, target read or existing-file replacement.
set -euo pipefail
umask 077
[[ $EUID -eq 0 && $# -eq 2 ]] || { echo 'Usage (root): stage.sh /opt/sequester-native/releases/RELEASE /root/private/request.json' >&2; exit 2; }
release=$1
request=$2
export LC_ALL=C
python3 - "$release" "$request" <<'PY'
import json,os,pathlib,stat,sys
release,request=map(pathlib.Path,sys.argv[1:])
def protected(path,private=False):
    if not path.is_absolute() or str(path)!=os.path.normpath(str(path)):raise SystemExit('Canonical absolute path required')
    for node in [path,*path.parents]:
        info=node.lstat()
        if stat.S_ISLNK(info.st_mode) or info.st_uid!=0 or info.st_mode&0o022:raise SystemExit('Unsafe root installation path')
    if private and path.stat().st_mode&0o077:raise SystemExit('Root-private installation input required')
protected(release,True);protected(request,True);protected(request.parent,True)
if release.parent!=pathlib.Path('/opt/sequester-native/releases'):raise SystemExit('Exact staged release parent required')
if not release.is_dir() or not request.is_file() or request.stat().st_nlink!=1 or request.stat().st_size>65536:raise SystemExit('Bounded root request and release directory required')
body=json.loads(request.read_bytes())
if body.get('PackageDirectory')!=str(release/'native'):raise SystemExit('Request must bind this release native directory')
for node in (release/'app').rglob('*'):
    protected(node)
    if not (node.is_dir() or node.is_file()) or node.is_file() and node.stat().st_nlink!=1:raise SystemExit('Unexpected managed package member')
protected(release/'app/RansomFree.LinuxAgent')
for name in ['SensorId','Server','PublicKeyBase64','ServiceUid','ServiceGroup','Members','TargetPaths']:
    if name not in body:raise SystemExit('Explicit installation request fields required')
for name in ['ServiceUid','ServiceGroup']:
    if type(body[name]) is not int or not 0<body[name]<4294967295:raise SystemExit('Exact nonroot service IDs required')
for path in ['/etc/sequester-native','/var/lib/sequester-native','/var/lib/sequester-native-export','/run/sequester-native']:
    p=pathlib.Path(path)
    if p.exists() or p.is_symlink():raise SystemExit('Existing native installation retained: '+path)
for path in ['/opt/sequester-native/current','/etc/systemd/system/sequester-native.service','/etc/systemd/system/ransomfree-client.service.d/20-native-drain.conf']:
    p=pathlib.Path(path)
    if p.exists() or p.is_symlink():raise SystemExit('Existing native service/link retained: '+path)
PY
service_uid=$(python3 -c 'import json,sys;print(json.load(open(sys.argv[1]))["ServiceUid"])' "$request")
service_gid=$(python3 -c 'import json,sys;print(json.load(open(sys.argv[1]))["ServiceGroup"])' "$request")
[[ $(id -u rfclient) == "$service_uid" ]] || { echo 'Request UID must match installed ordinary rfclient account' >&2; exit 3; }
if getent group sequester-native >/dev/null; then
    [[ $(getent group sequester-native | cut -d: -f3) == "$service_gid" ]] || { echo 'Dedicated native group differs from request' >&2; exit 3; }
else
    groupadd --system --gid "$service_gid" sequester-native
fi
python3 - "$service_gid" <<'PY'
import subprocess,sys
group=subprocess.check_output(['getent','group','sequester-native'],text=True).strip().split(':')
if len(group)!=4 or any(x and x!='rfclient' for x in group[3].split(',')):raise SystemExit('Native bridge group contains another account')
for row in subprocess.check_output(['getent','passwd'],text=True).splitlines():
    fields=row.split(':')
    if len(fields)==7 and fields[3]==sys.argv[1] and fields[0]!='rfclient':raise SystemExit('Another account uses native bridge group')
PY
install -d -m 0700 -o root -g root /etc/sequester-native /var/lib/sequester-native /var/lib/sequester-native/tmp
install -d -m 0750 -o root -g sequester-native /var/lib/sequester-native-export /run/sequester-native
"$release/app/RansomFree.LinuxAgent" --native-prepare "$request"
"$release/app/RansomFree.LinuxAgent" --native-validate
echo 'Native configuration staged and admitted. Services remain uninstalled and inactive; existing sensor configuration is unchanged.'
