#!/usr/bin/env bash
set -euo pipefail
[[ ${SEQUESTER_RULE_MASK_FIXTURE:-} == 1 && -f /.dockerenv && $EUID == 0 ]] || exit 2
version=$(dpkg-query -W -f='${Version}' libaudit1)
echo "Distribution libaudit1: $version"
case "$version" in *3.0.7*|*4.0.2*) ;; *) echo 'Unreviewed libaudit version' >&2; exit 2;; esac
/fixture/mask-fixture/AuditRuleMaskFixture explicit b64
/fixture/mask-fixture/AuditRuleMaskFixture explicit b32
legacy=$(/fixture/mask-fixture/AuditRuleMaskFixture implicit b64)
echo "$legacy"
if [[ $version == *4.0.2* ]]; then
    expected='open,bind,truncate,ftruncate,rename,mkdir,rmdir,creat,link,unlink,symlink,readlink,chmod,fchmod,chown,fchown,lchown,mknod,acct,swapon,quotactl,setxattr,lsetxattr,fsetxattr,getxattr,lgetxattr,fgetxattr,listxattr,llistxattr,flistxattr,removexattr,lremovexattr,fremovexattr,openat,mkdirat,mknodat,fchownat,unlinkat,renameat,linkat,symlinkat,readlinkat,fchmodat,fallocate,renameat2,openat2'
    IFS=, read -r -a calls <<< "$expected"
    [[ $legacy == "LEGACY: b64 count=${#calls[@]} syscalls=$expected" ]]
    echo 'PASS: exact preserved nginx01 4.0.2 expanded mask reproduced in memory from historical implicit command.'
else
    [[ $legacy == 'LEGACY: b64 count=0 syscalls=' ]]
    echo 'PASS: 3.0.7 implicit libaudit mask unset; auditctl subsequently applies its default-all fallback (source-reviewed, not executed here).'
fi
/fixture/mask-fixture/AuditRuleMaskFixture implicit b32
/fixture/fixture/AuditRuleFixture
/fixture/status-fixture/AuditStatusFixture
echo 'PASS: two native explicit-all masks, historical-mask differential, 23 planner cases and 17 annotated-status/exit cases. Pure native-library heap compilation only: no auditctl or kernel audit/netlink operations.'
