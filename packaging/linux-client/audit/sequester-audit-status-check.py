#!/usr/bin/python3
"""Read kernel audit status; revoke stale successful health claims on failure.
Never enables auditing, edits audit rules, or declares failed rule coverage repaired.
The existing reviewed rule reconciler is required to restore a successful claim.
"""
import datetime, json, os, pathlib, stat, subprocess, tempfile
ROOT = pathlib.Path("/var/lib/sequester-audit")

def parse_status(text):
    if len(text) > 65536: raise ValueError("status-too-large")
    fields = {}
    for line in text.splitlines():
        tokens = line.split()
        if not tokens: continue
        if len(tokens) < 2 or len(line) > 512 or tokens[0] in fields or not tokens[1].isdigit():
            raise ValueError("invalid-status")
        if tokens[0] == "loginuid_immutable":
            if len(tokens) != 3 or tokens[1] not in ("0", "1") or tokens[2] not in ("locked", "unlocked"): raise ValueError("invalid-feature")
        elif len(tokens) != 2: raise ValueError("invalid-scalar")
        fields[tokens[0]] = int(tokens[1])
    if len(fields) > 256 or fields.get("enabled") not in (0, 1, 2) or not 1 < fields.get("pid", 0) <= 2147483647:
        raise ValueError("kernel-identity-unavailable")
    return fields["enabled"], fields["pid"]

def protected(path, directory=False):
    info = path.lstat()
    if info.st_uid != 0 or info.st_mode & 0o022 or stat.S_ISLNK(info.st_mode) or (directory and not stat.S_ISDIR(info.st_mode)):
        raise ValueError("unprotected-path")
    return info

def atomic_json(path, value, gid):
    descriptor, name = tempfile.mkstemp(prefix="kernel-health-", suffix=".tmp", dir=ROOT)
    try:
        created = os.fstat(descriptor)
        if created.st_uid != 0 or created.st_gid != gid: raise PermissionError("evidence-group-inheritance-mismatch")
        os.fchmod(descriptor, 0o640)
        with os.fdopen(descriptor, "w") as stream:
            json.dump(value, stream); stream.flush(); os.fsync(stream.fileno())
        os.replace(name, path)
        directory = os.open(ROOT, os.O_RDONLY | os.O_DIRECTORY)
        try: os.fsync(directory)
        finally: os.close(directory)
    finally:
        if os.path.exists(name): os.unlink(name)

def failure_status(previous, reason, now):
    result = dict(previous)
    result.update(UpdatedUtc=now, Success=False, Phase="Failed", FailureCategory=reason, FailureStage="KernelAuditHealthMonitor")
    return result

def main():
    if os.getuid() != 0 or os.geteuid() != 0: raise PermissionError("root-required")
    protected(ROOT, True)
    rule_path = ROOT / "rules-status.json"; info = protected(rule_path)
    if info.st_size > 262144: raise ValueError("rule-status-too-large")
    previous = json.loads(rule_path.read_text())
    if not isinstance(previous, dict) or not isinstance(previous.get("Success"), bool): raise ValueError("rule-status-invalid")
    now = datetime.datetime.now(datetime.timezone.utc).isoformat()
    reason = None; enabled = None; pid = None; native_status = None
    try:
        tool = pathlib.Path("/usr/sbin/auditctl")
        if not tool.exists(): tool = pathlib.Path("/sbin/auditctl")
        protected(tool.resolve())
        result = subprocess.run([str(tool), "-s"], text=True, capture_output=True, timeout=10,
                                env={"LC_ALL":"C", "PATH":"/usr/sbin:/usr/bin:/sbin:/bin"})
        native_status = result.returncode
        if native_status != 0: raise OSError("audit-status-command-failed")
        enabled, pid = parse_status(result.stdout)
        boot = pathlib.Path("/proc/sys/kernel/random/boot_id").read_text().strip()
        process_stat = pathlib.Path("/proc/%d/stat" % pid).read_text()
        fields = process_stat[process_stat.rindex(")") + 2:].split()
        if fields[0] in ("Z", "X") or boot != previous.get("BootId") or pid != previous.get("AuditdPid") or fields[19] != previous.get("AuditdStartTicks"):
            reason = "KernelAuditIdentityChanged"
        elif enabled == 0: reason = "KernelAuditDisabled"
    except Exception as error:
        reason = "KernelAuditStatusUnavailable:" + type(error).__name__
    summary = dict(Version=1, CheckedUtc=now, Enabled=enabled, AuditdPid=pid, NativeStatus=native_status, Failure=reason)
    if reason is not None:
        # Conservatively remove success only. Never reset a failure based on status alone.
        atomic_json(rule_path, failure_status(previous, reason, now), info.st_gid)
    atomic_json(ROOT / "kernel-health.json", summary, info.st_gid)
    print(json.dumps(summary))
    return 1 if reason else 0

if __name__ == "__main__":
    raise SystemExit(main())
