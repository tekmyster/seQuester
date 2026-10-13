import importlib.util, pathlib
source = pathlib.Path(__file__).resolve().parents[1] / "packaging/linux-client/audit/sequester-audit-status-check.py"
spec=importlib.util.spec_from_file_location("audit_health",source); module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
checks=0
def check(value):
    global checks
    assert value;checks+=1
for enabled in (0,1,2): check(module.parse_status("enabled %d\npid 20\nloginuid_immutable 0 unlocked\n" % enabled)==(enabled,20))
for text in ("enabled 3\npid 20", "enabled 1\npid 0", "enabled 1\npid 20\npid 21", "enabled 1", "enabled 1\npid 20 extra", "enabled 1\npid 20\nloginuid_immutable 0 fake", "x"*65537):
    try:module.parse_status(text)
    except ValueError:checks+=1
    else:raise AssertionError(text[:80])
original={"Success":True,"RunId":"original","Expected":6,"Added":0,"BootId":"boot","AuditdPid":20,"AuditdStartTicks":"123","DesiredSha256":"digest"}
for reason in ("KernelAuditDisabled","KernelAuditIdentityChanged","KernelAuditStatusUnavailable:OSError"):
    result=module.failure_status(original,reason,"now")
    check(result["Success"] is False and result["FailureCategory"]==reason and result["FailureStage"]=="KernelAuditHealthMonitor")
    check(all(result[key]==value for key,value in original.items() if key!="Success"))
check(original["Success"] is True)
print("PASS: %d kernel audit status checks; parser, disabled/unknown identity, metadata preservation. No live audit configuration changed." % checks)
