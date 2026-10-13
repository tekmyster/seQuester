"""Independently verify private v1 record layout and user token truth pairs."""
import argparse
import hashlib
import json
import struct
from pathlib import Path

p = argparse.ArgumentParser()
p.add_argument("--directory", required=True)
p.add_argument("--output", required=True)
a = p.parse_args()
root = Path(a.directory)
output = Path(a.output)
if output.exists():
    raise SystemExit("Immutable raw evidence receipt already exists")
raw = (root / "native-records.bin").read_bytes()
wire = (root / "native.jsonl").read_bytes()
encoding = "utf-16" if wire.startswith((b"\xff\xfe", b"\xfe\xff")) else "utf-8-sig"
events = [json.loads(line) for line in wire.decode(encoding).splitlines() if line.strip()]
if len(events) != 10 or not events[-1].get("Complete") or events[-1].get("Passed") != 9:
    raise SystemExit("Native controlled execution not complete")
header = struct.Struct("<II5Q4QIIIiiiIIII")
token = struct.Struct("<I5i6I3Q68s4x")
assert header.size == 120 and token.size == 144
record_size = header.size + 2 * token.size
pair_size = record_size + 2 * token.size
if len(raw) != 9 * pair_size:
    raise SystemExit("Unexpected private v1 record count/size")

def sid(data, length):
    if length < 8 or data[0] != 1 or 8 + data[1] * 4 != length:
        raise ValueError("Invalid SID bytes/length")
    authority = int.from_bytes(data[2:8], "big")
    parts = [str(struct.unpack_from("<I", data, 8 + 4 * i)[0]) for i in range(data[1])]
    return "S-1-" + str(authority) + ("-" + "-".join(parts) if parts else "")

def read_token(offset):
    t = token.unpack_from(raw, offset)
    if t[0] != 31 or any(t[1:6]):
        raise ValueError("Incomplete token collection or native collection error")
    return {"Captured": t[0], "Sid": sid(t[15], t[6]),
        "SessionId": t[7], "IntegrityRid": t[8], "Elevated": t[9],
        "TokenType": t[10], "ImpersonationLevel": t[11],
        "TokenId": f"{t[12]:016X}", "AuthenticationId": f"{t[13]:016X}",
        "ModifiedId": f"{t[14]:016X}"}

rows = []
prior = 0
for i, event in enumerate(events[:-1]):
    base = i * pair_size
    h = header.unpack_from(raw, base)
    owner = read_token(base + header.size)
    effective = read_token(base + header.size + token.size)
    owner_truth = read_token(base + record_size)
    effective_truth = read_token(base + record_size + token.size)
    expected_status = 0xC0000022 if i < 6 else 0xC0000054 if i < 8 else 0
    expected_op = [1, 2, 2, 3, 3, 3, 1, 2, 1][i]
    expected_class = [0, 0, 0, 20, 10, 13, 0, 0, 0][i]
    checks = [h[0] == 1, h[1] == record_size, h[2] > prior,
        h[7] == event["Pid"], h[8] == event["Tid"], h[9] == event["Birth"],
        h[11] == expected_op, h[12] == expected_class,
        (h[14] & 0xFFFFFFFF) == expected_status,
        event["NativeStatus"] == f"0x{expected_status:08X}",
        h[15] == 0, h[16] == 0, h[17] == (2 if i < 8 else 1),
        h[18] == 0, h[19] == 1, h[6] >= h[4],
        owner == owner_truth, effective == effective_truth,
        owner["Sid"] == event["OwnerSid"], effective["Sid"] == event["EffectiveSid"],
        event["Passed"], event["TargetUnchanged"], event["FullTokenMatch"]]
    if not all(checks):
        raise SystemExit(f"Raw independent verification failed at {event['Case']}: {checks}")
    prior = h[2]
    rows.append({"Case": event["Case"], "Passed": True, "ProcessId": h[7],
        "ThreadId": h[8], "ProcessBirth": h[9], "Sequence": h[2],
        "Status": f"0x{expected_status:08X}", "Owner": owner, "Effective": effective})
result = {"Passed": True, "Cases": 9, "RawSha256": hashlib.sha256(raw).hexdigest(),
    "NativeLogSha256": hashlib.sha256(wire).hexdigest(),
    "Layout": {"SchemaVersion": 1, "RecordBytes": record_size, "TruthPairBytes": pair_size},
    "Rows": rows, "CentralIntegrated": False, "AllWindowsHostsQualified": False}
output.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
print(json.dumps({"Passed": True, "Cases": len(rows), "RawSha256": result["RawSha256"],
    "CentralIntegrated": False, "AllWindowsHostsQualified": False}))
