"""Independent callback-context verification; never asserts token capture."""
import argparse
import hashlib
import json
import struct
from pathlib import Path

p=argparse.ArgumentParser()
p.add_argument('--directory',required=True)
p.add_argument('--output',required=True)
a=p.parse_args()
root=Path(a.directory)
output=Path(a.output)
if output.exists():
    raise SystemExit('Preserve context acceptance receipt')
raw=(root/'native-records.bin').read_bytes()
wire=(root/'native.jsonl').read_bytes()
encoding='utf-16' if wire.startswith((b'\xff\xfe',b'\xfe\xff')) else 'utf-8-sig'
events=[json.loads(line) for line in wire.decode(encoding).splitlines() if line.strip()]
context=struct.Struct('<II6Q6I4Q')
assert context.size==112
pair_size=2*112+2*144
if len(raw)!=9*pair_size or len(events)!=10 or not events[-1].get('ContextOnly') or events[-1].get('TokenCaptureEstablished') is not False:
    raise SystemExit('Not a complete nine-pair context-only artifact')
prior=0
rows=[]
for i,event in enumerate(events[:-1]):
    entry=context.unpack_from(raw,i*pair_size)
    returned=context.unpack_from(raw,i*pair_size+112)
    expected=0xc0000022 if i<6 else 0xc0000054 if i<8 else 0
    operation=1 if i in (0,6,8) else 2 if i in (1,2,7) else 3
    for c,stage in [(entry,1),(returned,2)]:
        assert c[0:2]==(1,112)
        assert c[5:8]==(event['Pid'],event['Tid'],event['Birth'])
        assert c[9]==operation and c[10]==stage and c[11]<=1
        assert c[12] in (0,1) and c[13] in (0,1)
    assert prior<entry[2]<returned[2] and returned[3]>=entry[3]
    assert (returned[14]&0xffffffff)==expected==int(event['NativeStatus'],16)
    assert event['Passed'] and event['TargetUnchanged'] and event['TokenCaptureEstablished'] is False
    assert entry[11:14]==(event['EntryIrql'],event['EntryInterruptsEnabled'],event['EntryAllApcsDisabled'])
    assert returned[11:14]==(event['ReturnIrql'],event['ReturnInterruptsEnabled'],event['ReturnAllApcsDisabled'])
    rows.append(dict(Case=event['Case'],EntryIrql=entry[11],ReturnIrql=returned[11],
        EntryInterruptsEnabled=bool(entry[12]),ReturnInterruptsEnabled=bool(returned[12]),
        EntryAllApcsDisabled=bool(entry[13]),ReturnAllApcsDisabled=bool(returned[13]),
        TokenCaptureEstablished=False))
    prior=returned[2]
result=dict(Passed=True,Cases=9,RawSha256=hashlib.sha256(raw).hexdigest(),
    TokenCaptureEstablished=False,CentralIntegrated=False,ProductionQualified=False,Rows=rows)
output.write_text(json.dumps(result,indent=2),encoding='utf-8')
print(json.dumps(result))
