"""Offline admission only. Never modifies/loads the Microsoft driver."""
import argparse
import hashlib
import json
import struct
from pathlib import Path

p = argparse.ArgumentParser()
p.add_argument('image')
p.add_argument('output')
p.add_argument('--dependency')
a = p.parse_args()
out = Path(a.output)
if out.exists():
    raise SystemExit('Preserve previous admission')
data = Path(a.image).read_bytes()
u16 = lambda o: struct.unpack_from('<H', data, o)[0]
u32 = lambda o: struct.unpack_from('<I', data, o)[0]
u64 = lambda o: struct.unpack_from('<Q', data, o)[0]
pe = u32(60)
if data[:2] != b'MZ' or data[pe:pe+4] != b'PE\0\0' or u16(pe+4) != 0x8664 or u16(pe+24) != 0x20b:
    raise SystemExit('Expected x64 PE32+ driver')
opt = pe+24
base = u64(opt+24)
sections = []
for i in range(u16(pe+6)):
    o = opt+u16(pe+20)+40*i
    sections.append(dict(Name=data[o:o+8].rstrip(b'\0').decode(), VirtualSize=u32(o+8),
        Rva=u32(o+12), RawSize=u32(o+16), RawOffset=u32(o+20), Flags=u32(o+36)))
def offset(rva):
    for s in sections:
        if s['Rva'] <= rva < s['Rva']+s['RawSize']:
            return s['RawOffset']+rva-s['Rva']
    raise ValueError('Unbacked RVA')
def text(rva):
    o = offset(rva)
    return data[o:data.index(b'\0', o)].decode('ascii')
eo = offset(u32(opt+112))
functions, names, ordinals = u32(eo+28), u32(eo+32), u32(eo+36)
exports = {}
for i in range(u32(eo+24)):
    name = text(u32(offset(names)+4*i))
    ordinal = u16(offset(ordinals)+2*i)
    exports[name] = u32(offset(functions)+4*ordinal)
expected = {32:'dtrace_unregister', 40:'dtrace_condense', 48:'dtrace_probe_lookup',
    56:'dtrace_probe_create', 64:'dtrace_module_unloaded', 72:'dtrace_probe'}
candidates = []
for s in sections:
    if s['Flags'] & 0x20000000:
        continue
    for o in range(s['RawOffset'], s['RawOffset']+s['RawSize']-79, 8):
        if u32(o) != 80:
            continue
        if not all(u64(o+k) == base+exports[v] for k,v in expected.items()):
            continue
        pointers = [u64(o+k)-base for k in range(8,80,8)]
        if not all(any(t['Flags'] & 0x20000000 and t['Rva'] <= r < t['Rva']+t['VirtualSize'] for t in sections) for r in pointers):
            continue
        candidates.append(dict(Rva=s['Rva']+o-s['RawOffset'], Size=80, Section=s['Name'], CallbackRvas=pointers))
result = dict(ReadOnly=True, RuntimeQualified=False, ImageSha256=hashlib.sha256(data).hexdigest(),
    ImageBase=base, ImageSize=u32(opt+56), Exports={k:exports.get(k) for k in
    ['TraceRegisterEngine','TraceInitSystem',*expected.values()]},
    UniqueCompatibleTable=len(candidates)==1, Candidates=candidates,
    Scope='Exact on-disk Microsoft TRACE_ENGINE table layout only; registration, replacement, callback IRQL and token capture remain untested')
if a.dependency:
    import sys
    sys.path.insert(0, a.dependency)
    import capstone
    if capstone.__version__ != '5.0.6':
        raise SystemExit('Pinned decoder changed')
    decoder = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
    result['ExportInstructions'] = {}
    for name in ['TraceRegisterEngine', 'TraceInitSystem']:
        rva = exports[name]
        result['ExportInstructions'][name] = [dict(Rva=i.address, Bytes=bytes(i.bytes).hex(),
            Instruction=i.mnemonic+' '+i.op_str) for i in decoder.disasm(data[offset(rva):offset(rva)+1024], rva, count=120)]
out.write_text(json.dumps(result, indent=2), encoding='utf-8')
print(json.dumps(result))
