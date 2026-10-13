"""Read-only first-instruction relocation admission; never runtime proof."""
import argparse
import hashlib
import json
import sys
from pathlib import Path

parser = argparse.ArgumentParser()
parser.add_argument("--dependency", required=True)
parser.add_argument("--receipts", nargs="+", required=True)
parser.add_argument("--output", required=True)
args = parser.parse_args()
output = Path(args.output)
if output.exists():
    raise SystemExit("Immutable prologue receipt already exists")
sys.path.insert(0, args.dependency)
import capstone
from capstone.x86 import X86_OP_MEM, X86_REG_RIP

if capstone.__version__ != "5.0.6":
    raise SystemExit("Pinned decoder version changed")
decoder = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
decoder.detail = True
rows = []
for receipt in args.receipts:
    wire = Path(receipt).read_bytes()
    source = json.loads(wire.decode("utf-8-sig"))
    for export in source["Exports"]:
        if not export["Name"].startswith("Nt"):
            continue
        data = bytes.fromhex(export["PrologueHex"])
        address = int(export["Rva"], 16)
        instructions = list(decoder.disasm(data, address, count=1))
        reasons = []
        insn = instructions[0] if len(instructions) == 1 else None
        if export["Forwarded"]:
            reasons.append("forwarded_export")
        if insn is None:
            reasons.append("instruction_decode_failed")
        else:
            if (address & 4095) + insn.size > 4096:
                reasons.append("instruction_crosses_page")
            if any(insn.group(g) for g in (capstone.CS_GRP_JUMP,
                    capstone.CS_GRP_CALL, capstone.CS_GRP_RET,
                    capstone.CS_GRP_INT, capstone.CS_GRP_IRET,
                    capstone.CS_GRP_BRANCH_RELATIVE)):
                reasons.append("control_flow_instruction_requires_relocation")
            if any(op.type == X86_OP_MEM and op.mem.base == X86_REG_RIP
                   for op in insn.operands):
                reasons.append("rip_relative_operand_requires_relocation")
        rows.append({"Receipt": str(Path(receipt).resolve()),
            "ReceiptSha256": hashlib.sha256(wire).hexdigest(),
            "KernelSha256": source["Sha256"], "KernelVersion": source["FileVersion"],
            "Export": export["Name"], "Rva": export["Rva"],
            "Instruction": None if insn is None else insn.mnemonic + " " + insn.op_str,
            "InstructionBytes": None if insn is None else bytes(insn.bytes).hex(),
            "CopyWithoutRelocationAdmitted": not reasons, "Reasons": reasons,
            "RuntimeQualified": False})
result = {"DecoderVersion": capstone.__version__, "ReadOnly": True,
    "Scope": "on-disk first instruction only; live image and backend not qualified",
    "AllFirstInstructionsAdmitted": bool(rows) and all(
        r["CopyWithoutRelocationAdmitted"] for r in rows), "Rows": rows,
    "RuntimeQualified": False}
output.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
print(json.dumps({"Receipt": str(output.resolve()), "Rows": len(rows),
    "AllFirstInstructionsAdmitted": result["AllFirstInstructionsAdmitted"],
    "RuntimeQualified": False}))
