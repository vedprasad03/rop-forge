from pathlib import Path

from capstone import CS_ARCH_X86, CS_MODE_64, CS_OP_MEM, CS_OP_REG, Cs
from capstone import CS_GRP_CALL, CS_GRP_IRET, CS_GRP_JUMP, CS_GRP_RET
from elftools.elf.elffile import ELFFile

from .database import GadgetDatabase
from .gadget import Gadget, GadgetKind

_RET_BYTE = 0xC3
_MAX_X86_INSN_BYTES = 15
_DEFAULT_MAX_INSTRUCTIONS = 6
_DEFAULT_MAX_LOOKBACK_BYTES = 24

# CS_GRP_RET is checked separately as a terminator, not here — a control-
# transfer instruction only aborts a gadget-in-progress if it *isn't* one of
# our three accepted terminators (ret / jmp reg / call reg). CS_GRP_INT is
# deliberately excluded: `syscall` lives in that group too, and stopping on
# it would make `syscall ; ret` gadgets impossible to find.
_DIVERTING_GROUPS = {CS_GRP_JUMP, CS_GRP_CALL, CS_GRP_IRET}

_RSP_REG_NAMES = {"rsp", "esp"}


def scan_gadgets(
    binary_path: str | Path,
    max_instructions: int = _DEFAULT_MAX_INSTRUCTIONS,
    max_lookback_bytes: int = _DEFAULT_MAX_LOOKBACK_BYTES,
) -> GadgetDatabase:
    with open(binary_path, "rb") as f:
        elffile = ELFFile(f)
        text = elffile.get_section_by_name(".text")
        if text is None:
            return GadgetDatabase([])
        code = text.data()
        base_addr = text["sh_addr"]

    md = Cs(CS_ARCH_X86, CS_MODE_64)
    md.detail = True

    anchors = _find_anchors(md, code)
    candidate_starts = _candidate_starts(anchors, max_lookback_bytes)

    chunk_len = _MAX_X86_INSN_BYTES * max_instructions
    gadgets = []
    for start in sorted(candidate_starts):
        gadget = _try_build_gadget(md, code, start, base_addr, max_instructions, chunk_len)
        if gadget is not None:
            gadgets.append(gadget)
    return GadgetDatabase(gadgets)


def _find_anchors(md: Cs, code: bytes) -> list[int]:
    anchors = {i for i, b in enumerate(code) if b == _RET_BYTE}
    # address=0 makes insn.address equal the byte offset into `code` directly
    for insn in md.disasm(code, 0):
        if _is_reg_jmp_or_call(insn):
            anchors.add(insn.address)
    return sorted(anchors)


def _candidate_starts(anchors: list[int], max_lookback_bytes: int) -> set[int]:
    starts = set()
    for anchor in anchors:
        lo = max(0, anchor - max_lookback_bytes)
        starts.update(range(lo, anchor + 1))
    return starts


def _try_build_gadget(
    md: Cs, code: bytes, start: int, base_addr: int, max_instructions: int, chunk_len: int
) -> Gadget | None:
    chunk = code[start : start + chunk_len]
    insns = []
    for insn in md.disasm(chunk, base_addr + start):
        if _is_terminator(insn):
            insns.append(insn)
            return _build_gadget(insns)
        if _is_diverting(insn):
            return None
        insns.append(insn)
        if len(insns) >= max_instructions:
            return None
    return None


def _is_terminator(insn) -> bool:
    return CS_GRP_RET in insn.groups or _is_reg_jmp_or_call(insn)


def _is_reg_jmp_or_call(insn) -> bool:
    if not (CS_GRP_JUMP in insn.groups or CS_GRP_CALL in insn.groups):
        return False
    return bool(insn.operands) and insn.operands[0].type == CS_OP_REG


def _is_diverting(insn) -> bool:
    return any(group in insn.groups for group in _DIVERTING_GROUPS)


def _build_gadget(insns) -> Gadget:
    texts = tuple(f"{insn.mnemonic} {insn.op_str}".strip() for insn in insns)
    return Gadget(address=insns[0].address, instructions=texts, kind=_classify(insns))


def _classify(insns) -> GadgetKind:
    mnemonics = [insn.mnemonic for insn in insns]
    if "syscall" in mnemonics:
        return GadgetKind.SYSCALL
    if _is_stack_pivot(insns):
        return GadgetKind.STACK_PIVOT
    if len(mnemonics) > 1 and all(m == "pop" for m in mnemonics[:-1]):
        return GadgetKind.POP_REG
    if _has_mem_write(insns):
        return GadgetKind.MOV_MEM
    return GadgetKind.OTHER


def _is_stack_pivot(insns) -> bool:
    for insn in insns:
        if insn.mnemonic == "leave":
            return True
        if insn.mnemonic == "pop" and insn.op_str in _RSP_REG_NAMES:
            return True
        if insn.mnemonic in ("add", "sub", "xchg") and insn.operands:
            first = insn.operands[0]
            if first.type == CS_OP_REG and insn.reg_name(first.reg) in _RSP_REG_NAMES:
                return True
    return False


def _has_mem_write(insns) -> bool:
    for insn in insns:
        if insn.mnemonic == "mov" and insn.operands and insn.operands[0].type == CS_OP_MEM:
            return True
    return False
