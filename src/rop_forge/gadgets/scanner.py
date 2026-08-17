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

# Maps every x86-64 GPR sub-register name to its 64-bit family, so a write to
# e.g. "eax" can be recognized as clobbering "rax" — capstone's regs_access()
# reports the exact accessed width, not a canonicalized register id.
_REG_FAMILIES = {
    name: family
    for family, names in {
        "rax": ("rax", "eax", "ax", "al", "ah"),
        "rbx": ("rbx", "ebx", "bx", "bl", "bh"),
        "rcx": ("rcx", "ecx", "cx", "cl", "ch"),
        "rdx": ("rdx", "edx", "dx", "dl", "dh"),
        "rsi": ("rsi", "esi", "si", "sil"),
        "rdi": ("rdi", "edi", "di", "dil"),
        "rbp": ("rbp", "ebp", "bp", "bpl"),
        "rsp": ("rsp", "esp", "sp", "spl"),
        **{
            f"r{n}": (f"r{n}", f"r{n}d", f"r{n}w", f"r{n}b")
            for n in range(8, 16)
        },
    }.items()
    for name in names
}


def _reg_family(name: str) -> str:
    return _REG_FAMILIES.get(name, name)


def _is_ret_terminated(insns) -> bool:
    return CS_GRP_RET in insns[-1].groups


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
    kind = _classify(insns)
    # pop_order/mem_write/zeroed_reg feed the chain builder, which assumes a
    # gadget's own `ret` consumes the next stack value in sequence — a
    # jmp-reg/call-reg terminated gadget doesn't do that (it jumps to
    # whatever that register holds instead), so it's still classified
    # normally for display but exposes no structured effect data to build
    # on.
    ret_terminated = _is_ret_terminated(insns)
    zero_effect = (
        _find_zero_reg_effect(insns) if kind == GadgetKind.ZERO_REG and ret_terminated else None
    )
    return Gadget(
        address=insns[0].address,
        instructions=texts,
        kind=kind,
        pop_order=_extract_pop_order(insns) if kind == GadgetKind.POP_REG and ret_terminated else (),
        mem_write=(
            _extract_mem_write(insns) if kind == GadgetKind.MOV_MEM and ret_terminated else None
        ),
        zeroed_reg=zero_effect[0] if zero_effect else None,
        zero_clobbers=zero_effect[1] if zero_effect else frozenset(),
    )


def _classify(insns) -> GadgetKind:
    mnemonics = [insn.mnemonic for insn in insns]
    if "syscall" in mnemonics:
        return GadgetKind.SYSCALL
    if _is_stack_pivot(insns):
        return GadgetKind.STACK_PIVOT
    if len(mnemonics) > 1 and all(m == "pop" for m in mnemonics[:-1]):
        return GadgetKind.POP_REG
    if _find_zero_reg_effect(insns) is not None:
        return GadgetKind.ZERO_REG
    if _has_mem_write(insns):
        return GadgetKind.MOV_MEM
    return GadgetKind.OTHER


def _find_zero_reg_effect(insns) -> tuple[str, frozenset] | None:
    # Finds the first `xor reg, reg` / `sub reg, reg` — 32-bit (edx) or
    # 64-bit (rdx) only, since those zero-extend the full register on
    # x86-64; an 8/16-bit form (dl, dx) only touches its own sub-register —
    # and reports which OTHER registers this gadget's own later
    # instructions write to, so the chain builder can invalidate any
    # previously-tracked value there rather than assume it survives (e.g.
    # "xor edx, edx ; mov eax, edx ; ret" also sets rax). The zeroing
    # instruction itself never depends on prior state — self-xor is 0 no
    # matter what was there before — so unlike mem_write's dest/src
    # clobber check, there's nothing to verify about instructions
    # *before* it, only what happens after.
    #
    # Reject the whole gadget outright if ANY instruction writes to
    # memory (e.g. "add byte ptr [rdi], cl ; ... ; xor edx, edx ; ...
    # ; ret") — found for real: a candidate exactly like that corrupted
    # libc's own embedded "/bin/sh" string when rdi happened to already
    # point there, because this model only reasons about register
    # effects. A memory write's target/effect isn't something a plain
    # register-clobber check can account for, so treat any gadget that
    # has one as unsafe rather than trying to reason about it.
    if any(insn.operands and insn.operands[0].type == CS_OP_MEM for insn in insns):
        return None
    for i, insn in enumerate(insns):
        if insn.mnemonic not in ("xor", "sub") or len(insn.operands) != 2:
            continue
        dest, src = insn.operands
        if dest.type != CS_OP_REG or src.type != CS_OP_REG or dest.reg != src.reg:
            continue
        if dest.size not in (4, 8):
            continue
        zeroed = _reg_family(insn.reg_name(dest.reg))
        clobbers = set()
        for later in insns[i + 1 :]:
            _, written = later.regs_access()
            for reg_id in written:
                family = _reg_family(later.reg_name(reg_id))
                # rsp/rip are never a goal target or tracked chain-state
                # register in this model — ret's own implicit stack-pointer
                # write would otherwise pollute every single gadget's
                # clobber set with meaningless noise.
                if family not in (zeroed, "rsp", "rip"):
                    clobbers.add(family)
        return zeroed, frozenset(clobbers)
    return None


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


def _extract_pop_order(insns) -> tuple[str, ...]:
    order = []
    for insn in insns[:-1]:  # exclude the terminator
        if insn.mnemonic == "pop" and insn.operands and insn.operands[0].type == CS_OP_REG:
            order.append(insn.reg_name(insn.operands[0].reg))
    return tuple(order)


def _extract_mem_write(insns) -> tuple[str, str, int] | None:
    # Only simple base(+disp) destinations with a register-sourced value are
    # usable as a controllable write primitive — an immediate source can't
    # be repointed at arbitrary data, an indexed destination needs a second
    # register we'd also have to control, and "rip" (capstone's base for
    # RIP-relative addressing) isn't settable via a pop gadget the way a
    # general-purpose register is. None of these are attempted in v1.
    for i, insn in enumerate(insns):
        if insn.mnemonic != "mov" or not insn.operands:
            continue
        dest, src = insn.operands[0], insn.operands[1] if len(insn.operands) > 1 else None
        if dest.type != CS_OP_MEM or src is None or src.type != CS_OP_REG:
            continue
        if dest.mem.index != 0 or dest.mem.base == 0:
            continue
        dest_reg = insn.reg_name(dest.mem.base)
        if dest_reg == "rip":
            continue
        src_reg = insn.reg_name(src.reg)
        # A gadget can contain instructions before the mov that overwrite
        # dest_reg/src_reg's value — e.g. "mov eax, 0x48000000 ; mov [rax],
        # rdx ; ret" clobbers rax right before the write we'd rely on. Skip
        # any mov whose dest/src was written by an earlier instruction in
        # this same gadget.
        if _clobbered_before(insns[:i], dest_reg, src_reg):
            continue
        return (dest_reg, src_reg, dest.mem.disp)
    return None


def _clobbered_before(prior_insns, dest_reg: str, src_reg: str) -> bool:
    target_families = {_reg_family(dest_reg), _reg_family(src_reg)}
    for insn in prior_insns:
        _, written = insn.regs_access()
        if any(_reg_family(insn.reg_name(reg_id)) in target_families for reg_id in written):
            return True
    return False
