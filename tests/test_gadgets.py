import elftools.elf.elffile as elffile_module
import pytest
from capstone import CS_ARCH_X86, CS_MODE_64, Cs

from rop_forge.gadgets import GadgetKind, scan_gadgets
from rop_forge.gadgets.scanner import _build_gadget, _candidate_starts, _classify


def test_scan_gadgets_on_tiny_fixture_is_well_formed(fixture_path):
    db = scan_gadgets(fixture_path("fixture1_none"))
    assert len(db) > 0
    for gadget in db:
        assert gadget.instructions
        last = gadget.instructions[-1]
        is_ret = last.split()[0] in ("ret", "retf")
        is_reg_jmp_call = last.split()[0] in ("jmp", "call") and " " in last
        assert is_ret or is_reg_jmp_call


def test_scan_gadgets_kind_invariants_hold_on_libc(libc_gadgets):
    for gadget in libc_gadgets.by_kind(GadgetKind.POP_REG):
        assert all(insn.startswith("pop ") for insn in gadget.instructions[:-1])

    for gadget in libc_gadgets.by_kind(GadgetKind.SYSCALL):
        assert any(insn == "syscall" for insn in gadget.instructions)

    for gadget in libc_gadgets.by_kind(GadgetKind.MOV_MEM):
        assert any("mov" in insn and "ptr" in insn and "[" in insn for insn in gadget.instructions)

    for gadget in libc_gadgets.by_kind(GadgetKind.ZERO_REG):
        assert any(insn.split()[0] in ("xor", "sub") for insn in gadget.instructions)


def test_scan_gadgets_finds_a_large_and_diverse_set_in_libc(libc_gadgets):
    assert len(libc_gadgets) > 1000
    assert libc_gadgets.by_kind(GadgetKind.POP_REG)
    assert libc_gadgets.by_kind(GadgetKind.SYSCALL)


def test_scan_gadgets_finds_classic_pop_rdi_ret_in_libc(libc_gadgets):
    pop_rdi_ret = [
        g for g in libc_gadgets.by_kind(GadgetKind.POP_REG)
        if g.instructions == ("pop rdi", "ret")
    ]
    assert pop_rdi_ret, "expected at least one bare 'pop rdi ; ret' gadget in glibc"


def test_scan_gadgets_addresses_are_unique(fixture_path, libc_gadgets):
    tiny_db = scan_gadgets(fixture_path("fixture1_none"))
    for db in (tiny_db, libc_gadgets):
        addresses = [g.address for g in db]
        assert len(addresses) == len(set(addresses))


def test_scan_gadgets_returns_empty_when_no_text_section(fixture_path, monkeypatch):
    real_get_section = elffile_module.ELFFile.get_section_by_name

    def fake_get_section(self, name):
        return None if name == ".text" else real_get_section(self, name)

    monkeypatch.setattr(elffile_module.ELFFile, "get_section_by_name", fake_get_section)
    db = scan_gadgets(fixture_path("fixture1_none"))
    assert len(db) == 0


def test_candidate_starts_clamps_at_buffer_start():
    # An anchor near byte 0 must not produce negative candidate offsets.
    starts = _candidate_starts(anchors=[2], max_lookback_bytes=24)
    assert min(starts) == 0
    assert max(starts) == 2
    assert starts == set(range(0, 3))


def _disasm(code: bytes, addr: int = 0x1000):
    md = Cs(CS_ARCH_X86, CS_MODE_64)
    md.detail = True
    return list(md.disasm(code, addr))


@pytest.mark.parametrize(
    "code,expected_kind",
    [
        (b"\x5f\xc3", GadgetKind.POP_REG),  # pop rdi ; ret
        (b"\x0f\x05\xc3", GadgetKind.SYSCALL),  # syscall ; ret
        (b"\xc9\xc3", GadgetKind.STACK_PIVOT),  # leave ; ret
        (b"\x48\x83\xc4\x08\xc3", GadgetKind.STACK_PIVOT),  # add rsp, 8 ; ret
        (b"\x5c\xc3", GadgetKind.STACK_PIVOT),  # pop rsp ; ret — priority over POP_REG
        (b"\x48\x89\x38\xc3", GadgetKind.MOV_MEM),  # mov [rax], rdi ; ret
        (b"\x31\xd2\xc3", GadgetKind.ZERO_REG),  # xor edx, edx ; ret
        (b"\x30\xd2\xc3", GadgetKind.OTHER),  # xor dl, dl ; ret — 8-bit doesn't zero-extend
        (b"\x90\xc3", GadgetKind.OTHER),  # nop ; ret
    ],
    ids=[
        "pop_reg", "syscall", "leave", "add_rsp", "pop_rsp_priority", "mov_mem",
        "zero_reg", "zero_reg_8bit_excluded", "other",
    ],
)
def test_classify_known_instruction_sequences(code, expected_kind):
    assert _classify(_disasm(code)) is expected_kind


# --- pop_order/mem_write: only populated for ret-terminated gadgets --------
# The chain builder assumes a gadget's own `ret` consumes the next stack
# value in sequence. A jmp-reg/call-reg terminated gadget still classifies
# normally (useful for display) but must expose no structured effect data,
# since chaining into it would jump wherever that register points instead.


def test_build_gadget_pop_order_empty_when_jmp_terminated():
    gadget = _build_gadget(_disasm(b"\x5f\xff\xe0"))  # pop rdi ; jmp rax
    assert gadget.kind == GadgetKind.POP_REG
    assert gadget.pop_order == ()


def test_build_gadget_mem_write_none_when_jmp_terminated():
    gadget = _build_gadget(_disasm(b"\x48\x89\x38\xff\xe0"))  # mov [rax], rdi ; jmp rax
    assert gadget.kind == GadgetKind.MOV_MEM
    assert gadget.mem_write is None


# --- mem_write: rejected if an earlier instruction clobbers the registers --
# it relies on (e.g. "mov eax, X ; mov [rax], rdx ; ret" overwrites rax
# right before the write that would use it).


def test_build_gadget_mem_write_none_when_dest_reg_clobbered():
    # mov eax, 0x48000000 ; mov [rax], rdx ; ret
    gadget = _build_gadget(_disasm(b"\xb8\x00\x00\x00\x48\x48\x89\x10\xc3"))
    assert gadget.kind == GadgetKind.MOV_MEM
    assert gadget.mem_write is None


def test_build_gadget_mem_write_present_when_not_clobbered():
    gadget = _build_gadget(_disasm(b"\x48\x89\x10\xc3"))  # mov [rax], rdx ; ret
    assert gadget.mem_write == ("rax", "rdx", 0)


# --- zeroed_reg: 32-bit form zero-extends to the full 64-bit family name ---
# ("xor edx, edx" sets the full rdx, not just its low 32 bits — a real
# discovery: some real-world libc builds have no POP_REG path to a given
# register at all, single- or multi-pop, only this. See ENGINEERING_LOG.md.)


def test_build_gadget_zeroed_reg_normalizes_to_64bit_family():
    gadget = _build_gadget(_disasm(b"\x31\xd2\xc3"))  # xor edx, edx ; ret
    assert gadget.kind == GadgetKind.ZERO_REG
    assert gadget.zeroed_reg == "rdx"
    assert gadget.zero_clobbers == frozenset()


def test_build_gadget_zeroed_reg_reports_later_clobbers():
    # xor edx, edx ; mov eax, edx ; ret — also sets rax as a side effect,
    # which the chain builder needs to know about (see builder.py's
    # _find_zero_gadgets/state.py's with_registers `clears`).
    gadget = _build_gadget(_disasm(b"\x31\xd2\x89\xd0\xc3"))
    assert gadget.kind == GadgetKind.ZERO_REG
    assert gadget.zeroed_reg == "rdx"
    assert gadget.zero_clobbers == frozenset({"rax"})
