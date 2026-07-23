import elftools.elf.elffile as elffile_module
import pytest
from capstone import CS_ARCH_X86, CS_MODE_64, Cs

from rop_forge.gadgets import GadgetKind, scan_gadgets
from rop_forge.gadgets.scanner import _candidate_starts, _classify


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
        (b"\x90\xc3", GadgetKind.OTHER),  # nop ; ret
    ],
    ids=["pop_reg", "syscall", "leave", "add_rsp", "pop_rsp_priority", "mov_mem", "other"],
)
def test_classify_known_instruction_sequences(code, expected_kind):
    assert _classify(_disasm(code)) is expected_kind
