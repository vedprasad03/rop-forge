from rop_forge.gadgets import GadgetKind, scan_gadgets


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
