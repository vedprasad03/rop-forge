import pytest

from rop_forge.chainer import (
    Chain,
    ChainElement,
    ChainNotFoundError,
    ChainState,
    Goal,
    build_chain,
    build_execve_chain,
    execve_goal,
    find_system_libc,
    verify_shell,
)
from rop_forge.gadgets import Gadget, GadgetDatabase, GadgetKind
from rop_forge.offset import find_offset

# --- ChainState --------------------------------------------------------


def test_chain_state_get_returns_none_for_unset_register():
    assert ChainState.initial().get("rax") is None


def test_chain_state_with_registers_and_write():
    state = ChainState.initial().with_registers({"rax": 5}).with_write(0x1000)
    assert state.get("rax") == 5
    assert 0x1000 in state.written


def test_chain_state_is_hashable_for_bfs_dedup():
    a = ChainState.initial().with_registers({"rax": 5})
    b = ChainState.initial().with_registers({"rax": 5})
    assert a == b
    assert len({a, b}) == 1


# --- Goal / execve_goal --------------------------------------------------


def test_goal_is_satisfied_checks_registers_and_memory():
    goal = Goal(register_values={"rax": 1}, memory_writes={0x1000: b"hi"})
    assert not goal.is_satisfied(ChainState.initial())
    satisfied = ChainState.initial().with_registers({"rax": 1}).with_write(0x1000)
    assert goal.is_satisfied(satisfied)


def test_execve_goal_shape():
    goal = execve_goal(0x404000)
    assert goal.register_values == {"rax": 59, "rdi": 0x404000, "rsi": 0, "rdx": 0}
    assert goal.memory_writes == {0x404000: b"/bin/sh\x00"}
    assert goal.final_gadget_kind is GadgetKind.SYSCALL


# --- Chain -----------------------------------------------------------------


def test_chain_payload_packs_little_endian_u64_per_element():
    chain = Chain((ChainElement(0x1000, "a"), ChainElement(0x2000, "b")))
    assert chain.payload() == (0x1000).to_bytes(8, "little") + (0x2000).to_bytes(8, "little")
    assert len(chain) == 2


# --- build_chain(): synthetic gadgets, no real binary/libc needed ----------


def _pop(address: int, *regs: str) -> Gadget:
    return Gadget(
        address=address,
        instructions=tuple(f"pop {r}" for r in regs) + ("ret",),
        kind=GadgetKind.POP_REG,
        pop_order=regs,
    )


def _mem_write(address: int, dest_reg: str, src_reg: str, disp: int = 0) -> Gadget:
    return Gadget(
        address=address,
        instructions=(f"mov qword ptr [{dest_reg}], {src_reg}", "ret"),
        kind=GadgetKind.MOV_MEM,
        mem_write=(dest_reg, src_reg, disp),
    )


def _syscall(address: int) -> Gadget:
    return Gadget(address=address, instructions=("syscall", "ret"), kind=GadgetKind.SYSCALL)


def _minimal_execve_gadgets() -> list:
    return [
        _pop(0x1000, "rdi"),
        _pop(0x1010, "rsi"),
        _pop(0x1020, "rdx"),
        _pop(0x1030, "rax"),
        _mem_write(0x1040, "rdi", "rsi"),
        _syscall(0x1050),
    ]


def test_build_chain_finds_minimal_execve_chain():
    db = GadgetDatabase(_minimal_execve_gadgets())
    chain = build_chain(db, execve_goal(0x404000))
    assert chain.elements[-1].value == 0x1050
    assert len(chain.payload()) % 8 == 0


def test_build_chain_raises_when_no_syscall_gadget():
    db = GadgetDatabase([_pop(0x1000, "rdi")])
    with pytest.raises(ChainNotFoundError, match="syscall"):
        build_chain(db, execve_goal(0x404000))


def test_build_chain_raises_when_register_unreachable():
    # no gadget can ever set rdx
    gadgets = [g for g in _minimal_execve_gadgets() if g.pop_order != ("rdx",)]
    with pytest.raises(ChainNotFoundError):
        build_chain(GadgetDatabase(gadgets), execve_goal(0x404000))


def test_build_chain_respects_max_depth():
    db = GadgetDatabase(_minimal_execve_gadgets())
    with pytest.raises(ChainNotFoundError):
        build_chain(db, execve_goal(0x404000), max_depth=2)


# --- Real integration: binary + libc, actual live processes ---------------


def test_build_execve_chain_ends_in_syscall(execve_chain_fixture1):
    assert "syscall" in execve_chain_fixture1.elements[-1].description


def test_build_execve_chain_payload_is_word_aligned(execve_chain_fixture1):
    assert len(execve_chain_fixture1.payload()) % 8 == 0


def test_find_system_libc_finds_a_real_file():
    path = find_system_libc()
    assert path is not None
    assert path.exists()


def test_execve_chain_gets_a_real_shell_on_fixture1(fixture_path, execve_chain_fixture1):
    path = fixture_path("fixture1_none")
    offset = find_offset(path)
    assert verify_shell(path, execve_chain_fixture1, offset)


def test_execve_chain_gets_a_real_shell_on_fixture2_nx(fixture_path):
    # NX forces a real ROP chain instead of shellcode injection (PRD.md §7
    # Phase 4) — the same chain builder must generalize with no changes.
    path = fixture_path("fixture2_nx")
    chain = build_execve_chain(path)
    offset = find_offset(path)
    assert verify_shell(path, chain, offset)
