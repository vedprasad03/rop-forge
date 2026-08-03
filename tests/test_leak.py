import dataclasses
from dataclasses import dataclass
from pathlib import Path

import pytest

from rop_forge.chainer import build_chain, build_leaked_execve_chain, verify_leaked_shell
from rop_forge.chainer.exploit import _BINSH
from rop_forge.chainer.goal import execve_goal_preexisting_string
from rop_forge.gadgets import GadgetDatabase
from rop_forge.leak import ForkingServer, LeakError, ServerStartError, probe
from rop_forge.leak.finder import _wait_for_crash_core


@pytest.fixture
def leak_server(fixture_path):
    server = ForkingServer(fixture_path("fixture4_nx_pie_server"))
    yield server
    server.close()


# Building a leaked chain scans the full libc gadget database (~80s, see
# ENGINEERING_LOG.md's Phase 2 entry) — session-scoped so every test that
# needs a real chain shares this one build, instead of repeating that scan
# per test (the exact per-test-rescan mistake Phase 2 already fixed once).
@pytest.fixture(scope="session")
def leaked_execve_fixture4(fixture_path, libc_path):
    server = ForkingServer(fixture_path("fixture4_nx_pie_server"))
    chain, offset = build_leaked_execve_chain(server, libc_path)
    yield server, chain, offset
    server.close()


# --- ForkingServer: real process, real socket -------------------------------


def test_forking_server_reports_a_valid_port(leak_server):
    assert 0 < leak_server.port < 65536


def test_forking_server_raises_on_a_non_server_binary(fixture_path):
    # fixture1_none's own main() blocks on stdin instead of printing
    # "PORT ..." — a real, authentic way to trigger the "didn't start
    # correctly" path without fabricating a fake binary.
    with pytest.raises(ServerStartError):
        ForkingServer(fixture_path("fixture1_none"))


# --- probe(): real crash + corefile forensics against a live, ASLR'd target -
# (cheap — just a crash + corefile read, no gadget scanning — safe to call
# per test rather than needing a shared fixture.)


def test_probe_recovers_offset_and_libc_base(leak_server, libc_path):
    result = probe(leak_server, libc_path)
    # Same offset as every other fixture (PIE affects address randomization,
    # not the stack layout that determines it) — see test_offset.py.
    assert result.offset == 72
    assert result.libc_base != 0
    assert result.libc_base % 0x1000 == 0  # page-aligned, a real mapping base


def test_probe_is_consistent_across_repeated_crashes_on_the_same_server(leak_server, libc_path):
    # fork() never re-randomizes — two *separate* crashed connections to the
    # *same* long-lived server must report the identical libc base. This is
    # the specific causal guarantee build_leaked_execve_chain()'s two-
    # connection design (leak via one connection, strike via a later one)
    # depends on. This devcontainer's QEMU emulation doesn't vary ASLR at
    # all (see ENGINEERING_LOG.md's Phase 5 entry), so it can't additionally
    # prove real *variance* across independently-spawned servers — only
    # same-server consistency, which is what this test checks.
    first = probe(leak_server, libc_path)
    second = probe(leak_server, libc_path)
    assert first.libc_base == second.libc_base
    assert first.offset == second.offset


def test_probe_raises_for_a_libc_path_that_does_not_exist(leak_server):
    with pytest.raises(FileNotFoundError):
        probe(leak_server, "/nonexistent/libc.so.6")


# --- build_leaked_execve_chain() / verify_leaked_shell(): real end-to-end --


def test_leaked_execve_chain_ends_in_syscall(leaked_execve_fixture4):
    _server, chain, _offset = leaked_execve_fixture4
    assert "syscall" in chain.elements[-1].description


def test_leaked_execve_chain_gets_a_real_shell(leaked_execve_fixture4):
    server, chain, offset = leaked_execve_fixture4
    assert verify_leaked_shell(server, chain, offset)


def test_verify_leaked_shell_fails_with_a_corrupted_base(leaked_execve_fixture4, libc_path, libc_gadgets):
    # Falsification test: a wrong-but-plausible-looking base must NOT
    # produce a shell. Without this, a subtle relocation bug could pass
    # every other test purely because this devcontainer's QEMU emulation
    # happens to hand out the same fixed address on every run (see
    # ENGINEERING_LOG.md) — this is the one test actually sensitive to
    # whether the leaked value is being used correctly, not just present.
    server, _chain, offset = leaked_execve_fixture4
    result = probe(server, libc_path)
    # XOR a high bit rather than adding a small offset — a small offset can
    # land on still-valid, still-mapped libc code (libc's mapping spans
    # several MB) and behave unpredictably instead of failing cleanly.
    corrupted_base = result.libc_base ^ 0x400000000000

    relocated = [dataclasses.replace(g, address=g.address + corrupted_base) for g in libc_gadgets]
    binsh_offset = Path(libc_path).read_bytes().find(_BINSH)
    goal = execve_goal_preexisting_string(corrupted_base + binsh_offset)
    chain = build_chain(GadgetDatabase(relocated), goal)

    assert not verify_leaked_shell(server, chain, offset)


@dataclass
class _FakeServer:
    binary_path: str
    cwd: Path


def test_wait_for_crash_core_raises_when_no_core_dump_appears(tmp_path):
    # Genuinely triggering "the target crashed but produced no core dump"
    # would mean sabotaging the OS-level core-dump mechanism itself —
    # impractical to construct for real, so this unit-tests the private
    # helper directly against an empty directory instead (same pattern
    # offset/finder.py's own corefile-failure tests use).
    fake_server = _FakeServer(binary_path="/nonexistent/binary", cwd=tmp_path)
    with pytest.raises(LeakError, match="no core dump"):
        _wait_for_crash_core(fake_server)
