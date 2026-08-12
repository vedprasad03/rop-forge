import pytest

from rop_forge.canary import (
    CanaryNotFoundError,
    build_canary_execve_chain,
    crack_canary,
    verify_canary_shell,
)
from rop_forge.leak import ForkingServer


@pytest.fixture
def canary_server(fixture_path):
    server = ForkingServer(fixture_path("fixture3_nx_canary_server"))
    yield server
    server.close()


# Building a canary-cracked chain scans the full libc gadget database (~80s,
# see ENGINEERING_LOG.md's Phase 2/5 entries) — session-scoped so every test
# that needs a real chain shares this one build, instead of repeating that
# scan per test.
@pytest.fixture(scope="session")
def canary_execve_fixture3(fixture_path, libc_path):
    server = ForkingServer(fixture_path("fixture3_nx_canary_server"))
    chain, header = build_canary_execve_chain(server, libc_path)
    yield server, chain, header
    server.close()


# --- crack_canary(): real byte-by-byte brute force against a live server --


def test_crack_canary_recovers_offset_and_full_canary(canary_server):
    result = crack_canary(canary_server)
    assert result.offset == 72
    assert len(result.canary) == 8
    # Well-known glibc/gcc convention: the canary's lowest-addressed byte
    # is always null, specifically to stop naive string-based leaks (a
    # %s-style read would stop right there) — verified here empirically
    # against this project's actual toolchain, not assumed.
    assert result.canary[0] == 0x00


def test_crack_canary_is_consistent_across_repeated_cracks_on_the_same_server(canary_server):
    # Same fork()-sharing guarantee Phase 5's ASLR leak relies on, applied
    # to the canary secret instead: two independent cracks against the same
    # long-lived server must agree, since every child inherits the exact
    # canary chosen once at the parent's own startup.
    first = crack_canary(canary_server)
    second = crack_canary(canary_server)
    assert first == second


def test_crack_canary_leaves_no_core_files_behind(canary_server):
    # Every wrong guess triggers a real SIGABRT core dump underneath — a
    # full crack makes hundreds of them. Checked as an invariant, not just
    # assumed cleaned up (same pattern as test_offset.py's own corefile-
    # litter test).
    crack_canary(canary_server)
    litter = list(canary_server.cwd.glob("*.core")) + list(canary_server.cwd.glob("core"))
    assert litter == []


def test_crack_canary_raises_for_a_target_with_no_canary(fixture_path):
    # fixture4_nx_pie_server (built for Phase 5) has NX+PIE but no canary —
    # a real, authentic way to trigger "no stack-smashing within range"
    # without needing a fixture built just for this negative case. It still
    # crashes (SIGSEGV on the corrupted return address), just never prints
    # the "stack smashing" text this module's detection signal looks for.
    server = ForkingServer(fixture_path("fixture4_nx_pie_server"))
    try:
        with pytest.raises(CanaryNotFoundError):
            crack_canary(server, search_max=128)
    finally:
        server.close()


# --- build_canary_execve_chain() / verify_canary_shell(): real end-to-end -


def test_canary_execve_chain_ends_in_syscall(canary_execve_fixture3):
    _server, chain, _header = canary_execve_fixture3
    assert "syscall" in chain.elements[-1].description


def test_canary_execve_chain_gets_a_real_shell(canary_execve_fixture3):
    server, chain, header = canary_execve_fixture3
    assert verify_canary_shell(server, header, chain)


def test_verify_canary_shell_fails_with_a_wrong_canary_byte(canary_execve_fixture3):
    # Falsification test, same spirit as Phase 5's corrupted-libc-base test:
    # flipping a single bit of the *correct*, already-cracked canary must
    # trip __stack_chk_fail and produce no shell — otherwise a bug in the
    # cracking or header-assembly logic could silently pass by coincidence.
    server, chain, header = canary_execve_fixture3
    corrupted = bytearray(header)
    corrupted[72] ^= 0xFF  # canary's own first byte, per offset=72 above
    assert not verify_canary_shell(server, bytes(corrupted), chain)


def test_canary_execve_chain_gets_a_real_shell_on_fixture5_pie(fixture_path, libc_path):
    # PRD.md's own Phase 6 text names fixture5 (PIE + canary combined) as
    # "the hardest tier". This confirms build_canary_execve_chain()
    # generalizes to it completely unchanged — it never depends on the
    # target binary's own PIE base at all, only libc's (see
    # ENGINEERING_LOG.md's Phase 5 design note on sourcing everything from
    # libc), so adding PIE on top of the canary costs nothing extra here.
    server = ForkingServer(fixture_path("fixture5_nx_pie_canary_server"))
    try:
        chain, header = build_canary_execve_chain(server, libc_path)
        assert verify_canary_shell(server, header, chain)
    finally:
        server.close()
