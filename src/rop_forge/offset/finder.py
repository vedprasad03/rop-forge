import shutil
import tempfile
from pathlib import Path

from pwn import ELF, context, p64, process

_DEFAULT_PATTERN_LENGTH = 512
# Canonical (top bytes zero) AND well below Linux's default mmap_min_addr,
# so this is guaranteed unmapped — a clean, reproducible page fault rather
# than a general-protection fault. See _crash_and_find_offset()'s docstring
# for why that distinction is the whole point.
_MARKER = 0x1337
_MAX_CRASH_ATTEMPTS = 3


class OffsetNotFoundError(Exception):
    pass


def find_offset(binary_path: str | Path, pattern_length: int = _DEFAULT_PATTERN_LENGTH) -> int:
    binary_path = str(Path(binary_path).resolve())
    context.log_level = "error"
    context.binary = ELF(binary_path)

    candidate = _crash_and_find_offset(binary_path, pattern_length)
    _verify_offset(binary_path, candidate)
    return candidate


def _crash_and_find_offset(binary_path: str, pattern_length: int) -> int:
    """Binary-searches for the offset using crash-vs-no-crash, not by
    reading *what* the crash's RIP is.

    Reading RIP after smashing the return address with a raw filler
    pattern (the original approach, `cyclic()` + `cyclic_find()`) only
    works because QEMU user-mode emulation doesn't faithfully reproduce
    real x86-64 fault semantics. `cyclic()`'s alphabet is lowercase ASCII,
    so any 8-byte window read as an address has a non-zero high byte —
    essentially never a canonical address. On real hardware, a `ret` to a
    non-canonical address raises a general-protection fault *before* RIP
    is ever updated (the crash's saved RIP stays at the `ret` instruction
    itself — confirmed against a real x86-64 GitHub Actions runner via
    strace + objdump, see ENGINEERING_LOG.md), not at the garbage value —
    QEMU instead reports RIP as the garbage value directly. Crash-vs-no-
    crash doesn't care what kind of fault occurred, so it's portable to
    both; `_verify_offset()` below still reads RIP, but only after
    confirming the offset via this search, using a marker chosen to
    guarantee a real page fault instead (see _MARKER).
    """
    if not _crashes(binary_path, pattern_length):
        raise OffsetNotFoundError(
            f"{binary_path} did not crash within {pattern_length} bytes "
            "(pattern_length may be too short to reach the return address)"
        )
    lo, hi = 0, pattern_length
    while lo + 1 < hi:
        mid = (lo + hi) // 2
        if _crashes(binary_path, mid):
            hi = mid
        else:
            lo = mid
    return lo


def _crashes(binary_path: str, n: int) -> bool:
    """True if `n` filler bytes make the target die via signal — n bytes
    short of the return address, it returns normally instead."""
    cwd = Path(tempfile.mkdtemp(prefix="rop-forge-offset-"))
    try:
        io = process(binary_path, cwd=str(cwd))
        io.send(b"A" * n)
        io.wait()
        status = io.poll()
        io.close()
        return status is not None and status < 0
    finally:
        shutil.rmtree(cwd, ignore_errors=True)


def _verify_offset(binary_path: str, offset: int) -> None:
    rip = _crash_and_get_rip(binary_path, b"A" * offset + p64(_MARKER))
    if rip != _MARKER:
        raise OffsetNotFoundError(
            f"{binary_path}: offset {offset} did not reproduce a controlled crash "
            f"(expected rip=0x{_MARKER:x}, got 0x{rip:x})"
        )


def _crash_and_get_rip(binary_path: str, payload: bytes) -> int:
    # Own isolated cwd per attempt — without this, every process() spawn
    # across the whole test suite writes its corefile into the same shared
    # directory (this container's core_pattern has no %p), and under
    # repeated rapid crashes a *different* crash can overwrite it before we
    # read it (leak/server.py's ForkingServer already does this for the
    # same reason).
    #
    # This is now only ever called by _verify_offset(), confirming an
    # already-determined offset with a controlled payload that should
    # deterministically crash — so *any* unexpected outcome here (didn't
    # crash, corefile unreadable, wrong architecture) is retried rather
    # than assumed to be a genuine offset error, the same way the binary
    # search's own crash-detection would be. A truly wrong offset would
    # fail identically on every attempt anyway; a transient spawn/IO hiccup
    # (observed rarely, in a full-suite run with thousands of process
    # spawns) won't.
    last_error = None
    for _ in range(_MAX_CRASH_ATTEMPTS):
        cwd = Path(tempfile.mkdtemp(prefix="rop-forge-offset-"))
        try:
            io = process(binary_path, cwd=str(cwd))
            io.send(payload)
            io.wait()
            try:
                rip = _get_crash_rip(io, binary_path)
                io.close()
                return rip
            except Exception as exc:  # noqa: BLE001 - deliberately broad, see above
                io.close()
                last_error = exc
        finally:
            shutil.rmtree(cwd, ignore_errors=True)
    raise OffsetNotFoundError(
        f"{binary_path}: could not reliably reproduce a controlled crash after "
        f"{_MAX_CRASH_ATTEMPTS} attempts; last error: {last_error}"
    )


def _get_crash_rip(io, binary_path: str) -> int:
    status = io.poll()
    if status is None or status >= 0:
        raise OffsetNotFoundError(f"{binary_path} did not crash (exit status: {status})")
    try:
        core = io.corefile
    except Exception as exc:
        raise OffsetNotFoundError(
            f"{binary_path} crashed but its core dump could not be parsed: {exc}"
        ) from exc
    if core is None:
        raise OffsetNotFoundError(f"{binary_path} crashed but produced no core dump")

    rip = core.rip
    core_path = Path(core.file.name)
    core.file.close()
    core_path.unlink(missing_ok=True)
    # Under QEMU emulation, the host kernel also writes a raw "core" file
    # (the qemu-x86_64 interpreter's own memory image) that pwntools reads
    # to derive core_path above but never cleans up itself.
    (core_path.parent / "core").unlink(missing_ok=True)
    return rip
