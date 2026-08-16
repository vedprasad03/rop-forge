import shutil
import tempfile
from pathlib import Path

from pwn import ELF, context, cyclic, cyclic_find, p64, process

_DEFAULT_PATTERN_LENGTH = 512
_MARKER = 0x4141414141414141
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
    rip = _crash_and_get_rip(binary_path, cyclic(pattern_length))
    # cyclic_find() hangs/misbehaves when given a raw int for an 8-byte
    # value — pass the packed bytes instead, which is fast and correct.
    offset = cyclic_find(p64(rip))
    if offset == -1:
        raise OffsetNotFoundError(
            f"{binary_path}: crash address 0x{rip:x} not found in cyclic pattern "
            f"(pattern_length={pattern_length} may be too short to reach the return address)"
        )
    return offset


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
    # read it. Under QEMU that mostly surfaced as an AttributeError (the
    # host's own ARM64 qemu-x86_64 core instead of our x86-64 guest's,
    # caught by the retry below); on genuinely fast native hardware it can
    # just as easily hand back a *different x86-64 crash's* stale-but-valid
    # core, silently — cwd isolation removes the shared-file race itself
    # rather than only catching one of its symptoms (leak/server.py's
    # ForkingServer already does this for the same reason).
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
            except OffsetNotFoundError:
                io.close()
                raise
            except Exception as exc:  # noqa: BLE001 - deliberately broad, see above
                io.close()
                last_error = exc
        finally:
            shutil.rmtree(cwd, ignore_errors=True)
    raise OffsetNotFoundError(
        f"{binary_path}: could not reliably read a crash corefile after "
        f"{_MAX_CRASH_ATTEMPTS} attempts (likely a QEMU corefile-naming race); "
        f"last error: {last_error}"
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
