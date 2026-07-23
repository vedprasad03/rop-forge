from pathlib import Path

from pwn import ELF, context, cyclic, cyclic_find, p64, process

_DEFAULT_PATTERN_LENGTH = 512
_MARKER = 0x4141414141414141


class OffsetNotFoundError(Exception):
    pass


def find_offset(binary_path: str | Path, pattern_length: int = _DEFAULT_PATTERN_LENGTH) -> int:
    binary_path = str(binary_path)
    context.log_level = "error"
    context.binary = ELF(binary_path)

    candidate = _crash_and_find_offset(binary_path, pattern_length)
    _verify_offset(binary_path, candidate)
    return candidate


def _crash_and_find_offset(binary_path: str, pattern_length: int) -> int:
    io = process(binary_path)
    io.send(cyclic(pattern_length))
    io.wait()
    rip = _get_crash_rip(io, binary_path)
    io.close()
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
    io = process(binary_path)
    io.send(b"A" * offset + p64(_MARKER))
    io.wait()
    rip = _get_crash_rip(io, binary_path)
    io.close()
    if rip != _MARKER:
        raise OffsetNotFoundError(
            f"{binary_path}: offset {offset} did not reproduce a controlled crash "
            f"(expected rip=0x{_MARKER:x}, got 0x{rip:x})"
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
