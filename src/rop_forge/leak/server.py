import re
import shutil
import tempfile
from pathlib import Path

from pwn import context, process

_PORT_RE = re.compile(rb"PORT (\d+)")
_STARTUP_TIMEOUT = 5.0


class ServerStartError(Exception):
    pass


class ForkingServer:
    """Launches the forking-server harness (fixtures/src/server_main.c)
    wrapping a target binary. Every accepted connection is handled by a
    forked child sharing the parent's own ASLR-randomized memory layout —
    fork() never re-randomizes — so a base recovered via one connection
    (even a crashed one) stays valid for a later connection to the same
    still-running server, without ever disabling ASLR. Matches how a real
    leak-based exploit targets a persistent/forking network service.

    Runs in a dedicated temp directory so its crash corefiles can't collide
    with another test/run's litter (this project's core dumps use a plain
    "core"/`qemu_<basename>_*.core` naming with no per-run isolation of
    their own).
    """

    def __init__(self, binary_path: str | Path):
        self.binary_path = str(Path(binary_path).resolve())
        self.cwd = Path(tempfile.mkdtemp(prefix="rop-forge-leak-"))

        context.log_level = "error"
        self.io = process(self.binary_path, cwd=str(self.cwd))
        line = self.io.recvline(timeout=_STARTUP_TIMEOUT)
        match = _PORT_RE.search(line)
        if not match:
            self.io.close()
            shutil.rmtree(self.cwd, ignore_errors=True)
            raise ServerStartError(f"server did not report a listening port (got: {line!r})")
        self.port = int(match.group(1))

    def close(self) -> None:
        self.io.close()
        shutil.rmtree(self.cwd, ignore_errors=True)

    def __enter__(self) -> "ForkingServer":
        return self

    def __exit__(self, *exc_info) -> None:
        self.close()
