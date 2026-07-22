"""Command-line entrypoint for rop-forge."""

import argparse
import sys

from rop_forge.analyzer import Protections, analyze_protections

STAGES = ["analyzer", "gadgets", "offset", "chainer", "leak", "exploit"]


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


def _run_analyzer(binary_path: str) -> int:
    _print_protections(analyze_protections(binary_path))
    return 0


def _stage_not_yet_implemented(stage: str):
    def _run(binary_path: str) -> int:
        print(f"rop-forge: stage '{stage}' not yet implemented", file=sys.stderr)
        return 1

    return _run


STAGE_RUNNERS = {
    "analyzer": _run_analyzer,
    "gadgets": _stage_not_yet_implemented("gadgets"),
    "offset": _stage_not_yet_implemented("offset"),
    "chainer": _stage_not_yet_implemented("chainer"),
    "leak": _stage_not_yet_implemented("leak"),
    "exploit": _stage_not_yet_implemented("exploit"),
}


def _run_full_pipeline(binary_path: str) -> int:
    exit_code = _run_analyzer(binary_path)
    if exit_code != 0:
        return exit_code
    print("rop-forge: remaining pipeline stages not yet implemented", file=sys.stderr)
    return 1


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    runner = STAGE_RUNNERS[args.stage] if args.stage else _run_full_pipeline
    try:
        return runner(args.binary)
    except (FileNotFoundError, IsADirectoryError) as exc:
        print(f"rop-forge: cannot read binary '{args.binary}': {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
