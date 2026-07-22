"""Command-line entrypoint for rop-forge."""

import argparse
import sys

from rop_forge.analyzer import analyze_protections


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
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    try:
        protections = analyze_protections(args.binary)
    except (FileNotFoundError, IsADirectoryError) as exc:
        print(f"rop-forge: cannot read binary '{args.binary}': {exc}", file=sys.stderr)
        return 2

    print(f"NX:     {'enabled' if protections.nx else 'disabled'}")
    print(f"PIE:    {'enabled' if protections.pie else 'disabled'}")
    print(f"Canary: {'enabled' if protections.canary else 'disabled'}")
    print(f"RELRO:  {protections.relro.value}")

    print("rop-forge: remaining pipeline stages not yet implemented", file=sys.stderr)
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
