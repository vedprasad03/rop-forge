"""Command-line entrypoint for rop-forge."""

import argparse
import sys


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
    print(f"rop-forge: pipeline not yet implemented (target={args.binary})", file=sys.stderr)
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
