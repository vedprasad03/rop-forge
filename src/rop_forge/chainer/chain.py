from dataclasses import dataclass

from pwn import p64


@dataclass(frozen=True)
class ChainElement:
    value: int
    description: str


@dataclass(frozen=True)
class Chain:
    elements: tuple

    def payload(self) -> bytes:
        return b"".join(p64(e.value) for e in self.elements)

    def __len__(self) -> int:
        return len(self.elements)

    def __str__(self) -> str:
        return "\n".join(f"0x{e.value:016x}  {e.description}" for e in self.elements)


@dataclass(frozen=True)
class SolvedExploit:
    """Everything a leak- and/or canary-based build_*_execve_chain() solved,
    both for live use (verify_leaked_shell()/verify_canary_shell() just need
    `chain` + `header`) and for Phase 7's exploit/ emitter, which needs the
    structural facts (`libc_base`, `offset`, `canary_offset`) broken out
    separately from `header` — those are safe to bake into a generated
    script (not secrets, just stack layout), unlike `header`'s actual
    canary bytes, which are only valid for the one process they were
    cracked from.

    `header` is everything to send before `chain.payload()`: just
    `b"A" * offset` when there's no canary, or `b"A" * canary_offset +
    canary + b"A" * offset` when there is.
    """

    chain: Chain
    header: bytes
    libc_base: int
    offset: int
    canary_offset: int | None = None
