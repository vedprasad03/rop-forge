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
