from dataclasses import dataclass
from enum import Enum


class GadgetKind(Enum):
    POP_REG = "pop_reg"
    MOV_MEM = "mov_mem"
    SYSCALL = "syscall"
    STACK_PIVOT = "stack_pivot"
    OTHER = "other"


@dataclass(frozen=True)
class Gadget:
    address: int
    instructions: tuple[str, ...]
    kind: GadgetKind

    @property
    def text(self) -> str:
        return " ; ".join(self.instructions)

    def __str__(self) -> str:
        return f"0x{self.address:x}: {self.text}"
