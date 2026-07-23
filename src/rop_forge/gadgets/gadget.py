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
    # Structured effect data, populated only for the kind it's relevant to —
    # best-effort extraction at scan time (see scanner.py), not a guarantee
    # every gadget of that kind has it (e.g. an immediate-sourced MOV_MEM
    # gadget still classifies as MOV_MEM but has mem_write=None, since its
    # write value isn't attacker-controllable).
    pop_order: tuple[str, ...] = ()  # POP_REG: registers popped, in order
    mem_write: tuple[str, str, int] | None = None  # MOV_MEM: (dest_reg, src_reg, disp)

    @property
    def text(self) -> str:
        return " ; ".join(self.instructions)

    def __str__(self) -> str:
        return f"0x{self.address:x}: {self.text}"
