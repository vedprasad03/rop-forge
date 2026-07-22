from dataclasses import dataclass
from enum import Enum


class Relro(Enum):
    NONE = "none"
    PARTIAL = "partial"
    FULL = "full"


@dataclass(frozen=True)
class Protections:
    nx: bool
    pie: bool
    canary: bool
    relro: Relro
