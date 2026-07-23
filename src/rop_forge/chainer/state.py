from dataclasses import dataclass


@dataclass(frozen=True)
class ChainState:
    """BFS node: which registers hold which values, and which target
    addresses already have their required bytes written. Both fields are
    frozensets so ChainState is hashable — required for the BFS's
    visited-state deduplication, which is what keeps the search tractable
    regardless of how many gadgets are available (see builder.py)."""

    registers: frozenset  # frozenset[tuple[str, int]]
    written: frozenset  # frozenset[int] — addresses successfully written

    def get(self, reg: str) -> int | None:
        for name, value in self.registers:
            if name == reg:
                return value
        return None

    @staticmethod
    def initial() -> "ChainState":
        return ChainState(registers=frozenset(), written=frozenset())

    def with_registers(self, updates: dict) -> "ChainState":
        merged = dict(self.registers)
        merged.update(updates)
        return ChainState(registers=frozenset(merged.items()), written=self.written)

    def with_write(self, address: int) -> "ChainState":
        return ChainState(registers=self.registers, written=self.written | {address})
