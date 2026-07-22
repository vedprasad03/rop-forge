from collections.abc import Iterator

from .gadget import Gadget, GadgetKind


class GadgetDatabase:
    """Flat list + linear scan.

    Per PRD.md §11's own open question, this starts as simple as possible —
    a flat list with linear-scan queries. Worth revisiting only if the
    ChainBuilder's search turns out to be bottlenecked on gadget lookups.
    """

    def __init__(self, gadgets: list[Gadget]):
        self._gadgets = gadgets

    def by_kind(self, kind: GadgetKind) -> list[Gadget]:
        return [g for g in self._gadgets if g.kind is kind]

    def __len__(self) -> int:
        return len(self._gadgets)

    def __iter__(self) -> Iterator[Gadget]:
        return iter(self._gadgets)
