import itertools
from collections import defaultdict, deque

from rop_forge.gadgets import Gadget, GadgetDatabase, GadgetKind

from .chain import Chain, ChainElement
from .goal import Goal
from .state import ChainState

_DEFAULT_MAX_DEPTH = 8
_MAX_MEM_GADGET_CANDIDATES = 5

_FULL_64BIT_REGS = {
    "rax", "rbx", "rcx", "rdx", "rsi", "rdi", "rbp", "rsp",
    "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15",
}


class ChainNotFoundError(Exception):
    pass


def build_chain(gadgets: GadgetDatabase, goal: Goal, max_depth: int = _DEFAULT_MAX_DEPTH) -> Chain:
    """BFS over gadget state transitions, per PRD.md §6.3.

    Since pop gadgets let the attacker choose the popped value freely, the
    search never needs to explore "which value to pop" — it only ever picks
    from the small set of goal-relevant constants, plus a 0 filler for
    registers a multi-pop gadget touches incidentally. That keeps the
    *state* space small, as long as the set of "relevant" registers stays
    small too.

    Two things that aren't small by default, both handled before the BFS
    even starts:
    - A real binary plus libc has hundreds of different-address gadgets
      that are semantically identical for chain-building (libc alone has
      566 separate `pop rdi ; ret` instances) — deduped to one
      representative per distinct (pop_order) / (dest_reg, src_reg, disp)
      pattern.
    - There can be dozens of *distinct* usable memory-write gadgets
      (different register pairs), and naively treating all of them as
      simultaneously available blows up the relevant-register set to
      nearly all 16 GPRs, which then blows up branching on any multi-pop
      gadget. Instead, only one memory-write gadget is used per search
      attempt — ranked by how much it overlaps with registers the goal
      already needs — with a bounded number of fallback attempts if the
      top choice doesn't lead to a valid chain.
    """
    final_gadget = _pick_final_gadget(gadgets, goal)
    pop_gadgets_all = _dedupe_by_key(
        (g for g in gadgets.by_kind(GadgetKind.POP_REG) if g.pop_order),
        key=lambda g: g.pop_order,
    )

    if not goal.memory_writes:
        return _search(pop_gadgets_all, [], goal, final_gadget, max_depth)

    mem_candidates = _rank_mem_gadgets(gadgets, goal)[:_MAX_MEM_GADGET_CANDIDATES]
    if not mem_candidates:
        raise ChainNotFoundError("no usable memory-write gadget available")

    last_error = None
    for mem_gadget in mem_candidates:
        try:
            return _search(pop_gadgets_all, [mem_gadget], goal, final_gadget, max_depth)
        except ChainNotFoundError as exc:
            last_error = exc
    raise ChainNotFoundError(
        f"tried {len(mem_candidates)} memory-write gadgets, none led to a valid "
        f"chain within {max_depth} gadgets; last error: {last_error}"
    )


def _search(pop_gadgets_all, mem_gadgets, goal: Goal, final_gadget: Gadget, max_depth: int) -> Chain:
    candidate_values = _compute_candidate_values(goal, mem_gadgets)
    relevant = set(candidate_values)
    pop_gadgets = [g for g in pop_gadgets_all if set(g.pop_order) & relevant]

    initial = ChainState.initial()
    if goal.is_satisfied(initial):
        return _finalize([], final_gadget)

    visited = {initial}
    frontier = deque([(initial, [])])

    while frontier:
        state, path = frontier.popleft()
        if len(path) >= max_depth:
            continue

        for gadget in pop_gadgets:
            for new_state, chosen in _apply_pop(state, gadget, candidate_values):
                if new_state in visited:
                    continue
                new_path = path + [(gadget, chosen)]
                if goal.is_satisfied(new_state):
                    return _finalize(new_path, final_gadget)
                visited.add(new_state)
                frontier.append((new_state, new_path))

        for gadget in mem_gadgets:
            new_state = _apply_mem_write(state, gadget, goal)
            if new_state is None or new_state in visited:
                continue
            new_path = path + [(gadget, {})]
            if goal.is_satisfied(new_state):
                return _finalize(new_path, final_gadget)
            visited.add(new_state)
            frontier.append((new_state, new_path))

    raise ChainNotFoundError(
        f"no chain found within {max_depth} gadgets for goal {goal.register_values}"
    )


def _pick_final_gadget(gadgets: GadgetDatabase, goal: Goal) -> Gadget:
    matches = gadgets.by_kind(goal.final_gadget_kind)
    if not matches:
        raise ChainNotFoundError(f"no {goal.final_gadget_kind.value} gadget available")
    return min(matches, key=lambda g: len(g.instructions))


def _dedupe_by_key(gadgets_iter, key) -> list:
    seen = {}
    for gadget in gadgets_iter:
        seen.setdefault(key(gadget), gadget)
    return list(seen.values())


def _rank_mem_gadgets(gadgets: GadgetDatabase, goal: Goal) -> list:
    goal_regs = set(goal.register_values)
    deduped = _dedupe_by_key(
        (
            g
            for g in gadgets.by_kind(GadgetKind.MOV_MEM)
            if g.mem_write and g.mem_write[0] in _FULL_64BIT_REGS and g.mem_write[1] in _FULL_64BIT_REGS
        ),
        key=lambda g: g.mem_write,
    )

    def overlap_score(gadget: Gadget) -> int:
        dest_reg, src_reg, _ = gadget.mem_write
        return int(dest_reg in goal_regs) + int(src_reg in goal_regs)

    return sorted(deduped, key=overlap_score, reverse=True)


def _compute_candidate_values(goal: Goal, mem_gadgets: list) -> dict:
    candidates = defaultdict(set)
    for reg, value in goal.register_values.items():
        candidates[reg].add(value)
    for gadget in mem_gadgets:
        dest_reg, src_reg, disp = gadget.mem_write
        for address, data in goal.memory_writes.items():
            candidates[dest_reg].add(address - disp)
            candidates[src_reg].add(int.from_bytes(data, "little"))
    return dict(candidates)


def _apply_pop(state: ChainState, gadget: Gadget, candidate_values: dict):
    choice_lists = [sorted(candidate_values.get(reg, set()) | {0}) for reg in gadget.pop_order]
    for combo in itertools.product(*choice_lists):
        chosen = dict(zip(gadget.pop_order, combo))
        yield state.with_registers(chosen), chosen


def _apply_mem_write(state: ChainState, gadget: Gadget, goal: Goal) -> ChainState | None:
    dest_reg, src_reg, disp = gadget.mem_write
    for address, data in goal.memory_writes.items():
        if address in state.written:
            continue
        required_dest = address - disp
        required_src = int.from_bytes(data, "little")
        if state.get(dest_reg) == required_dest and state.get(src_reg) == required_src:
            return state.with_write(address)
    return None


def _finalize(path, final_gadget: Gadget) -> Chain:
    elements = []
    for gadget, chosen in path:
        elements.append(ChainElement(gadget.address, gadget.text))
        for reg in gadget.pop_order:
            elements.append(ChainElement(chosen[reg], f"  -> {reg} = 0x{chosen[reg]:x}"))
    elements.append(ChainElement(final_gadget.address, final_gadget.text))
    return Chain(tuple(elements))
