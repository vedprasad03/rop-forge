from dataclasses import dataclass

from rop_forge.gadgets import GadgetKind

_SYS_EXECVE = 59
_BINSH = b"/bin/sh\x00"


@dataclass(frozen=True)
class Goal:
    register_values: dict
    memory_writes: dict  # address -> exact bytes required there
    final_gadget_kind: GadgetKind = GadgetKind.SYSCALL

    def is_satisfied(self, state) -> bool:
        for reg, value in self.register_values.items():
            if state.get(reg) != value:
                return False
        return all(address in state.written for address in self.memory_writes)


def execve_goal(binsh_address: int) -> Goal:
    """execve("/bin/sh", NULL, NULL) via a raw syscall — PRD.md §6.3's own
    worked example: rdi=&"/bin/sh", rsi=0, rdx=0, then a syscall gadget."""
    return Goal(
        register_values={"rax": _SYS_EXECVE, "rdi": binsh_address, "rsi": 0, "rdx": 0},
        memory_writes={binsh_address: _BINSH},
        final_gadget_kind=GadgetKind.SYSCALL,
    )


def execve_goal_preexisting_string(binsh_address: int) -> Goal:
    """Same execve("/bin/sh", NULL, NULL) goal as execve_goal(), but for when
    "/bin/sh" already exists in memory at `binsh_address` (e.g. glibc ships
    this exact string internally, for system()/popen()) — no memory-write
    gadget needed to plant it, so `memory_writes` stays empty."""
    return Goal(
        register_values={"rax": _SYS_EXECVE, "rdi": binsh_address, "rsi": 0, "rdx": 0},
        memory_writes={},
        final_gadget_kind=GadgetKind.SYSCALL,
    )
