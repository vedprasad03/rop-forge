# PRD: rop-forge — Automated ROP-Chain Exploit Generator

**Author:** Ved Prasad

**Status:** Draft for implementation

**Target timeline:** 3–4 weeks (part-time)

---

## 1. Summary

`rop-forge` is a tool that automatically generates working exploits for 64-bit Linux ELF binaries vulnerable to stack buffer overflows. Given a binary (and optionally its libc), it detects enabled protections (NX, PIE, stack canary, ASLR), scans for usable ROP gadgets, automatically computes the overflow offset, constructs a gadget chain via graph search to achieve a target goal (typically a shell), and outputs a working, runnable exploit script.

The project exists to convert an existing manual skill (CTF binary exploitation) into a general-purpose automated tool — this is a meaningfully harder task than solving individual CTF challenges, and it exercises binary internals, systems programming, and search/graph algorithms in combination.

---

## 2. Goals

- Build an end-to-end pipeline: binary in → working exploit out, with no manual gadget-hunting by the user.
- Support a **graduated ladder of protection combinations**, from none to NX+PIE+canary+ASLR, and demonstrate the tool defeating each tier.
- Implement gadget discovery, offset discovery, and chain construction **from scratch** (using disassembly/ELF-parsing libraries as primitives, not using existing ROP-chain-building tools like `pwntools.rop.ROP` or `angrop` as the solver).
- Produce a runnable, self-contained exploit script as output, and a `--run` mode that proves it works end-to-end against a live target.
- Produce clear documentation (README + design notes) that explains *why* the tool works, not just what it does — this is the artifact that will actually get read in interviews.

## 3. Non-goals (explicitly out of scope)

- Support for 32-bit binaries, Windows PE, or macOS Mach-O targets.
- Support for vulnerability classes beyond stack buffer overflows (no heap exploitation, no format-string-as-primary-vuln, no use-after-free) in v1. Format strings may appear *only* as an information-leak mechanism in the ASLR-bypass phase.
- A GUI. This is a CLI tool.
- Handling of exotic/custom mitigations (CFI, stack canary + ASLR combined with PIE + full RELRO + fortify source all at once) — pick a reasonable maximum protection tier and stop there.
- Attacking real-world/third-party binaries or services. All targets are self-compiled fixtures, and this constraint is stated explicitly in the README.
- Multi-architecture gadget support (ARM, etc.) — x86-64 only.
- Production-grade robustness/performance. This is a portfolio project; correctness and clarity of design matter more than handling every edge case.

---

## 4. Target users / use case

Primary "user" is a security-minded engineer who has a vulnerable binary and wants an automated first-pass exploit rather than hand-building a ROP chain. Secondary "user" is anyone reading the GitHub repo/README to understand or reuse the tool — documentation and demo quality matter as much as the code.

---

## 5. Tech stack

| Layer | Choice | Rationale |
|---|---|---|
| Core language | Python 3.11+ | Fast iteration, strong ecosystem for binary tooling |
| Dev/build environment | `uv` for dependency management; a Linux (x86-64) devcontainer via Docker/colima when developing on a non-Linux host | Target is Linux-ELF-only — `pwntools.process()` must fork/exec real ELF binaries, and `unicorn` (a `pwntools` dep) has no macOS-arm64 wheel. Not part of the shipped package: on native Linux, `uv sync` alone is sufficient, no container required |
| ELF parsing | `pyelftools` | Don't hand-roll ELF parsing — not the point of the project |
| Disassembly | `capstone` | Industry-standard disassembly engine, clean Python bindings |
| Process interaction / exploit runtime | `pwntools` (`process`, `remote`, `context`, `cyclic`) | Standard for interacting with target processes; used as infrastructure, not as the solver |
| Target fixtures | C, compiled with `gcc` under varying flags | Need real binaries with real protection combinations |
| Testing | `pytest` | Unit tests for gadget parsing, offset detection, chain search |
| Packaging | `pyproject.toml`, installable as a CLI (`rop-forge <binary>`) | Makes it usable/demoable as a real tool, not just a script |
| Demo/docs | `asciinema` recording + README | Portfolio artifact quality |

**Explicitly not used as the exploit solver:** `pwntools.rop.ROP`, `angrop`, `ropper`'s automated chaining. These may be referenced in the README as prior art / points of comparison, and pwntools' lower-level primitives (`cyclic`, `process`, `context.binary`) are fine to use as infrastructure — but the gadget search and chain construction logic are all implemented from scratch.

---

## 6. System design

### 6.1 Pipeline overview

```
binary (+ libc) 
   → [Analyzer]         detect protections (NX, PIE, canary, RELRO)
   → [GadgetScanner]    disassemble, extract & categorize gadgets
   → [OffsetFinder]     cyclic pattern → crash → compute overflow offset
   → [ChainBuilder]     graph search over gadgets → goal state
   → [LeakHandler]      (if ASLR/PIE) leak address → compute base
   → [ExploitEmitter]   generate runnable pwntools exploit script
   → [Runner]           (optional) execute exploit, confirm shell
```

### 6.2 Module breakdown

- **`analyzer/`** — ELF header parsing; detect NX (`GNU_STACK` segment flags), PIE (`e_type == ET_DYN`), RELRO (`GNU_RELRO` segment + `BIND_NOW` flag), and canary (heuristic: prologue reads `fs:0x28`, epilogue calls `__stack_chk_fail`).
- **`gadgets/`** — Disassemble executable segments (and libc, if loaded), extract instruction sequences ending in `ret`/`jmp reg`/`call reg`, classify by effect (`pop reg; ret`, `mov [dst], src; ret`, `syscall; ret`, etc.), build an indexed, queryable gadget database.
- **`offset/`** — Generate a De Bruijn sequence via `pwntools.cyclic`, send to target, parse the crash (core dump or captured signal), compute exact offset to return address via `cyclic_find`.
- **`chainer/`** — Model chain construction as a search problem over gadget state transitions (see §6.3). Output an ordered list of gadget addresses + stack values.
- **`leak/`** — For PIE/ASLR targets: use a leak primitive (e.g., `puts(GOT[puts])` via a short gadget chain, or a format-string leak if present) to recover a runtime address, compute the load base via known static offsets.
- **`exploit/`** — Serialize the constructed chain into a working, standalone Python (pwntools) script; separately support directly executing it against the live target for verification.

### 6.3 Chain construction as a search problem

This is the algorithmic core and should be treated as a genuine CS problem, not just glue code:

- **State**: mapping of registers → symbolic value classes (`unknown`, `attacker-controlled constant`, `pointer to controlled data`, `leaked base + offset`).
- **Goal state**: register assignments required for the target call (e.g., for `execve("/bin/sh", NULL, NULL)`: `rdi = &"/bin/sh"`, `rsi = 0`, `rdx = 0`, then control flow reaches `execve`).
- **Transitions**: each gadget maps to a state transition function (e.g., `pop rdi; ret` sets `rdi = <next stack value>`, other registers unchanged).
- **Search**: BFS over gadget sequences (bounded depth, e.g. max 8 gadgets) for a v1; note in the design docs where this could be upgraded to A* with a heuristic (e.g., number of unset goal registers) if time allows.

Document this explicitly in `chainer/README.md` with a small diagram — this is the core algorithmic contribution of the project and deserves clear explanation.

---

## 7. Implementation plan

### Phase 0 — Project scaffolding & fixtures (2–3 days)
- Repo structure, `pyproject.toml`, CLI entrypoint stub, pytest setup.
- Write 4–5 vulnerable C fixtures with increasing protection: (1) no protections, (2) NX only, (3) NX + canary, (4) NX + PIE, (5) NX + PIE + canary. Compile each with explicit `gcc` flags, commit the Makefile.

### Phase 1 — Analyzer (2–3 days)
- ELF header parsing, protection detection for all 4 flags.
- Unit tests against all 5 fixtures, asserting correct detection.

### Phase 2 — Gadget scanner (3–4 days)
- Disassemble `.text`, extract gadgets ending in `ret`.
- Categorize into a handful of useful gadget types.
- Unit tests against fixtures + a known libc, checking expected gadgets are found.

### Phase 3 — Offset finder (1–2 days)
- Cyclic pattern generation, crash detection, offset computation.
- Test against fixture 1 (simplest case) end-to-end.

### Phase 4 — Chain builder (4–5 days, core effort)
- Implement the state/goal/search model from §6.3.
- Get a working chain for fixture 1 (no protections) first: prove you can pop registers and call `execve`.
- Extend to fixture 2 (NX): forces a ROP chain instead of shellcode injection — this should already work if chain builder is general.

### Phase 5 — ASLR/PIE bypass (3–4 days)
- Implement leak primitive + base computation.
- Extend chain builder to work against fixture 4 (PIE).

### Phase 6 — Canary bypass (2–3 days, stretch — include if time allows)
- Brute-force byte-by-byte approach against a forking test service.
- Extend to fixture 5 (PIE + canary) — the hardest tier.

### Phase 7 — Exploit emitter + runner + polish (3–4 days)
- Generate standalone pwntools scripts from constructed chains.
- `--run` flag for live verification.
- Record asciinema demo(s) against 2–3 tiers.
- Write README with architecture diagram, design rationale, and a "how this differs from angrop/ropper" section.

**Total: ~3–4 weeks part-time.** Phases 0–4 (through basic NX bypass on a non-PIE binary) constitute a legitimate, demoable v1 if time runs short — phases 5–6 are what push it from "solid" to "standout."

---

## 8. Milestones / demoable checkpoints

1. **M1** — Tool detects protections correctly on all 5 fixtures.
2. **M2** — Tool finds and categorizes gadgets in a fixture binary + libc.
3. **M3** — Tool auto-computes overflow offset against a live process.
4. **M4** — Tool builds and executes a working exploit against fixture 1 (no protections) — **first true end-to-end win**.
5. **M5** — Same, against fixture 2/3 (NX, NX+canary bypass via brute force).
6. **M6** — Same, against fixture 4 (PIE, via leak + base computation) — **stretch-complete v1**.
7. **M7** — README + demo recording finished, repo polished for external viewing.

---

## 9. Success criteria

- Tool produces a working shell against at least 3 of the 5 protection tiers, fully automated (no manual gadget lookup).
- Core algorithms (gadget scanning, offset detection, chain search) are original implementations, not calls into existing ROP-building libraries.
- README clearly explains the design and includes a recorded demo.
- Code is modular enough that each phase (`analyzer`, `gadgets`, `chainer`, etc.) could be understood, tested, and explained independently.

---

## 10. Risks & mitigations

| Risk | Mitigation |
|---|---|
| Chain search becomes combinatorially expensive on large binaries | Bound search depth; scope gadget database to a reasonable size; document the tradeoff rather than over-engineering a solution |
| PIE/ASLR leak primitive doesn't generalize across fixtures | It's fine to hand-craft the leak primitive per fixture tier for v1 — document this as a known limitation, note how a more general leak-detection phase could be added later |
| Canary bypass (brute force) requires a forking service, adds complexity | Treat as explicit stretch goal (Phase 6); ship without it if time-constrained, note it as future work in README |
| Scope creep (wanting to support heap exploitation, other arches, etc.) | Non-goals section exists precisely to prevent this — resist mid-project expansion |

---

## 11. Open questions for implementation (to resolve early with Claude Code)

- Exact gadget-database representation: flat list with linear scan vs. indexed by register-effect for faster lookup — start simple, optimize only if search is too slow.
- Whether to support x86-64 only from the start (yes) vs. leaving an abstraction seam for future architectures (not worth the complexity for v1).
- How much of the leak primitive logic should be fixture-specific vs. generalized — default to fixture-specific for v1, per Risk table above.
