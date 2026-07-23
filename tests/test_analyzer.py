import subprocess
from pathlib import Path
from types import SimpleNamespace

import pytest
from elftools.elf.elffile import ELFFile

from rop_forge.analyzer import Relro, analyze_protections
from rop_forge.analyzer.analyzer import _has_bind_now, _has_symbol

FIXTURE_CASES = [
    ("fixture1_none", dict(nx=False, pie=False, canary=False, relro=Relro.NONE)),
    ("fixture2_nx", dict(nx=True, pie=False, canary=False, relro=Relro.NONE)),
    ("fixture3_nx_canary", dict(nx=True, pie=False, canary=True, relro=Relro.NONE)),
    ("fixture4_nx_pie", dict(nx=True, pie=True, canary=False, relro=Relro.NONE)),
    ("fixture5_nx_pie_canary", dict(nx=True, pie=True, canary=True, relro=Relro.NONE)),
]


@pytest.mark.parametrize("name,expected", FIXTURE_CASES, ids=[case[0] for case in FIXTURE_CASES])
def test_analyze_protections_matches_expected_tier(fixture_path, name, expected):
    protections = analyze_protections(fixture_path(name))
    assert protections.nx == expected["nx"]
    assert protections.pie == expected["pie"]
    assert protections.canary == expected["canary"]
    assert protections.relro == expected["relro"]


def _compile(tmp_path: Path, name: str, ld_flags: list[str]) -> Path:
    src = tmp_path / f"{name}.c"
    src.write_text("int main(void) { return 0; }\n")
    out = tmp_path / name
    subprocess.run(["gcc", *ld_flags, "-o", str(out), str(src)], check=True)
    return out


# None of the five fixture tiers vary RELRO (the Makefile disables it
# uniformly), so partial/full detection is exercised separately here.


def test_analyze_protections_detects_partial_relro(tmp_path):
    binary = _compile(tmp_path, "partial_relro", ["-Wl,-z,relro", "-Wl,-z,lazy"])
    assert analyze_protections(binary).relro == Relro.PARTIAL


def test_analyze_protections_detects_full_relro(tmp_path):
    binary = _compile(tmp_path, "full_relro", ["-Wl,-z,relro", "-Wl,-z,now"])
    assert analyze_protections(binary).relro == Relro.FULL


def test_analyze_protections_raises_for_missing_file():
    with pytest.raises(FileNotFoundError):
        analyze_protections("/nonexistent/path/to/binary")


# --- _detect_nx: no GNU_STACK segment at all -------------------------------
# Modern gcc/binutils always emit one, so this branch needs a binary that
# genuinely lacks it. Patching p_type to PT_NULL (0) on a real fixture's
# GNU_STACK program header entry is a minimal, surgical way to construct
# that — everything else about the file stays byte-identical and valid.


def _binary_with_gnu_stack_removed(source_path: Path, tmp_path: Path) -> Path:
    data = bytearray(source_path.read_bytes())
    with open(source_path, "rb") as f:
        elffile = ELFFile(f)
        phoff = elffile.header["e_phoff"]
        phentsize = elffile.header["e_phentsize"]
        index = next(
            i
            for i, segment in enumerate(elffile.iter_segments())
            if segment["p_type"] == "PT_GNU_STACK"
        )
    entry_offset = phoff + index * phentsize
    data[entry_offset : entry_offset + 4] = (0).to_bytes(4, "little")  # p_type = PT_NULL
    dest = tmp_path / "no_gnu_stack"
    dest.write_bytes(data)
    dest.chmod(0o755)
    return dest


def test_detect_nx_defaults_to_executable_when_gnu_stack_missing(fixture_path, tmp_path):
    patched = _binary_with_gnu_stack_removed(fixture_path("fixture1_none"), tmp_path)
    assert analyze_protections(patched).nx is False


# --- _has_bind_now: each of the three RELRO-full signal tags ---------------
# Real ld output only ever exercises whichever subset of these tags this
# toolchain happens to emit — unit-testing the private function directly
# with fakes proves each branch independently, not just "whatever glibc's ld
# does today".


def _tag(d_tag: str, d_val: int = 0):
    return SimpleNamespace(entry=SimpleNamespace(d_tag=d_tag, d_val=d_val))


class _FakeDynamicSection:
    def __init__(self, tags):
        self._tags = tags

    def iter_tags(self):
        return iter(self._tags)


@pytest.mark.parametrize(
    "tags,expected",
    [
        ([_tag("DT_BIND_NOW")], True),
        ([_tag("DT_FLAGS", d_val=0x8)], True),  # DF_BIND_NOW
        ([_tag("DT_FLAGS_1", d_val=0x1)], True),  # DF_1_NOW
        ([_tag("DT_FLAGS", d_val=0x4)], False),  # some other flag bit, not DF_BIND_NOW
        ([_tag("DT_NEEDED")], False),
        ([], False),
    ],
    ids=["DT_BIND_NOW", "DF_BIND_NOW", "DF_1_NOW", "unrelated-flag", "unrelated-tag", "empty"],
)
def test_has_bind_now_branches(tags, expected):
    assert _has_bind_now(_FakeDynamicSection(tags)) is expected


# --- _has_symbol: .symtab fallback and missing-section handling ------------
# Every fixture is dynamically linked, so __stack_chk_fail always shows up
# in .dynsym and the .symtab fallback path is never exercised by any real
# binary in this project's corpus (statically linked targets are out of
# scope per PRD.md's non-goals). Unit-tested directly instead.


class _FakeSymbol:
    def __init__(self, name):
        self.name = name


class _FakeSymbolSection:
    def __init__(self, names):
        self._names = names

    def iter_symbols(self):
        return (_FakeSymbol(name) for name in self._names)


class _FakeElfFile:
    def __init__(self, sections: dict):
        self._sections = sections

    def get_section_by_name(self, name):
        return self._sections.get(name)


def test_has_symbol_falls_back_to_symtab_when_absent_from_dynsym():
    elffile = _FakeElfFile(
        {
            ".dynsym": _FakeSymbolSection(["puts"]),
            ".symtab": _FakeSymbolSection(["__stack_chk_fail"]),
        }
    )
    assert _has_symbol(elffile, "__stack_chk_fail") is True


def test_has_symbol_false_when_absent_from_both_tables():
    elffile = _FakeElfFile(
        {
            ".dynsym": _FakeSymbolSection(["puts"]),
            ".symtab": _FakeSymbolSection(["main"]),
        }
    )
    assert _has_symbol(elffile, "__stack_chk_fail") is False


def test_has_symbol_false_when_neither_section_present():
    assert _has_symbol(_FakeElfFile({}), "__stack_chk_fail") is False
