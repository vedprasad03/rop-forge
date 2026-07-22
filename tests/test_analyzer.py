import subprocess
from pathlib import Path

import pytest

from rop_forge.analyzer import Relro, analyze_protections

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
