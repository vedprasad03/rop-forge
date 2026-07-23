import subprocess
from pathlib import Path

import pytest

FIXTURES_DIR = Path(__file__).parent.parent / "fixtures"
FIXTURES_BUILD_DIR = FIXTURES_DIR / "build"


@pytest.fixture(scope="session", autouse=True)
def build_fixtures():
    subprocess.run(["make", "-C", str(FIXTURES_DIR)], check=True)


@pytest.fixture(scope="session")
def fixture_path():
    def _fixture_path(name: str) -> Path:
        return FIXTURES_BUILD_DIR / name

    return _fixture_path


# The "known libc" tests scan against (PRD.md §7 Phase 2) is the devcontainer's
# own system glibc, resolved by path rather than committed to the repo — this
# is a large redistributable binary blob, and it's already what our fixtures
# link against, consistent with the project's Linux-only devcontainer
# architecture (see ENGINEERING_LOG.md).
_LIBC_CANDIDATES = [
    Path("/lib/x86_64-linux-gnu/libc.so.6"),
    Path("/usr/lib/x86_64-linux-gnu/libc.so.6"),
    Path("/lib64/libc.so.6"),
]


@pytest.fixture(scope="session")
def libc_path() -> Path:
    for candidate in _LIBC_CANDIDATES:
        if candidate.exists():
            return candidate
    pytest.skip("no system glibc found at any known path")


@pytest.fixture(scope="session")
def libc_gadgets(libc_path):
    from rop_forge.gadgets import scan_gadgets

    return scan_gadgets(libc_path)


@pytest.fixture(scope="session")
def execve_chain_fixture1(fixture_path):
    from rop_forge.chainer import build_execve_chain

    return build_execve_chain(fixture_path("fixture1_none"))
