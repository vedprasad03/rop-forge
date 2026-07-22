import subprocess
from pathlib import Path

import pytest

FIXTURES_DIR = Path(__file__).parent.parent / "fixtures"
FIXTURES_BUILD_DIR = FIXTURES_DIR / "build"


@pytest.fixture(scope="session", autouse=True)
def build_fixtures():
    subprocess.run(["make", "-C", str(FIXTURES_DIR)], check=True)


@pytest.fixture
def fixture_path():
    def _fixture_path(name: str) -> Path:
        return FIXTURES_BUILD_DIR / name

    return _fixture_path
