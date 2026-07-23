import pytest

from rop_forge.offset import OffsetNotFoundError, find_offset
from rop_forge.offset import finder as finder_module
from rop_forge.offset.finder import _get_crash_rip

# Canary-protected fixtures (3, 5) aren't in scope for Phase 3 — a raw
# cyclic-pattern overflow trips __stack_chk_fail before reaching `ret`, so
# offset-finding needs a different technique there (Phase 6, canary bypass).
NON_CANARY_FIXTURES = ["fixture1_none", "fixture2_nx", "fixture4_nx_pie"]


@pytest.mark.parametrize("name", NON_CANARY_FIXTURES)
def test_find_offset_matches_known_stack_layout(fixture_path, name):
    # buf[64] + saved rbp (8 bytes) = 72, for all three non-canary,
    # non-stripped tiers built from the same fixtures/src/vuln.c.
    assert find_offset(fixture_path(name)) == 72


def test_find_offset_leaves_no_core_files_behind(fixture_path, tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    find_offset(fixture_path("fixture1_none"))
    assert list(tmp_path.glob("core*")) == []


def test_find_offset_raises_when_pattern_too_short_to_crash(fixture_path):
    # 10 bytes never reaches the 64-byte buffer's end, let alone the saved
    # rbp/return address — the target just reads them and exits normally.
    with pytest.raises(OffsetNotFoundError, match="did not crash"):
        find_offset(fixture_path("fixture1_none"), pattern_length=10)


def test_crash_and_find_offset_raises_when_address_not_in_pattern(fixture_path, monkeypatch):
    # Forces the "crashed, but the address isn't in our cyclic pattern"
    # branch — impractical to construct for real against an actual binary,
    # since a genuine crash from our own payload is always findable by
    # construction. A real crash still happens here; only the lookup result
    # is faked.
    monkeypatch.setattr(finder_module, "cyclic_find", lambda *_a, **_kw: -1)
    with pytest.raises(OffsetNotFoundError, match="not found in cyclic pattern"):
        finder_module._crash_and_find_offset(str(fixture_path("fixture1_none")), 200)


class _FakeIO:
    """Stands in for a pwntools process/tube for unit-testing _get_crash_rip's
    error branches directly — these are impractical to trigger for real
    (would require sabotaging the OS-level core dump mechanism itself)."""

    def __init__(self, poll_result, corefile_value=None, corefile_raises=None):
        self._poll_result = poll_result
        self._corefile_value = corefile_value
        self._corefile_raises = corefile_raises

    def poll(self):
        return self._poll_result

    @property
    def corefile(self):
        if self._corefile_raises is not None:
            raise self._corefile_raises
        return self._corefile_value


@pytest.mark.parametrize("poll_result", [0, None])
def test_get_crash_rip_raises_when_process_did_not_crash(poll_result):
    with pytest.raises(OffsetNotFoundError, match="did not crash"):
        _get_crash_rip(_FakeIO(poll_result=poll_result), "some_binary")


def test_get_crash_rip_raises_when_corefile_parse_fails():
    io = _FakeIO(poll_result=-11, corefile_raises=RuntimeError("boom"))
    with pytest.raises(OffsetNotFoundError, match="could not be parsed"):
        _get_crash_rip(io, "some_binary")


def test_get_crash_rip_raises_when_no_corefile_produced():
    io = _FakeIO(poll_result=-11, corefile_value=None)
    with pytest.raises(OffsetNotFoundError, match="produced no core dump"):
        _get_crash_rip(io, "some_binary")
