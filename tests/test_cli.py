import pytest

from rop_forge.cli import build_parser, main


def test_parser_requires_binary():
    parser = build_parser()
    args = parser.parse_args(["fixtures/build/fixture1"])
    assert args.binary == "fixtures/build/fixture1"
    assert args.run is False
    assert args.stage is None


def test_main_returns_nonzero_until_pipeline_exists(capsys, fixture_path):
    exit_code = main([str(fixture_path("fixture1_none"))])
    assert exit_code == 1
    out = capsys.readouterr().out
    assert "NX:" in out
    assert "Found" in out and "gadgets" in out
    assert "Offset to return address:" in out


def test_main_reports_missing_binary():
    exit_code = main(["fixtures/build/does_not_exist"])
    assert exit_code == 2


def test_main_reports_directory_as_binary(fixture_path):
    exit_code = main([str(fixture_path("fixture1_none").parent)])
    assert exit_code == 2


def test_stage_analyzer_runs_standalone(capsys, fixture_path):
    exit_code = main([str(fixture_path("fixture1_none")), "--stage", "analyzer"])
    assert exit_code == 0
    out = capsys.readouterr().out
    assert "NX:" in out
    assert "RELRO:" in out


def test_stage_gadgets_runs_standalone(capsys, fixture_path):
    exit_code = main([str(fixture_path("fixture1_none")), "--stage", "gadgets"])
    assert exit_code == 0
    assert "Found" in capsys.readouterr().out


def test_stage_offset_runs_standalone(capsys, fixture_path):
    exit_code = main([str(fixture_path("fixture1_none")), "--stage", "offset"])
    assert exit_code == 0
    assert "Offset to return address: 72 bytes" in capsys.readouterr().out


def test_stage_chainer_with_run_builds_and_verifies_shell(capsys, fixture_path):
    exit_code = main([str(fixture_path("fixture1_none")), "--stage", "chainer", "--run"])
    assert exit_code == 0
    out = capsys.readouterr().out
    assert "Chain (" in out
    assert "Shell verified" in out


def test_stage_leak_runs_standalone(capsys, fixture_path):
    exit_code = main([str(fixture_path("fixture4_nx_pie_server")), "--stage", "leak"])
    assert exit_code == 0
    out = capsys.readouterr().out
    assert "Offset to return address: 72 bytes" in out
    assert "Libc runtime base: 0x" in out


def test_stage_chainer_with_server_uses_leaked_flow(capsys, fixture_path):
    exit_code = main(
        [
            str(fixture_path("fixture4_nx_pie")),
            "--server",
            str(fixture_path("fixture4_nx_pie_server")),
            "--stage",
            "chainer",
            "--run",
        ]
    )
    assert exit_code == 0
    out = capsys.readouterr().out
    assert "Chain (" in out
    assert "Shell verified" in out


def test_stage_canary_runs_standalone(capsys, fixture_path):
    exit_code = main([str(fixture_path("fixture3_nx_canary_server")), "--stage", "canary"])
    assert exit_code == 0
    out = capsys.readouterr().out
    assert "Offset to canary: 72 bytes" in out
    assert "Canary: " in out


def test_stage_chainer_with_server_auto_detects_canary(capsys, fixture_path):
    exit_code = main(
        [
            str(fixture_path("fixture3_nx_canary")),
            "--server",
            str(fixture_path("fixture3_nx_canary_server")),
            "--stage",
            "chainer",
            "--run",
        ]
    )
    assert exit_code == 0
    out = capsys.readouterr().out
    assert "Chain (" in out
    assert "Shell verified" in out


def test_stage_chainer_with_server_handles_pie_and_canary_together(capsys, fixture_path):
    # fixture5_nx_pie_canary — PRD.md's "hardest tier" — exercised via the
    # actual CLI entrypoint, not just the underlying library functions
    # directly (as test_canary.py's own fixture5 test does): confirms the
    # same --server auto-detection path used above also handles PIE and
    # canary together, with no extra flags or special-casing needed.
    exit_code = main(
        [
            str(fixture_path("fixture5_nx_pie_canary")),
            "--server",
            str(fixture_path("fixture5_nx_pie_canary_server")),
            "--stage",
            "chainer",
            "--run",
        ]
    )
    assert exit_code == 0
    out = capsys.readouterr().out
    assert "Chain (" in out
    assert "Shell verified" in out


@pytest.mark.parametrize("stage", ["exploit"])
def test_unimplemented_stage_reports_clearly(capsys, fixture_path, stage):
    exit_code = main([str(fixture_path("fixture1_none")), "--stage", stage])
    assert exit_code == 1
    assert stage in capsys.readouterr().err


def test_stage_rejects_unknown_choice():
    parser = build_parser()
    with pytest.raises(SystemExit):
        parser.parse_args(["binary", "--stage", "bogus"])
