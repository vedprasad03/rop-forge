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


@pytest.mark.parametrize("stage", ["chainer", "leak", "exploit"])
def test_unimplemented_stage_reports_clearly(capsys, fixture_path, stage):
    exit_code = main([str(fixture_path("fixture1_none")), "--stage", stage])
    assert exit_code == 1
    assert stage in capsys.readouterr().err


def test_stage_rejects_unknown_choice():
    parser = build_parser()
    with pytest.raises(SystemExit):
        parser.parse_args(["binary", "--stage", "bogus"])
