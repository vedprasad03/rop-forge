from rop_forge.cli import build_parser, main


def test_parser_requires_binary():
    parser = build_parser()
    args = parser.parse_args(["fixtures/build/fixture1"])
    assert args.binary == "fixtures/build/fixture1"
    assert args.run is False


def test_main_returns_nonzero_until_pipeline_exists(capsys, fixture_path):
    exit_code = main([str(fixture_path("fixture1_none"))])
    assert exit_code == 1
    assert "NX:" in capsys.readouterr().out


def test_main_reports_missing_binary():
    exit_code = main(["fixtures/build/does_not_exist"])
    assert exit_code == 2
