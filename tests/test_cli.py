from rop_forge.cli import build_parser, main


def test_parser_requires_binary():
    parser = build_parser()
    args = parser.parse_args(["fixtures/build/fixture1"])
    assert args.binary == "fixtures/build/fixture1"
    assert args.run is False


def test_main_returns_nonzero_until_pipeline_exists(capsys):
    exit_code = main(["fixtures/build/fixture1"])
    assert exit_code == 1
