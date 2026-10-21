"""Command-line checks not covered by a stage's own tests: rules list, the zipapp build's write errors, and counts."""

import pytest

from interlinear_cti import cli
from interlinear_cti.rules import load_library


@pytest.mark.parametrize("n, text", [(0, "0 failures"), (1, "1 failure"), (2, "2 failures")])
def test_counts_read_correctly_for_one(n, text):
    assert cli._count(n, "failure", "failures") == text


@pytest.mark.parametrize("extra, tail", [(1, "  ... and 1 more rejection"), (2, "  ... and 2 more rejections")])
def test_the_tail_after_100_messages_counts_in_the_singular_too(capsys, extra, tail):
    cli._print_some([f"line {k}: no such line" for k in range(100 + extra)], "rejected", "rejection", "rejections")
    lines = capsys.readouterr().err.splitlines()
    assert len(lines) == 101 and lines[-1] == tail


def test_rules_test_counts_examples_and_failures(capsys):
    assert cli.main(["rules", "test"]) == 0
    assert capsys.readouterr().out.rstrip().endswith(" examples checked, 0 failures")


def test_rules_list_prints_every_rule_then_the_count_and_version(capsys):
    assert cli.main(["rules", "list"]) == 0
    lines = capsys.readouterr().out.splitlines()
    library = load_library()
    assert lines[-1] == f"{len(library.rules)} rules, version {library.version}"
    assert [line.split()[0] for line in lines[:-1]] == [rule.id for rule in library.rules]
    context = [line for line, rule in zip(lines, library.rules) if rule.context]
    assert context and all(line.split()[1] == "context" for line in context)


def test_build_parse_pyz_exits_3_when_the_output_cannot_be_written(tmp_path, capsys):
    blocker = tmp_path / "blocker"
    blocker.write_text("x", encoding="utf-8")
    assert cli.main(["build-parse-pyz", "-o", str(blocker / "interlinear-parse.pyz")]) == 3
    assert "cannot write output" in capsys.readouterr().err
