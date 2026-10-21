"""The install hints in the CLI's error, the gloss skill and the README: the PyPI forms for pipx, uv and pip, each
with the countermap extra and `countermap build`, and Countermap's range the same as the extra's."""

import re
from pathlib import Path

import pytest

from interlinear_cti.verify import INSTALL_HINT

ROOT = Path(__file__).resolve().parent.parent


def read(*parts):
    return (ROOT.joinpath(*parts)).read_text(encoding="utf-8").replace("\r\n", "\n")


def extra_range():
    found = re.search(r'^countermap = \["countermap(?P<range>[^"]+)"\]$', read("pyproject.toml"), re.MULTILINE)
    assert found, "pyproject.toml has no countermap extra"
    return found["range"]


def hints():
    return {
        "verify.INSTALL_HINT": INSTALL_HINT,
        "SKILL.md": read("plugin", "skills", "gloss", "SKILL.md"),
        "README.md": read("README.md").split("## Install", 1)[1].split("\n## ", 1)[0],
    }


@pytest.mark.parametrize("name", ["verify.INSTALL_HINT", "SKILL.md", "README.md"])
def test_each_hint_gives_the_pypi_forms_and_the_database_build(name):
    text = hints()[name].replace('"', "'")
    assert "pipx install 'interlinear-cti[countermap]'" in text
    assert f"pipx inject --include-apps --force interlinear-cti 'countermap{extra_range()}'" in text
    assert "uv tool install 'interlinear-cti[countermap]' --with-executables-from countermap" in text
    assert "pip install 'interlinear-cti[countermap]'" in text
    assert "countermap build" in text
    assert "git+" not in text


def test_the_cli_hint_is_one_line():
    assert "\n" not in INSTALL_HINT
