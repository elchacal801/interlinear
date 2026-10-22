import json
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def test_package_version():
    import interlinear_cti

    assert interlinear_cti.__version__ == "0.1.2"


def test_every_version_string_agrees():
    import interlinear_cti

    pyproject = re.search(r'^version = "([^"]+)"', (ROOT / "pyproject.toml").read_text(encoding="utf-8"), re.M)
    plugin = json.loads((ROOT / "plugin" / ".claude-plugin" / "plugin.json").read_text(encoding="utf-8"))
    changelog = (ROOT / "CHANGELOG.md").read_text(encoding="utf-8")
    assert pyproject.group(1) == plugin["version"] == interlinear_cti.__version__
    assert f"## {interlinear_cti.__version__} (" in changelog
