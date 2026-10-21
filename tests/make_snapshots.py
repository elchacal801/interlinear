"""Regenerate the approved snapshot copies in tests/fixtures/approved/. Review every diff before committing."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))


def main() -> None:
    from conftest import FakeResolver
    from test_fixtures import APPROVED, INPUTS, glossed, scenario_text

    from interlinear_cti.render import render_markdown

    APPROVED.mkdir(exist_ok=True)
    wanted = set()
    for path in INPUTS:
        transcript = glossed(path, FakeResolver())
        names = (f"{path.name}.md", f"{path.name}.scenario.json")
        wanted.update(names)
        (APPROVED / names[0]).write_text(render_markdown(transcript), encoding="utf-8", newline="\n")
        (APPROVED / names[1]).write_text(scenario_text(transcript), encoding="utf-8", newline="\n")
        print(f"wrote {names[0]} and {names[1]}")
    for stale in sorted(APPROVED.iterdir()):
        if stale.name not in wanted:
            stale.unlink()
            print(f"removed {stale.name}")


if __name__ == "__main__":
    main()
