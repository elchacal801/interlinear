# Interlinear design

How Interlinear is built and why. The [README](../README.md) covers installation and use, and
[evaluation.md](evaluation.md) covers how far to trust each label.

## Purpose

Interlinear turns attacker transcripts into interlinear glosses. Under every line an attacker or an offensive AI agent
typed, it adds what the line does in plain English, the MITRE ATT&CK® or ATLAS techniques it maps to, the artifacts and
IOCs it touches, and where that gloss came from. The name comes from interlinear glossed text in linguistics: an
original line with an aligned gloss beneath it.

The inputs are shell histories, dropped scripts and AI-agent logs collected from attacker infrastructure. The outputs
feed case files, write-ups and Countermap threat models.

## Pipeline

```
raw files (in a sandbox)
   |  interlinear parse          standard library only; no network, never executes its input
   v
transcript.json   (normalized, defanged lines; file hashes; actors; every gloss "pending")
   |  interlinear gloss          the rule library; Countermap verifies technique IDs
   v
transcript.json   (rule and context glosses filled; the rest stays "pending")
   |  /interlinear:gloss         Claude Code skill; submits through interlinear apply-glosses
   |  interlinear annotate       analyst glosses, which may replace any gloss
   v
transcript.json
   |-- interlinear render           -> transcript.md (the interlinear view)
   |-- interlinear export-scenario  -> scenario.json (a Countermap scenario)
```

`transcript.json` is the only interface between stages, so parsing can run in a locked-down sandbox while glossing,
rendering and export run anywhere.

## Safety model

- **Stage separation.** `interlinear parse` is the only command that opens raw files. Every other command refuses an
  input that is not a valid `transcript.json`.
- **No execution and no network in parse.** The parse path uses only the standard library, imports no networking
  module, never imports pydantic, PyYAML or Countermap, and never starts a process. `interlinear build-parse-pyz`
  packages it as a single zipapp, so a sandbox needs nothing but a Python interpreter. Tests enforce all of this with
  patched sockets and an audit hook.
- **Hostile files and folders.** Folders are walked without following links, only regular files are opened, and every
  file and run is capped in bytes, lines, files, warnings and depth. Binary files are recorded by hash only.
- **Defanging.** URLs, IPv4 and IPv6 addresses and domains are made non-clickable at parse time (`hxxp://`,
  `203.0.113[.]5`, `2001[:]db8[:][:]1`), including leading-zero octets, full-width dots and bracketed hosts. Defanging
  is idempotent.
- **Blobs and long lines.** Runs of 200 or more base64 or hex characters become `<blob sha256=… len=…>`, and lines over
  4,096 characters are cut with a hash of the full text.
- **Hidden characters.** Control characters are shown as control pictures, and format and other invisible characters
  as `⟨U+XXXX⟩`, so text such as `cu⟨U+034F⟩rl` cannot pass for `curl`.
- **Untrusted glosses.** The model that writes glosses has read attacker text and may be prompt-injected.
  `apply-glosses` and `annotate` validate every entry with strict types and limits, pass its free text through the same
  normalizer as parse, defang every IOC, and never echo raw input in an error.
- **Inert outputs.** The Markdown view keeps all transcript text inside code, the export shows hidden characters and
  defangs after every cut, and `render` never writes an agent instruction file such as `CLAUDE.md`.

## Data model

`transcript.json` holds the sources (name, SHA-256, size, kind, why a file was rejected), the lines and the warnings.
Each line has its position, its source file and line number, an optional UTC timestamp, an actor and the normalized
text, plus its gloss and any earlier glosses an analyst replaced. The schema forbids unknown fields at every level.

**Actors.** `operator` (a human-typed command), `agent_tool` (a tool call), `agent_reasoning` (the agent's own text),
`tool_output` (recorded, never glossed) and `unknown`.

**Gloss sources.**

| Source | Meaning | `by` |
|---|---|---|
| `rule` | Matched a rule in the library | `rules <version>` |
| `model` | Written by the gloss skill through `apply-glosses`, which only fills pending lines | the model ID |
| `analyst` | A person's edit through `annotate`; the earlier gloss moves to the line's history | the analyst's name |
| `none` | A context line a rule recognized, or tool output | `rules <version>` |
| `pending` | Not glossed yet | none |

A model's or analyst's context gloss keeps its own source, so a reader can always tell who decided a line is context.

**Agent logs.** The generic format is one JSON object per line with `role` (`user`, `assistant`, `tool_call`,
`tool_result`) and one text field per role. A tool call that holds several commands is split into one line per
command, each with a `part` entry that records its place in the call.

## Rule library

The rules are YAML files in `interlinear_cti/rules/`, versioned in `rules/VERSION`. A rule has an ID, a regex, a
meaning, techniques, artifacts, the IOC extractors to run, a confidence, and `match` and `no_match` examples.

- **First match wins.** Files load in name order and rules in file order, so order is priority: context rules first,
  then persistence writes, then transfer and execution, with specific rules before general ones.
- **Commands only.** Rules gloss history and script lines, agent tool calls and lines of unknown format. They never
  gloss agent reasoning, chat or tool output, where a matched word would claim a technique nobody ran.
- **Placeholders.** Regexes use placeholders for the command position (`{cmd}`), which steps over wrappers such as
  `sudo`, `nohup` or `env`, and for the start of any simple command (`{stage}`), the end of a command word and so on.
- **Linear time.** Rule regexes run on attacker-written lines, so `interlinear rules test` times every rule on
  adversarial lines and fails any that grows faster than linear, then checks every example against the whole library.
- **Verification.** Loading the library through Countermap checks every technique ID; a revoked or unknown ID fails the
  load.

### CONTEXT is default-deny

A line gets the context label only when it passes three gates: it is plainly literal printable ASCII of a shape the
rules understand; its file or session has not changed how later commands run (an alias, a function, a shell option, a
sourced file, `PATH` or another special variable); and the file holds no NUL, carriage return or other control
character, except a PowerShell file whose line endings are all CRLF. Everything else goes to the model. The README and
[evaluation.md](evaluation.md) give the full rule and how it was tested.

## Countermap integration

- **Verification.** Technique IDs are checked through Countermap's Python API against its local MITRE data. Only
  canonical IDs (`T1234`, `T1234.001`, `AML.T0051`) are looked up. Countermap is an optional extra.
- **Scenario export.** `export-scenario` reads only the transcript and never imports Countermap. Each step is a run of
  consecutive glossed lines from one source file that share a primary technique and actor. Context, pending and tool
  output lines are skipped, steps built only from model glosses say so, and all text is capped and defanged. The
  scenario can then be drawn with `countermap render` or `/countermap:threat-model`.

## Testing

- **Fixtures** are synthetic bash, zsh and PowerShell histories, shell and PowerShell scripts and agent JSONL, using
  only documentation addresses and reserved names.
- **Safety tests** parse with sockets and processes patched to fail and under an audit hook, and check that no
  networking module, pydantic, PyYAML or Countermap was loaded.
- **A defang sweep** checks every fixture's text, IOCs, view and scenario for live URLs, addresses and domains.
- **Hardening suites** feed crafted input to the readers, normalizer, parser, IOC extraction, glossing, rules and
  verification. The default-deny suite runs every known context bypass through every reader.
- **Snapshot tests** compare each fixture's Markdown view and scenario with approved copies.
- **Integration tests**, marked `countermap`, run real technique lookups and render the export in every Countermap
  format when the package and its database are present.

## Known limitations

- **`ftp://` with a single-label host stays live,** since only `http` and `https` schemes are rewritten and only
  dotted hosts are defanged.
- **IDN hosts in free text stay live,** since domain defanging reads ASCII labels and TLDs. IOCs in glosses files are
  defanged whatever their labels.
- **Bare names with a TLD that doubles as a file extension stay live,** such as `evil.example.zip`, so script names stay
  readable and matchable.
- **The shell and PowerShell scans are approximations.** The comments in `normalize.py`, `iocs.py` and
  `readers/script.py` list their known gaps.
- **Technique tags are role-blind,** and rule glosses of wrappers such as `docker exec` or `ssh host "..."` leave the
  inner command unexplained. See [evaluation.md](evaluation.md).

## Later

- A PentAGI reader, once its log structure is documented from real samples.
- An HTML viewer, honeypot session logs, translation of non-English comments, and a branching scenario export.
