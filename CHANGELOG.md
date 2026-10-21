# Changelog

All notable changes to Interlinear are recorded here. Versions follow [Semantic Versioning](https://semver.org/).

## 0.1.0 (2026-10-21)

The first release.

### Readers

- Bash and zsh histories, PowerShell `ConsoleHost_history.txt`, shell scripts, PowerShell scripts and generic AI-agent
  JSONL transcripts. A file's name or content decides how it is read; anything else is kept line by line as `unknown`.
- Multi-line commands (continuations, quoted newlines, arrays, pipelines and heredocs) are read as one record, then
  split at the newlines, `;`, `&&`, `||` and `&` that end a command. An oversized heredoc body is split with a warning
  instead of being truncated.
- An agent tool call that holds several commands is glossed one command at a time. Each part records where it came
  from in a `part` entry: its index, the number of parts and its offset in the command as the agent sent it. The first
  part also holds the whole command, which the Markdown view shows above the parts.

### Safety

- Only `interlinear parse` reads raw attacker files. It is standard-library Python that never executes its input,
  opens no network connections, defangs URLs, IPs and domains, and replaces encoded blobs with their SHA-256.
  `interlinear build-parse-pyz` packages it as a single zipapp to run in a sandbox.
- Every later stage reads only the resulting `transcript.json`.

### Glosses

- Every gloss is labeled by its source: `rule`, `model`, `analyst`, `none` (context) or `pending`.
- The rule library, version 2026.10.6, holds 90 rules mapped to MITRE ATT&CK and ATLAS techniques, each with match
  and no-match examples that `interlinear rules test` checks (`--verify` also checks every technique ID).
- The context label is default-deny. A line is labeled context only when it is plainly literal printable ASCII, and
  only while its file or session has not changed how later commands are found or run (an alias, a function, a shell
  option, a sourced file, `PATH` or another special variable). A file or session with a NUL, a carriage return or
  another control character gets no context label. The README explains what the label does and does not promise.
- A PowerShell history or script whose line endings are all CRLF is read as if they were LF, so Windows files keep the
  context label. A lone CR, mixed line endings or any other control character still removes it, and bash, zsh and sh
  files with CRLF never get it.
- Technique IDs are checked against Countermap's local MITRE data, through the `countermap` extra
  (`countermap>=0.2,<0.3`).

### Claude Code plugin

- The `gloss` skill glosses the lines the rule library could not and submits them through
  `interlinear apply-glosses`, which validates, defangs and bounds them and labels them `model`. Analysts record their
  own glosses with `interlinear annotate`.
- The skill runs on Haiku by default, which matched Opus on meaning and technique in trials on agent transcripts. Its
  report lists every line left pending or glossed with low confidence, for an analyst to review.

### Outputs

- `transcript.json`, the source of truth for every later stage.
- `interlinear render`: a Markdown interlinear view.
- `interlinear export-scenario`: a Countermap scenario that Countermap can draw.

### Documentation

- `docs/design.md`: the pipeline, the safety model, the data model, the rule library and the known limits.
- `docs/evaluation.md`: how far to trust each label, how the default-deny CONTEXT gates were tested, a sampled check
  of rule glosses, coverage on public AI-agent duel transcripts, the model-tier trials, and the known limits.

### Not yet included

- A dedicated PentAGI reader, which waits for documented real samples.
