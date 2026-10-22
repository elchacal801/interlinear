# Changelog

All notable changes to Interlinear are recorded here. Versions follow [Semantic Versioning](https://semver.org/).

## 0.1.2 (2026-10-22)

Fixes from an external review of 0.1.1, which used synthetic inputs only. Rules 2026.10.8.

### Redaction

- Quoted passwords are redacted whole: after `user:` in `user:'pass word'@host`, after impacket's
  `domain/user:'...'` (and a whole quoted target, `'domain/user:pass word'`), after `curl -u user:'...'` and
  `smbclient -U user%'...'` (or with the whole credential quoted), and glued to `-p` (`mysql -p'...'`, `7z -p"..."`).
  0.1.1 left them in `interlinear pending` output when the line was still pending, so the gloss skill could send them
  to the hosted model.
- A secret matched by two patterns is redacted once. 0.1.1 turned `secretsdump.py domain/user:pw@host` into
  `user:<redacted password> password>@host`, and redacting that text again changed it again. Patterns for a known
  tool now run first, and a value that overlaps an existing marker is left alone.

### Rules

- A script run through the interpreter is the command: `python3 secretsdump.py ...`,
  `python3 /opt/impacket/examples/psexec.py ...` and the other Impacket examples get the same rules as when run by
  name. Only python's flags that take no argument are stepped over; after `-c`, `-m` or `-W`, python stays the command.
- The PowerShell download cradle (`IEX (New-Object Net.WebClient).DownloadString('...')`) is no longer marked
  partial because of the URL or variable inside `DownloadString(...)`. A later pipeline stage still makes it partial.
- `http-upload` says "a remote web or FTP server", since `curl -T FILE ftp://...` is one of its forms.

## 0.1.1 (2026-10-22)

Fixes from an external review of 0.1.0, which used synthetic intrusions only.

### Glosses

- A rule gloss can now be partial. A rule describes the command it matched; when the line also runs something the
  rule does not describe (a later pipeline stage that runs a shell, a command substitution, any tool other than one
  that prints, reads or filters text), the gloss is marked `partial` with the reason and the line still goes to the
  model, whose gloss replaces it. Before, `echo <base64> | base64 -d | bash` got only T1140 and the model never saw
  that the decoded content runs.
- `interlinear pending` lists partial lines with what the rule found (`rule.id`, `rule.techniques`, `rule.partial`),
  and the Markdown view marks them `[rule: ID; partial]`. `crontab -l` counts as read-only, so the usual
  `(crontab -l; echo ...) | crontab -` append stays a whole `cron` gloss.
- A word with `=` after the command word is an argument, not an assignment, so `echo <base64>== | base64 -d` no longer
  ends context for the rest of its file. Before the command word, and as an argument of `export`, `declare`,
  `typeset`, `local`, `readonly` or `let`, it still does. Every default-deny probe still passes.
- A line whose text addresses whoever reads the transcript ("ignore all previous instructions", "note to the
  reviewer") is never labeled context, is marked `aimed_at_reader` in `pending`, and gets a warning in the Markdown
  view.

### Decoded payloads

- `interlinear parse` decodes encoded payloads as plain data, never running them: base64 on a line that also decodes
  base64, and PowerShell `-EncodedCommand` blobs (UTF-16LE). What a payload holds becomes child lines after its line,
  defanged, with a `decoded` entry that names the parent line, the encoding, the nesting depth and the payload's
  SHA-256 and length (the blob marker in the parent keeps the same hash). Child lines go through the rules, IOC
  extraction and the model, and are never labeled context. A payload decodes to at most 64 KiB, a command gives at
  most 8 payloads and 64 child lines, and payloads inside payloads are decoded to 3 levels. The parse stage is still
  standard-library Python only.

### Secrets

- `interlinear pending`, whose output the gloss skill sends to a hosted model, now redacts credentials by default:
  passwords, tokens, keys and hashes become `<redacted KIND>`. `--no-redact-secrets` turns that off.
- `interlinear render --redact-secrets` redacts the Markdown view the same way. `transcript.json` keeps every
  credential as evidence.
- Forms covered include `--password` and `-Password`, `-p` to tools that take a password, `user:password@host`,
  impacket's `domain/user:password`, `net user NAME PASSWORD`, credential-named variables, `Authorization` and
  `Cookie` headers, and AWS, GitHub, Anthropic, OpenAI and Slack token formats and JWTs. Redaction is a best effort,
  not a guarantee.

### Scenario export

- `export-scenario` chains steps only within each source file. Files are parallel lanes, since nothing in them orders
  one host's history against another's, and each step names its file when there are several. `--source NAME_OR_ID`
  exports one file alone.
- Back-to-back lines with the same technique become one step, whatever the actor.
- A line whose text addresses an analyst or an AI model rather than the target (possible prompt injection) is left
  out of the scenario, with a warning.

### Rules

- Rule library 2026.10.7: 109 rules. New: `decode-pipe-shell` (T1140, T1059.004), and a Windows, Active Directory and
  cloud pack of 18 rules: DCSync, NTDS, SAM and LSASS dumps (including comsvcs.dll MiniDump), shadow copy and
  recovery deletion, Kerberoasting and AS-REP roasting, evil-winrm and NetExec pass the hash, WinRM, NetExec password
  spraying, PsExec and smbexec, WMI execution, BloodHound collection, credential files such as `~/.aws/credentials`,
  the cloud metadata service, `sudo -l`, and HTTP uploads of host data (a system, home or user file, or an archive,
  database, document, dump, backup or key) with `curl -T`, a form upload or an `Invoke-WebRequest` POST. Every
  technique is checked against MITRE ATT&CK 20.0.
- On the OpenRAE Duels agent traces, rule coverage of red tool lines went from 7.7% to 8.4%, with no line wrongly
  labeled context. docs/evaluation.md has the details.
- `sudo -l` was not glossed before; it now gets `sudo-list` (T1548.003).

### Upgrading

- 0.1.1 reads transcripts written by 0.1.0. It writes the new `partial` and `decoded` fields only when a line has
  them, so 0.1.0 still reads a 0.1.1 transcript that has none; one that has them needs 0.1.1.

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
