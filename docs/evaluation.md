# How far to trust Interlinear's labels

This page is for analysts deciding how much weight to give each gloss in an Interlinear transcript. It says what each label promises, how those promises were tested, and where they stop.

In short:

| Label | What it promises | How to treat it |
|---|---|---|
| `rule` | A deterministic match against the rule library. The same line always gets the same gloss. | Reliable for the common shape of a command. Check the technique tag on defender transcripts (see [Known limits](#6-known-limits-and-open-design-questions)). |
| `none` (CONTEXT) | The line is plainly literal and its file or session has not changed how commands run. | Safe to skim. It is an aid, not a guarantee against a transcript crafted to mislead. |
| `model` | Claude's analysis of the line, validated and defanged by `apply-glosses`. | A good first reading. Not ground truth. |
| `analyst` | A person's edit, recorded with their name. | As good as the analyst. |
| `pending` | Nothing has glossed the line yet. | Read it yourself. |

## 1. What each label promises

### Rule glosses are deterministic

A `rule` gloss comes from a pattern in the rule library (version 2026.10.6 at the time of writing; 2026.10.7 in Interlinear 0.1.1, section 4). It has no model in the loop, so the same line gets the same meaning, techniques and IOCs on every run. Its accuracy is the accuracy of the rule: section 3 measures it on a sample.

### CONTEXT is a default-deny allowlist

A line gets CONTEXT (`none`) only when it passes three gates. Anything that fails a gate goes to the model or stays pending; nothing is labeled context by default.

1. **Literal gate.** The line is printable ASCII with no expansion, substitution, glob, redirection, pipe or separator, and it is one of the shapes the rules positively understand, such as `cd /tmp`, `ls -la` or `echo done`.
2. **Session-taint gate.** The line comes from a history, script or agent session that has not changed how later commands are found or run. Once a session defines an alias or a function, sets a shell option, sources a file, or assigns `PATH` or another special, uppercase or credential name, no later line from it is labeled context. The transcript's warnings name the line where that happened.
3. **Byte-taint gate.** The file or session holds no NUL, carriage return or other control character, since those can make a shell read a line differently than it is stored. The one exception is a PowerShell file whose line endings are all CRLF, which PowerShell reads as plain line ends.

The README section [What the CONTEXT label means](../README.md#what-the-context-label-means) gives the full rule.

A synthetic example of the session-taint gate, simplified from the Markdown view:

```text
  3  cd /opt/app                 none     (literal, session still clean)
  4  TARGET=web01                pending  (assigns an uppercase name: the session is now tainted)
  5  echo "--- done ---"         pending  (literal, but after the taint)
```

### Model glosses are model analysis

A `model` gloss is written by the gloss skill (Claude, on Haiku by default) for a line the rules did not cover. `interlinear apply-glosses` checks its technique IDs against Countermap's MITRE data, defangs it, bounds its length and labels it `model`, and it only fills pending lines. It never overwrites a rule, context or analyst gloss. The model's reading is usually right (section 5) but it is still an opinion about the line.

### Pending lines are for the analyst

A line stays `pending` when no rule matched, it failed a context gate, and the model left it out or its output was stopped. The gloss skill ends with a list of those lines, plus every line it glossed with `low` confidence, for an analyst to review and record with `interlinear annotate`.

## 2. How the default-deny design was tested

The CONTEXT gates were built from bypasses found in several review rounds, and each bypass became a probe in the test suite.

- **What the probes are.** `tests/test_default_deny.py` holds the probes: a record that changes session state followed by a literal command that now runs code (aliases, functions, `hash -p`, `enable -n`, traps, `PATH`, `PROMPT_COMMAND`, `source`, `eval`, `set -k` and the zsh forms of these), bytes that a shell reads differently than they are stored (NUL, lone CR, backslash before a control byte), lines that read as context but are not (`env -S`, Docker global options, a no-break space, letters that fold to ASCII), and the forms found in earlier rounds. `tests/test_context_shapes.py` and the hardening suites (`test_parse_hardening.py`, `test_readers_hardening.py`, `test_normalize_hardening.py`, `test_glossing_hardening.py`, `test_rules_hardening.py`, `test_iocs_hardening.py`, `test_verify_hardening.py`) cover the parser, readers, normalizer and rules the gates depend on.
- **Every reader.** Each probe runs through the real path (`parse_paths` on a file, then the rule library) as a bash history, a zsh history, a shell script, an agent log with one tool call per line, and an agent log with the whole probe as one multi-command tool call, which Interlinear splits into its commands.
- **The pass condition.** No line that runs code may be labeled context, or be claimed by a persistence-write rule that would describe the record while hiding what it runs. A matching set of plain lines must still get context, so the gates are not simply closed.

All probes pass in every reader, including the multi-command agent call. Attack-like text in these tests is assembled from fragments at runtime.

## 3. Rule precision

**Method.** 25 rule-glossed agent tool lines were drawn at random from the agent transcripts described in section 4, before the fixes below. The sample was stratified rather than proportional: 13 red (offense) lines and 12 blue (defense) lines, with the `container-exec` rule (`docker exec`) capped at 3 so it did not dominate. Each gloss was checked for its meaning, its ATT&CK technique and its IOCs.

| Check | Correct | Rate (95% Wilson interval) |
|---|---|---|
| Meaning describes the line | 23 / 25 | 92% (75-98%) |
| Technique right at parent level | 24 / 25 | 96% (81-99%) |
| Technique right at sub-technique level | 23 / 25 | 92% (75-98%) |

**The two errors, both now fixed:**

- `nmap -sn <subnet>` is a host ping sweep, but the `network-scan` rule glossed it as a port scan and tagged T1046. `nmap -sn` and `-sP` now go to the rule `host-discovery-scan`, tagged T1018 (Remote System Discovery).
- `hydra -C <pairs file>` tries login and password pairs, which is credential stuffing, but the `brute-force` rule tagged it T1110.001 (Password Guessing). `hydra -C` and `medusa -C` now go to the rule `credential-stuffing`, tagged T1110.004.

The sample also turned up a loopback address reported as an IOC. Glosses no longer report loopback or link-local addresses.

These fixes correct rules that were wrong on any input; they were not fitted to the evaluation data. With n = 25, the intervals are wide: the result says the rules are usually right, not how often they are wrong to within a few points.

## 4. Coverage on agent transcripts

**Data.** OpenRÆ Duels v1.0.0 ([Hugging Face `openrae/duels`](https://huggingface.co/datasets/openrae/duels)), a public set of red and blue AI-agent traces from supervised attack and defense duels on a cyber range, released under CC BY 4.0. Citation:

> Edwards, B. (2026). *OpenRÆ Duels: BSidesNYC 2026 Red-Blue Agent Traces* (Version 1.0.0) [Data set]. Zenodo. https://doi.org/10.5281/zenodo.23459249

The traces were converted to Interlinear's generic agent log format and run through `interlinear parse` and `interlinear gloss` in an isolated sandbox. The input was the three episodes the dataset marks as approved that have the most tool calls, red and blue sides each. This was evaluation only: nothing in Interlinear was tuned to this data, and none of it is in the repository.

**Results** (rules 2026.10.6, agent tool lines only; tool output is never glossed):

| Side | Lines | Rule | CONTEXT | Pending |
|---|---|---|---|---|
| Red | 1,541 | 118 (7.7%) | 4 (0.3%) | 1,419 (92.1%) |
| Blue | 987 | 335 (33.9%) | 11 (1.1%) | 641 (64.9%) |

- **Wrong CONTEXT: 0 of 2,528 lines.** All 15 CONTEXT lines are literal `echo "..."` lines, such as a separator or a "nothing found" message. None runs code.
- **Rule coverage is low on agent work.** Agents write long multi-line calls with inline Python and heredocs, which the rule library mostly does not cover. Blue coverage looks higher only because of `docker exec`: 282 of the 335 blue rule lines are `container-exec`. Without it, blue rule coverage is about 5%, close to red. The rules that do fire fit the offense: network and host discovery, file discovery, brute force and credential stuffing, password cracking, SSH, Python execution.
- **Most lines go to the model.** That is the cost of default-deny on this kind of input, and the reason the model stage and the analyst list matter.

**Why there was no wrong CONTEXT, and why so much is pending.** Session taint ends context early. In each of the six transcripts, a record between record 23 and record 76 (of about 460) could change how later commands run: an assignment to an uppercase name in three of them, and an array assignment, `source` or a `for` loop variable in one each. After that record, no line of the session was eligible for context, so only a handful of literal lines before it got the label.

This is stricter than these sessions needed. Both agents' tools run each call in a fresh shell: the red tool opens a new SSH exec channel per call, and the blue agent's Bash tool runs each command in a separate process, so environment variables, functions and aliases set in one call do not reach the next (the blue tool does keep the working directory). Interlinear does not assume that, and treats the whole session as one taint unit. The zero is therefore what a conservative design should produce here, not a test of the gates against a hostile transcript. Section 2 is that test.

### Re-run with Interlinear 0.1.1

The same JSONL was parsed and glossed again with 0.1.1 (rules 2026.10.7: a decode-pipe-shell rule, a Windows, Active Directory and cloud pack, partial rule glosses, decoded payloads and redaction in `pending`), in the same sandbox.

| Side | Lines | Rule, 0.1.0 to 0.1.1 | Of which partial | CONTEXT | Pending |
|---|---|---|---|---|---|
| Red | 1,541 | 118 (7.7%) to 129 (8.4%) | 2 | 4 (0.3%) | 1,408 (91.4%) |
| Blue | 987 | 335 (33.9%) to 336 (34.0%) | 7 | 11 (1.1%) | 640 (64.8%) |

- **Wrong CONTEXT: still 0.** Partial lines go to the model as well as pending ones.
- **New rules:** 12 hits on red (`impacket-secretsdump` against the domain controller as DCSync 6, `sudo -l` 3, Kerberoasting 1, NetExec password spraying 1) and 1 on blue (a `.env` file read). All 12 red hits were judged correct by hand.
- **One rule corrected on this data.** The first 0.1.1 run also glossed 3 red lines as HTTP exfiltration. All three were the attacker uploading its own scratch files to the target's upload form, which is ingress. The command does not show the direction, so `http-upload` now claims only a file that looks like host data (a system, home or user folder; an archive, database, document, dump, backup or key) and leaves the rest to the model. The rule was wrong on any such input; the fix was not fitted to the numbers.
- **Redaction.** A scan of the text `pending` sends to the model found one password left visible: impacket's `domain/user:password` with the host given by `-dc-ip`. That form, and literal cookie values, are now redacted. Passwords in form data (`password=...`) and `PGPASSWORD=` were already redacted.
- **No decoded payloads.** None of these episodes holds base64 or `-EncodedCommand` text that decodes to text, so the decoder was not exercised here; its tests use synthetic intrusions.

## 5. Model-tier trials

**Method.** Two trials, each on 50 distinct pending lines from the same transcripts (30 red, 20 blue, spread across command families, with few trivial lines such as comments and echoes). Secrets were masked before any model saw the lines. Each model glossed the same lines under the gloss skill's rules (meaning, ATT&CK IDs, context flag, confidence). A reference key was written before any model output was read: acceptable technique IDs at parent level for each line, and a flag on every line that performs an action, where a context label would be a serious miss.

| Model | Runs | Meaning right | Technique acceptable | Action lines labeled context |
|---|---|---|---|---|
| Haiku | 2 of 2 delivered | 100 / 100 | 96 / 100 | 0 |
| Opus | 1 of 2 delivered | 50 / 50 | 49 / 50 | 0 |
| Sonnet | 0 of 1 delivered | - | - | - |

- **Haiku matched Opus** on meaning and technique where both delivered. Most of the technique misses on both sides were role-blind tags on defender lines (see section 6), not misreadings of the line. They differed on 6 borderline lines, where Opus labeled the line context and Haiku labeled it an action with low or medium confidence.
- **Classifier stops: 2 of 5 runs.** A safety classifier stopped the Sonnet run in the first trial and the Opus run in the second, each partway through, with nothing delivered. With n = 5 this does not show that one tier is stopped more often than another. It does show that any tier may return nothing for a batch of offensive content.
- **Confidence did not flag the errors.** Haiku marked 3 of 50 lines low confidence in the second trial, but none of its 3 technique misses was among them. A rule that sends low-confidence lines to a stronger model would not have caught them.

**What this means for the defaults.**

- The gloss skill runs on Haiku (`model: haiku` in its frontmatter). It was as accurate as Opus on these lines, it delivered on both trials, and it is the cheapest tier.
- There is no automatic fallback to a stronger model. It would not have caught Haiku's actual errors, and it may be stopped. Instead, the skill lists every line it left out or glossed with low confidence for an analyst, and lines from a stopped batch stay pending.

## 6. Known limits and open design questions

### Open design questions

- **Role-blind technique tags.** Techniques are tagged by what a command does, not by who runs it. In a defender transcript, a `docker exec` into a container gets T1609 and log collection over SSH gets T1021.004. The meaning is right, but these are not techniques used against anyone. All 12 blue lines in the precision sample had this issue. Until Interlinear knows a transcript's role, read technique tags on defender transcripts as "behavior match", and take care when exporting them to a threat model.
- **Wrapper-only glosses.** For `docker exec ...`, `ssh host "..."` and `python3 -c "..."`, the rule glosses the wrapper and leaves the inner command unexplained. 7 of the 25 sampled lines were like this. They were counted as correct, but they are shallow: read the inner command yourself.
- **Per-call taint.** Making each agent tool call its own taint unit would be correct for tools that start a fresh shell per call, as both Duels agents do, as long as writes that cross calls through the file system (a shell startup file, `ld.so.preload`, a directory on `PATH`) stay session-wide taints. In a simulation, this would move pending from 92.1% to 81.1% on red and from 64.9% to 58.6% on blue, with every newly labeled line passing the literal gate. It is not implemented: whether a tool starts a fresh shell is a property of the agent, not of the transcript.
- **Duplicate-text dedup.** Agents repeat lines. The 1,419 red pending lines hold 1,090 unique texts, and the 641 blue pending lines hold 540. Glossing each unique text once and copying the gloss would cut model work by 23% and 16% with no change in meaning. It is not implemented.

### Limits of this evaluation

- **One scenario.** All coverage, precision and model numbers come from one cyber-range scenario and three episodes per side. Other agents, other targets and human attacker histories may look very different.
- **Small samples.** 25 lines for rule precision and 100 lines for the model trials. The intervals in section 3 show how wide that is.
- **A lenient key.** Techniques were scored at parent level, and a gloss counted as acceptable if it named any of the techniques the key allowed for the line.
- **An Opus-family judge.** The model trials were scored by a session running an Opus-family model, which may favor Opus.
- **Text limits.** In the first model trial, five long lines reached the models shortened. The second trial capped every line at 350 characters, so very long calls were judged on their first part.
- **Evaluation, not tuning.** No threshold or rule was fitted to these numbers. The two rule fixes in section 3 and the `http-upload` fix in section 4 correct rules that were wrong on any input.
