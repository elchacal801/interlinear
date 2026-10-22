# `inventory.ps1`: interlinear transcript

Sources: `inventory.ps1` (sha256 `89778de22911`…, 4 lines)

Glosses: 3 rule, 0 model, 0 analyst, 1 none, 0 pending · rules `2026.10.8` · ATT&CK `20.0`

## `inventory.ps1`

```text
   1  # inventory
      [context]
      A comment, or a script's interpreter line (#!); context, it runs nothing.

   2  Get-Process | Sort-Object CPU -Descending | Select-Object -First 5
      T1057 Process Discovery   [rule: process-list]
      Lists running processes, for example to spot security tools or competing malware.

   3  ipconfig /all
      T1016 System Network Configuration Discovery   [rule: network-config]
      Reads the host's network configuration (interfaces, addresses, routes, DNS).

   4  systeminfo
      T1082 System Information Discovery   [rule: system-info]
      Collects operating system and hardware details.
```
