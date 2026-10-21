"""Credentials in command text, redacted for text that leaves the analyst's machine or may be published.

transcript.json keeps every credential as evidence. `interlinear pending`, whose output the gloss skill sends to a
hosted model, redacts them by default, and `interlinear render --redact-secrets` redacts the Markdown view. Each
secret value is replaced with <redacted KIND>; the option or name before it stays, so the reader still sees that a
password, token, key or hash was given.

The patterns are a best effort over common forms, written to over-match on the value and never on the option: a
password option (--password, -Password, password=, /p:), a password given to a tool known to take one with -p (or
-P, -w, -H) or inside user:password@host, a credential-named variable assignment, an Authorization header, and
token formats with a known prefix (AWS access keys, GitHub, Anthropic and OpenAI keys, Slack tokens, JWTs, private
key blocks). Every pattern starts at a literal or a word start and scans at most one word or one quoted string
after it, so redaction runs in linear time.
"""

from __future__ import annotations

import re

_VALUE = r"""(?P<v>'[^'\n]*'|"[^"\n]*"|[^\s'"|;&<>()]+)"""
# Tools that take a password with -p (and a hash with -H or -hashes); -p means a port or a parent folder to most
# others.
_PASSWORD_TOOLS = re.compile(
    r"(?i)(?<![\w.-])(?:sshpass|hydra|medusa|ncrack|crackmapexec|cme|netexec|nxc|evil-winrm|smbmap|rdesktop|kerbrute"
    r"|bloodhound-python|enum4linux(?:-ng)?|certipy(?:-ad)?|impacket-[\w-]+|useradd|usermod"
    r"|(?:psexec|wmiexec|smbexec|atexec|dcomexec|mssqlclient|getuserspns|getnpusers|secretsdump|ldapdomaindump"
    r"|gettgt|getst)(?:\.py)?)(?![\w-])")
_GLUED_P_TOOLS = re.compile(r"(?i)(?<![\w.-])(?:mysql|mysqldump|mariadb|7z|7za|7zr)(?:\.exe)?(?![\w-])")
_CAPITAL_P_TOOLS = re.compile(r"(?i)(?<![\w.-])(?:sqlcmd|zip|unzip|osql|bcp)(?:\.exe)?(?![\w-])")
_LDAP = re.compile(r"(?i)(?<![\w.-])ldap(?:search|modify|add|delete|passwd|whoami)(?![\w-])")

# (kind, pattern) pairs that apply to any text: each has a group v, the secret.
_ALWAYS = [
    # An option that names a password, token or key, with its value after = or a blank.
    ("password", re.compile(r"(?i)(?<![\w-])--?(?:password|passwd|pass|pwd)(?:=|[ \t]+)" + _VALUE)),
    ("token", re.compile(r"(?i)(?<![\w-])--?(?:token|auth-?token|access-?token|secret|client-?secret|api-?key"
                         r"|access-?key|secret-?key)(?:=|[ \t]+)" + _VALUE)),
    # NAME=value with a credential-like name, in an assignment, an environment prefix or a URL query.
    ("secret", re.compile(r"(?i)(?<![\w.-])[\w.-]*?(?:pass(?:word|wd)?|pwd|secret|token|api_?key|apikey|access_?key"
                          r"|private_?key|credential|auth)[\w.-]*=(?!=)" + _VALUE)),
    # PowerShell: $name = 'value' with a credential-like name, and ConvertTo-SecureString 'value' -AsPlainText.
    ("secret", re.compile(r"(?i)\$\w*?(?:pass|pwd|secret|token|key|cred)\w*[ \t]*=[ \t]*"
                          r"""(?P<v>'[^'\n]*'|"[^"\n]*")""")),
    ("password", re.compile(r"(?i)convertto-securestring[ \t]+(?:-string[ \t]+)?" + _VALUE)),
    # aws configure set aws_secret_access_key VALUE
    ("secret", re.compile(r"(?i)(?<![\w.-])configure[ \t]+set[ \t]+[\w.]*(?:secret|token|key)[\w.]*[ \t]+" + _VALUE)),
    # user:password@host in a URL or an impacket target (domain/user:password@host). A start follows a blank, / or =,
    # and the user holds none of them, nor does the password hold a /, so a scan from each start ends at the next.
    ("password", re.compile(r"""(?<![^\s/'"=])[^\s:/@'"=]+:(?P<v>[^\s/'"]+)@[^\s@'"/]+""")),
    # curl -u user:password, smbclient -U user%password, xfreerdp /p:password, openssl pass:password.
    ("password", re.compile(r"""(?<![\w-])(?:-u|--user)[ \t]+['"]?[^\s:'"]+:(?P<v>[^\s'"]+)""")),
    ("password", re.compile(r"""(?<![\w-])(?:-U|--user)[ \t]+['"]?[^\s%'"]+%(?P<v>[^\s'"]+)""")),
    ("password", re.compile(r"(?i)(?<!\S)/(?:p|pass|password):" + _VALUE)),
    ("password", re.compile(r"(?<![\w-])pass:" + _VALUE)),
    # net user NAME PASSWORD (not * or an option), and net use \\host\share PASSWORD.
    ("password", re.compile(r"""(?i)(?<![\w.-])net1?(?:\.exe)?[ \t]+user[ \t]+(?:'[^'\n]*'|"[^"\n]*"|[^\s/'"]+)"""
                            r"""[ \t]+(?P<v>(?![/*])(?:'[^'\n]*'|"[^"\n]*"|\S+))""")),
    ("password", re.compile(r"(?i)(?<![\w.-])net1?(?:\.exe)?[ \t]+use[ \t]+(?:[A-Za-z]:[ \t]+)?\\\\\S+[ \t]+"
                            r"(?P<v>(?![/*])\S+)")),
    # echo PASSWORD | sudo -S, and echo user:password | chpasswd
    ("password", re.compile(r"""(?<![\w-])echo[ \t]+(?P<v>'[^'\n]*'|"[^"\n]*"|[^\s'"|]+)[ \t]*\|[ \t]*sudo"""
                            r"(?:[ \t]+-[A-Za-z]+){0,8}?[ \t]+-[A-Za-z]*S(?![\w-])")),
    ("password", re.compile(r"""(?<![\w-])echo[ \t]+['"]?[\w.-]+:(?P<v>[^\s'"|]+)['"]?[ \t]*\|[ \t]*(?:sudo[ \t]+)?"""
                            r"chpasswd")),
    # Authorization and API key headers.
    ("token", re.compile(r"(?i)(?<![\w-])(?:proxy-)?authorization:[ \t]*(?:(?:basic|bearer|token|digest|ntlm|negotiate)"
                         r"""[ \t]+)?(?P<v>[^\s'"]+)""")),
    ("token", re.compile(r"""(?i)(?<![\w-])x-api-key:[ \t]*(?P<v>[^\s'"]+)""")),
    # A literal cookie, in a Cookie header or curl -b NAME=VALUE (curl -b FILE reads a file; $VAR is left alone).
    ("token", re.compile(r"""(?i)(?<![\w-])cookie:[ \t]*(?P<v>(?![ \t$])[^'"\n]+)""")),
    ("token", re.compile(r"""(?<![\w-])(?:-b|--cookie)[ \t]+['"]?(?P<v>[^\s'"=/$]+=[^\s'"]+)""")),
    # Token formats with a known prefix.
    ("key", re.compile(r"(?<![A-Z0-9])(?P<v>(?:AKIA|ASIA|AGPA|AROA|AIDA)[A-Z0-9]{16})(?![A-Z0-9])")),
    ("token", re.compile(r"(?<![\w-])(?P<v>(?:gh[pousr]_[A-Za-z0-9]{30,}|github_pat_[A-Za-z0-9_]{20,}"
                         r"|glpat-[\w-]{20,}|xox[abprs]-[A-Za-z0-9-]{10,}|AIza[\w-]{30,}"
                         r"|sk-(?:ant-|proj-)?[\w-]{20,}))")),
    ("token", re.compile(r"(?<![\w-])(?P<v>eyJ[\w-]{4,}\.eyJ[\w-]{4,}\.[\w-]{4,})")),
    ("key", re.compile(r"(?P<v>-----BEGIN [A-Z ]{0,40}PRIVATE KEY-----(?:(?!-----BEGIN )[\s\S])*?"
                       r"(?:-----END [A-Z ]{0,40}PRIVATE KEY-----|\Z))")),
]
# (gate, kind, pattern): the pattern applies only to text the gate matches.
_GATED = [
    (_PASSWORD_TOOLS, "password", re.compile(r"(?<![\w-])-p[ \t]+" + _VALUE)),
    (_PASSWORD_TOOLS, "hash", re.compile(r"(?<![\w-])-(?:H|hashes)[ \t]+" + _VALUE)),
    # impacket's target DOMAIN/USER:PASSWORD with the host given by an option (-dc-ip) instead of @host
    (_PASSWORD_TOOLS, "password", re.compile(r"""(?<![^\s'"])['"]?[\w.-]+/[\w.$-]+:(?P<v>[^\s@'"/]+)(?=['"]?(?:\s|$))""")),
    (_GLUED_P_TOOLS, "password", re.compile(r"""(?<![\w-])-p(?P<v>[^\s'"|;&<>()]+)""")),
    (_CAPITAL_P_TOOLS, "password", re.compile(r"(?<![\w-])-P[ \t]+" + _VALUE)),
    (_LDAP, "password", re.compile(r"(?<![\w-])-w[ \t]+" + _VALUE)),
]
_MARKER = re.compile(r"<redacted [a-z]+>")


def _replace(kind: str, pattern: re.Pattern, text: str) -> str:
    def one(match: re.Match) -> str:
        if _MARKER.search(match.group("v")):
            return match.group()  # already redacted
        start, end = match.start("v") - match.start(), match.end("v") - match.start()
        whole = match.group()
        return whole[:start] + f"<redacted {kind}>" + whole[end:]

    return pattern.sub(one, text)


def redact(text: str) -> str:
    """text with each credential it holds replaced by <redacted KIND>. Text with nothing to redact is returned
    unchanged, and redacting twice changes nothing."""
    for kind, pattern in _ALWAYS:
        text = _replace(kind, pattern, text)
    for gate, kind, pattern in _GATED:
        if gate.search(text):
            text = _replace(kind, pattern, text)
    return text
