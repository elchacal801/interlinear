"""IOC extractors. They run on defanged text, so they look for defanged forms.

The text is attacker-written, so every pattern here runs in linear time, and the command-aware scans (users and
ports) never rescan it: each resumes where the last one stopped. Each extractor yields (offset, value) pairs, and
extract() orders them by offset and drops duplicates.
"""

from __future__ import annotations

import bisect
import ipaddress
import re
from collections.abc import Callable, Generator, Iterable, Iterator

from .model import IOC

IOC_TYPES = ("url", "ipv4", "ipv6", "domain", "hash", "path", "user", "port")

Hit = tuple[int, str]

# Only the generated placeholders are removed: normalize's blob marker and truncation marker, and the start of a
# blob marker that the truncation cut off, right before the final truncation marker. Text the attacker wrote, such
# as '<blob ', stays, so it cannot hide the IOCs after it.
_TRUNCATED = r"<truncated len=[0-9]+ sha256=[0-9a-f]{64}>"
_BLOB_CUT = (r"(?: (?:s(?:h(?:a(?:2(?:5(?:6(?:="
             r"(?:[0-9a-f]{64} (?:l(?:e(?:n(?:=[0-9]*)?)?)?)?|[0-9a-f]{0,64})"
             r")?)?)?)?)?)?)?)?")
_PLACEHOLDER = re.compile(
    r"<blob sha256=[0-9a-f]{64} len=[0-9]+>|" + _TRUNCATED + r"|<blob" + _BLOB_CUT + r"(?= " + _TRUNCATED + r"\Z)"
)

# A scheme starts at a word boundary that is not inside a run of scheme characters, and is at most 32 characters
# long, so no start rescans a long run. A URL ends at a backtick, at a comma that starts another URL, at ${IFS} or
# $IFS (a shell's way to write a blank), and at a parenthesis it did not open. One level of balanced parentheses
# stays, as in /wiki/Foo_(bar), and a ")" glued after a URL ends it, so the scan resumes there and finds the next.
_SCHEME = r"(?:hxxps?:/|[A-Za-z][A-Za-z0-9+.-]{0,31}://)"
_URL_CHAR = r"[^\s'\"<>|;`,()$]"
_URL = re.compile(r"\b(?<![A-Za-z0-9+.-])(" + _SCHEME + r")((?:" + _URL_CHAR + r"|\$(?!\{IFS\}|IFS(?!\w))|,(?!"
                  + _SCHEME + r")|\([^\s'\"<>|;`,()]*\))+)", re.IGNORECASE)
_URL_TRAILING = ".,;:!?"
_URL_CLOSERS = {"}": "{", "]": "["}
# An octet as normalize defangs it: 1 to 4 digits, 255 or less (0203, 0005), so 1.2.3.1234 and 2026.10.18.1 are
# version strings, not addresses.
_OCTET = r"(?:0?(?:[01][0-9]{2}|2[0-4][0-9]|25[0-5])|[0-9]{1,2})"
_IPV4 = re.compile(r"(?<![0-9])(?<![0-9]\.)" + _OCTET + r"\." + _OCTET + r"\." + _OCTET + r"\[\.\]" + _OCTET
                   + r"(?![0-9])")
_IPV6 = re.compile(r"(?<![\w\]])[0-9A-Fa-f]{0,4}(?:\[:\][0-9A-Fa-f]{0,4}){2,7}(?![\w\[])")
# Starts mirror normalize._DOMAIN: never mid-label or mid-name, but after "//", "*." or "..." is fine, and never
# inside a hyphenated label, which would rescan a run such as a-a-a-a. from every label.
# A known limitation: an option letter glued to a domain stays on it. normalize cannot tell the h of
# -hdb.example.com from a first label, so it defangs the run as -hdb.example[.]com, and the domain extracted here
# is hdb.example[.]com.
_DOMAIN = re.compile(r"(?<!\w)(?<![A-Za-z0-9_-]\.)(?<![\w-]-)(?:[A-Za-z0-9_][A-Za-z0-9_-]*\.)*"
                     r"[A-Za-z0-9_][A-Za-z0-9_-]*\[\.\][A-Za-z]{2,24}(?![\w-])")
# A hash is a whole token: a hex run inside a longer word (a key, a token, an identifier) is not one.
_HASH = re.compile(r"(?<![0-9A-Za-z_])(?:[0-9A-Fa-f]{64}|[0-9A-Fa-f]{40}|[0-9A-Fa-f]{32})(?![0-9A-Za-z_])")
# A path segment may hold defanged dots, so /dev/tcp/203.0.113[.]5/4444 stays whole. A path may start at ~, $HOME
# or ${HOME}, and is kept as written.
_SEGMENT = r"(?:[\w.@+-]|\[\.\])+"
_UNIX_PATH = re.compile(r"(?<![\w:/.\[\]~-])((?:~|\$HOME|\$\{HOME\})?/(?:" + _SEGMENT + r"/)*" + _SEGMENT + r")")
_UNIX_ROOTS = frozenset("/root /tmp /etc /var /home /dev /opt /usr /bin /sbin /boot /srv /mnt /media /proc /sys /run "
                        "/lib".split())
# A drive path starts at the start of the line, or after a blank, "=" (--out=C:\x) or ">" (>C:\x.txt), so never
# after an option dash (awk -F:\t). In quotes that start there, it runs to the closing quote, spaces and all
# ("C:\Program Files\..."); otherwise to a blank or a quote, also after a quote that never closes. It never holds
# < > or |, which cannot appear in a Windows path. A second ":" cannot either, so a run that meets one is not a
# path (sed 's:\(a\):b:', or the stream in x.exe:ads).
_DRIVE = r"[A-Za-z]:\\"
_WINDOWS_PATH = re.compile(
    r"(?:^|(?<=[\s=>]))(?:\"(" + _DRIVE + r"[^\"\n<>|:]*)\"|'(" + _DRIVE + r"[^'\n<>|:]*)'|(" + _DRIVE
    + r"[^\s'\"<>|:]*)(?=[\s'\"<>|]|\Z))|(?<=['\"])(?<![^\s=>]['\"])(" + _DRIVE + r"[^\s'\"<>|:]*)(?=[\s'\"<>|]|\Z)"
)
# Inside echo or printf text, X:\ before one of these letters, in a single component, is an escape such as \n or
# \t (printf "a:\n"), not a drive path. C:\temp\x.exe there, with a second component, is still a path.
_ESCAPE_LETTERS = frozenset("abefnrtv")


def _matches(pattern: re.Pattern) -> Callable[[str], Iterator[Hit]]:
    return lambda text: ((m.start(), m.group()) for m in pattern.finditer(text))


def _url_tail(rest: str) -> str:
    """rest without trailing punctuation, or a trailing } or ] that it did not open, as in {curl,http://host/a}."""
    unmatched = {closer: rest.count(closer) - rest.count(opener) for closer, opener in _URL_CLOSERS.items()}
    end = len(rest)
    while end:
        ch = rest[end - 1]
        if ch in _URL_TRAILING:
            end -= 1
        elif unmatched.get(ch, 0) > 0:
            unmatched[ch] -= 1
            end -= 1
        else:
            break
    return rest[:end]


def _urls(text: str) -> Iterator[Hit]:
    for m in _URL.finditer(text):
        rest = _url_tail(m.group(2))
        if rest.strip("/"):  # more than the scheme
            yield m.start(), m.group(1) + rest


def _paths(text: str) -> Iterator[Hit]:
    for m in _UNIX_PATH.finditer(text):
        path = m.group(1)
        # One segment with no dot, as in /f, /q or /add, is a Windows command switch, unless it is a well-known
        # Unix root such as /tmp or /root.
        if path.startswith("/") and path.count("/") == 1 and "." not in path and path not in _UNIX_ROOTS:
            continue
        yield m.start(1), path
    echo_args = None
    for m in _WINDOWS_PATH.finditer(text):
        start, path = m.start(m.lastindex), m.group(m.lastindex)
        if path[3:4] in _ESCAPE_LETTERS and "\\" not in path[3:]:
            if echo_args is None:
                echo_args = _echo_arguments(text)
            if _in_spans(echo_args, start):
                continue
        yield start, path


def _in_spans(spans: list[tuple[int, int]], pos: int) -> bool:
    """Whether pos falls in one of spans, sorted (start, end) pairs that do not overlap."""
    k = bisect.bisect_right(spans, (pos, float("inf"))) - 1
    return k >= 0 and pos < spans[k][1]


# Shell words, for the command-aware extractors. A word runs to a blank, a shell operator, a parenthesis or a quote
# that never closes. A quoted part ('...' or "..."), a backtick substitution and a $( ) substitution (with one level
# of nested parentheses) belong to the word, so a password made by $(openssl passwd -1 x) is one option argument.
_WORD = re.compile(r"""(?:\$\((?:[^()\n]|\([^()\n]*\))*\)|`[^`\n]*`|[^\s'"`|;&<>()]|"[^"\n]*"|'[^'\n]*')+""")
_QUOTED = re.compile(r""""([^"\n]*)"|'([^'\n]*)'""")
_BLANKS = re.compile(r"[^\S\n]*")
_COMMAND_END = frozenset("\n|;&<>()#")
# A command word: at the start, or after a blank, an operator, a parenthesis, a backtick or a quote (sh -c '...').
_AT_COMMAND = r"(?:^|(?<=[\s;|&(`'\"]))"


def _unquote(word: str) -> str:
    if "'" not in word and '"' not in word:
        return word
    return _QUOTED.sub(lambda m: m.group(1) if m.group(1) is not None else m.group(2), word)


def _words(text: str, pos: int) -> Iterator[tuple[int, int, str]]:
    """Yield (start, end, value) for each word of the simple command whose arguments start at text[pos].

    The command ends at a newline, |, ;, &, a parenthesis, a comment or a redirection (>, >>, <, 2>, &> and the
    like). One level of quotes is removed. A quote or backtick that never closes takes the rest of the line.
    """
    n = len(text)
    while True:
        pos = _BLANKS.match(text, pos).end()
        if pos >= n or text[pos] in _COMMAND_END:
            return
        m = _WORD.match(text, pos)
        if m is None:  # a quote that never closes
            end = text.find("\n", pos)
            end = n if end < 0 else end
            yield pos, end, text[pos + 1 : end]
            return
        if m.end() < n and text[m.end()] in "<>" and m.group().isdigit():  # 2>/dev/null, 1>>log
            return
        yield pos, m.end(), _unquote(m.group())
        pos = m.end()


_ECHO_COMMAND = re.compile(_AT_COMMAND + r"(?:echo|printf)(?=\s|$)")


def _echo_arguments(text: str) -> list[tuple[int, int]]:
    """(start, end) of the arguments of each echo or printf command in text, in order."""
    spans: list[tuple[int, int]] = []
    pos = 0
    while (m := _ECHO_COMMAND.search(text, pos)) is not None:
        end = m.end()
        for _start, end, _value in _words(text, m.end()):
            pass
        spans.append((m.end(), end))
        pos = max(end, m.end())
    return spans


def _options(text: str, pos: int, takes_arg: frozenset[str],
             long_takes_arg: frozenset[str] = frozenset()) -> Iterator[tuple[str, str | None, str | None, int, int]]:
    """Walk a command's words getopt-style, yielding (kind, name, value, start, end).

    kind is "opt" for an option with its argument (name is the letter or the long name; value is None when the
    argument is missing), "flag" for an option without one, and "operand". Clustered letters (-lvnp 4444) and glued
    arguments (-p2222, --port=1) are split as getopt splits them. After "--", every word is an operand.
    """
    words = _words(text, pos)
    operands_only = False
    for start, end, word in words:
        if operands_only or word == "-" or not word.startswith("-"):
            yield "operand", None, word, start, end
        elif word == "--":
            operands_only = True
        elif word.startswith("--"):
            name, eq, value = word[2:].partition("=")
            if eq:
                yield "opt", name, value, start, end
            elif name in long_takes_arg:
                arg = next(words, None)
                yield ("opt", name, None, start, end) if arg is None else ("opt", name, arg[2], arg[0], arg[1])
            else:
                yield "flag", name, None, start, end
        else:
            for k, letter in enumerate(word[1:], 1):
                if letter not in takes_arg:
                    yield "flag", letter, None, start, end
                elif k + 1 < len(word):
                    yield "opt", letter, word[k + 1 :], start, end
                    break
                else:
                    arg = next(words, None)
                    yield ("opt", letter, None, start, end) if arg is None else ("opt", letter, arg[2], arg[0], arg[1])
                    break


# Users. The user is the first operand of useradd, adduser, usermod or passwd, after their options and the
# arguments of the options that take one (shadow-utils, Debian adduser and BusyBox adduser), and also the new name
# that usermod -l gives; the next word after net user; or the name of a record written into /etc/passwd by echo,
# printf or tee, or by a heredoc. openssl passwd makes a password hash and names no user.
_USER_COMMAND = re.compile(_AT_COMMAND + r"(?<!openssl )(?:(?:/usr)?(?:/local)?/s?bin/)?"
                           r"(useradd|adduser|usermod|passwd)(?=\s|$)")
_SHADOW_ARGS = frozenset("bcdefgGkKpPRsuZ")
_SHADOW_LONG_ARGS = frozenset({"base-dir", "comment", "home-dir", "home", "expiredate", "inactive", "gid", "groups",
                               "skel", "key", "password", "shell", "uid", "root", "prefix", "selinux-user",
                               "selinux-range"})
# Per command: the short and long options that take an argument, and those whose argument is a user name.
_USER_OPTIONS = {
    "useradd": (_SHADOW_ARGS, _SHADOW_LONG_ARGS, frozenset()),
    "usermod": (_SHADOW_ARGS | frozenset("lvVwW"),
                _SHADOW_LONG_ARGS | {"login", "add-subuids", "del-subuids", "add-subgids", "del-subgids"},
                frozenset({"l", "login"})),
    "adduser": (frozenset("hgsGuk"), frozenset({"home", "shell", "uid", "gid", "gecos", "ingroup", "comment", "conf",
                                                "firstuid", "lastuid", "firstgid", "lastgid"}), frozenset()),
    "passwd": (frozenset("ainwxrRP"),
               frozenset({"inactive", "mindays", "warndays", "maxdays", "repository", "root", "prefix"}), frozenset()),
}
_UNIX_USER = re.compile(r"[A-Za-z_][A-Za-z0-9_.-]{0,31}\$?")
_NET_USER = re.compile(_AT_COMMAND + r"net(?:\.exe)?[^\S\n]+user(?=\s|$)", re.IGNORECASE)
_WINDOWS_USER = re.compile(r'[^"/\\\[\]:;|=,+*?<>]{1,64}')
# A passwd record: name, then a password field that may hold a $( ) substitution, then a numeric uid.
_RECORD = r"([A-Za-z_][A-Za-z0-9_.-]{0,31}\$?):(?:[^:\s'\"$]|\$(?!\()|\$\([^()\n]*\))*:[0-9]+:"
_PASSWD_RECORD = re.compile(_AT_COMMAND + r"(?:echo|printf)[^\S\n]+(?:-[A-Za-z]+[^\S\n]+)*['\"]?" + _RECORD)
_RECORD_LINE = re.compile(_RECORD)
_PASSWD_TARGET = re.compile(r"(?:>|\btee(?:[^\S\n]+-[A-Za-z-]+)*)[^\S\n]*/etc/passwd(?![\w./-])")
# A heredoc opener: <<WORD, <<-WORD, and the quoted forms <<'WORD', <<"WORD" and <<\WORD; never a <<< here-string.
_HEREDOC = re.compile(r"(?<!<)<<(?!<)(-?)[^\S\n]*\\?(['\"]?)([A-Za-z_][A-Za-z0-9_]*)\2")
_NEWLINE = re.compile(r"\n")


def _heredoc_records(text: str) -> Iterator[Hit]:
    """The names of the records in a heredoc body that a line writes to /etc/passwd (cat >> /etc/passwd <<EOF)."""
    lines = text.split("\n")
    offsets = [0]
    for line in lines[:-1]:
        offsets.append(offsets[-1] + len(line) + 1)
    k = 0
    while k < len(lines):
        opener = _HEREDOC.search(lines[k]) if _PASSWD_TARGET.search(lines[k]) else None
        k += 1
        if opener is None:
            continue
        strip_tabs, delimiter = opener.group(1) == "-", opener.group(3)
        while k < len(lines):
            line = lines[k].lstrip("\t") if strip_tabs else lines[k]
            if line == delimiter:
                break
            record = _RECORD_LINE.match(line)
            if record:
                yield offsets[k] + len(lines[k]) - len(line) + record.start(1), record.group(1)
            k += 1
        k += 1


def _users(text: str) -> Iterator[Hit]:
    pos = 0
    while (m := _USER_COMMAND.search(text, pos)) is not None:
        pos = m.end()
        takes_arg, long_takes_arg, names_user = _USER_OPTIONS[m.group(1)]
        for kind, name, value, start, end in _options(text, m.end(), takes_arg, long_takes_arg):
            pos = end
            if kind == "opt" and name in names_user and value and _UNIX_USER.fullmatch(value):
                yield start, value
            elif kind == "operand":
                if _UNIX_USER.fullmatch(value):
                    yield start, value
                break
    pos = 0
    while (m := _NET_USER.search(text, pos)) is not None:
        pos = m.end()
        for start, end, value in _words(text, m.end()):
            pos = end
            if value.strip() and _WINDOWS_USER.fullmatch(value):
                yield start, value
            break
    # echo 'name:x:0:0::/root:/bin/sh' >> /etc/passwd, and the printf and tee forms: a record, then a write to
    # /etc/passwd later on the same line.
    targets = [m.start() for m in _PASSWD_TARGET.finditer(text)]
    if targets:
        newlines = [m.start() for m in _NEWLINE.finditer(text)]
        for m in _PASSWD_RECORD.finditer(text):
            k = bisect.bisect_left(targets, m.end())
            line = bisect.bisect_left(newlines, m.end())
            if k < len(targets) and (line == len(newlines) or newlines[line] > targets[k]):
                yield m.start(1), m.group(1)
    if "\n" in text and targets:
        yield from _heredoc_records(text)


# Ports, from 1 to 65535. Command-aware: ssh, scp and sftp, the nmap family, netcat, chisel and ngrok. Generic:
# --port, Port=, /dev/tcp and /dev/udp, listeners with an empty host, and host:port right after a host-like token.
# -p means a port only for the commands below (also run by path, as in /usr/bin/nc or C:\Users\Public\nc.exe):
# sshpass -p, ps -p and mysql -p do not.
_PORT_COMMAND = re.compile(r"(?:^|(?<=[\s;|&(`'\"/\\]))"
                           r"(ssh|scp|sftp|nmap|masscan|naabu|rustscan|nc|ncat|netcat|chisel|ngrok)(?:\.exe)?(?=\s|$)")
_SSH_ARGS = frozenset("BbcDEeFIiJLlmOoPpQRSWw")
_SCP_ARGS = frozenset("BbcDFiJloPRSsX")
_NC_ARGS = frozenset("cegGHiIKmMoOpPqRsTVwWxXZ")
_NC_LONG_ARGS = frozenset({"sh-exec", "exec", "lua-exec", "proxy", "proxy-type", "proxy-auth", "proxy-dns",
                           "output", "hex-dump", "wait", "idle-timeout", "source", "source-port", "allow",
                           "allowfile", "deny", "denyfile", "max-conns", "delay", "ssl-cert", "ssl-key",
                           "ssl-trustfile", "ssl-ciphers", "ssl-servername", "ssl-alpn"})
_SSH_PORT_OPTION = re.compile(r"port(?:[^\S\n]*=[^\S\n]*|[^\S\n]+)([0-9]+)", re.IGNORECASE)
_PORT_ITEM = re.compile(r"([0-9]{1,5})(?:-([0-9]{1,5}))?")
_SCAN_PROTOCOL = re.compile(r"[TUS]:")
_FORWARD_SPECIAL = re.compile(r"[\[\]:]")
_GENERIC_PORTS = (
    re.compile(r"--port(?:=|[^\S\n]+)([0-9]{1,5})(?![\w.])"),
    re.compile(r"(?<![\w-])(?i:port)=([0-9]{1,5})(?![\w.])"),
    re.compile(r"/dev/(?:tcp|udp)/[^/\s]+/([0-9]{1,5})(?![\w.])"),
    # A listener with an empty host: gost -L=:8080, -L=socks5://:1080.
    re.compile(r"(?:=|://|@):([0-9]{1,5})(?![\w.:\[@])"),
    # A socat listener address: TCP-LISTEN:4444, UDP4-LISTEN:53 and the like.
    re.compile(r"\b(?i:(?:tcp|udp|sctp|dccp|openssl|ssl)[46]?-listen):([0-9]{1,5})(?![\w.])"),
)
# A bare listener word, as in gost -L :8080. Inside a quoted argument (grep ':22 ', sed -n ':1') or a comment
# (# don't :80) it is not one.
_BARE_LISTENER = re.compile(r"(?<!\S):([0-9]{1,5})(?![\w.:\[@])")
_QUOTED_SPAN = re.compile(r"'[^'\n]*'|\"[^\"\n]*\"")
_COMMENT_MARK = re.compile(r"(?<!\S)#")
_CHISEL_PORT_OPTIONS = ("-p", "--p", "-port", "--port")
_NGROK_PROTOCOLS = frozenset({"tcp", "http", "tls"})
_LOCALHOST = re.compile(r"(?<![\w.-])localhost", re.IGNORECASE)
# A bracketed IPv6 host as written ([2001:db8::1]) or as normalize defangs it ([2001[:]db8[:][:]1]), so the port
# after it is found. Bounded, so each "[" costs a fixed amount.
_BRACKETED_IPV6 = re.compile(r"\[[0-9A-Fa-f.]{0,40}(?::|\[:\])(?:[0-9A-Fa-f.:]|\[:\]){0,60}(?:%[\w.-]{1,32})?\]")
_HOSTS = (_IPV4, _DOMAIN, _IPV6, _LOCALHOST, _BRACKETED_IPV6)
# Not before a word character, a dot, another colon (10:30:45), a "[", an "@" (user:12345@host is a password) or
# a dash.
_AFTER_HOST = re.compile(r":([0-9]{1,5})(?![\w.:\[@-])")


def _port(value: str | None, ranges: bool = False) -> str | None:
    """value as a port, or as a range a-b when ranges are allowed; None if it is not one from 1 to 65535."""
    m = _PORT_ITEM.fullmatch(value or "")
    if m is None or (m.group(2) is not None and not ranges):
        return None
    low = int(m.group(1))
    high = low if m.group(2) is None else int(m.group(2))
    if not 1 <= low <= high <= 65535:
        return None
    return str(low) if m.group(2) is None else f"{low}-{high}"


def _forward_ports(spec: str) -> list[str]:
    """The ports of an ssh -D, -L or -R spec: [bind:]port, [bind:]port:host:hostport and the socket forms.

    Fields are split on the colons outside brackets, so [::1] and a bracketed IPv6 host stay whole.
    """
    fields, depth, start = [], 0, 0
    for special in _FORWARD_SPECIAL.finditer(spec):
        ch = special.group()
        if ch == "[":
            depth += 1
        elif ch == "]":
            depth = max(depth - 1, 0)
        elif not depth:
            fields.append(spec[start : special.start()])
            start = special.end()
    fields.append(spec[start:])
    return [port for port in map(_port, fields) if port]


def _ssh_option_ports(name: str, value: str, start: int, port_letter: str) -> Iterator[Hit]:
    """Ports from one ssh, scp or sftp option. The port option is -p for ssh (whose -P is a tag), -P for scp and
    sftp (whose -p preserves times)."""
    if name == port_letter:
        port = _port(value)
        if port:
            yield start, port
    elif name == "o":
        option = _SSH_PORT_OPTION.fullmatch(value.strip())
        port = _port(option.group(1)) if option else None
        if port:
            yield start, port
    elif name in ("D", "L", "R"):
        for port in _forward_ports(value):
            yield start, port


def _ssh_ports(text: str, pos: int) -> Generator[Hit, None, int]:
    """ssh -p, -o Port= and the -D, -L and -R specs. Options may follow the destination, as ssh allows; the next
    operand starts the remote command, whose -p is not ssh's. Returns where the remote command starts."""
    end, destination = pos, False
    for kind, name, value, start, end in _options(text, pos, _SSH_ARGS):
        if kind == "operand":
            if destination:
                return start
            destination = True
        elif kind == "opt" and value is not None:
            yield from _ssh_option_ports(name, value, start, "p")
    return end


def _scp_ports(text: str, pos: int) -> Generator[Hit, None, int]:
    """scp and sftp -P, and -o Port=."""
    end = pos
    for kind, name, value, start, end in _options(text, pos, _SCP_ARGS):
        if kind == "opt" and value is not None and name in ("P", "o"):
            yield from _ssh_option_ports(name, value, start, "P")
    return end


def _scanner_ports(text: str, pos: int) -> Generator[Hit, None, int]:
    """nmap, masscan, naabu and rustscan -p lists: each item is a port, a range stays a-b, T: U: S: are dropped."""
    end = pos
    words = _words(text, pos)
    for start, end, word in words:
        if word == "-p":
            following = next(words, None)
            if following is None:
                break
            start, end, ports = following
        elif word.startswith("-p"):
            ports = word[2:]
        else:
            continue
        for item in ports.split(","):
            port = _port(item[2:] if _SCAN_PROTOCOL.match(item) else item, ranges=True)
            if port:
                yield start, port
    return end


def _nc_ports(text: str, pos: int) -> Generator[Hit, None, int]:
    """netcat -p (also clustered, as in -lvnp 4444), the port operands after the host, or a lone one with -l."""
    end, listen, operands = pos, False, []
    for kind, name, value, start, end in _options(text, pos, _NC_ARGS, _NC_LONG_ARGS):
        if kind == "operand":
            operands.append((start, value))
        elif kind == "flag" and name in ("l", "listen"):
            listen = True
        elif kind == "opt" and name in ("p", "source-port"):
            port = _port(value)
            if port:
                yield start, port
    for start, value in operands if listen and len(operands) == 1 else operands[1:]:
        port = _port(value, ranges=True)
        if port:
            yield start, port
    return end


def _chisel_ports(text: str, pos: int) -> Generator[Hit, None, int]:
    """chisel -p (Go flags: -p, --port, -port=N), and the ports of its R: and L: remotes, as in R:1080:socks or
    R:2222:localhost:22/tcp."""
    end = pos
    words = _words(text, pos)
    for start, end, word in words:
        if word in _CHISEL_PORT_OPTIONS:
            following = next(words, None)
            if following is None:
                break
            start, end, word = following
            port = _port(word)
            if port:
                yield start, port
        elif word.partition("=")[0] in _CHISEL_PORT_OPTIONS:
            port = _port(word.partition("=")[2])
            if port:
                yield start, port
        elif word[:2] in ("R:", "L:"):
            for port in _forward_ports(word[2:].partition("/")[0]):
                yield start, port
    return end


def _ngrok_ports(text: str, pos: int) -> Generator[Hit, None, int]:
    """ngrok tcp, http or tls [address:]port: the first operand after the protocol that ends in a port.

    The word after a --long option without "=" is that option's value, never the address: --basic-auth admin:12345
    holds a password, and --remote-addr 1.tcp.ngrok.io:20000 the public address. Other operands that do not end in
    a port are skipped too."""
    end, protocol, value_next = pos, False, False
    for start, end, word in _words(text, pos):
        if value_next:
            value_next = False
            continue
        if word.startswith("-"):
            value_next = word.startswith("--") and "=" not in word and word != "--"
            continue
        if not protocol:
            protocol = word in _NGROK_PROTOCOLS
            if not protocol:
                break
            continue
        port = _port(word.rpartition(":")[2])
        if port:
            yield start, port
            break
    return end


_PORT_PARSERS = {"ssh": _ssh_ports, "scp": _scp_ports, "sftp": _scp_ports, "nmap": _scanner_ports,
                 "masscan": _scanner_ports, "naabu": _scanner_ports, "rustscan": _scanner_ports, "nc": _nc_ports,
                 "ncat": _nc_ports, "netcat": _nc_ports, "chisel": _chisel_ports, "ngrok": _ngrok_ports}


def _outside_quotes_and_comments(text: str, hits: Iterable[re.Match]) -> Iterator[re.Match]:
    """The matches that start outside every '...' and "..." span of text, and outside every comment: a # at the
    start of a word and outside quotes, to the end of its line."""
    quotes = [(q.start(), q.end()) for q in _QUOTED_SPAN.finditer(text)]
    comments: list[tuple[int, int]] = []
    for mark in _COMMENT_MARK.finditer(text):
        if (comments and mark.start() < comments[-1][1]) or _in_spans(quotes, mark.start()):
            continue
        end = text.find("\n", mark.start())
        comments.append((mark.start(), len(text) if end < 0 else end))
    for m in hits:
        if not _in_spans(quotes, m.start()) and not _in_spans(comments, m.start()):
            yield m


def _ports(text: str) -> Iterator[Hit]:
    pos = 0
    while (m := _PORT_COMMAND.search(text, pos)) is not None:
        end = yield from _PORT_PARSERS[m.group(1)](text, m.end())
        pos = max(end, m.end())
    for pattern in _GENERIC_PORTS:
        for m in pattern.finditer(text):
            port = _port(m.group(1))
            if port:
                yield m.start(1), port
    if ":" in text:
        for m in _outside_quotes_and_comments(text, _BARE_LISTENER.finditer(text)):
            port = _port(m.group(1))
            if port:
                yield m.start(1), port
    if ":" in text:
        for pattern in _HOSTS:
            for host in pattern.finditer(text):
                after = _AFTER_HOST.match(text, host.end())
                port = _port(after.group(1)) if after else None
                if port:
                    yield after.start(1), port


_EXTRACTORS: dict[str, Callable[[str], Iterable[Hit]]] = {
    "url": _urls,
    "ipv4": _matches(_IPV4),
    "ipv6": _matches(_IPV6),
    "domain": _matches(_DOMAIN),
    "hash": _matches(_HASH),
    "path": _paths,
    "user": _users,
    "port": _ports,
}
# Duplicates differing only in case are dropped for these, keeping the first one's case. URLs, paths and users are
# case-sensitive.
_CASE_INSENSITIVE = frozenset({"domain", "hash"})


def _collect(clean: str, types: list[str], keep: Callable[[str, int, str], bool]) -> list[IOC]:
    found: list[IOC] = []
    seen: set[tuple[str, str]] = set()
    for kind in types:
        for start, value in sorted(_EXTRACTORS[kind](clean), key=lambda hit: hit[0]):
            if not keep(kind, start, value):
                continue
            key = (kind, value.lower() if kind in _CASE_INSENSITIVE else value)
            if key not in seen:
                seen.add(key)
                found.append(IOC(type=kind, value=value))
    return found


def extract(text: str, types: list[str]) -> list[IOC]:
    return _collect(_PLACEHOLDER.sub(" ", text), types, lambda kind, start, value: True)


# Pseudo-devices that shell lines name all the time (2>/dev/null, /dev/urandom, /dev/fd/3) are noise, not
# indicators. /dev/tcp/..., /dev/udp/... and /dev/shm/... are not on the list: they mean something.
PSEUDO_PATHS = frozenset("/dev/null /dev/zero /dev/stdin /dev/stdout /dev/stderr /dev/tty /dev/random "
                         "/dev/urandom".split())
_DEV_FD = re.compile(r"/dev/fd/[0-9]+")


def is_pseudo_path(value: str) -> bool:
    return value in PSEUDO_PATHS or _DEV_FD.fullmatch(value) is not None


# A command run by its system path (/usr/bin/wget, sudo /bin/rm, C:\Windows\System32\cmd.exe) names the tool, not
# an indicator. Only paths in the standard binary directories are left out: a dropped tool run by its own path, such
# as /tmp/.x/run, is an indicator. The command word is the first word of a simple command, after any wrapper below,
# the wrapper's options (with their arguments) and VAR=value words.
_SYSTEM_COMMAND = re.compile(r"(?:/usr(?:/local)?)?/s?bin/[^/\s]+|/usr/libexec/\S+|[A-Za-z]:\\(?i:windows)\\"
                             r"(?i:system32|syswow64)\\\S+")
_COMMAND_STARTS = re.compile(r"[|;&(`\n]")
_ASSIGNMENT = re.compile(r"[A-Za-z_][A-Za-z0-9_]*=")
# Each wrapper, with its short options that take an argument.
_WRAPPERS = {"sudo": "CDghprtTUu", "doas": "Cu", "sshpass": "dfpP", "timeout": "ks", "env": "CSu", "nice": "n",
             "time": "fo", "exec": "a", "stdbuf": "ioe", "setsid": "", "nohup": "", "busybox": "", "command": ""}


def _command_word_starts(text: str) -> set[int]:
    """Offsets of the command words of text: the first word of each simple command, past its wrappers."""
    quoted = [(m.start(), m.end()) for m in _QUOTED_SPAN.finditer(text)]
    starts: set[int] = set()
    for pos in [0] + [m.end() for m in _COMMAND_STARTS.finditer(text) if not _in_spans(quoted, m.start())]:
        wrapper, argument, duration = None, False, False  # an option's argument, or timeout's duration, is next
        for start, _end, value in _words(text, pos):
            if argument:
                argument = False
                continue
            if wrapper is not None and value.startswith("-") and value != "-":
                letters = value[1:]
                argument = (letters.isalpha() and letters[-1] in _WRAPPERS[wrapper]) or (
                    wrapper == "sudo" and value in ("--user", "--group"))
                continue
            if duration:
                duration = False
                continue
            if _ASSIGNMENT.match(value) and wrapper in (None, "env"):
                continue
            name = value.rsplit("/", 1)[-1]
            if name in _WRAPPERS:
                wrapper, duration = name, name == "timeout"
                continue
            starts.add(start + 1 if text[start] in "'\"" else start)
            break
    return starts


def is_local_address(kind: str, value: str) -> bool:
    """Whether a defanged ipv4 or ipv6 IOC is a loopback (127.0.0.0/8, ::1) or link-local (169.254.0.0/16,
    fe80::/10) address: the host itself or its own link, never remote infrastructure. An IPv4 octet written with a
    leading zero may be read as octal (0177.0.0.1 is 127.0.0.1, and 0127.0.0.1 is not), so such an address is kept."""
    plain = value.replace("[.]", ".").replace("[:]", ":")
    if kind == "ipv4":
        octets = plain.split(".")
        if any(len(octet) > 1 and octet.startswith("0") for octet in octets):
            return False
        return octets[0] == "127" or octets[:2] == ["169", "254"]
    if kind == "ipv6":
        try:
            address = ipaddress.IPv6Address(plain)
        except ValueError:
            return False
        return address.is_loopback or address.is_link_local
    return False


def indicators(text: str, types: list[str]) -> list[IOC]:
    """The IOCs a gloss reports: extract(), less the pseudo-device paths, which are never reported, less a command's
    own system path, and less loopback and link-local addresses (is_local_address)."""
    clean = _PLACEHOLDER.sub(" ", text)
    commands = _command_word_starts(clean) if "path" in types else set()

    def keep(kind: str, start: int, value: str) -> bool:
        if kind in ("ipv4", "ipv6"):
            return not is_local_address(kind, value)
        if kind != "path":
            return True
        if is_pseudo_path(value):
            return False
        return not (start in commands and _SYSTEM_COMMAND.fullmatch(value))

    return _collect(clean, types, keep)
