"""Text normalization for transcript lines: blob replacement, defanging, truncation, and joining and splitting commands.
It also holds the check for a plain heredoc write (is_plain_heredoc_write), which reads a record with the same scans.

Standard library only: this module runs inside the untrusted sandbox as part of the parse zipapp. Its input is
attacker-written, so every regex here must run in linear time and no scan may rescan its input.
"""

from __future__ import annotations

import bisect
import functools
import hashlib
import ipaddress
import re
import unicodedata

from .textshow import is_hidden, show_controls
from .tlds import IANA_TLDS

MAX_LINE = 4096
BLOB_MIN = 200

# TLDs that double as common file extensions stay bare, so script names stay readable and rule-matchable.
EXTENSION_TLDS = frozenset("sh py pl rs md zip mov app cc so ps pro java cab pid pm pub".split())

# Top-level domains defanged when they appear as bare arguments.
TLDS = IANA_TLDS - EXTENSION_TLDS

_BLOB = re.compile(r"[A-Za-z0-9+/=_-]{%d,}" % BLOB_MIN)
_SURROGATE = re.compile(r"[\ud800-\udfff]")
# Also the one-slash http:/ and https:/; _URL_HOST then defangs the host after hxxp:/ and hxxps:/.
_SCHEME = re.compile(r"http(s?):/", re.IGNORECASE)
# The host after "://" (any scheme, or none when a blob swallowed the scheme) or after a one-slash hxxp:/, behind
# an optional user[:pass]@. The userinfo ends where the authority does (/ ? # or a backslash), and its last @ wins,
# so a@b@host works but an @ in the query does not hide the host. Labels may contain "_". The host ends at anything
# that cannot continue a hostname: / : ? # quotes ) | > , ` a final "." or the end. A host may already hold [.], so a
# later pass reads the same userinfo and host as the first pass did and leaves them alone: otherwise, once the host
# after the last @ is defanged, a pass would read the userinfo up to an earlier @ as the host, one pass per @.
_URL_HOST = re.compile(
    r"((?:://|(?i:hxxps?):/)(?:[^\s/?#\\'\"]*@)?)([A-Za-z0-9_-]+(?:(?:\.|\[\.\])[A-Za-z0-9_-]+)+)"
    r"(?![\w\[-]|\.[\w\[-])"
)
# A dotted quad, also glued to an option letter (-h203.0.113.5), after "..." or before a final period, but never
# part of a longer run of dotted numbers such as a version string. An octet may have 1 to 4 digits, leading zeros
# included (203.0.113.05, 0203.0.113.5), which ipaddress rejects but many tools accept; each must be 255 or less.
_IPV4 = re.compile(r"(?<![0-9])(?<![0-9]\.)([0-9]{1,4}\.[0-9]{1,4}\.[0-9]{1,4})\.([0-9]{1,4})(?![0-9]|\.[0-9])")
# An IPv6 host in brackets, as in a URL (hxxp://[2001:db8::1]:8080) or ssh root@[2001:db8::5], with an optional zone.
# The bare IPv6 pattern below never starts after "[" or ends before "]", so these need their own.
_BRACKETED_IPV6 = re.compile(r"\[([0-9A-Fa-f:.]{2,45}(?:%[\w.-]{1,32})?)\]")
# Dots that IDNA reads as ".", in a hostname: U+3002 IDEOGRAPHIC FULL STOP, U+FF0E FULLWIDTH FULL STOP and U+FF61
# HALFWIDTH IDEOGRAPHIC FULL STOP. Between two ASCII label characters, each becomes ".", so a host joined by them is
# defanged like a dotted host (evil.example[.]com) and its IOC extracts like one, while text in a CJK script keeps its
# full stops. The text no longer shows which dot was typed. Built with chr() so this file stays ASCII.
_WIDE_DOT = re.compile("(?<=[A-Za-z0-9_-])[" + chr(0x3002) + chr(0xFF0E) + chr(0xFF61) + "](?=[A-Za-z0-9_-])")
# A bare domain, also before a final period. Labels may contain "_" (SRV names such as _ldap._tcp). Each lookbehind
# keeps starts out of the middle of a run of label characters, which keeps the scan linear:
# - not right after a word character, "_" included (allowing that costs about 2.3 s per MB);
# - not right after a label character and a dot, but after "*.", ",." or "...";
# - not after a dash inside a hyphenated label, but right after an option dash (-hdb.example.com);
#   so --evil.example.com stays live, the accepted trade for linear time;
# - not right after one "/" (file paths), but after "//" (//host/share).
_DOMAIN = re.compile(
    r"(?<!\w)(?<![A-Za-z0-9_-]\.)(?<![\w-]-)(?:(?<!/)|(?<=//))"
    r"((?:[A-Za-z0-9_](?:[A-Za-z0-9_-]{0,61}[A-Za-z0-9_])?\.)+)([A-Za-z]{2,24})(?![\w\[-]|\.[A-Za-z0-9])"
)
_IPV6 = re.compile(r"(?<![\w:\[])([0-9A-Fa-f]{0,4}(?::[0-9A-Fa-f]{0,4}){2,7})(?![\w:\]])")
# The last character of a local part or userinfo (user, user:pass) or of a blob marker (>), before an @.
_LOCAL_PART_END = re.compile(r"[\w.%+:>-]")
_DEFANG_PASSES = 4


def scrub_surrogates(text: str) -> str:
    """Replace lone surrogates (U+D800 to U+DFFF), which cannot be encoded as UTF-8, with U+FFFD."""
    return _SURROGATE.sub("\ufffd", text)


def _blob_marker(blob: str) -> str:
    return f"<blob sha256={hashlib.sha256(blob.encode('utf-8')).hexdigest()} len={len(blob)}>"


def replace_blobs(text: str) -> str:
    """Replace any run of 200+ base64 or hex characters with its SHA-256 and length.

    A run that starts right after ".", ":" or "@" and has a "/" at index 1 to 64 began inside a URL host
    (host.tld/..., host:port/..., ://host/...). Everything up to that "/" stays visible so the host can be
    defanged, and only the rest is hashed, if it is still long enough. Any other run is hashed whole, including
    one after ".", ":" or "@" with no near "/": that is a credential, such as a JWT segment or key:<base64>.
    """

    def repl(match: re.Match) -> str:
        blob = match.group(0)
        if match.start() and text[match.start() - 1] in ".:@":
            slash = blob.find("/", 1, 65)
            if slash > 0:
                if len(blob) - (slash + 1) < BLOB_MIN:
                    return blob
                return blob[: slash + 1] + _blob_marker(blob[slash + 1 :])
        return _blob_marker(blob)

    return _BLOB.sub(repl, text)


def _url_host(match: re.Match) -> str:
    if "[.]" in match.group(2):  # already defanged
        return match.group(0)
    head, _, tld = match.group(2).rpartition(".")
    return f"{match.group(1)}{head}[.]{tld}"


def _ipv4(match: re.Match) -> str:
    if any(int(octet) > 255 for octet in match.group(1).split(".")) or int(match.group(2)) > 255:
        return match.group(0)
    return f"{match.group(1)}[.]{match.group(2)}"


def _bracketed_ipv6(match: re.Match) -> str:
    candidate = match.group(1)
    try:
        ipaddress.IPv6Address(candidate)
    except ValueError:
        return match.group(0)
    return "[" + candidate.replace(":", "[:]") + "]"


def _domain(match: re.Match) -> str:
    tld = match.group(2).lower()
    # Right after user@ even an extension TLD names a host, as in user@evil.example.zip. The @ must follow a
    # local-part or userinfo character (or the ">" that ends a blob marker), so an @file mention such as
    # @install.sh, which AI coding agents use, stays readable. So does a name that starts with a www label and has
    # another label after it, as in www.evil.example.zip: a file name rarely does.
    text, k = match.string, match.start()
    after_at = k >= 2 and text[k - 1] == "@" and _LOCAL_PART_END.match(text, k - 2) is not None
    www = match.group(1).lower().startswith("www.") and match.group(1).count(".") >= 2
    if tld not in TLDS and not ((after_at or www) and tld in IANA_TLDS):
        return match.group(0)
    return f"{match.group(1)[:-1]}[.]{match.group(2)}"


def _ipv6(match: re.Match) -> str:
    candidate = match.group(1)
    try:
        ipaddress.IPv6Address(candidate)
    except ValueError:
        return candidate
    return candidate.replace(":", "[:]")


def _defang_once(text: str) -> str:
    text = _WIDE_DOT.sub(".", text)
    text = _SCHEME.sub(lambda m: f"hxxp{m.group(1).lower()}:/", text)
    text = _URL_HOST.sub(_url_host, text)
    text = _BRACKETED_IPV6.sub(_bracketed_ipv6, text)
    text = _IPV4.sub(_ipv4, text)
    text = _DOMAIN.sub(_domain, text)
    return _IPV6.sub(_ipv6, text)


def defang(text: str) -> str:
    """Make URLs, IP addresses and domains non-clickable.

    The passes repeat until the text stops changing, at most four times. Each pass reads the hosts the first one did
    (a URL host already holding [.] still matches, and is left alone), so at most two passes change the text and
    defanging twice changes nothing, verified by a fuzz test. A test also pins a URL glued to a chain of user@ hosts,
    which a pass per @ would leave changeable.
    """
    for _ in range(_DEFANG_PASSES):
        out = _defang_once(text)
        if out == text:
            break
        text = out
    return text


def truncate(text: str, limit: int = MAX_LINE) -> str:
    if len(text) <= limit:
        return text
    digest = hashlib.sha256(text.encode("utf-8")).hexdigest()
    return f"{text[:limit]} <truncated len={len(text)} sha256={digest}>"


def normalize_text(text: str) -> str:
    """Scrub surrogates, replace blobs (so encoded payloads are hashed, not defanged), defang, then truncate."""
    return truncate(defang(replace_blobs(scrub_surrogates(text))))


# Anything but tab, newline and printable ASCII: the characters has_unusual_characters looks at one by one.
_NOT_PRINTABLE_ASCII = re.compile("[^\t\n" + chr(0x20) + "-" + chr(0x7E) + "]")


@functools.lru_cache(maxsize=4096)
def _is_unusual(ch: str) -> bool:
    """For a character outside tab, newline and printable ASCII: a control (C0, DEL or C1), any whitespace, a control
    picture (U+2400 to U+243F), an angle bracket of a code point shown as U+27E8, U+NNNN, U+27E9, a format character
    or a hidden character (textshow.is_hidden)."""
    code = ord(ch)
    return (code < 0xA0 or ch.isspace() or 0x2400 <= code <= 0x243F or code in (0x27E8, 0x27E9)
            or unicodedata.category(ch) in ("Cc", "Cf") or is_hidden(ch))


def has_unusual_characters(text: str) -> bool:
    """Whether text holds a character that bash may read differently than the text looks, so that no rule should
    describe it (rules.Library.match and match_record).

    That is a blank other than space and tab (a no-break space, an ideographic space, a vertical tab: part of a word to
    bash, so a # after one starts no comment), a control character other than tab and newline (bash drops a NUL, so
    EO<NUL>F ends a heredoc at EOF), and the forms in which stored text shows them: the control pictures U+2400 to
    U+243F (show_controls writes a NUL as U+2400) and the angle brackets of a code point, which also show the hidden
    characters (textshow.is_hidden). Visible text outside ASCII, such as accented or CJK letters, is not unusual.
    Linear: ASCII text is checked in one search, and any other character is decided once and cached.
    """
    if text.isascii():
        return _NOT_PRINTABLE_ASCII.search(text) is not None
    return any(_is_unusual(m.group()) for m in _NOT_PRINTABLE_ASCII.finditer(text))


# Characters the shell scans below act on: escapes, quotes, comments, separators, grouping, << and $(( )).
_SHELL_SPECIAL = re.compile(r"[\\'\"`#;&|()<$]")
# The same, and the brackets of a [[ ]] test, for split_commands.
_SPLIT_SPECIAL = re.compile(r"[\\'\"`#;&|()<$\[\]]")
_NOT_NEWLINE = re.compile("[^\n]")
# Where a quoted string can end, or escape the next character: "...", `...` and ANSI-C $'...'.
_QUOTE_STOP = {'"': re.compile(r'[\\"]'), "`": re.compile(r"[\\`]"), "'": re.compile(r"[\\']")}
# bash's blanks are space and tab only (zsh's too): any other whitespace, such as a no-break space, an ideographic space,
# a vertical tab or a form feed, is part of a word, so a # after one starts no comment. Records and their parts are
# stripped of these blanks (and of the newlines around a part) and of nothing else, so a stored record keeps every
# other character where bash sees it. Python's strip() with no argument would also drop the rest.
_SHELL_BLANKS = " \t"
_PART_EDGES = " \t\n"
# Bash's blanks, newline and metacharacters, less ")": a # right after one of these (or at the start) begins a
# comment. Any other character, including a no-break space or a vertical tab, is part of a word to bash. A ")" is
# left out because the one that closes $( ), $(( )) or <( ) does not end the word, so $(echo a)#x; rm still runs rm.
_COMMENT_AFTER = frozenset(" \t\n;&|(<>")
# Known limitations of the comment and URL scans, which do not model them:
# - ${x:- #}: a # inside a parameter expansion is taken as a comment, hiding the commands after it;
# - nested quotes inside "$( )", as in "$(echo "a;b")": in the one-line scans (split_commands and comments), the
#   inner quote closes the outer one early. The bash joiner's scan nests them;
# - a bare (...)# x: in the one-line scans, the # after a subshell's ")" is not taken as a comment, so a later
#   command is over-reported. The bash joiner's scan takes it as one, as bash does;
# - "A"*200 + "http:/host": the blob swallows the scheme, and a host after a bare ":/" stays live;
# - evil.example.com[0]: a host followed by "[" stays live, because "[" marks text that is already defanged.


def _skip_quoted(text: str, i: int, ansi_c: bool = False) -> int:
    """Index just past the quoted string that opens at text[i], or len(text) if it never closes.

    ansi_c marks the quote of a $'...' string, in which a backslash escapes the next character.
    """
    if text[i] == "'" and not ansi_c:  # nothing is special inside plain single quotes
        end = text.find("'", i + 1)
        return len(text) if end < 0 else end + 1
    stop = _QUOTE_STOP[text[i]]
    i += 1
    while (found := stop.search(text, i)) is not None:
        if found.group() != "\\":
            return found.end()
        i = found.end() + 1  # an escaped character never closes the string
    return len(text)


def _next_unquoted(text: str, i: int, special: re.Pattern = _SHELL_SPECIAL) -> int:
    """Index of the next special character at or after i that is outside quotes and escapes, or -1.

    A # is returned only when it begins a comment. The comment runs to the end of the text, so callers stop there.
    special is _SHELL_SPECIAL, or _SPLIT_SPECIAL, which adds [ and ].
    """
    escaped = -1  # index of the last character a backslash escaped; it belongs to a word, so no comment follows
    while (found := special.search(text, i)) is not None:
        i = found.start()
        ch = text[i]
        if ch == "\\":
            escaped = i + 1
            i += 2
        elif ch in "'\"`":
            i = _skip_quoted(text, i)
        elif ch == "$" and text.startswith("$", i + 1):  # $$ is the shell's PID: its second $ opens nothing
            i += 2
        elif ch == "$" and text.startswith("'", i + 1):  # an unescaped $ before ' opens ANSI-C quoting
            i = _skip_quoted(text, i + 1, ansi_c=True)
        elif ch == "#" and i > 0 and (text[i - 1] not in _COMMENT_AFTER or i - 1 == escaped):
            i += 1  # a # inside a word
        else:
            return i
    return -1


def _has_comment(text: str) -> bool:
    if "#" not in text:  # the common case, checked at C speed
        return False
    i = _next_unquoted(text, 0)
    while i >= 0 and text[i] != "#":
        i = _next_unquoted(text, i + 1)
    return i >= 0


# Words after which a [[ opens a test: it is a reserved word only where a command starts.
_TEST_LEADS = ("if", "elif", "while", "until", "then", "do", "else", "time", "!", "{")
# What may follow the ]] that closes a test.
_AFTER_TEST = ("", " ", "\t", "\n", ";", "&", "|", ")")


def _opens_test(text: str, i: int, start: int) -> bool:
    """Whether text[i] begins a [[ that opens a test: [[ as a word of its own, where a command starts.

    That is at the start of the command (which begins at start), right after a | or &, or after a word of
    _TEST_LEADS. Only the blanks right before this [[ are stepped back over, so the scan stays linear.
    """
    if not text.startswith("[[", i) or text[i + 2 : i + 3] not in ("", " ", "\t", "\n"):
        return False
    j = i
    while j > start and text[j - 1] in " \t\n":
        j -= 1
    if j == start or text[j - 1] in "|&":
        return True
    return j < i and any(
        text.endswith(word, start, j) and (j - len(word) == start or text[j - len(word) - 1] in " \t\n")
        for word in _TEST_LEADS)


def _closes_test(text: str, i: int) -> bool:
    """Whether text[i] begins the ]] that closes a test: ]] after a blank, before a blank, ;, &, |, ) or the end."""
    return text.startswith("]]", i) and i > 0 and text[i - 1] in " \t\n" and text[i + 2 : i + 3] in _AFTER_TEST


def _too_long_to_keep(part: str) -> bool:
    """Whether normalizing a part a test kept together would pass MAX_LINE, so that truncation could hide a command in
    a misread test. Normalizing at most triples a text's length (a "." becomes "[.]"), so a part of up to a third of
    MAX_LINE is never normalized here."""
    return len(part) * 3 > MAX_LINE and len(normalize_text(part.strip(_PART_EDGES))) > MAX_LINE


def _ends_background_job(text: str, i: int) -> bool:
    """Whether the & at text[i], which is not part of &&, ends a command as a background job: it is not the & of |&,
    >&, <&, &>, 2>&1 or the ;& of a case pattern. An escaped character before it is part of a word, not of an
    operator, so in a\\>& b the & ends a background job and bash runs b."""
    return (not (i > 0 and text[i - 1] in "|<>&;" and not _escaped(text, i - 1))
            and not text.startswith(">", i + 1))


def _cuts(text: str) -> list[tuple[int, int]]:
    """Where split_commands splits one command line: (index, length) of each ;, && and || outside quotes, comments,
    parentheses and [[ ]] tests, in order, and a cut of length 0 right after each & that ends a background job
    (_ends_background_job), so the & stays on the command it ends.

    A [[ that opens a test (_opens_test) keeps the &&, || and & inside it, up to the ]] that closes it (_closes_test).
    A test that no ]] closes before the next ; or the end is cut at them after all, as before, and so is a part a test
    kept together that would be too long to store whole (_too_long_to_keep), which can only over-report.
    """
    cuts: list[tuple[int, int]] = []  # (index, length) of each separator the text is split at
    held: list[tuple[int, int]] = []  # the && and || inside the test still open
    kept: list[tuple[int, int]] = []  # the && and || inside tests that closed
    start = depth = 0  # where the current command begins, and the parentheses open
    in_test = False
    i = _next_unquoted(text, 0, _SPLIT_SPECIAL)
    while i >= 0 and text[i] != "#":  # a comment keeps the rest of the text, ; and all
        ch = text[i]
        step = 1
        if ch == "(":
            depth += 1
        elif ch == ")":
            depth = max(depth - 1, 0)
        elif depth:
            pass
        elif ch == "[":
            if not in_test and _opens_test(text, i, start):
                in_test, step = True, 2
        elif ch == "]":
            if in_test and _closes_test(text, i):
                in_test, step = False, 2
                kept += held
                held = []
        elif ch == ";" or text.startswith(("&&", "||"), i):
            step = 1 if ch == ";" else 2
            if in_test and step == 2:
                held.append((i, step))
            else:
                cuts += held  # a ; ends the command, so the test it held open never closed
                held, in_test = [], False
                cuts.append((i, step))
                start = i + step
        elif ch == "&" and _ends_background_job(text, i):
            if in_test:
                held.append((i + 1, 0))
            else:
                cuts.append((i + 1, 0))
                start = i + 1
        i = _next_unquoted(text, i + step, _SPLIT_SPECIAL)
    cuts += held
    if not kept:
        return cuts
    out: list[tuple[int, int]] = []
    begin = k = 0
    for index, length in [*cuts, (len(text), -1)]:  # the last entry only ends the last part
        inside = []
        while k < len(kept) and kept[k][0] < index:  # the separators a test kept in this part
            inside.append(kept[k])
            k += 1
        if inside and _too_long_to_keep(text[begin:index]):
            out += inside
        if length >= 0:
            out.append((index, length))
        begin = index + max(length, 0)
    return out


def _spans(text: str, cuts: list[tuple[int, int]], offset: int = 0) -> list[tuple[int, str]]:
    """The parts of text between the cuts, stripped of blanks and newlines, as (index of the part's first character +
    offset, part)."""
    out = []
    begin = 0
    for index, length in [*cuts, (len(text), 0)]:
        part = text[begin:index]
        stripped = part.strip(_PART_EDGES)
        if stripped:
            out.append((offset + begin + len(part) - len(part.lstrip(_PART_EDGES)), stripped))
        begin = index + length
    return out


def split_command_spans(text: str) -> list[tuple[int, str]]:
    """split_commands, with where each part starts in text, as (index, part).

    One line is split at ;, && and ||, and after a background & (_cuts). Pipes stay together. Text spanning lines is
    first split at the newlines that end a command (_command_chunks, which reads it as the bash joiner does), and each
    piece is then split as one line is, with its heredoc bodies read as blank text. A command keeps the bodies of the
    heredocs it opens: no separator between a heredoc operator and its body splits it. So the only parts left spanning
    lines are commands whose arguments do: a quoted string, a substitution, an array, a heredoc body or a pipeline
    continued on the next line. Every part is a slice of text, in order, so no text is lost or moved.
    """
    if "\n" not in text:
        return _spans(text, _cuts(text))
    out: list[tuple[int, str]] = []
    for begin, end, bodies, uncut in _command_chunks(text):
        chunk = text[begin:end]
        view = chunk
        if bodies:  # the bodies read as blanks, with their newlines kept, so every index stays the same
            pieces, last = [], begin
            for body_begin, body_end in bodies:
                pieces += [text[last:body_begin], _NOT_NEWLINE.sub(" ", text[body_begin:body_end])]
                last = body_end
            pieces.append(text[last:end])
            view = "".join(pieces)
        cuts = _cuts(view)
        if uncut:  # drop the cuts between a heredoc operator and its body
            kept_cuts, k = [], 0
            for index, length in cuts:
                while k < len(uncut) and uncut[k][1] <= begin + index:
                    k += 1
                if k == len(uncut) or begin + index < uncut[k][0]:
                    kept_cuts.append((index, length))
            cuts = kept_cuts
        out += _spans(chunk, cuts, begin)
    return out


def split_commands(text: str) -> list[str]:
    """Split one logical command on ;, && and || and after a background & outside quotes, comments, subshells, $( )
    and [[ ]] tests, and text spanning lines also at the newlines that end a command. See split_command_spans."""
    return [part for _, part in split_command_spans(text)]


_BLANKS = re.compile(r"[ \t]*")
# Unquoted word characters: anything but blanks, shell metacharacters, quotes and backslashes.
_PLAIN_WORD = re.compile(r"[^ \t|&;()<>\\'\"]+")
_DOUBLE_QUOTED_PLAIN = re.compile(r'[^"\\]+')


def _double_quoted(text: str, i: int) -> tuple[str | None, int]:
    """Quote removal for a double-quoted string whose contents start at text[i].

    Returns (contents, index past the closing quote), or (None, len(text)) if the quote never closes. Inside
    double quotes a backslash escapes only $ ` " and itself; before anything else it stays.
    """
    parts: list[str] = []
    while i < len(text):
        ch = text[i]
        if ch == '"':
            return "".join(parts), i + 1
        if ch == "\\":
            escaped = text[i + 1 : i + 2]
            if escaped and escaped in '$`"\\':
                parts.append(escaped)
                i += 2
            else:
                parts.append(ch)
                i += 1
            continue
        run = _DOUBLE_QUOTED_PLAIN.match(text, i)
        parts.append(run.group())
        i = run.end()
    return None, len(text)


# A heredoc word's plain characters: as _PLAIN_WORD, but a $ right before a quote opens $'...' or $"...", unless it is
# the second $ of $$, the shell's PID.
_HEREDOC_PLAIN = re.compile(r"(?:[^ \t|&;()<>\\'\"$]|\$\$|\$(?!['\"]))+")
# An escape in $'...', and what bash 5.2 decodes it to (_ansi_c_escape).
_ANSI_C_ESCAPE = re.compile(r"\\(?:([0-7]{1,3})|x([0-9A-Fa-f]{1,2})|u([0-9A-Fa-f]{1,4})|U([0-9A-Fa-f]{1,8})|c(.)|(.))",
                            re.DOTALL)
_ANSI_C_LETTERS = {"a": 7, "b": 8, "e": 27, "E": 27, "f": 12, "n": 10, "r": 13, "t": 9, "v": 11, "\\": 92, "'": 39,
                   '"': 34, "?": 63}


def _ansi_c_escape(match: re.Match) -> str:
    """The character an escape in $'...' stands for: an octal byte, a hex byte, a Unicode code point, a control
    character (\\cx), or a letter's (\\n); an unknown escape, or a code point past U+10FFFF, stays as it is."""
    octal, byte, short, long, control, other = match.groups()
    if octal:
        return chr(int(octal, 8) & 0xFF)
    digits = byte or short or long
    if digits:
        value = int(digits, 16)
        return chr(value) if value <= 0x10FFFF else match.group()
    if control is not None:
        return chr(0x7F if control == "?" else ord(control) & 0x1F)
    return chr(_ANSI_C_LETTERS[other]) if other in _ANSI_C_LETTERS else match.group()


def _ansi_c_quoted(text: str, i: int) -> tuple[str | None, int]:
    """Quote removal for the $'...' string whose quote is text[i], with its escapes decoded.

    Returns (contents, index past the closing quote), or (None, len(text)) if the quote never closes. A backslash
    escapes the next character, so \\' does not close the string.
    """
    end = i + 1
    while (found := _QUOTE_STOP["'"].search(text, end)) is not None:
        if found.group() == "'":
            return _ANSI_C_ESCAPE.sub(_ansi_c_escape, text[i + 1 : found.start()]), found.end()
        end = found.end() + 1
    return None, len(text)


def _heredoc_word(text: str, i: int) -> tuple[str | None, int]:
    """Read the delimiter word that follows a heredoc operator ending at text[i], with quote removal.

    Returns (delimiter, index past the word). The delimiter is None when no word follows or a quote never
    closes, so `<<'EOF`, `<<` alone, `<< |` and `<<#x` open nothing. As in bash (checked with 5.2), $'...' is
    read with its escapes decoded and $"..." as "...", so <<$'EOF' ends at a line EOF, not $EOF.
    """
    i = _BLANKS.match(text, i).end()
    if text.startswith("#", i):  # an unquoted # here starts a comment to the end of the line (bash rejects it),
        return None, len(text)  # so no later << on the line opens a heredoc either
    start = i
    parts: list[str] = []
    while i < len(text):
        ch = text[i]
        if ch == "\\":
            parts.append(text[i + 1 : i + 2])
            i = min(i + 2, len(text))
        elif ch == "'":
            end = text.find("'", i + 1)
            if end < 0:
                return None, len(text)
            parts.append(text[i + 1 : end])
            i = end + 1
        elif ch == '"':
            quoted, i = _double_quoted(text, i + 1)
            if quoted is None:
                return None, i
            parts.append(quoted)
        elif text.startswith(("$'", '$"'), i):
            quoted, i = _ansi_c_quoted(text, i + 1) if text[i + 1] == "'" else _double_quoted(text, i + 2)
            if quoted is None:
                return None, i
            parts.append(quoted)
        else:
            run = _HEREDOC_PLAIN.match(text, i)
            if run is None:  # a blank or a shell metacharacter ends the word
                break
            parts.append(run.group())
            i = run.end()
    if i == start:
        return None, i
    return "".join(parts), i


# Known limitations of the heredoc scan. It does not model these, so a << inside them that bash reads as text
# still opens a heredoc here (one that consumes lines only if a line equal to its delimiter follows):
# - the (( )) arithmetic command, as in (( m = 1<<n ));
# - $[ ] arithmetic, as in $[1<<n];
# - parameter expansions, as in ${x:-<<word};
# - << inside a command substitution nested in double quotes, as in "$(echo "<<word")".
def _heredoc_openers(command: str) -> list[tuple[str, bool]]:
    """The heredocs a command line opens, in order, as (delimiter, strip_tabs) pairs.

    << and <<- count only outside quotes, comments and $(( )) arithmetic, and never as part of a <<< here-string.
    """
    openers: list[tuple[str, bool]] = []
    if "<<" not in command:
        return openers
    arithmetic = 0  # parentheses still open in the $(( )) being scanned; 0 outside arithmetic
    i = _next_unquoted(command, 0)
    while i >= 0 and command[i] != "#":
        resume = i + 1
        if arithmetic:
            if command[i] == "(":
                arithmetic += 1
            elif command[i] == ")":
                arithmetic -= 1
        elif command.startswith("$((", i):
            arithmetic, resume = 2, i + 3
        elif command.startswith("<<<", i):
            resume = i + 3
        elif command.startswith("<<", i):
            strip_tabs = command.startswith("<<-", i)
            delimiter, resume = _heredoc_word(command, i + 3 if strip_tabs else i + 2)
            if delimiter is not None:
                openers.append((delimiter, strip_tabs))
        i = _next_unquoted(command, resume)
    return openers


def _line_positions(lines) -> dict[str, list[int]]:
    positions: dict[str, list[int]] = {}
    for k, line in enumerate(lines):
        positions.setdefault(line, []).append(k)
    return positions


class _Terminators:
    """Finds the line that ends a heredoc body.

    The lines are indexed once, on first use, so many heredocs (even unterminated ones) never rescan the input.
    """

    def __init__(self, lines: list[str]) -> None:
        self._lines = lines
        self._index: dict[bool, dict[str, list[int]]] = {}

    def find(self, delimiter: str, strip_tabs: bool, start: int) -> int | None:
        """Index of the first line at or after start that ends the heredoc, or None if no line does.

        For <<, the line must equal the delimiter exactly; for <<-, after its leading tabs are stripped.
        """
        if strip_tabs not in self._index:
            lines = (line.lstrip("\t") for line in self._lines) if strip_tabs else self._lines
            self._index[strip_tabs] = _line_positions(lines)
        found = self._index[strip_tabs].get(delimiter, [])
        k = bisect.bisect_left(found, start)
        return found[k] if k < len(found) else None


def _continues(line: str, continuation: str) -> bool:
    """Whether a physical line continues onto the next one.

    It must end in an odd number of continuation characters (an even run is escaped continuation characters),
    and a line with a comment never continues: the continuation character is part of the comment.
    """
    if not continuation:
        return False
    end, run = len(line), 0
    while line.endswith(continuation, 0, end):
        end -= len(continuation)
        run += 1
    return run % 2 == 1 and not _has_comment(line)


def _join_pieces(segments: list[list[str]]) -> tuple[str, tuple[int, ...]]:
    """A record's text, built from its physical lines, and where each line after the first starts in it.

    Each piece is one physical line, in order. A segment's pieces are joined by spaces, empty ones skipped, the
    segments by newlines, and the result is stripped of blanks and newlines. The offsets, one per line after the first,
    never decrease: an
    empty piece gets the offset where the next text would go, so a part's line is the record's first line plus the
    number of offsets at or before the part's first character (RawCommand.line_starts).
    """
    if len(segments) == 1 and len(segments[0]) == 1:  # one physical line
        return segments[0][0].strip(_SHELL_BLANKS), ()
    out: list[str] = []
    starts: list[int] = []
    size = 0
    for s, segment in enumerate(segments):
        if s:
            out.append("\n")
            size += 1
        written = False  # whether this segment has text yet, so that the next piece goes after a space
        for k, piece in enumerate(segment):
            if piece and written:
                out.append(" ")
                size += 1
            if s or k:
                starts.append(size)
            if piece:
                out.append(piece)
                size += len(piece)
                written = True
    text = "".join(out)
    stripped = text.strip(_PART_EDGES)
    lead = len(text) - len(text.lstrip(_PART_EDGES))
    return stripped, tuple(min(max(offset - lead, 0), len(stripped)) for offset in starts)


def _join_simple(lines: list[str], continuation: str = "\\",
                 unjoined: list[tuple[int, int, str]] | None = None) -> list[tuple[int, str, tuple[int, ...]]]:
    """Join physical lines into logical commands by continuations and heredocs only, each line read on its own.

    A line ending in an unescaped continuation character is joined with the next one, unless it has a comment.
    A heredoc's body stays with the command that opened it, through its terminator line; a heredoc that is never
    terminated consumes nothing. A body that would make the record too long to store whole (its text, controls
    shown, then normalized, past MAX_LINE) is not joined, since truncation could hide a command piped into
    bash <<EOF: the command stays a record of its own, each line of the body and its terminator becomes one too, and
    the run is added to unjoined, if given. Returns (1-based number of the first physical line, text, where each
    later physical line starts in it) for each record, as join_logical_records does, and drops blank lines.
    join_logical_records reads lines this way when it cannot keep them joined (see the notes above _scan_line), and
    when their continuation character is not a backslash.
    """
    out: list[tuple[int, str, tuple[int, ...]]] = []
    terminators = _Terminators(lines)
    i = 0
    while i < len(lines):
        start = i
        pieces = [lines[i]]
        i += 1
        while i < len(lines) and _continues(lines[i - 1], continuation):  # the physical line, as bash reads it
            pieces[-1] = pieces[-1][: -len(continuation)].rstrip(_SHELL_BLANKS)
            pieces.append(lines[i].lstrip(_SHELL_BLANKS))
            i += 1
        text = " ".join(piece for piece in pieces if piece)
        body_end = i
        for delimiter, strip_tabs in _heredoc_openers(text):
            end = terminators.find(delimiter, strip_tabs, body_end)
            if end is None:  # no terminator: the following lines stay commands of their own
                break
            body_end = end + 1
        if body_end == i and len(pieces) == 1:  # the common case: a line on its own
            record, starts = text.strip(_SHELL_BLANKS), ()
        else:
            record, starts = _join_pieces([pieces, *([line] for line in lines[i:body_end])])
        if body_end > i and len(normalize_text(show_controls(record))) > MAX_LINE:
            command, command_starts = _join_pieces([pieces])
            if command:
                out.append((start + 1, command, command_starts))
            out.extend((k + 1, lines[k].strip(_SHELL_BLANKS), ()) for k in range(i, body_end)
                       if lines[k].strip(_SHELL_BLANKS))
            if unjoined is not None:
                unjoined.append((start + 1, body_end, _HEREDOC_TOO_LONG))
        elif record:
            out.append((start + 1, record, starts))
        i = body_end
    return out


# The bash joiner (join_logical_lines) scans each physical line with a stack of the contexts still open at its start,
# innermost last, so it knows whether a newline ends a command or falls inside a string, a substitution or an array:
# - strings: '...' (nothing is special in it), "..." (a backslash escapes, and $( ), $(( )) and `...` nest in it),
#   $'...' and `...` (a backslash escapes);
# - in code: $( ), <( ) and >( ) substitutions, $(( )) arithmetic and the (( )) arithmetic command, name=( ) and
#   name+=( ) array assignments, and any other ( ), such as a subshell's or a function's (), which is tracked only so
#   that its ) matches;
# - in code, as the one-line scans read them: backslash escapes, comments (a # where a word starts) and heredoc
#   operators, but not in arithmetic. As bash does (checked with bash 5), it also reads a # right after a ) that ends
#   a subshell, a function's (), a (( )) command or a case pattern as starting a comment, while a # right after the )
#   of a substitution, $(( )) or an array, or after }, is part of a word.
# A newline inside a string, a substitution, arithmetic or an array assignment joins the next line to the record,
# newline and all, as bash reads it. A newline in code ends a command line: the bodies of the heredocs that line opened
# follow it, and the record goes on if one of those contexts is still open, or if the line ends in |, ||, |& or &&
# (then the next line joins with a space, unless a heredoc body came between). Any other ( ) left open joins nothing,
# so the lines of a multi-line subshell stay apart, as before.
# So eval and sh -c bodies spanning lines go whole to the model, as heredoc bodies do. Lines joined that way stay one
# record only while it is short enough to store whole: its stored text (controls shown, then normalized) must fit in
# MAX_LINE, and reading stops once the record passes _JOIN_LIMIT characters. A record too long, a quote or bracket
# still open at the end of the lines, and nesting deeper than _MAX_DEPTH each send the lines read back to _join_simple,
# which can only over-report, and the reader warns about them. So does a command that its heredoc bodies alone make
# too long, and _join_simple then keeps those bodies apart too.
# split_commands then splits a record that spans lines at the newlines that end a command and at ;, && and ||, so a
# record that spans lines keeps only one command whose arguments span them.
# Known limitations of the joiner's scan:
# - a case pattern's ) inside $( ) closes the substitution early, so the lines after it are not joined to it;
# - ${ } parameter expansions are read as code, so a quote or a # inside one is read as it would be outside it;
# - a backtick string is read as a string, so quotes nested in a command inside it are text;
# - a heredoc word that a backslash continuation splits, as in cat <<\ then EOF on the next line, opens nothing;
# - every (( is read as the arithmetic command, so ((cd /tmp); ls) is read as arithmetic too (its ) still match);
# - one quote that never closes, early in a file, turns the new joining off for the lines after it, up to
#   _JOIN_LIMIT characters or the end of the file: they are read one by one, which can only over-report.
_JOIN_LIMIT = 4 * MAX_LINE  # larger than MAX_LINE, since a blob in the record shrinks to its marker when normalized
_MAX_DEPTH = 64
_UNCLOSED = "a quote or bracket in the command starting here never closes"
_TOO_LONG = f"joined, these lines would pass {MAX_LINE} characters"
_HEREDOC_TOO_LONG = f"with its heredoc body, this command would pass {MAX_LINE} characters"
_TOO_DEEP_NESTING = f"quotes and brackets nest more than {_MAX_DEPTH} deep"
# How a physical line ends.
_ENDS, _COMMENT, _CONTINUES, _IN_STRING, _TOO_DEEP = range(5)
# The contexts on the stack. Each entry is [context, open parentheses], the count used by arithmetic only.
_SINGLE, _DOUBLE, _ANSI_C, _BACKTICK, _SUBSTITUTION, _ARITHMETIC, _ARRAY, _PARENS, _ARITHMETIC_COMMAND = range(9)
_STRINGS = frozenset((_SINGLE, _DOUBLE, _ANSI_C, _BACKTICK))
_JOINING = frozenset((_SINGLE, _DOUBLE, _ANSI_C, _BACKTICK, _SUBSTITUTION, _ARITHMETIC, _ARRAY, _ARITHMETIC_COMMAND))
_COUNTING = frozenset((_ARITHMETIC, _ARITHMETIC_COMMAND))  # contexts that count their parentheses
_CLOSER = {_SINGLE: "'", _DOUBLE: '"', _ANSI_C: "'", _BACKTICK: "`"}
_OPENER = {"'": _SINGLE, '"': _DOUBLE, "$'": _ANSI_C, "`": _BACKTICK, "$(": _SUBSTITUTION, "<(": _SUBSTITUTION,
           ">(": _SUBSTITUTION, "$((": _ARITHMETIC, "=(": _ARRAY, "((": _ARITHMETIC_COMMAND, "(": _PARENS}
# The tokens of code: a whole string with nothing special in it (skipped in one step), an escape, a quote, $$ (the
# shell's PID, which opens nothing), $' $(( $(, a here-string or heredoc operator, <( >( =(, (( ( ) and #.
# Arithmetic has no heredocs or comments.
_CODE_TOKEN = re.compile(r"'[^']*'|\"[^\"\\`$]*\"|\\.?|\(\(|['\"`#()]|\$\$|\$'|\$\(\(|\$\(|<<<|<<-?|[<>=]\(")
_ARITHMETIC_TOKEN = re.compile(r"'[^']*'|\"[^\"\\`$]*\"|\\.?|['\"`()]|\$\$|\$'|\$\(\(|\$\(")
# The tokens of each string: its closing quote, an escape, and in "..." what nests in it.
_STRING_TOKEN = {_SINGLE: re.compile("'"), _DOUBLE: re.compile(r'\\.?|"|`|\$\$|\$\(\(|\$\('),
                 _ANSI_C: re.compile(r"\\.?|'"), _BACKTICK: re.compile(r"\\.?|`")}
# A line with none of these, read at the top level, opens nothing and does not continue with a backslash.
_NEEDS_SCAN = re.compile(r"['\"`(\\#]|<<")


def _heredoc_operator(line: str, start: int, pos: int, strip_tabs: bool,
                      heredocs: list[tuple[str, bool, int]]) -> tuple[int | None, int]:
    """Read the word of the heredoc operator at line[start:pos], for _scan_line.

    Returns (how the line ends, or None to scan on, the index to scan on from), and adds an opened heredoc to heredocs.
    An unquoted # starts a comment, so the operator has no word. With no word, the scan goes on right after the
    operator, so a quote that opens and does not close is read as a string. A word that ends in the line's
    continuation backslash continues the line, as in _join_simple; a word that is only that backslash opens nothing.
    """
    word = _BLANKS.match(line, pos).end()
    if line.startswith("#", word):
        return _COMMENT, pos
    delimiter, end = _heredoc_word(line, pos)
    if delimiter is None or line[word:end] == "\\":
        return None, pos
    heredocs.append((delimiter, strip_tabs, start))
    if end == len(line) and line.endswith("\\") and (len(line) - len(line.rstrip("\\"))) % 2:
        return _CONTINUES, end
    return None, end


def _scan_line(line: str, stack: list[list[int]], heredocs: list[tuple[str, bool, int]]) -> int:
    """Scan one physical line in the contexts an earlier line left open on the stack, and update the stack.

    The heredocs it opens in code are added to heredocs, as (delimiter, strip_tabs, index of the operator). Returns
    how the line ends: _ENDS in code, _COMMENT in a comment, _CONTINUES at an unescaped backslash in code,
    _IN_STRING, or _TOO_DEEP when the stack would pass _MAX_DEPTH (only crafted input goes there).
    """
    pos = 0
    escape_end = -1  # where the last escape in code ended: a # right there is part of a word
    paren_end = -1  # where the last ) that ends a word ended: a # right there starts a comment
    while True:
        context = stack[-1][0] if stack else None
        if context in _STRINGS:
            found = _STRING_TOKEN[context].search(line, pos)
            if found is None:
                return _IN_STRING
            token, pos = found.group(), found.end()
            if token == _CLOSER[context]:
                stack.pop()
            elif token[0] != "\\" and token != "$$":  # ` $( or $(( nested in "..."
                if len(stack) >= _MAX_DEPTH:
                    return _TOO_DEEP
                stack.append([_OPENER[token], 2])
            continue
        found = (_ARITHMETIC_TOKEN if context in _COUNTING else _CODE_TOKEN).search(line, pos)
        if found is None:
            return _ENDS
        token, start, pos = found.group(), found.start(), found.end()
        if token == "\\":  # a backslash with nothing after it
            return _CONTINUES
        if token[0] == "\\":
            escape_end = pos
        elif token == "#":
            if start == 0 or start == paren_end or (line[start - 1] in _COMMENT_AFTER and start != escape_end):
                return _COMMENT
        elif token == ")":
            if context in _COUNTING:
                stack[-1][1] -= 1
                if stack[-1][1] == 0:
                    stack.pop()
                    if context == _ARITHMETIC_COMMAND:
                        paren_end = pos
            elif not stack:  # a ) with nothing open, as after a case pattern, ends a word
                paren_end = pos
            elif stack.pop()[0] == _PARENS:  # so does the ) of a subshell or a function's ()
                paren_end = pos
        elif token == "(" and context in _COUNTING:
            stack[-1][1] += 1
        elif token in _OPENER:
            if len(stack) >= _MAX_DEPTH:
                return _TOO_DEEP
            stack.append([_OPENER[token], 2])
        elif token in ("<<", "<<-"):
            how, pos = _heredoc_operator(line, start, pos, token == "<<-", heredocs)
            if how is not None:
                return how
        # Anything else (a whole string, $$ or <<<) opens nothing.


def _escaped(text: str, k: int) -> bool:
    """Whether text[k] follows an odd run of backslashes, which escapes it."""
    run = 0
    while k - run > 0 and text[k - run - 1] == "\\":
        run += 1
    return run % 2 == 1


def _ends_in_operator(line: str) -> bool:
    """Whether a line scanned to its end in code ends in |, ||, |& or &&, which continue the command on the next line.

    The operator must not be escaped, and a | right after an unescaped > is the >| redirection, not a pipe.
    """
    if not line or line[-1] not in "|& \t":
        return False
    end = len(line.rstrip(" \t"))
    if end == 0:
        return False
    if line[end - 1] == "|":
        return not _escaped(line, end - 1) and not (end >= 2 and line[end - 2] == ">" and not _escaped(line, end - 2))
    return line[end - 1] == "&" and end >= 2 and line[end - 2] in "&|" and not _escaped(line, end - 2)


def _stands_alone(line: str) -> bool:
    """Whether a line read at the top level is a record of its own: it opens no heredoc and nothing that joins lines,
    and does not continue with a backslash or an operator. Most lines are, so join_logical_lines checks this first."""
    if _NEEDS_SCAN.search(line) is None:
        return not _ends_in_operator(line)
    stack: list[list[int]] = []
    heredocs: list[tuple[str, bool, int]] = []
    how = _scan_line(line, stack, heredocs)
    if how not in (_ENDS, _COMMENT) or heredocs or any(entry[0] in _JOINING for entry in stack):
        return False
    return how == _COMMENT or not _ends_in_operator(line)


def _read_record(lines: list[str], first: int,
                 terminators: _Terminators) -> tuple[int, str, tuple[int, ...], str | None]:
    """Read the logical line that starts at lines[first], as the notes above _scan_line describe.

    Returns (index past its last line, its text, where each later physical line starts in it (_join_pieces), None),
    or (index past the lines read, "", (), the reason) when the lines read must fall back to _join_simple.
    """
    stack: list[list[int]] = []
    heredocs: list[tuple[str, bool, int]] = []
    segments = [[lines[first]]]  # joined by newlines, each a list of pieces joined by spaces
    joined = False  # whether a string, a bracket or an operator joined a line: the limits apply only then
    bodies = False  # whether the record holds a heredoc body: its stored length is checked then too
    size = len(lines[first])
    i = first
    while True:
        line = lines[i]
        how = _scan_line(line, stack, heredocs) if stack or _NEEDS_SCAN.search(line) else _ENDS
        if how == _TOO_DEEP:
            return i + 1, "", (), _TOO_DEEP_NESTING
        if how == _CONTINUES:
            separator, still_open = " ", False
        elif how == _IN_STRING:
            separator, still_open = "\n", True
        else:  # the newline ends a command line, and the bodies of the heredocs that line opened follow it
            body = False
            for delimiter, strip_tabs, _ in heredocs:
                end = terminators.find(delimiter, strip_tabs, i + 1)
                if end is None:  # no terminator: the following lines stay commands of their own
                    break
                segments.extend([body_line] for body_line in lines[i + 1 : end + 1])
                size += sum(len(body_line) + 1 for body_line in lines[i + 1 : end + 1])
                i, body, bodies = end, True, True
            heredocs.clear()
            if any(entry[0] in _JOINING for entry in stack):
                separator, still_open = "\n", True
            elif how == _ENDS and _ends_in_operator(line):
                separator, still_open = ("\n" if body else " "), False
            else:
                break
        if how != _CONTINUES:
            joined = True
        if i + 1 == len(lines):
            if still_open:
                return len(lines), "", (), _UNCLOSED
            break  # a final continuation or operator stays as it is
        i += 1
        if separator == "\n":
            segments.append([lines[i]])
        else:
            piece = segments[-1][-1]
            segments[-1][-1] = (piece[:-1] if how == _CONTINUES else piece).rstrip(_SHELL_BLANKS)
            segments[-1].append(lines[i].lstrip(_SHELL_BLANKS))
        size += len(lines[i]) + 1
        if joined and size > _JOIN_LIMIT:
            return i + 1, "", (), _TOO_LONG
    text, starts = _join_pieces(segments)
    if (joined or bodies) and len(normalize_text(show_controls(text))) > MAX_LINE:
        return i + 1, "", (), _TOO_LONG if joined else _HEREDOC_TOO_LONG
    return i + 1, text, starts, None


def join_logical_records(lines: list[str], continuation: str = "\\",
                         unjoined: list[tuple[int, int, str]] | None = None) -> list[tuple[int, str, tuple[int, ...]]]:
    """Join physical lines into logical commands, and record where each physical line starts in each one.

    With a backslash continuation (bash), lines join as the notes above _scan_line describe: by continuations and
    heredocs as before, and also by strings, substitutions and array assignments that span lines, and by a line that
    ends in |, ||, |& or &&. Lines that would join into a record too long to store whole, heredoc bodies included,
    or that leave a quote or bracket open at the end, are read as _join_simple reads them instead, and each such run
    is added to unjoined, if given, as (its first line, its last line, the reason), numbered from 1. Any other
    continuation character gets _join_simple's reading. Returns (1-based number of the first physical line, text,
    where each later physical line starts in text) for each record, and drops blank lines. The offsets are those of
    RawCommand.line_starts (_join_pieces): a continuation or an operator joins lines with a space, so a part of the
    record is numbered from them rather than from its newlines.
    """
    if continuation != "\\":
        return _join_simple(lines, continuation, unjoined)
    out: list[tuple[int, str, tuple[int, ...]]] = []
    terminators = _Terminators(lines)
    i = 0
    while i < len(lines):
        line = lines[i]
        if _stands_alone(line):  # the common case, checked without building a record
            if line.strip(_SHELL_BLANKS):
                out.append((i + 1, line.strip(_SHELL_BLANKS), ()))
            i += 1
            continue
        end, text, starts, reason = _read_record(lines, i, terminators)
        if reason is None:
            if text:
                out.append((i + 1, text, starts))
        else:
            out.extend((i + k, piece, piece_starts) for k, piece, piece_starts in _join_simple(lines[i:end]))
            if unjoined is not None:
                unjoined.append((i + 1, end, reason))
        i = end
    return out


def join_logical_lines(lines: list[str], continuation: str = "\\",
                       unjoined: list[tuple[int, int, str]] | None = None) -> list[tuple[int, str]]:
    """join_logical_records without the line starts: (1-based number of the first physical line, text) pairs."""
    return [(number, text) for number, text, _ in join_logical_records(lines, continuation, unjoined)]


def _command_chunks(text: str) -> list[tuple[int, int, list[tuple[int, int]], list[tuple[int, int]]]]:
    """Split text that spans lines at the newlines that end a command, reading it as _read_record does.

    A newline ends a command when it is in code at the top level: not inside a string, a substitution, arithmetic, an
    array or any other ( ), not right after a backslash, and not after a line that ends in |, ||, |& or &&. The bodies
    of the heredocs a line opens follow that line and belong to its chunk. Returns, for each chunk,
    (begin, end, bodies, uncut): text[begin:end], the (begin, end) of each heredoc body in it, and the ranges from a
    heredoc operator to its body, in which split_command_spans makes no cut. Past _MAX_DEPTH, the rest of the text is
    one chunk. Each line is scanned once and each body found by the terminator index, so this is linear.
    """
    lines = text.split("\n")
    terminators = _Terminators(lines)
    chunks: list[tuple[int, int, list[tuple[int, int]], list[tuple[int, int]]]] = []
    stack: list[list[int]] = []
    heredocs: list[tuple[str, bool, int]] = []
    bodies: list[tuple[int, int]] = []
    uncut: list[tuple[int, int]] = []
    begin = offset = 0  # where the current chunk begins, and where lines[i] begins
    operator_at = -1  # where the first heredoc operator still waiting for its body is
    i = 0
    while i < len(lines):
        line = lines[i]
        how = _scan_line(line, stack, heredocs) if stack or _NEEDS_SCAN.search(line) else _ENDS
        if how == _TOO_DEEP:
            break
        if heredocs and operator_at < 0:
            operator_at = offset + heredocs[0][2]
        offset += len(line) + 1
        if how in (_CONTINUES, _IN_STRING):
            i += 1
            continue
        for delimiter, strip_tabs, _ in heredocs:
            end = terminators.find(delimiter, strip_tabs, i + 1)
            if end is None:  # no terminator: the following lines stay commands of their own
                break
            body_begin = offset
            offset += sum(len(body_line) + 1 for body_line in lines[i + 1 : end + 1])
            bodies.append((body_begin, offset - 1))
            if operator_at >= 0:
                uncut.append((operator_at, body_begin))
                operator_at = -1
            i = end
        heredocs.clear()
        operator_at = -1
        if not stack and not (how == _ENDS and _ends_in_operator(line)):
            chunks.append((begin, offset - 1, bodies, uncut))
            begin, bodies, uncut = offset, [], []
        i += 1
    if begin < len(text):
        chunks.append((begin, len(text), bodies, uncut))
    return chunks


# The check for a plain heredoc write (is_plain_heredoc_write). Each limit closes a way in which a record that looks
# like one runs something else in bash 5.2 (checked in a container).
# Text the first line may not hold anywhere, even in quotes: a substitution runs its command, and some builtins run one
# in a quoted word, as read 'a[$(id)]' <<A does.
_RUNS_CODE = ("$(", "`", "<(", ">(")
# A reserved word that starts the first line makes it a compound command or a syntax error, and after a syntax error
# an interactive bash drops the line, heredoc and all, and runs the body's lines as commands.
_RESERVED_WORDS = frozenset(
    "! [[ ]] { } case coproc do done elif else esac fi for function if in select then time until while".split())
# What the first line's scan stops at outside quotes and escapes: blanks, a comment, the separators, ( ), both
# redirection characters and $.
_WORD_SPECIAL = re.compile(r"[\\'\"`#;&|()<>$ \t]")
# The redirection operators, longest first in each family. &> and &>> are read only where an & is followed by >.
_REDIRECTIONS = ("<<<", "<<-", "<<", "<>", "<&", "<", ">>", ">|", ">&", ">", "&>>", "&>")
# Digits or a {name} right before < or >, which bash reads as the descriptor of the next redirection, not as a word.
_DESCRIPTOR = re.compile(r"(?:[0-9]+|\{[A-Za-z_][A-Za-z0-9_]*\})[<>]")
_BRACED_NAME = re.compile(r"[A-Za-z_][A-Za-z0-9_]*\}")


def _simple_command_words(line: str) -> list[str] | None:
    r"""The words of a line that _scan_line read to its end in code, as written and without its redirections, if it
    is one simple command whose standard input is its heredoc; otherwise None. For is_plain_heredoc_write.

    One simple command: its first word is not a reserved word, and outside quotes and escapes it holds no comment, no
    ;, | or |&, no ( or ), no & but in a redirection operator, no redirection operator without a word after it (a
    syntax error; in < 2>&1, the 2 is the next redirection's descriptor), no ${ } but ${name}, and no $( or $[ ].
    Like _cuts, this also stops at an & right after an escaped character, as in a\>& b, which bash reads as a
    background job. The heredoc must read into descriptor 0, and no other redirection may touch it (cat <<A <x reads
    x). A redirection leaves out its operator, its descriptor and its word. Each character is scanned a bounded number
    of times, so this is linear.
    """
    begin = _BLANKS.match(line).end()  # where the current word begins, or -1 between words
    first = _PLAIN_WORD.match(line, begin)
    if first is not None and first.group() in _RESERVED_WORDS:
        return None
    words: list[str] = []
    target = False  # whether the current word is a redirection's
    i = _next_unquoted(line, begin, _WORD_SPECIAL)
    while True:
        stop = len(line) if i < 0 else i
        ch = line[i] if i >= 0 else ""
        operator = ch in ("<", ">") or line.startswith("&>", stop)
        if ch in ("", " ", "\t") or operator:  # the current word ends here
            descriptor = ""
            if 0 <= begin < stop:
                if target:
                    target = False
                elif operator and _DESCRIPTOR.match(line, begin):
                    descriptor = line[begin:stop]
                else:
                    words.append(line[begin:stop])
            if not ch:
                return words
            if not operator:
                begin = _BLANKS.match(line, i).end()
                i = _next_unquoted(line, begin, _WORD_SPECIAL)
                continue
            redirection = next(op for op in _REDIRECTIONS if line.startswith(op, i))
            if (redirection in ("<<", "<<-")) != ((descriptor or ("0" if ch == "<" else "1")) == "0"):
                return None  # the heredoc reads into another descriptor, or something else redirects 0
            begin = _BLANKS.match(line, i + len(redirection)).end()
            if begin == len(line) or line[begin] in "|&;()<>" or _DESCRIPTOR.match(line, begin):
                return None
            target = True
            i = _next_unquoted(line, begin, _WORD_SPECIAL)
        elif ch == "$":
            i += 1
            if line.startswith(("(", "["), i):
                return None
            if line.startswith("{", i):
                name = _BRACED_NAME.match(line, i + 1)
                if name is None:
                    return None
                i = name.end()
            i = _next_unquoted(line, i, _WORD_SPECIAL)
        else:  # a comment, ;, |, (, ) or an & that ends a command
            return None


# The commands that copy the standard input they read, as it is, are cat, tee and crontab (_copies_its_input), run from
# PATH or from a system folder. Any other command may run the body (an interpreter, ssh, exec, an editor such as ed or
# vim, whose scripts run commands with ! and :!) or write something else.
_SYSTEM_FOLDERS = ("/bin/", "/usr/bin/")
_ASSIGNMENT = re.compile(r"[A-Za-z_][A-Za-z0-9_]*\+?=")
# sudo's options that leave the command and its standard input alone: flags, and the user or group to run as. -S would
# read a password from the body, and -A, -e, -i, -s and the rest do something else.
_SUDO_FLAGS = frozenset("EHPkn")
_SUDO_LONG = frozenset(("--preserve-env", "--set-home", "--preserve-groups", "--reset-timestamp", "--non-interactive"))


def _program(word: str) -> str:
    """The program a command word names: the word, or its name in a system folder, or "" for any other path."""
    for folder in _SYSTEM_FOLDERS:
        if word.startswith(folder):
            word = word[len(folder) :]
            break
    return "" if "/" in word else word


def _sudo_options(words: list[str], k: int) -> int:
    """The index past sudo's options that start at words[k], or -1 if one may change what runs, or an assignment
    follows them (sudo PATH=/tmp/.x cat runs another cat)."""
    while k < len(words) and words[k].startswith("-"):
        option = words[k]
        k += 1
        if option == "--":
            break
        if option in ("-u", "-g"):
            k += 1
        elif not (option[:2] in ("-u", "-g") or option.startswith(("--user=", "--group=")) or option in _SUDO_LONG
                  or (option[1:2] != "-" and set(option[1:]) <= _SUDO_FLAGS and len(option) > 1)):
            return -1
    if k < len(words) and _ASSIGNMENT.match(words[k]):
        return -1
    return k


def _copies_its_input(words: list[str]) -> bool:
    """Whether a simple command's words (_simple_command_words) run cat, tee or crontab on its standard input.

    The wrappers sudo (with -E, -H, -P, -k, -n, -u USER or -g GROUP), env (with -i and -u NAME), command (with -p) and
    nohup are skipped. An assignment, before the command or behind env or sudo, makes it no plain write: PATH=/tmp/.x
    cat runs another cat, and LD_PRELOAD loads code into it. Then cat may take options and "-" but no file (cat FILE
    copies the file), tee any options and files, and crontab only -u USER and "-" or /dev/stdin (crontab -e runs an
    editor on the body). Words are compared as written, so a quoted name such as 'cat' is not recognized, which can
    only send a record to the model.
    """
    k = 0
    if words and _ASSIGNMENT.match(words[0]):
        return False
    while k < len(words):
        program = _program(words[k])
        k += 1
        if program == "sudo":
            k = _sudo_options(words, k)
            if k < 0:
                return False
        elif program == "env":
            while k < len(words) and (words[k] in ("-", "-i", "-u", "--ignore-environment")
                                      or words[k].startswith("--unset=")):
                k += 2 if words[k] == "-u" else 1
            if k < len(words) and _ASSIGNMENT.match(words[k]):
                return False
        elif program == "command":
            if words[k : k + 1] == ["-p"]:
                k += 1
        elif program != "nohup":
            args = words[k:]
            if program == "cat":  # options and "-" only: after --, any other word is a file
                ended = False
                for arg in args:
                    if arg != "-" and (ended or not arg.startswith("-")):
                        return False
                    ended = ended or arg == "--"
                return True
            if program == "crontab":
                if args[:1] == ["-u"]:
                    args = args[2:]
                elif args[:1] and args[0].startswith("-u"):
                    args = args[1:]
                return args in (["-"], ["/dev/stdin"])
            return program == "tee"
    return False


def is_plain_heredoc_write(text: str) -> bool:
    """Whether a record spanning lines is a copier writing one heredoc's body, with nothing else that bash runs.

    A rule that describes such a record's first line may describe the whole record (rules.Library.match_record): the
    other lines are the heredoc's body, which cat, tee or crontab copies as data. The record is read as bash reads it,
    with _scan_line, _heredoc_openers, _cuts and the other scans here rather than regexes. True only when:
    - the record holds no blank but space and tab and no control character but tab and newline, in any form
      (has_unusual_characters): bash drops a NUL, so a terminator EO<NUL>F, or a delimiter E<NUL>OF, ends the heredoc
      at a line EOF, where these scans do not;
    - the first line opens exactly one heredoc, as both _scan_line and _heredoc_openers read it, and holds no other
      "<<" at all: no here-string, no << in quotes, arithmetic or ${ }, no operator without a word, and no delimiter
      that blob replacement turned into "<<<";
    - it ends in code, with no string, bracket or substitution still open, no comment and no continuation, so the
      record spans lines only through the heredoc (sh -c '... <<EOF and ssh host "... <<K span them in a string);
    - it is one simple command: _cuts finds no ;, &&, || or background &, and _simple_command_words finds no |, |&
      or other &, no ( or ), no redirection without a word, no ${ } but ${name}, no $[ ] and no reserved word first,
      and no redirection but the heredoc on descriptor 0;
    - the command is cat, tee or crontab reading its standard input, perhaps behind sudo, env, command or nohup, with
      no assignment before it or behind a wrapper (_copies_its_input): an interpreter, ssh or exec runs the body, an
      editor's script can run commands, and PATH=... or LD_PRELOAD=... changes what runs;
    - it holds no $(, backtick, <( or >( anywhere, even in quotes, since read 'a[$(id)]' <<A runs id;
    - the heredoc's delimiter word holds no $: bash decodes the escapes of <<$'...', which this reads as bash 5.2 does
      (_heredoc_word), but a record with one is left to the model;
    - the lines after it are the body and then the terminator, the first line that ends the heredoc (for <<-, once
      its leading tabs are stripped), with nothing after it, not even a newline;
    - if the delimiter is unquoted, so that bash expands the body, no body line holds a $ that no backslash escapes
      (any expansion: a value set earlier runs through ${x@P}, and through $[x], ${y:x} or ${b[x]} when it holds a
      subscript), a backtick, or ends in a backslash, which bash would join to the next line before looking for the
      terminator.
    Each limit closes a way, checked with bash 5.2, in which such a record runs something else. Not modeled: what a
    name means where it is run (an alias or function named cat, or a PATH set earlier that finds another cat), and
    history expansion (!) in an interactive shell. Linear in the length of text.
    """
    first, newline, rest = text.partition("\n")
    if not newline or first.count("<<") != 1 or any(code in first for code in _RUNS_CODE):
        return False
    if has_unusual_characters(text):
        return False
    stack: list[list[int]] = []
    heredocs: list[tuple[str, bool, int]] = []
    if _scan_line(first, stack, heredocs) != _ENDS or stack or len(heredocs) != 1:
        return False
    delimiter, strip_tabs, operator = heredocs[0]
    if _heredoc_openers(first) != [(delimiter, strip_tabs)] or _cuts(first):
        return False
    words = _simple_command_words(first)
    if words is None or not _copies_its_input(words):
        return False
    after = operator + (3 if strip_tabs else 2)
    word = first[_BLANKS.match(first, after).end() : _heredoc_word(first, after)[1]]
    if "$" in word:
        return False
    *body, terminator = rest.split("\n")
    if strip_tabs:
        body, terminator = [line.lstrip("\t") for line in body], terminator.lstrip("\t")
    if terminator != delimiter or delimiter in body:
        return False
    if any(quote in word for quote in "'\"\\"):  # a quoted delimiter: the body is read as it is
        return True
    return not any("`" in line or line.endswith("\\") or _expands(line) for line in body)


def _expands(line: str) -> bool:
    """Whether a line of an unquoted heredoc body holds a $ that no backslash escapes, which bash expands. Each $ looks
    back only over the backslashes right before it, so this is linear."""
    k = line.find("$")
    while k >= 0:
        if not _escaped(line, k):
            return True
        k = line.find("$", k + 1)
    return False
