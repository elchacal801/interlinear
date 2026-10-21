"""Encoded payloads in a command, decoded as plain data: never run. Standard library only, for the parse stage.

Two kinds are decoded: base64 written on a line that also decodes base64 (base64 -d, FromBase64String, b64decode and
the like), and a PowerShell -EncodedCommand blob, which is base64 of UTF-16LE text. Parse stores what a payload holds
as child lines (model.Decoded), so the rules, IOC extraction and the model see the command it hides. Only text is
kept: a payload that decodes to bytes that are not mostly printable text is left alone. Every limit is small: a
payload decodes to at most MAX_DECODED_BYTES, a command gives at most MAX_PAYLOADS payloads out of at most
MAX_CANDIDATES words tried, and payloads inside payloads are decoded to MAX_DEPTH levels.
"""

from __future__ import annotations

import base64
import binascii
import re

MAX_DEPTH = 3
MAX_DECODED_BYTES = 64 * 1024
MAX_PAYLOADS = 8
MAX_CANDIDATES = 64
_TEXT_SHARE = 0.9  # the share of decoded characters that must be printable, tab, CR or LF
_MIN_TEXT = 2  # characters
BASE64 = "base64"
UTF16 = "base64-utf16le"

# A run of base64 characters, eight or more, that no other base64 character touches. Starts never fall inside a run,
# so the scan is linear.
_TOKEN = re.compile(r"(?<![A-Za-z0-9+/=])[A-Za-z0-9+/]{8,}={0,2}(?![A-Za-z0-9+/=])")
# Something on the line decodes base64: base64 with a decode option (-d, -D, -di, --decode, after up to 8 other
# options), .NET's FromBase64String, Python's b64decode, PHP's base64_decode, Ruby's decode64 or JavaScript's atob.
_DECODER = re.compile(r"(?i)(?<![\w.-])base64(?:[ \t]+-w[ \t]+[0-9]+|[ \t]+-[\w-]*){0,8}?[ \t]+-(?:[a-z]*d[a-z]*|-decode)"
                      r"(?![\w-])|frombase64string|b64decode|base64_decode|decode64|(?<![\w.])atob[ \t]*\(")
_POWERSHELL = re.compile(r"(?i)(?<![\w.-])(?:powershell|pwsh)(?:\.exe)?(?![\w-])")
# -e, -ec, -en..., -EncodedCommand (any prefix PowerShell accepts), with - or /, then the blob.
_ENCODED_COMMAND = re.compile(r"(?i)(?<![\w-])[-/]e(?:c|n[a-z]*)?[ \t]+[\"']?([A-Za-z0-9+/]{8,}={0,2})"
                              r"(?![A-Za-z0-9+/=])")


def payloads(text: str) -> list[tuple[str, str]]:
    """The candidate payloads in one command's text, in order, as (token, encoding): a PowerShell -EncodedCommand
    blob (UTF16) when the text names powershell or pwsh, and every base64 run when something on it decodes base64
    (BASE64). At most MAX_CANDIDATES."""
    found: dict[int, tuple[str, str]] = {}
    if _POWERSHELL.search(text):
        for match in _ENCODED_COMMAND.finditer(text):
            found[match.start(1)] = (match.group(1), UTF16)
    if _DECODER.search(text):
        for match in _TOKEN.finditer(text):
            found.setdefault(match.start(), (match.group(), BASE64))
            if len(found) >= MAX_CANDIDATES:
                break
    return [found[start] for start in sorted(found)][:MAX_CANDIDATES]


def _looks_utf16(data: bytes) -> bool:
    """Whether data reads as UTF-16LE text mostly in the ASCII range: most of its odd bytes are NUL."""
    return len(data) >= 4 and data[1::2].count(0) >= 0.9 * (len(data) // 2)


def _text(data: bytes, codec: str, truncated: bool) -> str | None:
    """data decoded strictly, or None. A cut payload may end inside a character, so up to three bytes are dropped."""
    for drop in range(4 if truncated else 1):
        try:
            return data[: len(data) - drop].decode(codec).removeprefix(chr(0xFEFF))  # without a byte order mark
        except UnicodeDecodeError:
            continue
    return None


def _is_text(text: str) -> bool:
    if len(text) < _MIN_TEXT:
        return False
    plain = sum(1 for ch in text if ch.isprintable() or ch in "\t\r\n")
    return plain >= _TEXT_SHARE * len(text)


def decode_payload(token: str, encoding: str) -> tuple[str, str, bool] | None:
    """What a payload holds, as (text, encoding, truncated), or None when it is not valid base64 or not text.

    Only the first MAX_DECODED_BYTES are decoded (truncated is then true). A BASE64 payload that reads as UTF-16LE
    is decoded as such, and reported as UTF16.
    """
    limit = MAX_DECODED_BYTES // 3 * 4  # base64 characters that decode to at most MAX_DECODED_BYTES
    truncated = len(token) > limit
    body = token[:limit] if truncated else token.rstrip("=")
    if len(body) % 4 == 1:
        return None
    try:
        data = base64.b64decode(body + "=" * (-len(body) % 4), validate=True)
    except (binascii.Error, ValueError):
        return None
    if encoding == BASE64 and _looks_utf16(data):
        encoding = UTF16
    if encoding == UTF16:
        data = data[: len(data) // 2 * 2]
    text = _text(data, "utf-16-le" if encoding == UTF16 else "utf-8", truncated)
    if text is None or not _is_text(text):
        return None
    return text, encoding, truncated
