"""Which characters stored and displayed text shows by their code point instead of writing them raw.

One rule, for every place that shows text: the parse stage's line text, names and warnings, glossing's free text, and
the Markdown view's last pass. A hidden character is one that draws nothing or changes the text around it, so text
holding it can read as something else: cu, then U+034F, then rl displays as curl but matches no rule, and the tag
characters spell text a model reads and an analyst never sees. Controls are each caller's to show, in its own form;
line text's form (show_controls) lives here because the bash joiner, which checks the length a record is stored at,
uses it too.

Standard library only: the parse stage's zipapp includes this module.
"""

from __future__ import annotations

import bisect
import functools
import re
import unicodedata

# The Default_Ignorable_Code_Point characters outside category Cf, from Unicode's DerivedCoreProperties.txt (checked
# against Unicode 18.0.0: 4,036 code points, 263 Mn, 4 Lo and 3,769 reserved Cn), and U+2800 BRAILLE PATTERN BLANK,
# which is not default ignorable but draws nothing. The Cf ones are found by category. The Cn ranges are reserved by
# Unicode for more default-ignorable characters. Sorted (first, last) ranges, both ends included.
_RANGES = (
    (0x034F, 0x034F),  # Mn  COMBINING GRAPHEME JOINER
    (0x115F, 0x1160),  # Lo  HANGUL CHOSEONG FILLER, HANGUL JUNGSEONG FILLER
    (0x17B4, 0x17B5),  # Mn  KHMER VOWEL INHERENT AQ, KHMER VOWEL INHERENT AA
    (0x180B, 0x180D),  # Mn  MONGOLIAN FREE VARIATION SELECTOR ONE to THREE
    (0x180F, 0x180F),  # Mn  MONGOLIAN FREE VARIATION SELECTOR FOUR
    (0x2065, 0x2065),  # Cn  reserved
    (0x2800, 0x2800),  # So  BRAILLE PATTERN BLANK
    (0x3164, 0x3164),  # Lo  HANGUL FILLER
    (0xFE00, 0xFE0F),  # Mn  VARIATION SELECTOR-1 to 16
    (0xFFA0, 0xFFA0),  # Lo  HALFWIDTH HANGUL FILLER
    (0xFFF0, 0xFFF8),  # Cn  reserved
    (0xE0000, 0xE0000),  # Cn  reserved
    (0xE0002, 0xE001F),  # Cn  reserved
    (0xE0080, 0xE00FF),  # Cn  reserved
    (0xE0100, 0xE01EF),  # Mn  VARIATION SELECTOR-17 to 256
    (0xE01F0, 0xE0FFF),  # Cn  reserved
)
_FIRSTS = [first for first, _ in _RANGES]
_SEPARATORS = (0x2028, 0x2029)  # LINE SEPARATOR and PARAGRAPH SEPARATOR, which are whitespace, not Cf
_NOT_ASCII = re.compile("[^" + chr(0) + "-" + chr(0x7F) + "]")
# Line text shows each control but tab and newline, and each hidden character, with printable characters that are
# never digits or word characters, so a defanging pattern still sees an address written right after one, and that are
# not shell metacharacters, so the splitters read the line as before. C0 controls and DEL become their Unicode control
# pictures (U+2400 to U+241F, U+2421). The rest have none, so U+0085 becomes U+27E8, "U+0085" and U+27E9, and U+E0041
# becomes U+27E8, "U+E0041" and U+27E9: angle brackets that, unlike < and >, cannot make bash read a following # as a
# comment.
_LINE_CONTROL_FORMS = {code: chr(0x2400 + code) for code in range(0x20) if code not in (0x09, 0x0A)}
_LINE_CONTROL_FORMS[0x7F] = chr(0x2421)
_LINE_CANDIDATES = re.compile("[^" + chr(0x09) + chr(0x0A) + chr(0x20) + "-" + chr(0x7E) + "]")


def is_hidden(ch: str) -> bool:
    """Whether ch is shown by its code point: a format character (Cf), U+2028 or U+2029, a default-ignorable code
    point outside Cf, or U+2800. No ASCII character is: controls are each caller's to show."""
    code = ord(ch)
    if code < 0x80:
        return False
    k = bisect.bisect_right(_FIRSTS, code) - 1
    return (k >= 0 and code <= _RANGES[k][1]) or code in _SEPARATORS or unicodedata.category(ch) == "Cf"


def code_point(ch: str) -> str:
    """How line, gloss and view text show a character: U+27E8, U+, the code point in hex (four digits or more), U+27E9.

    Neither angle bracket is a digit, a word character or a shell metacharacter, so an address right after one is
    still defanged, and a splitter reads the line as before.
    """
    return f"{chr(0x27E8)}U+{ord(ch):04X}{chr(0x27E9)}"


@functools.lru_cache(maxsize=4096)
def _shown(ch: str) -> str:
    return code_point(ch) if is_hidden(ch) else ch


def show_hidden(text: str) -> str:
    """text with each hidden character (is_hidden) shown by its code point, and everything else kept as it is.

    ASCII text, the common case, is returned after one check; otherwise only the characters outside ASCII are looked
    at, each decided once, so the time is linear in the text's length.
    """
    if text.isascii():
        return text
    return _NOT_ASCII.sub(lambda m: _shown(m.group()), text)


@functools.lru_cache(maxsize=4096)
def _line_form(ch: str) -> str:
    form = _LINE_CONTROL_FORMS.get(ord(ch))
    if form is None and (0x80 <= ord(ch) <= 0x9F or is_hidden(ch)):
        form = code_point(ch)
    return ch if form is None else form


def show_controls(text: str) -> str:
    r"""Line text's form of invisible characters: control pictures for C0 controls and DEL, and U+27E8, U+ and the
    code point's hex digits, and U+27E9 (code_point) for C1 controls and hidden characters.

    Tab and newline are kept. Typed text such as printf '\x7fELF' has no invisible character, so it is stored exactly
    as typed, and a stored line has none either, so parsing stored lines again gives the same lines. A line of
    printable ASCII, the common case, is checked in one call; any other has only its characters outside printable
    ASCII looked at. (isprintable alone would pass hidden characters such as U+034F, which count as printable.)
    """
    if text.isascii() and text.isprintable():
        return text
    return _LINE_CANDIDATES.sub(lambda m: _line_form(m.group()), text)
