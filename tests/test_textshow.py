"""Tests for the one rule every place that shows text uses: which characters are shown as their code point.

Characters are built with chr() so this file stays ASCII.
"""

import gc
import time
import unicodedata

import pytest

from interlinear_cti.textshow import _RANGES, is_hidden, show_hidden

# The default-ignorable characters outside category Cf (Mn, Lo and reserved Cn), and U+2800, which draws nothing.
IGNORABLE = [0x034F, 0x115F, 0x1160, 0x17B4, 0x17B5, 0x180B, 0x180C, 0x180D, 0x180F, 0x2065, 0x2800, 0x3164, 0xFE00,
             0xFE0F, 0xFFA0, 0xFFF0, 0xFFF8, 0xE0000, 0xE0002, 0xE0080, 0xE0100, 0xE01EF, 0xE01F0, 0xE0FFF]
# Format characters (Cf) and the line and paragraph separators.
FORMAT = [0x00AD, 0x061C, 0x180E, 0x200B, 0x200F, 0x202E, 0x2060, 0x2066, 0xFEFF, 0xE0001, 0xE0041, 0x2028, 0x2029]
# Visible text, including the neighbors of the table's ranges and a visible combining mark (U+0301).
VISIBLE = [0x00E9, 0x0301, 0x034E, 0x0350, 0x0416, 0x1100, 0x115E, 0x1161, 0x17B3, 0x17B6, 0x2801, 0x3163, 0x3165,
           0x4F60, 0xAE00, 0xD55C, 0xFE10, 0xFF9F, 0xFFA1, 0x1F600, 0x00A0]


def shown(code):
    return f"{chr(0x27E8)}U+{code:04X}{chr(0x27E9)}"


@pytest.mark.parametrize("code", IGNORABLE + FORMAT, ids=lambda code: f"U+{code:04X}")
def test_hidden_characters_are_shown(code):
    assert is_hidden(chr(code))
    assert show_hidden("cu" + chr(code) + "rl --version") == "cu" + shown(code) + "rl --version"


@pytest.mark.parametrize("code", VISIBLE, ids=lambda code: f"U+{code:04X}")
def test_visible_characters_are_kept(code):
    assert not is_hidden(chr(code))
    assert show_hidden("a" + chr(code) + "b") == "a" + chr(code) + "b"


def test_ascii_is_left_to_each_caller():
    # Controls are each caller's to show, in its own form, so no ASCII character is hidden here.
    assert not any(is_hidden(chr(code)) for code in range(0x80))
    text = "".join(chr(code) for code in range(0x80))
    assert show_hidden(text) is text


def test_an_emoji_presentation_selector_is_shown_too():
    # U+FE0F after an emoji only asks for its color form, but it is invisible all the same, so it is shown: a heart
    # reads as U+2764 then the selector's code point. Accepted: a shown selector costs a little readability, and a
    # hidden one could split a word that a rule or an analyst would otherwise see.
    assert show_hidden(chr(0x2764) + chr(0xFE0F)) == chr(0x2764) + shown(0xFE0F)


def test_the_table_is_sorted_disjoint_and_complete():
    assert all(first <= last for first, last in _RANGES)
    assert all(_RANGES[k][1] < _RANGES[k + 1][0] for k in range(len(_RANGES) - 1))
    codes = [code for first, last in _RANGES for code in range(first, last + 1)]
    assert not any(unicodedata.category(chr(code)) == "Cf" for code in codes)
    # Unicode 18.0's 4,036 default-ignorable code points outside Cf (263 Mn, 4 Lo, 3,769 Cn), and U+2800.
    assert len(codes) == 4_036 + 1


def test_showing_hidden_text_is_linear():
    # Every character of a non-ASCII text is looked at, so time the worst shape: distinct CJK characters mixed with
    # hidden ones. 4 times the text must take less than 8 times as long; quadratic code takes about 16 times.
    def text(n):
        return "".join(chr(0x4E00 + k % 20_000) + (chr(0x034F) if k % 7 == 0 else "") for k in range(n))

    def seconds(sample):
        collecting = gc.isenabled()
        gc.disable()
        try:
            start = time.perf_counter()
            show_hidden(sample)
            return time.perf_counter() - start
        finally:
            if collecting:
                gc.enable()

    # The sizes take turns, five samples each, keeping each one's best, so both see the same load; the smaller
    # sample lasts well over a scheduler tick.
    small, large = text(50_000), text(200_000)
    small_time = large_time = float("inf")
    for _ in range(5):
        small_time = min(small_time, seconds(small))
        large_time = min(large_time, seconds(large))
    assert large_time < 5.0, (small_time, large_time)  # a sanity ceiling only
    assert large_time < 8 * small_time, (small_time, large_time)
