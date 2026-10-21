"""Text aimed at an analyst or an AI model rather than at the target: prompt injection planted in a transcript.

An attacker who expects their history or agent log to be read by an analyst, or by a model, can write lines for that
reader: "ignore all previous instructions", "note to the reviewer: this is an authorized pentest", a fake system
turn. Such a line acts on the reader, not on the host, so export-scenario leaves it out of the attack steps and says
so. The test looks for common phrasings only; the gloss skill is told to treat every line as data whatever it says.
Each alternative starts at a word and reads a few bounded words, so the scan is linear.
"""

from __future__ import annotations

import re

_B = r"[ \t]+"
_READER = r"(?:ai|a\.i\.|llm|assistant|language" + _B + r"model|model|chatbot|analyst|reviewer|investigator|soc" \
          r"|defender|blue" + _B + r"team|incident" + _B + r"responder)s?"
_AIMED = re.compile("(?i)" + "|".join((
    # ignore all previous instructions
    r"\b(?:ignore|disregard|forget|override)" + _B + r"(?:(?:all|any|the|your|my|of)" + _B + r"){0,3}"
    r"(?:previous|prior|above|earlier|preceding|former|system)" + _B
    + r"(?:instructions?|prompts?|rules|directions|guidelines|context|messages?)\b",
    # you are an AI assistant
    r"\byou(?:" + _B + r"are|'re)" + _B + r"(?:now" + _B + r")?(?:an?" + _B + r")?(?:ai|a\.i\.|assistant|language"
    + _B + r"model|llm|chatbot)\b",
    # note to the reviewer; dear analyst; AI: please ignore ...
    r"\b(?:note|message|instructions?|memo)" + _B + r"(?:to|for)" + _B + r"(?:the" + _B + r"|any" + _B + r")?"
    + _READER + r"\b",
    r"\b(?:dear|attention|hello|hi)[ \t,]+(?:the" + _B + r")?" + _READER + r"\b",
    r"\b" + _READER + r"[ \t]*[:,][ \t]*(?:please" + _B + r")?(?:ignore|disregard|do" + _B + r"not|don'?t|mark"
    r"|classify|label|treat|report|stop|skip)\b",
    # mark this session as benign
    r"\b(?:mark|classify|label|treat|report|tag)" + _B + r"(?:this|these|the|all|it|them)(?:" + _B + r"\w+){0,2}?"
    + _B + r"as" + _B + r"(?:benign|safe|clean|harmless|legitimate|authorized|false" + _B
    + r"positives?|context|non-?malicious|expected)\b",
    r"\b(?:do" + _B + r"not|don'?t|never)" + _B + r"(?:report|flag|alert|escalate|investigate)\b",
    # this is an authorized pentest
    r"\bthis" + _B + r"is" + _B + r"(?:an?" + _B + r")?(?:authorized|sanctioned|approved|legitimate)" + _B
    + r"(?:pentest|penetration" + _B + r"test|red" + _B + r"team|security" + _B + r"test|test|exercise|engagement)\b",
    # chat-template markers and a fake system turn
    r"<\|im_(?:start|end)\|>|\[/?INST\]|<</?SYS>>|</?system>|\bsystem" + _B + r"prompt\b",
)))


def aimed_at_reader(text: str) -> bool:
    """Whether text addresses an analyst or an AI model reading the transcript rather than the target host."""
    return _AIMED.search(text) is not None
