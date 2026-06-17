"""Response analysis helpers shared by scanner modules."""

from __future__ import annotations

from .payloads import SQL_ERROR_REGEX


def find_sql_error(text: str) -> str:
    """Return the matched SQL error signature if the response leaks one, else ''."""
    if not text:
        return ""
    match = SQL_ERROR_REGEX.search(text)
    return match.group(0) if match else ""


def reflects(text: str, marker: str) -> bool:
    """True if the marker appears verbatim in the response body."""
    return bool(text) and marker in text


def snippet(text: str, needle: str, context: int = 60) -> str:
    """Return a short slice of text around the first occurrence of needle."""
    if not text or not needle:
        return ""
    idx = text.find(needle)
    if idx == -1:
        return ""
    start = max(0, idx - context)
    end = min(len(text), idx + len(needle) + context)
    return text[start:end].replace("\n", " ").strip()
