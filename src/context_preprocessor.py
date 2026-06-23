from __future__ import annotations

import re
import unicodedata
from dataclasses import dataclass


INVISIBLE_CHARS_RE = re.compile(r"[\u200b\u200c\u200d\ufeff\u2060]")
HTML_COMMENT_RE = re.compile(r"<!--(.*?)-->", re.DOTALL | re.IGNORECASE)


@dataclass
class PreparedText:
    original: str
    normalized: str
    lowercase: str
    html_comments: list[str]
    has_invisible_chars: bool


class ContextPreprocessor:
    """Normalizes text and extracts simple structural indicators."""

    def prepare(self, text: str | None) -> PreparedText:
        original = text or ""
        normalized = unicodedata.normalize("NFKC", original)
        html_comments = [m.group(1).strip() for m in HTML_COMMENT_RE.finditer(normalized)]
        has_invisible = bool(INVISIBLE_CHARS_RE.search(normalized))
        lowercase = normalized.lower()
        return PreparedText(
            original=original,
            normalized=normalized,
            lowercase=lowercase,
            html_comments=html_comments,
            has_invisible_chars=has_invisible,
        )
