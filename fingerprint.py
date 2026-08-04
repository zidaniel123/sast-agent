"""Stable finding identity and deduplication.

Deduplication here is arithmetic over strings, not a judgement call. The model
decides *what it found*; this module decides *what that finding is called* and
whether two findings are the same one. Keeping it in Python rather than in a
prompt means it is deterministic, testable, and free of context cost.

Two properties matter:

**Stable across runs.** The fingerprint hashes the *content* around a finding,
not its line number. Adding an import forty lines above a vulnerability shifts
every line number in the file; it does not change the vulnerability. A
line-number-based ID would report the whole file as new findings.

**Stable across paths to the same sink.** One ``eval()`` reachable from three
tainted sources is one finding with three flows, not three findings. The fix is
at the sink, so the sink is the identity.
"""

from __future__ import annotations

import hashlib
import re
from typing import Any

_WHITESPACE = re.compile(r"\s+")
_LINE_COMMENT = re.compile(r"(?://|#).*$", re.MULTILINE)
_BLOCK_COMMENT = re.compile(r"/\*.*?\*/", re.DOTALL)
_STRING_LITERAL = re.compile(r"(['\"])(?:\\.|(?!\1).)*\1", re.DOTALL)
_LINE_SUFFIX = re.compile(r":\d+(?:-\d+)?$")


def normalize_code(snippet: str) -> str:
    """Reduce a code snippet to something insensitive to cosmetic edits.

    Comments are dropped, string literals are collapsed to a placeholder, and
    runs of whitespace become single spaces. Reformatting, re-indenting, or
    changing a message string will not change the fingerprint; changing the
    actual expression will.
    """
    text = _BLOCK_COMMENT.sub(" ", snippet or "")
    text = _LINE_COMMENT.sub(" ", text)
    text = _STRING_LITERAL.sub('"S"', text)
    return _WHITESPACE.sub(" ", text).strip()


def strip_line_numbers(location: str) -> str:
    """``app/db.py:58`` and ``app/db.py:56-58`` both become ``app/db.py``."""
    return _LINE_SUFFIX.sub("", (location or "").strip())


def sink_of(finding: dict[str, Any]) -> str:
    """The location the vulnerability actually lands, without line numbers.

    Falls back through the taint analysis and then the evidence list, because
    model output is not guaranteed to populate every field.
    """
    taint = finding.get("taint_analysis") or {}
    for candidate in (taint.get("sink_location"), taint.get("source_location")):
        if candidate:
            return strip_line_numbers(str(candidate))
    for evidence in finding.get("evidences") or []:
        for key in ("path", "code_file"):
            if evidence.get(key):
                return strip_line_numbers(str(evidence[key]))
    return ""


def _evidence_context(finding: dict[str, Any]) -> str:
    """Normalized code of the *first* evidence only.

    Deliberately not every snippet: the same vulnerability is often reported
    twice with a different number of supporting snippets (one path traced, then
    a second path to the same sink). If identity depended on the whole evidence
    list, those two reports would hash differently and never merge — which is
    exactly the duplicate the fingerprint exists to collapse.
    """
    for evidence in finding.get("evidences") or []:
        normalized = normalize_code(str(evidence.get("snippet", "")))
        if normalized:
            return normalized
    return ""


def finding_fingerprint(finding: dict[str, Any]) -> str:
    """A stable 16-hex-character identity for one finding.

    Inputs are deliberately limited to things that do not change when unrelated
    code moves: the weakness class, the file the sink lives in, and normalized
    code context. Severity and prose descriptions are excluded — the model
    rewords those between runs and they do not change what the finding *is*.
    """
    parts = [
        str(finding.get("cwe_id", "")).strip().upper(),
        sink_of(finding),
        _evidence_context(finding),
    ]
    if not any(parts):
        # Nothing stable to hash; fall back to the title so the finding still
        # gets an id rather than colliding with every other empty finding.
        parts = [str(finding.get("vulnerability", ""))]
    digest = hashlib.sha256("\x1f".join(parts).encode("utf-8")).hexdigest()
    return digest[:16]


_SEVERITY_ORDER = ["informational", "low", "medium", "high", "critical"]


def _strongest(left: str, right: str) -> str:
    """Keep the higher of two severities, preserving unknown values as-is."""
    try:
        return max((left, right), key=lambda value: _SEVERITY_ORDER.index(str(value).lower()))
    except ValueError:
        return left or right


def deduplicate(findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Merge findings that share a fingerprint, preserving order of first sight.

    Merging unions evidence (by snippet, so identical snippets do not stack up)
    and keeps the strongest severity claimed for the finding. It never invents
    evidence: the merged finding carries only evidence the model actually
    produced for one of the duplicates.
    """
    merged: dict[str, dict[str, Any]] = {}
    for finding in findings:
        if not isinstance(finding, dict):
            continue
        key = finding_fingerprint(finding)
        existing = merged.get(key)
        if existing is None:
            item = dict(finding)
            item["finding_id"] = key
            item["duplicate_count"] = 1
            merged[key] = item
            continue

        existing["duplicate_count"] += 1
        existing["severity"] = _strongest(
            existing.get("severity", ""), finding.get("severity", "")
        )
        seen = {
            normalize_code(str(evidence.get("snippet", "")))
            for evidence in existing.get("evidences") or []
        }
        for evidence in finding.get("evidences") or []:
            if normalize_code(str(evidence.get("snippet", ""))) not in seen:
                existing.setdefault("evidences", []).append(evidence)
    return list(merged.values())
