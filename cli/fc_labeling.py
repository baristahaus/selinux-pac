"""
fc_labeling.py — Detect when .fc already labels a path (drift vs missing entry).

Prevents accumulating one gen_context line per mislabeled file when a directory
regex already assigns the correct type.
"""

from __future__ import annotations

import re

FC_LINE_RE = re.compile(
    r"^\s*(?P<pattern>\S+)\s+gen_context\(system_u:object_r:(?P<type>\w+),",
    re.MULTILINE,
)


def regex_pattern_to_probe_path(pattern: str) -> str:
    """Best-effort concrete path to test whether a .fc regex applies."""
    p = pattern
    p = p.replace(r"\(", "(").replace(r"\)", ")")
    p = re.sub(r"\(\/\.\*\)\?", "/_probe_", p)
    p = re.sub(r"\(\/\.\*\)", "/_probe_", p)
    p = re.sub(r"\(\[\^/\]\+\)", "_probe_", p)
    p = p.replace(r"\.", ".")
    p = re.sub(r"\[[^\]]+\]", "0", p)
    p = p.replace("(/.*)?", "/_probe_")
    p = p.replace("*", "0")
    p = re.sub(r"\\(.)", r"\1", p)
    return p


def existing_fc_covers(path: str, want_type: str, fc_text: str) -> bool:
    """True when an existing .fc regex already assigns want_type to path."""
    if not path or not want_type:
        return False
    for match in FC_LINE_RE.finditer(fc_text):
        if match.group("type") != want_type:
            continue
        pattern = match.group("pattern")
        try:
            if re.match(f"^{pattern}$", path):
                return True
        except re.error:
            continue
    return False


def fc_line_already_present(line: str, fc_text: str) -> bool:
    normalized = line.strip()
    if not normalized:
        return True
    for existing in fc_text.splitlines():
        if existing.strip() == normalized:
            return True
    return False


def proposed_fc_line_redundant(line: str, existing_fc: str, path_hint: str | None = None) -> bool:
    """
    True if adding line would not change labeling semantics (already in .fc or
    covered by a broader existing pattern).
    """
    stripped = line.strip()
    if not stripped or stripped.startswith("#"):
        return True
    if fc_line_already_present(stripped, existing_fc):
        return True
    m = FC_LINE_RE.match(stripped)
    if not m:
        return False
    want_type = m.group("type")
    probe = path_hint or regex_pattern_to_probe_path(m.group("pattern"))
    return existing_fc_covers(probe, want_type, existing_fc)


def filter_fc_fix_lines(
    existing_fc: str,
    fc_lines: list[str],
    path_hints: dict[str, str] | None = None,
) -> tuple[list[str], list[str]]:
    """
    Split proposed .fc lines into those to append vs redundant (label drift).

    path_hints maps rendered fc line -> audit path= from AVC (most accurate probe).
    """
    hints = path_hints or {}
    kept: list[str] = []
    redundant: list[str] = []
    for line in fc_lines:
        if proposed_fc_line_redundant(line, existing_fc, hints.get(line)):
            redundant.append(line)
        else:
            kept.append(line)
    return kept, redundant


def strip_redundant_fc_lines(baseline_fc: str, candidate_fc: str) -> str:
    """
    Drop new candidate lines that only duplicate coverage already in baseline_fc.
    Used when a candidate .fc repeats lines the baseline already covers.
    """
    baseline_lines = {
        ln.strip()
        for ln in baseline_fc.splitlines()
        if ln.strip() and not ln.strip().startswith("#")
    }
    out: list[str] = []
    for line in candidate_fc.splitlines():
        stripped = line.strip()
        if not stripped:
            out.append(line)
            continue
        if stripped.startswith("#"):
            out.append(line)
            continue
        if stripped in baseline_lines:
            out.append(line)
            continue
        if proposed_fc_line_redundant(stripped, baseline_fc):
            continue
        out.append(line)
    text = "\n".join(out)
    return text if text.endswith("\n") else text + "\n"
