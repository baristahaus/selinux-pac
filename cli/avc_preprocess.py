"""
avc_preprocess.py — Merge AVC lines and subtract allows already present in a .te.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING

from policy_rules import JAVA_EXEC_FILE_PERMS

if TYPE_CHECKING:
    from avc_parse import AvcEntry

# Braced `{ read write }` and a single permission without braces (`execmem`).
ALLOW_RULE_RE = re.compile(
    r"^\s*allow\s+(\S+)\s+(\S+):(\S+)\s+(?:\{([^}]+)\}|([^{}\s;]+))\s*;\s*$",
    re.MULTILINE,
)


@dataclass(frozen=True)
class AccessNeed:
    src_type: str
    tgt_type: str
    tclass: str
    perms: frozenset[str]

    @property
    def key(self) -> tuple[str, str, str]:
        return (self.src_type, self.tgt_type, self.tclass)


def extract_type(context: str) -> str:
    """Extract SELinux type from a context string (user:role:type:level)."""
    if not context:
        return ""
    parts = context.split(":")
    if len(parts) >= 3:
        return parts[2]
    return context


def normalize_perms(perm_str: str) -> frozenset[str]:
    """Parse permission tokens from AVC denied { ... } or perm= fields."""
    cleaned = perm_str.strip().strip("{}").strip()
    if not cleaned:
        return frozenset()
    return frozenset(token for token in cleaned.split() if token)


def merge_avc_entries(entries: list[AvcEntry]) -> list[AccessNeed]:
    """Group AVC lines by (src_type, tgt_type, class) and union permissions."""
    merged: dict[tuple[str, str, str], set[str]] = {}
    for entry in entries:
        src_type = extract_type(entry.scontext)
        tgt_type = extract_type(entry.tcontext)
        if not src_type or not tgt_type or not entry.tclass:
            continue
        key = (src_type, tgt_type, entry.tclass)
        merged.setdefault(key, set()).update(normalize_perms(entry.perm))

    needs: list[AccessNeed] = []
    for (src_type, tgt_type, tclass), perms in sorted(merged.items()):
        if perms:
            needs.append(AccessNeed(src_type, tgt_type, tclass, frozenset(perms)))
    return needs


def _te_rules_only(te_text: str) -> str:
    """Drop comments. A note that names a macro is not an allow."""
    return "\n".join(line.split("#", 1)[0] for line in te_text.splitlines())


def parse_existing_allows(te_text: str) -> dict[tuple[str, str, str], frozenset[str]]:
    """Parse allow rules from existing .te source into a lookup table.

    `self` is the source domain, so an AVC whose target type is that domain
    matches `allow domain self:class perm`.
    """
    te_text = _te_rules_only(te_text)
    allows: dict[tuple[str, str, str], set[str]] = {}

    def add(src_type: str, tgt_type: str, tclass: str, perms: frozenset[str]) -> None:
        allows.setdefault((src_type, tgt_type, tclass), set()).update(perms)

    for match in ALLOW_RULE_RE.finditer(te_text):
        src_type, tgt_type, tclass, braced, single = match.groups()
        perms = normalize_perms(braced if braced is not None else single or "")
        if not perms:
            continue
        add(src_type, tgt_type, tclass, perms)
        if tgt_type == "self":
            add(src_type, src_type, tclass, perms)
    # corecmd_exec_bin(domain) and java_exec(domain) are can_exec on bin_t. On RHEL 9
    # java_exec_t is an alias of bin_t, so an AVC names bin_t. Neither is an entrypoint.
    for match in re.finditer(
        r"\b(?:corecmd_exec_bin|java_exec)\(\s*([A-Za-z_][A-Za-z0-9_]*)\s*\)", te_text
    ):
        for exec_type in ("bin_t", "java_exec_t"):
            add(match.group(1), exec_type, "file", JAVA_EXEC_FILE_PERMS)
    for match in re.finditer(
        r"\bcan_exec\(\s*([A-Za-z_][A-Za-z0-9_]*)\s*,\s*(bin_t|java_exec_t)\s*\)", te_text
    ):
        for exec_type in ("bin_t", "java_exec_t"):
            add(match.group(1), exec_type, "file", JAVA_EXEC_FILE_PERMS)
    return {key: frozenset(perms) for key, perms in allows.items()}


def subtract_covered(
    merged: list[AccessNeed],
    existing: dict[tuple[str, str, str], frozenset[str]],
) -> tuple[list[AccessNeed], list[AccessNeed]]:
    """Split merged AVC needs into net-new vs already covered by existing .te."""
    net_new: list[AccessNeed] = []
    already_covered: list[AccessNeed] = []

    for need in merged:
        existing_perms = existing.get(need.key, frozenset())
        uncovered = need.perms - existing_perms
        covered = need.perms & existing_perms

        if uncovered:
            net_new.append(
                AccessNeed(need.src_type, need.tgt_type, need.tclass, frozenset(uncovered))
            )
        if covered:
            already_covered.append(
                AccessNeed(need.src_type, need.tgt_type, need.tclass, frozenset(covered))
            )

    return net_new, already_covered


def _format_perm_list(perms: frozenset[str]) -> str:
    return ", ".join(sorted(perms))


def _format_need_table(needs: list[AccessNeed]) -> str:
    if not needs:
        return "(none)"
    lines = ["| Source | Target | Class | Permissions |", "| --- | --- | --- | --- |"]
    for need in needs:
        lines.append(
            f"| {need.src_type} | {need.tgt_type} | {need.tclass} | {_format_perm_list(need.perms)} |"
        )
    return "\n".join(lines)


MACRO_COVERAGE_NOTE = (
    "Note: subtraction parses explicit allow lines only; rules expanded by "
    "init_daemon_domain, domain_auto_trans, and files_type macros may already cover some AVCs."
)


def format_structured_summary(
    net_new: list[AccessNeed],
    already_covered: list[AccessNeed],
    stats: dict[str, int],
) -> str:
    """Build a readable summary of net-new and already-covered access."""
    sections = [
        MACRO_COVERAGE_NOTE,
        "",
        "## Net-new access needs (from AVCs, not in existing .te)",
        _format_need_table(net_new),
        "",
        "## Already covered by existing policy (for reference only)",
        _format_need_table(already_covered),
        "",
        (
            "Stats: "
            f"raw={stats['raw']} merged={stats['merged']} "
            f"net_new={stats['net_new']} already_covered={stats['already_covered']}"
        ),
    ]
    return "\n".join(sections)


def preprocess_avc_entries(
    entries: list[AvcEntry],
    *,
    existing_te: str = "",
) -> tuple[str, dict[str, int]]:
    """
    Merge AVC entries, subtract existing allows, return summary text and stats.
    """
    raw_count = len(entries)
    merged = merge_avc_entries(entries)
    existing = parse_existing_allows(existing_te)
    net_new, already_covered = subtract_covered(merged, existing)

    stats = {
        "raw": raw_count,
        "merged": len(merged),
        "net_new": len(net_new),
        "already_covered": len(already_covered),
    }

    summary = format_structured_summary(net_new, already_covered, stats)
    return summary, stats


def preprocess_avc_file(
    path: Path,
    domain: str,
    *,
    existing_te: str = "",
) -> tuple[str, dict[str, int]]:
    """Load AVC file, filter to the domain, merge, and subtract existing allows."""
    from avc_parse import filter_avc_entries, parse_avc_line

    if not path.is_file():
        raise RuntimeError(f"Audit log not found: {path}")

    entries: list[AvcEntry] = []
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        if "type=AVC" in line:
            entries.append(parse_avc_line(line))

    entries = filter_avc_entries(entries, domain)
    return preprocess_avc_entries(entries, existing_te=existing_te)


def preprocess_avc_lines(
    lines: list[str],
    domain: str,
    *,
    existing_te: str = "",
) -> tuple[str, dict[str, int]]:
    """Parse raw AVC lines (for example from ausearch), filter, merge, subtract."""
    from avc_parse import filter_avc_entries, parse_avc_line

    entries: list[AvcEntry] = []
    for line in lines:
        if "type=AVC" in line:
            entries.append(parse_avc_line(line))

    entries = filter_avc_entries(entries, domain)
    return preprocess_avc_entries(entries, existing_te=existing_te)
