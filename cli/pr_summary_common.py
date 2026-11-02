"""Shared PR summary headings and vendor-override banners."""

from __future__ import annotations

PR_SUMMARY_REQUIRED_HEADINGS = (
    "### Network Bindings",
    "### File System Access",
    "### Process Execution",
    "### Explicit Denials Maintained",
)

VENDOR_OVERRIDE_HEADING = "### Vendor policy override (higher scrutiny)"


def format_vendor_override_summary(override: dict) -> str:
    """Near-top pr_summary.md block for a --force vendor bypass."""
    situation = str(override.get("situation") or "unknown")
    module = str(override.get("module") or "") or "(none)"
    package = str(override.get("package") or "") or "(none)"
    reason = str(override.get("reason") or "").strip() or "(no reason recorded)"
    return "\n".join(
        [
            VENDOR_OVERRIDE_HEADING,
            "",
            "This generation **bypassed** a vendor or base SELinux policy. Treat this PR as "
            "higher scrutiny than a greenfield module.",
            "",
            f"- **Situation overridden:** `{situation}`",
            f"- **Module:** `{module}`",
            f"- **Package:** `{package}`",
            f"- **Reason:** {reason}",
            "",
        ]
    )


def format_vendor_override_pr_banner(override: dict) -> str:
    """High-visibility PR body banner. Reviewers should see this before the rule diff."""
    situation = str(override.get("situation") or "unknown")
    module = str(override.get("module") or "") or "(none)"
    package = str(override.get("package") or "") or "(none)"
    cls = str(override.get("class") or "") or "(none)"
    reason = str(override.get("reason") or "").strip() or "(no reason recorded)"
    return "\n".join(
        [
            "> ## HIGHER SCRUTINY — vendor policy override",
            ">",
            "> This PR generated a custom module **despite** a vendor or base SELinux policy "
            "covering this app.",
            "> Confirm the override is justified **before** reading the rule diff.",
            ">",
            "> | Field | Value |",
            "> | --- | --- |",
            f"> | Situation overridden | `{situation}` |",
            f"> | Module | `{module}` |",
            f"> | Package | `{package}` |",
            f"> | Class | `{cls}` |",
            f"> | Reason | {reason} |",
            "",
        ]
    )


def split_vendor_override_head(text: str) -> tuple[str, str]:
    """Split a preserved vendor-override head from the rest of pr_summary.md."""
    stripped = text.strip()
    if not stripped.startswith(VENDOR_OVERRIDE_HEADING):
        return "", text
    rest_idx = len(stripped)
    for heading in PR_SUMMARY_REQUIRED_HEADINGS + ("### Needs review (domain-weakening permissions)",):
        idx = stripped.find(heading)
        if idx != -1 and idx < rest_idx:
            rest_idx = idx
    if rest_idx >= len(stripped):
        return stripped, ""
    return stripped[:rest_idx].rstrip(), stripped[rest_idx:]


def validate_pr_summary(pr_summary: str) -> None:
    missing = [h for h in PR_SUMMARY_REQUIRED_HEADINGS if h not in pr_summary]
    if missing:
        raise RuntimeError(
            "pr_summary missing required headings: "
            + ", ".join(missing)
            +             ". Use Network Bindings / File System Access / Process Execution / Explicit Denials Maintained."
        )
