#!/usr/bin/env python3
"""
verify_avc_coverage.py — Ensure candidate .te covers net-new AVC needs from a log.

Static check: re-merge AVCs and subtract allows parsed from the candidate .te.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import yaml  # noqa: E402
from avc_preprocess import AccessNeed, merge_avc_entries, parse_existing_allows, subtract_covered  # noqa: E402
from deterministic_gen import domains_from_manifest, parse_avc_file  # noqa: E402


from policy_rules import (  # noqa: E402
    GENERIC_PORT_TYPES,
    VERDICT_BASELINE,
    VERDICT_BOOLEAN,
    VERDICT_FC,
    VERDICT_FC_DRIFT,
    VERDICT_FORBIDDEN,
    VERDICT_PORT,
)


def findings_rows_from_json(data: object) -> list[dict]:
    if isinstance(data, list):
        return data
    if isinstance(data, dict) and isinstance(data.get("findings"), list):
        return data["findings"]
    raise ValueError("findings.json must be a list or {findings: [...]}")


def load_findings_handling(findings_path: Path) -> tuple[set[tuple[str, str, str]], list[tuple[str, str, frozenset[str]]]]:
    if not findings_path.is_file():
        return set(), []
    data = json.loads(findings_path.read_text(encoding="utf-8"))
    rows = findings_rows_from_json(data)
    handled_keys: set[tuple[str, str, str]] = set()
    port_handled: list[tuple[str, str, frozenset[str]]] = []
    for row in rows:
        key = (row["src"], row["tgt"], row["class"])
        verdict = row.get("verdict")
        if verdict in (
            VERDICT_FC,
            VERDICT_FC_DRIFT,
            VERDICT_BASELINE,
            VERDICT_BOOLEAN,
            VERDICT_FORBIDDEN,
        ):
            handled_keys.add(key)
        if verdict == VERDICT_PORT:
            port_handled.append(
                (row["src"], row["class"], frozenset(row.get("perms", [])))
            )
    return handled_keys, port_handled


def need_handled(
    need: AccessNeed,
    handled_keys: set[tuple[str, str, str]],
    port_handled: list[tuple[str, str, frozenset[str]]],
) -> bool:
    if need.key in handled_keys:
        return True
    if need.tgt_type in GENERIC_PORT_TYPES:
        for src, tclass, perms in port_handled:
            if need.src_type == src and need.tclass == tclass and need.perms <= perms:
                return True
    return False


def main() -> int:
    parser = argparse.ArgumentParser(description="Verify AVC log is covered by candidate .te")
    parser.add_argument("--avc-log", type=Path, required=True)
    parser.add_argument("--te", type=Path, required=True)
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument(
        "--findings",
        type=Path,
        help="findings.json from deterministic_gen (fc_fix/baseline need no allow rule)",
    )
    parser.add_argument("--json-out", type=Path, help="Write uncovered needs as JSON")
    args = parser.parse_args()

    manifest = yaml.safe_load(args.manifest.read_text(encoding="utf-8"))
    domains = domains_from_manifest(manifest)
    te_text = args.te.read_text(encoding="utf-8")

    findings_path = args.findings or (args.te.parent / "findings.json")
    handled_keys, port_handled = load_findings_handling(findings_path)
    if findings_path.is_file():
        raw = json.loads(findings_path.read_text(encoding="utf-8"))
        for row in findings_rows_from_json(raw):
            rendered = row.get("rendered") or ""
            if rendered and rendered.strip() in te_text:
                handled_keys.add((row["src"], row["tgt"], row["class"]))

    entries, _paths, _ports = parse_avc_file(args.avc_log, domains)
    merged = merge_avc_entries(entries)
    net_new, _ = subtract_covered(merged, parse_existing_allows(te_text))

    uncovered = [n for n in net_new if not need_handled(n, handled_keys, port_handled)]
    if uncovered:
        print(f"Uncovered net-new access needs ({len(uncovered)}):", file=sys.stderr)
        for need in uncovered:
            perms = " ".join(sorted(need.perms))
            print(
                f"  {need.src_type} → {need.tgt_type}:{need.tclass} {{{perms}}}",
                file=sys.stderr,
            )
        if args.json_out:
            args.json_out.write_text(
                json.dumps(
                    [
                        {
                            "src": n.src_type,
                            "tgt": n.tgt_type,
                            "class": n.tclass,
                            "perms": sorted(n.perms),
                        }
                        for n in uncovered
                    ],
                    indent=2,
                )
                + "\n",
                encoding="utf-8",
            )
        return 1

    print(f"AVC coverage OK — {len(merged)} merged denial(s) accounted for in {args.te}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
