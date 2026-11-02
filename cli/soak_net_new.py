#!/usr/bin/env python3
"""Compute net-new AVC access needs vs installed policy (sesearch)."""

from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from avc_preprocess import AccessNeed, merge_avc_entries, subtract_covered  # noqa: E402
from avc_parse import parse_avc_line  # noqa: E402

import yaml  # noqa: E402

PATH_FIELD_RE = re.compile(r'path="([^"]+)"')


def domains_from_manifest(manifest: dict) -> set[str]:
    out = {str(manifest["domain"])}
    for svc in manifest.get("services", {}).values():
        if isinstance(svc, dict) and svc.get("domain"):
            out.add(str(svc["domain"]))
    return out


def parse_avc_lines(lines: list[str], domains: set[str]) -> list:
    entries = []
    for line in lines:
        if "type=AVC" not in line:
            continue
        entry = parse_avc_line(line)
        src = entry.scontext.split(":")[2] if entry.scontext.count(":") >= 2 else ""
        if src not in domains:
            continue
        entries.append(entry)
    return entries

SESEARCH_ALLOW_RE = re.compile(
    r"^\s*allow\s+(\S+)\s+(\S+):(\S+)\s+\{([^}]+)\}\s*;?\s*$"
)
DEFAULT_POLICY_KERN = Path("/sys/fs/selinux/policy")


def parse_sesearch_allows(text: str) -> dict[tuple[str, str, str], frozenset[str]]:
    allows: dict[tuple[str, str, str], set[str]] = {}
    for line in text.splitlines():
        match = SESEARCH_ALLOW_RE.match(line.strip())
        if not match:
            continue
        src, tgt, tclass, perm_block = match.groups()
        key = (src, tgt, tclass)
        perms = frozenset(p.strip() for p in perm_block.split() if p.strip())
        allows.setdefault(key, set()).update(perms)
    return {k: frozenset(v) for k, v in allows.items()}


def sesearch_bin() -> str:
    found = shutil.which("sesearch")
    if found:
        return found
    for candidate in ("/usr/bin/sesearch", "/bin/sesearch", "/usr/sbin/sesearch"):
        if os.access(candidate, os.X_OK):
            return candidate
    raise RuntimeError("sesearch not found (install setools-console)")


def fetch_sesearch_allows(domains: set[str], policy_kern: Path) -> dict[tuple[str, str, str], frozenset[str]]:
    sesearch = sesearch_bin()
    if not policy_kern.is_file():
        raise RuntimeError(f"policy kernel not found: {policy_kern}")
    merged: dict[tuple[str, str, str], set[str]] = {}
    for domain in sorted(domains):
        proc = subprocess.run(
            [sesearch, "--allow", "-s", domain, str(policy_kern)],
            capture_output=True,
            text=True,
            check=False,
        )
        if proc.returncode not in (0, 1):
            raise RuntimeError(proc.stderr.strip() or f"sesearch failed for {domain}")
        for key, perms in parse_sesearch_allows(proc.stdout).items():
            merged.setdefault(key, set()).update(perms)
    return {k: frozenset(v) for k, v in merged.items()}


def analyze(
    avc_lines: list[str],
    domains: set[str],
    policy_kern: Path,
) -> dict:
    raw_count = sum(1 for line in avc_lines if line.startswith("type=AVC"))
    fail_closed = False
    reason = ""
    net_new: list[AccessNeed] = []
    exceptions: list[dict] = []
    sample_by_key: dict[tuple[str, str, str], str] = {}

    entries = parse_avc_lines(avc_lines, domains)
    merged = merge_avc_entries(entries)
    if not merged:
        return {
            "raw_count": raw_count,
            "merged_count": 0,
            "net_new_count": 0,
            "fail_closed": False,
            "exceptions": [],
        }

    try:
        installed = fetch_sesearch_allows(domains, policy_kern)
        net_new, _covered = subtract_covered(merged, installed)
    except RuntimeError as exc:
        fail_closed = True
        net_new = merged
        reason = str(exc)

    for line in avc_lines:
        if not line.startswith("type=AVC"):
            continue
        entry = parse_avc_line(line)
        src = entry.scontext.split(":")[2] if entry.scontext.count(":") >= 2 else ""
        tgt = entry.tcontext.split(":")[2] if entry.tcontext.count(":") >= 2 else ""
        if not src or not tgt or not entry.tclass:
            continue
        key = (src, tgt, entry.tclass)
        sample_by_key.setdefault(key, line)

    for need in net_new:
        exceptions.append(
            {
                "src": need.src_type,
                "tgt": need.tgt_type,
                "class": need.tclass,
                "perms": sorted(need.perms),
                "sample_avc": sample_by_key.get(need.key, ""),
            }
        )

    out = {
        "raw_count": raw_count,
        "merged_count": len(merged),
        "net_new_count": len(net_new),
        "fail_closed": fail_closed,
        "exceptions": exceptions,
    }
    if fail_closed:
        out["fail_closed_reason"] = reason
    return out


def main() -> int:
    parser = argparse.ArgumentParser(description="Net-new AVC needs vs installed SELinux policy")
    parser.add_argument("--manifest", type=Path, help="App manifest YAML")
    parser.add_argument("--domains", help="Comma-separated domains (overrides manifest)")
    parser.add_argument("--avc-file", type=Path, help="AVC log file")
    parser.add_argument("--policy-kern", type=Path, default=DEFAULT_POLICY_KERN)
    parser.add_argument("--json-out", type=Path, help="Write JSON result")
    args = parser.parse_args()

    domains: set[str] = set()
    if args.domains:
        domains = {d.strip() for d in args.domains.split(",") if d.strip()}
    elif args.manifest and args.manifest.is_file():
        manifest = yaml.safe_load(args.manifest.read_text(encoding="utf-8"))
        domains = set(domains_from_manifest(manifest))
    else:
        print("Provide --manifest or --domains", file=sys.stderr)
        return 2

    if args.avc_file:
        lines = args.avc_file.read_text(encoding="utf-8", errors="replace").splitlines()
    else:
        lines = sys.stdin.read().splitlines()

    result = analyze(lines, domains, args.policy_kern)
    payload = json.dumps(result, indent=2) + "\n"
    if args.json_out:
        args.json_out.write_text(payload, encoding="utf-8")
    print(payload, end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
