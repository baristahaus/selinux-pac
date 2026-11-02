#!/usr/bin/env python3
"""
tune_report.py — Read-only vendor-domain denial analysis.

Classifies AVCs for a vendor/base domain (tomcat_t, httpd_t, …) and prints
host tuning commands. Never writes a policy module.
"""

from __future__ import annotations

import argparse
import re
import shutil
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from avc_preprocess import merge_avc_entries, subtract_covered  # noqa: E402
from boolean_hints import load_boolean_hints  # noqa: E402
from deterministic_gen import (  # noqa: E402
    Finding,
    classify,
    parse_avc_file,
    suggest_fc_type,
)
from policy_rules import (  # noqa: E402
    GENERIC_FILE_TYPES,
    VERDICT_BOOLEAN,
    VERDICT_DIRECT,
    VERDICT_FC,
    VERDICT_FC_DRIFT,
    VERDICT_FORBIDDEN,
    VERDICT_INTERFACE,
    VERDICT_NEEDS_REVIEW,
    VERDICT_PORT,
    VERDICT_TOOLCHAIN,
)
from avc_parse import parse_avc_line  # noqa: E402

TUNE_VERDICTS = frozenset({VERDICT_FC, VERDICT_FC_DRIFT, VERDICT_BOOLEAN, VERDICT_PORT})
UNRESOLVABLE_VERDICTS = frozenset(
    {
        VERDICT_DIRECT,
        VERDICT_INTERFACE,
        VERDICT_FORBIDDEN,
        VERDICT_NEEDS_REVIEW,
        VERDICT_TOOLCHAIN,
    }
)

SYSTEM_PATH_PREFIXES = (
    "/proc/",
    "/sys/",
    "/dev/",
    "/run/user/",
    "/root/",
    "/home/",
    "/boot/",
    "/etc/",
    "/usr/bin/",
    "/usr/sbin/",
    "/usr/libexec/",
)

VENDOR_PATHS: dict[str, dict[str, object]] = {
    "tomcat": {
        "install_root": "/usr/share/tomcat",
        "var_dir": "/var/lib/tomcat",
        "log_dir": "/var/log/tomcat",
        "runtime_dir": "/run/tomcat",
        "extra_fc_roots": ["/opt/appdata"],
    },
    "jws6_tomcat": {
        "install_root": "/opt/rh/jws6",
        "var_dir": "/opt/rh/jws6/var",
        "log_dir": "/opt/rh/jws6/logs",
        "runtime_dir": "/run/jws6",
        "extra_fc_roots": ["/opt/appdata"],
    },
    "httpd": {
        "install_root": "/etc/httpd",
        "var_dir": "/var/www",
        "log_dir": "/var/log/httpd",
        "runtime_dir": "/run/httpd",
        "extra_fc_roots": [],
    },
    "postgresql": {
        "install_root": "/usr/share/pgsql",
        "var_dir": "/var/lib/pgsql",
        "log_dir": "/var/log/postgresql",
        "runtime_dir": "/run/postgresql",
        "extra_fc_roots": [],
    },
    "named": {
        "install_root": "/etc/named",
        "var_dir": "/var/named",
        "log_dir": "/var/log/named",
        "runtime_dir": "/run/named",
        "extra_fc_roots": [],
    },
    "eap": {
        "install_root": "/opt/rh/eap",
        "var_dir": "/opt/rh/eap",
        "log_dir": "/opt/rh/eap/standalone/log",
        "runtime_dir": "/run/eap",
        "extra_fc_roots": ["/opt/appdata"],
    },
}

VERDICT_SORT = {
    VERDICT_FC_DRIFT: 0,
    VERDICT_FC: 1,
    VERDICT_BOOLEAN: 2,
    VERDICT_PORT: 3,
}

AUDIT2WHY_TS_RE = re.compile(r"msg=audit\([^)]+\)")
AUDIT_TS_RE = re.compile(r"\baudit\(\d")


def vendor_app_name(domain: str, class_name: str) -> str:
    if domain.endswith("_t"):
        base = domain[:-2]
        if base in VENDOR_PATHS:
            return base
    if class_name in VENDOR_PATHS:
        return class_name
    if class_name == "tomcat" and domain.startswith("jws"):
        return "jws6_tomcat"
    if class_name == "eap":
        return "eap"
    return class_name if class_name != "none" else (domain[:-2] if domain.endswith("_t") else domain)


def is_system_path(path: str) -> bool:
    if path in {"/proc", "/sys", "/dev", "/root", "/home", "/boot", "/etc"}:
        return True
    return any(path.startswith(prefix) for prefix in SYSTEM_PATH_PREFIXES)


def extra_roots_from_paths(path_map: dict, extra: list[str]) -> list[str]:
    roots: list[str] = []
    seen: set[str] = set()
    for item in extra:
        base = item.rstrip("/")
        if base and base not in seen:
            seen.add(base)
            roots.append(base)
    for (_src, tgt, _tclass), paths in path_map.items():
        if tgt not in GENERIC_FILE_TYPES:
            continue
        for path in paths:
            if not path or is_system_path(path):
                continue
            base = path.rstrip("/")
            if "/" in base and not base.endswith("/"):
                # Prefer the directory that actually holds app content.
                parent = str(Path(base).parent)
                if parent not in {"/", "."} and not is_system_path(parent + "/"):
                    base = parent
            if base not in seen:
                seen.add(base)
                roots.append(base)
    return sorted(roots)


def synthetic_manifest(
    app_name: str,
    domain: str,
    extra_roots: list[str],
) -> dict:
    defaults = VENDOR_PATHS.get(app_name) or VENDOR_PATHS.get("tomcat") or {}
    paths = {
        "install_root": str(defaults.get("install_root") or ""),
        "var_dir": str(defaults.get("var_dir") or ""),
        "log_dir": str(defaults.get("log_dir") or ""),
        "runtime_dir": str(defaults.get("runtime_dir") or ""),
        "extra_fc_roots": extra_roots_from_paths({}, list(defaults.get("extra_fc_roots") or []) + extra_roots),
    }
    return {
        "app_name": app_name,
        "domain": domain,
        "paths": paths,
    }


def fcontext_root(path: str, roots: list[str], preferred: list[str] | None = None) -> str:
    preferred = preferred or []
    for root in sorted((r.rstrip("/") for r in preferred if r), key=len, reverse=True):
        if path == root or path.startswith(root + "/"):
            return root
    matches = [
        root.rstrip("/")
        for root in roots
        if path == root.rstrip("/") or path.startswith(root.rstrip("/") + "/")
    ]
    if matches:
        return sorted(matches, key=len, reverse=True)[0]
    if path.endswith("/"):
        return path.rstrip("/")
    parent = str(Path(path).parent)
    if parent not in {"/", "."}:
        return parent
    return path


def prefer_boolean_names(names: list[str], domain: str) -> list[str]:
    prefixes: list[str] = []
    if domain.endswith("_t"):
        base = domain[:-2]
        prefixes.append(base + "_")
        prefixes.append(base.split("_")[0] + "_")
        if "jws" in base:
            prefixes.extend(["jws6_", "jws_"])
        if base == "tomcat":
            prefixes.append("tomcat_")
    scoped = [name for name in names if any(name.startswith(prefix) for prefix in prefixes)]
    return scoped or names


def audit2why_kind(text: str) -> str:
    low = text.lower()
    if "boolean" in low:
        return "boolean"
    if "restorecon" in low or "file context" in low or "fcontext" in low:
        return "label"
    if "semanage port" in low or "port type" in low:
        return "port"
    if "type enforcement" in low or "allow " in low:
        return "te"
    return "other"


def our_kind(verdict: str) -> str:
    if verdict in (VERDICT_FC, VERDICT_FC_DRIFT):
        return "label"
    if verdict == VERDICT_BOOLEAN:
        return "boolean"
    if verdict == VERDICT_PORT:
        return "port"
    return "te"


def run_audit2why(avc_line: str) -> str | None:
    if not shutil.which("audit2why"):
        return None
    try:
        proc = subprocess.run(
            ["audit2why"],
            input=avc_line + "\n",
            capture_output=True,
            text=True,
            check=False,
        )
    except OSError:
        return None
    text = (proc.stdout or "").strip()
    if not text:
        return None
    kept: list[str] = []
    for line in text.splitlines():
        stripped = line.strip()
        if not stripped:
            continue
        if stripped.startswith("type=AVC") or "avc:  denied" in stripped or "avc: denied" in stripped:
            continue
        if AUDIT_TS_RE.search(stripped) or AUDIT2WHY_TS_RE.search(stripped):
            continue
        kept.append(stripped)
    return "\n".join(kept).strip() or None


def raw_lines_for_need(avc_path: Path, need, domains: set[str]) -> list[str]:
    lines: list[str] = []
    for line in avc_path.read_text(encoding="utf-8", errors="replace").splitlines():
        if "type=AVC" not in line:
            continue
        entry = parse_avc_line(line)
        src = entry.scontext.split(":")[2] if entry.scontext.count(":") >= 2 else ""
        tgt = entry.tcontext.split(":")[2] if entry.tcontext.count(":") >= 2 else ""
        if src not in domains or tgt != need.tgt_type or entry.tclass != need.tclass:
            continue
        if src != need.src_type:
            continue
        lines.append(line)
    return sorted(set(lines))


def extract_fc_type(finding: Finding, manifest: dict, fallback: str) -> str:
    rendered = finding.rendered or ""
    match = re.search(r"object_r:([A-Za-z0-9_]+)", rendered)
    if match:
        return match.group(1)
    for path in finding.paths:
        want = suggest_fc_type(path, manifest)
        if want:
            return want
    return fallback


def boolean_commands(finding: Finding, domain: str) -> list[str]:
    names = [part.strip() for part in (finding.boolean or "").split(",") if part.strip()]
    if not names:
        names = re.findall(r"setsebool -P (\S+) on", finding.rendered or "")
    names = prefer_boolean_names(names, domain)
    return [f"setsebool -P {name} on" for name in names]


def tune_commands(
    finding: Finding,
    manifest: dict,
    fc_type: str,
    port_type: str,
    extra_roots: list[str],
    domain: str,
) -> list[str]:
    if finding.verdict == VERDICT_FC_DRIFT:
        path = finding.paths[0] if finding.paths else ""
        preferred = list(manifest.get("paths", {}).get("extra_fc_roots") or [])
        root = fcontext_root(path, extra_roots, preferred) if path else path
        return [f"restorecon -Rv {root}"] if root else []
    if finding.verdict == VERDICT_FC:
        path = finding.paths[0] if finding.paths else ""
        if not path:
            return []
        roots = list(manifest.get("paths", {}).get("extra_fc_roots") or []) + extra_roots
        for key in ("var_dir", "log_dir", "runtime_dir", "install_root"):
            val = manifest.get("paths", {}).get(key)
            if val:
                roots.append(str(val))
        preferred = list(manifest.get("paths", {}).get("extra_fc_roots") or [])
        root = fcontext_root(path, [str(r) for r in roots if r], preferred)
        want = extract_fc_type(finding, manifest, fc_type)
        return [
            f'semanage fcontext -a -t {want} "{root}(/.*)?"  &&  restorecon -Rv {root}'
        ]
    if finding.verdict == VERDICT_BOOLEAN:
        return boolean_commands(finding, domain)
    if finding.verdict == VERDICT_PORT:
        port = finding.bind_port
        proto = finding.bind_proto or "tcp"
        if port is None:
            return [f"semanage port -a -t {port_type} -p {proto} <port>"]
        return [f"semanage port -a -t {port_type} -p {proto} {port}"]
    return []


def sort_findings(findings: list[Finding]) -> list[Finding]:
    return sorted(
        findings,
        key=lambda f: (
            VERDICT_SORT.get(f.verdict, 10),
            f.need.src_type,
            f.need.tgt_type,
            f.need.tclass,
            " ".join(sorted(f.need.perms)),
            f.paths[0] if f.paths else "",
            f.bind_port if f.bind_port is not None else -1,
        ),
    )


def finding_heading(finding: Finding) -> str:
    perms = " ".join(sorted(finding.need.perms))
    path = finding.paths[0] if finding.paths else ""
    extra = f" path=`{path}`" if path else ""
    if finding.bind_port is not None:
        extra += f" port={finding.bind_port}/{finding.bind_proto or 'tcp'}"
    return (
        f"`{finding.need.src_type}` → `{finding.need.tgt_type}:{finding.need.tclass}` "
        f"{{ {perms} }}{extra}"
    )


def render_report(
    *,
    findings: list[Finding],
    commands: list[tuple[Finding, list[str]]],
    unresolvable: list[Finding],
    audit2why: dict[int, tuple[str | None, bool]],
    identity: dict[str, str],
    limitations: list[str],
    avc_count: int,
) -> str:
    lines: list[str] = [
        "# Vendor policy tune report",
        "",
        "Read-only analysis. These commands are for a human to run; this tool does not "
        "modify the host, install packages, or write a policy module.",
        "",
        "## Identity",
        "",
        f"- App: `{identity.get('app', '')}`",
        f"- Situation: `{identity.get('situation', '')}`",
        f"- Vendor module: `{identity.get('module', '') or '(none)'}`",
        f"- Package: `{identity.get('package', '') or '(none)'}`",
        f"- Class: `{identity.get('class', '')}`",
        f"- Domain: `{identity.get('domain', '')}`",
        f"- Denials classified: {avc_count}",
        "",
        "## Tuning commands",
        "",
    ]
    if commands:
        lines.append("Run in this order. Do not generate a `.te` for these.")
        lines.append("")
        for finding, cmds in commands:
            lines.append(f"### {finding_heading(finding)}")
            lines.append("")
            for cmd in cmds:
                lines.append(f"    {cmd}")
            lines.append("")
            why_text, disagreed = audit2why.get(id(finding), (None, False))
            if why_text:
                if disagreed:
                    lines.append(
                        "Our classification and `audit2why` disagree. Both are shown."
                    )
                    lines.append("")
                    lines.append(f"- Classification: `{finding.verdict}`")
                    lines.append("")
                lines.append("audit2why:")
                lines.append("")
                lines.append("```")
                lines.extend(why_text.splitlines())
                lines.append("```")
                lines.append("")
    else:
        lines.append("No denials classified as labeling, boolean, or port tuning.")
        lines.append("")

    lines.extend(
        [
            "## Not resolvable by tuning",
            "",
        ]
    )
    if unresolvable:
        lines.append(
            "These denials are not `fc_drift` / `fc_fix` / `boolean` / `private_port`. "
            "Not resolvable by tuning; this may be a genuine vendor policy gap worth "
            "raising with Red Hat support. No policy module is written."
        )
        lines.append("")
        for finding in unresolvable:
            lines.append(f"- {finding_heading(finding)} (`{finding.verdict}`)")
            if finding.note:
                lines.append(f"  - {finding.note}")
            why_text, disagreed = audit2why.get(id(finding), (None, False))
            if why_text:
                if disagreed:
                    lines.append("  - Classification and `audit2why` disagree; both kept.")
                lines.append("  - audit2why:")
                for why_line in why_text.splitlines():
                    lines.append(f"    {why_line}")
        lines.append("")
    else:
        lines.append("None.")
        lines.append("")

    lines.extend(["## Limitations", ""])
    if limitations:
        for item in sorted(set(limitations)):
            lines.append(f"- {item}")
    else:
        lines.append("- None.")
    lines.append("")
    return "\n".join(lines)


def run(args: argparse.Namespace) -> int:
    limitations: list[str] = []
    domain = args.domain
    domains = {domain}
    app_name = vendor_app_name(domain, args.vendor_class)
    existing_fc = ""
    if args.existing_fc and args.existing_fc.is_file():
        existing_fc = args.existing_fc.read_text(encoding="utf-8")

    if not args.avc_log.is_file() or args.avc_log.stat().st_size == 0:
        limitations.append("No AVC log to classify.")
        report = render_report(
            findings=[],
            commands=[],
            unresolvable=[],
            audit2why={},
            identity=_identity(args, app_name),
            limitations=limitations,
            avc_count=0,
        )
        return _write(args, report)

    entries, path_map, port_map = parse_avc_file(args.avc_log, domains)
    known_roots = [
        str(r)
        for r in (VENDOR_PATHS.get(app_name) or {}).get("extra_fc_roots") or []
        if r
    ]
    extra_from_avc: list[str] = []
    for (_src, tgt, _tclass), paths in path_map.items():
        if tgt not in GENERIC_FILE_TYPES:
            continue
        for path in paths:
            if not path or is_system_path(path):
                continue
            if any(
                path == root or path.startswith(root.rstrip("/") + "/")
                for root in known_roots
            ):
                continue
            extra_from_avc.append(str(Path(path).parent) if Path(path).name else path)
    manifest = synthetic_manifest(app_name, domain, extra_from_avc)
    extra_roots = list(manifest["paths"]["extra_fc_roots"])
    merged = merge_avc_entries(entries)
    net_new, _covered = subtract_covered(merged, {})
    hints = load_boolean_hints(args.boolean_hints)

    findings: list[Finding] = []
    for need in net_new:
        paths = tuple(sorted(path_map.get(need.key, set())))
        bind_ports = tuple(sorted(port_map.get(need.key, set())))
        finding = classify(
            need,
            manifest,
            paths,
            "",
            existing_fc,
            True,
            None,
            hints,
            bind_ports,
        )
        if finding.verdict == VERDICT_TOOLCHAIN:
            finding = Finding(
                need,
                VERDICT_DIRECT,
                "",
                "No fcontext, boolean, or port rule covers this denial.",
                finding.paths,
                engine="house_rules",
            )
        findings.append(finding)
    findings = sort_findings(findings)

    audit_available = shutil.which("audit2why") is not None
    if not audit_available:
        limitations.append("audit2why not found; skipped.")

    commands: list[tuple[Finding, list[str]]] = []
    unresolvable: list[Finding] = []
    audit_map: dict[int, tuple[str | None, bool]] = {}
    for finding in findings:
        why = None
        if audit_available:
            raw_lines = raw_lines_for_need(args.avc_log, finding.need, domains)
            snippets = [run_audit2why(line) for line in raw_lines]
            snippets = [s for s in snippets if s]
            why = "\n".join(sorted(set(snippets))) if snippets else None
        disagreed = bool(why) and audit2why_kind(why) != our_kind(finding.verdict)
        audit_map[id(finding)] = (why, disagreed)
        if finding.verdict in TUNE_VERDICTS:
            cmds = tune_commands(
                finding,
                manifest,
                args.fc_type,
                args.port_type,
                extra_roots,
                domain,
            )
            if cmds:
                commands.append((finding, cmds))
            else:
                unresolvable.append(finding)
        elif finding.verdict in UNRESOLVABLE_VERDICTS or finding.verdict not in TUNE_VERDICTS:
            unresolvable.append(finding)

    report = render_report(
        findings=findings,
        commands=commands,
        unresolvable=unresolvable,
        audit2why=audit_map,
        identity=_identity(args, app_name),
        limitations=limitations,
        avc_count=len(findings),
    )
    return _write(args, report)


def _identity(args: argparse.Namespace, app_name: str) -> dict[str, str]:
    return {
        "app": args.app_name,
        "situation": args.situation,
        "module": args.module,
        "package": args.package,
        "class": args.vendor_class,
        "domain": args.domain,
        "vendor_app": app_name,
    }


def _write(args: argparse.Namespace, report: str) -> int:
    args.out_dir.mkdir(parents=True, exist_ok=True)
    out = args.out_dir / "tune_report.md"
    text = report if report.endswith("\n") else report + "\n"
    out.write_text(text, encoding="utf-8")
    sys.stdout.write(text)
    print(f"Wrote {out}", file=sys.stderr)
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Read-only vendor-domain tune report (no policy module)"
    )
    parser.add_argument("--avc-log", type=Path, required=True)
    parser.add_argument("--out-dir", type=Path, default=Path("policy_out"))
    parser.add_argument("--app-name", required=True)
    parser.add_argument("--domain", required=True, help="Vendor SELinux domain, e.g. tomcat_t")
    parser.add_argument("--module", default="")
    parser.add_argument("--package", default="")
    parser.add_argument("--vendor-class", default="tomcat", dest="vendor_class")
    parser.add_argument("--situation", default="loaded")
    parser.add_argument("--fc-type", default="tomcat_var_lib_t")
    parser.add_argument("--port-type", default="http_port_t")
    parser.add_argument("--existing-fc", type=Path, default=None)
    parser.add_argument(
        "--boolean-hints",
        type=Path,
        default=Path(__file__).resolve().parent.parent / "config" / "boolean_hints.yml",
    )
    args = parser.parse_args()
    try:
        return run(args)
    except Exception as exc:  # noqa: BLE001 — degrade cleanly for the developer loop
        print(f"[WARN] tune-report could not complete: {exc}", file=sys.stderr)
        args.out_dir.mkdir(parents=True, exist_ok=True)
        skip = (
            "# Vendor policy tune report\n\n"
            "Read-only analysis could not complete on this host.\n\n"
            f"- {exc}\n"
        )
        (args.out_dir / "tune_report.md").write_text(skip, encoding="utf-8")
        sys.stdout.write(skip)
        return 0


if __name__ == "__main__":
    raise SystemExit(main())
