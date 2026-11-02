#!/usr/bin/env python3
"""
deterministic_gen.py — Offline, reproducible AVC → policy updates (house rules + optional sepolgen).

Requires PyYAML. Optional RHEL sepolgen: policycoreutils-devel + sepolgen-ifgen.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import yaml  # noqa: E402
from avc_preprocess import AccessNeed, merge_avc_entries, parse_existing_allows, subtract_covered  # noqa: E402
from boolean_hints import (  # noqa: E402
    load_boolean_hints,
    query_policy_identity,
    render_boolean_finding,
    resolve_booleans_for_need,
)
from policy_rules import (
    JAVA_EXEC_FILE_PERMS,  # noqa: E402
    EXEC_BIN_EXCEPTION,
    EXEC_BIN_REVIEW_NOTE,
    EXEC_BIN_TYPES,
    FORBIDDEN_TARGET_TYPES,
    GENERIC_FILE_TYPES,
    GENERIC_PORT_TYPES,
    STALE_ENTRYPOINT_TYPES,
    PATTERN_MACROS,
    VERDICT_BASELINE,
    VERDICT_DIRECT,
    VERDICT_FC,
    VERDICT_FC_DRIFT,
    VERDICT_FORBIDDEN,
    VERDICT_INTERFACE,
    VERDICT_PORT,
    VERDICT_BOOLEAN,
    VERDICT_TOOLCHAIN,
    VERDICT_NEEDS_REVIEW,
    NEXT_ACTION,
    format_needs_review_note,
    manifest_exception,
    needs_review_hits,
)
from avc_parse import (  # noqa: E402
    format_version,
    parse_avc_line,
    parse_version,
    read_policy_version,
    SELINUX_DIR,
)

from fc_labeling import (  # noqa: E402
    existing_fc_covers,
    filter_fc_fix_lines,
)

PATH_FIELD_RE = re.compile(r'path="([^"]+)"')
BIND_SRC_RE = re.compile(r"\bsrc=(\d+)\b")
POLICY_MODULE_RE = re.compile(r"policy_module\(\s*(\w+)\s*,\s*([\d.]+)\s*\)")

SEPOLGEN_UNAVAILABLE = object()

SEPOLGEN_WARN_BANNER = """\
================================================================================
WARNING: SEPOLGEN INTERFACE MATCHING IS NOT AVAILABLE
================================================================================
{detail}

Impact:
  - Base-type AVCs (e.g. var_log_t, port types) will NOT map to refpolicy macros.
  - This generator REFUSES raw allows on base types (exit 1) unless you pass
    --allow-degraded (audit2allow-grade output; not recommended).

Fix on RHEL / CentOS Stream (with SELinux):
  sudo dnf install -y policycoreutils-devel setools-console
  sudo sepolgen-ifgen

Do not confuse with "no interface matched" — that message only appears when
sepolgen-ifgen data is present but your specific denial has no macro.
================================================================================
"""


def sepolgen_diagnose() -> dict[str, str]:
    """Return status: available | missing_python_modules | missing_ifgen | unreadable_ifgen."""
    try:
        import sepolgen.defaults as defaults
    except ImportError:
        return {
            "status": "missing_python_modules",
            "detail": (
                "Python sepolgen is not installed. "
                "Install policycoreutils-devel (provides sepolgen modules)."
            ),
            "if_path": "",
        }

    try:
        if_path = defaults.interface_info()
    except (OSError, AttributeError) as exc:
        return {
            "status": "missing_ifgen",
            "detail": f"Cannot resolve sepolgen interface_info path: {exc}. Run: sudo sepolgen-ifgen",
            "if_path": "",
        }

    try:
        with open(if_path, encoding="utf-8") as fd:
            if not fd.read(1):
                return {
                    "status": "unreadable_ifgen",
                    "detail": f"interface_info at {if_path} is empty. Re-run: sudo sepolgen-ifgen",
                    "if_path": str(if_path),
                }
    except OSError as exc:
        return {
            "status": "missing_ifgen",
            "detail": (
                f"interface_info missing at {if_path}: {exc}. "
                "Run: sudo sepolgen-ifgen (after policycoreutils-devel is installed)."
            ),
            "if_path": str(if_path),
        }

    return {
        "status": "available",
        "detail": "",
        "if_path": str(if_path),
    }


def sepolgen_toolchain_available() -> bool:
    return sepolgen_diagnose()["status"] == "available"


def emit_sepolgen_warning(diagnose: dict[str, str] | None = None) -> None:
    diagnose = diagnose or sepolgen_diagnose()
    if diagnose["status"] == "available":
        return
    print(SEPOLGEN_WARN_BANNER.format(detail=diagnose["detail"]), file=sys.stderr)


def emit_degraded_warning(findings: list[Finding]) -> None:
    degraded = [f for f in findings if f.engine == "degraded"]
    if not degraded:
        return
    print(
        "\n"
        "================================================================================\n"
        "WARNING: --allow-degraded IS ON — EMITTING RAW ALLOWS WITHOUT SEPOLGEN\n"
        "================================================================================\n"
        f"{len(degraded)} rule(s) use engine=degraded in findings.json. "
        "Admin review must treat these as audit2allow output, not interface-backed policy.\n"
        "Install sepolgen-ifgen and regenerate without --allow-degraded when possible.\n"
        "================================================================================\n",
        file=sys.stderr,
    )


@dataclass(frozen=True)
class Finding:
    need: AccessNeed
    verdict: str
    rendered: str
    note: str
    paths: tuple[str, ...] = ()
    engine: str = "house_rules"
    boolean: str = ""
    bind_port: int | None = None
    bind_proto: str = ""
    port_type: str = ""
    review_key: str = ""

    @property
    def next_action(self) -> str:
        return NEXT_ACTION.get(self.verdict, "")


def load_manifest(path: Path) -> dict:
    return yaml.safe_load(path.read_text(encoding="utf-8"))


def domains_from_manifest(manifest: dict) -> set[str]:
    out = {manifest["domain"]}
    for svc in manifest.get("services", {}).values():
        if isinstance(svc, dict) and svc.get("domain"):
            out.add(str(svc["domain"]))
    return out


def private_types(manifest: dict) -> set[str]:
    app = manifest["app_name"]
    return {
        f"{app}_t",
        f"{app}_backend_t",
        f"{app}_exec_t",
        f"{app}_lib_t",
        f"{app}_var_lib_t",
        f"{app}_var_run_t",
        f"{app}_log_t",
        f"{app}_script_exec_t",
        f"{app}_backend_exec_t",
        f"{app}_port_t",
        f"{app}_backend_port_t",
    }


def suggest_fc_type(path: str, manifest: dict) -> str | None:
    app = manifest["app_name"]
    paths = manifest.get("paths", {})
    rules = (
        ("log_dir", "log_t"),
        ("var_dir", "var_lib_t"),
        ("runtime_dir", "var_run_t"),
        ("install_root", "exec_t"),
    )
    for key, suffix in rules:
        root = paths.get(key)
        if not root:
            continue
        base = root.rstrip("/")
        if path == base or path.startswith(base + "/"):
            # shopapi's .fc labels only bin/shopapi as the exec type. The jar
            # and config under the same tree are shopapi_lib_t.
            if suffix == "exec_t" and app == "shopapi" and path != f"{base}/bin/{app}":
                return f"{app}_lib_t"
            return f"{app}_{suffix}"
    extras = paths.get("extra_fc_roots") or []
    if isinstance(extras, str):
        extras = [extras]
    for root in extras:
        if not root:
            continue
        base = str(root).rstrip("/")
        if path == base or path.startswith(base + "/"):
            return f"{app}_var_lib_t"
    return None


def fc_regex_for_app_path(path: str, manifest: dict) -> str:
    """Data roots (var/log/run/extra_fc_roots) become recursive .fc regexes.

    Nested files under those roots must match the directory regex so restorecon
    labels the whole tree (shopapi /feature-spool → /var/spool/shopapi(/.*)?).
    install_root is not recursive here: a cache file under /opt/app is a
    specific .fc line, not a blanket exec_t tree.
    """
    paths = manifest.get("paths") or {}
    recursive_roots: list[str] = []
    for key in ("var_dir", "log_dir", "runtime_dir", "var_opt_dir"):
        root = paths.get(key)
        if root:
            recursive_roots.append(str(root).rstrip("/"))
    extras = paths.get("extra_fc_roots") or []
    if isinstance(extras, str):
        extras = [extras]
    recursive_roots.extend(str(r).rstrip("/") for r in extras if r)
    p = path.rstrip("/")
    for root in recursive_roots:
        if p == root or p.startswith(root + "/"):
            return f"{re.escape(root)}(/.*)?"
    return re.escape(path)


def collapse_to_pattern(perms: frozenset[str]) -> str | None:
    perm_set = set(perms)
    for required, macro in PATTERN_MACROS:
        if required <= perm_set:
            return macro
    return None


def parse_avc_file(
    avc_path: Path, domains: set[str]
) -> tuple[list, dict[tuple[str, str, str], set[str]], dict[tuple[str, str, str], set[int]]]:
    from avc_parse import AvcEntry

    entries: list[AvcEntry] = []
    paths: dict[tuple[str, str, str], set[str]] = {}
    ports: dict[tuple[str, str, str], set[int]] = {}
    for line in avc_path.read_text(encoding="utf-8", errors="replace").splitlines():
        if "type=AVC" not in line:
            continue
        entry = parse_avc_line(line)
        src = entry.scontext.split(":")[2] if entry.scontext.count(":") >= 2 else ""
        tgt = entry.tcontext.split(":")[2] if entry.tcontext.count(":") >= 2 else ""
        if src not in domains:
            continue
        entries.append(entry)
        if not tgt or not entry.tclass:
            continue
        key = (src, tgt, entry.tclass)
        pm = PATH_FIELD_RE.search(line)
        if pm:
            paths.setdefault(key, set()).add(pm.group(1))
        if "name_bind" in (entry.perm or ""):
            sm = BIND_SRC_RE.search(line)
            if sm:
                ports.setdefault(key, set()).add(int(sm.group(1)))
    return entries, paths, ports


_SEPOLGEN_IFSETS: dict[str, object] = {}


def try_sepolgen_interface(
    src: str, tgt: str, tclass: str, perms: frozenset[str]
) -> tuple[str, str] | None | object:
    try:
        import sepolgen.access as access_mod
        import sepolgen.defaults as defaults
        import sepolgen.interfaces as interfaces
        import sepolgen.matching as matching
    except ImportError:
        return SEPOLGEN_UNAVAILABLE

    if_path = defaults.interface_info()
    ifset = _SEPOLGEN_IFSETS.get(if_path)
    if ifset is None:
        # Parsing interface_info takes seconds. Do it once per run, not per denial.
        try:
            with open(if_path, encoding="utf-8") as fd:
                ifset = interfaces.InterfaceSet()
                ifset.from_file(fd)
        except OSError:
            return SEPOLGEN_UNAVAILABLE
        _SEPOLGEN_IFSETS[if_path] = ifset

    try:
        av = access_mod.AccessVector([src, tgt, tclass, *sorted(perms)])
        matcher = matching.Match()
        candidates = matcher.search(ifset, av)
    except (AttributeError, TypeError, ValueError):
        return None
    if not candidates:
        return None
    best = sorted(candidates, key=lambda m: (-getattr(m, "dist", 0), m.interface.name))[0]
    return f"{best.interface.name}({src})", f"Matched refpolicy interface (distance {getattr(best, 'dist', '?')})."


def baseline_macro_covers(need: AccessNeed, te_text: str) -> bool:
    if need.tgt_type == "random_device_t" and need.perms <= frozenset({"read", "open", "getattr"}):
        if f"dev_read_urand({need.src_type})" in te_text:
            return True
    return False


def finding_needs_review_allowed(finding: Finding, args: argparse.Namespace) -> bool:
    # bin_t execute is unlocked only by a reviewed reason in the app manifest.
    if finding.review_key == EXEC_BIN_EXCEPTION:
        return False
    if getattr(args, "allow_needs_review", False):
        return True
    allowed = {str(p).lower() for p in (getattr(args, "allow_needs_review_perm", None) or [])}
    return any(perm.lower() in allowed for perm in finding.need.perms)


def generation_blockers(findings: list[Finding], args: argparse.Namespace) -> list[Finding]:
    blocked: list[Finding] = []
    for finding in findings:
        if finding.verdict == VERDICT_TOOLCHAIN:
            blocked.append(finding)
        elif finding.verdict == VERDICT_NEEDS_REVIEW and not finding_needs_review_allowed(
            finding, args
        ):
            blocked.append(finding)
    return blocked


def classify(
    need: AccessNeed,
    manifest: dict,
    paths: tuple[str, ...],
    existing_te: str,
    existing_fc: str,
    allow_degraded: bool,
    policy_kern: Path | None,
    boolean_hints: list[dict],
    bind_ports: tuple[int, ...] = (),
) -> Finding:
    src, tgt, tclass = need.src_type, need.tgt_type, need.tclass
    perms = need.perms
    if tclass == "tcp_socket" and src == tgt:
        need = AccessNeed(src, tgt, tclass, perms | frozenset({"read", "write", "ioctl"}))
        perms = need.perms

    if baseline_macro_covers(need, existing_te):
        return Finding(
            need,
            VERDICT_BASELINE,
            "",
            "Covered by dev_read_urand in reviewed baseline block.",
            paths,
        )

    if (
        tclass == "file"
        and "entrypoint" in perms
        and tgt in STALE_ENTRYPOINT_TYPES
    ):
        for path in paths:
            want = suggest_fc_type(path, manifest)
            if not want:
                continue
            if existing_fc_covers(path, want, existing_fc):
                return Finding(
                    need,
                    VERDICT_FC_DRIFT,
                    "",
                    f"{path} is already covered by the .fc as {want}, but the denial "
                    f"names {tgt}. The label on disk is stale. No allow is written. "
                    f"Run: restorecon -Rv {path}",
                    paths,
                )
            fc = (
                f"{fc_regex_for_app_path(path, manifest)}    "
                f"gen_context(system_u:object_r:{want},s0)"
            )
            return Finding(
                need,
                VERDICT_FC,
                fc,
                f"{path} is an entrypoint labeled {tgt}. Label it {want}. "
                f"Do not allow {tgt}.",
                paths,
            )
        return Finding(
            need,
            VERDICT_FC_DRIFT,
            "",
            f"entrypoint on shared type {tgt} is a stale label. "
            f"Do not allow {tgt}. restorecon the module's exec type.",
            paths,
        )

    if tgt in FORBIDDEN_TARGET_TYPES:
        return Finding(
            need,
            VERDICT_FORBIDDEN,
            "",
            f"Refusing to grant {src} access to {tgt}. Denied paths: {', '.join(paths) or 'n/a'}",
            paths,
        )

    if tgt in GENERIC_FILE_TYPES:
        use_paths = paths
        if not use_paths and tgt == "var_spool_t":
            extras = manifest.get("paths", {}).get("extra_fc_roots") or []
            if isinstance(extras, str):
                extras = [extras]
            use_paths = tuple(str(r) for r in extras if r)
        for path in use_paths:
            want = suggest_fc_type(path, manifest)
            if want:
                if existing_fc_covers(path, want, existing_fc):
                    return Finding(
                        need,
                        VERDICT_FC_DRIFT,
                        "",
                        f"{path} should already be {want} per the .fc, but is labeled "
                        f"{tgt} on disk. No policy change needed — run: "
                        f"restorecon -Rv {path}",
                        paths,
                        engine="house_rules",
                    )
                fc = f"{fc_regex_for_app_path(path, manifest)}    gen_context(system_u:object_r:{want},s0)"
                return Finding(
                    need,
                    VERDICT_FC,
                    fc,
                    f"{path} is under an app-owned directory but labeled {tgt}. "
                    f"Fix labeling (.fc + restorecon), do not allow {tgt}.",
                    paths,
                )

    if tgt in GENERIC_PORT_TYPES and "name_bind" in perms:
        app = manifest["app_name"]
        ptype = f"{app}_port_t"
        port = bind_ports[0] if bind_ports else None
        proto = "udp" if tclass == "udp_socket" else "tcp"
        note = f"Use private port type {ptype} and semanage port — not {tgt}."
        if port is not None:
            note += (
                f" Add to the app manifest selinux_ports "
                f"(port {port}/{proto}, type {ptype}); canary runs semanage port -a."
            )
        return Finding(
            need,
            VERDICT_PORT,
            f"allow {src} {ptype}:{tclass} name_bind;",
            note,
            paths,
            bind_port=port,
            bind_proto=proto if port is not None else "",
            port_type=ptype,
        )

    if tgt == "node_t" and "node_bind" in perms and tclass in ("tcp_socket", "udp_socket"):
        proto = "udp" if tclass == "udp_socket" else "tcp"
        return Finding(
            need,
            VERDICT_INTERFACE,
            f"corenet_{proto}_bind_generic_node({src})",
            "Bind a socket to a network node (refpolicy corenet).",
            paths,
            engine="house_rules",
        )

    if tgt == "cgroup_t":
        return Finding(
            need,
            VERDICT_BASELINE,
            "",
            "cgroup_t is JVM cgroupfs telemetry; omit rather than require an undeclared type.",
            paths,
        )

    if tgt == "random_device_t":
        return Finding(
            need,
            VERDICT_INTERFACE,
            f"dev_read_urand({src})\ndev_read_rand({src})",
            "Observed /dev/random and /dev/urandom reads.",
            paths,
            engine="house_rules",
        )

    if tgt == "tmp_t":
        if tclass == "dir":
            rendered = f"files_manage_generic_tmp_dirs({src})"
        else:
            parts: list[str] = []
            if "map" in perms:
                parts.append(f"files_map_generic_tmp_files({src})")
            if perms - {"map"}:
                parts.append(f"files_manage_generic_tmp_files({src})")
            rendered = "\n".join(parts) or f"files_manage_generic_tmp_files({src})"
        return Finding(
            need,
            VERDICT_INTERFACE,
            rendered,
            "Observed generic tmp (hsperfdata / work files).",
            paths,
            engine="house_rules",
        )

    if tgt == "proc_t":
        return Finding(
            need,
            VERDICT_INTERFACE,
            f"kernel_read_system_state({src})",
            "Observed /proc/stat (and similar) reads.",
            paths,
            engine="house_rules",
        )

    if tgt == "proc_net_t":
        rendered = (
            f"kernel_read_network_state_symlinks({src})"
            if tclass == "lnk_file"
            else f"kernel_read_network_state({src})"
        )
        return Finding(
            need,
            VERDICT_INTERFACE,
            rendered,
            "Observed /proc/net reads.",
            paths,
            engine="house_rules",
        )

    existing = parse_existing_allows(existing_te)
    uncovered = need.perms - existing.get(need.key, frozenset())
    if not uncovered:
        return Finding(
            need,
            VERDICT_BASELINE,
            "",
            "Already allowed in existing .te",
            paths,
        )

    if (
        tgt in EXEC_BIN_TYPES
        and tclass == "file"
        and "execute" in need.perms
        and "entrypoint" not in need.perms
        and need.perms <= JAVA_EXEC_FILE_PERMS
    ):
        rendered = f"corecmd_exec_bin({src})"
        ran = ", ".join(paths) if paths else "a program labeled bin_t"
        reason = manifest_exception(manifest, EXEC_BIN_EXCEPTION)
        if reason:
            return Finding(
                need,
                VERDICT_INTERFACE,
                rendered,
                f"Reviewed exception (selinux_exceptions.exec_bin): {reason} Executed: {ran}.",
                paths,
                engine="house_rules",
                review_key=EXEC_BIN_EXCEPTION,
            )
        return Finding(
            need,
            VERDICT_NEEDS_REVIEW,
            rendered,
            f"{EXEC_BIN_REVIEW_NOTE} Executed: {ran}.",
            paths,
            review_key=EXEC_BIN_EXCEPTION,
        )

    module_types = private_types(manifest) | domains_from_manifest(manifest)
    review_hits = needs_review_hits(src, tgt, tclass, need.perms, module_types)
    if review_hits:
        tgt_render = "self" if src == tgt else tgt
        perm_list = " ".join(sorted(need.perms))
        rendered = (
            f"allow {src} {tgt_render}:{tclass} {{ {perm_list} }};"
            if len(need.perms) > 1
            else f"allow {src} {tgt_render}:{tclass} {perm_list};"
        )
        return Finding(
            need,
            VERDICT_NEEDS_REVIEW,
            rendered,
            format_needs_review_note(review_hits),
            paths,
        )

    if tgt in private_types(manifest):
        macro = collapse_to_pattern(need.perms)
        if macro and tclass in ("file", "dir"):
            rendered = f"{macro}({src}, {tgt}, {tgt})"
        else:
            perm_list = " ".join(sorted(need.perms))
            rendered = (
                f"allow {src} {tgt}:{tclass} {{ {perm_list} }};"
                if len(need.perms) > 1
                else f"allow {src} {tgt}:{tclass} {perm_list};"
            )
        return Finding(need, VERDICT_DIRECT, rendered, "Module-private type.", paths)

    boolean_unavailable_detail = ""
    triage = resolve_booleans_for_need(
        need,
        boolean_hints,
        manifest,
        policy_kern=policy_kern,
    )
    if triage.status == "matched" and triage.matches:
        rendered, note, names = render_boolean_finding(triage.matches)
        engine = "boolean_triage"
        if triage.policy_query_status == "unavailable":
            engine = "curated_override"
        return Finding(
            need,
            VERDICT_BOOLEAN,
            rendered,
            note,
            paths,
            engine=engine,
            boolean=names,
        )
    if triage.status == "unavailable":
        boolean_unavailable_detail = triage.detail

    iface = try_sepolgen_interface(src, tgt, tclass, need.perms)
    if iface is SEPOLGEN_UNAVAILABLE:
        if boolean_unavailable_detail:
            return Finding(
                need,
                VERDICT_TOOLCHAIN,
                "",
                "Boolean policy check could not run "
                f"({boolean_unavailable_detail}). "
                "Refusing raw allow on base type without sepolgen. "
                "Install setools-console, ensure policy is loaded, run sepolgen-ifgen, "
                "or pass --allow-degraded (not recommended).",
                paths,
                engine="none",
            )
        if allow_degraded:
            perm_list = " ".join(sorted(need.perms))
            rendered = f"allow {src} {tgt}:{tclass} {{ {perm_list} }};"
            return Finding(
                need,
                VERDICT_DIRECT,
                rendered,
                "sepolgen unavailable — degraded raw allow on base type (--allow-degraded). "
                "Install policycoreutils-devel and run sepolgen-ifgen for interface matching.",
                paths,
                engine="degraded",
            )
        return Finding(
            need,
            VERDICT_TOOLCHAIN,
            "",
            "Refusing raw allow on base type without sepolgen. Install policycoreutils-devel, "
            "run sepolgen-ifgen, or pass --allow-degraded (records degraded rules in findings.json).",
            paths,
            engine="none",
        )
    if iface:
        rendered, note = iface
        return Finding(need, VERDICT_INTERFACE, rendered, note, paths, engine="sepolgen")

    if boolean_unavailable_detail:
        return Finding(
            need,
            VERDICT_TOOLCHAIN,
            "",
            "Boolean policy check could not run "
            f"({boolean_unavailable_detail}). "
            "Refusing raw allow without confirming no boolean applies — manual review required.",
            paths,
            engine="none",
        )

    perm_list = " ".join(sorted(need.perms))
    rendered = f"allow {src} {tgt}:{tclass} {{ {perm_list} }};"
    return Finding(
        need,
        VERDICT_DIRECT,
        rendered,
        "sepolgen ran but no refpolicy interface matched this denial — manual review required "
        "(not the same as sepolgen missing).",
        paths,
        engine="house_rules",
    )


def render_fragment(findings: list[Finding], meta: dict) -> str:
    lines = [
        "########################################",
        "# Generated by deterministic_gen.py (reproducible for identical inputs).",
        f"# avc-sha256-prefix: {meta.get('avc_sha', 'unknown')}",
        f"# refpolicy-devel:     {meta.get('refpolicy', 'unknown')}",
        f"# selinux-policy-rpm:  {meta.get('selinux_policy_rpm', 'unknown')}",
        f"# policy-version:      {meta.get('policy_version', 'unknown')}",
        f"# policy-kern:         {meta.get('policy_kern', 'unknown')}",
        "########################################",
        "",
    ]
    review_rows = sorted(
        (f for f in findings if f.verdict == VERDICT_NEEDS_REVIEW and f.rendered),
        key=lambda f: (f.need.src_type, f.need.tgt_type, f.need.tclass, f.rendered),
    )
    if review_rows:
        lines.append("# Needs review (domain-weakening permissions; --allow-needs-review)")
        for f in review_rows:
            lines.append(f"# {f.note}")
            lines.append(f.rendered)
        lines.append("")
    for verdict, heading in (
        (VERDICT_INTERFACE, "# Refpolicy interfaces"),
        (VERDICT_DIRECT, "# Module-private / direct access"),
        (VERDICT_PORT, "# Private port binding"),
    ):
        rows = sorted({f.rendered for f in findings if f.verdict == verdict and f.rendered})
        if rows:
            lines.append(heading)
            if verdict == VERDICT_DIRECT:
                # A raw allow on a base type does not compile until the module
                # requires that type. Types this module declares do not.
                external = sorted(
                    {
                        f.need.tgt_type
                        for f in findings
                        if f.verdict == VERDICT_DIRECT
                        and f.rendered.startswith("allow ")
                        and not f.note.startswith("Module-private")
                        and f.need.tgt_type not in ("", "self")
                    }
                )
                if external:
                    lines.append("gen_require(`")
                    for tgt_type in external:
                        lines.append(f"\ttype {tgt_type};")
                    lines.append("')")
            lines.extend(rows)
            lines.append("")
    return "\n".join(lines).rstrip() + "\n"


def merge_te(existing_te: str, app_name: str, new_version: str, fragment: str) -> str:
    te = existing_te
    if POLICY_MODULE_RE.search(te):
        te = POLICY_MODULE_RE.sub(f"policy_module({app_name}, {new_version})", te, count=1)
    if fragment.strip():
        te = te.rstrip() + "\n\n" + fragment
    return te if te.endswith("\n") else te + "\n"


def merge_fc(existing_fc: str, fc_lines: list[str], path_hints: dict[str, str] | None = None) -> str:
    kept, redundant = filter_fc_fix_lines(existing_fc, fc_lines, path_hints)
    if redundant and not kept:
        return existing_fc if existing_fc.endswith("\n") else existing_fc + "\n"
    if not kept:
        return existing_fc if existing_fc.endswith("\n") else existing_fc + "\n"
    block = "\n".join(sorted(set(kept))) + "\n"
    return existing_fc.rstrip() + "\n\n# deterministic_gen labeling fixes\n" + block


def write_pr_summary(findings: list[Finding], app_name: str, meta: dict | None = None) -> str:
    meta = meta or {}
    from pr_summary_common import format_vendor_override_summary

    lines: list[str] = []
    override = meta.get("vendor_override")
    if isinstance(override, dict) and override.get("reason"):
        lines.append(format_vendor_override_summary(override).rstrip())
        lines.append("")

    module_rows = [
        f
        for f in findings
        if f.verdict
        in (VERDICT_DIRECT, VERDICT_FC, VERDICT_FC_DRIFT, VERDICT_INTERFACE, VERDICT_PORT)
    ]
    boolean_rows = [f for f in findings if f.verdict == VERDICT_BOOLEAN]
    review_rows = sorted(
        (f for f in findings if f.verdict == VERDICT_NEEDS_REVIEW),
        key=lambda f: (
            f.need.src_type,
            f.need.tgt_type,
            f.need.tclass,
            " ".join(sorted(f.need.perms)),
        ),
    )

    if review_rows:
        lines.extend(
            [
                "### Needs review (domain-weakening permissions)",
                "",
                "These permissions were present in the AVC log. They are **security decisions**, "
                "not labeling misses. Without `--allow-needs-review` they are **not** written to "
                "the `.te`.",
                "",
            ]
        )
        for f in review_rows:
            perms = " ".join(sorted(f.need.perms))
            lines.append(
                f"- `{f.need.src_type}` → `{f.need.tgt_type}:{f.need.tclass} {{ {perms} }}`"
            )
            if f.rendered:
                lines.append(f"  - Proposed rule: `{f.rendered}`")
            lines.append(f"  - {f.note}")
        lines.append("")

    lines.extend(
        [
            "### Network Bindings",
        ]
    )
    port_rows = [f for f in findings if f.verdict == VERDICT_PORT]
    if port_rows:
        for f in port_rows:
            port = f.bind_port if f.bind_port is not None else "?"
            lines.append(
                f"- `{f.next_action}`: {f.need.src_type} bind {port}/{f.bind_proto or 'tcp'} "
                f"({f.verdict}); add to manifest `selinux_ports`, do not `semanage port -a` on prod"
            )
    else:
        lines.append("- See generated port / interface rules below")

    lines.extend(
        [
            "",
            "### File System Access",
        ]
    )
    for f in module_rows:
        if f.verdict == VERDICT_PORT:
            continue
        lines.append(f"- {f.need.src_type} → {f.need.tgt_type}:{f.need.tclass} ({f.verdict})")

    lines.extend(
        [
            "",
            "### Host administrative actions (not shipped in RPM)",
        ]
    )
    if boolean_rows:
        lines.append(
            "These are **host-wide** `setsebool` decisions — not applied by the policy module package:"
        )
        for f in boolean_rows:
            lines.append(f"- `{f.rendered}` — {f.note[:200]}")
    else:
        lines.append("- None")

    lines.extend(["", "### Next action"])
    action_rows = [f for f in findings if f.next_action]
    if not action_rows:
        lines.append("- None")
    else:
        for f in action_rows:
            if f.verdict == VERDICT_PORT and f.bind_port is not None:
                lines.append(
                    f"- `{f.next_action}` — add to `config/{app_name}.manifest.yml` `selinux_ports` "
                    "(canary runs semanage port -a):"
                )
                lines.append("  ```yaml")
                lines.append(f"  - port: {f.bind_port}")
                lines.append(f"    proto: {f.bind_proto or 'tcp'}")
                lines.append(f"    type: {f.port_type}")
                lines.append("  ```")
            elif f.verdict in (VERDICT_FC, VERDICT_FC_DRIFT):
                lines.append(f"- `{f.next_action}` — {f.note}")
            elif f.verdict == VERDICT_BOOLEAN:
                lines.append(f"- `{f.next_action}` — `{f.rendered}` (not shipped in the RPM)")
            elif f.verdict == VERDICT_NEEDS_REVIEW:
                lines.append(
                    f"- `{f.next_action}` — pass `--allow-needs-review` only after confirming "
                    f"this AVC ({f.need.tclass}:{' '.join(sorted(f.need.perms))})"
                )
            else:
                lines.append(f"- `{f.next_action}` — {f.note[:160]}")

    lines.extend(
        [
            "",
            "### Policy context (boolean query)",
            f"- selinux-policy RPM: `{meta.get('selinux_policy_rpm', 'unknown')}`",
            f"- Policy version: `{meta.get('policy_version', 'unknown')}`",
            f"- policy.kern: `{meta.get('policy_kern') or 'unavailable'}`",
            "",
            "### Process Execution",
            f"- {app_name}_exec_t entrypoints unchanged unless .fc fixes applied",
            "",
            "### Explicit Denials Maintained",
            "- No wildcard allows; forbidden targets refused at generation time",
            "",
            "### Classification audit (engine)",
            "| Verdict | Target | Engine | Note |",
            "| --- | --- | --- | --- |",
        ]
    )
    for f in findings:
        note = f.note.replace("|", "\\|")[:120]
        lines.append(
            f"| {f.verdict} | {f.need.tgt_type} | {f.engine} | {note} |"
        )
    lines.append("")
    return "\n".join(lines)


def host_admin_actions(findings: list[Finding]) -> list[dict]:
    actions: list[dict] = []
    for f in findings:
        if f.verdict != VERDICT_BOOLEAN:
            continue
        actions.append(
            {
                "kind": "boolean",
                "boolean": f.boolean,
                "command": f.rendered,
                "note": f.note,
                "src": f.need.src_type,
                "tgt": f.need.tgt_type,
                "class": f.need.tclass,
                "perms": sorted(f.need.perms),
            }
        )
    return actions


def write_findings_artifact(
    out_dir: Path,
    findings: list[Finding],
    sepolgen_info: dict[str, str],
    *,
    generation_blocked: bool,
    vendor_override: dict | None = None,
) -> None:
    out_dir.mkdir(parents=True, exist_ok=True)
    payload: dict = {
        "sepolgen_status": sepolgen_info["status"],
        "sepolgen_detail": sepolgen_info.get("detail", ""),
        "generation_blocked": generation_blocked,
        "policy_identity": {
            "selinux_policy_rpm": sepolgen_info.get("selinux_policy_rpm", "unknown"),
            "policy_version": sepolgen_info.get("policy_version", "unknown"),
            "policy_kern": sepolgen_info.get("policy_kern", ""),
        },
        "host_admin_actions": host_admin_actions(findings),
        "findings": [
            {
                "src": f.need.src_type,
                "tgt": f.need.tgt_type,
                "class": f.need.tclass,
                "perms": sorted(f.need.perms),
                "verdict": f.verdict,
                "rendered": f.rendered,
                "note": f.note,
                "engine": f.engine,
                **({"boolean": f.boolean} if f.boolean else {}),
                **({"review_key": f.review_key} if f.review_key else {}),
                **({"next_action": f.next_action} if f.next_action else {}),
                **({"port": f.bind_port} if f.bind_port is not None else {}),
                **({"proto": f.bind_proto} if f.bind_proto else {}),
                **({"port_type": f.port_type} if f.port_type else {}),
                **(
                    {
                        "selinux_ports_snippet": {
                            "port": f.bind_port,
                            "proto": f.bind_proto or "tcp",
                            "type": f.port_type,
                        }
                    }
                    if f.verdict == VERDICT_PORT and f.bind_port is not None and f.port_type
                    else {}
                ),
            }
            for f in findings
        ],
    }
    if vendor_override:
        payload["vendor_override"] = vendor_override
    out_dir.joinpath("findings.json").write_text(
        json.dumps(payload, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )


def tool_versions() -> dict[str, str]:
    def rpm_q(pkg: str) -> str:
        try:
            return subprocess.run(
                ["rpm", "-q", pkg],
                capture_output=True,
                text=True,
                check=True,
            ).stdout.strip()
        except (FileNotFoundError, subprocess.CalledProcessError):
            return "unknown"

    return {"refpolicy": rpm_q("selinux-policy-devel")}


def _load_vendor_override(path: Path | None) -> dict | None:
    if path is None:
        return None
    override_path = Path(path)
    if not override_path.is_file():
        return None
    data = json.loads(override_path.read_text(encoding="utf-8"))
    return data if isinstance(data, dict) else None


def run(args: argparse.Namespace) -> int:
    project_root = Path(__file__).resolve().parent.parent
    lib_dir = project_root / "scripts" / "lib"
    if str(lib_dir) not in sys.path:
        sys.path.insert(0, str(lib_dir))
    from app_manifest import load_manifest as load_manifest_checked, policy_source_paths

    manifest = load_manifest_checked(args.manifest)
    if getattr(args, "app_name", None) is not None:
        if args.app_name != manifest["app_name"]:
            print(
                f"[ERROR] --app-name {args.app_name!r} conflicts with manifest app_name {manifest['app_name']!r}",
                file=sys.stderr,
            )
            return 1
    app_name = manifest["app_name"]
    src = policy_source_paths(project_root, manifest)
    te_path = args.existing_te or src["te"]
    fc_path = args.existing_fc or src["fc"]
    version_file = args.version_file or src["version_file"]

    domains = domains_from_manifest(manifest)
    existing_te = te_path.read_text(encoding="utf-8")
    existing_fc = fc_path.read_text(encoding="utf-8")

    sepolgen_info = sepolgen_diagnose()
    emit_sepolgen_warning(sepolgen_info)
    if args.allow_degraded and sepolgen_info["status"] != "available":
        print(
            "[WARN] --allow-degraded: base-type denials may become raw allows in output.\n",
            file=sys.stderr,
        )

    hints = load_boolean_hints(args.boolean_hints)
    policy_id = query_policy_identity(args.policy_kern)

    entries, path_map, port_map = parse_avc_file(args.avc_log, domains)
    merged = merge_avc_entries(entries)
    net_new, covered = subtract_covered(merged, parse_existing_allows(existing_te))

    findings: list[Finding] = []
    for need in [*net_new, *covered]:
        paths = tuple(sorted(path_map.get(need.key, set())))
        bind_ports = tuple(sorted(port_map.get(need.key, set())))
        findings.append(
            classify(
                need,
                manifest,
                paths,
                existing_te,
                existing_fc,
                args.allow_degraded,
                args.policy_kern,
                hints,
                bind_ports,
            )
        )

    meta = tool_versions()
    meta.update(policy_id)
    meta["avc_sha"] = hashlib.sha256(args.avc_log.read_bytes()).hexdigest()[:16]
    meta["sepolgen"] = sepolgen_info["status"]
    if sepolgen_info.get("if_path"):
        meta["sepolgen_if_path"] = sepolgen_info["if_path"]
    vendor_override = _load_vendor_override(getattr(args, "vendor_override", None))
    if vendor_override:
        meta["vendor_override"] = vendor_override

    blockers = generation_blockers(findings, args)

    artifact_ctx = {**sepolgen_info, **policy_id}

    if args.explain:
        for f in findings:
            perms = " ".join(sorted(f.need.perms))
            print(
                f"[{f.verdict:>12}] {f.need.src_type} → {f.need.tgt_type}:"
                f"{f.need.tclass} {{{perms}}}"
            )
            print(f"               {f.note}")
            if f.rendered:
                print(f"               → {f.rendered}")
        emit_degraded_warning(findings)
        refused = any(f.verdict == VERDICT_FORBIDDEN for f in findings)
        if blockers or refused:
            args.out_dir.mkdir(parents=True, exist_ok=True)
            write_findings_artifact(
                args.out_dir,
                findings,
                artifact_ctx,
                generation_blocked=True,
                vendor_override=vendor_override,
            )
        return 1 if blockers or refused else 0

    if blockers:
        review = [f for f in blockers if f.verdict == VERDICT_NEEDS_REVIEW]
        other = [f for f in blockers if f.verdict != VERDICT_NEEDS_REVIEW]
        if other:
            print(
                "\n*** GENERATION BLOCKED — fix sepolgen or remove base-type denials from AVC log ***\n",
                file=sys.stderr,
            )
        exec_bin = [f for f in review if f.review_key == EXEC_BIN_EXCEPTION]
        if len(exec_bin) < len(review):
            print(
                "\n*** GENERATION BLOCKED — domain-weakening permission requires "
                "--allow-needs-review (or --allow-needs-review-perm) ***\n",
                file=sys.stderr,
            )
        if exec_bin:
            print(
                f"\n*** GENERATION BLOCKED — executing a bin_t program needs a reviewed reason "
                f"in the app manifest: selinux_exceptions.exec_bin ({args.manifest}) ***\n",
                file=sys.stderr,
            )
        for f in blockers:
            label = "NEEDS REVIEW" if f.verdict == VERDICT_NEEDS_REVIEW else "REFUSED"
            print(f"{label}: {f.note}", file=sys.stderr)
        write_findings_artifact(
            args.out_dir,
            findings,
            artifact_ctx,
            generation_blocked=True,
            vendor_override=vendor_override,
        )
        (args.out_dir / "pr_summary.md").write_text(
            write_pr_summary(findings, app_name, meta),
            encoding="utf-8",
        )
        print(f"\nWrote {args.out_dir}/findings.json (generation_blocked=true)\n", file=sys.stderr)
        return 1

    forbidden = [f for f in findings if f.verdict == VERDICT_FORBIDDEN]
    emittable = [
        f
        for f in findings
        if f.rendered
        and f.verdict
        in (VERDICT_INTERFACE, VERDICT_DIRECT, VERDICT_PORT, VERDICT_NEEDS_REVIEW, VERDICT_FC)
    ]
    if forbidden and not emittable:
        print(
            "\n*** GENERATION BLOCKED — fix sepolgen or remove base-type denials from AVC log ***\n",
            file=sys.stderr,
        )
        for f in forbidden:
            print(f"REFUSED: {f.note}", file=sys.stderr)
        write_findings_artifact(
            args.out_dir,
            findings,
            artifact_ctx,
            generation_blocked=True,
            vendor_override=vendor_override,
        )
        (args.out_dir / "pr_summary.md").write_text(
            write_pr_summary(findings, app_name, meta),
            encoding="utf-8",
        )
        print(f"\nWrote {args.out_dir}/findings.json (generation_blocked=true)\n", file=sys.stderr)
        return 1
    if forbidden:
        for f in forbidden:
            print(f"REFUSED: {f.note}", file=sys.stderr)

    if findings and all(f.verdict == VERDICT_BASELINE for f in findings):
        args.out_dir.mkdir(parents=True, exist_ok=True)
        out_te = existing_te if existing_te.endswith("\n") else existing_te + "\n"
        out_fc = existing_fc if existing_fc.endswith("\n") else existing_fc + "\n"
        (args.out_dir / f"{app_name}.te").write_text(out_te, encoding="utf-8")
        (args.out_dir / f"{app_name}.fc").write_text(out_fc, encoding="utf-8")
        write_findings_artifact(
            args.out_dir,
            findings,
            artifact_ctx,
            generation_blocked=False,
            vendor_override=vendor_override,
        )
        print("No change")
        return 0

    emit_degraded_warning(findings)

    drift_notes = [f for f in findings if f.verdict == VERDICT_FC_DRIFT]
    if drift_notes:
        print("\nLABELING DRIFT (restorecon — no .fc / .te change):", file=sys.stderr)
        for f in drift_notes:
            print(f"  {f.note}", file=sys.stderr)

    boolean_notes = [f for f in findings if f.verdict == VERDICT_BOOLEAN]
    if boolean_notes:
        print("\nBOOLEAN TRIAGE (setsebool — no permanent .te allow):", file=sys.stderr)
        for f in boolean_notes:
            print(f"  {f.rendered}  # {f.note}", file=sys.stderr)

    version_file = version_file
    if args.bump_version:
        major, minor, patch = parse_version(read_policy_version(version_file))
        new_version = format_version(major, minor, patch + 1)
    else:
        new_version = read_policy_version(version_file)
        m = POLICY_MODULE_RE.search(existing_te)
        if m:
            new_version = m.group(2)

    fragment = render_fragment(findings, meta)
    fc_candidates = sorted({f.rendered for f in findings if f.verdict == VERDICT_FC and f.rendered})
    path_hints: dict[str, str] = {}
    for f in findings:
        if f.verdict == VERDICT_FC and f.rendered and f.paths:
            path_hints[f.rendered] = f.paths[0]

    args.out_dir.mkdir(parents=True, exist_ok=True)
    out_te = merge_te(existing_te, app_name, new_version, fragment)
    out_fc = merge_fc(existing_fc, list(fc_candidates), path_hints)
    fc_fixes, _fc_dropped = filter_fc_fix_lines(existing_fc, list(fc_candidates), path_hints)

    (args.out_dir / f"{app_name}.te").write_text(out_te, encoding="utf-8")
    (args.out_dir / f"{app_name}.fc").write_text(out_fc, encoding="utf-8")
    write_findings_artifact(
        args.out_dir,
        findings,
        artifact_ctx,
        generation_blocked=False,
        vendor_override=vendor_override,
    )
    (args.out_dir / "pr_summary.md").write_text(
        write_pr_summary(findings, app_name, meta),
        encoding="utf-8",
    )
    if args.bump_version:
        (args.out_dir / "policy_version.txt").write_text(new_version + "\n", encoding="utf-8")

    if fc_fixes:
        print("\nLABELING FIXES (.fc — restorecon, do not grant generic types):")
        for line in fc_fixes:
            print(f"  {line}")

    print(f"\nWrote {args.out_dir}/{app_name}.{{te,fc}} ({len(findings)} net-new denial(s) classified)")
    return 0


def main() -> int:
    project_root = Path(__file__).resolve().parent.parent
    parser = argparse.ArgumentParser(description="Deterministic AVC → policy generator")
    parser.add_argument("--avc-log", type=Path, required=True)
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--existing-te", type=Path, default=None)
    parser.add_argument("--existing-fc", type=Path, default=None)
    parser.add_argument("--out-dir", type=Path, default=Path("policy_out"))
    parser.add_argument(
        "--app-name",
        default=None,
        help="Deprecated: app identity comes from --manifest only",
    )
    parser.add_argument("--bump-version", action="store_true")
    parser.add_argument(
        "--version-file",
        type=Path,
        default=None,
        help="SemVer SSOT (default: policy_version.txt beside module from manifest)",
    )
    parser.add_argument("--explain", action="store_true")
    parser.add_argument(
        "--allow-degraded",
        action="store_true",
        help="When sepolgen is missing, emit raw allows on base types (engine=degraded in findings)",
    )
    parser.add_argument(
        "--allow-needs-review",
        action="store_true",
        help="Write needs_review allows into the .te (domain-weakening; confirm the AVC first)",
    )
    parser.add_argument(
        "--allow-needs-review-perm",
        action="append",
        default=[],
        metavar="PERM",
        help="Opt in a single needs_review permission (repeatable), e.g. execmem",
    )
    parser.add_argument(
        "--policy-kern",
        type=Path,
        default=None,
        help="Path to policy.kern for boolean lookup (default: active targeted policy or POLICY_KERN)",
    )
    parser.add_argument(
        "--boolean-hints",
        type=Path,
        default=Path(__file__).resolve().parent.parent / "config" / "boolean_hints.yml",
        help="Curated boolean overrides (consulted before sesearch policy query)",
    )
    parser.add_argument(
        "--vendor-override",
        type=Path,
        default=None,
        help="JSON from vendor_policy_preflight --force \"reason\" (recorded in findings.json)",
    )
    args = parser.parse_args()
    return run(args)


if __name__ == "__main__":
    raise SystemExit(main())
