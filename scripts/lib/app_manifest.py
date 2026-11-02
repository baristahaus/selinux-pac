#!/usr/bin/env python3
"""Load and validate per-app manifest YAML for deploy/readiness scripts."""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path
from typing import Any

try:
    import yaml
except ImportError:  # pragma: no cover - CI installs pyyaml
    yaml = None  # type: ignore


REQUIRED_TOP = ("app_name", "domain")
REQUIRED_PATHS = ("install_root", "var_dir")


def _deep_get(data: dict[str, Any], *keys: str, default: Any = None) -> Any:
    cur: Any = data
    for key in keys:
        if not isinstance(cur, dict) or key not in cur:
            return default
        cur = cur[key]
    return cur


def default_manifest_path(project_root: Path, app_name: str) -> Path:
    return project_root / "config" / f"{app_name}.manifest.yml"


def resolve_manifest_path(
    explicit: str | None = None,
    *,
    project_root: Path | None = None,
    app_name: str | None = None,
) -> Path | None:
    if explicit:
        path = Path(explicit)
        return path if path.is_file() else None
    root = project_root or Path(__file__).resolve().parents[2]
    if app_name:
        candidate = default_manifest_path(root, app_name)
        return candidate if candidate.is_file() else None
    return None


def load_raw(path: Path) -> dict[str, Any]:
    if yaml is None:
        raise RuntimeError("PyYAML required: pip install pyyaml")
    data = yaml.safe_load(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise ValueError(f"{path}: manifest root must be a mapping")
    return data


def normalize(raw: dict[str, Any]) -> dict[str, Any]:
    app_name = str(raw["app_name"]).strip()
    domain = str(raw["domain"]).strip()
    paths_in = raw.get("paths") or {}
    if not isinstance(paths_in, dict):
        raise ValueError("paths must be a mapping")

    install_root = paths_in.get("install_root", f"/opt/{app_name}")
    var_dir = paths_in.get("var_dir", f"/var/lib/{app_name}")
    log_dir = paths_in.get("log_dir", f"/var/log/{app_name}")
    runtime_dir = paths_in.get("runtime_dir", f"/run/{app_name}")
    var_opt_dir = paths_in.get("var_opt_dir")
    extras_in = paths_in.get("extra_fc_roots") or []
    if isinstance(extras_in, str):
        extras_in = [extras_in]
    extra_fc_roots = [str(x) for x in extras_in if x]

    services_in = raw.get("services") or {}
    if not isinstance(services_in, dict):
        raise ValueError("services must be a mapping")
    primary = services_in.get("primary") or {}
    if not isinstance(primary, dict):
        raise ValueError("services.primary must be a mapping")
    primary_unit = primary.get("unit", f"{app_name}.service")
    primary_domain = primary.get("domain", domain)

    backend_block = services_in.get("backend")
    backend: dict[str, Any] | None = None
    if backend_block:
        if not isinstance(backend_block, dict):
            raise ValueError("services.backend must be a mapping")
        backend = {
            "unit": backend_block.get("unit", f"{app_name}-backend.service"),
            "domain": backend_block.get("domain", f"{app_name}_backend_t"),
        }

    http_in = raw.get("http") or {}
    if not isinstance(http_in, dict):
        raise ValueError("http must be a mapping")
    http_host = http_in.get("host", "127.0.0.1")
    http_port = int(http_in.get("port", 8080))
    endpoints_raw = http_in.get("endpoints") or ["/"]
    if not isinstance(endpoints_raw, list) or not endpoints_raw:
        raise ValueError("http.endpoints must be a non-empty list")
    endpoints = [str(p if isinstance(p, str) else p.get("path")) for p in endpoints_raw]

    backend_http: dict[str, Any] | None = None
    if backend and http_in.get("backend"):
        bh = http_in["backend"]
        if not isinstance(bh, dict):
            raise ValueError("http.backend must be a mapping")
        backend_http = {
            "port": int(bh.get("port", 8081)),
            "health_path": str(bh.get("health_path", "/health")),
        }
    elif backend:
        backend_http = {"port": 8081, "health_path": "/health"}

    deploy_in = raw.get("deploy") or {}
    ops_dir = f"/var/lib/selinux-policy-ops/{app_name}"
    soak_marker = deploy_in.get("soak_marker_file", f"{ops_dir}/selinux_canary_deployed_at")
    deploy_report = deploy_in.get("deploy_report_file", f"{ops_dir}/selinux_deploy_report.json")

    policy_in = raw.get("policy") or {}
    module_dir = policy_in.get("module_dir", "selinux")

    return {
        "app_name": app_name,
        "domain": domain,
        "paths": {
            "install_root": str(install_root),
            "var_dir": str(var_dir),
            "log_dir": str(log_dir),
            "runtime_dir": str(runtime_dir),
            **({"var_opt_dir": str(var_opt_dir)} if var_opt_dir else {}),
            **({"extra_fc_roots": extra_fc_roots} if extra_fc_roots else {}),
        },
        "services": {
            "primary": {"unit": str(primary_unit), "domain": str(primary_domain)},
            "backend": backend,
        },
        "http": {
            "host": str(http_host),
            "port": http_port,
            "endpoints": endpoints,
            "backend": backend_http,
        },
        "selinux_ports": raw.get("selinux_ports") or [],
        "selinux_booleans": raw.get("selinux_booleans") or [],
        "selinux_exceptions": raw.get("selinux_exceptions") or {},
        "soak": {"ignore": _normalize_soak_ignore(raw.get("soak"))},
        "policy": {"module_dir": str(module_dir), "service_name": str(primary_unit)},
        "deploy": {
            "soak_marker_file": str(soak_marker),
            "deploy_report_file": str(deploy_report),
        },
    }


def port_types_declared(te_text: str) -> set[str]:
    """Port types this module declares (`type name_port_t;`)."""
    return set(re.findall(r"^\s*type\s+(\w+_port_t)\s*;", te_text, re.MULTILINE))


def module_te_for_manifest(manifest_path: Path, manifest: dict[str, Any]) -> Path | None:
    """Repo manifests live in config/ next to selinux/. Installed copies may not."""
    if manifest_path.parent.name != "config":
        return None
    rel = manifest["policy"]["module_dir"]
    te = manifest_path.parent.parent / rel / f"{manifest['app_name']}.te"
    return te if te.is_file() else None


def validate_selinux_ports(ports: Any, declared: set[str] | None) -> list[str]:
    """Ports are 1024–65535 unless allow_privileged, and the type is this module's."""
    errors: list[str] = []
    if not isinstance(ports, list):
        return ["selinux_ports must be a list"]
    for index, entry in enumerate(ports):
        label = f"selinux_ports[{index}]"
        if not isinstance(entry, dict):
            errors.append(f"{label} must be a mapping")
            continue
        try:
            port = int(entry["port"])
        except (KeyError, TypeError, ValueError):
            errors.append(f"{label} needs an integer port")
            continue
        if port < 1 or port > 65535:
            errors.append(f"{label} port {port} is outside 1-65535")
        elif port < 1024 and not entry.get("allow_privileged"):
            errors.append(
                f"{label} port {port} is below 1024; set allow_privileged: true to keep it"
            )
        ptype = str(entry.get("type") or "")
        if not ptype.endswith("_port_t"):
            errors.append(f"{label} type {ptype!r} is not a port type")
        elif declared is not None and ptype not in declared:
            errors.append(f"{label} type {ptype} is not declared by this module")
    return errors


# Ranges such as unreserved_port_t are not an application assignment.
# semanage port -a carves a port out of those ranges. A named type is a conflict.
GENERIC_PORT_ASSIGNMENTS = frozenset(
    {"unreserved_port_t", "port_t", "reserved_port_t", "ephemeral_port_t"}
)


def classify_port_assignment(listing: str, port: int, proto: str, want_type: str) -> str:
    """Return 'add' or 'present'. Raise if another application type already owns the port.

    Generic ranges are not ownership. The caller adds with semanage port -a and
    does not fall back to semanage port -m.
    """
    proto = proto.lower()
    owners: list[str] = []
    for raw in listing.splitlines():
        line = raw.strip()
        if not line or line.lower().startswith("selinux "):
            continue
        parts = line.split()
        if len(parts) < 3:
            continue
        type_name, line_proto = parts[0], parts[1].lower()
        if line_proto != proto:
            continue
        numbers: list[int] = []
        for token in " ".join(parts[2:]).replace(",", " ").split():
            if token.isdigit():
                numbers.append(int(token))
                continue
            if "-" in token:
                left, right = token.split("-", 1)
                if left.isdigit() and right.isdigit():
                    numbers.extend(range(int(left), int(right) + 1))
        if port in numbers and type_name not in GENERIC_PORT_ASSIGNMENTS:
            owners.append(type_name)
    if not owners:
        return "add"
    if set(owners) == {want_type}:
        return "present"
    raise ValueError(
        f"port {port}/{proto} is already assigned to {', '.join(owners)}, not {want_type}. "
        "Refusing to run semanage port -m."
    )


# Reviewed exceptions to the house rules. Keep in sync with
# cli/policy_rules.py MANIFEST_EXCEPTION_KEYS.
SELINUX_EXCEPTION_KEYS = frozenset({"exec_bin"})


def validate_selinux_exceptions(exceptions: Any) -> list[str]:
    """Each key is a known exception. Each value is the reviewer's written reason."""
    if exceptions is None or exceptions == {}:
        return []
    if not isinstance(exceptions, dict):
        return ["selinux_exceptions must be a mapping of exception name to reason"]
    errors: list[str] = []
    for key, reason in exceptions.items():
        if key not in SELINUX_EXCEPTION_KEYS:
            errors.append(
                f"selinux_exceptions.{key} is not a known exception "
                f"(known: {', '.join(sorted(SELINUX_EXCEPTION_KEYS))})"
            )
            continue
        if not isinstance(reason, str) or len(reason.strip()) < 20:
            errors.append(
                f"selinux_exceptions.{key} needs a written reason (at least 20 characters)"
            )
    return errors


def manifest_exception_reason(path: Path, key: str) -> str:
    """Reason for one exception, read without the rest of the schema. '' when absent."""
    raw = load_raw(path)
    exceptions = raw.get("selinux_exceptions")
    errors = validate_selinux_exceptions(exceptions)
    if errors:
        raise ValueError(f"{path}: " + "; ".join(errors))
    reason = (exceptions or {}).get(key)
    return reason.strip() if isinstance(reason, str) else ""


def validate_selinux_booleans(booleans: Any, domain: str) -> list[str]:
    """Optional persistent booleans. Names are identifiers, not free text.

    tomcat_can_network_connect is not a tunable in RHEL 9 tomcat.te
    (the connect tunable is tomcat_can_network_connect_db).
    httpd_can_network_connect belongs to the apache module; do not set it
    on tomcat_t or a JWS tomcat domain.
    """
    if booleans is None:
        return []
    if not isinstance(booleans, list):
        return ["selinux_booleans must be a list"]
    errors: list[str] = []
    tomcat_domain = domain == "tomcat_t" or domain.endswith("_tomcat_t")
    for index, entry in enumerate(booleans):
        label = f"selinux_booleans[{index}]"
        if not isinstance(entry, dict):
            errors.append(f"{label} must be a mapping")
            continue
        name = str(entry.get("name") or "")
        if re.match(r"[A-Za-z_][A-Za-z0-9_]*\Z", name) is None:
            errors.append(f"{label} name {name!r} is not a boolean identifier")
        if name == "tomcat_can_network_connect":
            errors.append(
                f"{label} tomcat_can_network_connect is not a tunable in RHEL 9 tomcat.te"
            )
        if name == "httpd_can_network_connect" and tomcat_domain:
            errors.append(
                f"{label} httpd_can_network_connect is an apache boolean; do not set it for {domain}"
            )
        if "state" not in entry or not isinstance(entry["state"], bool):
            errors.append(f"{label} state must be true or false")
        if "persistent" in entry and not isinstance(entry["persistent"], bool):
            errors.append(f"{label} persistent must be true or false")
    return errors


def _normalize_soak_ignore(soak: Any) -> list[dict[str, str]]:
    if soak is None:
        return []
    if not isinstance(soak, dict):
        return []
    ignore = soak.get("ignore") or []
    if not isinstance(ignore, list):
        return []
    rows: list[dict[str, str]] = []
    for entry in ignore:
        if not isinstance(entry, dict):
            rows.append({"tclass": "", "target_type": ""})
            continue
        rows.append(
            {
                "tclass": str(entry.get("tclass") or ""),
                "target_type": str(entry.get("target_type") or ""),
            }
        )
    return rows


def _selinux_identifier(value: str) -> bool:
    return re.match(r"[A-Za-z_][A-Za-z0-9_]*\Z", value) is not None


def validate_soak_ignore(ignore: Any) -> list[str]:
    """soak.ignore entries are tclass plus target type. Empty means ignore nothing."""
    errors: list[str] = []
    if not isinstance(ignore, list):
        return ["soak.ignore must be a list"]
    for index, entry in enumerate(ignore):
        label = f"soak.ignore[{index}]"
        if not isinstance(entry, dict):
            errors.append(f"{label} must be a mapping")
            continue
        tclass = str(entry.get("tclass") or "")
        target = str(entry.get("target_type") or "")
        if not _selinux_identifier(tclass):
            errors.append(f"{label} tclass {tclass!r} is not an SELinux class name")
        if not _selinux_identifier(target):
            errors.append(f"{label} target_type {target!r} is not an SELinux type")
    return errors


def soak_ignore_csv(manifest: dict[str, Any]) -> str:
    parts = [
        f"{row['tclass']}:{row['target_type']}"
        for row in manifest.get("soak", {}).get("ignore", [])
    ]
    return ",".join(parts)


def validate_normalized(manifest: dict[str, Any]) -> list[str]:
    errors: list[str] = []
    for key in REQUIRED_TOP:
        if not manifest.get(key):
            errors.append(f"missing required field: {key}")
    for key in REQUIRED_PATHS:
        if not manifest["paths"].get(key):
            errors.append(f"missing paths.{key}")
    if not manifest["services"]["primary"].get("unit"):
        errors.append("missing services.primary.unit")
    if not manifest["http"]["endpoints"]:
        errors.append("http.endpoints must not be empty")
    backend = manifest["services"].get("backend")
    if backend and not manifest["http"].get("backend"):
        errors.append("services.backend defined but http.backend missing")
    return errors


def load_manifest(path: Path) -> dict[str, Any]:
    raw = load_raw(path)
    manifest = normalize(raw)
    errors = validate_normalized(manifest)
    te = module_te_for_manifest(path, manifest)
    declared = port_types_declared(te.read_text(encoding="utf-8")) if te else None
    errors.extend(validate_selinux_ports(manifest["selinux_ports"], declared))
    errors.extend(validate_selinux_booleans(manifest["selinux_booleans"], str(manifest["domain"])))
    errors.extend(validate_selinux_exceptions(raw.get("selinux_exceptions")))
    soak_raw = raw.get("soak")
    if soak_raw is not None and not isinstance(soak_raw, dict):
        errors.append("soak must be a mapping")
    elif isinstance(soak_raw, dict) and "ignore" in soak_raw and not isinstance(soak_raw.get("ignore"), list):
        errors.append("soak.ignore must be a list")
    else:
        errors.extend(validate_soak_ignore(manifest["soak"]["ignore"]))
    if errors:
        raise ValueError(f"{path}: " + "; ".join(errors))
    return manifest


def policy_source_paths(project_root: Path, manifest: dict[str, Any]) -> dict[str, Path]:
    """Resolve .te / .fc / policy_version.txt from manifest policy.module_dir."""
    app_name = manifest["app_name"]
    rel = manifest["policy"]["module_dir"]
    mod_dir = Path(rel)
    if not mod_dir.is_absolute():
        mod_dir = (project_root / mod_dir).resolve()
    te = mod_dir / f"{app_name}.te"
    fc = mod_dir / f"{app_name}.fc"
    version_file = mod_dir / "policy_version.txt"
    if not version_file.is_file():
        legacy = (project_root / "selinux" / "policy_version.txt").resolve()
        if legacy.is_file():
            version_file = legacy
    return {
        "module_dir": mod_dir,
        "te": te,
        "fc": fc,
        "version_file": version_file,
    }


def manifest_paths_csv(manifest: dict[str, Any]) -> str:
    """Comma-separated path substrings for AVC filtering (manifest paths only)."""
    paths = manifest["paths"]
    order = ("install_root", "var_dir", "log_dir", "runtime_dir", "var_opt_dir")
    parts = [str(paths[k]) for k in order if paths.get(k)]
    extras = paths.get("extra_fc_roots") or []
    if isinstance(extras, str):
        extras = [extras]
    parts.extend(str(x) for x in extras if x)
    if not parts:
        raise ValueError("manifest paths yield no AVC path filters")
    return ",".join(parts)


def manifest_service_domains_csv(manifest: dict[str, Any]) -> str:
    """Comma-separated process domains for sesearch / blast-radius collection."""
    domains: set[str] = set()
    for _role, _unit, domain in service_units_ordered(manifest):
        domains.add(str(domain))
    top = manifest.get("domain")
    if top:
        domains.add(str(top))
    if not domains:
        raise ValueError("manifest has no service domains")
    return ",".join(sorted(domains))


def service_units_ordered(manifest: dict[str, Any]) -> list[tuple[str, str, str]]:
    """Return list of (role, unit, domain) — backend before primary when present."""
    items: list[tuple[str, str, str]] = []
    backend = manifest["services"].get("backend")
    if backend:
        items.append(("backend", backend["unit"], backend["domain"]))
    primary = manifest["services"]["primary"]
    items.append(("primary", primary["unit"], primary["domain"]))
    return items


def shell_export(
    manifest: dict[str, Any],
    *,
    project_root: Path | None = None,
) -> str:
    primary = manifest["services"]["primary"]
    backend = manifest["services"].get("backend")
    lines = [
        f"APP_NAME={json.dumps(manifest['app_name'])}",
        f"APP_DOMAIN={json.dumps(manifest['domain'])}",
        f"PRIMARY_DOMAIN={json.dumps(primary['domain'])}",
        f"PATHS_CSV={json.dumps(manifest_paths_csv(manifest))}",
        f"SOAK_IGNORE_CSV={json.dumps(soak_ignore_csv(manifest))}",
        f"PRIMARY_SERVICE={json.dumps(primary['unit'])}",
        f"HTTP_HOST={json.dumps(manifest['http']['host'])}",
        f"HTTP_PORT={manifest['http']['port']}",
        f"ENDPOINT_PATHS={json.dumps(json.dumps(manifest['http']['endpoints']))}",
    ]

    # Identity keys (phase 2): every script gets these from one source.
    app_name = manifest["app_name"]
    lines.append(f"MODULE_NAME={json.dumps(app_name)}")
    lines.append(f"DOMAINS_CSV={json.dumps(manifest_service_domains_csv(manifest))}")

    ports_parts: list[str] = []
    for entry in manifest.get("selinux_ports") or []:
        ports_parts.append(f"{entry['port']}/{entry.get('proto', 'tcp')}/{entry['type']}")
    lines.append(f"SELINUX_PORTS_CSV={json.dumps(','.join(ports_parts))}")

    if project_root is not None:
        paths = policy_source_paths(project_root, manifest)
        lines.append(f"MODULE_DIR={json.dumps(str(paths['module_dir']))}")
        lines.append(f"POLICY_TE={json.dumps(str(paths['te']))}")
        lines.append(f"POLICY_FC={json.dumps(str(paths['fc']))}")
        lines.append(f"POLICY_PP={json.dumps(str(paths['module_dir'] / f'{app_name}.pp'))}")
        lines.append(f"POLICY_VERSION_FILE={json.dumps(str(paths['version_file']))}")

    if backend:
        lines.append(f"BACKEND_SERVICE={json.dumps(backend['unit'])}")
        lines.append(f"BACKEND_DOMAIN={json.dumps(backend['domain'])}")
        bh = manifest["http"].get("backend") or {}
        lines.append(f"BACKEND_HTTP_PORT={bh.get('port', 8081)}")
        lines.append(f"BACKEND_HEALTH_PATH={json.dumps(bh.get('health_path', '/health'))}")
        lines.append("HAS_BACKEND=1")
    else:
        lines.append("BACKEND_DOMAIN=")
        lines.append("HAS_BACKEND=0")
    return "\n".join(lines)


def domain_context_matches(endpoint_data: dict[str, Any], manifest: dict[str, Any]) -> bool:
    ctx = endpoint_data.get("domain_context") or {}
    for _role, unit, domain in service_units_ordered(manifest):
        if ctx.get(unit) != domain:
            return False
    return True


def service_roles(manifest: dict[str, Any]) -> list[tuple[str, str]]:
    """Return (role_name, unit) for deploy report service status."""
    items: list[tuple[str, str]] = []
    backend = manifest["services"].get("backend")
    if backend:
        items.append(("backend", backend["unit"]))
    primary = manifest["services"]["primary"]
    items.append(("primary", primary["unit"]))
    return items


def main() -> int:
    parser = argparse.ArgumentParser(description="App manifest loader")
    parser.add_argument(
        "command",
        choices=(
            "json",
            "validate",
            "shell-export",
            "resolve",
            "check-domain-context",
            "paths-csv",
            "domains-csv",
            "check-port",
            "exception",
        ),
    )
    parser.add_argument("--key", default="", help="exception name for the exception command")
    parser.add_argument("--port", type=int, default=None)
    parser.add_argument("--proto", default="tcp")
    parser.add_argument("--type", dest="port_type", default="")
    parser.add_argument("path", nargs="?", help="Manifest YAML path or endpoint JSON for check-domain-context")
    parser.add_argument("endpoint_json", nargs="?", help="Endpoint JSON path for check-domain-context")
    parser.add_argument("--app-name", default=None)
    args = parser.parse_args()

    if args.command == "check-port":
        if args.port is None or not args.port_type:
            print("usage: check-port --port N --proto tcp --type TYPE", file=sys.stderr)
            return 2
        listing = sys.stdin.read()
        try:
            print(classify_port_assignment(listing, args.port, args.proto, args.port_type))
        except ValueError as exc:
            print(str(exc), file=sys.stderr)
            return 1
        return 0

    if args.command == "exception":
        # Exit 0 and print the reason when the manifest records it. Exit 1 when
        # the manifest or the exception is absent. Exit 2 on a malformed entry.
        if not args.key or not args.path:
            print("usage: exception MANIFEST --key NAME", file=sys.stderr)
            return 2
        manifest_path = Path(args.path)
        if not manifest_path.is_file():
            return 1
        try:
            reason = manifest_exception_reason(manifest_path, args.key)
        except ValueError as exc:
            print(str(exc), file=sys.stderr)
            return 2
        if not reason:
            return 1
        print(reason)
        return 0

    if args.command == "resolve":
        path = resolve_manifest_path(args.path, app_name=args.app_name)
        if path:
            print(path)
            return 0
        return 1

    if args.command == "check-domain-context":
        if not args.path or not args.endpoint_json:
            print("usage: check-domain-context MANIFEST ENDPOINT_JSON", file=sys.stderr)
            return 1
        manifest = load_manifest(Path(args.path))
        endpoint_data = json.loads(Path(args.endpoint_json).read_text(encoding="utf-8"))
        print("yes" if domain_context_matches(endpoint_data, manifest) else "no")
        return 0 if domain_context_matches(endpoint_data, manifest) else 1

    if not args.path:
        path = resolve_manifest_path(app_name=args.app_name)
        if not path:
            print("No manifest found", file=sys.stderr)
            return 1
    else:
        path = Path(args.path)

    if args.command == "validate":
        try:
            load_manifest(path)
        except (ValueError, OSError, RuntimeError) as exc:
            print(str(exc), file=sys.stderr)
            return 1
        print(f"OK {path}")
        return 0

    manifest = load_manifest(path)
    if args.command == "json":
        print(json.dumps(manifest, indent=2))
        return 0
    if args.command == "shell-export":
        root = path.parent.parent if path.parent.name == "config" else Path.cwd()
        print(shell_export(manifest, project_root=root))
        return 0
    if args.command == "paths-csv":
        print(manifest_paths_csv(manifest))
        return 0
    if args.command == "domains-csv":
        print(manifest_service_domains_csv(manifest))
        return 0
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
