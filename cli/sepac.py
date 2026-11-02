#!/usr/bin/env python3
"""sepac — SELinux policy as code for RHEL admins.

One command for the whole policy lifecycle: decide whether to write policy
(triage), collect evidence (capture, denials), write it (generate), gate it
(check), try it on QA (load, status), and ship it (build, canary, soak,
enforce, rollback). The scripts under scripts/ and the Ansible playbooks are
the engine; admins use sepac.

Python 3.9 (RHEL 9 python3). No new dependencies.
"""
from __future__ import annotations

import argparse
import configparser
import hashlib
import json
import os
import re
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any, List, Optional, Sequence

# ── Tool tree (code: cli/, scripts/) ─────────────────────────────────────────

_SELF = Path(__file__).resolve()
# When installed: /usr/share/selinux-pac/cli/sepac.py → tool tree = /usr/share/selinux-pac
# In a checkout: cli/sepac.py → tool tree = the repo root
TOOL_TREE = _SELF.parent.parent
SCRIPTS = TOOL_TREE / "scripts"

# ── Policy tree (config/, selinux/, ansible/) ─────────────────────────────────

_SEPAC_CONF = Path(os.environ.get("SEPAC_CONF", "/etc/selinux-pac/sepac.conf"))


def _read_conf_tree() -> str:
    """Read tree= from /etc/selinux-pac/sepac.conf."""
    if not _SEPAC_CONF.is_file():
        return ""
    cp = configparser.ConfigParser()
    try:
        with open(_SEPAC_CONF, encoding="utf-8") as fh:
            # sepac.conf has no section headers; inject one
            cp.read_string("[sepac]\n" + fh.read())
        return cp.get("sepac", "tree", fallback="").strip()
    except (configparser.Error, OSError):
        return ""


def _git_toplevel(d: Path) -> str:
    """Return git top-level of *d*, or '' on failure."""
    try:
        r = subprocess.run(
            ["git", "rev-parse", "--show-toplevel"],
            cwd=str(d),
            capture_output=True,
            text=True,
        )
        return r.stdout.strip() if r.returncode == 0 else ""
    except (FileNotFoundError, OSError):
        return ""


def _is_policy_tree(d: str) -> bool:
    p = Path(d)
    return (p / "config").is_dir() and (p / "selinux").is_dir()


def resolve_policy_tree(cli_tree: str | None) -> Path | None:
    """Resolve the policy tree. Returns None when no policy tree is found."""
    # 1. --tree DIR
    if cli_tree:
        p = Path(cli_tree)
        if _is_policy_tree(str(p)):
            return p
        return None
    # 2. git top-level of cwd, if it has config/ and selinux/
    top = _git_toplevel(Path.cwd())
    if top and _is_policy_tree(top):
        return Path(top)
    # 3. tree= in sepac.conf
    conf_tree = _read_conf_tree()
    if conf_tree and _is_policy_tree(conf_tree):
        return Path(conf_tree)
    return None


# These are resolved lazily, after argument parsing
POLICY_TREE: Path | None = None
# Backward compatibility: REPO_ROOT still works for commands in a checkout
REPO_ROOT = TOOL_TREE


def _require_policy_tree(args: argparse.Namespace) -> Path:
    """Return the policy tree or exit."""
    global POLICY_TREE
    if POLICY_TREE is None:
        POLICY_TREE = resolve_policy_tree(getattr(args, "tree", None))
    if POLICY_TREE is None:
        print(
            "No policy tree found (need config/ and selinux/).\n"
            "Run from a selinux-pac checkout, pass --tree DIR, or set tree= in "
            f"{_SEPAC_CONF}",
            file=sys.stderr,
        )
        raise SystemExit(2)
    return POLICY_TREE


def _init_trees(args: argparse.Namespace) -> None:
    """Resolve policy tree and update globals. Called once from main()."""
    global POLICY_TREE, REPO_ROOT, ANSIBLE
    POLICY_TREE = resolve_policy_tree(getattr(args, "tree", None))
    if POLICY_TREE is not None:
        REPO_ROOT = POLICY_TREE
    ANSIBLE = REPO_ROOT / "ansible"

# ── Manifest helper (reuse existing code) ────────────────────────────────────

sys.path.insert(0, str(SCRIPTS / "lib"))
from app_manifest import (  # noqa: E402
    classify_port_assignment,
    load_manifest,
    policy_source_paths,
)

# ── Constants ────────────────────────────────────────────────────────────────

APP_RE = re.compile(r"^[a-z][a-z0-9_]{0,40}$")
PERM_RE = re.compile(r"^[a-z_]+$")
ROLE_FILE = os.environ.get("SEPAC_ROLE_FILE", "/etc/selinux-pac/role")
ANSIBLE = TOOL_TREE / "ansible"  # updated by _init_trees()


# ── Version ──────────────────────────────────────────────────────────────────

def _sepac_version() -> str:
    """RPM version when installed, git describe in a checkout."""
    try:
        r = subprocess.run(
            ["rpm", "-q", "--qf", "%{VERSION}-%{RELEASE}", "selinux-pac"],
            capture_output=True, text=True,
        )
        if r.returncode == 0 and r.stdout and "not installed" not in r.stdout:
            return r.stdout.strip()
    except FileNotFoundError:
        pass
    try:
        r = subprocess.run(
            ["git", "describe", "--tags", "--always", "--dirty"],
            cwd=str(TOOL_TREE),
            capture_output=True, text=True,
        )
        if r.returncode == 0 and r.stdout.strip():
            return r.stdout.strip()
    except (FileNotFoundError, OSError):
        pass
    return "unknown"

DIM = "\033[2m"
NC = "\033[0m"

# Triage advice lines keyed by situation.
TRIAGE_ADVICE = {
    "none": "No Red Hat policy for {app}. Write one: sepac generate {app}",
    "loaded": "Red Hat policy confines {app}. Tune it, do not write a module: sepac tune {app}",
    "loaded_unconfined": (
        "Red Hat module loaded, but {domain} is unconfined. "
        "Install the vendor's confining package. Generate only with --force \"reason\"."
    ),
    "package_installed": "Vendor SELinux package {pkg} is installed but not loaded. Enable it first.",
    "package_available": "Vendor SELinux package {pkg} is available. Install it first.",
    "base_policy": "Base policy covers {app}. Tune it: sepac tune {app}",
    "unconfined": "{app} runs unconfined ({domain}). Install the vendor package first.",
}


# ── Utilities ────────────────────────────────────────────────────────────────

def _validate_app(app: str) -> None:
    if not APP_RE.match(app):
        print(f"Invalid app name: {app!r} (must match {APP_RE.pattern})", file=sys.stderr)
        raise SystemExit(2)


def _validate_perm(perm: str) -> None:
    if not PERM_RE.match(perm):
        print(f"Invalid permission: {perm!r} (must match {PERM_RE.pattern})", file=sys.stderr)
        raise SystemExit(2)


def _validate_env(env: str) -> Path:
    inv = ANSIBLE / f"inventory.{env}.yml"
    if not inv.is_file():
        print(
            f"No inventory for --env {env} (looked for {inv}).\n"
            f"Create it: bash lab/setup_rhel_hosts.sh write --qa-host … --prod-host …",
            file=sys.stderr,
        )
        raise SystemExit(2)
    return inv


def _manifest_path(app: str, manifest_flag: str | None = None) -> Path:
    """Manifest lookup order: --manifest PATH → policy tree config/ → /etc/selinux-pac/apps/."""
    if manifest_flag:
        return Path(manifest_flag)
    if POLICY_TREE is not None:
        p = POLICY_TREE / "config" / f"{app}.manifest.yml"
        if p.is_file():
            return p
    etc = Path(f"/etc/selinux-pac/apps/{app}.manifest.yml")
    if etc.is_file():
        return etc
    # Return the policy-tree path even if it doesn't exist (for error messages)
    if POLICY_TREE is not None:
        return POLICY_TREE / "config" / f"{app}.manifest.yml"
    return Path(f"/etc/selinux-pac/apps/{app}.manifest.yml")


def _load_app_manifest(app: str, manifest_flag: str | None = None) -> dict[str, Any]:
    p = _manifest_path(app, manifest_flag)
    if not p.is_file():
        print(f"No manifest: {p}", file=sys.stderr)
        raise SystemExit(2)
    return load_manifest(p)


def _require_manifest(app: str, manifest_flag: str | None = None) -> dict[str, Any]:
    """For commands that strictly need a manifest (generate, check, load, status)."""
    return _load_app_manifest(app, manifest_flag)


def _app_domain(app: str, manifest: dict[str, Any] | None) -> str:
    if manifest:
        return str(manifest["domain"])
    return f"{app}_t"


def _app_unit(app: str, manifest: dict[str, Any] | None, override: str | None) -> str:
    if override:
        return override
    if manifest:
        return str(manifest["services"]["primary"]["unit"])
    return f"{app}.service"


def _module_dir(manifest: dict[str, Any]) -> Path:
    paths = policy_source_paths(REPO_ROOT, manifest)
    return paths["module_dir"]


def _need_sudo() -> bool:
    return os.geteuid() != 0


def _sudo_prefix() -> list[str]:
    return ["sudo"] if _need_sudo() else []


def _run(
    argv: list[str],
    *,
    dry_run: bool = False,
    verbose: bool = False,
    env: dict[str, str] | None = None,
    check: bool = False,
    capture: bool = False,
) -> subprocess.CompletedProcess[str]:
    if dry_run:
        print(" ".join(argv))
        return subprocess.CompletedProcess(argv, 0, "", "")
    if verbose:
        print(f"{DIM}{' '.join(argv)}{NC}", file=sys.stderr)
    run_env: dict[str, str] | None = None
    if env:
        run_env = dict(os.environ)
        run_env.update(env)
    return subprocess.run(
        argv,
        env=run_env,
        check=check,
        capture_output=capture,
        text=True,
    )


# ── Load guardrail (section 4) ──────────────────────────────────────────────

def _check_qa_role() -> None:
    """Refuse load on hosts whose role is not qa or dev."""
    role_file = Path(ROLE_FILE)
    if not role_file.is_file():
        print(
            "This host's role is not qa. Production gets policy from the signed RPM "
            "(sepac canary). On a QA host: echo qa | sudo tee /etc/selinux-pac/role",
            file=sys.stderr,
        )
        raise SystemExit(1)
    role = role_file.read_text(encoding="utf-8").strip().lower()
    if role not in ("qa", "dev"):
        print(
            f"This host's role is {role!r}, not qa. Production gets policy from the signed RPM "
            "(sepac canary). On a QA host: echo qa | sudo tee /etc/selinux-pac/role",
            file=sys.stderr,
        )
        raise SystemExit(1)


def _check_not_production() -> None:
    """Refuse generate/check/load on production hosts."""
    role_file = Path(ROLE_FILE)
    if not role_file.is_file():
        return
    role = role_file.read_text(encoding="utf-8").strip().lower()
    if role == "production":
        print(
            "This host's role is production. generate, check, and load are not "
            "available on production hosts — use sepac canary to deploy from the "
            "signed RPM.",
            file=sys.stderr,
        )
        raise SystemExit(1)


# ── Commands ─────────────────────────────────────────────────────────────────

def cmd_doctor(args: argparse.Namespace) -> int:
    argv = ["bash", str(SCRIPTS / "selinux_pac_adopt.sh"), "doctor"]
    r = _run(argv, dry_run=args.dry_run, verbose=args.verbose)
    return r.returncode


def cmd_triage(args: argparse.Namespace) -> int:
    app = args.app
    _validate_app(app)
    manifest: dict[str, Any] | None = None
    mp = _manifest_path(app, getattr(args, "manifest", None))
    if mp.is_file():
        try:
            manifest = load_manifest(mp)
        except (ValueError, OSError):
            pass
    unit = _app_unit(app, manifest, args.unit)
    domain = _app_domain(app, manifest)

    argv = [
        "bash", str(SCRIPTS / "lib" / "vendor_policy_check.sh"),
        "--report", "--app-name", app, "--unit", unit,
    ]
    r = _run(argv, dry_run=args.dry_run, verbose=args.verbose, capture=not args.dry_run)
    if args.dry_run:
        return 0
    if r.stdout:
        print(r.stdout, end="")
    if r.stderr:
        print(r.stderr, end="", file=sys.stderr)
    # Parse triage line and print advice
    for line in (r.stdout or "").splitlines():
        if "TRIAGE" not in line:
            continue
        fields: dict[str, str] = {}
        for token in line.split():
            if "=" in token:
                k, _, v = token.partition("=")
                fields[k] = v
        situation = fields.get("situation", "")
        tpl = TRIAGE_ADVICE.get(situation)
        if tpl:
            print(tpl.format(
                app=app,
                domain=fields.get("domain", domain),
                pkg=fields.get("package", ""),
            ))
        break
    return r.returncode


def cmd_tune(args: argparse.Namespace) -> int:
    app = args.app
    _validate_app(app)
    manifest: dict[str, Any] | None = None
    mp = _manifest_path(app, getattr(args, "manifest", None))
    if mp.is_file():
        try:
            manifest = load_manifest(mp)
        except (ValueError, OSError):
            pass
    unit = _app_unit(app, manifest, args.unit)
    argv = _sudo_prefix() + [
        "bash", str(SCRIPTS / "dev_generate_policy.sh"),
        "--tune-report", "--app-name", app, "--unit", unit,
        "--app-root", str(REPO_ROOT),
    ]
    r = _run(argv, dry_run=args.dry_run, verbose=args.verbose)
    return r.returncode


# ── AVC helpers ──────────────────────────────────────────────────────────────

_AVC_EPOCH = re.compile(r"msg=audit\((\d+)\.\d+:\d+\)")
_AVC_PERMS = re.compile(r"denied\s+\{\s*([^}]*)\}")
_AVC_FIELD = re.compile(r'\b(scontext|tcontext|tclass|permissive)=(\S+)')
_AVC_PATH = re.compile(r'\b(?:path|name)="([^"]*)"')


def _ctx_type(ctx: str) -> str:
    parts = ctx.split(":")
    return parts[2] if len(parts) >= 3 else ""


def parse_avc(line: str) -> dict[str, Any] | None:
    """Parse one type=AVC line. Returns None for anything else."""
    if "type=AVC" not in line or "denied" not in line:
        return None
    fields = dict(_AVC_FIELD.findall(line))
    m_epoch = _AVC_EPOCH.search(line)
    m_perms = _AVC_PERMS.search(line)
    m_path = _AVC_PATH.search(line)
    return {
        "epoch": int(m_epoch.group(1)) if m_epoch else 0,
        "perms": (m_perms.group(1).split() if m_perms else []),
        "stype": _ctx_type(fields.get("scontext", "")),
        "ttype": _ctx_type(fields.get("tcontext", "")),
        "tclass": fields.get("tclass", ""),
        "permissive": fields.get("permissive", "") == "1",
        "path": m_path.group(1) if m_path else "",
        "raw": line,
    }


def _source_matches(stype: str, domains: list[str], app: str) -> bool:
    """With a manifest: the source type is one of the app's domains.
    Without one: the source type contains the app name (tomcat matches
    tomcat_t and jws6_tomcat_t)."""
    if domains:
        return stype in domains
    return app in stype


def _app_domains(app: str, manifest: dict[str, Any] | None) -> list[str]:
    if not manifest:
        return []
    found = [str(manifest["domain"])]
    backend = (manifest.get("services") or {}).get("backend") or {}
    if backend.get("domain") and backend["domain"] not in found:
        found.append(str(backend["domain"]))
    return found


def _ausearch(since: str) -> list[str]:
    r = subprocess.run(
        _sudo_prefix() + ["ausearch", "-m", "avc", "-ts", since],
        capture_output=True, text=True,
    )
    return (r.stdout or "").splitlines()


def cmd_denials(args: argparse.Namespace) -> int:
    app = args.app
    _validate_app(app)
    manifest: dict[str, Any] | None = None
    mp = _manifest_path(app, getattr(args, "manifest", None))
    if mp.is_file():
        try:
            manifest = load_manifest(mp)
        except (ValueError, OSError):
            pass
    domains = _app_domains(app, manifest)
    label = ", ".join(domains) if domains else f"domains matching '{app}'"
    since = args.since
    last_n = args.last

    ausearch_argv = _sudo_prefix() + ["ausearch", "-m", "avc", "-ts", since]
    if args.dry_run:
        desc = [" ".join(ausearch_argv), f"| keep scontext type {label}"]
        if args.enforced:
            desc.append("| permissive=0 only")
        if args.why:
            desc.append("| audit2why")
        desc.append(f"| last {last_n}")
        print(" ".join(desc))
        return 0

    if args.verbose:
        print(f"{DIM}{' '.join(ausearch_argv)}{NC}", file=sys.stderr)
    kept: list[str] = []
    for line in _ausearch(since):
        avc = parse_avc(line)
        if not avc or not _source_matches(avc["stype"], domains, app):
            continue
        if args.enforced and avc["permissive"]:
            continue
        kept.append(line)

    if not kept:
        print(f"No denials for {label} since {since}")
        return 0

    tail = kept[-last_n:]
    if args.why:
        if args.verbose:
            print(f"{DIM}| audit2why{NC}", file=sys.stderr)
        wp = subprocess.run(["audit2why"], input="\n".join(tail) + "\n",
                            capture_output=True, text=True)
        print(wp.stdout, end="")
        if wp.stderr:
            print(wp.stderr, end="", file=sys.stderr)
    else:
        for line in tail:
            print(line)
    return 0


def cmd_generate(args: argparse.Namespace) -> int:
    _require_policy_tree(args)
    app = args.app
    _validate_app(app)
    if not args.dry_run:
        _check_not_production()
    for perm in (args.approve or []):
        _validate_perm(perm)
    manifest = _require_manifest(app, getattr(args, "manifest", None))

    argv = _sudo_prefix() + [
        "bash", str(SCRIPTS / "dev_generate_policy.sh"),
        "--app-name", app,
        "--app-root", str(REPO_ROOT),
    ]
    if args.apply:
        argv.append("--apply")
    for perm in (args.approve or []):
        argv.extend(["--allow-needs-review-perm", perm])
    if args.force:
        argv.extend(["--force", args.force])
    if args.skip_export:
        argv.append("--skip-export")
    r = _run(argv, dry_run=args.dry_run, verbose=args.verbose)

    if r.returncode != 0 and not args.dry_run:
        hint = blocked_hint(app, REPO_ROOT / "policy_out" / "findings.json")
        if hint:
            print(hint)
    return r.returncode


def blocked_hint(app: str, findings_path: Path) -> str | None:
    """One line naming the permissions that stopped generation, and the exact
    command to run after review. None when generation was not blocked for review."""
    try:
        data = json.loads(findings_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None
    if not data.get("generation_blocked"):
        return None
    needs = [
        f for f in data.get("findings", [])
        if f.get("verdict") == "needs_review" and not f.get("review_key")
    ]
    perms = sorted({p for f in needs for p in f.get("perms", [])})
    if not perms:
        return None
    approve = " ".join(f"--approve {p}" for p in perms)
    return (
        f"Blocked for review: {', '.join(perms)}. "
        f"After review: sepac generate {app} {approve} --apply"
    )


def _have_policy_devel() -> bool:
    return Path("/usr/share/selinux/devel/Makefile").is_file()


def _have_setools() -> bool:
    try:
        subprocess.run(["sesearch", "--version"], capture_output=True, check=True)
        return True
    except (FileNotFoundError, subprocess.CalledProcessError):
        return False


def cmd_check(args: argparse.Namespace) -> int:
    """The CI gate. On a host without selinux-policy-devel (a laptop or a
    controller), the manifest and forbidden-pattern checks still run; compile
    and the semantic checks are reported as skipped, never as passed."""
    _require_policy_tree(args)
    app = args.app
    _validate_app(app)
    if not args.dry_run:
        _check_not_production()
    manifest = _require_manifest(app, getattr(args, "manifest", None))
    mod_dir = _module_dir(manifest)
    mp = _manifest_path(app, getattr(args, "manifest", None))
    devel = args.dry_run or _have_policy_devel()

    def step(argv: list[str]) -> int:
        r = _run(argv, dry_run=args.dry_run, verbose=args.verbose)
        return 0 if args.dry_run else r.returncode

    # 1. The manifest
    rc = step(["bash", str(SCRIPTS / "validate_app_manifest.sh"), str(mp)])
    if rc != 0:
        return rc
    # 2. Forbidden patterns, then compile (compile_and_validate runs both)
    if devel:
        rc = step(["bash", str(SCRIPTS / "compile_and_validate.sh"), str(mod_dir), "--app", app])
    else:
        rc = step(["bash", str(SCRIPTS / "validate_forbidden_patterns.sh"), str(mod_dir), "--app", app])
        if rc == 0:
            print("SKIP compile and semantics: needs selinux-policy-devel (QA and CI run them)")
            return 0
    if rc != 0:
        return rc
    # 3. Semantic checks against a throwaway copy of the policy store
    if not args.dry_run and not _have_setools():
        print("SKIP semantics: needs setools-console")
        return 0
    return step(_sudo_prefix() + ["bash", str(SCRIPTS / "validate_policy_semantics.sh"), str(mod_dir), "--app", app])


def _restore_paths(manifest: dict[str, Any], *, dry: bool) -> list[str]:
    result: list[str] = []
    mp = manifest["paths"]
    for key in ("install_root", "var_dir", "log_dir", "runtime_dir"):
        p = mp.get(key)
        if p and (dry or Path(p).exists()):
            result.append(p)
    for p in mp.get("extra_fc_roots", []):
        if p and (dry or Path(p).exists()):
            result.append(p)
    return result


def _policy_out_matches(app: str, mod_dir: Path) -> bool:
    """policy_out/APP.pp was built from exactly the .te/.fc in MODULE_DIR."""
    out = REPO_ROOT / "policy_out"
    pairs = [(out / f"{app}.te", mod_dir / f"{app}.te"), (out / f"{app}.fc", mod_dir / f"{app}.fc")]
    if not (out / f"{app}.pp").is_file():
        return False
    return all(a.is_file() and b.is_file() and a.read_bytes() == b.read_bytes() for a, b in pairs)


def _reference_pp(app: str, manifest: dict[str, Any]) -> tuple[Path | None, str]:
    """The module this host should be running, and where it came from.

    QA (a policy tree): the build of MODULE_DIR. Managed host (no tree): the
    module the APP-selinux RPM installed.
    """
    if POLICY_TREE is not None:
        mod_dir = _module_dir(manifest)
        if _policy_out_matches(app, mod_dir):
            return REPO_ROOT / "policy_out" / f"{app}.pp", "the repo build"
        built = mod_dir / f"{app}.pp"
        return (built if built.is_file() else None), "the repo build"
    pkg = Path(f"/usr/share/selinux/packages/{app}.pp")
    return (pkg if pkg.is_file() else None), f"the {app}-selinux RPM"


def _source_version(app: str, manifest: dict[str, Any]) -> str:
    if POLICY_TREE is not None:
        vf = _module_dir(manifest) / "policy_version.txt"
        if vf.is_file():
            return vf.read_text(encoding="utf-8").strip()
    try:
        r = subprocess.run(["rpm", "-q", "--qf", "%{VERSION}", f"{app}-selinux"],
                           capture_output=True, text=True)
        if r.returncode == 0 and r.stdout.strip():
            return r.stdout.strip()
    except FileNotFoundError:
        pass
    return "?"


def _loaded_matches(app: str, pp: Path | None) -> bool | None:
    """True when the loaded module is byte-identical to *pp*. None when unknown."""
    if pp is None or not pp.is_file():
        return None
    with tempfile.TemporaryDirectory() as td:
        try:
            # semodule -E writes APP.pp into the current directory.
            r = subprocess.run(_sudo_prefix() + ["semodule", "-E", app],
                               cwd=td, capture_output=True, text=True)
        except FileNotFoundError:
            return None
        extracted = Path(td) / f"{app}.pp"
        if r.returncode != 0 or not extracted.is_file():
            return None
        same = hashlib.sha256(extracted.read_bytes()).digest() == hashlib.sha256(pp.read_bytes()).digest()
        # The extracted copy is root-owned when sudo wrote it.
        subprocess.run(_sudo_prefix() + ["rm", "-f", str(extracted)], capture_output=True)
        return same


def _permissive_domains() -> list[str]:
    r = subprocess.run(_sudo_prefix() + ["semanage", "permissive", "-l"],
                       capture_output=True, text=True)
    return (r.stdout or "").split()


def _set_domain_mode(domain: str, enforcing: bool, *, dry_run: bool, verbose: bool) -> int:
    flag = "-d" if enforcing else "-a"
    argv = _sudo_prefix() + ["semanage", "permissive", flag, domain]
    if dry_run:
        _run(argv, dry_run=True)
        return 0
    on_list = domain in _permissive_domains()
    if enforcing and not on_list:
        print(f"{domain}: already enforcing")
        return 0
    if not enforcing and on_list:
        print(f"{domain}: already permissive")
        return 0
    r = _run(argv, verbose=verbose, capture=True)
    if r.returncode != 0:
        print(r.stderr, end="", file=sys.stderr)
        return r.returncode
    if enforcing:
        print(f"{domain}: enforcing (removed from the permissive list)")
    else:
        print(f"{domain}: permissive (logged, not blocked)")
    return 0


def _label_ports(manifest: dict[str, Any], *, dry_run: bool, verbose: bool) -> int:
    """Add each manifest port with semanage port -a. Never -m: a port another
    application type owns is refused, the same rule the canary role follows."""
    ports = manifest.get("selinux_ports", []) or []
    if not ports:
        return 0
    listing = ""
    if not dry_run:
        r = subprocess.run(_sudo_prefix() + ["semanage", "port", "-l"], capture_output=True, text=True)
        listing = r.stdout or ""
    for entry in ports:
        port, proto, ptype = int(entry["port"]), entry.get("proto", "tcp"), entry["type"]
        argv = _sudo_prefix() + ["semanage", "port", "-a", "-t", ptype, "-p", proto, str(port)]
        if dry_run:
            _run(argv, dry_run=True)
            continue
        try:
            state = classify_port_assignment(listing, port, proto, ptype)
        except ValueError as exc:
            print(f"Refusing: {exc}", file=sys.stderr)
            return 1
        if state == "present":
            continue
        r = _run(argv, verbose=verbose, capture=True)
        if r.returncode != 0:
            print(r.stderr, end="", file=sys.stderr)
            return r.returncode
        print(f"Port {proto}/{port} labeled {ptype}")
    return 0


def cmd_load(args: argparse.Namespace) -> int:
    _require_policy_tree(args)
    app = args.app
    _validate_app(app)
    manifest = _require_manifest(app, getattr(args, "manifest", None))
    domain = str(manifest["domain"])
    if not args.dry_run:
        _check_qa_role()

    mod_dir = _module_dir(manifest)
    version = _source_version(app, manifest)
    if _policy_out_matches(app, mod_dir):
        pp_path = REPO_ROOT / "policy_out" / f"{app}.pp"
    else:
        compile_argv = ["bash", str(SCRIPTS / "compile_and_validate.sh"), str(mod_dir), "--app", app]
        r = _run(compile_argv, dry_run=args.dry_run, verbose=args.verbose,
                 capture=not args.dry_run)
        if not args.dry_run and r.returncode != 0:
            print(r.stdout, end="")
            print(r.stderr, end="", file=sys.stderr)
            return r.returncode
        pp_path = mod_dir / f"{app}.pp"

    # 1. The module. Skip semodule -i (a full policy rebuild) when it is already loaded.
    argv_load = _sudo_prefix() + ["semodule", "-i", str(pp_path)]
    if args.dry_run:
        _run(argv_load, dry_run=True)
    elif _loaded_matches(app, pp_path):
        print(f"{app} {version} is already loaded")
    else:
        r = _run(argv_load, verbose=args.verbose)
        if r.returncode != 0:
            return r.returncode
        print(f"Loaded {app} {version}")

    # 2. File labels from the manifest paths (restorecon -v prints each change).
    paths = _restore_paths(manifest, dry=args.dry_run)
    if paths:
        _run(_sudo_prefix() + ["restorecon", "-Rv"] + paths, dry_run=args.dry_run, verbose=args.verbose)

    # 3. Ports from the manifest.
    rc = _label_ports(manifest, dry_run=args.dry_run, verbose=args.verbose)
    if rc != 0:
        return rc

    # 4. Optional: enforcing or permissive on QA.
    if args.enforcing or args.permissive:
        return _set_domain_mode(domain, bool(args.enforcing), dry_run=args.dry_run, verbose=args.verbose)
    return 0


def cmd_status(args: argparse.Namespace) -> int:
    app = args.app
    _validate_app(app)
    manifest = _require_manifest(app, getattr(args, "manifest", None))
    domain = str(manifest["domain"])
    unit = str(manifest["services"]["primary"]["unit"])

    if args.dry_run:
        print("getenforce")
        print(f"semodule -lfull | grep {app}; semodule -E {app} (compare with the build)")
        print(f"semanage permissive -l | grep {domain}")
        print(f"systemctl show -p MainPID --value {unit}; ps -o label= -p PID")
        print(f"restorecon -Rnv {' '.join(_restore_paths(manifest, dry=True))}")
        print(f"ausearch -m avc -ts recent (scontext type {domain})")
        return 0

    def row(name: str, value: str) -> None:
        print(f"{name:<9}{value}")

    # 1. Host mode
    try:
        ge = subprocess.run(["getenforce"], capture_output=True, text=True).stdout.strip()
    except FileNotFoundError:
        ge = "getenforce not found"
    row("Host", ge)

    # 2. Module
    version = _source_version(app, manifest)
    try:
        lfull = subprocess.run(_sudo_prefix() + ["semodule", "-lfull"], capture_output=True, text=True)
        loaded = [ln.split() for ln in lfull.stdout.splitlines() if app in ln.split()]
    except FileNotFoundError:
        loaded = []
    if loaded:
        priority = loaded[0][0] if len(loaded[0]) >= 3 else "?"
        ref, source = _reference_pp(app, manifest)
        same = _loaded_matches(app, ref)
        verdict = {True: f"matches {source}", False: f"differs from {source}", None: "not compared"}[same]
        row("Module", f"{app} {version}, priority {priority}, {verdict}")
    else:
        row("Module", f"{app} not loaded ({version} in the source)")

    # 3. Domain mode
    try:
        perm = domain in _permissive_domains()
        row("Domain", f"{domain} {'permissive (logged, not blocked)' if perm else 'enforcing'}")
    except FileNotFoundError:
        row("Domain", "semanage not found")

    # 4. Process label
    try:
        pid = subprocess.run(["systemctl", "show", "-p", "MainPID", "--value", unit],
                             capture_output=True, text=True).stdout.strip()
        if pid.isdigit() and pid != "0":
            label = subprocess.run(["ps", "-o", "label=", "-p", pid], capture_output=True, text=True).stdout.strip()
            row("Process", f"{unit} {label or '(label unknown)'}")
        else:
            row("Process", f"{unit} not running")
    except FileNotFoundError:
        row("Process", "systemctl not found")

    # 5. File labels
    rpaths = _restore_paths(manifest, dry=False)
    if rpaths:
        rc = subprocess.run(_sudo_prefix() + ["restorecon", "-Rn", "-v"] + rpaths, capture_output=True, text=True)
        diff_lines = [ln for ln in (rc.stdout or "").splitlines() if ln.strip()]
        row("Labels", f"{len(diff_lines)} files differ (sepac load {app} fixes them)" if diff_lines else "ok")
    else:
        row("Labels", "no paths on disk")

    # 6. Recent denials
    domains = _app_domains(app, manifest)
    count = 0
    for line in _ausearch("recent"):
        avc = parse_avc(line)
        if avc and _source_matches(avc["stype"], domains, app):
            count += 1
    row("Denials", f"{count} in the last 10 minutes")
    return 0


# ── capture: collect evidence ────────────────────────────────────────────────

_URL_PATH_RE = re.compile(r"^/[A-Za-z0-9._~/%-]*$")


def _http_get(host: str, port: int, path: str, timeout: float = 10.0) -> str:
    """Status code as text, or a short error. Never goes through a proxy."""
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    try:
        with opener.open(f"http://{host}:{port}{path}", timeout=timeout) as resp:
            return str(resp.status)
    except urllib.error.HTTPError as exc:
        return str(exc.code)
    except (urllib.error.URLError, OSError) as exc:
        reason = getattr(exc, "reason", exc)
        return f"no answer ({reason})"


def _wait_ready(host: str, port: int, path: str, seconds: int = 90) -> float | None:
    start = time.time()
    while time.time() - start < seconds:
        if _http_get(host, port, path, timeout=3).isdigit():
            return time.time() - start
        time.sleep(1)
    return None


def _count(n: int, noun: str) -> str:
    return f"{n} {noun}" if n == 1 else f"{n} {noun}s"


def capture_summary(app: str, manifest: dict[str, Any], lines: list[str], since_epoch: int) -> list[str]:
    """Group the app's denials since *since_epoch* into expected (soak.ignore in
    the manifest) and new. Returns the lines to print."""
    domains = _app_domains(app, manifest)
    ignore = {(i["tclass"], i["target_type"]) for i in (manifest.get("soak") or {}).get("ignore", [])}
    expected: dict[tuple[str, str], set[str]] = {}
    new: dict[tuple[str, str], dict[str, Any]] = {}
    total = 0
    blocked = False
    for line in lines:
        avc = parse_avc(line)
        if not avc or avc["epoch"] < since_epoch or not _source_matches(avc["stype"], domains, app):
            continue
        total += 1
        blocked = blocked or not avc["permissive"]
        key = (avc["ttype"], avc["tclass"])
        if (avc["tclass"], avc["ttype"]) in ignore:
            expected.setdefault(key, set()).update(avc["perms"])
            continue
        slot = new.setdefault(key, {"perms": set(), "path": ""})
        slot["perms"].update(avc["perms"])
        slot["path"] = slot["path"] or avc["path"]
    label = ", ".join(domains)
    if total == 0:
        return [f"{label}: no denials"]
    mode = "enforcing: blocked" if blocked else "permissive: logged, not blocked"
    out = [f"{label}: {_count(total, 'denial')} ({mode})"]
    if expected:
        names = ", ".join(sorted({f"{t} {c}" for t, c in expected}))
        out.append(f"  expected, listed in the manifest's soak.ignore: {names}")
    if new:
        out.append(f"  new: {_count(len(new), 'access need')}")
        for (ttype, tclass), slot in sorted(new.items())[:5]:
            perms = " ".join(sorted(slot["perms"]))
            where = f"  {slot['path']}" if slot["path"] else ""
            out.append(f"    {{ {perms} }} on {ttype} {tclass}{where}")
        if len(new) > 5:
            out.append(f"    … {len(new) - 5} more: sepac denials {app}")
        out.append(f"  Next: sepac generate {app}")
    elif expected:
        out.append("  new: none")
    return out


def cmd_capture(args: argparse.Namespace) -> int:
    app = args.app
    _validate_app(app)
    manifest = _require_manifest(app, getattr(args, "manifest", None))
    if not args.dry_run and not args.no_restart:
        _check_not_production()
    http = manifest.get("http") or {}
    host, port = str(http.get("host") or "127.0.0.1"), int(http.get("port") or 0)
    paths = list(http.get("endpoints") or [])
    for extra in (args.url or []):
        if not _URL_PATH_RE.match(extra):
            print(f"Invalid --url {extra!r} (a path such as /feature-spool)", file=sys.stderr)
            raise SystemExit(2)
        if extra not in paths:
            paths.append(extra)
    if not port or not paths:
        print(f"The manifest for {app} has no http port or endpoints to call", file=sys.stderr)
        raise SystemExit(2)
    unit = str(manifest["services"]["primary"]["unit"])
    full_audit = bool(args.full_audit)
    restore = _sudo_prefix() + ["bash", str(SCRIPTS / "semodule_restore_dontaudit.sh"), "--app", app]

    if args.dry_run:
        if full_audit:
            _run(_sudo_prefix() + ["semodule", "-DB"], dry_run=True)
        if not args.no_restart:
            _run(_sudo_prefix() + ["systemctl", "restart", unit], dry_run=True)
        for path in paths:
            print(f"GET http://{host}:{port}{path}")
        if full_audit:
            _run(restore, dry_run=True)
        _run(_sudo_prefix() + ["ausearch", "-m", "avc", "-ts", "boot"], dry_run=True)
        return 0

    since = int(time.time()) - 1
    try:
        if full_audit:
            r = _run(_sudo_prefix() + ["semodule", "-DB"], verbose=args.verbose, capture=True)
            if r.returncode != 0:
                print(r.stderr, end="", file=sys.stderr)
                return r.returncode
            print("Full auditing on (dontaudit rules off)")
        if not args.no_restart:
            r = _run(_sudo_prefix() + ["systemctl", "restart", unit], verbose=args.verbose)
            if r.returncode != 0:
                return r.returncode
            took = _wait_ready(host, port, paths[0])
            if took is None:
                print(f"Restarted {unit}, but it did not answer on {host}:{port} within 90s")
            else:
                print(f"Restarted {unit} (answering after {took:.0f}s)")
        for path in paths:
            print(f"GET {path:<18} {_http_get(host, port, path)}")
    finally:
        if full_audit:
            _run(restore, verbose=args.verbose, capture=True)
            print("Auditing restored")
    time.sleep(1)  # let auditd write the last records
    for line in capture_summary(app, manifest, _ausearch("boot"), since):
        print(line)
    return 0


# ── init: onboard an app ─────────────────────────────────────────────────────

_MANIFEST_TEMPLATE = """\
# {app}: the one file sepac reads for this app. Review every value.
# Bind ports stay the same in every environment; the probe host may change.
app_name: {app}
domain: {app}_t

paths:
  install_root: /opt/{app}
  var_dir: /var/lib/{app}
  log_dir: /var/log/{app}
  runtime_dir: /run/{app}

services:
  primary:
    unit: {unit}
    domain: {app}_t

http:
  host: 127.0.0.1
  port: {port}
  endpoints:
    - /health

selinux_ports:
  - port: {port}
    proto: tcp
    type: {app}_port_t

policy:
  module_dir: selinux/{app}
  service_name: {unit}

deploy:
  soak_marker_file: /var/lib/selinux-policy-ops/{app}/selinux_canary_deployed_at
  deploy_report_file: /var/lib/selinux-policy-ops/{app}/selinux_deploy_report.json
"""


def cmd_init(args: argparse.Namespace) -> int:
    tree = _require_policy_tree(args)
    app = args.app
    _validate_app(app)
    unit = args.unit or f"{app}.service"
    if not re.match(r"^[A-Za-z0-9@._-]+\.service$", unit):
        print(f"Invalid --unit {unit!r} (a systemd unit such as {app}.service)", file=sys.stderr)
        raise SystemExit(2)
    manifest_path = tree / "config" / f"{app}.manifest.yml"
    module_dir = tree / "selinux" / app
    te = module_dir / f"{app}.te"
    scaffold = ["bash", str(SCRIPTS / "scaffold_sepolicy_module.sh"), app, f"{app}_t"]

    if args.dry_run:
        print(f"write {manifest_path}" + (" (exists: kept)" if manifest_path.is_file() else ""))
        _run(scaffold, dry_run=True)
        print(f"write {module_dir / 'policy_version.txt'}")
        return 0

    if manifest_path.is_file():
        print(f"Kept {manifest_path.relative_to(tree)} (already there)")
    else:
        manifest_path.write_text(_MANIFEST_TEMPLATE.format(app=app, unit=unit, port=args.port),
                                 encoding="utf-8")
        print(f"Wrote {manifest_path.relative_to(tree)}: review the paths, unit, port and endpoints")

    if te.is_file():
        print(f"Kept {te.relative_to(tree)} (already there)")
    else:
        have_generate = subprocess.run(["sh", "-c", "command -v sepolicy-generate"],
                                       capture_output=True).returncode == 0
        if not have_generate:
            print("Policy not scaffolded: sepolicy-generate is missing (policycoreutils-devel). "
                  f"Run sepac init {app} again on the QA host.")
        else:
            env = {"SCAFFOLD_PROJECT_ROOT": str(tree)}
            r = _run(scaffold, verbose=args.verbose, env=env)
            if r.returncode != 0:
                return r.returncode
    version_file = module_dir / "policy_version.txt"
    if te.is_file() and not version_file.is_file():
        m = re.search(r"policy_module\(\s*\w+\s*,\s*([0-9]+\.[0-9]+\.[0-9]+)\s*\)", te.read_text(encoding="utf-8"))
        version_file.write_text((m.group(1) if m else "1.0.0") + "\n", encoding="utf-8")
        print(f"Wrote {version_file.relative_to(tree)}")

    print()
    print("Next, on the QA host with the app installed:")
    print(f"  sepac triage {app}            # Red Hat's policy first")
    print(f"  sepac check {app}             # manifest and policy pass the gate")
    print(f"  sepac load {app} --permissive # labels, port, domain logging only")
    print(f"  sepac capture {app} --full-audit")
    print(f"  sepac generate {app}")
    return 0


# ── Ansible commands ─────────────────────────────────────────────────────────

def _ansible_limit(args: argparse.Namespace) -> list[str]:
    limit = getattr(args, "limit", None)
    return ["--limit", limit] if limit else []


def cmd_canary(args: argparse.Namespace) -> int:
    _require_policy_tree(args)
    inv = _validate_env(args.env)
    argv = [
        "ansible-playbook", "-i", str(inv),
        str(ANSIBLE / "deploy_canary.yml"),
    ] + _ansible_limit(args)
    r = _run(argv, dry_run=args.dry_run, verbose=args.verbose)
    return r.returncode


def cmd_soak(args: argparse.Namespace) -> int:
    _require_policy_tree(args)
    inv = _validate_env(args.env)
    playbook = "soak_status.yml" if args.status else "soak_monitor.yml"
    argv = [
        "ansible-playbook", "-i", str(inv),
        str(ANSIBLE / playbook),
    ] + _ansible_limit(args)
    r = _run(argv, dry_run=args.dry_run, verbose=args.verbose)
    return r.returncode


def cmd_enforce(args: argparse.Namespace) -> int:
    _require_policy_tree(args)
    if not args.ticket:
        print("--ticket is required for enforce", file=sys.stderr)
        raise SystemExit(2)
    inv = _validate_env(args.env)
    argv = [
        "ansible-playbook", "-i", str(inv),
        str(ANSIBLE / "enforce_production.yml"),
        "-e", f"change_ticket={args.ticket}",
    ]
    if args.skip_soak_days:
        argv.extend(["-e", "skip_soak_days=true"])
    if args.break_glass:
        argv.extend(["-e", "force_enforce=true", "-e", f"break_glass_reason={args.break_glass}"])
    argv += _ansible_limit(args)
    r = _run(argv, dry_run=args.dry_run, verbose=args.verbose)
    return r.returncode


def cmd_rollback(args: argparse.Namespace) -> int:
    _require_policy_tree(args)
    inv = _validate_env(args.env)
    argv = [
        "ansible-playbook", "-i", str(inv),
        str(ANSIBLE / "emergency_rollback.yml"),
    ] + _ansible_limit(args)
    r = _run(argv, dry_run=args.dry_run, verbose=args.verbose)
    return r.returncode


def cmd_build(args: argparse.Namespace) -> int:
    _require_policy_tree(args)
    argv = ["bash", str(REPO_ROOT / "packaging" / "build_rpms.sh")]
    env: dict[str, str] = {}
    if args.allow_dirty:
        env["BUILD_RPMS_ALLOW_DIRTY"] = "1"
    r = _run(argv, dry_run=args.dry_run, verbose=args.verbose, env=env if env else None)
    return r.returncode


def cmd_publish(args: argparse.Namespace) -> int:
    """publish_internal.sh reads packaging/internal.env itself. --env-file adds
    settings (the lab's signing env); without it, dist/lab-signing.env is used
    when present."""
    _require_policy_tree(args)
    env_file = Path(args.env_file) if args.env_file else REPO_ROOT / "dist" / "lab-signing.env"
    if args.env_file and not args.dry_run and not env_file.is_file():
        print(f"Env file not found: {env_file}", file=sys.stderr)
        raise SystemExit(2)
    env: dict[str, str] = {}
    if not args.dry_run and env_file.is_file():
        for line in env_file.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            k, _, v = line.partition("=")
            env[k.strip().removeprefix("export ").strip()] = v.strip().strip("'\"")
    argv = ["bash", str(REPO_ROOT / "packaging" / "publish_internal.sh")]
    r = _run(argv, dry_run=args.dry_run, verbose=args.verbose, env=env if env else None)
    return r.returncode


# ── Completion ───────────────────────────────────────────────────────────────

def cmd_completion(args: argparse.Namespace) -> int:
    """Print bash completion script generated from the argparse parser."""
    parser = build_parser()
    subcmds: list[str] = []
    subcmd_flags: dict[str, list[str]] = {}

    for action in parser._subparsers._actions:
        if isinstance(action, argparse._SubParsersAction):
            for name, sub in action.choices.items():
                if name.startswith("_"):
                    continue
                subcmds.append(name)
                flags: list[str] = []
                for a in sub._actions:
                    for opt in a.option_strings:
                        if not opt.startswith("-"):
                            continue
                        flags.append(opt)
                subcmd_flags[name] = flags

    global_flags = ["--dry-run", "-v", "--verbose", "--version", "--tree"]

    lines = [
        "# bash completion for sepac — generated by sepac completion bash",
        "_sepac_complete() {",
        '    local cur prev words cword',
        '    _init_completion || return',
        '',
        '    local subcmds="' + " ".join(subcmds) + '"',
        '    local global_flags="' + " ".join(global_flags) + '"',
        '',
        '    # Find the subcommand',
        '    local subcmd=""',
        '    local i',
        '    for ((i=1; i < cword; i++)); do',
        '        case "${words[i]}" in',
        '            -*) ;;',
        '            *)',
        '                subcmd="${words[i]}"',
        '                break',
        '                ;;',
        '        esac',
        '    done',
        '',
        '    if [[ -z "${subcmd}" ]]; then',
        '        COMPREPLY=( $(compgen -W "${subcmds} ${global_flags}" -- "${cur}") )',
        '        return 0',
        '    fi',
        '',
        '    case "${prev}" in',
        '        --env)',
        '            local envs',
        '            envs="$(sepac _complete envs 2>/dev/null)"',
        '            COMPREPLY=( $(compgen -W "${envs}" -- "${cur}") )',
        '            return 0',
        '            ;;',
        '        --approve)',
        '            local perms',
        '            perms="$(sepac _complete perms 2>/dev/null)"',
        '            COMPREPLY=( $(compgen -W "${perms}" -- "${cur}") )',
        '            return 0',
        '            ;;',
        '    esac',
        '',
        '    case "${subcmd}" in',
    ]

    for name in subcmds:
        flags = subcmd_flags.get(name, [])
        # Commands that take APP positional
        app_cmds = {"init", "triage", "tune", "capture", "denials", "generate", "check", "load", "status"}
        if name in app_cmds:
            lines.append(f'        {name})')
            lines.append('            if [[ "${cur}" == -* ]]; then')
            lines.append(f'                COMPREPLY=( $(compgen -W "{" ".join(flags)}" -- "${{cur}}") )')
            lines.append('            else')
            lines.append('                local apps')
            lines.append('                apps="$(sepac _complete apps 2>/dev/null)"')
            lines.append('                COMPREPLY=( $(compgen -W "${apps}" -- "${cur}") )')
            lines.append('            fi')
            lines.append('            ;;')
        else:
            lines.append(f'        {name})')
            lines.append(f'            COMPREPLY=( $(compgen -W "{" ".join(flags)}" -- "${{cur}}") )')
            lines.append('            ;;')

    lines += [
        '    esac',
        '}',
        'complete -F _sepac_complete sepac',
    ]

    print("\n".join(lines))
    return 0


def cmd_complete(args: argparse.Namespace) -> int:
    """Dynamic completion helper: sepac _complete apps|envs|perms."""
    what = args.what

    if what == "apps":
        apps: set[str] = set()
        if POLICY_TREE is not None:
            config_dir = POLICY_TREE / "config"
            if config_dir.is_dir():
                for f in config_dir.glob("*.manifest.yml"):
                    apps.add(f.name.replace(".manifest.yml", ""))
        etc_apps = Path("/etc/selinux-pac/apps")
        if etc_apps.is_dir():
            for f in etc_apps.glob("*.manifest.yml"):
                apps.add(f.name.replace(".manifest.yml", ""))
        print("\n".join(sorted(apps)))
        return 0

    if what == "envs":
        envs: set[str] = set()
        if POLICY_TREE is not None:
            ansible_dir = POLICY_TREE / "ansible"
            if ansible_dir.is_dir():
                for f in ansible_dir.glob("inventory.*.yml"):
                    name = f.name.replace("inventory.", "").replace(".yml", "")
                    if not name.endswith(".example"):
                        envs.add(name)
        print("\n".join(sorted(envs)))
        return 0

    if what == "perms":
        from policy_rules import NEEDS_REVIEW_RATIONALE
        perms = sorted({perm for _, perm in NEEDS_REVIEW_RATIONALE})
        print("\n".join(perms))
        return 0

    return 1


# ── Man page ─────────────────────────────────────────────────────────────────

def cmd_man(args: argparse.Namespace) -> int:
    """Generate groff -man source for sepac(8)."""
    import datetime

    parser = build_parser()
    date_str = datetime.date.today().strftime("%B %Y")

    lines: list[str] = []

    def _w(s: str = "") -> None:
        lines.append(s)

    _w(f'.TH SEPAC 8 "{date_str}" "selinux-pac" "System Administration"')
    _w(".SH NAME")
    _w("sepac \\- SELinux Policy as Code admin CLI")
    _w(".SH SYNOPSIS")
    _w(".B sepac")
    _w("[\\fB\\-\\-version\\fR]")
    _w("[\\fB\\-\\-tree\\fR \\fIDIR\\fR]")
    _w("[\\fB\\-\\-dry\\-run\\fR]")
    _w("[\\fB\\-v\\fR]")
    _w("\\fICOMMAND\\fR [\\fIargs\\fR]")

    _w(".SH DESCRIPTION")
    _w("SELinux policy as code for RHEL admins. sepac decides whether an app needs")
    _w("new policy at all, collects the evidence, writes the smallest policy that")
    _w("covers it, stops for review on domain-weakening permissions, refuses")
    _w("forbidden ones, gates the result like CI, and ships it as a signed RPM")
    _w("through canary, soak and enforce. The host stays Enforcing throughout.")

    _w(".SH COMMANDS")
    _w(".SS On the QA host")

    qa_cmds = ["init", "doctor", "triage", "tune", "capture", "denials", "generate", "check", "load", "status"]
    ansible_cmds = ["build", "publish", "canary", "soak", "enforce", "rollback"]

    # Collect help text from the subparser action
    _subcmd_help: dict[str, str] = {}
    for action in parser._subparsers._actions:
        if isinstance(action, argparse._SubParsersAction):
            for name, sub in action.choices.items():
                # help is stored on the pseudo-action for this choice
                _subcmd_help[name] = action._choices_actions[
                    [a.dest for a in action._choices_actions].index(name)
                ].help if name in [a.dest for a in action._choices_actions] else ""

    for action in parser._subparsers._actions:
        if not isinstance(action, argparse._SubParsersAction):
            continue
        for name, sub in action.choices.items():
            if name.startswith("_") or name == "completion":
                continue
            if name in ansible_cmds:
                continue
            _w(f".TP")
            flag_parts: list[str] = []
            for a in sub._actions:
                if a.option_strings:
                    for opt in a.option_strings:
                        if opt in ("--dry-run", "-v", "--verbose", "--tree", "-h", "--help"):
                            continue
                        flag_parts.append(f"\\fB{opt}\\fR")
                elif hasattr(a, "metavar") and a.metavar:
                    flag_parts.append(f"\\fI{a.metavar}\\fR")
            _w(f".B {name}")
            if flag_parts:
                _w(" ".join(flag_parts))
            _w(_subcmd_help.get(name, ""))

    _w(".SS Where Ansible runs")
    for action in parser._subparsers._actions:
        if not isinstance(action, argparse._SubParsersAction):
            continue
        for name, sub in action.choices.items():
            if name not in ansible_cmds:
                continue
            _w(f".TP")
            flag_parts = []
            for a in sub._actions:
                if a.option_strings:
                    for opt in a.option_strings:
                        if opt in ("--dry-run", "-v", "--verbose", "--tree", "-h", "--help"):
                            continue
                        flag_parts.append(f"\\fB{opt}\\fR")
                elif hasattr(a, "metavar") and a.metavar:
                    flag_parts.append(f"\\fI{a.metavar}\\fR")
            _w(f".B {name}")
            if flag_parts:
                _w(" ".join(flag_parts))
            _w(_subcmd_help.get(name, ""))

    _w(".SH FILES")
    _w(".TP")
    _w(".I /etc/selinux-pac/role")
    _w("Host role (qa, dev, staging, production). Controls which commands are allowed.")
    _w(".TP")
    _w(".I /etc/selinux-pac/apps/")
    _w("Per-app manifest copies installed by the Ansible role.")
    _w(".TP")
    _w(".I /etc/selinux-pac/sepac.conf")
    _w("Configuration file. Set \\fBtree\\fR to point at a policy tree.")

    _w(".SH EXAMPLES")
    _w("On a QA host:")
    _w(".PP")
    _w(".nf")
    _w("sepac triage shopapi")
    _w("sepac capture shopapi")
    _w("sepac generate shopapi")
    _w("sepac generate shopapi --approve execmem --apply")
    _w("sepac check shopapi")
    _w("sepac load shopapi --enforcing")
    _w("sepac status shopapi")
    _w(".fi")
    _w(".PP")
    _w("Where Ansible runs:")
    _w(".PP")
    _w(".nf")
    _w("sepac build && sepac publish")
    _w("sepac canary --env production --limit canary")
    _w("sepac soak --env production --status")
    _w("sepac enforce --env production --ticket CHG123")
    _w(".fi")

    _w(".SH SEE ALSO")
    _w(".BR semanage (8),")
    _w(".BR restorecon (8),")
    _w(".BR semodule (8),")
    _w(".BR ausearch (8),")
    _w(".BR audit2why (1)")

    print("\n".join(lines))
    return 0

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="sepac",
        usage="sepac [--dry-run] [-v] [--tree DIR] COMMAND [APP] [options]",
        description="SELinux policy as code for RHEL admins.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "On the QA host:\n"
            "  init       Onboard an app: manifest and a scaffolded policy module\n"
            "  doctor     Check that this host has the SELinux tools sepac needs\n"
            "  triage     Should we write policy at all? (Red Hat's policy first)\n"
            "  tune       Host fixes for a vendor domain: labels, ports, booleans\n"
            "  capture    Restart the app, call its endpoints, summarise the denials\n"
            "  denials    Show the app's denials (--why explains them)\n"
            "  generate   Write policy from the denials; stops for review, refuses the forbidden\n"
            "  check      The CI gate: manifest, forbidden patterns, compile, semantics\n"
            "  load       Load on QA: module, file labels, ports (--enforcing, --permissive)\n"
            "  status     Host mode, module, domain, process, labels, recent denials\n"
            "\n"
            "Where Ansible runs:\n"
            "  build      Build the RPMs\n"
            "  publish    Sign and publish them to the internal repo\n"
            "  canary     Install on the canary hosts, domain permissive, start the soak\n"
            "  soak       Daily soak gate (--status: read-only)\n"
            "  enforce    Enforce after a clean soak (--ticket required)\n"
            "  rollback   Domain back to permissive, optional RPM downgrade\n"
            "\n"
            "  completion bash   Print the bash completion script\n"
            "\n"
            "sepac COMMAND --help shows the options. --dry-run prints what would run.\n"
        ),
    )
    parser.add_argument("--version", action="store_true", help="Print version and exit")
    parser.add_argument("--tree", default=None, metavar="DIR",
                        help="Policy tree root (config/, selinux/, ansible/)")
    parser.add_argument("--dry-run", action="store_true", help="Print what would run; change nothing")
    parser.add_argument("-v", "--verbose", action="store_true", help="Print each command before running it")

    subs = parser.add_subparsers(dest="command", metavar="COMMAND", help=argparse.SUPPRESS, prog="sepac")

    def _common(p: argparse.ArgumentParser) -> None:
        """Add --dry-run, -v, and --tree to a subparser so they work after the subcommand too."""
        p.add_argument("--dry-run", action="store_true", default=argparse.SUPPRESS, help=argparse.SUPPRESS)
        p.add_argument("-v", "--verbose", action="store_true", default=argparse.SUPPRESS, help=argparse.SUPPRESS)
        p.add_argument("--tree", default=argparse.SUPPRESS, help=argparse.SUPPRESS)

    # ── On the QA host ────────────────────────────────────────────────────

    p = subs.add_parser("init", help="Onboard an app: manifest and a scaffolded policy module")
    p.add_argument("app", metavar="APP")
    p.add_argument("--unit", default=None, help="systemd unit (default: APP.service)")
    p.add_argument("--port", type=int, default=8080, help="The port the app binds (default: 8080)")
    _common(p)
    p.set_defaults(func=cmd_init)

    p = subs.add_parser("doctor", help="Check host prerequisites")
    _common(p)
    p.set_defaults(func=cmd_doctor)

    p = subs.add_parser("triage", help="Does Red Hat already ship policy?")
    p.add_argument("app", metavar="APP")
    p.add_argument("--unit", default=None, help="systemd unit (default: APP.service)")
    p.add_argument("--manifest", default=None, metavar="PATH", help="Manifest file path")
    _common(p)
    p.set_defaults(func=cmd_triage)

    p = subs.add_parser("tune", help="Vendor-domain tune report")
    p.add_argument("app", metavar="APP")
    p.add_argument("--unit", default=None, help="systemd unit")
    p.add_argument("--manifest", default=None, metavar="PATH", help="Manifest file path")
    _common(p)
    p.set_defaults(func=cmd_tune)

    p = subs.add_parser("capture", help="Restart the app, call its endpoints, summarise the denials")
    p.add_argument("app", metavar="APP")
    p.add_argument("--url", action="append", metavar="PATH",
                   help="Also call this path (repeatable), e.g. a new feature")
    p.add_argument("--no-restart", action="store_true", help="Call the endpoints without restarting")
    p.add_argument("--full-audit", action="store_true",
                   help="Turn dontaudit rules off for the run, so hidden denials are logged too")
    p.add_argument("--manifest", default=None, metavar="PATH", help="Manifest file path")
    _common(p)
    p.set_defaults(func=cmd_capture)

    p = subs.add_parser("denials", help="Show AVC denials for an app")
    p.add_argument("app", metavar="APP")
    p.add_argument("--since", default="recent", choices=["recent", "boot", "today", "this-hour"],
                   help="recent (10 minutes, default), boot, today, this-hour")
    p.add_argument("--enforced", action="store_true", help="Only permissive=0 lines")
    p.add_argument("--why", action="store_true", help="Pipe kept lines to audit2why")
    p.add_argument("--last", type=int, default=10, help="Show last N lines (default: 10)")
    p.add_argument("--manifest", default=None, metavar="PATH", help="Manifest file path")
    _common(p)
    p.set_defaults(func=cmd_denials)

    p = subs.add_parser("generate", help="Generate policy from audit log")
    p.add_argument("app", metavar="APP")
    p.add_argument("--approve", action="append", metavar="PERM",
                   help="Approve a needs_review permission (repeatable)")
    p.add_argument("--apply", action="store_true", help="Copy to selinux/")
    p.add_argument("--force", metavar="REASON", help="Bypass vendor check")
    p.add_argument("--skip-export", action="store_true", help="Use existing policy_out/avc.log")
    p.add_argument("--manifest", default=None, metavar="PATH", help="Manifest file path")
    _common(p)
    p.set_defaults(func=cmd_generate)

    p = subs.add_parser("check", help="CI gate: manifest + compile + semantics")
    p.add_argument("app", metavar="APP")
    p.add_argument("--manifest", default=None, metavar="PATH", help="Manifest file path")
    _common(p)
    p.set_defaults(func=cmd_check)

    p = subs.add_parser("load", help="Load on QA: module, file labels, ports")
    p.add_argument("app", metavar="APP")
    mode = p.add_mutually_exclusive_group()
    mode.add_argument("--enforcing", action="store_true", help="Then take the domain off the permissive list")
    mode.add_argument("--permissive", action="store_true", help="Then put the domain on the permissive list")
    p.add_argument("--manifest", default=None, metavar="PATH", help="Manifest file path")
    _common(p)
    p.set_defaults(func=cmd_load)

    p = subs.add_parser("status", help="Six-line status for an app")
    p.add_argument("app", metavar="APP")
    p.add_argument("--manifest", default=None, metavar="PATH", help="Manifest file path")
    _common(p)
    p.set_defaults(func=cmd_status)

    # ── Where Ansible runs ────────────────────────────────────────────────

    p = subs.add_parser("canary", help="Deploy canary via Ansible")
    p.add_argument("--env", required=True, help="dev, staging, or production")
    p.add_argument("--limit", default=None, help="Ansible --limit")
    _common(p)
    p.set_defaults(func=cmd_canary)

    p = subs.add_parser("soak", help="Soak monitor or status")
    p.add_argument("--env", required=True, help="dev, staging, or production")
    p.add_argument("--limit", default=None, help="Ansible --limit")
    p.add_argument("--status", action="store_true", help="Read-only soak_status.yml")
    _common(p)
    p.set_defaults(func=cmd_soak)

    p = subs.add_parser("enforce", help="Enforce after soak")
    p.add_argument("--env", required=True, help="dev, staging, or production")
    p.add_argument("--ticket", required=True, help="Change ticket (required)")
    p.add_argument("--limit", default=None, help="Ansible --limit")
    p.add_argument("--skip-soak-days", action="store_true", help="Skip day count gate")
    p.add_argument("--break-glass", metavar="REASON", help="Force enforce with reason")
    _common(p)
    p.set_defaults(func=cmd_enforce)

    p = subs.add_parser("rollback", help="Emergency rollback via Ansible")
    p.add_argument("--env", required=True, help="dev, staging, or production")
    p.add_argument("--limit", default=None, help="Ansible --limit")
    _common(p)
    p.set_defaults(func=cmd_rollback)

    p = subs.add_parser("build", help="Build RPMs")
    p.add_argument("--allow-dirty", action="store_true", help="Skip dirty-tree check")
    _common(p)
    p.set_defaults(func=cmd_build)

    p = subs.add_parser("publish", help="Publish RPMs to internal repo")
    p.add_argument("--env-file", default=None,
                   help="Extra signing settings (default: dist/lab-signing.env if present)")
    _common(p)
    p.set_defaults(func=cmd_publish)

    # ── Utility commands ──────────────────────────────────────────────────

    p = subs.add_parser("completion", help="Print shell completion script")
    p.add_argument("shell", choices=["bash"], help="Shell (only bash supported)")
    p.set_defaults(func=cmd_completion)

    p = subs.add_parser("_complete")
    p.add_argument("what", choices=["apps", "envs", "perms"])
    p.add_argument("--tree", default=argparse.SUPPRESS, help=argparse.SUPPRESS)
    p.set_defaults(func=cmd_complete)

    p = subs.add_parser("_man")
    p.set_defaults(func=cmd_man)

    return parser


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    for flag in ("dry_run", "verbose"):
        if not hasattr(args, flag):
            setattr(args, flag, False)
    if getattr(args, "version", False):
        print(f"sepac {_sepac_version()}")
        return 0
    if not args.command:
        parser.print_help()
        return 2
    _init_trees(args)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
