"""Source and compiled-policy audits. CI and validate_policy_semantics.sh share this."""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

from policy_rules import COMPILED_REJECT_CAPABILITIES, FORBIDDEN_TARGET_TYPES

COMPILED_SECURITY_PERMS = ("load_policy", "setenforce")


def join_policy_lines(text: str) -> str:
    """Join rules that are split across lines so a newline cannot hide a type."""
    logical: list[str] = []
    buf = ""
    for raw in text.splitlines():
        line = raw.split("#", 1)[0].strip()
        if not line:
            continue
        buf = f"{buf} {line}".strip() if buf else line
        if buf.endswith(";") or buf.endswith(")"):
            logical.append(buf)
            buf = ""
    if buf:
        logical.append(buf)
    return "\n".join(logical)


def dontaudit_forbidden_hits(text: str) -> list[str]:
    joined = join_policy_lines(text)
    hits: list[str] = []
    for match in re.finditer(r"\bdontaudit\b[^;]*;", joined, re.IGNORECASE):
        rule = match.group(0)
        for type_name in sorted(FORBIDDEN_TARGET_TYPES):
            if re.search(rf"\b{re.escape(type_name)}\b", rule):
                hits.append(f"dontaudit names forbidden type {type_name}: {rule}")
    return hits


def fc_path_tokens(text: str) -> list[str]:
    tokens: list[str] = []
    for raw in text.splitlines():
        line = raw.split("#", 1)[0].strip()
        if not line or line.startswith("policy_module"):
            continue
        token = line.split()[0]
        if token.startswith("/"):
            tokens.append(token)
    return tokens


def literal_prefix(fc_regex: str) -> str:
    prefix: list[str] = []
    i = 0
    while i < len(fc_regex):
        ch = fc_regex[i]
        if ch == "\\":
            if i + 1 < len(fc_regex):
                prefix.append(fc_regex[i + 1])
                i += 2
                continue
            break
        if ch in "([*+?{":
            break
        prefix.append(ch)
        i += 1
    return "".join(prefix).rstrip("/")


def allowed_fc_roots(paths: dict) -> list[str]:
    roots: list[str] = []
    for key, value in paths.items():
        if key == "extra_fc_roots" and isinstance(value, list):
            roots.extend(str(item) for item in value if str(item).startswith("/"))
        elif isinstance(value, str) and value.startswith("/"):
            roots.append(value)
    aliased: list[str] = []
    for root in roots:
        if root == "/run" or root.startswith("/run/"):
            aliased.append("/var" + root)
        if root == "/var/run" or root.startswith("/var/run/"):
            aliased.append(root.replace("/var/run", "/run", 1))
    return roots + aliased


def fc_paths_outside_roots(tokens: list[str], roots: list[str]) -> list[str]:
    bad: list[str] = []
    normalized = [root.rstrip("/") for root in roots]
    for token in tokens:
        prefix = literal_prefix(token)
        if not prefix.startswith("/"):
            bad.append(token)
            continue
        if any(prefix == root or prefix.startswith(root + "/") for root in normalized):
            continue
        bad.append(token)
    return bad


def audit_allow_text(text: str, domain: str) -> list[str]:
    """Reject dangerous allows in sesearch output (compiled policy, one rule per line)."""
    compact = re.sub(r"\s*:\s*", ":", re.sub(r"\s+", " ", text))
    errors: list[str] = []
    for type_name in sorted(FORBIDDEN_TARGET_TYPES):
        if re.search(rf"\ballow\s+{re.escape(domain)}\s+{re.escape(type_name)}\b", compact):
            errors.append(f"compiled allow {domain} -> {type_name}")
    if re.search(rf"\ballow\s+{re.escape(domain)}\s+file_type\b", compact):
        errors.append(f"compiled allow {domain} -> file_type (every file type)")
    for perm in sorted(COMPILED_REJECT_CAPABILITIES):
        if re.search(
            rf"\ballow\s+{re.escape(domain)}\s+self:capability\b[^{{;]*\{{[^}}]*\b{perm}\b",
            compact,
        ) or re.search(
            rf"\ballow\s+{re.escape(domain)}\s+self:capability\s+{perm}\b",
            compact,
        ):
            errors.append(f"compiled allow {domain} self:capability {perm}")
    for perm in COMPILED_SECURITY_PERMS:
        if re.search(
            rf"\ballow\s+{re.escape(domain)}\s+\S+:security\b[^{{;]*\{{[^}}]*\b{perm}\b",
            compact,
        ) or re.search(
            rf"\ballow\s+{re.escape(domain)}\s+\S+:security\s+{perm}\b",
            compact,
        ):
            errors.append(f"compiled allow {domain} security {perm}")
    return errors


def audit_foreign_entrypoint(text: str, domain: str, declared_types: set[str]) -> list[str]:
    """Reject file entrypoint allows whose target this module does not declare."""
    compact = re.sub(r"\s*:\s*", ":", re.sub(r"\s+", " ", join_policy_lines(text)))
    errors: list[str] = []
    pattern = re.compile(
        rf"\ballow\s+{re.escape(domain)}\s+(\S+):file\b([^;]*);",
    )
    for match in pattern.finditer(compact):
        target, rest = match.group(1), match.group(2)
        if not re.search(r"\bentrypoint\b", rest):
            continue
        if target not in declared_types:
            errors.append(
                f"compiled entrypoint {domain} -> {target} is not declared by this module"
            )
    return errors


def audit_type_attributes(seinfo_text: str, domain: str) -> list[str]:
    if "unconfined_domain_type" in seinfo_text or re.search(
        rf"\bunconfined_domain\s*\(\s*{re.escape(domain)}\s*\)", seinfo_text
    ):
        return [f"{domain} has unconfined_domain_type"]
    return []


def audit_permissive_types(seinfo_text: str, domain: str) -> list[str]:
    if re.search(rf"\b{re.escape(domain)}\b", seinfo_text):
        return [f"compiled policy marks {domain} permissive"]
    return []


def _manifest_paths(repo: Path, module: str) -> dict | None:
    sys.path.insert(0, str(repo / "scripts" / "lib"))
    from app_manifest import load_manifest

    for name in (f"{module}.manifest.yml", f"{module}.manifest.example.yml"):
        path = repo / "config" / name
        if path.is_file():
            return load_manifest(path)["paths"]
    return None


def audit_tree(repo: Path, selinux_dir: Path) -> list[str]:
    errors: list[str] = []
    for path in sorted(selinux_dir.rglob("*")):
        if path.suffix not in {".te", ".if", ".cil", ".fc"}:
            continue
        text = path.read_text(encoding="utf-8")
        if path.suffix != ".fc":
            for hit in dontaudit_forbidden_hits(text):
                errors.append(f"{path.relative_to(repo)}: {hit}")
            continue
        module = path.stem
        paths = _manifest_paths(repo, module)
        tokens = fc_path_tokens(text)
        if paths is None:
            if tokens:
                errors.append(f"{path.relative_to(repo)}: .fc has paths but no manifest for {module}")
            continue
        for token in fc_paths_outside_roots(tokens, allowed_fc_roots(paths)):
            errors.append(
                f"{path.relative_to(repo)}: .fc path {token} is outside manifest paths"
            )
    return errors


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Audit SELinux sources and compiled allows")
    parser.add_argument("--selinux-dir", type=Path)
    parser.add_argument("--allows-file", type=Path)
    parser.add_argument("--dontaudit-file", type=Path)
    parser.add_argument("--seinfo-file", type=Path)
    parser.add_argument("--permissive-file", type=Path)
    parser.add_argument("--domain", default="")
    parser.add_argument("--declared-types-file", type=Path)
    args = parser.parse_args(argv)
    repo = Path(__file__).resolve().parents[1]
    errors: list[str] = []
    if args.selinux_dir:
        errors.extend(audit_tree(repo, args.selinux_dir))
    if args.allows_file:
        if not args.domain:
            print("policy_audit: --domain is required with --allows-file", file=sys.stderr)
            return 2
        allows_text = args.allows_file.read_text(encoding="utf-8")
        errors.extend(audit_allow_text(allows_text, args.domain))
        if args.declared_types_file:
            declared = {
                line.strip()
                for line in args.declared_types_file.read_text(encoding="utf-8").splitlines()
                if line.strip()
            }
            errors.extend(audit_foreign_entrypoint(allows_text, args.domain, declared))
    if args.dontaudit_file:
        errors.extend(dontaudit_forbidden_hits(args.dontaudit_file.read_text(encoding="utf-8")))
    if args.seinfo_file and args.domain:
        errors.extend(audit_type_attributes(args.seinfo_file.read_text(encoding="utf-8"), args.domain))
    if args.permissive_file and args.domain:
        errors.extend(
            audit_permissive_types(args.permissive_file.read_text(encoding="utf-8"), args.domain)
        )
    if errors:
        for err in errors:
            print(err, file=sys.stderr)
        return 1
    print("policy audit passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
