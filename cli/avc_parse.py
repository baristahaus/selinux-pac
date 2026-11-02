"""AVC line parsing, domain filtering, and policy version helpers."""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parent.parent
SELINUX_DIR = PROJECT_ROOT / "selinux"


@dataclass
class AvcEntry:
    raw_line: str
    scontext: str = ""
    tcontext: str = ""
    tclass: str = ""
    perm: str = ""

    @property
    def key(self) -> tuple[str, str, str, str]:
        return (self.scontext, self.tcontext, self.tclass, self.perm)


def domain_for_app(app_name: str) -> str:
    return f"{app_name}_t"


def parse_version(text: str) -> tuple[int, int, int]:
    parts = text.strip().split(".")
    if len(parts) != 3:
        raise ValueError(f"Invalid semver: {text!r}")
    return int(parts[0]), int(parts[1]), int(parts[2])


def format_version(major: int, minor: int, patch: int) -> str:
    return f"{major}.{minor}.{patch}"


def read_policy_version(version_file: Path) -> str:
    if version_file.is_file():
        return version_file.read_text(encoding="utf-8").strip()
    return "1.0.0"


def bump_policy_version(version_file: Path) -> str:
    major, minor, patch = parse_version(read_policy_version(version_file))
    patch += 1
    new_version = format_version(major, minor, patch)
    version_file.parent.mkdir(parents=True, exist_ok=True)
    version_file.write_text(new_version + "\n", encoding="utf-8")
    return new_version


def parse_avc_field(line: str, field: str) -> str:
    match = re.search(rf"{field}=([^\s]+)", line)
    return match.group(1) if match else ""


def parse_avc_line(line: str) -> AvcEntry:
    perm = parse_avc_field(line, "perm")
    if not perm:
        denied_match = re.search(r"avc:\s+denied\s+\{([^}]+)\}", line)
        if denied_match:
            perm = denied_match.group(1).strip()

    return AvcEntry(
        raw_line=line.strip(),
        scontext=parse_avc_field(line, "scontext"),
        tcontext=parse_avc_field(line, "tcontext"),
        tclass=parse_avc_field(line, "tclass"),
        perm=perm,
    )


def filter_avc_entries(entries: list[AvcEntry], domain: str) -> list[AvcEntry]:
    filtered: list[AvcEntry] = []
    for entry in entries:
        if domain in entry.scontext or domain in entry.raw_line:
            filtered.append(entry)
            continue
        if "/opt/myapp" in entry.raw_line or "/var/lib/myapp" in entry.raw_line or "/run/myapp" in entry.raw_line:
            filtered.append(entry)
            continue
        if 'comm="python' in entry.raw_line and "myapp" in entry.raw_line:
            filtered.append(entry)
    return filtered


def deduplicate_avc_entries(entries: list[AvcEntry]) -> list[AvcEntry]:
    seen: set[tuple[str, str, str, str]] = set()
    unique: list[AvcEntry] = []
    for entry in entries:
        if entry.key in seen:
            continue
        seen.add(entry.key)
        unique.append(entry)
    return unique
