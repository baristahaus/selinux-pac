"""
policy_rules.py — Shared house rules for deterministic generation and CI alignment.
"""

from __future__ import annotations

# High-privilege / sensitive targets. Compiled-policy CI enforces these
# in scripts/validate_policy_semantics.sh via cli/policy_audit.py.
FORBIDDEN_TARGET_TYPES = frozenset(
    {
        "shadow_t",
        "unconfined_t",
        "sysadm_t",
        "security_t",
        "selinux_config_t",
        "passwd_file_t",
    }
)

GENERIC_FILE_TYPES = frozenset(
    {
        "var_t",
        "var_lib_t",
        "var_log_t",
        "var_run_t",
        "var_spool_t",
        "usr_t",
        "etc_t",
        "tmp_t",
        "default_t",
        "unlabeled_t",
        "home_root_t",
        "user_home_t",
        "user_home_dir_t",
    }
)

# can_exec() permissions. c9s policy/support/misc_macros.spt:
#   define(`can_exec',`allow $1 $2:file { mmap_exec_file_perms ioctl lock execute_no_trans };')
# mmap_exec_file_perms is { getattr open map read execute ioctl }.
# corecmd_exec_bin() and java_exec() both use can_exec. Neither grants entrypoint.
JAVA_EXEC_FILE_PERMS = frozenset(
    {
        "getattr",
        "open",
        "map",
        "read",
        "execute",
        "ioctl",
        "lock",
        "execute_no_trans",
    }
)

# On RHEL 9 the system JVM is bin_t. java_exec_t is an alias of bin_t in the
# base corecommands module (c9s policy/modules/kernel/corecommands.te:
# "type bin_t alias { ... java_exec_t mono_exec_t };"), and the contrib java
# module is not in the build. An AVC therefore names bin_t, and java_exec(),
# corecmd_exec_bin() and can_exec(x, java_exec_t) all compile to execute on
# bin_t. Red Hat's own tomcat, httpd and postgresql policies use
# corecmd_exec_bin. This project allows it only as a reviewed exception written
# in the app manifest (selinux_exceptions.exec_bin), never as a raw allow and
# never from a command-line opt-in.
EXEC_BIN_TYPES = frozenset({"bin_t", "java_exec_t"})
EXEC_BIN_EXCEPTION = "exec_bin"
MANIFEST_EXCEPTION_KEYS = frozenset({EXEC_BIN_EXCEPTION})
EXEC_BIN_REVIEW_NOTE = (
    "Security decision (needs review): this domain executed a program labeled bin_t. "
    "On RHEL 9 the system JVM is bin_t (java_exec_t is an alias of bin_t), so there is "
    "no narrower type to allow. corecmd_exec_bin() is the rule Red Hat's tomcat, httpd "
    "and postgresql policies use. Programs run this way stay in this domain and gain no "
    "rights, but a compromised app can run any bin_t program within its own limits. "
    "To accept it, a reviewer writes the reason in the app manifest under "
    "selinux_exceptions.exec_bin. --allow-needs-review does not unlock this finding."
)


def manifest_exception(manifest: dict, key: str) -> str:
    """Reviewed reason for a house-rule exception, or '' when the manifest has none."""
    exceptions = manifest.get("selinux_exceptions") or {}
    if not isinstance(exceptions, dict):
        return ""
    reason = exceptions.get(key)
    return reason.strip() if isinstance(reason, str) else ""


# Shared executable types. An entrypoint denial on one of these, at a path
# this module's .fc already covers, is a stale label (restorecon), not an allow.
STALE_ENTRYPOINT_TYPES = frozenset(
    {
        "bin_t",
        "java_exec_t",
        "usr_t",
        "lib_t",
        "shell_exec_t",
    }
)

GENERIC_PORT_TYPES = frozenset(
    {
        "unreserved_port_t",
        "port_t",
        "reserved_port_t",
        "ephemeral_port_t",
    }
)

PATTERN_MACROS: list[tuple[frozenset[str], str]] = [
    (
        frozenset(
            {
                "create",
                "write",
                "unlink",
                "rename",
                "setattr",
                "append",
                "read",
                "open",
                "getattr",
            }
        ),
        "manage_files_pattern",
    ),
    (
        frozenset(
            {
                "create",
                "write",
                "add_name",
                "remove_name",
                "rmdir",
                "search",
                "read",
                "open",
                "getattr",
            }
        ),
        "manage_dirs_pattern",
    ),
    (
        frozenset({"read", "open", "getattr", "lock", "ioctl"}),
        "read_files_pattern",
    ),
    (
        frozenset({"search", "read", "open", "getattr"}),
        "list_dirs_pattern",
    ),
]

VERDICT_FC = "fc_fix"
VERDICT_FC_DRIFT = "fc_drift"
VERDICT_PORT = "private_port"
VERDICT_FORBIDDEN = "forbidden"
VERDICT_BASELINE = "baseline"
VERDICT_INTERFACE = "interface"
VERDICT_DIRECT = "direct"
VERDICT_TOOLCHAIN = "toolchain_required"
VERDICT_BOOLEAN = "boolean"
VERDICT_NEEDS_REVIEW = "needs_review"

# Permissions that can be legitimate but measurably weaken the domain.
# Checked before interface matching and the direct-allow fallback.
# Tuple: (tclass, perm, scope) where scope is "any" or "foreign_domain"
# (process transition/dyntransition only when the target is outside this module).
NEEDS_REVIEW_RULES: frozenset[tuple[str, str, str]] = frozenset(
    {
        ("process", "execmem", "any"),
        ("process", "execstack", "any"),
        ("process", "execheap", "any"),
        ("process", "setexec", "any"),
        ("process", "setcurrent", "any"),
        ("capability", "dac_override", "any"),
        ("capability", "dac_read_search", "any"),
        ("capability", "sys_admin", "any"),
        ("capability", "sys_module", "any"),
        ("capability", "sys_ptrace", "any"),
        ("capability", "setuid", "any"),
        ("capability", "setgid", "any"),
        ("process", "transition", "foreign_domain"),
        ("process", "dyntransition", "foreign_domain"),
    }
)

# Compiled-policy CI hard-fails these capability permissions. They must stay a
# subset of NEEDS_REVIEW_RULES. Other needs-review permissions (execmem, dac_override,
# setuid, ...) stay an opt-in review and do not fail the compiled check.
COMPILED_REJECT_CAPABILITIES = frozenset({"sys_admin", "sys_module"})

# What the permission allows, why it weakens the domain, and alternatives.
# Keyed by (tclass, perm). Keep in sync with NEEDS_REVIEW_RULES.
NEEDS_REVIEW_RATIONALE: dict[tuple[str, str], tuple[str, str, str]] = {
    ("process", "execmem"): (
        "map memory as both writable and executable",
        "it breaks W^X: memory the process can write, it can also execute",
        "this AVC showed process execmem was denied. Some JVM/runtime configurations "
        "avoid writable+executable mappings; do not assume a JVM needs execmem. "
        "Confirm empirically for this workload and its options before "
        "--allow-needs-review",
    ),
    ("process", "execstack"): (
        "an executable stack",
        "stack contents can be executed (classic stack-smash path)",
        "clear PT_GNU_STACK / disable an executable stack on the binary; grant only "
        "if this AVC is confirmed on the shipped binary",
    ),
    ("process", "execheap"): (
        "an executable heap",
        "heap data can be executed",
        "avoid making the heap executable; confirm this AVC against the workload",
    ),
    ("process", "setexec"): (
        "set the exec security context before execve",
        "the domain can choose a different domain for a child at exec",
        "use a labeled entrypoint and type_transition in this module instead of setexec",
    ),
    ("process", "setcurrent"): (
        "change the current process security context",
        "the process can leave its confined domain",
        "do not grant; use a domain transition on exec of a labeled binary",
    ),
    ("capability", "dac_override"): (
        "bypass DAC write/access checks",
        "Unix file permissions no longer constrain this domain",
        "fix ownership, mode, or labels so dac_override is unnecessary",
    ),
    ("capability", "dac_read_search"): (
        "bypass DAC read/search checks",
        "the domain can read files the Unix owner did not grant",
        "fix ownership, mode, or labels so dac_read_search is unnecessary",
    ),
    ("capability", "sys_admin"): (
        "a wide range of administrative operations",
        "the domain gains near-admin capability",
        "drop the need for sys_admin, or split a privileged helper domain",
    ),
    ("capability", "sys_module"): (
        "load or unload kernel modules",
        "the domain can change kernel integrity",
        "do not grant to an app domain; load modules from an admin domain",
    ),
    ("capability", "sys_ptrace"): (
        "ptrace-attach other processes",
        "the domain can inspect and modify other processes' memory",
        "do not grant; debug from a separate admin/debug domain",
    ),
    ("capability", "setuid"): (
        "change UID",
        "the domain can assume other Unix identities",
        "run as the intended UID from systemd; avoid setuid in the app",
    ),
    ("capability", "setgid"): (
        "change GID",
        "the domain can assume other Unix group identities",
        "run as the intended GID from systemd; avoid setgid in the app",
    ),
    ("process", "transition"): (
        "create a process in another SELinux domain",
        "this domain can start code as a domain this module does not own",
        "if the target is this app's helper, add it to the module; otherwise do not "
        "grant an outbound domain transition",
    ),
    ("process", "dyntransition"): (
        "dynamically change to another SELinux domain",
        "this domain can become a domain this module does not own",
        "if the target is this app's helper, add it to the module; otherwise do not "
        "grant dyntransition",
    ),
}

# What the author should do next (not a live host patch).
NEXT_ACTION = {
    VERDICT_FC: "update_fc_and_restorecon",
    VERDICT_FC_DRIFT: "update_fc_and_restorecon",
    VERDICT_PORT: "add_manifest_port",
    VERDICT_BOOLEAN: "setsebool_host",
    VERDICT_DIRECT: "update_te_allow",
    VERDICT_INTERFACE: "update_te_allow",
    VERDICT_FORBIDDEN: "refuse",
    VERDICT_TOOLCHAIN: "install_sepolgen",
    VERDICT_NEEDS_REVIEW: "review_then_opt_in",
    VERDICT_BASELINE: "",
}


def needs_review_hits(
    src_type: str,
    tgt_type: str,
    tclass: str,
    perms: frozenset[str],
    module_types: set[str],
) -> tuple[tuple[str, str], ...]:
    """Return sorted (tclass, perm) pairs from NEEDS_REVIEW_RULES that match this need."""
    hits: list[tuple[str, str]] = []
    for rule_class, perm, scope in sorted(NEEDS_REVIEW_RULES):
        if tclass != rule_class or perm not in perms:
            continue
        if scope == "foreign_domain":
            if tgt_type in module_types or tgt_type in {src_type, "self"}:
                continue
        hits.append((rule_class, perm))
    return tuple(hits)


def format_needs_review_note(hits: tuple[tuple[str, str], ...]) -> str:
    """Deterministic reviewer text: what it allows, why it weakens, alternatives."""
    parts = [
        "Security decision (needs review): the AVC log showed this permission was "
        "denied. It is not a labeling miss. The proposed allow is recorded in "
        "findings.json / pr_summary.md but is not written to the .te unless you pass "
        "--allow-needs-review (or --allow-needs-review-perm)."
    ]
    for tclass, perm in hits:
        allows, weakens, alternatives = NEEDS_REVIEW_RATIONALE.get(
            (tclass, perm),
            (
                f"{tclass}:{perm}",
                "it is a high-privilege permission",
                "confirm empirically; opt in only with --allow-needs-review",
            ),
        )
        parts.append(
            f"{tclass}:{perm} allows {allows}. It weakens the domain because {weakens}. "
            f"Alternatives: {alternatives}."
        )
    return " ".join(parts)
