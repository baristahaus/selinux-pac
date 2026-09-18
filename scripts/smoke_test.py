#!/usr/bin/env python3
"""Local smoke tests (no SELinux host required for most)."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import subprocess
import sys
import tempfile
import time
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
BASH = shutil.which("bash") or "/bin/bash"
sys.path.insert(0, str(PROJECT_ROOT / "cli"))

from avc_preprocess import (  # noqa: E402
    AccessNeed,
    build_llm_avc_summary,
    extract_type,
    merge_avc_entries,
    normalize_perms,
    parse_existing_allows,
    preprocess_avc_entries,
    subtract_covered,
)
from prompt_templates import SYSTEM_PROMPT, build_user_prompt  # noqa: E402
from selinux_gen import (  # noqa: E402
    bump_policy_version,
    deduplicate_avc_entries,
    filter_avc_entries,
    parse_avc_line,
    parse_policy_json,
    read_policy_version,
    validate_policy_content,
    validate_pr_summary,
)


def assert_mentions(text: str, *needles: str) -> None:
    """Talk tracks name these apps/paths — prefer this over a deny-list of old strings."""
    blob = text.lower()
    missing = [n for n in needles if n.lower() not in blob]
    assert not missing, f"talk output missing {missing}"


def test_prompts() -> None:
    avc = (
        'type=AVC msg=audit(123): avc: denied { write } for pid=1 comm="python3" '
        "scontext=system_u:system_r:myapp_t:s0 "
        "tcontext=system_u:object_r:myapp_var_lib_t:s0 tclass=file permissive=1"
    )
    te = (PROJECT_ROOT / "selinux" / "myapp.te").read_text(encoding="utf-8")
    fc = (PROJECT_ROOT / "selinux" / "myapp.fc").read_text(encoding="utf-8")
    prompt = build_user_prompt(
        "myapp_t", avc, app_name="myapp", version="1.0.0", existing_te=te, existing_fc=fc
    )
    assert "myapp_t" in prompt
    assert "Existing Type Enforcement" in prompt
    assert len(SYSTEM_PROMPT) > 100


def test_avc_parsing() -> None:
    line = (
        'type=AVC msg=audit(1): avc: denied { write append open } for pid=99 '
        'scontext=system_u:system_r:myapp_t:s0 '
        "tcontext=system_u:object_r:myapp_var_lib_t:s0 tclass=file permissive=1"
    )
    entry = parse_avc_line(line)
    assert entry.perm == "write append open"
    deduped = deduplicate_avc_entries([entry, parse_avc_line(line)])
    assert len(deduped) == 1
    assert len(filter_avc_entries(deduped, "myapp_t")) == 1


def _sample_avc_line(perm: str, scontext: str, tcontext: str, tclass: str = "file") -> str:
    return (
        f'type=AVC msg=audit(1): avc: denied {{ {perm} }} for pid=1 comm="python3" '
        f"scontext={scontext} tcontext={tcontext} tclass={tclass} permissive=1"
    )


def test_perm_merge() -> None:
    line_a = _sample_avc_line(
        "write",
        "system_u:system_r:myapp_t:s0",
        "system_u:object_r:myapp_var_lib_t:s0",
    )
    line_b = _sample_avc_line(
        "append open",
        "system_u:system_r:myapp_t:s0",
        "system_u:object_r:myapp_var_lib_t:s0",
    )
    merged = merge_avc_entries([parse_avc_line(line_a), parse_avc_line(line_b)])
    assert len(merged) == 1
    assert merged[0].perms == frozenset({"write", "append", "open"})


def test_type_extraction_dedup() -> None:
    line_a = _sample_avc_line(
        "write",
        "system_u:system_r:myapp_t:s0",
        "system_u:object_r:myapp_var_lib_t:s0",
    )
    line_b = _sample_avc_line(
        "write",
        "system_u:object_r:myapp_t:s0",
        "system_u:object_r:myapp_var_lib_t:s0",
    )
    merged = merge_avc_entries([parse_avc_line(line_a), parse_avc_line(line_b)])
    assert len(merged) == 1
    assert extract_type("system_u:system_r:myapp_t:s0") == "myapp_t"


def test_subtract_existing() -> None:
    te = (PROJECT_ROOT / "selinux" / "myapp.te").read_text(encoding="utf-8")
    existing = parse_existing_allows(te)
    merged = [
        AccessNeed("myapp_t", "myapp_lib_t", "file", frozenset({"read"})),
    ]
    net_new, covered = subtract_covered(merged, existing)
    assert len(net_new) == 0, f"unexpected net_new: {net_new}"
    assert len(covered) == 1
    assert "read" in covered[0].perms


def test_net_new_detection() -> None:
    te = (PROJECT_ROOT / "selinux" / "myapp.te").read_text(encoding="utf-8")
    existing = parse_existing_allows(te)
    merged = [
        AccessNeed("myapp_t", "myapp_lib_t", "file", frozenset({"read", "write"})),
    ]
    net_new, covered = subtract_covered(merged, existing)
    assert any("write" in need.perms for need in net_new)
    assert any("read" in need.perms for need in covered)


def test_preprocess_stats() -> None:
    lines = [
        _sample_avc_line("write", "system_u:system_r:myapp_t:s0", "system_u:object_r:myapp_var_lib_t:s0"),
        _sample_avc_line("append", "system_u:system_r:myapp_t:s0", "system_u:object_r:myapp_var_lib_t:s0"),
        _sample_avc_line(
            "name_bind",
            "system_u:system_r:myapp_t:s0",
            "system_u:object_r:unreserved_port_t:s0",
            tclass="tcp_socket",
        ),
    ]
    entries = [parse_avc_line(line) for line in lines]
    entries = filter_avc_entries(entries, "myapp_t")
    _, stats = preprocess_avc_entries(entries, existing_te="")
    assert stats["raw"] == 3
    assert stats["merged"] == 2
    assert stats["merged"] < stats["raw"]


def test_prompt_uses_summary() -> None:
    te = (PROJECT_ROOT / "selinux" / "myapp.te").read_text(encoding="utf-8")
    fc = (PROJECT_ROOT / "selinux" / "myapp.fc").read_text(encoding="utf-8")
    entries = [
        parse_avc_line(
            _sample_avc_line("link", "system_u:system_r:myapp_t:s0", "system_u:object_r:myapp_var_lib_t:s0")
        )
    ]
    summary, _ = build_llm_avc_summary(entries, existing_te=te)
    prompt = build_user_prompt(
        "myapp_t", summary, app_name="myapp", version="1.0.0", existing_te=te, existing_fc=fc
    )
    assert "Net-new access needs" in prompt
    assert "Access needs derived from AVCs" in prompt
    assert "Already covered by existing policy" in prompt


def test_no_changes_needed_summary() -> None:
    te = (PROJECT_ROOT / "selinux" / "myapp.te").read_text(encoding="utf-8")
    entries = [
        parse_avc_line(
            _sample_avc_line("read", "system_u:system_r:myapp_t:s0", "system_u:object_r:myapp_lib_t:s0")
        )
    ]
    summary, stats = build_llm_avc_summary(entries, existing_te=te)
    assert stats.get("no_changes_needed") == 1
    assert "no te_content changes required" in summary.lower() or "No te_content changes" in summary


def test_pr_summary_split_and_validate() -> None:
    from pr_summary_common import (
        merge_pr_summary,
        split_pr_summary_sections,
        validate_narrative_section,
        validate_pr_summary,
    )

    narrative = "\n".join(
        [
            "### Network Bindings",
            "- port 8888",
            "",
            "### File System Access",
            "- /var/lib/myapp",
            "",
            "### Process Execution",
            "- myapp_exec_t",
            "",
            "### Explicit Denials Maintained",
            "- no wildcards",
        ]
    )
    tail = "\n".join(
        [
            "### Host administrative actions (not shipped in RPM)",
            "- None",
            "",
            "### Classification audit (engine)",
            "| Verdict | Target | Engine | Note |",
            "| --- | --- | --- | --- |",
            "| direct | myapp_log_t | rules | ok |",
        ]
    )
    template = narrative + "\n\n" + tail
    got_narr, got_tail = split_pr_summary_sections(template)
    assert "### Host administrative" in got_tail
    assert "Classification audit" in got_tail
    merged = merge_pr_summary(got_narr, got_tail)
    validate_pr_summary(merged)
    validate_narrative_section(got_narr)
    try:
        validate_narrative_section("allow myapp_t shadow_t:file read;")
        raise AssertionError("expected validate_narrative_section to fail")
    except RuntimeError:
        pass


def test_policy_json_validation() -> None:
    payload = {
        "module_name": "myapp",
        "te_content": "policy_module(myapp, 1.0.0)\ntype myapp_t;\n",
        "fc_content": (
            "/opt/myapp/app\\.py -- gen_context(system_u:object_r:myapp_exec_t,s0)\n"
            "/var/lib/myapp(/.*)? gen_context(system_u:object_r:myapp_var_lib_t,s0)\n"
            "/run/myapp(/.*)? gen_context(system_u:object_r:myapp_var_run_t,s0)\n"
        ),
        "rationale": "test",
        "pr_summary": (
            "### Network Bindings\n- Binds unreserved_port_t:8888\n\n"
            "### File System Access\n- myapp_var_lib_t read/write\n\n"
            "### Process Execution\n- myapp_exec_t transitions\n\n"
            "### Explicit Denials Maintained\n- No shadow_t access\n"
        ),
    }
    data = parse_policy_json(json.dumps(payload))
    validate_policy_content(data["te_content"], data["fc_content"], "myapp_t", "myapp")
    validate_pr_summary(data["pr_summary"])


def test_version_bump() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        vf = Path(tmp) / "policy_version.txt"
        vf.write_text("1.0.0\n", encoding="utf-8")
        assert read_policy_version(vf) == "1.0.0"
        assert bump_policy_version(vf) == "1.0.1"
        assert read_policy_version(vf) == "1.0.1"


def test_assemble_pr_body_policy_diff_section() -> None:
    """assemble_pr_body embeds precomputed sesearch delta (full diff needs sesearch + git merge-base)."""
    fixture = PROJECT_ROOT / "docs" / "examples" / "fixtures" / "policy_diff" / "sample_delta.md"
    assert fixture.is_file(), f"missing {fixture}"
    with tempfile.TemporaryDirectory() as tmp:
        pr_summary = Path(tmp) / "pr_summary.md"
        pr_summary.write_text("### Network Bindings\n- test\n", encoding="utf-8")
        avc_log = Path(tmp) / "avc.log"
        avc_log.write_text("type=AVC msg=audit(1): avc: denied { read } for pid=1\n", encoding="utf-8")
        output = Path(tmp) / "pr_body.md"
        script = PROJECT_ROOT / "scripts" / "assemble_pr_body.sh"
        subprocess.run(
            [
                "bash",
                str(script),
                "--template",
                str(PROJECT_ROOT / ".github" / "PULL_REQUEST_TEMPLATE" / "selinux_policy_review.md"),
                "--pr-summary",
                str(pr_summary),
                "--avc-log",
                str(avc_log),
                "--output",
                str(output),
                "--app-name",
                "myapp",
                "--policy-diff-file",
                str(fixture),
            ],
            check=True,
            cwd=PROJECT_ROOT,
        )
        body = output.read_text(encoding="utf-8")
        assert "Rules ADDED" in body
        assert "name_bind" in body
        assert "sediff unavailable" not in body.lower()


def test_assemble_pr_body() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        pr_summary = Path(tmp) / "pr_summary.md"
        pr_summary.write_text(
            "### Network Bindings\n- Port 8888 via unreserved_port_t\n\n"
            "### File System Access\n- /var/lib/myapp data dir\n\n"
            "### Process Execution\n- backup.sh via myapp_exec_t\n\n"
            "### Explicit Denials Maintained\n- No wildcard allows\n",
            encoding="utf-8",
        )
        avc_log = Path(tmp) / "avc.log"
        avc_log.write_text(
            'type=AVC msg=audit(1): avc: denied { write } for pid=1 comm="python3" '
            "scontext=system_u:system_r:myapp_t:s0 "
            "tcontext=system_u:object_r:myapp_var_lib_t:s0 tclass=file permissive=1\n",
            encoding="utf-8",
        )
        output = Path(tmp) / "pr_body.md"
        template = PROJECT_ROOT / ".github" / "PULL_REQUEST_TEMPLATE" / "selinux_policy_review.md"
        script = PROJECT_ROOT / "scripts" / "assemble_pr_body.sh"
        subprocess.run(
            [
                "bash",
                str(script),
                "--template",
                str(template),
                "--pr-summary",
                str(pr_summary),
                "--avc-log",
                str(avc_log),
                "--output",
                str(output),
                "--app-name",
                "myapp",
                "--staging-host",
                "staging.example.com",
                "--skip-policy-diff",
            ],
            check=True,
            cwd=PROJECT_ROOT,
        )
        body = output.read_text(encoding="utf-8")
        assert "### Network Bindings" in body
        assert "Security and Sysadmin Checklist" in body
        assert "staging.example.com" in body
        assert "type=AVC" in body
        assert "<!-- AUTO:PR_SUMMARY -->" not in body
        assert "<!-- AUTO:AVC_EXCERPT -->" not in body
        assert "<!-- AUTO:VENDOR_OVERRIDE -->" not in body


def test_verify_file_contexts_skip() -> None:
    script = PROJECT_ROOT / "scripts" / "verify_file_contexts.sh"
    result = subprocess.run(
        ["bash", str(script), "--skip-if-unavailable"],
        cwd=PROJECT_ROOT,
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0, result.stderr


def test_check_soak_ready_gate() -> None:
    script = PROJECT_ROOT / "scripts" / "check_soak_ready.sh"
    with tempfile.TemporaryDirectory() as tmp:
        marker = Path(tmp) / "marker"
        report = Path(tmp) / "selinux_deploy_report.json"
        report.write_text(
            json.dumps(
                {
                    "status": "pass",
                    "endpoints_exercised": True,
                    "domain_context_verified": True,
                }
            ),
            encoding="utf-8",
        )
        missing = subprocess.run(
            ["bash", str(script), "--marker-file", str(marker), "--min-days", "7"],
            cwd=PROJECT_ROOT,
            capture_output=True,
            text=True,
        )
        assert missing.returncode != 0

        marker.write_text(str(int(time.time())), encoding="utf-8")
        recent = subprocess.run(
            ["bash", str(script), "--marker-file", str(marker), "--min-days", "7", "--max-avc", "0"],
            cwd=PROJECT_ROOT,
            capture_output=True,
            text=True,
        )
        assert recent.returncode != 0

        old_epoch = int(time.time()) - (8 * 86400)
        marker.write_text(str(old_epoch), encoding="utf-8")
        old = subprocess.run(
            [
                "bash",
                str(script),
                "--marker-file",
                str(marker),
                "--min-days",
                "7",
                "--max-avc",
                "0",
                "--skip-if-unavailable",
                "--report-file",
                str(report),
            ],
            cwd=PROJECT_ROOT,
            capture_output=True,
            text=True,
        )
        assert old.returncode == 0, old.stderr


def test_monitor_avc_skip() -> None:
    script = PROJECT_ROOT / "scripts" / "monitor_avc.sh"
    manifest = PROJECT_ROOT / "config" / "myapp.manifest.yml"
    result = subprocess.run(
        [
            "bash",
            str(script),
            "--skip-if-unavailable",
            "--max-avc",
            "-1",
            "--manifest",
            str(manifest),
        ],
        cwd=PROJECT_ROOT,
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0, result.stderr


def test_vendor_policy_check() -> None:
    script = PROJECT_ROOT / "scripts" / "lib" / "vendor_policy_check.sh"

    def run(args: list[str], extra_env: dict[str, str] | None = None, *, mock: bool = True) -> subprocess.CompletedProcess[str]:
        env = os.environ.copy()
        for key in list(env):
            if key.startswith("VENDOR_CHECK_"):
                del env[key]
        if mock:
            env["VENDOR_CHECK_MOCK"] = "1"
        if extra_env:
            env.update(extra_env)
        return subprocess.run(
            [BASH, str(script), *args],
            cwd=PROJECT_ROOT,
            capture_output=True,
            text=True,
            env=env,
        )

    loaded = run(
        ["--app-name", "tomcat"],
        {
            "VENDOR_CHECK_SEMODULE_L": "container\njws6_tomcat\t1.0.0\n",
            "VENDOR_CHECK_RPM_QA": "",
            "VENDOR_CHECK_DNF_AVAILABLE": "",
            "VENDOR_CHECK_PS_EZ": "",
        },
    )
    loaded_out = loaded.stdout + loaded.stderr
    assert loaded.returncode != 0, loaded_out
    assert "jws6_tomcat" in loaded_out
    assert "already loaded" in loaded_out.lower()
    assert "do not generate" in loaded_out.lower()

    available = run(
        ["--app-name", "tomcat"],
        {
            "VENDOR_CHECK_SEMODULE_L": "",
            "VENDOR_CHECK_RPM_QA": "",
            "VENDOR_CHECK_DNF_AVAILABLE": "jws6-tomcat-selinux",
            "VENDOR_CHECK_PS_EZ": "",
        },
    )
    available_out = available.stdout + available.stderr
    assert available.returncode != 0, available_out
    assert "jws6-tomcat-selinux" in available_out
    assert "available but not installed" in available_out.lower()

    unconfined = run(
        ["--app-name", "tomcat", "--unit", "tomcat.service"],
        {
            "VENDOR_CHECK_SEMODULE_L": "",
            "VENDOR_CHECK_RPM_QA": "",
            "VENDOR_CHECK_DNF_AVAILABLE": "",
            "VENDOR_CHECK_PS_EZ": "system_u:system_r:unconfined_java_t:s0  java",
        },
    )
    unconfined_out = unconfined.stdout + unconfined.stderr
    assert unconfined.returncode != 0, unconfined_out
    assert "unconfined_java_t" in unconfined_out
    assert "not enabled" in unconfined_out.lower()

    proceed = run(
        ["--app-name", "myapp"],
        {
            "VENDOR_CHECK_SEMODULE_L": "jws6_tomcat\nhttpd",
            "VENDOR_CHECK_RPM_QA": "jws6-tomcat-selinux-1.0-1.el9.noarch",
            "VENDOR_CHECK_DNF_AVAILABLE": "jws6-tomcat-selinux",
            "VENDOR_CHECK_PS_EZ": "system_u:system_r:unconfined_java_t:s0  java",
        },
    )
    proceed_out = proceed.stdout + proceed.stderr
    assert proceed.returncode == 0, proceed_out
    assert "continuing" in proceed_out.lower()
    assert "no vendor or base module covers 'myapp'" in proceed_out

    bare = run(
        ["--app-name", "tomcat", "--force"],
        {"VENDOR_CHECK_SEMODULE_L": "jws6_tomcat"},
    )
    bare_out = bare.stdout + bare.stderr
    assert bare.returncode != 0, bare_out
    assert "reason" in bare_out.lower()
    assert "bare --force" in bare_out.lower()

    forced = run(
        ["--app-name", "tomcat", "--force", "non-standard layout vs jws6_tomcat"],
        {"VENDOR_CHECK_SEMODULE_L": "jws6_tomcat"},
    )
    forced_out = forced.stdout + forced.stderr
    assert forced.returncode == 0, forced_out
    assert "bypassed (--force)" in forced_out
    assert "non-standard layout vs jws6_tomcat" in forced_out
    assert "TRIAGE situation=loaded" in forced_out

    with tempfile.TemporaryDirectory() as empty_path:
        skipped = run(
            ["--app-name", "tomcat"],
            {"PATH": empty_path},
            mock=False,
        )
    skipped_out = skipped.stdout + skipped.stderr
    assert skipped.returncode == 0, skipped_out
    assert "vendor policy check skipped" in skipped_out
    assert "semodule and rpm not found" in skipped_out

    reported = run(
        ["--app-name", "tomcat", "--report"],
        {"VENDOR_CHECK_SEMODULE_L": "jws6_tomcat"},
    )
    reported_out = reported.stdout + reported.stderr
    assert reported.returncode == 0, reported_out
    assert "TRIAGE situation=loaded" in reported_out
    assert "jws6_tomcat" in reported_out
    assert "domain_confined=yes" in reported_out

    unconfined_loaded = run(
        ["--app-name", "tomcat", "--report"],
        {
            "VENDOR_CHECK_SEMODULE_L": "tomcat",
            "VENDOR_CHECK_DOMAIN_UNCONFINED": "1",
        },
    )
    unconfined_loaded_out = unconfined_loaded.stdout + unconfined_loaded.stderr
    assert unconfined_loaded.returncode == 0, unconfined_loaded_out
    assert "TRIAGE situation=loaded" in unconfined_loaded_out
    assert "domain_confined=no" in unconfined_loaded_out
    assert "does not mean file or port denials will fire" in unconfined_loaded_out


def test_demo_present_dry_run() -> None:
    script = PROJECT_ROOT / "scripts" / "demo_present.sh"
    result = subprocess.run(
        [
            BASH,
            str(script),
            "--dry-run",
            "--no-type",
            "--auto",
            "--profile",
            "customer",
        ],
        cwd=PROJECT_ROOT,
        capture_output=True,
        text=True,
    )
    out = result.stdout + result.stderr
    assert result.returncode == 0, out
    assert "Act 0" in out
    assert "TRIAGE" in out or "vendor" in out.lower()
    assert "App A" in out
    assert "App B" in out or "inherited" in out.lower()
    assert "shopapi" in out.lower() or "Spring Boot" in out
    assert "audit2why" in out
    assert "SELinuxContext" in out
    assert "make demo-bootstrap" in out or "demo-bootstrap" in out
    assert_mentions(out, "shopapi", "tomcat")
    assert "status --short selinux" in out
    assert "semodule -l" in out
    assert "files_unconfined_type" in out
    help_run = subprocess.run(
        [BASH, str(script), "--help"],
        cwd=PROJECT_ROOT,
        capture_output=True,
        text=True,
    )
    help_out = help_run.stdout + help_run.stderr
    assert help_run.returncode == 0, help_out
    assert "demo_e2e_mac.sh" in help_out
    te = (PROJECT_ROOT / "selinux" / "shopapi" / "shopapi.te").read_text(encoding="utf-8")
    assert not any(
        (not line.lstrip().startswith("#")) and "execmem" in line
        for line in te.splitlines()
    )
    pre = subprocess.run(
        [
            BASH,
            str(script),
            "--dry-run",
            "--no-type",
            "--auto",
            "--preflight",
        ],
        cwd=PROJECT_ROOT,
        capture_output=True,
        text=True,
    )
    pre_out = pre.stdout + pre.stderr
    assert pre.returncode == 0, pre_out
    assert "make demo-bootstrap" in pre_out
    assert "semanage port -d" in pre_out
    assert "8090" in pre_out
    tech = subprocess.run(
        [
            BASH,
            str(script),
            "--dry-run",
            "--no-type",
            "--auto",
            "--profile",
            "technical",
        ],
        cwd=PROJECT_ROOT,
        capture_output=True,
        text=True,
    )
    tech_out = tech.stdout + tech.stderr
    assert tech.returncode == 0, tech_out
    assert "Act 5" in tech_out
    assert "demo_e2e_mac.sh" in tech_out
    assert_mentions(tech_out, "shopapi")


def test_demo_e2e_scripts_dry_run() -> None:
    """Mac/QA/prod talk tracks: shopapi, not Flask. QA/prod scripts refuse Darwin."""
    mac = PROJECT_ROOT / "scripts" / "demo_e2e_mac.sh"
    qa = PROJECT_ROOT / "scripts" / "demo_e2e_rhel_qa.sh"
    prod = PROJECT_ROOT / "scripts" / "demo_e2e_rhel_prod.sh"
    reset = PROJECT_ROOT / "scripts" / "reset_demo_vms.sh"
    setup = PROJECT_ROOT / "scripts" / "setup_rhel_hosts.sh"

    mac_run = subprocess.run(
        [BASH, str(mac), "--dry-run", "--no-type", "--auto"],
        cwd=PROJECT_ROOT,
        capture_output=True,
        text=True,
    )
    mac_out = mac_run.stdout + mac_run.stderr
    if sys.platform == "darwin":
        assert mac_run.returncode == 0, mac_out
        assert_mentions(
            mac_out, "shopapi", "/feature-spool", "demo_e2e_rhel_qa.sh", "selinux/shopapi"
        )
        assert "LAB ONLY" in mac_out
        assert "soak_min_days" in mac_out
    else:
        # Off a Mac the talk track refuses by design (e2e_require_mac): assert the
        # refusal, so `make check` is a real offline health check on Linux too.
        assert mac_run.returncode != 0, mac_out
        assert "This script is the Mac talk track" in mac_out, mac_out
    mac_help = subprocess.run(
        [BASH, str(mac), "--help"],
        cwd=PROJECT_ROOT,
        capture_output=True,
        text=True,
    )
    mac_help_out = mac_help.stdout + mac_help.stderr
    assert mac_help.returncode == 0, mac_help_out
    assert "demo_present.sh" in mac_help_out

    qa_run = subprocess.run(
        [BASH, str(qa), "--dry-run", "--no-type", "--auto", "--part", "app"],
        cwd=PROJECT_ROOT,
        capture_output=True,
        text=True,
    )
    qa_out = qa_run.stdout + qa_run.stderr
    if sys.platform == "darwin":
        assert qa_run.returncode != 0, qa_out
        assert "not on the Mac" in qa_out
    prod_run = subprocess.run(
        [BASH, str(prod), "--dry-run", "--no-type", "--auto", "--part", "app"],
        cwd=PROJECT_ROOT,
        capture_output=True,
        text=True,
    )
    prod_out = prod_run.stdout + prod_run.stderr
    if sys.platform == "darwin":
        assert prod_run.returncode != 0, prod_out
        assert "not on the Mac" in prod_out

    reset_run = subprocess.run(
        [BASH, str(reset), "--dry-run"],
        cwd=PROJECT_ROOT,
        capture_output=True,
        text=True,
    )
    reset_out = reset_run.stdout + reset_run.stderr
    assert reset_run.returncode == 0, reset_out
    assert "shopapi" in reset_out.lower()
    assert "Would restore types-only selinux/shopapi/" in reset_out
    assert "8090" in reset_out
    assert "fcontext" in reset_out

    boot = subprocess.run(
        [BASH, str(setup), "bootstrap"],
        cwd=PROJECT_ROOT,
        capture_output=True,
        text=True,
    )
    boot_out = boot.stdout + boot.stderr
    assert boot.returncode == 0, boot_out
    assert_mentions(boot_out, "demo_bootstrap.sh --shopapi-only")


def test_e2e_quiet_ssh_wrap_skips_when_ssh_missing() -> None:
    """No SSH client: wrapping must no-op (eval hosts, empty PATH)."""
    with tempfile.TemporaryDirectory() as raw:
        bindir = Path(raw)
        src = shutil.which("bash")
        assert src
        (bindir / "bash").symlink_to(Path(src).resolve())
        env = os.environ.copy()
        env["PATH"] = str(bindir)
        result = subprocess.run(
            [
                str(bindir / "bash"),
                "-c",
                'set -euo pipefail; cd "$1"; E2E_DRY=0; '
                "source scripts/lib/training_lab_runner.sh; "
                "source scripts/lib/e2e_demo.sh; "
                "e2e_install_quiet_ssh; echo WRAP_OK",
                "_",
                str(PROJECT_ROOT),
            ],
            capture_output=True,
            text=True,
            env=env,
        )
    out = result.stdout + result.stderr
    assert result.returncode == 0, out
    assert "WRAP_OK" in result.stdout
    assert "Bad substitution" not in out


def test_demo_present_preflight_names_bootstrap() -> None:
    script = PROJECT_ROOT / "scripts" / "demo_present.sh"
    result = subprocess.run(
        [
            BASH,
            str(script),
            "--preflight",
            "--no-type",
            "--auto",
        ],
        cwd=PROJECT_ROOT,
        capture_output=True,
        text=True,
    )
    out = result.stdout + result.stderr
    if sys.platform != "linux":
        assert result.returncode != 0, out
        assert "make demo-bootstrap" in out
        return
    if result.returncode != 0:
        assert "make demo-bootstrap" in out, out


def test_soak_net_new_empty_manifest() -> None:
    manifest = PROJECT_ROOT / "config" / "myapp.manifest.yml"
    proc = subprocess.run(
        [
            sys.executable,
            str(PROJECT_ROOT / "cli" / "soak_net_new.py"),
            "--manifest",
            str(manifest),
        ],
        input="",
        cwd=PROJECT_ROOT,
        capture_output=True,
        text=True,
    )
    assert proc.returncode == 0, proc.stderr
    data = json.loads(proc.stdout)
    assert data["raw_count"] == 0
    assert data["net_new_count"] == 0


def test_app_manifest() -> None:
    loader = PROJECT_ROOT / "scripts" / "lib" / "app_manifest.py"
    demo_manifest = PROJECT_ROOT / "config" / "myapp.manifest.yml"
    example_manifest = PROJECT_ROOT / "config" / "payments.manifest.example.yml"
    shopapi_manifest = PROJECT_ROOT / "config" / "shopapi.manifest.yml"

    for path in (demo_manifest, example_manifest, shopapi_manifest):
        result = subprocess.run(
            ["python3", str(loader), "validate", str(path)],
            cwd=PROJECT_ROOT,
            capture_output=True,
            text=True,
        )
        assert result.returncode == 0, result.stderr or result.stdout

    wrapper = PROJECT_ROOT / "scripts" / "validate_app_manifest.sh"
    result = subprocess.run(
        ["bash", str(wrapper), str(demo_manifest)],
        cwd=PROJECT_ROOT,
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0, result.stderr or result.stdout
    assert "OK" in result.stdout

    export = subprocess.run(
        ["python3", str(loader), "shell-export", str(demo_manifest)],
        cwd=PROJECT_ROOT,
        capture_output=True,
        text=True,
    )
    assert export.returncode == 0, export.stderr
    assert "HTTP_PORT=8888" in export.stdout
    assert "PRIMARY_SERVICE=\"myapp.service\"" in export.stdout
    assert "PATHS_CSV=" in export.stdout
    assert "/var/opt/myapp" in export.stdout

    paths_csv = subprocess.run(
        ["python3", str(loader), "paths-csv", str(demo_manifest)],
        cwd=PROJECT_ROOT,
        capture_output=True,
        text=True,
    )
    assert paths_csv.returncode == 0, paths_csv.stderr
    assert "/opt/myapp" in paths_csv.stdout
    assert "myapp" in paths_csv.stdout
    assert "/opt/payments" not in paths_csv.stdout


def test_rpm_ops_parity() -> None:
    script = PROJECT_ROOT / "scripts" / "validate_rpm_ops_parity.sh"
    result = subprocess.run(
        ["bash", str(script)],
        cwd=PROJECT_ROOT,
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0, result.stderr or result.stdout


def test_version_consistency() -> None:
    script = PROJECT_ROOT / "scripts" / "validate_version_consistency.sh"
    result = subprocess.run(
        ["bash", str(script)],
        cwd=PROJECT_ROOT,
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0, result.stderr or result.stdout


def test_version_consistency_fails_on_payments_drift() -> None:
    script = PROJECT_ROOT / "scripts" / "validate_version_consistency.sh"
    vf = PROJECT_ROOT / "selinux" / "payments" / "policy_version.txt"
    original = vf.read_text(encoding="utf-8")
    try:
        vf.write_text("9.9.9\n", encoding="utf-8")
        result = subprocess.run(
            ["bash", str(script)],
            cwd=PROJECT_ROOT,
            capture_output=True,
            text=True,
        )
        assert result.returncode != 0, "expected failure when payments policy_version.txt drifts from .te"
    finally:
        vf.write_text(original, encoding="utf-8")


def test_scaffold_billing_no_myapp_leak() -> None:
    script = PROJECT_ROOT / "scripts" / "scaffold_sepolicy_module.sh"
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        (root / "selinux").mkdir()
        fake_bin = root / "bin"
        fake_bin.mkdir()
        fake_sep = fake_bin / "sepolicy-generate"
        fake_sep.write_text(
            "#!/usr/bin/env bash\n"
            "set -euo pipefail\n"
            "cat > \"${PWD}/billing.te\" <<'EOF'\n"
            "policy_module(billing, 1.0.0)\n"
            "type billing_t;\n"
            "EOF\n"
            "touch \"${PWD}/billing.fc\" \"${PWD}/billing.if\"\n",
            encoding="utf-8",
        )
        fake_sep.chmod(0o755)
        env = {
            **os.environ,
            "PATH": f"{fake_bin}:{os.environ.get('PATH', '')}",
            "SCAFFOLD_PROJECT_ROOT": str(root),
        }
        result = subprocess.run(
            ["bash", str(script), "billing", "billing_t"],
            cwd=PROJECT_ROOT,
            capture_output=True,
            text=True,
            env=env,
        )
        assert result.returncode == 0, result.stderr + result.stdout
        te = root / "selinux" / "billing" / "billing.te"
        assert te.is_file(), te
        text = te.read_text(encoding="utf-8")
        forbidden = ("myapp_t", "/opt/myapp", "Order Processor", "myapp_port_t")
        for needle in forbidden:
            assert needle not in text, f"scaffold leaked {needle!r} in {text}"


def test_deterministic_payments_manifest_check() -> None:
    script = PROJECT_ROOT / "scripts" / "run_deterministic_payments_check.sh"
    result = subprocess.run(
        ["bash", str(script)],
        cwd=PROJECT_ROOT,
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0, result.stderr + result.stdout


def test_version_consistency_fails_on_drift() -> None:
    script = PROJECT_ROOT / "scripts" / "validate_version_consistency.sh"
    spec = PROJECT_ROOT / "packaging" / "myapp-selinux.spec"
    original = spec.read_text(encoding="utf-8")
    try:
        spec.write_text(original.replace("Version:        %{modver}", "Version:        9.9.9"), encoding="utf-8")
        result = subprocess.run(
            ["bash", str(script)],
            cwd=PROJECT_ROOT,
            capture_output=True,
            text=True,
        )
        assert result.returncode != 0, "expected failure when spec Version is hardcoded"
    finally:
        spec.write_text(original, encoding="utf-8")


def test_promote_policy_version_from_te() -> None:
    """promote_to_selinux must rewrite selinux/policy_version.txt from policy_module() when missing in policy_out."""
    import tempfile

    version_sh = PROJECT_ROOT / "scripts" / "lib" / "version.sh"
    te_src = PROJECT_ROOT / "docs" / "examples" / "fixtures" / "skip_ai" / "generated" / "myapp.te"
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        policy_out = root / "policy_out"
        selinux = root / "selinux"
        policy_out.mkdir()
        selinux.mkdir()
        (policy_out / "myapp.te").write_text(te_src.read_text(encoding="utf-8"), encoding="utf-8")
        (policy_out / "myapp.fc").write_text("# fixture\n", encoding="utf-8")
        (selinux / "policy_version.txt").write_text("1.0.0\n", encoding="utf-8")
        script = f"""
set -euo pipefail
PROJECT_ROOT="{root}"
APP_NAME=myapp
POLICY_OUT="${{PROJECT_ROOT}}/policy_out"
SELINUX_DIR="${{PROJECT_ROOT}}/selinux"
source "{version_sh}"
match="$(policy_module_version_from_te "${{POLICY_OUT}}/myapp.te" "${{APP_NAME}}")"
echo "${{match}}" > "${{SELINUX_DIR}}/policy_version.txt"
"""
        result = subprocess.run(["bash", "-c", script], capture_output=True, text=True)
        assert result.returncode == 0, result.stderr
        got = (selinux / "policy_version.txt").read_text(encoding="utf-8").strip()
        expected = None
        for line in te_src.read_text(encoding="utf-8").splitlines():
            if line.startswith("policy_module(myapp,"):
                expected = line.split(",", 1)[1].strip().rstrip(")")
                break
        assert expected, "fixture te missing policy_module(myapp, …)"
        assert got == expected, f"expected {expected} from fixture te, got {got!r}"


def test_classify_fail_closed_json() -> None:
    script = PROJECT_ROOT / "scripts" / "classify_policy_blast_radius.sh"
    with tempfile.TemporaryDirectory() as tmp:
        base = Path(tmp) / "base.pp"
        cand = Path(tmp) / "cand.pp"
        base.write_bytes(b"FAKE")
        cand.write_bytes(b"FAKE")
        result = subprocess.run(
            ["bash", str(script), str(base), str(cand)],
            cwd=PROJECT_ROOT,
            capture_output=True,
            text=True,
            env={**os.environ, "CLASSIFY_SKIP_PODMAN": "1"},
        )
    assert result.returncode == 0, result.stderr
    payload = json.loads(result.stdout)
    assert payload["min_days"] == 7
    assert payload.get("fail_closed") is True
    assert "tier" in payload


def test_check_soak_auto_tier_fail_closed() -> None:
    """--auto-tier must not shorten soak when classifier returns fail_closed."""
    script = PROJECT_ROOT / "scripts" / "check_soak_ready.sh"
    base = PROJECT_ROOT / "tests/fixtures/blast_radius/_common/base.te"
    cand = PROJECT_ROOT / "tests/fixtures/blast_radius/low_private_type/cand.te"
    with tempfile.TemporaryDirectory() as tmp:
        marker = Path(tmp) / "marker"
        report = Path(tmp) / "selinux_deploy_report.json"
        report.write_text(
            json.dumps(
                {
                    "status": "pass",
                    "endpoints_exercised": True,
                    "domain_context_verified": True,
                }
            ),
            encoding="utf-8",
        )
        old_epoch = int(time.time()) - (8 * 86400)
        marker.write_text(str(old_epoch), encoding="utf-8")
        result = subprocess.run(
            [
                "bash",
                str(script),
                "--marker-file",
                str(marker),
                "--report-file",
                str(report),
                "--min-days",
                "7",
                "--max-avc",
                "9999",
                "--skip-if-unavailable",
                "--auto-tier",
                "--base-policy",
                str(base),
                "--candidate-policy",
                str(cand),
            ],
            cwd=PROJECT_ROOT,
            capture_output=True,
            text=True,
            env={**os.environ, "CLASSIFY_SKIP_PODMAN": "1"},
        )
    combined = result.stdout + result.stderr
    assert "Blast-radius classifier fail-closed" in combined, combined
    assert "soak minimum 7 day" in combined, combined


def test_skip_ai_fixture_sync() -> None:
    """Offline demo generated/ must match selinux/ (refresh_skip_ai_fixture.sh)."""
    fix = PROJECT_ROOT / "docs" / "examples" / "fixtures" / "skip_ai" / "generated"
    for name in ("myapp.te", "myapp.fc"):
        assert (fix / name).read_text(encoding="utf-8") == (
            PROJECT_ROOT / "selinux" / name
        ).read_text(encoding="utf-8"), f"Drift in skip_ai/generated/{name} — run refresh_skip_ai_fixture.sh"


DETERMINISTIC_CLASSIFICATION_VERDICTS = frozenset(
    {
        "fc_fix",
        "fc_drift",
        "private_port",
        "forbidden",
        "baseline",
        "interface",
        "direct",
        "toolchain_required",
        "boolean",
        "needs_review",
    }
)


def _deterministic_fixture_dirs(root: Path) -> list[Path]:
    return sorted(
        p
        for p in root.iterdir()
        if p.is_dir() and (p / "avc.log").is_file() and (p / "expected.json").is_file()
    )


def _deterministic_case_meta(case_dir: Path) -> dict:
    meta_path = case_dir / "case.meta.json"
    if meta_path.is_file():
        return json.loads(meta_path.read_text(encoding="utf-8"))
    return {"exit_code": 0}


def _deterministic_boolean_mock(case_dir: Path) -> dict | None:
    mock_path = case_dir / "boolean_mock.json"
    if not mock_path.is_file():
        return None
    return json.loads(mock_path.read_text(encoding="utf-8"))


def _deterministic_sepolgen_mock(case_dir: Path) -> dict | None:
    mock_path = case_dir / "sepolgen_mock.json"
    if not mock_path.is_file():
        return None
    return json.loads(mock_path.read_text(encoding="utf-8"))


def _deterministic_run_args(
    case_dir: Path,
    manifest: Path,
    te: Path,
    fc: Path,
    *,
    explain: bool,
    out_dir: Path,
) -> argparse.Namespace:
    meta = _deterministic_case_meta(case_dir)
    hints_path = PROJECT_ROOT / "config" / "boolean_hints.yml"
    rel = meta.get("boolean_hints")
    if rel:
        hints_path = case_dir / str(rel)
    return argparse.Namespace(
        avc_log=case_dir / "avc.log",
        manifest=manifest,
        existing_te=te,
        existing_fc=fc,
        out_dir=out_dir,
        app_name=None,
        bump_version=False,
        version_file=PROJECT_ROOT / "selinux" / "policy_version.txt",
        explain=explain,
        allow_degraded=False,
        allow_needs_review=False,
        allow_needs_review_perm=[],
        policy_kern=None,
        boolean_hints=hints_path,
        vendor_override=None,
    )


def _boolean_lookup_from_mock(mock: dict):
    from boolean_hints import BooleanLookupResult, BooleanMatch

    behavior = mock.get("behavior")
    if behavior == "match":
        matches = tuple(
            BooleanMatch(str(m["name"]), str(m.get("description") or ""))
            for m in mock.get("matches") or []
        )
        return BooleanLookupResult(status="matched", matches=matches)
    if behavior == "none":
        return BooleanLookupResult(status="none")
    if behavior == "unavailable":
        return BooleanLookupResult(
            status="unavailable",
            detail=str(mock.get("detail") or "boolean lookup unavailable"),
        )
    raise ValueError(f"unknown boolean_mock behavior {behavior!r}")


def _run_deterministic_gen(
    case_dir: Path,
    manifest: Path,
    te: Path,
    fc: Path,
    *,
    explain: bool,
    out_dir: Path,
    mock: dict | None,
    boolean_mock: dict | None,
    allow_needs_review: bool = False,
    allow_needs_review_perm: list[str] | None = None,
    allow_degraded: bool = False,
) -> tuple[int, str, str]:
    """Run deterministic_gen; in-process when fixture mocks are present."""
    import io
    from contextlib import ExitStack, redirect_stderr, redirect_stdout
    from unittest.mock import patch

    import deterministic_gen as dg

    args = _deterministic_run_args(
        case_dir, manifest, te, fc, explain=explain, out_dir=out_dir
    )
    args.allow_needs_review = allow_needs_review
    args.allow_needs_review_perm = list(allow_needs_review_perm or [])
    args.allow_degraded = allow_degraded
    stdout = io.StringIO()
    stderr = io.StringIO()

    def _invoke() -> int:
        with redirect_stdout(stdout), redirect_stderr(stderr):
            return dg.run(args)

    extra_flags: list[str] = []
    if allow_needs_review:
        extra_flags.append("--allow-needs-review")
    if allow_degraded:
        extra_flags.append("--allow-degraded")
    for perm in args.allow_needs_review_perm:
        extra_flags.extend(["--allow-needs-review-perm", perm])

    if not mock and not boolean_mock:
        gen = PROJECT_ROOT / "cli" / "deterministic_gen.py"
        result = subprocess.run(
            [
                sys.executable,
                str(gen),
                *(["--explain"] if explain else []),
                "--avc-log",
                str(args.avc_log),
                "--manifest",
                str(manifest),
                "--existing-te",
                str(te),
                "--existing-fc",
                str(fc),
                "--out-dir",
                str(out_dir),
                *extra_flags,
            ],
            cwd=PROJECT_ROOT,
            capture_output=True,
            text=True,
        )
        return result.returncode, result.stdout, result.stderr

    with ExitStack() as stack:
        if mock:
            behavior = mock.get("behavior")
            if behavior == "match":
                rendered = mock["rendered"]
                note = mock.get("note", "mock interface")

                def _fake_match(*_a, **_k):
                    return (rendered, note)

                stack.enter_context(patch.object(dg, "try_sepolgen_interface", _fake_match))
            elif behavior == "no_match":
                stack.enter_context(patch.object(dg, "try_sepolgen_interface", return_value=None))
            elif behavior == "unavailable":
                stack.enter_context(
                    patch.object(
                        dg, "try_sepolgen_interface", return_value=dg.SEPOLGEN_UNAVAILABLE
                    )
                )
            else:
                raise ValueError(f"{case_dir.name}: unknown sepolgen_mock behavior {behavior!r}")
        if boolean_mock:

            def _fake_bool(*_a, **_k):
                return _boolean_lookup_from_mock(boolean_mock)

            import boolean_hints as bh

            stack.enter_context(patch.object(bh, "lookup_booleans_for_need", _fake_bool))
        code = _invoke()

    return code, stdout.getvalue(), stderr.getvalue()


def test_deterministic_verdict_fixture_coverage() -> None:
    """Every classification verdict has at least one golden fixture row."""
    root = PROJECT_ROOT / "docs" / "examples" / "fixtures" / "deterministic"
    seen: set[str] = set()
    for case_dir in _deterministic_fixture_dirs(root):
        for row in json.loads((case_dir / "expected.json").read_text(encoding="utf-8")):
            seen.add(row["verdict"])
    missing = DETERMINISTIC_CLASSIFICATION_VERDICTS - seen
    assert not missing, f"Add fixtures for verdict(s): {sorted(missing)}"


def test_needs_review_hits() -> None:
    """NEEDS_REVIEW_RULES matches execmem/capabilities/foreign transitions only."""
    sys.path.insert(0, str(PROJECT_ROOT / "cli"))
    from policy_rules import needs_review_hits

    module = {"myapp_t", "myapp_backend_t"}
    assert needs_review_hits(
        "myapp_t", "myapp_t", "process", frozenset({"execmem"}), module
    ) == (("process", "execmem"),)
    assert (
        needs_review_hits("myapp_t", "myapp_t", "process", frozenset({"getattr"}), module)
        == ()
    )
    assert needs_review_hits(
        "myapp_t", "unconfined_t", "process", frozenset({"transition"}), module
    ) == (("process", "transition"),)
    assert (
        needs_review_hits(
            "myapp_t", "myapp_backend_t", "process", frozenset({"transition"}), module
        )
        == ()
    )
    assert needs_review_hits(
        "myapp_t", "myapp_t", "capability", frozenset({"dac_override"}), module
    ) == (("capability", "dac_override"),)
    from policy_rules import NEEDS_REVIEW_RATIONALE, NEEDS_REVIEW_RULES

    rule_keys = {(tclass, perm) for tclass, perm, _scope in NEEDS_REVIEW_RULES}
    assert rule_keys == set(NEEDS_REVIEW_RATIONALE), (
        "NEEDS_REVIEW_RATIONALE keys must match NEEDS_REVIEW_RULES (tclass, perm)"
    )


def test_deterministic_fixture_classify() -> None:
    """Golden verdict checks for deterministic_gen --explain and full generation."""
    root = PROJECT_ROOT / "docs" / "examples" / "fixtures" / "deterministic"
    manifest = PROJECT_ROOT / "config" / "myapp.manifest.yml"
    te = PROJECT_ROOT / "selinux" / "myapp.te"
    fc = PROJECT_ROOT / "selinux" / "myapp.fc"

    for case_dir in _deterministic_fixture_dirs(root):
        case = case_dir.name
        meta = _deterministic_case_meta(case_dir)
        mock = _deterministic_sepolgen_mock(case_dir)
        boolean_mock = _deterministic_boolean_mock(case_dir)
        expected = json.loads((case_dir / "expected.json").read_text(encoding="utf-8"))
        want_exit = int(meta.get("exit_code", 0))

        code, out, err = _run_deterministic_gen(
            case_dir,
            manifest,
            te,
            fc,
            explain=True,
            out_dir=case_dir / "_out",
            mock=mock,
            boolean_mock=boolean_mock,
        )
        combined = out + err
        assert code == want_exit, f"{case}: explain exit {code}, want {want_exit}\n{combined}"
        for needle in meta.get("stderr_substrings", []):
            assert needle in combined, f"{case}: stderr missing {needle!r}\n{combined}"

        gen_code, gen_out, gen_err = _run_deterministic_gen(
            case_dir,
            manifest,
            te,
            fc,
            explain=False,
            out_dir=case_dir / "_out",
            mock=mock,
            boolean_mock=boolean_mock,
        )
        assert gen_code == want_exit, (
            f"{case}: generation exit {gen_code}, want {want_exit}\n{gen_err}{gen_out}"
        )
        findings_path = case_dir / "_out" / "findings.json"
        assert findings_path.is_file(), f"{case}: missing findings.json"
        payload = json.loads(findings_path.read_text(encoding="utf-8"))
        rows = payload["findings"] if isinstance(payload, dict) else payload
        for want in expected:
            matched = [
                row
                for row in rows
                if row.get("verdict") == want["verdict"] and row.get("tgt") == want["tgt"]
            ]
            assert matched, f"{case}: missing {want} in {rows}"
            if want.get("boolean"):
                assert any(row.get("boolean") == want["boolean"] for row in matched), (
                    f"{case}: boolean name mismatch for {want}"
                )
            if want.get("next_action"):
                assert any(row.get("next_action") == want["next_action"] for row in matched), (
                    f"{case}: next_action mismatch for {want} in {matched}"
                )
            if "port" in want:
                assert any(row.get("port") == want["port"] for row in matched), (
                    f"{case}: port mismatch for {want} in {matched}"
                )
        if want_exit != 0:
            assert payload.get("generation_blocked") is True, f"{case}: expected generation_blocked"
            if case == "12-execmem-review":
                summary = (case_dir / "_out" / "pr_summary.md").read_text(encoding="utf-8")
                assert summary.startswith("### Needs review (domain-weakening permissions)"), (
                    f"{case}: needs_review heading must come first in pr_summary.md"
                )
                assert "execmem" in summary
                assert "--allow-needs-review" in summary
                assert "W^X" in summary or "writable" in summary.lower()
                te_blocked = case_dir / "_out" / "myapp.te"
                if te_blocked.is_file():
                    assert "execmem" not in te_blocked.read_text(encoding="utf-8"), (
                        f"{case}: blocked run must not emit execmem in the .te"
                    )
                row = next(r for r in rows if r.get("verdict") == "needs_review")
                assert "execmem" in (row.get("rendered") or "")
                assert "allow myapp_t self:process execmem;" in (row.get("rendered") or "")
                with tempfile.TemporaryDirectory() as tmp:
                    tmp_path = Path(tmp)
                    allow_code, allow_out, allow_err = _run_deterministic_gen(
                        case_dir,
                        manifest,
                        te,
                        fc,
                        explain=False,
                        out_dir=tmp_path,
                        mock=mock,
                        boolean_mock=boolean_mock,
                        allow_needs_review=True,
                    )
                    allow_combined = allow_out + allow_err
                    assert allow_code == 0, f"{case}: --allow-needs-review exit {allow_code}\n{allow_combined}"
                    allow_te = (tmp_path / "myapp.te").read_text(encoding="utf-8")
                    assert "allow myapp_t self:process execmem;" in allow_te
                    assert "# Needs review" in allow_te
                    allow_summary = (tmp_path / "pr_summary.md").read_text(encoding="utf-8")
                    assert "### Needs review (domain-weakening permissions)" in allow_summary
                    assert "execmem" in allow_summary
                    allow_findings = json.loads((tmp_path / "findings.json").read_text(encoding="utf-8"))
                    assert allow_findings.get("generation_blocked") is False
            continue

        if case == "13-cgroup-omit":
            out_te = (case_dir / "_out" / "myapp.te").read_text(encoding="utf-8")
            assert "cgroup_t" not in out_te, f"{case}: must not emit cgroup_t in the .te"
            with tempfile.TemporaryDirectory() as tmp:
                tmp_path = Path(tmp)
                deg_code, deg_out, deg_err = _run_deterministic_gen(
                    case_dir,
                    manifest,
                    te,
                    fc,
                    explain=False,
                    out_dir=tmp_path,
                    mock=mock,
                    boolean_mock=boolean_mock,
                    allow_degraded=True,
                )
                assert deg_code == 0, f"{case}: --allow-degraded exit {deg_code}\n{deg_out}{deg_err}"
                deg_te = (tmp_path / "myapp.te").read_text(encoding="utf-8")
                assert "cgroup_t" not in deg_te, (
                    f"{case}: --allow-degraded must still omit cgroup_t"
                )
        if case == "02-port-bind":
            summary = (case_dir / "_out" / "pr_summary.md").read_text(encoding="utf-8")
            assert "add_manifest_port" in summary, f"{case}: pr_summary missing next_action"
            assert "port: 8888" in summary, f"{case}: pr_summary missing selinux_ports snippet"
        if case == "01-mislabeled-var-lib":
            out_fc = (case_dir / "_out" / "myapp.fc").read_text(encoding="utf-8")
            assert out_fc == fc.read_text(encoding="utf-8"), (
                f"{case}: .fc must not grow per-file lines when directory regex already covers path"
            )
        if case == "06-fc-missing-line":
            out_fc = (case_dir / "_out" / "myapp.fc").read_text(encoding="utf-8")
            assert "/opt/myapp/cache/data" in out_fc, f"{case}: expected new .fc line for cache path"
        if case == "04-boolean-network-connect":
            digest_a = hashlib.sha256(
                (case_dir / "_out" / "myapp.te").read_bytes()
                + (case_dir / "_out" / "findings.json").read_bytes()
            ).hexdigest()
            code2, _, _ = _run_deterministic_gen(
                case_dir,
                manifest,
                te,
                fc,
                explain=False,
                out_dir=case_dir / "_out2",
                mock=mock,
                boolean_mock=boolean_mock,
            )
            assert code2 == 0
            digest_b = hashlib.sha256(
                (case_dir / "_out2" / "myapp.te").read_bytes()
                + (case_dir / "_out2" / "findings.json").read_bytes()
            ).hexdigest()
            assert digest_a == digest_b, f"{case}: non-deterministic output between runs"
        if case in ("04-boolean-network-connect", "10-boolean-hint"):
            out_te = (case_dir / "_out" / "myapp.te").read_text(encoding="utf-8")
            assert "http_port_t" not in out_te, f"{case}: must not add permanent allow on http_port_t"
            row = next(r for r in rows if r.get("verdict") == "boolean")
            assert row.get("boolean") == "httpd_can_network_connect"
            assert "setsebool -P" in (row.get("rendered") or "")
            assert payload.get("host_admin_actions"), f"{case}: expected host_admin_actions in findings"
        if case == "10-boolean-hint":
            row10 = next(r for r in rows if r.get("verdict") == "boolean")
            assert row10.get("engine") == "curated_override", row10


def test_payments_onboarding_module() -> None:
    """Second app: manifest example + selinux/payments with shipped .if."""
    mod = PROJECT_ROOT / "selinux" / "payments"
    for name in ("payments.te", "payments.fc", "payments.if"):
        assert (mod / name).is_file(), f"missing {mod / name}"
    if_text = (mod / "payments.if").read_text(encoding="utf-8")
    assert "interface(`payments_read_public_state'" in if_text
    loader = PROJECT_ROOT / "scripts" / "lib" / "app_manifest.py"
    result = subprocess.run(
        ["python3", str(loader), "json", str(PROJECT_ROOT / "config" / "payments.manifest.example.yml")],
        cwd=PROJECT_ROOT,
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0, result.stderr
    norm = json.loads(result.stdout)
    assert norm["policy"]["module_dir"] == "selinux/payments"


def test_export_app_avcs_requires_paths() -> None:
    avc_lib = PROJECT_ROOT / "scripts" / "lib" / "avc_query.sh"
    result = subprocess.run(
        [
            "bash",
            "-c",
            f"source '{avc_lib}' && export_app_avcs_to_file /tmp/x.log boot payments_t '' ''",
        ],
        cwd=PROJECT_ROOT,
        capture_output=True,
        text=True,
    )
    assert result.returncode != 0
    assert "paths_csv required" in result.stderr


def test_avc_filter_keeps_pathless_bind_drops_passwd() -> None:
    avc_lib = PROJECT_ROOT / "scripts" / "lib" / "avc_query.sh"
    result = subprocess.run(
        [
            "bash",
            "-c",
            f"""
source '{avc_lib}'
avc_filter_lines_by_paths '/opt/shopapi,/var/lib/shopapi' 'shopapi_t' <<'AVC'
type=AVC msg=audit(1): avc:  denied  {{ name_bind }} for  pid=1 comm="java" src=8091 scontext=system_u:system_r:shopapi_t:s0 tcontext=system_u:object_r:unreserved_port_t:s0 tclass=tcp_socket permissive=1
type=AVC msg=audit(1): avc:  denied  {{ execmem }} for  pid=1 comm="java" scontext=system_u:system_r:shopapi_t:s0 tcontext=system_u:system_r:shopapi_t:s0 tclass=process permissive=1
type=AVC msg=audit(1): avc:  denied  {{ read }} for  pid=1 comm="java" name="passwd" scontext=system_u:system_r:shopapi_t:s0 tcontext=system_u:object_r:passwd_file_t:s0 tclass=file permissive=1
type=AVC msg=audit(1): avc:  denied  {{ append }} for  pid=1 comm="java" name="state.txt" scontext=system_u:system_r:shopapi_t:s0 tcontext=system_u:object_r:shopapi_var_lib_t:s0 tclass=file permissive=1
type=AVC msg=audit(1): avc:  denied  {{ open }} for  pid=1 comm="java" path="/opt/shopapi/lib/libjli.so" scontext=system_u:system_r:shopapi_t:s0 tcontext=system_u:object_r:shopapi_exec_t:s0 tclass=file permissive=1
type=AVC msg=audit(1): avc:  denied  {{ open }} for  pid=1 comm="java" path="/etc/passwd" scontext=system_u:system_r:shopapi_t:s0 tcontext=system_u:object_r:passwd_file_t:s0 tclass=file permissive=1
type=AVC msg=audit(1): avc:  denied  {{ write }} for  pid=1 comm="http-nio-0.0.0." name="shopapi" scontext=system_u:system_r:shopapi_t:s0 tcontext=unconfined_u:object_r:var_spool_t:s0 tclass=dir permissive=0
AVC
""",
        ],
        cwd=PROJECT_ROOT,
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0, result.stderr
    out = result.stdout
    assert "name_bind" in out
    assert "execmem" in out
    assert "state.txt" in out
    assert "libjli.so" in out
    assert "passwd" not in out
    assert "var_spool_t" in out


def test_boolean_policy_render() -> None:
    from boolean_hints import BooleanMatch, render_boolean_finding, resolve_booleans_for_need

    rendered, note, names = render_boolean_finding(
        (BooleanMatch("httpd_can_network_connect", "Allow httpd to connect to http ports"),)
    )
    assert rendered == "setsebool -P httpd_can_network_connect on"
    assert "-P" in rendered
    assert names == "httpd_can_network_connect"
    assert "Host-wide" in note

    multi = (
        BooleanMatch("aaa_first", "desc a"),
        BooleanMatch("bbb_second", "desc b"),
    )
    rendered_m, note_m, names_m = render_boolean_finding(multi)
    assert "setsebool -P aaa_first on" in rendered_m
    assert "setsebool -P bbb_second on" in rendered_m
    assert "aaa_first" in names_m and "bbb_second" in names_m
    assert "choose deliberately" in note_m


def test_boolean_triage_two_matches() -> None:
    from boolean_hints import BooleanLookupResult, BooleanMatch, resolve_booleans_for_need

    need = AccessNeed(
        "myapp_t",
        "http_port_t",
        "tcp_socket",
        frozenset({"name_connect"}),
    )

    def _fake(_need, *, policy_kern=None):
        return BooleanLookupResult(
            status="matched",
            matches=(
                BooleanMatch("aaa_first", "desc a"),
                BooleanMatch("bbb_second", "desc b"),
            ),
        )

    out = resolve_booleans_for_need(need, [], {}, policy_lookup=_fake)
    assert out.status == "matched"
    assert [m.name for m in out.matches] == ["aaa_first", "bbb_second"]
    from boolean_hints import render_boolean_finding

    rendered, note, names = render_boolean_finding(out.matches)
    assert "setsebool -P aaa_first on" in rendered
    assert "setsebool -P bbb_second on" in rendered
    assert "choose deliberately" in note
    assert "aaa_first" in names and "bbb_second" in names


def test_boolean_curated_when_policy_unavailable() -> None:
    from boolean_hints import BooleanLookupResult, resolve_booleans_for_need

    need = AccessNeed("payments_t", "http_port_t", "tcp_socket", frozenset({"name_connect"}))
    hints = [
        {
            "boolean": "httpd_can_network_connect",
            "note": "site",
            "match": {"tgt_type": "http_port_t", "tclass": "tcp_socket", "perms": ["name_connect"]},
        }
    ]

    def _unavail(_need, *, policy_kern=None):
        return BooleanLookupResult(status="unavailable", detail="offline")

    out = resolve_booleans_for_need(need, hints, {"app_name": "payments", "domain": "payments_t"}, policy_lookup=_unavail)
    assert out.status == "matched"
    assert out.matches[0].name == "httpd_can_network_connect"


def test_boolean_hint_yaml_still_documents_patterns() -> None:
    from boolean_hints import load_boolean_hints

    hints = load_boolean_hints(PROJECT_ROOT / "config" / "boolean_hints.yml")
    assert hints and hints[0].get("boolean") == "httpd_can_network_connect"
    assert "src_type" not in (hints[0].get("match") or {})


def test_fc_labeling_drift_detection() -> None:
    from fc_labeling import existing_fc_covers, filter_fc_fix_lines, strip_redundant_fc_lines

    baseline = (PROJECT_ROOT / "selinux" / "myapp.fc").read_text(encoding="utf-8")
    path = "/var/lib/myapp/data.log"
    assert existing_fc_covers(path, "myapp_var_lib_t", baseline)

    redundant_line = (
        r"/var/lib/myapp/data\.log    gen_context(system_u:object_r:myapp_var_lib_t,s0)"
    )
    kept, dropped = filter_fc_fix_lines(baseline, [redundant_line], {redundant_line: path})
    assert not kept
    assert dropped == [redundant_line]

    bloated = baseline.rstrip() + "\n" + redundant_line + "\n"
    trimmed = strip_redundant_fc_lines(baseline, bloated)
    assert redundant_line not in trimmed
    assert "/var/lib/myapp(/.*)?" in trimmed


def test_rhel_runtime_file_contexts() -> None:
    myapp_fc = (PROJECT_ROOT / "selinux" / "myapp.fc").read_text(encoding="utf-8")
    assert "/run/myapp(/.*)?" in myapp_fc
    assert "/var/run/myapp(/.*)?" in myapp_fc
    shopapi_fc = (PROJECT_ROOT / "selinux" / "shopapi" / "shopapi.fc").read_text(encoding="utf-8")
    assert "/run/shopapi(/.*)?" in shopapi_fc
    unit = (PROJECT_ROOT / "demo" / "shopapi" / "shopapi.service").read_text(encoding="utf-8")
    assert "NoNewPrivileges=false" in unit
    assert "SELinuxContext=" in unit
    assert "ExecStart=/opt/shopapi/bin/java" in unit


def _tune_report_env(extra: dict[str, str] | None = None) -> dict[str, str]:
    env = os.environ.copy()
    for key in list(env):
        if key.startswith("VENDOR_CHECK_"):
            del env[key]
    env["VENDOR_CHECK_MOCK"] = "1"
    env["VENDOR_CHECK_SEMODULE_L"] = "tomcat"
    env["VENDOR_CHECK_RPM_QA"] = ""
    env["VENDOR_CHECK_DNF_AVAILABLE"] = ""
    env["VENDOR_CHECK_PS_EZ"] = ""
    if extra:
        env.update(extra)
    return env


def test_tune_report() -> None:
    fixture = PROJECT_ROOT / "docs" / "examples" / "fixtures" / "tune_report" / "tomcat"
    avc = fixture / "avc.log"
    expected = json.loads((fixture / "expected.json").read_text(encoding="utf-8"))
    script = PROJECT_ROOT / "scripts" / "dev_generate_policy.sh"
    with tempfile.TemporaryDirectory() as tmp:
        out_dir = Path(tmp) / "policy_out"
        result = subprocess.run(
            [
                BASH,
                str(script),
                "--tune-report",
                "--skip-export",
                "--app-name",
                "tomcat",
                "--unit",
                "tomcat.service",
                "--avc-log",
                str(avc),
                "--out-dir",
                str(out_dir),
                "--app-root",
                str(PROJECT_ROOT),
            ],
            cwd=PROJECT_ROOT,
            capture_output=True,
            text=True,
            env=_tune_report_env(),
        )
        combined = result.stdout + result.stderr
        assert result.returncode == 0, combined
        report_path = out_dir / "tune_report.md"
        assert report_path.is_file(), combined
        report = report_path.read_text(encoding="utf-8")
        combined_text = combined + "\n" + report
        for command in expected["commands"]:
            assert command in combined_text, f"missing {command!r} in:\n{combined_text}"
        assert "Not resolvable by tuning" in report
        assert expected["unresolvable_tgt"] in report
        assert "policy_module" not in report
        te_files = list(out_dir.glob("*.te")) + list(out_dir.glob("*.fc")) + list(out_dir.glob("*.pp"))
        assert te_files == [], f"tune-report must not write a policy module: {te_files}"


def test_tune_report_skip_no_selinux() -> None:
    script = PROJECT_ROOT / "scripts" / "dev_generate_policy.sh"
    python = shutil.which("python3")
    bash = shutil.which("bash") or BASH
    assert python and bash
    with tempfile.TemporaryDirectory() as tmp:
        bindir = Path(tmp) / "bin"
        bindir.mkdir()
        os.symlink(python, bindir / "python3")
        os.symlink(bash, bindir / "bash")
        for name in (
            "grep",
            "cut",
            "head",
            "cat",
            "mkdir",
            "mktemp",
            "dirname",
            "basename",
            "rm",
            "sort",
            "tr",
            "uname",
            "id",
            "chmod",
            "ln",
            "cp",
            "mv",
            "tee",
            "awk",
            "sed",
        ):
            src = shutil.which(name)
            if src:
                dest = bindir / name
                if not dest.exists():
                    os.symlink(src, dest)
        out_dir = Path(tmp) / "out"
        env = os.environ.copy()
        for key in list(env):
            if key.startswith("VENDOR_CHECK_"):
                del env[key]
        env["PATH"] = str(bindir)
        result = subprocess.run(
            [
                BASH,
                str(script),
                "--tune-report",
                "--app-name",
                "tomcat",
                "--out-dir",
                str(out_dir),
                "--app-root",
                str(PROJECT_ROOT),
            ],
            cwd=PROJECT_ROOT,
            capture_output=True,
            text=True,
            env=env,
        )
        combined = result.stdout + result.stderr
        assert result.returncode == 0, combined
        report_text = ""
        report_file = out_dir / "tune_report.md"
        if report_file.is_file():
            report_text = report_file.read_text(encoding="utf-8")
        blob = (combined + "\n" + report_text).lower()
        assert "tune-report skipped" in blob, blob
        assert list(out_dir.glob("*.te")) == []


def test_force_reason_recorded() -> None:
    gen = PROJECT_ROOT / "scripts" / "dev_generate_policy.sh"
    bare = subprocess.run(
        [BASH, str(gen), "--force"],
        cwd=PROJECT_ROOT,
        capture_output=True,
        text=True,
    )
    bare_out = bare.stdout + bare.stderr
    assert bare.returncode != 0, bare_out
    assert "reason" in bare_out.lower()

    case_dir = PROJECT_ROOT / "docs" / "examples" / "fixtures" / "deterministic" / "11-private-getopt"
    with tempfile.TemporaryDirectory() as tmp:
        out_dir = Path(tmp)
        override_path = out_dir / "vendor_override.json"
        override = {
            "reason": "private connector layout vs jws6_tomcat",
            "situation": "loaded",
            "module": "jws6_tomcat",
            "package": "jws6-tomcat-selinux",
            "class": "tomcat",
        }
        override_path.write_text(json.dumps(override, indent=2) + "\n", encoding="utf-8")
        result = subprocess.run(
            [
                sys.executable,
                str(PROJECT_ROOT / "cli" / "deterministic_gen.py"),
                "--avc-log",
                str(case_dir / "avc.log"),
                "--manifest",
                str(PROJECT_ROOT / "config" / "myapp.manifest.yml"),
                "--existing-te",
                str(PROJECT_ROOT / "selinux" / "myapp.te"),
                "--existing-fc",
                str(PROJECT_ROOT / "selinux" / "myapp.fc"),
                "--out-dir",
                str(out_dir),
                "--vendor-override",
                str(override_path),
            ],
            cwd=PROJECT_ROOT,
            capture_output=True,
            text=True,
        )
        combined = result.stdout + result.stderr
        assert result.returncode == 0, combined
        findings = json.loads((out_dir / "findings.json").read_text(encoding="utf-8"))
        assert findings["vendor_override"]["reason"] == override["reason"]
        assert findings["vendor_override"]["situation"] == "loaded"
        assert findings["vendor_override"]["module"] == "jws6_tomcat"
        summary = (out_dir / "pr_summary.md").read_text(encoding="utf-8")
        assert "Vendor policy override (higher scrutiny)" in summary
        assert override["reason"] in summary
        assert summary.find("Vendor policy override") < summary.find("### Network Bindings")

        pr_summary = out_dir / "pr_summary.md"
        avc_log = out_dir / "avc.log"
        avc_log.write_text((case_dir / "avc.log").read_text(encoding="utf-8"), encoding="utf-8")
        output = out_dir / "pr_body.md"
        assembled = subprocess.run(
            [
                BASH,
                str(PROJECT_ROOT / "scripts" / "assemble_pr_body.sh"),
                "--template",
                str(PROJECT_ROOT / ".github" / "PULL_REQUEST_TEMPLATE" / "selinux_policy_review.md"),
                "--pr-summary",
                str(pr_summary),
                "--avc-log",
                str(avc_log),
                "--output",
                str(output),
                "--app-name",
                "myapp",
                "--skip-policy-diff",
            ],
            cwd=PROJECT_ROOT,
            capture_output=True,
            text=True,
        )
        assert assembled.returncode == 0, assembled.stdout + assembled.stderr
        body = output.read_text(encoding="utf-8")
        assert "HIGHER SCRUTINY" in body
        assert override["reason"] in body
        assert body.find("HIGHER SCRUTINY") < body.find("### 2.5 Policy access delta")
        assert "<!-- AUTO:VENDOR_OVERRIDE -->" not in body


def _load_book_builder():
    """Import tools/book/build.py by path (it is not a package)."""
    import importlib.util

    path = PROJECT_ROOT / "tools" / "book" / "build.py"
    spec = importlib.util.spec_from_file_location("book_build", path)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    sys.modules["book_build"] = module
    spec.loader.exec_module(module)
    return module


def test_book_builder_contract() -> None:
    """The generator builds the real book: pages, search index, no problems."""
    module = _load_book_builder()
    book_dir = PROJECT_ROOT / "book"
    book = module.load_book(book_dir)
    with tempfile.TemporaryDirectory() as tmp:
        out = Path(tmp)
        problems, warnings = module.build(book, book_dir, out)
        assert not problems, problems
        assert not warnings, warnings
        assert (out / "index.html").is_file()
        assert (out / "assets" / "book.css").is_file()
        assert (out / ".nojekyll").is_file()
        index = json.loads((out / "search.json").read_text())
        assert len(index) == len(book.entries)
        for page in book.entries:
            html_text = (out / f"{page.slug}.html").read_text()
            assert "<h1" in html_text, page.file
            assert f'<a href="{page.slug}.html"' in html_text or page.slug == "index"
        assert not module.check(book, book_dir)[0]


def test_book_builder_fails_loudly() -> None:
    """Unsupported or broken markdown is a build error, never silence."""
    module = _load_book_builder()
    config = """title = "Test Book"
[[front]]
file = "index.md"
title = "Cover"
[[part]]
title = "Part I. Test"
chapters = [ { file = "01-one.md", title = "One" } ]
"""
    with tempfile.TemporaryDirectory() as tmp:
        book_dir = Path(tmp)
        (book_dir / "assets").mkdir()
        (book_dir / "assets" / "book.css").write_text("")
        (book_dir / "book.toml").write_text(config)
        (book_dir / "index.md").write_text("# Test Book\n")

        (book_dir / "01-one.md").write_text("# One\n\n```bash\nunclosed\n")
        problems, _ = module.build(module.load_book(book_dir), book_dir, book_dir / "out")
        assert any("unclosed code fence" in problem for problem in problems), problems

        (book_dir / "01-one.md").write_text("# One\n\n::: bogus\nbody\n:::\n")
        problems, _ = module.build(module.load_book(book_dir), book_dir, book_dir / "out")
        assert any("unknown callout type" in problem for problem in problems), problems

        (book_dir / "01-one.md").write_text("# One\n\nSee [nothing](no-such-page.md).\n")
        problems, _ = module.check(module.load_book(book_dir), book_dir)
        assert any("not in book.toml" in problem for problem in problems), problems

        (book_dir / "01-one.md").write_text("# One\n\nSee [gone](repo:no/such/file.te).\n")
        problems, _ = module.check(module.load_book(book_dir), book_dir)
        assert any("does not exist" in problem for problem in problems), problems

        # a code span that names a repository path is a claim; a stale path fails the build
        (book_dir / "01-one.md").write_text("# One\n\nRun `scripts/no_such_script.sh`.\n")
        problems, _ = module.check(module.load_book(book_dir), book_dir)
        assert any("names a repository path" in problem for problem in problems), problems

        # ... while an on-host or gitignored runtime path is not a repository path
        (book_dir / "01-one.md").write_text(
            "# One\n\nWritten to `ansible/inventory.dev.yml` on the controller.\n"
        )
        problems, _ = module.check(module.load_book(book_dir), book_dir)
        assert not any("names a repository path" in problem for problem in problems), problems

        # a command that runs a library module is not a command
        (book_dir / "01-one.md").write_text(
            "# One\n\n```bash\n$ python3 cli/avc_preprocess.py --in x\n```\n"
        )
        problems, _ = module.check(module.load_book(book_dir), book_dir)
        assert any("__main__ guard" in problem for problem in problems), problems

        # ... while a module that does define a CLI passes
        (book_dir / "01-one.md").write_text(
            "# One\n\n```bash\n$ python3 cli/verify_avc_coverage.py --help\n```\n"
        )
        problems, _ = module.check(module.load_book(book_dir), book_dir)
        assert not any("__main__ guard" in problem for problem in problems), problems


def main() -> int:
    tests = [
        ("prompts", test_prompts),
        ("avc_parsing", test_avc_parsing),
        ("perm_merge", test_perm_merge),
        ("type_extraction_dedup", test_type_extraction_dedup),
        ("subtract_existing", test_subtract_existing),
        ("net_new_detection", test_net_new_detection),
        ("preprocess_stats", test_preprocess_stats),
        ("prompt_uses_summary", test_prompt_uses_summary),
        ("no_changes_needed_summary", test_no_changes_needed_summary),
        ("pr_summary_split_and_validate", test_pr_summary_split_and_validate),
        ("policy_json_validation", test_policy_json_validation),
        ("version_bump", test_version_bump),
        ("assemble_pr_body_policy_diff_section", test_assemble_pr_body_policy_diff_section),
        ("assemble_pr_body", test_assemble_pr_body),
        ("verify_file_contexts_skip", test_verify_file_contexts_skip),
        ("check_soak_ready_gate", test_check_soak_ready_gate),
        ("monitor_avc_skip", test_monitor_avc_skip),
        ("vendor_policy_check", test_vendor_policy_check),
        ("demo_present_dry_run", test_demo_present_dry_run),
        ("demo_e2e_scripts_dry_run", test_demo_e2e_scripts_dry_run),
        ("e2e_quiet_ssh_wrap_skips_when_ssh_missing", test_e2e_quiet_ssh_wrap_skips_when_ssh_missing),
        ("demo_present_preflight_names_bootstrap", test_demo_present_preflight_names_bootstrap),
        ("soak_net_new_empty_manifest", test_soak_net_new_empty_manifest),
        ("app_manifest", test_app_manifest),
        ("rpm_ops_parity", test_rpm_ops_parity),
        ("version_consistency", test_version_consistency),
        ("version_consistency_fails_on_drift", test_version_consistency_fails_on_drift),
        ("version_consistency_fails_on_payments_drift", test_version_consistency_fails_on_payments_drift),
        ("scaffold_billing_no_myapp_leak", test_scaffold_billing_no_myapp_leak),
        ("deterministic_payments_manifest_check", test_deterministic_payments_manifest_check),
        ("promote_policy_version_from_te", test_promote_policy_version_from_te),
        ("classify_fail_closed_json", test_classify_fail_closed_json),
        ("check_soak_auto_tier_fail_closed", test_check_soak_auto_tier_fail_closed),
        ("skip_ai_fixture_sync", test_skip_ai_fixture_sync),
        ("deterministic_verdict_fixture_coverage", test_deterministic_verdict_fixture_coverage),
        ("needs_review_hits", test_needs_review_hits),
        ("deterministic_fixture_classify", test_deterministic_fixture_classify),
        ("payments_onboarding_module", test_payments_onboarding_module),
        ("export_app_avcs_requires_paths", test_export_app_avcs_requires_paths),
        ("boolean_policy_render", test_boolean_policy_render),
        ("boolean_triage_two_matches", test_boolean_triage_two_matches),
        ("boolean_curated_when_policy_unavailable", test_boolean_curated_when_policy_unavailable),
        ("boolean_hint_yaml_still_documents_patterns", test_boolean_hint_yaml_still_documents_patterns),
        ("fc_labeling_drift_detection", test_fc_labeling_drift_detection),
        ("rhel_runtime_file_contexts", test_rhel_runtime_file_contexts),
        ("tune_report", test_tune_report),
        ("tune_report_skip_no_selinux", test_tune_report_skip_no_selinux),
        ("force_reason_recorded", test_force_reason_recorded),
        ("book_builder_contract", test_book_builder_contract),
        ("book_builder_fails_loudly", test_book_builder_fails_loudly),
    ]
    for name, fn in tests:
        fn()
        print(f"PASS {name}")
    print(f"\n{len(tests)}/{len(tests)} smoke tests passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
