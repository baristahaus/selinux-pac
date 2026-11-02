#!/usr/bin/env python3
"""Local smoke tests (no SELinux host required for most)."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import time
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
BASH = shutil.which("bash") or "/bin/bash"
sys.path.insert(0, str(PROJECT_ROOT / "cli"))

from avc_parse import (  # noqa: E402
    bump_policy_version,
    deduplicate_avc_entries,
    filter_avc_entries,
    parse_avc_line,
    read_policy_version,
)
from avc_preprocess import (  # noqa: E402
    AccessNeed,
    extract_type,
    merge_avc_entries,
    normalize_perms,
    parse_existing_allows,
    preprocess_avc_entries,
    subtract_covered,
)
from pr_summary_common import validate_pr_summary  # noqa: E402


def assert_mentions(text: str, *needles: str) -> None:
    """Talk tracks name these apps/paths — prefer this over a deny-list of old strings."""
    blob = text.lower()
    missing = [n for n in needles if n.lower() not in blob]
    assert not missing, f"talk output missing {missing}"


def test_existing_execmem_rules_stay_baseline() -> None:
    """self and unbraced allows are already present; a second run must not copy them."""
    forms = (
        "allow shopapi_t self:process execmem;",
        "allow shopapi_t self:process { execmem };",
        "allow shopapi_t shopapi_t:process execmem;",
        "allow shopapi_t shopapi_t:process { execmem };",
    )
    avc = (
        "type=AVC msg=audit(1): avc:  denied  { execmem } for  pid=1 comm=\"java\" "
        "scontext=system_u:system_r:shopapi_t:s0 "
        "tcontext=system_u:system_r:shopapi_t:s0 tclass=process permissive=1\n"
    )
    gen = PROJECT_ROOT / "cli" / "deterministic_gen.py"
    manifest = PROJECT_ROOT / "config" / "shopapi.manifest.yml"
    fc = PROJECT_ROOT / "selinux" / "shopapi" / "shopapi.fc"
    version = PROJECT_ROOT / "selinux" / "shopapi" / "policy_version.txt"
    for rule in forms:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            te = root / "shopapi.te"
            te.write_text(f"policy_module(shopapi, 1.0.0)\n\n{rule}\n", encoding="utf-8")
            log = root / "avc.log"
            log.write_text(avc, encoding="utf-8")
            out1 = root / "out1"
            first = subprocess.run(
                [
                    sys.executable,
                    str(gen),
                    "--avc-log",
                    str(log),
                    "--manifest",
                    str(manifest),
                    "--existing-te",
                    str(te),
                    "--existing-fc",
                    str(fc),
                    "--version-file",
                    str(version),
                    "--out-dir",
                    str(out1),
                    "--allow-needs-review",
                ],
                cwd=PROJECT_ROOT,
                capture_output=True,
                text=True,
            )
            assert first.returncode == 0, f"{rule}\n{first.stderr}{first.stdout}"
            payload = json.loads((out1 / "findings.json").read_text(encoding="utf-8"))
            assert any(
                row.get("verdict") == "baseline" and row.get("tgt") == "shopapi_t"
                for row in payload["findings"]
            ), payload
            written = (out1 / "shopapi.te").read_text(encoding="utf-8")
            assert written.count("execmem") == 1, written
            out2 = root / "out2"
            second = subprocess.run(
                [
                    sys.executable,
                    str(gen),
                    "--avc-log",
                    str(log),
                    "--manifest",
                    str(manifest),
                    "--existing-te",
                    str(out1 / "shopapi.te"),
                    "--existing-fc",
                    str(fc),
                    "--version-file",
                    str(version),
                    "--out-dir",
                    str(out2),
                    "--allow-needs-review",
                ],
                cwd=PROJECT_ROOT,
                capture_output=True,
                text=True,
            )
            assert second.returncode == 0, f"{rule} second\n{second.stderr}"
            assert (out2 / "shopapi.te").read_text(encoding="utf-8").count("execmem") == 1


def test_rpm_signing_tree_and_shopapi_ports() -> None:
    publish = PROJECT_ROOT / "packaging" / "publish_internal.sh"
    build = PROJECT_ROOT / "packaging" / "build_rpms.sh"
    spec = (PROJECT_ROOT / "packaging" / "shopapi-selinux.spec").read_text(encoding="utf-8")
    assert "8091" not in spec
    assert "port -m" not in spec
    assert "%selinux_modules_install" in spec

    with tempfile.TemporaryDirectory() as tmp:
        tmp_path = Path(tmp)
        stamped = tmp_path / "sample.spec"
        stamped.write_text("%description\nCustom module.\n", encoding="utf-8")
        stamp = subprocess.run(
            [BASH, str(build), "--stamp-spec", str(stamped), "abc123def"],
            cwd=PROJECT_ROOT,
            capture_output=True,
            text=True,
        )
        assert stamp.returncode == 0, stamp.stderr
        assert "Built from git commit abc123def." in stamped.read_text(encoding="utf-8")

        bindir = tmp_path / "bin"
        bindir.mkdir()
        fake_git = bindir / "git"
        fake_git.write_text(
            "#!/bin/bash\n"
            "while [[ \"$1\" == \"-C\" ]]; do shift 2; done\n"
            "case \"$1\" in\n"
            "  status) printf '%s\\n' \"${FAKE_GIT_STATUS-}\"; exit 0 ;;\n"
            "  rev-parse) printf '%s\\n' \"${FAKE_GIT_SHA:-abc}\"; exit 0 ;;\n"
            "  *) echo unexpected >&2; exit 1 ;;\n"
            "esac\n",
            encoding="utf-8",
        )
        fake_git.chmod(0o755)
        env = os.environ.copy()
        env["PATH"] = f"{bindir}:{env.get('PATH', '')}"
        env["BUILD_RPMS_LOCAL"] = "1"
        env["FAKE_GIT_STATUS"] = " M Makefile"
        dirty = subprocess.run(
            [BASH, str(build)],
            cwd=PROJECT_ROOT,
            capture_output=True,
            text=True,
            env=env,
        )
        assert dirty.returncode != 0
        assert "dirty git tree" in dirty.stderr

        env["FAKE_GIT_STATUS"] = ""
        # Hide a host rpmbuild. The assertion is the missing-tool refusal.
        env["PATH"] = str(bindir)
        missing = subprocess.run(
            [BASH, str(build)],
            cwd=PROJECT_ROOT,
            capture_output=True,
            text=True,
            env=env,
        )
        assert missing.returncode != 0, missing.stdout + missing.stderr
        assert "rpmbuild is required" in missing.stderr
        assert "validating spec parity only" not in (missing.stderr + missing.stdout)

        repo = tmp_path / "repo"
        repo.mkdir()
        dist = PROJECT_ROOT / "dist"
        dist.mkdir(exist_ok=True)
        dummy = dist / "smoke-unsigned.rpm"
        dummy.write_bytes(b"not-a-real-rpm")
        sudo = bindir / "sudo"
        sudo.write_text("#!/bin/bash\nexec \"$@\"\n", encoding="utf-8")
        sudo.chmod(0o755)
        pub_env = os.environ.copy()
        pub_env["PATH"] = f"{bindir}:/usr/bin:/bin"
        pub_env["SELINUX_INTERNAL_ENV"] = str(tmp_path / "no-such.env")
        pub_env.pop("SELINUX_GPG_NAME", None)
        pub_env.pop("SELINUX_ALLOW_UNSIGNED", None)
        pub_env["SELINUX_RPM_REPO"] = str(repo)
        blocked = subprocess.run(
            [BASH, str(publish)],
            cwd=PROJECT_ROOT,
            capture_output=True,
            text=True,
            env=pub_env,
        )
        assert blocked.returncode != 0
        assert "signing is not configured" in blocked.stderr
        pub_env["SELINUX_ALLOW_UNSIGNED"] = "1"
        warned = subprocess.run(
            [BASH, str(publish)],
            cwd=PROJECT_ROOT,
            capture_output=True,
            text=True,
            env=pub_env,
        )
        dummy.unlink(missing_ok=True)
        assert warned.returncode == 0, warned.stderr
        assert "UNSIGNED" in warned.stderr
        assert "labs only" in warned.stderr


def test_signed_repo_published_on_qa() -> None:
    """Canary installs latest from a gpgcheck=1 repo. Signing uses --key-id or _gpg_name."""
    install = (
        PROJECT_ROOT / "ansible" / "roles" / "selinux_pac" / "tasks" / "install_packages.yml"
    ).read_text(encoding="utf-8")
    assert "ansible.builtin.rpm_key" in install
    assert "ansible.builtin.yum_repository" in install
    assert "gpgcheck: 1" in install
    assert "state: latest" in install
    assert "update_cache: true" in install
    publish = PROJECT_ROOT / "packaging" / "publish_internal.sh"
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        dist = PROJECT_ROOT / "dist"
        dist.mkdir(exist_ok=True)
        dummy = dist / "smoke-sign.rpm"
        dummy.write_bytes(b"not-a-real-rpm")
        bindir = root / "bin"
        bindir.mkdir()
        log = root / "rpmsign.log"
        sudo = bindir / "sudo"
        sudo.write_text("#!/bin/sh\nexec \"$@\"\n", encoding="utf-8")
        sudo.chmod(0o755)
        createrepo = bindir / "createrepo_c"
        createrepo.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
        createrepo.chmod(0o755)

        def write_rpmsign(help_text: str) -> None:
            (bindir / "rpmsign").write_text(
                "#!/bin/sh\n"
                "if [ \"$1\" = --help ]; then printf '%s\\n' \"" + help_text + "\"; exit 0; fi\n"
                "printf '%s\\n' \"$*\" >> \"$RPMSIGN_LOG\"\n"
                "exit 0\n",
                encoding="utf-8",
            )
            (bindir / "rpmsign").chmod(0o755)

        env = os.environ.copy()
        env["PATH"] = f"{bindir}:/usr/bin:/bin"
        env["SELINUX_INTERNAL_ENV"] = str(root / "no-such.env")
        env["SELINUX_RPM_REPO"] = str(root / "repo")
        env["SELINUX_GPG_NAME"] = "selinux-pac-lab"
        env["LAB_GNUPGHOME"] = str(root / "gnupg")
        env["RPMSIGN_LOG"] = str(log)
        env.pop("SELINUX_ALLOW_UNSIGNED", None)
        write_rpmsign("Usage: rpmsign --addsign --key-id KEYID")
        with_key = subprocess.run(
            [BASH, str(publish)], cwd=PROJECT_ROOT, capture_output=True, text=True, env=env
        )
        assert with_key.returncode == 0, with_key.stderr
        signed = log.read_text(encoding="utf-8")
        assert "--key-id" in signed
        assert "_gpg_name selinux-pac-lab" in signed
        log.write_text("", encoding="utf-8")
        write_rpmsign("Usage: rpmsign --addsign")
        with_macro = subprocess.run(
            [BASH, str(publish)], cwd=PROJECT_ROOT, capture_output=True, text=True, env=env
        )
        dummy.unlink(missing_ok=True)
        assert with_macro.returncode == 0, with_macro.stderr
        signed = log.read_text(encoding="utf-8")
        assert "--key-id" not in signed
        assert "_gpg_name selinux-pac-lab" in signed
    mac = (PROJECT_ROOT / "lab" / "demo_e2e_mac.sh").read_text(encoding="utf-8")
    serve = (PROJECT_ROOT / "lab" / "serve_lab_repo.sh").read_text(encoding="utf-8")
    assert 'pkill -f \\"[h]ttp.server 8765\\"' in mac
    assert "rpm-sign" in mac and "createrepo_c" in mac
    assert "mac_serve_repo" in mac
    assert "scp -3" in mac
    assert "public key, signed RPMs, repodata; no private key" in mac
    assert "curl -sfI http://${repo_host}:8765/RPM-GPG-KEY" in mac
    assert "exec python3 -m http.server" in serve


def test_selinux_ports_and_canary_refuses_modify() -> None:
    sys.path.insert(0, str(PROJECT_ROOT / "scripts" / "lib"))
    from app_manifest import (
        classify_port_assignment,
        load_manifest,
        port_types_declared,
        validate_selinux_ports,
    )

    declared = {"shopapi_port_t"}
    assert validate_selinux_ports(
        [{"port": 8091, "proto": "tcp", "type": "shopapi_port_t"}], declared
    ) == []
    low = validate_selinux_ports(
        [{"port": 80, "proto": "tcp", "type": "shopapi_port_t"}], declared
    )
    assert any("below 1024" in err for err in low)
    allowed = validate_selinux_ports(
        [{"port": 80, "proto": "tcp", "type": "shopapi_port_t", "allow_privileged": True}],
        declared,
    )
    assert allowed == []
    foreign = validate_selinux_ports(
        [{"port": 8091, "proto": "tcp", "type": "http_port_t"}], declared
    )
    assert any("not declared" in err for err in foreign)
    te = (PROJECT_ROOT / "selinux" / "shopapi" / "shopapi.te").read_text(encoding="utf-8")
    assert "shopapi_port_t" in port_types_declared(te)
    load_manifest(PROJECT_ROOT / "config" / "shopapi.manifest.yml")

    listing = "\n".join(
        [
            "SELinux Port Type              Proto    Port Number",
            "http_port_t                    tcp      80, 443, 8080",
            "shopapi_port_t                 tcp      8091",
            "unreserved_port_t              tcp      1024-32767",
        ]
    )
    assert classify_port_assignment(listing, 8091, "tcp", "shopapi_port_t") == "present"
    try:
        classify_port_assignment(listing, 80, "tcp", "shopapi_port_t")
        raise AssertionError("expected a conflict")
    except ValueError as exc:
        assert "port -m" in str(exc)
    # A port that only sits in the unreserved range is added, not modified.
    assert classify_port_assignment(listing, 8092, "tcp", "shopapi_port_t") == "add"
    assert classify_port_assignment(listing, 50000, "tcp", "shopapi_port_t") == "add"

    canary = (
        PROJECT_ROOT / "ansible" / "roles" / "selinux_pac" / "tasks" / "canary.yml"
    ).read_text(encoding="utf-8")
    assert "seport:" not in canary
    assert "port -m" not in canary
    assert "check-port" in canary
    assert "semanage port -a" in canary


def test_codeowners_covers_policy_surface() -> None:
    text = (PROJECT_ROOT / ".github" / "CODEOWNERS").read_text(encoding="utf-8")
    for path in (
        "/selinux/",
        "/ansible/",
        "/scripts/",
        "/.github/",
        "/packaging/",
        "/config/",
        "/cli/policy_rules.py",
    ):
        assert path in text, path
        assert "@anurag-saran" in text.split(path, 1)[1].splitlines()[0]


def test_ci_runs_full_suite_with_stable_names() -> None:
    """Every PR runs make test, and check names stay stable for branch protection."""
    import yaml

    workflow = yaml.safe_load(
        (PROJECT_ROOT / ".github" / "workflows" / "selinux-policy-ci.yml").read_text(encoding="utf-8")
    )
    assert "paths" not in (workflow.get("on", {}).get("pull_request") or {})
    jobs = workflow["jobs"]
    for job_id, job in jobs.items():
        assert job.get("name") == job_id, f"{job_id} name must match the job id"
    offline = jobs["offline-tests"]
    steps = "\n".join(str(step.get("run", "")) for step in offline["steps"])
    assert "make test" in steps
    forbidden = "\n".join(
        str(step.get("run", "")) for step in jobs["forbidden-patterns"]["steps"]
    )
    compiled = "\n".join(
        str(step.get("run", "")) for step in jobs["compiled-policy"]["steps"]
    )
    assert "selinux/payments" in forbidden
    assert "--app payments" in compiled


def test_make_deps_uses_venv() -> None:
    """make deps must not pip-install into the system interpreter."""
    text = (PROJECT_ROOT / "Makefile").read_text(encoding="utf-8")
    deps = text.split("deps:", 1)[1].split("\n\n", 1)[0]
    assert "python3 -m venv" in deps
    assert ".venv" in text
    assert "pip3 install" not in deps
    assert "$(PIP) install" in deps


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
    te = (PROJECT_ROOT / "selinux" / "myapp" / "myapp.te").read_text(encoding="utf-8")
    existing = parse_existing_allows(te)
    merged = [
        AccessNeed("myapp_t", "myapp_lib_t", "file", frozenset({"read"})),
    ]
    net_new, covered = subtract_covered(merged, existing)
    assert len(net_new) == 0, f"unexpected net_new: {net_new}"
    assert len(covered) == 1
    assert "read" in covered[0].perms


def test_net_new_detection() -> None:
    te = (PROJECT_ROOT / "selinux" / "myapp" / "myapp.te").read_text(encoding="utf-8")
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


def test_structured_summary_sections() -> None:
    te = (PROJECT_ROOT / "selinux" / "myapp" / "myapp.te").read_text(encoding="utf-8")
    entries = [
        parse_avc_line(
            _sample_avc_line("link", "system_u:system_r:myapp_t:s0", "system_u:object_r:myapp_var_lib_t:s0")
        )
    ]
    summary, stats = preprocess_avc_entries(entries, existing_te=te)
    assert stats["net_new"] >= 1
    assert "Net-new access needs" in summary
    assert "Already covered by existing policy" in summary


def test_pr_summary_headings() -> None:
    body = "\n".join(
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
    validate_pr_summary(body)
    try:
        validate_pr_summary("### Network Bindings\n- only one section\n")
        raise AssertionError("expected validate_pr_summary to fail")
    except RuntimeError:
        pass


def test_version_bump() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        vf = Path(tmp) / "policy_version.txt"
        vf.write_text("1.0.0\n", encoding="utf-8")
        assert read_policy_version(vf) == "1.0.0"
        assert bump_policy_version(vf) == "1.0.1"
        assert read_policy_version(vf) == "1.0.1"


def test_assemble_pr_body_policy_diff_section() -> None:
    """assemble_pr_body embeds precomputed sesearch delta (full diff needs sesearch + git merge-base)."""
    fixture = PROJECT_ROOT / "tests" / "fixtures" / "policy_diff" / "sample_delta.md"
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
        ["bash", str(script), "--app", "myapp", "--skip-if-unavailable"],
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
            ["bash", str(script), "--app", "myapp", "--marker-file", str(marker), "--min-days", "7"],
            cwd=PROJECT_ROOT,
            capture_output=True,
            text=True,
        )
        assert missing.returncode != 0

        marker.write_text(str(int(time.time())), encoding="utf-8")
        recent = subprocess.run(
            ["bash", str(script), "--app", "myapp", "--marker-file", str(marker), "--min-days", "7", "--max-avc", "0"],
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
                "--app",
                "myapp",
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


def test_avc_epoch_window() -> None:
    """Formatted ausearch -ts dates are not used. Denials after an epoch marker count."""
    query = subprocess.run(
        [BASH, str(PROJECT_ROOT / "tests" / "test_avc_query_epoch.sh")],
        cwd=PROJECT_ROOT,
        capture_output=True,
        text=True,
    )
    assert query.returncode == 0, query.stdout + query.stderr
    window = subprocess.run(
        [BASH, str(PROJECT_ROOT / "tests" / "test_avc_epoch_window.sh")],
        cwd=PROJECT_ROOT,
        capture_output=True,
        text=True,
    )
    assert window.returncode == 0, window.stdout + window.stderr
    workflow = (PROJECT_ROOT / ".github" / "workflows" / "selinux-policy-ci.yml").read_text(
        encoding="utf-8"
    )
    assert "test_avc_epoch_window.sh" in workflow
    assert "AVC_REQUIRE_AUSEARCH" in workflow


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
    assert "TRIAGE situation=loaded_unconfined" in unconfined_loaded_out
    assert "action=confine" in unconfined_loaded_out
    assert "domain_confined=no" in unconfined_loaded_out
    assert "does not mean file or port denials will fire" in unconfined_loaded_out
    refused = run(
        ["--app-name", "tomcat"],
        {
            "VENDOR_CHECK_SEMODULE_L": "tomcat",
            "VENDOR_CHECK_DOMAIN_UNCONFINED": "1",
        },
    )
    refused_out = refused.stdout + refused.stderr
    assert refused.returncode != 0, refused_out
    assert "loaded_unconfined" in refused_out
    assert "confining package" in refused_out
    assert '--force "reason"' in refused_out or "--force" in refused_out

    # c9s policy_module names: apache (httpd_t) and bind (named_t), not httpd/named.
    apache = run(
        ["--app-name", "httpd", "--report"],
        {"VENDOR_CHECK_SEMODULE_L": "apache\t1.0.0\n"},
    )
    apache_out = apache.stdout + apache.stderr
    assert apache.returncode == 0, apache_out
    assert "TRIAGE situation=loaded" in apache_out
    assert "module=apache" in apache_out
    assert "domain=httpd_t" in apache_out
    bind = run(
        ["--app-name", "named", "--report"],
        {"VENDOR_CHECK_SEMODULE_L": "bind\t1.0.0\n"},
    )
    bind_out = bind.stdout + bind.stderr
    assert bind.returncode == 0, bind_out
    assert "TRIAGE situation=loaded" in bind_out
    assert "module=bind" in bind_out
    assert "domain=named_t" in bind_out


def test_demo_present_dry_run() -> None:
    """Customer demo: every tool step is sepac, one caption per command, safe order."""
    script = PROJECT_ROOT / "lab" / "demo_present.sh"

    def dry(*extra: str) -> str:
        result = subprocess.run(
            [BASH, str(script), "--dry-run", "--no-type", "--auto", *extra],
            cwd=PROJECT_ROOT,
            capture_output=True,
            text=True,
        )
        out = re.sub(r"\x1b\[[0-9;]*m", "", result.stdout + result.stderr)
        assert result.returncode == 0, out
        return out

    out = dry("--profile", "customer")
    assert "demo-bootstrap" in out
    for title in ("1 · Triage", "2 · Inherited Tomcat", "3 · shopapi — write policy from evidence",
                  "4 · shopapi — enforce it"):
        assert title in out, f"missing part title {title!r}"
    full = dry("--profile", "full")
    assert "5 · A new feature hits production" in full, "the full profile must keep part 5"
    # The presenter explains. The screen has captions, not paragraphs.
    assert "Expected:" not in out
    assert "What this does:" not in out
    captions = [line for line in out.splitlines() if line.startswith("# ")]
    assert captions, out
    assert all(len(line) <= 90 for line in captions), captions
    commands = [line[len("demo# "):] for line in out.splitlines() if line.startswith("demo# ")]
    assert len(commands) <= 18, f"customer demo grew to {len(commands)} commands"
    # The demo is about sepac. Two typed commands are not: the inherited
    # Tomcat's traffic, and audit2allow as the old way to compare against.
    others = [c for c in commands if not c.startswith("sepac ")]
    assert len(others) <= 2, others
    assert any("audit2allow" in c for c in others), others
    assert not any("|| true" in c for c in commands), commands
    for cmd in commands:
        for leak in ("POLICY_MODULE", "--app-root", "scripts/", "--allow-needs-review", "semanage permissive"):
            assert leak not in cmd, f"{leak} on screen: {cmd}"
    # The customer profile stops after part 4. The ship order lives in part 5,
    # so check it on the full profile.
    out = dry("--profile", "full")
    assert_mentions(out, "shopapi", "tomcat")
    assert "loaded_unconfined" in out
    assert "GENERATION BLOCKED" in out
    order = [
        "demo# sepac triage tomcat",
        "demo# sepac triage shopapi",
        "demo# sepac denials tomcat --why",
        "demo# sepac status shopapi",
        "demo# sepac capture shopapi --full-audit",
        "audit2allow",
        "demo# sepac generate shopapi\n",
        "demo# sepac generate shopapi --approve execmem --apply",
        "demo# sepac check shopapi",
        "demo# sepac load shopapi\n",
        "demo# sepac load shopapi --enforcing",
        "demo# sepac capture shopapi --no-restart --url /feature-spool",
        "demo# sepac load shopapi --permissive",
        "demo# sepac capture shopapi --no-restart --url /feature-spool",
        "demo# sepac generate shopapi --apply",
        "demo# sepac load shopapi --enforcing",
        "demo# sepac capture shopapi --no-restart --url /feature-spool",
        "demo# sepac status shopapi",
    ]
    pos = -1
    for mark in order:
        nxt = out.find(mark, pos + 1)
        assert nxt > pos, f"{mark!r} missing or out of order"
        pos = nxt
    # Once shopapi_t is enforcing, nothing pre-approves a new risky permission.
    enforcing = out.find("demo# sepac load shopapi --enforcing")
    assert "--approve" not in out[enforcing:]
    assert "tomcat_can_network_connect" not in out
    assert "httpd_can_network_connect" not in out
    assert "Tomcat is vendor-covered" not in out
    assert "NEEDS_LIVE_CHECK" not in out

    jws_out = dry("--profile", "customer", "--variant", "jws")
    assert "action=tune" in jws_out
    assert "jws6_tomcat" in jws_out
    assert "loaded_unconfined" not in jws_out
    assert "Tomcat is vendor-covered" in jws_out
    assert "demo# sepac tune tomcat" in jws_out
    assert "semanage port -a -t http_port_t -p tcp 8090" in jws_out
    assert "restorecon -Rv /opt/appdata" in jws_out

    help_run = subprocess.run(
        [BASH, str(script), "--help"],
        cwd=PROJECT_ROOT,
        capture_output=True,
        text=True,
    )
    help_out = help_run.stdout + help_run.stderr
    assert help_run.returncode == 0, help_out
    assert "demo_e2e_mac.sh" in help_out
    assert "docs/demo.md" in help_out
    assert "--no-step" in help_out
    te = (PROJECT_ROOT / "selinux" / "shopapi" / "shopapi.te").read_text(encoding="utf-8")
    assert not any(
        (not line.lstrip().startswith("#")) and "execmem" in line
        for line in te.splitlines()
    )
    pre = subprocess.run(
        [BASH, str(script), "--dry-run", "--no-type", "--auto", "--preflight"],
        cwd=PROJECT_ROOT,
        capture_output=True,
        text=True,
    )
    pre_out = pre.stdout + pre.stderr
    assert pre.returncode == 0, pre_out
    assert "make demo-bootstrap" in pre_out
    assert "semanage port -d" in pre_out
    assert "8090" in pre_out
    assert "/etc/selinux-pac/role" in pre_out
    tech_out = dry("--profile", "technical")
    assert "4 · shopapi — enforce it" not in tech_out
    assert "5 · A new feature hits production" in tech_out
    assert "demo# sepac check shopapi" in tech_out
    assert_mentions(tech_out, "shopapi")


def test_demo_present_waits_for_enter() -> None:
    """Without --auto each typed command waits for Enter before it runs."""
    import time

    script = PROJECT_ROOT / "lab" / "demo_present.sh"
    args = [BASH, str(script), "--dry-run", "--no-type", "--acts", "1"]
    # Enough Enters for the banner, part 1's two commands and its pause.
    ok = subprocess.run(args, cwd=PROJECT_ROOT, input="\n" * 10, capture_output=True, text=True)
    assert ok.returncode == 0, ok.stdout + ok.stderr
    assert ok.stdout.count("demo# ") == 2, ok.stdout

    def run_with_open_stdin(extra: list[str]) -> str:
        # Two Enters, stdin left open: banner pause, then the first command.
        proc = subprocess.Popen(
            args + extra,
            cwd=PROJECT_ROOT,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
        )
        assert proc.stdin is not None
        proc.stdin.write("\n\n")
        proc.stdin.flush()
        time.sleep(3)
        proc.kill()
        out, _ = proc.communicate()
        return out

    stepped = run_with_open_stdin([])
    # The first command ran. The second is typed and waiting.
    assert stepped.count("(dry-run)") == 1, stepped
    assert stepped.count("demo# ") == 2, stepped
    nostep = run_with_open_stdin(["--no-step"])
    # --no-step runs both; only the part's pause waits.
    assert nostep.count("(dry-run)") == 2, nostep


def _install_healthy_audit(bindir: Path) -> None:
    systemctl = bindir / "systemctl"
    systemctl.write_text(
        "#!/bin/sh\nif [ \"$1\" = is-active ]; then exit 0; fi\nexit 1\n",
        encoding="utf-8",
    )
    systemctl.chmod(0o755)
    auditctl = bindir / "auditctl"
    auditctl.write_text("#!/bin/sh\nprintf '%s\\n' 'enabled 1' 'lost 0'\n", encoding="utf-8")
    auditctl.chmod(0o755)


def _lab_hosts(base: dict[str, str] | None = None) -> dict[str, str]:
    env = os.environ.copy() if base is None else dict(base)
    env["QA_HOST"] = "qa.example.com"
    env["PROD_HOST"] = "prod.example.com"
    env["SSH_USER"] = "ssh-user"
    return env


def _without_lab_hosts(base: dict[str, str] | None = None) -> dict[str, str]:
    env = os.environ.copy() if base is None else dict(base)
    for key in (
        "QA_HOST",
        "PROD_HOST",
        "SSH_USER",
        "DEV_HOST",
        "ANSIBLE_SSH_USER",
        "E2E_SSH_USER",
        "ANSIBLE_USER",
    ):
        env.pop(key, None)
    return env


def test_prod_soak_gate_and_lab_signing() -> None:
    """Prod soak curls /feature-spool, enforce refuses, then the fix. Lab signing stays gpgcheck=1."""
    mac = (PROJECT_ROOT / "lab" / "demo_e2e_mac.sh").read_text(encoding="utf-8")
    prod = (PROJECT_ROOT / "lab" / "demo_e2e_rhel_prod.sh").read_text(encoding="utf-8")
    guide = (PROJECT_ROOT / "docs" / "guides" / "302-TECHNICAL.md").read_text(encoding="utf-8")
    assert "LAST_VERIFIED:** 2026-10-09" in guide
    gate = mac.split("if [[ \"${mode}\" == \"soak_demo\" ]]; then", 1)[1].split("return 0", 1)[0]
    assert "/feature-spool" in gate
    assert "\" fail" in gate
    assert "sepac soak --env production" in gate
    assert "sepac enforce --env production --ticket DEMO" in gate
    assert "--break-glass" not in gate
    clean = mac.split("--part soak-clean", 1)[1].split("mac_copy_prod_avc_to_dev()", 1)[0]
    assert "--skip-soak-days" in clean
    assert "--break-glass" not in clean
    assert "day count" in clean
    talk = mac.split("Prod soak refuses", 1)[1]
    dirty = talk.find("mac_ship_prod soak_demo")
    glass = talk.find("--break-glass")
    fail = talk.find("--part fail")
    rollback = talk.find("sepac rollback")
    fix = talk.find("--part generate --skip-export")
    recanary = talk.find("mac_ship_prod recanary")
    ends = talk.find("shopapi_t enforcing")
    assert -1 not in (dirty, glass, fail, rollback, fix, recanary, ends)
    assert dirty < glass < fail < rollback < fix < recanary < ends
    assert "/feature-spool" in prod
    assert "part_soak()" in prod
    assert "lab_signing_setup.sh" in guide
    assert "gpgcheck=1" in guide
    script = PROJECT_ROOT / "lab" / "lab_signing_setup.sh"
    body = script.read_text(encoding="utf-8")
    assert "gpgcheck=1" in body
    assert "--export-secret-keys" not in body
    refused = subprocess.run(
        [BASH, str(script), "--print-secret"],
        cwd=PROJECT_ROOT,
        capture_output=True,
        text=True,
    )
    assert refused.returncode != 0
    assert "private key" in (refused.stdout + refused.stderr).lower()


def test_demo_outage_before_fix_dry_run() -> None:
    """Dry-run prints the 500 and the rollback before the spool allow, and ends enforcing."""
    mac = PROJECT_ROOT / "lab" / "demo_e2e_mac.sh"
    with tempfile.TemporaryDirectory() as tmp:
        uname = Path(tmp) / "uname"
        uname.write_text("#!/bin/sh\necho Darwin\n", encoding="utf-8")
        uname.chmod(0o755)
        env = _lab_hosts()
        env["PATH"] = f"{tmp}:{env.get('PATH', '/usr/bin:/bin')}"
        run = subprocess.run(
            [BASH, str(mac), "--dry-run", "--no-type", "--auto"],
            cwd=PROJECT_ROOT,
            capture_output=True,
            text=True,
            env=env,
        )
    out = run.stdout + run.stderr
    assert run.returncode == 0, out
    refuse = out.find("sepac enforce --env production --ticket DEMO")
    glass = out.find("--break-glass")
    fail = out.find("--part fail")
    rollback = out.find("sepac rollback --env production")
    fix = out.find("--part generate --skip-export")
    clean = out.find("--part soak-clean")
    ends = out.find("shopapi_t enforcing")
    assert -1 not in (refuse, glass, fail, rollback, fix, clean, ends), out
    assert refuse < glass < fail < rollback < fix < clean < ends


def test_demo_e2e_scripts_dry_run() -> None:
    """Mac/QA/prod talk tracks: shopapi, not Flask. QA/prod scripts refuse Darwin."""
    mac = PROJECT_ROOT / "lab" / "demo_e2e_mac.sh"
    qa = PROJECT_ROOT / "lab" / "demo_e2e_rhel_qa.sh"
    prod = PROJECT_ROOT / "lab" / "demo_e2e_rhel_prod.sh"
    reset = PROJECT_ROOT / "lab" / "reset_demo_vms.sh"
    setup = PROJECT_ROOT / "lab" / "setup_rhel_hosts.sh"

    # demo_e2e_mac.sh calls e2e_require_mac and exits 1 on Linux. Skip the
    # dry-run there; do not treat that refusal as a failed suite.
    if sys.platform == "darwin":
        mac_run = subprocess.run(
            [BASH, str(mac), "--dry-run", "--no-type", "--auto"],
            cwd=PROJECT_ROOT,
            capture_output=True,
            text=True,
            env=_lab_hosts(),
        )
        mac_out = mac_run.stdout + mac_run.stderr
        assert mac_run.returncode == 0, mac_out
        assert_mentions(
            mac_out, "shopapi", "/feature-spool", "demo_e2e_rhel_qa.sh", "selinux/shopapi"
        )
        assert "LAB ONLY" in mac_out
        assert "soak_min_days" in mac_out
        # --short: happy path — no outage, no rollback
        mac_short_run = subprocess.run(
            [BASH, str(mac), "--dry-run", "--no-type", "--auto", "--short"],
            cwd=PROJECT_ROOT,
            capture_output=True,
            text=True,
            env=_lab_hosts(),
        )
        mac_short_out = mac_short_run.stdout + mac_short_run.stderr
        assert mac_short_run.returncode == 0, mac_short_out
        assert "short happy path" in mac_short_out
        assert "--all-urls" in mac_short_out
        assert "--break-glass" not in mac_short_out
        assert "sepac rollback" not in mac_short_out
        assert "sepac enforce" in mac_short_out
    mac_help = subprocess.run(
        [BASH, str(mac), "--help"],
        cwd=PROJECT_ROOT,
        capture_output=True,
        text=True,
    )
    mac_help_out = mac_help.stdout + mac_help.stderr
    assert mac_help.returncode == 0, mac_help_out
    assert "demo_present.sh" in mac_help_out
    reset_text = reset.read_text(encoding="utf-8")
    assert "ausearch-since" in reset_text
    assert "auditd stop" not in reset_text
    assert "/var/log/audit/audit.log" not in reset_text
    mac_text = mac.read_text(encoding="utf-8")
    prod_text = prod.read_text(encoding="utf-8")
    guide_203 = (PROJECT_ROOT / "docs" / "guides" / "302-TECHNICAL.md").read_text(encoding="utf-8")
    # No e2e_run line should pull or checkout main (would overwrite generated module with seed)
    for line in mac_text.splitlines():
        if "e2e_run" in line:
            assert "git pull" not in line, f"e2e_run must not git pull: {line}"
            assert "git checkout" not in line, f"e2e_run must not git checkout: {line}"
    assert "sepac build --allow-dirty" in mac_text
    # Bind address: never 0.0.0.0, never fall back to DEV_HOST
    assert "--bind 0.0.0.0" not in mac_text
    assert 'REPO_HOST:-${DEV_HOST}' not in mac_text
    assert 'REPO_HOST:-$DEV_HOST' not in mac_text
    assert "gpgcheck=1" in mac_text
    assert "private key stays on rhel-qa" in mac_text
    assert "dnf repolist" in prod_text
    assert "rpm -q gpg-pubkey" in prod_text
    assert "rpm -Uvh" not in mac_text
    assert "rpm -Uvh" not in prod_text
    assert "192.168.64." not in guide_203
    assert "/Users/" not in guide_203
    # --all-urls in QA script enables /feature-spool during discovery
    qa_text = qa.read_text(encoding="utf-8")
    assert "E2E_ALL_URLS" in qa_text
    assert "sepac capture shopapi --full-audit --url /feature-spool" in qa_text
    # Host prep is lab plumbing: quiet, not typed. The typed QA steps are sepac.
    typed = re.findall(r'present_cmd "([^"]+)"', qa_text)
    assert typed and all(cmd.startswith("sepac ") for cmd in typed), typed

    qa_run = subprocess.run(
        [BASH, str(qa), "--dry-run", "--no-type", "--auto", "--part", "app"],
        cwd=PROJECT_ROOT,
        capture_output=True,
        text=True,
        env=_lab_hosts(),
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
        env=_lab_hosts(),
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
        env=_lab_hosts(),
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
        env=_lab_hosts(),
    )
    boot_out = boot.stdout + boot.stderr
    assert boot.returncode == 0, boot_out
    assert_mentions(boot_out, "demo_bootstrap.sh --shopapi-only")


def _open_pr_fixture(root: Path) -> None:
    """Temp clone whose shopapi sources differ from HEAD, so the PR script commits."""
    module = root / "selinux" / "shopapi"
    module.mkdir(parents=True)
    (module / "shopapi.te").write_text("policy_module(shopapi, 1.0.0)\n", encoding="utf-8")
    (module / "shopapi.fc").write_text("# seed\n", encoding="utf-8")
    (module / "policy_version.txt").write_text("1.0.0\n", encoding="utf-8")
    subprocess.run(["git", "init", "-q"], cwd=root, check=True)
    subprocess.run(["git", "config", "user.email", "smoke@example.com"], cwd=root, check=True)
    subprocess.run(["git", "config", "user.name", "smoke"], cwd=root, check=True)
    subprocess.run(["git", "add", "selinux/shopapi"], cwd=root, check=True)
    subprocess.run(["git", "commit", "-q", "-m", "seed"], cwd=root, check=True)
    (module / "shopapi.te").write_text("policy_module(shopapi, 1.0.1)\n", encoding="utf-8")
    (module / "policy_version.txt").write_text("1.0.1\n", encoding="utf-8")


def _pr_path_tools(root: Path) -> tuple[Path, dict[str, str]]:
    bindir = root / "bin"
    bindir.mkdir()
    log = root / "gh.log"
    log.write_text("", encoding="utf-8")
    git_real = shutil.which("git")
    assert git_real
    (bindir / "git").write_text(
        f"""#!/bin/bash
set -euo pipefail
if [[ "${{1:-}}" == "push" ]]; then
  exit 0
fi
exec {git_real} "$@"
""",
        encoding="utf-8",
    )
    (bindir / "gh").write_text(
        f"""#!/bin/bash
printf '%s\\n' "$*" >> {log}
if [[ "${{1:-}}" == "pr" && "${{2:-}}" == "list" ]]; then
  exit 0
fi
exit 0
""",
        encoding="utf-8",
    )
    (bindir / "git").chmod(0o755)
    (bindir / "gh").chmod(0o755)
    env = os.environ.copy()
    env["PATH"] = f"{bindir}{os.pathsep}{env.get('PATH', '')}"
    env["POLICY_PR_ROOT"] = str(root)
    env["DEMO_POLICY_BRANCH"] = "policy/shopapi-smoke"
    env.pop("DEMO_POLICY_PR_TITLE", None)
    env.pop("DEMO_REHEARSAL", None)
    return log, env


def test_rehearsal_and_review_pr_paths() -> None:
    """Rehearsal opens a draft; a normal run stays a review PR."""
    mac = (PROJECT_ROOT / "lab" / "demo_e2e_mac.sh").read_text(encoding="utf-8")
    assert "export DEMO_REHEARSAL=1" in mac
    script = PROJECT_ROOT / "lab" / "demo_open_generated_pr.sh"
    prefix = "[rehearsal - do not merge] "

    def run(root: Path, args: list[str], rehearsal: str | None) -> str:
        _open_pr_fixture(root)
        log, env = _pr_path_tools(root)
        if rehearsal is not None:
            env["DEMO_REHEARSAL"] = rehearsal
        proc = subprocess.run(
            [BASH, str(script), *args],
            cwd=root,
            capture_output=True,
            text=True,
            env=env,
        )
        out = proc.stdout + proc.stderr
        assert proc.returncode == 0, out
        return log.read_text(encoding="utf-8") + out

    with tempfile.TemporaryDirectory() as flag_dir, tempfile.TemporaryDirectory() as env_dir, tempfile.TemporaryDirectory() as review_dir:
        flagged = run(Path(flag_dir), ["--rehearsal"], "0")
        assert "--draft" in flagged
        assert prefix in flagged
        assert "do-not-merge" in flagged
        assert "pending-admin-review" not in flagged

        from_env = run(Path(env_dir), [], "1")
        assert "--draft" in from_env
        assert prefix in from_env
        assert "do-not-merge" in from_env
        assert "pending-admin-review" not in from_env

        review = run(Path(review_dir), [], "0")
        assert "--draft" not in review
        assert prefix not in review
        assert "pending-admin-review" in review
        assert "do-not-merge" not in review


def test_lab_env_required() -> None:
    """Talk scripts need QA_HOST, PROD_HOST, and SSH_USER, or lab/lab.env."""
    reset = PROJECT_ROOT / "lab" / "reset_demo_vms.sh"
    lab = PROJECT_ROOT / "lab" / "lab.env"
    legacy = PROJECT_ROOT / "scripts" / "lab.env"
    backup = lab.read_bytes() if lab.exists() else None
    legacy_backup = legacy.read_bytes() if legacy.exists() else None
    if lab.exists():
        lab.unlink()
    if legacy.exists():
        legacy.unlink()
    try:
        bare = _without_lab_hosts()
        missing = subprocess.run(
            [BASH, str(reset), "--dry-run"],
            cwd=PROJECT_ROOT,
            capture_output=True,
            text=True,
            env=bare,
        )
        missing_out = missing.stdout + missing.stderr
        assert missing.returncode == 2, missing_out
        assert "QA_HOST" in missing_out
        assert "PROD_HOST" in missing_out
        assert "SSH_USER" in missing_out
        assert "lab.env" in missing_out

        helped = subprocess.run(
            [BASH, str(reset), "--help"],
            cwd=PROJECT_ROOT,
            capture_output=True,
            text=True,
            env=bare,
        )
        assert helped.returncode == 0, helped.stdout + helped.stderr

        present = subprocess.run(
            [BASH, str(reset), "--dry-run"],
            cwd=PROJECT_ROOT,
            capture_output=True,
            text=True,
            env=_lab_hosts(bare),
        )
        present_out = present.stdout + present.stderr
        assert present.returncode == 0, present_out
        assert "qa.example.com" in present_out
        assert "192.168.64" not in present_out

        lab.write_text(
            "QA_HOST=from-file.example.com\n"
            "PROD_HOST=prod-file.example.com\n"
            "SSH_USER=file-user\n",
            encoding="utf-8",
        )
        from_file = subprocess.run(
            [BASH, str(reset), "--dry-run"],
            cwd=PROJECT_ROOT,
            capture_output=True,
            text=True,
            env=bare,
        )
        file_out = from_file.stdout + from_file.stderr
        assert from_file.returncode == 0, file_out
        assert "from-file.example.com" in file_out

        both = subprocess.run(
            [BASH, str(reset), "--dry-run"],
            cwd=PROJECT_ROOT,
            capture_output=True,
            text=True,
            env=_lab_hosts(bare),
        )
        both_out = both.stdout + both.stderr
        assert both.returncode == 0, both_out
        assert "qa.example.com" in both_out
        assert "from-file.example.com" not in both_out
    finally:
        if backup is None:
            lab.unlink(missing_ok=True)
        else:
            lab.write_bytes(backup)
        if legacy_backup is None:
            legacy.unlink(missing_ok=True)
        else:
            legacy.write_bytes(legacy_backup)

    readme = (PROJECT_ROOT / "README.md").read_text(encoding="utf-8")
    example = (PROJECT_ROOT / "lab" / "lab.env.example").read_text(encoding="utf-8")
    assert "192.168.64" not in readme
    assert "/Users/asaran" not in readme
    assert "fall back to a lab pair" not in readme
    assert "192.168.64" not in example
    assert "/Users/" not in example
    gitignore = (PROJECT_ROOT / ".gitignore").read_text(encoding="utf-8")
    assert "lab/lab.env" in gitignore
    assert "lab/lab.env.example" not in gitignore
    for rel in (
        "lab/lib/talk.sh",
        "lab/reset_demo_vms.sh",
        "lab/sync_rhel_dev.sh",
        "lab/build_rpms_on_dev.sh",
        "lab/setup_rhel_hosts.sh",
    ):
        text = (PROJECT_ROOT / rel).read_text(encoding="utf-8")
        assert "192.168.64" not in text, rel
    mac = (PROJECT_ROOT / "lab" / "demo_e2e_mac.sh").read_text(encoding="utf-8")
    assert "lab/lib/lab_env.sh" in mac
    assert "lab/lab.env" in mac
    boot = (PROJECT_ROOT / "lab" / "demo_bootstrap.sh").read_text(encoding="utf-8")
    assert "systemctl restart shopapi.service" in boot
    assert "enable --now shopapi.service ||" not in boot


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
                "source lab/lib/talk.sh; "
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


def test_narration_live_checks_and_enforce_paths() -> None:
    """Distro narration, one live-check list, and enforce-check uses the manifest."""
    live = PROJECT_ROOT / "docs" / "guides" / "LIVE_CHECKS.md"
    text = live.read_text(encoding="utf-8")
    assert "matchpathcon /run/shopapi/no-such-file" in text
    assert "ps -o label,args -C java" in text
    assert "rm -rf /run/shopapi" not in text
    assert "ps -eZ -C java" not in text
    hits = []
    for path in PROJECT_ROOT.rglob("*"):
        if not path.is_file() or path == live or path.name == "smoke_test.py" or ".git" in path.parts:
            continue
        if path.suffix not in {".md", ".sh", ".yml", ".py", ".service"} and path.name != "boolean_hints.yml":
            continue
        try:
            body = path.read_text(encoding="utf-8")
        except (UnicodeDecodeError, OSError):
            continue
        if "NEEDS_LIVE_CHECK" in body:
            hits.append(str(path.relative_to(PROJECT_ROOT)))
    assert hits == [], hits
    hints = (PROJECT_ROOT / "config" / "boolean_hints.yml").read_text(encoding="utf-8")
    assert "jws6_can_network_connect" not in hints
    assert "httpd_can_network_connect" in hints
    gen = (PROJECT_ROOT / "scripts" / "dev_generate_policy.sh").read_text(encoding="utf-8")
    start = gen.index("run_enforce_check()")
    end = gen.index("print_pr_steps()", start)
    body = gen[start:end]
    assert "/opt/myapp" not in body
    assert "myapp.service" not in body
    assert "PATHS_CSV" in body
    assert "PRIMARY_SERVICE" in body
    basics = (PROJECT_ROOT / "docs" / "guides" / "102-COMMANDS.md").read_text(encoding="utf-8")
    assert "matchpathcon /run/shopapi/no-such-file" in basics
    assert "ps -o label,args -C java" in basics


def test_demo_present_preflight_names_bootstrap() -> None:
    script = PROJECT_ROOT / "lab" / "demo_present.sh"
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


def test_selinux_booleans_and_app_ci() -> None:
    """Manifest booleans, packaged verify path, and app-repo CI call."""
    import yaml

    guide = (PROJECT_ROOT / "docs" / "shipping.md").read_text(
        encoding="utf-8"
    )
    assert "/usr/libexec/selinux-policy-ops/verify_file_contexts.sh" in guide
    assert "uses: OWNER/selinux-pac/.github/workflows/selinux-policy-app.yml@REF" in guide
    assert "does not work" in guide
    assert "module `jboss`" not in guide
    workflow = (PROJECT_ROOT / ".github" / "workflows" / "selinux-policy-app.yml").read_text(
        encoding="utf-8"
    )
    assert "workflow_call:" in workflow
    assert "app-forbidden-patterns:" in workflow
    assert "app-compiled-policy:" in workflow
    assert "tools_repo:" in workflow
    assert "tools_ref:" in workflow
    assert "anurag-saran/selinux-pac" in workflow
    assert "github.event_name" not in workflow
    assert "github.workflow_ref" not in workflow
    own = (PROJECT_ROOT / ".github" / "workflows" / "selinux-policy-ci.yml").read_text(
        encoding="utf-8"
    )
    assert "workflow_call:" not in own
    assert "github.event_name" not in own
    proof = (
        PROJECT_ROOT / ".github" / "workflows" / "selinux-policy-app-proof.yml"
    ).read_text(encoding="utf-8")
    assert "uses: ./.github/workflows/selinux-policy-app.yml" in proof
    assert "selinux/shopapi" in proof
    assert "can-setenforce" in proof
    assert "bypass module was accepted" in proof
    canary = (
        PROJECT_ROOT / "ansible" / "roles" / "selinux_pac" / "tasks" / "canary.yml"
    ).read_text(encoding="utf-8")
    assert "ansible.posix.seboolean" in canary
    aap = (PROJECT_ROOT / "ansible" / "aap" / "aap_configuration.yml").read_text(encoding="utf-8")
    assert "controller_templates:" in aap
    assert "controller_workflows:" in aap
    assert "SELinux – Promote to enforce" in aap
    assert "change_ticket" in aap
    assert "FREQ=DAILY" in aap
    vpc = (PROJECT_ROOT / "scripts" / "lib" / "vendor_policy_check.sh").read_text(encoding="utf-8")
    assert "echo '^apache$'" in vpc
    assert "echo '^bind$'" in vpc

    loader = PROJECT_ROOT / "scripts" / "lib" / "app_manifest.py"
    shop = yaml.safe_load(
        (PROJECT_ROOT / "config" / "shopapi.manifest.yml").read_text(encoding="utf-8")
    )

    def validate_copy(mutate) -> subprocess.CompletedProcess[str]:
        payload = yaml.safe_load(yaml.safe_dump(shop))
        mutate(payload)
        with tempfile.NamedTemporaryFile("w", suffix=".yml", delete=False) as handle:
            yaml.safe_dump(payload, handle)
            path = handle.name
        return subprocess.run(
            ["python3", str(loader), "validate", path],
            cwd=PROJECT_ROOT,
            capture_output=True,
            text=True,
        )

    missing = validate_copy(
        lambda payload: payload.__setitem__(
            "selinux_booleans",
            [{"name": "tomcat_can_network_connect", "state": True}],
        )
    )
    assert missing.returncode != 0, missing.stdout
    assert "tomcat_can_network_connect" in (missing.stdout + missing.stderr)

    tomcat = validate_copy(
        lambda payload: payload.update(
            {
                "domain": "tomcat_t",
                "selinux_booleans": [{"name": "httpd_can_network_connect", "state": True}],
            }
        )
    )
    assert tomcat.returncode != 0, tomcat.stdout
    assert "httpd_can_network_connect" in (tomcat.stdout + tomcat.stderr)

    allowed = validate_copy(
        lambda payload: payload.__setitem__(
            "selinux_booleans",
            [{"name": "tomcat_read_rpm_db", "state": True}],
        )
    )
    assert allowed.returncode == 0, allowed.stderr or allowed.stdout

    env = os.environ.copy()
    env["SELINUX_ROOT"] = str(PROJECT_ROOT / "selinux" / "shopapi")
    version = subprocess.run(
        ["bash", str(PROJECT_ROOT / "scripts" / "validate_version_consistency.sh")],
        cwd=PROJECT_ROOT,
        capture_output=True,
        text=True,
        env=env,
    )
    assert version.returncode == 0, version.stderr


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


def test_ops_rpm_soak_cli_imports_alone() -> None:
    """The ops RPM pac_cli set must run soak_net_new --help with no other repo modules."""
    names = [
        line.strip()
        for line in (PROJECT_ROOT / "packaging" / "pac_cli.list").read_text(encoding="utf-8").splitlines()
        if line.strip() and not line.strip().startswith("#")
    ]
    assert "soak_net_new.py" in names
    with tempfile.TemporaryDirectory() as tmp:
        dest = Path(tmp)
        for name in names:
            shutil.copy(PROJECT_ROOT / "cli" / name, dest / name)
        help_run = subprocess.run(
            [sys.executable, "-I", "soak_net_new.py", "--help"],
            cwd=dest,
            capture_output=True,
            text=True,
        )
        assert help_run.returncode == 0, help_run.stderr or help_run.stdout
        assert "Net-new" in help_run.stdout
    parity = subprocess.run(
        ["bash", str(PROJECT_ROOT / "scripts" / "validate_rpm_ops_parity.sh")],
        cwd=PROJECT_ROOT,
        capture_output=True,
        text=True,
    )
    assert parity.returncode == 0, parity.stderr or parity.stdout


def test_monitor_records_soak_stderr() -> None:
    """A failing soak_net_new.py puts its stderr in fail_closed_reason."""
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        bindir = root / "bin"
        bindir.mkdir()
        ausearch = bindir / "ausearch"
        ausearch.write_text(
            "#!/bin/sh\n"
            "printf '%s\\n' 'type=AVC msg=audit(1.1:1): avc: denied { read } for pid=1 "
            "path=\"/opt/shopapi/x\" scontext=system_u:system_r:shopapi_t:s0 "
            "tcontext=system_u:object_r:etc_t:s0 tclass=file permissive=1'\n",
            encoding="utf-8",
        )
        ausearch.chmod(0o755)
        env = os.environ.copy()
        env["PATH"] = f"{bindir}{os.pathsep}{env.get('PATH', '')}"
        env.pop("APP_MANIFEST", None)
        env.pop("AUDIT_LOG", None)
        result = subprocess.run(
            [
                BASH,
                str(PROJECT_ROOT / "scripts" / "monitor_avc.sh"),
                "--domain",
                "shopapi_t",
                "--paths",
                "/opt/shopapi",
                "--manifest",
                str(root / "missing-manifest.yml"),
                "--format",
                "json",
                "--max-avc",
                "-1",
            ],
            cwd=PROJECT_ROOT,
            capture_output=True,
            text=True,
            env=env,
        )
        blob = result.stdout + result.stderr
        assert "Provide --manifest or --domains" in blob, blob
        assert "sesearch / policy.kern" not in blob


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
    script = PROJECT_ROOT / "tests" / "run_deterministic_payments_check.sh"
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
    te_src = PROJECT_ROOT / "tests" / "fixtures" / "offline" / "generated" / "myapp.te"
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
            env={**os.environ, "CLASSIFY_SKIP_SELINUX": "1"},
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
                "--app",
                "myapp",
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
            env={**os.environ, "CLASSIFY_SKIP_SELINUX": "1"},
        )
    combined = result.stdout + result.stderr
    assert "Blast-radius classifier fail-closed" in combined, combined
    assert "soak minimum 7 day" in combined, combined


def test_tracked_tree_has_no_model_client() -> None:
    """Fail when a tracked file still names the removed model client."""
    pattern = "|".join(
        [
            r"\b" + "A" + "I" + r"\b",
            "LL" + "M",
            "open" + "a" + "i",
            "gp" + "t-",
            "dot" + "env",
            "prompt_" + "templates",
            "skip_" + "a" + "i",
        ]
    )
    result = subprocess.run(
        ["git", "grep", "-i", "-I", "-E", "-n", pattern],
        cwd=PROJECT_ROOT,
        capture_output=True,
        text=True,
    )
    assert result.returncode == 1, result.stdout
    assert result.stdout == ""
    # git grep -E does not treat \b as a word boundary on every platform.
    regex = re.compile(pattern, re.IGNORECASE)
    tracked = subprocess.run(
        ["git", "ls-files", "-z"],
        cwd=PROJECT_ROOT,
        capture_output=True,
    )
    hits: list[str] = []
    for name in tracked.stdout.split(b"\0"):
        if not name:
            continue
        path = PROJECT_ROOT / name.decode()
        if not path.is_file():
            continue
        text = path.read_text(encoding="utf-8", errors="replace")
        for lineno, line in enumerate(text.splitlines(), 1):
            if regex.search(line):
                hits.append(f"{name.decode()}:{lineno}:{line}")
    assert hits == [], "\n".join(hits)


def test_offline_fixture_sync() -> None:
    """Offline demo generated/ must match selinux/ (refresh_offline_fixture.sh)."""
    fix = PROJECT_ROOT / "tests" / "fixtures" / "offline" / "generated"
    for name in ("myapp.te", "myapp.fc"):
        assert (fix / name).read_text(encoding="utf-8") == (
            PROJECT_ROOT / "selinux" / "myapp" / name
        ).read_text(encoding="utf-8"), f"Drift in offline/generated/{name} — run refresh_offline_fixture.sh"


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
        version_file=PROJECT_ROOT / "selinux" / "myapp" / "policy_version.txt",
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


def test_docs_match_the_store() -> None:
    """Training pages name the store files, the RHEL 9 guide, and the current doc numbers."""
    c103 = (PROJECT_ROOT / "docs/guides/103-CONFIG-FILES.md").read_text(encoding="utf-8")
    assert "ports.local" in c103
    assert "file_contexts.local" in c103
    assert "booleans.local" in c103
    assert "permissive_<type>" in c103
    assert "priority 400" in c103
    assert "selinux-policy-targeted" in c103
    assert "Every `semodule` or `semanage` rebuild rewrites this file" in c103
    assert "It is what the kernel loads" in c103
    assert "/etc/selinux/targeted/contexts/files/" in c103
    assert "not this file by itself" not in c103

    c101 = (PROJECT_ROOT / "docs/guides/101-CONCEPTS.md").read_text(encoding="utf-8")
    assert "Java started from that shell runs as **`unconfined_java_t`**" in c101

    c102 = (PROJECT_ROOT / "docs/guides/102-COMMANDS.md").read_text(encoding="utf-8")
    assert "because `ausearch` reads stdin" in c102
    assert "`aureport -a` lists AVC events" in c102
    assert "`aureport -a --summary` counts them" in c102
    assert "stub module" not in c102
    assert "looking for `apache`" in c102
    assert "red_hat_enterprise_linux/9/html/using_selinux" in c102
    assert "red_hat_enterprise_linux/8/" not in c102

    c104 = (PROJECT_ROOT / "docs/guides/104-HAND-BUILT-MODULE.md").read_text(encoding="utf-8")
    assert c104.count("--checkpoint") >= 3
    assert "sudo mvn" not in c104
    assert "shopapi_log_t:dir { search write add_name }" in c104
    assert "shopapi_var_lib_t:dir { search write add_name }" in c104

    demo = (PROJECT_ROOT / "docs/demo.md").read_text(encoding="utf-8")
    assert "LAST_VERIFIED:**" in demo
    # Honest about the JWS/distro difference, and every on-screen step named.
    assert "loaded_unconfined" in demo and "jws6_tomcat_t" in demo
    for cmd in ("sepac triage tomcat", "sepac capture shopapi --full-audit",
                "sepac generate shopapi --approve execmem --apply", "sepac check shopapi",
                "sepac load shopapi --enforcing", "sepac status shopapi"):
        assert cmd in demo, cmd

    c401 = (PROJECT_ROOT / "docs/shipping.md").read_text(encoding="utf-8")
    assert "/var/lib/selinux-policy-ops/<app>/selinux_soak_last_fail.json" in c401
    assert "/var/lib/<app>/" not in c401
    assert "203 talk" not in c401

    monitor = (PROJECT_ROOT / "scripts/monitor_avc.sh").read_text(encoding="utf-8")
    assert "/var/lib/<app>" not in monitor
    assert 'FAIL_DIR:-/var/lib/selinux-policy-ops/<app>' in monitor
    assert '${fail_dir_shown}/selinux_soak_last_fail.json' in monitor

    readme = (PROJECT_ROOT / "README.md").read_text(encoding="utf-8")
    docs_readme = (PROJECT_ROOT / "docs/guides/README.md").read_text(encoding="utf-8")
    assert "(**204**)" not in readme
    assert "API key" not in readme
    assert "103-CONFIG-FILES.md" in readme
    assert "104-HAND-BUILT-MODULE.md" in readme
    assert "103-CONFIG-FILES.md" in docs_readme
    assert "→ **202**" not in docs_readme

    live = (PROJECT_ROOT / "docs/guides/LIVE_CHECKS.md").read_text(encoding="utf-8")
    assert "ls /var/lib/selinux/targeted/active/" in live
    assert "ls -l /etc/selinux/targeted/contexts/files/" in live
    assert (
        "sha256sum /etc/selinux/targeted/policy/policy.33 "
        "/var/lib/selinux/targeted/active/policy.kern"
    ) in live


def test_baseline_fixture_rerun_does_not_append() -> None:
    """A baseline-only log writes no header and no version bump. A second run is byte-identical."""
    case = PROJECT_ROOT / "tests/fixtures/deterministic/05-baseline-covered"
    gen = PROJECT_ROOT / "cli" / "deterministic_gen.py"
    manifest = PROJECT_ROOT / "config" / "myapp.manifest.yml"
    te = PROJECT_ROOT / "selinux" / "myapp" / "myapp.te"
    fc = PROJECT_ROOT / "selinux" / "myapp" / "myapp.fc"
    original = te.read_bytes()
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        first = root / "first"
        second = root / "second"
        cmd = [
            sys.executable,
            str(gen),
            "--avc-log",
            str(case / "avc.log"),
            "--manifest",
            str(manifest),
            "--existing-fc",
            str(fc),
            "--bump-version",
        ]
        one = subprocess.run(
            [*cmd, "--existing-te", str(te), "--out-dir", str(first)],
            cwd=PROJECT_ROOT,
            capture_output=True,
            text=True,
        )
        assert one.returncode == 0, one.stderr
        assert "No change" in one.stdout
        written = (first / "myapp.te").read_bytes()
        assert written == original
        assert "Generated by" not in written.decode().split("policy_module(")[0]
        assert not (first / "policy_version.txt").exists()
        two = subprocess.run(
            [*cmd, "--existing-te", str(first / "myapp.te"), "--out-dir", str(second)],
            cwd=PROJECT_ROOT,
            capture_output=True,
            text=True,
        )
        assert two.returncode == 0, two.stderr
        assert "No change" in two.stdout
        again = (second / "myapp.te").read_bytes()
        assert again == written
        assert again.decode().count("Generated by") == original.decode().count("Generated by")


def test_deterministic_verdict_fixture_coverage() -> None:
    """Every classification verdict has at least one golden fixture row."""
    root = PROJECT_ROOT / "tests" / "fixtures" / "deterministic"
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
    root = PROJECT_ROOT / "tests" / "fixtures" / "deterministic"
    default_manifest = PROJECT_ROOT / "config" / "myapp.manifest.yml"
    te = PROJECT_ROOT / "selinux" / "myapp" / "myapp.te"
    fc = PROJECT_ROOT / "selinux" / "myapp" / "myapp.fc"

    for case_dir in _deterministic_fixture_dirs(root):
        case = case_dir.name
        manifest = case_dir / "manifest.yml"
        if not manifest.is_file():
            manifest = default_manifest
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

        if case == "14-stale-entrypoint":
            out_te = (case_dir / "_out" / "myapp.te").read_text(encoding="utf-8")
            for stale in ("bin_t", "java_exec_t", "usr_t"):
                assert f"{stale}:file" not in out_te, f"{case}: must not allow {stale}"
                assert not any(
                    row.get("tgt") == stale and "allow" in (row.get("rendered") or "")
                    for row in rows
                ), f"{case}: rendered an allow for {stale}"
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
            # Fixture 10's manifest app_name is httpd, so the generator writes httpd.te.
            te_name = "httpd.te" if case == "10-boolean-hint" else "myapp.te"
            out_te = (case_dir / "_out" / te_name).read_text(encoding="utf-8")
            assert "http_port_t" not in out_te, f"{case}: must not add permanent allow on http_port_t"
            row = next(r for r in rows if r.get("verdict") == "boolean")
            assert row.get("boolean") == "httpd_can_network_connect"
            assert "setsebool -P" in (row.get("rendered") or "")
            assert payload.get("host_admin_actions"), f"{case}: expected host_admin_actions in findings"
        if case == "10-boolean-hint":
            row10 = next(r for r in rows if r.get("verdict") == "boolean")
            assert row10.get("engine") == "curated_override", row10
            avc10 = (case_dir / "avc.log").read_text(encoding="utf-8")
            assert "httpd_t" in avc10
            assert "myapp_t" not in avc10


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


def test_avc_filter_keeps_domain_denials() -> None:
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
    assert 'name="passwd"' in out
    assert 'path="/etc/passwd"' in out
    assert "var_spool_t" in out


def test_init_uses_daemon_domain() -> None:
    """systemd start uses init_daemon_domain, and the FCOS overlay files are gone."""
    te = (PROJECT_ROOT / "selinux" / "myapp" / "myapp.te").read_text(encoding="utf-8")
    assert te.count("init_daemon_domain(myapp_t, myapp_exec_t)") == 1
    assert te.count("init_daemon_domain(myapp_backend_t, myapp_backend_exec_t)") == 1
    assert "dyntransition" not in te
    assert "type_transition" not in te
    assert "allow init_t" not in te
    for path in (
        PROJECT_ROOT / "selinux" / "myapp_canary.te",
        PROJECT_ROOT / "selinux" / "myapp_canary.fc",
        PROJECT_ROOT / "selinux" / "myapp_ports.cil",
        PROJECT_ROOT / "ansible" / "roles" / "selinux_pac" / "templates" / "ports_from_manifest.cil.j2",
    ):
        assert not path.exists(), path
    forbidden = (PROJECT_ROOT / "scripts" / "validate_forbidden_patterns.sh").read_text(encoding="utf-8")
    assert "myapp_canary" not in forbidden
    enforce = (PROJECT_ROOT / "ansible" / "roles" / "selinux_pac" / "tasks" / "enforce.yml").read_text(encoding="utf-8")
    defaults = (PROJECT_ROOT / "ansible" / "roles" / "selinux_pac" / "defaults" / "main.yml").read_text(encoding="utf-8")
    assert "stub_policy" not in enforce and "stub_policy" not in defaults
    assert "FCOS" not in enforce and "FCOS" not in defaults
    classify = (PROJECT_ROOT / "scripts" / "classify_policy_blast_radius.sh").read_text(encoding="utf-8")
    assert "CLASSIFY_SKIP_SELINUX" in classify
    assert "CLASSIFY_SKIP_PODMAN" not in classify
    assert "DEMO_PODMAN_IMAGE" not in (PROJECT_ROOT / "lab" / "lib" / "demo_estate.sh").read_text(encoding="utf-8")
    assert "container_build" not in (PROJECT_ROOT / ".gitignore").read_text(encoding="utf-8")
    readme = (PROJECT_ROOT / "ansible" / "README.md").read_text(encoding="utf-8")
    assert "RHEL 9" in readme
    assert "FCOS" not in readme
    generated = (PROJECT_ROOT / "tests" / "fixtures" / "offline" / "generated" / "myapp.te").read_text(encoding="utf-8")
    assert generated == te


def test_vm_check_reports_each_result() -> None:
    """Each QA check prints PASS or FAIL, and a loaded bypass module fails the host check."""
    script = PROJECT_ROOT / "lab" / "vm_check.sh"
    text = script.read_text(encoding="utf-8")
    for name in (
        "integration-compile",
        "integration-semantics",
        "reject_compiled_bypasses",
        "test_avc_epoch_window",
        "test_avc_query_epoch",
        "integration-blast-radius",
        "host-unchanged",
    ):
        assert name in text
    assert "semodule -l" in text
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        bindir = root / "bin"
        bindir.mkdir()
        log = root / "ssh.log"
        ssh = bindir / "ssh"
        ssh.write_text(
            "#!/bin/sh\n"
            "cmd=\n"
            "for arg in \"$@\"; do cmd=\"$arg\"; done\n"
            "printf '%s\\n' \"$cmd\" >> \"$VM_LOG\"\n"
            "case \"$cmd\" in\n"
            "  *HOME/selinux-pac*) printf '%s' /home/ansible/selinux-pac ;;\n"
            "  *semodule*)\n"
            "    if [ \"$VM_MODE\" = bypass ]; then\n"
            "      printf '%s\\n' 'bypass_shadow 1.0' 'pac_control 1.0'\n"
            "    else\n"
            "      printf '%s\\n' 'shopapi 1.0'\n"
            "    fi\n"
            "    ;;\n"
            "  *integration-compile*)\n"
            "    if [ \"$VM_MODE\" = compile-fail ]; then echo 'SKIP integration-compile' >&2; exit 1; fi\n"
            "    ;;\n"
            "  *sha256sum*)\n"
            "    n=0\n"
            "    if [ -f \"$VM_HASH_LOG\" ]; then n=$(wc -l < \"$VM_HASH_LOG\"); fi\n"
            "    echo x >> \"$VM_HASH_LOG\"\n"
            "    if [ \"$VM_MODE\" = policy-changed ] && [ \"$n\" -gt 0 ]; then\n"
            "      printf '%s\\n' 'bbbb  /sys/fs/selinux/policy'\n"
            "    else\n"
            "      printf '%s\\n' 'aaaa  /sys/fs/selinux/policy'\n"
            "    fi\n"
            "    ;;\n"
            "esac\n"
            "exit 0\n",
            encoding="utf-8",
        )
        ssh.chmod(0o755)
        rsync = bindir / "rsync"
        rsync.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
        rsync.chmod(0o755)
        env = os.environ.copy()
        env["PATH"] = f"{bindir}{os.pathsep}{env.get('PATH', '')}"
        env["QA_HOST"] = "qa.example"
        env["PROD_HOST"] = "prod.example"
        env["SSH_USER"] = "ansible"
        env["VM_LOG"] = str(log)
        env["VM_HASH_LOG"] = str(root / "hashes")
        env["VM_MODE"] = "ok"
        ok = subprocess.run(
            [BASH, str(script)],
            cwd=PROJECT_ROOT,
            capture_output=True,
            text=True,
            env=env,
        )
        assert ok.returncode == 0, ok.stdout + ok.stderr
        for name in (
            "integration-compile",
            "integration-semantics",
            "reject_compiled_bypasses",
            "test_avc_epoch_window",
            "test_avc_query_epoch",
            "integration-blast-radius",
            "host-unchanged",
        ):
            assert f"PASS {name}" in ok.stdout, ok.stdout
        env["VM_MODE"] = "bypass"
        leaked = subprocess.run(
            [BASH, str(script)],
            cwd=PROJECT_ROOT,
            capture_output=True,
            text=True,
            env=env,
        )
        assert leaked.returncode != 0
        assert "FAIL host-unchanged" in leaked.stdout
        env["VM_MODE"] = "compile-fail"
        broken = subprocess.run(
            [BASH, str(script)],
            cwd=PROJECT_ROOT,
            capture_output=True,
            text=True,
            env=env,
        )
        assert broken.returncode != 0
        assert "FAIL integration-compile" in broken.stdout
        env["VM_MODE"] = "policy-changed"
        (root / "hashes").write_text("", encoding="utf-8")
        changed = subprocess.run(
            [BASH, str(script)],
            cwd=PROJECT_ROOT,
            capture_output=True,
            text=True,
            env=env,
        )
        assert changed.returncode != 0
        assert "FAIL host-unchanged" in changed.stdout
        assert "sha256sum /sys/fs/selinux/policy" in text


def test_audit_health_fails_closed() -> None:
    """Monitor and the health script refuse unless auditd is enabled and lost did not grow."""
    health = PROJECT_ROOT / "scripts" / "check_audit_health.sh"
    enforce = (
        PROJECT_ROOT / "ansible/roles/selinux_pac/tasks/enforce.yml"
    ).read_text(encoding="utf-8")
    assert "check_audit_health.sh" in enforce
    assert "not (force_enforce" in enforce
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        bindir = root / "bin"
        bindir.mkdir()
        marker = root / "marker"
        marker.write_text("100\n", encoding="utf-8")
        (marker.parent / "marker.audit_lost").write_text("1\n", encoding="utf-8")

        def write_tools(active: str, enabled: str, lost: str) -> None:
            (bindir / "systemctl").write_text(
                "#!/bin/sh\n"
                "if [ \"$1\" = is-active ]; then\n"
                f"  [ {active!r} = active ] && exit 0\n"
                "  exit 3\n"
                "fi\nexit 1\n",
                encoding="utf-8",
            )
            (bindir / "systemctl").chmod(0o755)
            (bindir / "auditctl").write_text(
                "#!/bin/sh\n"
                f"printf '%s\\n' 'enabled {enabled}' 'lost {lost}'\n",
                encoding="utf-8",
            )
            (bindir / "auditctl").chmod(0o755)

        env = os.environ.copy()
        env["PATH"] = f"{bindir}{os.pathsep}/usr/bin:/bin"
        write_tools("inactive", "1", "1")
        down = subprocess.run(
            [BASH, str(health), str(marker)],
            cwd=PROJECT_ROOT,
            capture_output=True,
            text=True,
            env=env,
        )
        assert down.returncode != 0
        assert "auditd is not active" in down.stderr
        write_tools("active", "0", "1")
        disabled = subprocess.run(
            [BASH, str(health), str(marker)],
            cwd=PROJECT_ROOT,
            capture_output=True,
            text=True,
            env=env,
        )
        assert disabled.returncode != 0
        assert "enabled" in disabled.stderr
        write_tools("active", "1", "4")
        grew = subprocess.run(
            [BASH, str(health), str(marker)],
            cwd=PROJECT_ROOT,
            capture_output=True,
            text=True,
            env=env,
        )
        assert grew.returncode != 0
        assert "lost records since the marker" in grew.stderr
        write_tools("active", "1", "1")
        ok = subprocess.run(
            [BASH, str(health), str(marker)],
            cwd=PROJECT_ROOT,
            capture_output=True,
            text=True,
            env=env,
        )
        assert ok.returncode == 0, ok.stderr

        for rel in (
            "scripts/validate_policy_semantics.sh",
            "scripts/lib/policy_module_diff_side.sh",
            "scripts/lib/blast_radius_collect.sh",
        ):
            text = (PROJECT_ROOT / rel).read_text(encoding="utf-8")
            for line in text.splitlines():
                if "semodule " in line and "-p " in line:
                    assert " -n " in f" {line} ", line


def test_runner_var_selects_rhel_host() -> None:
    """SELinux jobs stay on Stream 9 unless RUNNER is the rhel9-utm label."""
    import yaml

    jobs = {
        PROJECT_ROOT / ".github" / "workflows" / "selinux-policy-ci.yml": "compiled-policy",
        PROJECT_ROOT / ".github" / "workflows" / "selinux-policy-app.yml": "app-compiled-policy",
        PROJECT_ROOT / ".github" / "workflows" / "selinux-policy-app-proof.yml": "bypass-rejected",
        PROJECT_ROOT / ".github" / "workflows" / "demo-estate.yml": "shopapi-policy",
    }
    for path, job_id in jobs.items():
        workflow = yaml.safe_load(path.read_text(encoding="utf-8"))
        job = workflow["jobs"][job_id]
        assert "vars.RUNNER" in str(job["runs-on"])
        assert "rhel9-utm" in str(job["container"])
        assert "quay.io/centos/centos:stream9" in str(job["container"])
        assert "fedora:41" not in path.read_text(encoding="utf-8")
    guide = (PROJECT_ROOT / "docs" / "guides" / "303-TESTING.md").read_text(encoding="utf-8")
    assert "rhel-ci" in guide
    assert "rhel-qa" in guide and "rhel-prod" in guide
    assert "make vm-check" in guide


def test_runner_container_expression_both_cases() -> None:
    """rhel9-utm selects no container. Any other RUNNER value keeps Stream 9."""
    expr = re.compile(
        r"vars\.RUNNER != 'rhel9-utm' && '([^']+)' \|\| fromJSON\('null'\)"
    )

    def evaluate(runner: str, image: str):
        # GitHub Actions && and || return the operand, and fromJSON('null') is null.
        left = image if runner != "rhel9-utm" else False
        return left if left else None

    jobs = {
        PROJECT_ROOT / ".github" / "workflows" / "selinux-policy-ci.yml": "compiled-policy",
        PROJECT_ROOT / ".github" / "workflows" / "selinux-policy-app.yml": "app-compiled-policy",
        PROJECT_ROOT / ".github" / "workflows" / "selinux-policy-app-proof.yml": "bypass-rejected",
        PROJECT_ROOT / ".github" / "workflows" / "demo-estate.yml": "shopapi-policy",
    }
    import yaml

    for path, job_id in jobs.items():
        workflow = yaml.safe_load(path.read_text(encoding="utf-8"))
        container = str(workflow["jobs"][job_id]["container"])
        match = expr.search(container)
        assert match, container
        assert "vars.RUNNER == 'rhel9-utm'" not in container
        image = match.group(1)
        assert evaluate("rhel9-utm", image) is None
        assert evaluate("", image) == "quay.io/centos/centos:stream9"
        assert evaluate("ubuntu-latest", image) == "quay.io/centos/centos:stream9"
        runs = "\n".join(
            step.get("run") or "" for step in workflow["jobs"][job_id]["steps"]
        )
        assert "sudo dnf install" in runs
        assert re.search(r"(?m)^dnf install", runs) is None
    guide = (PROJECT_ROOT / "docs" / "guides" / "303-TESTING.md").read_text(encoding="utf-8")
    assert "github-runner ALL=(ALL) NOPASSWD: /usr/bin/dnf, /usr/bin/bash" in guide
    ci = (PROJECT_ROOT / ".github/workflows/selinux-policy-ci.yml").read_text(encoding="utf-8")
    assert "sudo bash scripts/validate_policy_semantics.sh" in ci
    assert "sudo bash scripts/reject_compiled_bypasses.sh" in ci


def test_soak_counts_every_domain_denial() -> None:
    """Denials outside the manifest paths still count when scontext is the app domain."""
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        bindir = root / "bin"
        bindir.mkdir()
        marker = root / "marker"
        marker.write_text("2000\n", encoding="utf-8")
        lines = [
            "type=AVC msg=audit(1000.1:1): avc: denied { read } for pid=1 "
            'path="/etc/pki/ca-trust/extracted/pem/old.pem" '
            "scontext=system_u:system_r:shopapi_t:s0 "
            "tcontext=system_u:object_r:cert_t:s0 tclass=file permissive=1",
            "type=AVC msg=audit(3000.1:2): avc: denied { read } for pid=1 "
            'path="/etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem" '
            "scontext=system_u:system_r:shopapi_t:s0 "
            "tcontext=system_u:object_r:cert_t:s0 tclass=file permissive=1",
            "type=AVC msg=audit(3001.1:3): avc: denied { read } for pid=1 "
            'path="/etc/shopapi-extra.conf" '
            "scontext=system_u:system_r:shopapi_t:s0 "
            "tcontext=system_u:object_r:etc_t:s0 tclass=file permissive=1",
            "type=AVC msg=audit(3002.1:4): avc: denied { read } for pid=1 "
            'path="/opt/shopapi/lib/app.jar" '
            "scontext=system_u:system_r:shopapi_t:s0 "
            "tcontext=system_u:object_r:shopapi_lib_t:s0 tclass=file permissive=1",
            "type=AVC msg=audit(3003.1:5): avc: denied { read } for pid=1 "
            'path="/etc/httpd/conf/httpd.conf" '
            "scontext=system_u:system_r:httpd_t:s0 "
            "tcontext=system_u:object_r:httpd_config_t:s0 tclass=file permissive=1",
        ]
        ausearch = bindir / "ausearch"
        ausearch.write_text("#!/bin/sh\nprintf '%s\\n' " + " ".join(repr(line) for line in lines) + "\n", encoding="utf-8")
        ausearch.chmod(0o755)
        _install_healthy_audit(bindir)
        env = os.environ.copy()
        env["PATH"] = f"{bindir}{os.pathsep}{env.get('PATH', '')}"
        env.pop("AUDIT_LOG", None)
        result = subprocess.run(
            [
                BASH,
                str(PROJECT_ROOT / "scripts" / "monitor_avc.sh"),
                "--manifest",
                str(PROJECT_ROOT / "config" / "shopapi.manifest.yml"),
                "--marker-file",
                str(marker),
                "--max-avc",
                "0",
                "--format",
                "json",
                "--show-lines",
                "0",
            ],
            cwd=PROJECT_ROOT,
            capture_output=True,
            text=True,
            env=env,
        )
        payload = json.loads(result.stdout)
        assert payload["count"] == 3, result.stdout + result.stderr
        assert payload["status"] == "fail"
        assert "httpd_t" not in result.stdout


def test_soak_ignore_is_explicit() -> None:
    """Only soak.ignore drops a domain denial, and the daily JSON records the count."""
    loader = PROJECT_ROOT / "scripts" / "lib" / "app_manifest.py"
    bad = subprocess.run(
        ["python3", str(loader), "validate", str(PROJECT_ROOT / "config" / "shopapi.manifest.yml")],
        cwd=PROJECT_ROOT,
        capture_output=True,
        text=True,
    )
    assert bad.returncode == 0, bad.stderr
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        manifest = root / "app.manifest.yml"
        text = (PROJECT_ROOT / "config" / "shopapi.manifest.yml").read_text(encoding="utf-8")
        text += "\nsoak:\n  ignore:\n    - tclass: file\n      target_type: etc_t\n"
        manifest.write_text(text, encoding="utf-8")
        ok = subprocess.run(
            ["python3", str(loader), "validate", str(manifest)],
            cwd=PROJECT_ROOT,
            capture_output=True,
            text=True,
        )
        assert ok.returncode == 0, ok.stderr
        broken = root / "bad.manifest.yml"
        broken.write_text(text + "    - tclass: 'file class'\n      target_type: etc_t\n", encoding="utf-8")
        rejected = subprocess.run(
            ["python3", str(loader), "validate", str(broken)],
            cwd=PROJECT_ROOT,
            capture_output=True,
            text=True,
        )
        assert rejected.returncode != 0
        bindir = root / "bin"
        bindir.mkdir()
        marker = root / "marker"
        marker.write_text("2000\n", encoding="utf-8")
        line = (
            "type=AVC msg=audit(3001.1:3): avc: denied { read } for pid=1 "
            'path="/etc/shopapi-extra.conf" '
            "scontext=system_u:system_r:shopapi_t:s0 "
            "tcontext=system_u:object_r:etc_t:s0 tclass=file permissive=1"
        )
        ausearch = bindir / "ausearch"
        ausearch.write_text("#!/bin/sh\nprintf '%s\\n' " + repr(line) + "\n", encoding="utf-8")
        ausearch.chmod(0o755)
        _install_healthy_audit(bindir)
        env = os.environ.copy()
        env["PATH"] = f"{bindir}{os.pathsep}{env.get('PATH', '')}"
        env.pop("AUDIT_LOG", None)
        result = subprocess.run(
            [
                BASH,
                str(PROJECT_ROOT / "scripts" / "monitor_avc.sh"),
                "--manifest",
                str(manifest),
                "--marker-file",
                str(marker),
                "--max-avc",
                "0",
                "--format",
                "json",
                "--show-lines",
                "0",
            ],
            cwd=PROJECT_ROOT,
            capture_output=True,
            text=True,
            env=env,
        )
        payload = json.loads(result.stdout)
        assert payload["count"] == 0, result.stdout + result.stderr
        assert payload["ignored_count"] == 1
        assert payload["ignored"] == [{"tclass": "file", "target_type": "etc_t", "count": 1}]
        assert payload["status"] == "pass"


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
    match = hints[0].get("match") or {}
    assert match.get("src_type") == "httpd_t"
    assert match.get("tgt_type") == "http_port_t"
    assert match.get("tclass") == "tcp_socket"
    assert match.get("perms") == ["name_connect"]


def test_fc_labeling_drift_detection() -> None:
    from fc_labeling import existing_fc_covers, filter_fc_fix_lines, strip_redundant_fc_lines

    baseline = (PROJECT_ROOT / "selinux" / "myapp" / "myapp.fc").read_text(encoding="utf-8")
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


def test_system_jvm_exec_bin_exception() -> None:
    """The system JVM is bin_t on RHEL 9. Only the manifest exception allows it."""
    import argparse

    from deterministic_gen import classify, finding_needs_review_allowed
    from policy_rules import (
        EXEC_BIN_EXCEPTION,
        VERDICT_BASELINE,
        VERDICT_INTERFACE,
        VERDICT_NEEDS_REVIEW,
    )

    manifest = {
        "app_name": "shopapi",
        "domain": "shopapi_t",
        "paths": {"install_root": "/opt/shopapi"},
    }
    jvm = ("/usr/lib/jvm/java-17-openjdk/bin/java",)
    perms = frozenset({"execute", "execute_no_trans", "read", "open", "getattr", "map"})
    for tgt in ("bin_t", "java_exec_t"):
        need = AccessNeed("shopapi_t", tgt, "file", perms)
        finding = classify(need, manifest, jvm, "", "", False, None, [])
        assert finding.verdict == VERDICT_NEEDS_REVIEW, (tgt, finding)
        assert finding.rendered == "corecmd_exec_bin(shopapi_t)"
        assert finding.review_key == EXEC_BIN_EXCEPTION
        assert "selinux_exceptions.exec_bin" in finding.note
        assert "java_exec(" not in finding.rendered
        opt_in = argparse.Namespace(allow_needs_review=True, allow_needs_review_perm=["execute"])
        assert not finding_needs_review_allowed(finding, opt_in)

    reviewed = {**manifest, "selinux_exceptions": {"exec_bin": "Reviewed: system JVM is bin_t."}}
    need = AccessNeed("shopapi_t", "bin_t", "file", perms)
    accepted = classify(need, reviewed, jvm, "", "", False, None, [])
    assert accepted.verdict == VERDICT_INTERFACE
    assert accepted.rendered == "corecmd_exec_bin(shopapi_t)"
    assert "Reviewed: system JVM is bin_t." in accepted.note

    entry = AccessNeed("shopapi_t", "bin_t", "file", frozenset({"entrypoint"}))
    blocked = classify(entry, reviewed, jvm, "", "", False, None, [])
    assert "corecmd_exec_bin(" not in blocked.rendered
    assert not blocked.rendered.startswith("allow ")

    for existing in ("corecmd_exec_bin(shopapi_t)\n", "java_exec(shopapi_t)\n"):
        again = classify(need, manifest, jvm, existing, "", False, None, [])
        assert again.verdict == VERDICT_BASELINE, existing
    commented = classify(
        need,
        manifest,
        jvm,
        "# generator writes corecmd_exec_bin(shopapi_t) only because\n",
        "",
        False,
        None,
        [],
    )
    assert commented.verdict == VERDICT_NEEDS_REVIEW

    tmp_map = classify(
        AccessNeed("shopapi_t", "tmp_t", "file", frozenset({"map"})),
        manifest,
        ("/tmp/hsperfdata_shopapi/1",),
        "",
        "",
        False,
        None,
        [],
    )
    assert tmp_map.rendered == "files_map_generic_tmp_files(shopapi_t)"
    tmp_both = classify(
        AccessNeed("shopapi_t", "tmp_t", "file", frozenset({"map", "write"})),
        manifest,
        ("/tmp/hsperfdata_shopapi/1",),
        "",
        "",
        False,
        None,
        [],
    )
    assert "files_map_generic_tmp_files(shopapi_t)" in tmp_both.rendered
    assert "files_manage_generic_tmp_files(shopapi_t)" in tmp_both.rendered

    seed = (PROJECT_ROOT / "selinux" / "shopapi" / "shopapi.te").read_text(encoding="utf-8")
    seed_rules = re.sub(r"#.*", "", seed)
    assert "java_exec(" not in seed_rules and "corecmd_exec_bin(" not in seed_rules
    assert "type shopapi_lib_t;" in seed
    shop = (PROJECT_ROOT / "config" / "shopapi.manifest.yml").read_text(encoding="utf-8")
    assert "exec_bin:" in shop and "alias of bin_t" in shop
    rules = (PROJECT_ROOT / "cli" / "policy_rules.py").read_text(encoding="utf-8")
    assert "java_exec_t mono_exec_t" in rules


def test_boolean_triage_loads_policy_once() -> None:
    """One policy load or one sesearch per denial, one semanage per run, one interface parse."""
    import types
    from unittest import mock

    import boolean_hints as bh
    import deterministic_gen as dg

    need = AccessNeed("myapp_t", "http_port_t", "tcp_socket", frozenset({"name_connect"}))
    two = AccessNeed("myapp_t", "var_t", "file", frozenset({"read", "open"}))
    lines = [
        "allow httpd_t http_port_t:tcp_socket name_connect; [ httpd_can_network_connect ]:True",
        "allow domain port_type:tcp_socket name_connect; [ nis_enabled || httpd_x ]:True",
        "allow myapp_t http_port_t:tcp_socket name_connect;",
        "allow myapp_t var_t:file read; [ split_bool ]:True",
        "allow myapp_t var_t:file { open getattr }; [ split_bool ]:False",
        "allow myapp_t var_t:file read; [ ! half_bool ]:True",
    ]
    assert bh.booleans_from_sesearch_lines(lines, need) == {
        "httpd_can_network_connect",
        "nis_enabled",
        "httpd_x",
    }
    assert bh.booleans_from_sesearch_lines(lines, two) == {"split_bool"}

    listing = "SELinux boolean State Default Description\n" + "\n".join(
        f"{n} (off , off) desc {n}" for n in ("httpd_can_network_connect", "nis_enabled", "split_bool")
    )
    calls: list[str] = []

    def fake_run(cmd: list[str]) -> subprocess.CompletedProcess:
        calls.append(cmd[0])
        out = listing if cmd[0] == "semanage" else "\n".join(lines)
        return subprocess.CompletedProcess(cmd, 0, out, "")

    with tempfile.NamedTemporaryFile() as kern:
        bh._list_booleans_cached.cache_clear()
        with mock.patch.object(bh, "_run", fake_run), mock.patch.dict(
            sys.modules, {"setools": None}
        ), mock.patch.object(bh.shutil, "which", return_value="/usr/bin/sesearch"):
            first = bh.lookup_booleans_for_need(need, policy_kern=Path(kern.name))
            second = bh.lookup_booleans_for_need(two, policy_kern=Path(kern.name))
        assert first.status == "matched"
        assert [m.name for m in first.matches] == ["httpd_can_network_connect", "nis_enabled"]
        assert [m.name for m in second.matches] == ["split_bool"]
        assert calls.count("semanage") == 1, calls
        assert calls.count("sesearch") == 2, calls

        loads: list[str] = []

        class Rule:
            def __init__(self, perms: set[str], booleans: set[str] | None) -> None:
                self.perms = perms
                self._booleans = booleans

            @property
            def conditional(self) -> object:
                if self._booleans is None:
                    raise ValueError("not conditional")
                return types.SimpleNamespace(booleans=self._booleans)

        def fake_policy(path: str) -> object:
            loads.append(path)
            return object()

        def fake_query(policy: object, **kw: object) -> object:
            rules = [Rule({"name_connect"}, {"httpd_can_network_connect"}), Rule({"name_connect"}, None)]
            return types.SimpleNamespace(results=lambda: iter(rules))

        fake = types.SimpleNamespace(SELinuxPolicy=fake_policy, TERuleQuery=fake_query)
        bh._SETOOLS_POLICY.clear()
        with mock.patch.dict(sys.modules, {"setools": fake}):
            for _ in range(3):
                got = bh.booleans_covering_need(Path(kern.name), need)
                assert got == {"httpd_can_network_connect"}
        assert len(loads) == 1, loads
        bh._SETOOLS_POLICY.clear()
    bh._list_booleans_cached.cache_clear()

    parses: list[str] = []

    class IfSet:
        def from_file(self, fd: object) -> None:
            parses.append("parse")

    with tempfile.NamedTemporaryFile("w", suffix="interface_info") as info:
        sep = types.ModuleType("sepolgen")
        modules = {
            "sepolgen": sep,
            "sepolgen.access": types.SimpleNamespace(AccessVector=lambda av: av),
            "sepolgen.defaults": types.SimpleNamespace(interface_info=lambda: info.name),
            "sepolgen.interfaces": types.SimpleNamespace(InterfaceSet=IfSet),
            "sepolgen.matching": types.SimpleNamespace(
                Match=lambda: types.SimpleNamespace(search=lambda ifset, av: [])
            ),
        }
        for name in ("access", "defaults", "interfaces", "matching"):
            setattr(sep, name, modules[f"sepolgen.{name}"])
        dg._SEPOLGEN_IFSETS.clear()
        with mock.patch.dict(sys.modules, modules):
            for _ in range(4):
                assert dg.try_sepolgen_interface("myapp_t", "etc_t", "file", frozenset({"read"})) is None
        dg._SEPOLGEN_IFSETS.clear()
    assert parses == ["parse"], parses


def test_forbidden_exec_bin_needs_manifest_reason() -> None:
    """Raw bin_t execute always fails. The macros pass only with the manifest reason."""
    checker = PROJECT_ROOT / "scripts" / "validate_forbidden_patterns.sh"
    semantics = (PROJECT_ROOT / "scripts" / "validate_policy_semantics.sh").read_text(
        encoding="utf-8"
    )
    assert "grant_beyond_control bin_t file execute" in semantics
    assert "selinux_exceptions.exec_bin" in semantics

    def run(root: Path, rule: str, manifest: Path) -> subprocess.CompletedProcess:
        (root / "probe.te").write_text(
            "policy_module(probe, 1.0.0)\n"
            "type probe_t;\n"
            "type probe_exec_t;\n"
            "type probe_var_lib_t;\n"
            "# corecmd_exec_bin(probe_t) in a comment is not a rule\n"
            f"{rule}\n",
            encoding="utf-8",
        )
        (root / "probe.fc").write_text(
            "/opt/probe    gen_context(system_u:object_r:probe_exec_t,s0)\n"
            "/var/lib/probe(/.*)?    gen_context(system_u:object_r:probe_var_lib_t,s0)\n",
            encoding="utf-8",
        )
        return subprocess.run(
            [BASH, str(checker), str(root), "--app", "probe", "--manifest", str(manifest)],
            cwd=PROJECT_ROOT,
            capture_output=True,
            text=True,
        )

    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        none = root / "none.manifest.yml"
        none.write_text("app_name: probe\n", encoding="utf-8")
        reviewed = root / "reviewed.manifest.yml"
        reviewed.write_text(
            "app_name: probe\n"
            "selinux_exceptions:\n"
            "  exec_bin: The system JVM is bin_t on RHEL 9; reviewed by the owner.\n",
            encoding="utf-8",
        )
        short = root / "short.manifest.yml"
        short.write_text("selinux_exceptions:\n  exec_bin: ok\n", encoding="utf-8")

        clean = run(root, "allow probe_t probe_var_lib_t:file { read };", none)
        assert clean.returncode == 0, clean.stderr
        for raw in (
            "allow probe_t bin_t:file { execute execute_no_trans map };",
            "allow probe_t bin_t:file execute;",
            "allow probe_t java_exec_t:file { execute };",
        ):
            for manifest in (none, reviewed):
                out = run(root, raw, manifest)
                assert out.returncode != 0, (raw, manifest.name)
                assert "raw allow of execute on bin_t" in out.stderr
        for macro in (
            "corecmd_exec_bin(probe_t)",
            "java_exec(probe_t)",
            "can_exec(probe_t, java_exec_t)",
        ):
            refused = run(root, macro, none)
            assert refused.returncode != 0, macro
            assert "selinux_exceptions.exec_bin" in refused.stderr
            accepted = run(root, macro, reviewed)
            assert accepted.returncode == 0, (macro, accepted.stderr)
            malformed = run(root, macro, short)
            assert malformed.returncode != 0, macro

    sys.path.insert(0, str(PROJECT_ROOT / "scripts" / "lib"))
    from app_manifest import validate_selinux_exceptions

    assert validate_selinux_exceptions(None) == []
    assert validate_selinux_exceptions({"exec_bin": "The system JVM is bin_t on RHEL 9."}) == []
    assert validate_selinux_exceptions({"exec_bin": ""})
    assert validate_selinux_exceptions({"bin_t": "The system JVM is bin_t on RHEL 9."})
    assert validate_selinux_exceptions(["exec_bin"])


def test_rhel_runtime_file_contexts() -> None:
    myapp_fc = (PROJECT_ROOT / "selinux" / "myapp" / "myapp.fc").read_text(encoding="utf-8")
    assert "/run/myapp(/.*)?" in myapp_fc
    assert "/var/run/myapp(/.*)?" in myapp_fc
    shopapi_fc = (PROJECT_ROOT / "selinux" / "shopapi" / "shopapi.fc").read_text(encoding="utf-8")
    assert "/run/shopapi(/.*)?" in shopapi_fc
    unit = (PROJECT_ROOT / "lab" / "apps" / "shopapi" / "shopapi.service").read_text(encoding="utf-8")
    assert "NoNewPrivileges=false" in unit
    assert not any(line.startswith("SELinuxContext=") for line in unit.splitlines())
    assert "ExecStart=/opt/shopapi/bin/shopapi -jar /opt/shopapi/shopapi.jar" in unit
    assert "/opt/shopapi/bin/shopapi            -- gen_context(system_u:object_r:shopapi_exec_t,s0)" in shopapi_fc
    assert "shopapi_lib_t" in shopapi_fc


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
    fixture = PROJECT_ROOT / "tests" / "fixtures" / "tune_report" / "tomcat"
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
        env["AUDIT_LOG"] = str(Path(tmp) / "no-such-audit.log")
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

    case_dir = PROJECT_ROOT / "tests" / "fixtures" / "deterministic" / "11-private-getopt"
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
                str(PROJECT_ROOT / "selinux" / "myapp" / "myapp.te"),
                "--existing-fc",
                str(PROJECT_ROOT / "selinux" / "myapp" / "myapp.fc"),
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


def test_policy_rules_are_the_single_source() -> None:
    """Generator and CI must read forbidden and needs-review rules from policy_rules."""
    import deterministic_gen
    import policy_audit
    import policy_rules

    assert deterministic_gen.FORBIDDEN_TARGET_TYPES is policy_rules.FORBIDDEN_TARGET_TYPES
    assert deterministic_gen.needs_review_hits is policy_rules.needs_review_hits
    assert policy_audit.COMPILED_REJECT_CAPABILITIES is policy_rules.COMPILED_REJECT_CAPABILITIES
    review_caps = {
        perm for tclass, perm, _scope in policy_rules.NEEDS_REVIEW_RULES if tclass == "capability"
    }
    assert policy_rules.COMPILED_REJECT_CAPABILITIES <= review_caps
    assert "execmem" not in policy_rules.COMPILED_REJECT_CAPABILITIES
    script = (PROJECT_ROOT / "scripts" / "validate_forbidden_patterns.sh").read_text(
        encoding="utf-8"
    )
    assert "from policy_rules import FORBIDDEN_TARGET_TYPES" in script
    assert "for priv in shadow_t unconfined_t sysadm_t" not in script

    def module(root: Path, allow_line: str) -> None:
        te = (
            "policy_module(probe, 1.0.0)\n"
            "type probe_t;\n"
            "type probe_exec_t;\n"
            "type probe_var_lib_t;\n"
            f"{allow_line}\n"
        )
        fc = (
            "/opt/probe    gen_context(system_u:object_r:probe_exec_t,s0)\n"
            "/var/lib/probe(/.*)?    gen_context(system_u:object_r:probe_var_lib_t,s0)\n"
        )
        (root / "probe.te").write_text(te, encoding="utf-8")
        (root / "probe.fc").write_text(fc, encoding="utf-8")

    checker = PROJECT_ROOT / "scripts" / "validate_forbidden_patterns.sh"
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        module(root, "allow probe_t probe_var_lib_t:file { read };")
        clean = subprocess.run(
            [BASH, str(checker), str(root), "--app", "probe"],
            cwd=PROJECT_ROOT,
            capture_output=True,
            text=True,
        )
        assert clean.returncode == 0, clean.stderr
        module(root, "allow probe_t selinux_config_t:file { read };")
        foreign = subprocess.run(
            [BASH, str(checker), str(root), "--app", "probe"],
            cwd=PROJECT_ROOT,
            capture_output=True,
            text=True,
        )
        assert foreign.returncode != 0, foreign.stdout
        assert "selinux_config_t" in foreign.stderr


def test_compiled_policy_rejects_foreign_entrypoint() -> None:
    """entrypoint on a type this module does not declare fails the compiled check."""
    fixture = PROJECT_ROOT / "tests" / "fixtures" / "compiled-policy"
    audit = PROJECT_ROOT / "cli" / "policy_audit.py"
    declared = fixture / "declared-types.txt"
    foreign = subprocess.run(
        [
            sys.executable,
            str(audit),
            "--allows-file",
            str(fixture / "foreign-entrypoint.txt"),
            "--declared-types-file",
            str(declared),
            "--domain",
            "shopapi_t",
        ],
        cwd=PROJECT_ROOT,
        capture_output=True,
        text=True,
    )
    assert foreign.returncode != 0, foreign.stdout
    for stale in ("bin_t", "java_exec_t", "usr_t"):
        assert stale in foreign.stderr, foreign.stderr
    own = subprocess.run(
        [
            sys.executable,
            str(audit),
            "--allows-file",
            str(fixture / "own-entrypoint.txt"),
            "--declared-types-file",
            str(declared),
            "--domain",
            "shopapi_t",
        ],
        cwd=PROJECT_ROOT,
        capture_output=True,
        text=True,
    )
    assert own.returncode == 0, own.stderr
    semantics = (PROJECT_ROOT / "scripts" / "validate_policy_semantics.sh").read_text(
        encoding="utf-8"
    )
    assert "--declared-types-file" in semantics


def test_policy_audit_rejects_review_bypasses() -> None:
    from policy_audit import (
        allowed_fc_roots,
        audit_allow_text,
        audit_permissive_types,
        audit_type_attributes,
        dontaudit_forbidden_hits,
        fc_paths_outside_roots,
    )

    domain = "shopapi_t"
    assert audit_allow_text("allow shopapi_t shadow_t:file { read open getattr };", domain)
    assert audit_allow_text("allow shopapi_t shadow_t : file { read open };", domain)
    assert audit_allow_text("allow shopapi_t file_type:file *;", domain)
    assert audit_allow_text("allow shopapi_t self : capability { sys_admin };", domain)
    assert audit_allow_text(
        "allow shopapi_t security_t : security { load_policy setenforce };", domain
    )
    assert audit_allow_text("allow shopapi_t self:capability { sys_module };", domain)
    assert not audit_allow_text("allow shopapi_t shopapi_var_lib_t:file { read write };", domain)
    assert audit_type_attributes("shopapi_t\n   unconfined_domain_type", domain)
    assert audit_permissive_types("Permissive Types: 1\n   shopapi_t", domain)
    assert not audit_permissive_types("Permissive Types: 1\n   unconfined_t", domain)
    assert dontaudit_forbidden_hits("dontaudit shopapi_t shadow_t:file read;")
    assert dontaudit_forbidden_hits("dontaudit shopapi_t\n    shadow_t:file { read };")
    assert not dontaudit_forbidden_hits("dontaudit shopapi_t shopapi_log_t:file read;")
    roots = allowed_fc_roots(
        {
            "install_root": "/opt/shopapi",
            "var_dir": "/var/lib/shopapi",
            "log_dir": "/var/log/shopapi",
            "runtime_dir": "/run/shopapi",
        }
    )
    assert fc_paths_outside_roots(["/etc/shadow"], roots) == ["/etc/shadow"]
    assert fc_paths_outside_roots(["/opt/shopapi(/.*)?"], roots) == []
    assert fc_paths_outside_roots(["/var/run/shopapi(/.*)?"], roots) == []

    result = subprocess.run(
        [sys.executable, str(PROJECT_ROOT / "cli" / "policy_audit.py"), "--selinux-dir", "selinux"],
        cwd=PROJECT_ROOT,
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0, result.stderr or result.stdout


def test_compiled_bypass_fixtures_fail_closed() -> None:
    """Each review bypass is a real module the Stream 9 job must reject."""
    import yaml

    names = [
        "interface-macro",
        "split-line",
        "permissive-declaration",
        "file-type-star",
        "unconfined-domain-type",
        "load-policy-setenforce",
        "sys-module-sys-admin",
        "fc-relabel-shadow",
        "foreign-entrypoint",
        "dontaudit-forbidden",
        "can-setenforce",
        "can-load-policy",
        "can-read-shadow-passwords",
        "can-write-shadow-passwords",
        "exec-bin-alias",
    ]
    root = PROJECT_ROOT / "tests" / "fixtures" / "compiled-bypasses"
    script = (PROJECT_ROOT / "scripts" / "reject_compiled_bypasses.sh").read_text(encoding="utf-8")
    semantics = (PROJECT_ROOT / "scripts" / "validate_policy_semantics.sh").read_text(encoding="utf-8")
    assert "was accepted" in script
    assert "accepted clean" in script
    assert "expected message" in script
    assert "pac_control_t" in semantics
    assert "attribute grant beyond control" in semantics
    assert "--dontaudit" in semantics
    assert "/etc/shadow" in semantics
    clean = root / "clean" / "bypass.te"
    assert "typeattribute" not in clean.read_text(encoding="utf-8")
    assert "allow " not in clean.read_text(encoding="utf-8")
    for name in names:
        assert name in script
        te = (root / name / "bypass.te").read_text(encoding="utf-8")
        fc = (root / name / "bypass.fc").read_text(encoding="utf-8")
        assert te.startswith("policy_module(bypass, 1.0.0)\n")
        assert "bypass_exec_t" in fc
        expected = (root / name / "expected.txt").read_text(encoding="utf-8").strip()
        assert expected, name
    interface_te = (root / "interface-macro" / "bypass.te").read_text(encoding="utf-8")
    interface_if = (root / "interface-macro" / "bypass.if").read_text(encoding="utf-8")
    assert "allow " not in interface_te
    assert "shadow_t:file read" in interface_if
    split = (root / "split-line" / "bypass.te").read_text(encoding="utf-8")
    allow_lines = [line for line in split.splitlines() if "allow" in line]
    assert allow_lines
    assert all("shadow_t" not in line for line in allow_lines)
    assert "permissive bypass_t;" in (root / "permissive-declaration" / "bypass.te").read_text(
        encoding="utf-8"
    )
    assert "file_type:file *;" in (root / "file-type-star" / "bypass.te").read_text(encoding="utf-8")
    assert "typeattribute bypass_t unconfined_domain_type;" in (
        root / "unconfined-domain-type" / "bypass.te"
    ).read_text(encoding="utf-8")
    load = (root / "load-policy-setenforce" / "bypass.te").read_text(encoding="utf-8")
    assert "load_policy" in load and "setenforce" in load
    caps = (root / "sys-module-sys-admin" / "bypass.te").read_text(encoding="utf-8")
    assert "sys_module" in caps and "sys_admin" in caps
    assert "/etc/shadow" in (root / "fc-relabel-shadow" / "bypass.fc").read_text(encoding="utf-8")
    assert "bin_t:file entrypoint" in (root / "foreign-entrypoint" / "bypass.te").read_text(
        encoding="utf-8"
    )
    assert "dontaudit bypass_t shadow_t:file read;" in (
        root / "dontaudit-forbidden" / "bypass.te"
    ).read_text(encoding="utf-8")
    for attr in (
        "can_setenforce",
        "can_load_policy",
        "can_read_shadow_passwords",
        "can_write_shadow_passwords",
    ):
        matched = list(root.glob(f"*/bypass.te"))
        assert any(
            f"typeattribute bypass_t {attr};" in path.read_text(encoding="utf-8")
            for path in matched
        ), attr
        assert attr in semantics
    assert "sesearch --direct" not in semantics
    assert "typepermissive" in semantics
    assert (root / "can-setenforce" / "expected.txt").read_text(encoding="utf-8").strip() == (
        "attribute grant beyond control: setenforce on security"
    )
    assert (root / "can-load-policy" / "expected.txt").read_text(encoding="utf-8").strip() == (
        "attribute grant beyond control: load_policy on security"
    )
    assert (root / "can-read-shadow-passwords" / "expected.txt").read_text(
        encoding="utf-8"
    ).strip() == "attribute grant beyond control: can_read_shadow_passwords"
    assert (root / "can-write-shadow-passwords" / "expected.txt").read_text(
        encoding="utf-8"
    ).strip() == "attribute grant beyond control: can_write_shadow_passwords"

    workflow = yaml.safe_load(
        (PROJECT_ROOT / ".github" / "workflows" / "selinux-policy-ci.yml").read_text(encoding="utf-8")
    )
    compiled = "\n".join(
        str(step.get("run", "")) for step in workflow["jobs"]["compiled-policy"]["steps"]
    )
    assert "reject_compiled_bypasses.sh" in compiled
    assert "--app payments" in compiled

    declared = subprocess.run(
        [
            BASH,
            str(PROJECT_ROOT / "scripts" / "validate_policy_semantics.sh"),
            "--print-declared-types",
            str(root / "foreign-entrypoint" / "bypass.te"),
        ],
        cwd=PROJECT_ROOT,
        capture_output=True,
        text=True,
    )
    assert declared.returncode == 0, declared.stderr
    assert set(declared.stdout.split()) == {"bypass_t", "bypass_exec_t"}

    audit = subprocess.run(
        [
            sys.executable,
            str(PROJECT_ROOT / "cli" / "policy_audit.py"),
            "--dontaudit-file",
            str(root / "dontaudit-forbidden" / "bypass.te"),
        ],
        cwd=PROJECT_ROOT,
        capture_output=True,
        text=True,
    )
    assert audit.returncode != 0, audit.stdout
    assert "shadow_t" in audit.stderr


def test_collect_soak_facts_monitor_crash() -> None:
    script = PROJECT_ROOT / "scripts" / "collect_soak_facts.sh"
    with tempfile.TemporaryDirectory() as tmp:
        marker = Path(tmp) / "marker"
        marker.write_text("1\n", encoding="utf-8")
        stub = Path(tmp) / "monitor.sh"
        stub.write_text("#!/bin/bash\necho '{\"count\":0}'\nexit 2\n", encoding="utf-8")
        stub.chmod(0o755)
        env = os.environ.copy()
        env["MONITOR_AVC_BIN"] = str(stub)
        result = subprocess.run(
            [
                BASH,
                str(script),
                "--app",
                "myapp",
                "--marker-file",
                str(marker),
                "--report-file",
                str(Path(tmp) / "missing.json"),
            ],
            cwd=PROJECT_ROOT,
            capture_output=True,
            text=True,
            env=env,
        )
        assert result.returncode == 0, result.stderr
        facts = json.loads(result.stdout)
        assert facts["avc_fail_closed"] is True
        assert facts["avc_net_new_count"] == -1
        assert facts["avc_count_since_marker"] == -1


def test_skip_soak_days_and_break_glass_reason() -> None:
    """skip_soak_days skips only the clock. force_enforce requires a recorded reason."""
    import yaml

    tasks = yaml.safe_load(
        (PROJECT_ROOT / "ansible/roles/selinux_pac/tasks/enforce.yml").read_text(encoding="utf-8")
    )
    by_name = {task["name"]: task for task in tasks if isinstance(task, dict) and "name" in task}
    day = by_name["Fail when soak period not met"]["when"]
    daily = by_name["Require consecutive passing daily soak results"]["when"]
    marker = by_name["Fail when canary marker missing"]["when"]
    net_new = by_name["Fail when net-new AVC needs too high"]["when"]
    report_gate = by_name["Fail when deploy report gate not satisfied"]["when"]
    for clause in (day, daily):
        assert any("skip_soak_days" in str(item) for item in clause)
        assert any("force_enforce" in str(item) for item in clause)
    for clause in (marker, net_new, report_gate):
        assert any("force_enforce" in str(item) for item in clause)
        assert not any("skip_soak_days" in str(item) for item in clause)
    reason = by_name["Require a reason for break-glass enforce"]
    assert reason["ansible.builtin.fail"]
    assert any("break_glass_reason" in str(item) for item in reason["when"])

    guide_201 = (PROJECT_ROOT / "docs/guides/201-TOOL-COMMANDS.md").read_text(encoding="utf-8")
    guide_302 = (PROJECT_ROOT / "docs/guides/302-TECHNICAL.md").read_text(encoding="utf-8")
    for guide in (guide_201, guide_302):
        assert "skips only the day count and the daily history" in guide
        assert "skips the marker, the AVC gate, net-new, the report, the day count, and the daily history" in guide
    assert "--skip-soak-days" in guide_302
    assert "break_glass" in guide_302

    report_script = PROJECT_ROOT / "scripts" / "post_deploy_report.sh"
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        skipped = root / "skipped.json"
        run = subprocess.run(
            [
                BASH,
                str(report_script),
                "--phase",
                "enforce",
                "--manifest",
                str(root / "no-manifest.yml"),
                "--report-file",
                str(skipped),
                "--marker-file",
                str(root / "absent-marker"),
                "--var-dir",
                str(root),
                "--policy-version",
                "1.2.3",
                "--skip-soak-days",
            ],
            cwd=PROJECT_ROOT,
            capture_output=True,
            text=True,
        )
        assert skipped.is_file(), run.stderr
        body = json.loads(skipped.read_text(encoding="utf-8"))
        assert body["skip_soak_days"] is True
        assert body["force_enforce"] is False
        assert body["daily_history_bypassed"] is True
        assert body["break_glass_reason"] is None
        glass = root / "glass.json"
        run = subprocess.run(
            [
                BASH,
                str(report_script),
                "--phase",
                "enforce",
                "--manifest",
                str(root / "no-manifest.yml"),
                "--report-file",
                str(glass),
                "--marker-file",
                str(root / "absent-marker"),
                "--var-dir",
                str(root),
                "--policy-version",
                "1.2.3",
                "--force-enforce",
                "--break-glass-reason",
                "show the enforcing denial before the fix",
            ],
            cwd=PROJECT_ROOT,
            capture_output=True,
            text=True,
        )
        assert glass.is_file(), run.stderr
        body = json.loads(glass.read_text(encoding="utf-8"))
        assert body["force_enforce"] is True
        assert body["skip_soak_days"] is False
        assert body["daily_history_bypassed"] is True
        assert body["break_glass_reason"] == "show the enforcing denial before the fix"


def test_sepac_help_lists_all_commands() -> None:
    """sepac --help lists every command in two groups."""
    sepac = PROJECT_ROOT / "cli" / "sepac.py"
    result = subprocess.run(
        [sys.executable, str(sepac), "--help"],
        capture_output=True, text=True,
    )
    out = result.stdout + result.stderr
    assert result.returncode == 0 or result.returncode == 2, out
    qa_cmds = ["doctor", "triage", "tune", "denials", "generate", "check", "load", "status"]
    ansible_cmds = ["build", "publish", "canary", "soak", "enforce", "rollback"]
    for cmd in qa_cmds + ansible_cmds:
        assert cmd in out, f"missing {cmd} in help"
    assert "On the QA host:" in out
    assert "Where Ansible runs:" in out


def test_sepac_dry_run_golden() -> None:
    """--dry-run prints the exact underlying argv per section 2."""
    sepac = PROJECT_ROOT / "cli" / "sepac.py"

    def dr(*args: str) -> str:
        r = subprocess.run(
            [sys.executable, str(sepac), *args, "--dry-run"],
            capture_output=True, text=True, cwd=PROJECT_ROOT,
        )
        return (r.stdout + r.stderr).strip()

    # generate with two --approve
    out = dr("generate", "shopapi", "--approve", "execmem", "--approve", "dac_override", "--apply")
    assert "--allow-needs-review-perm execmem" in out
    assert "--allow-needs-review-perm dac_override" in out
    assert "--apply" in out
    assert "--app-root" in out

    # check passes --app to each validator
    out = dr("check", "shopapi")
    assert "validate_app_manifest.sh" in out
    assert "compile_and_validate.sh" in out
    assert "--app shopapi" in out
    assert "validate_policy_semantics.sh" in out

    # load outputs semodule, restorecon, semanage port
    out = dr("load", "shopapi")
    assert "semodule -i" in out
    assert "restorecon -Rv" in out
    assert "semanage port -a" in out
    assert "shopapi_port_t" in out

    # enforce without --ticket is refused
    r = subprocess.run(
        [sys.executable, str(sepac), "enforce", "--env", "dev", "--dry-run"],
        capture_output=True, text=True, cwd=PROJECT_ROOT,
    )
    assert r.returncode == 2

    # canary dry-run
    inv = PROJECT_ROOT / "ansible" / "inventory.dev.example.yml"
    if inv.is_file():
        # Create a temp inventory so the env validation passes
        pass  # dev inventory may not exist; test validates the error message
    out = dr("doctor")
    assert "selinux_pac_adopt.sh" in out


def test_sepac_validation() -> None:
    """Invalid APP, PERM, and --env are refused before anything runs."""
    sepac = PROJECT_ROOT / "cli" / "sepac.py"

    def rc(*args: str) -> int:
        r = subprocess.run(
            [sys.executable, str(sepac), *args],
            capture_output=True, text=True, cwd=PROJECT_ROOT,
        )
        return r.returncode

    assert rc("triage", "INVALID-APP") == 2
    assert rc("triage", "123bad") == 2
    assert rc("generate", "shopapi", "--approve", "UPPER") == 2
    # no manifest → refused for generate, check, load
    assert rc("generate", "nonexistent", "--dry-run") == 2
    assert rc("check", "nonexistent", "--dry-run") == 2
    assert rc("load", "nonexistent", "--dry-run") == 2
    # triage, tune, denials accept no-manifest apps
    assert rc("triage", "tomcat", "--dry-run") == 0
    assert rc("denials", "tomcat", "--dry-run") == 0
    # bad --env
    assert rc("canary", "--env", "nonexistent", "--dry-run") == 2


def test_sepac_load_guardrail() -> None:
    """load refuses when role file is missing or says production."""
    sepac = PROJECT_ROOT / "cli" / "sepac.py"
    with tempfile.TemporaryDirectory() as td:
        # No role file
        role_path = str(Path(td) / "role")
        env = dict(os.environ)
        env["SEPAC_ROLE_FILE"] = role_path
        r = subprocess.run(
            [sys.executable, str(sepac), "load", "shopapi", "--dry-run"],
            capture_output=True, text=True, cwd=PROJECT_ROOT, env=env,
        )
        assert r.returncode == 0  # --dry-run skips the check

        r = subprocess.run(
            [sys.executable, str(sepac), "load", "shopapi"],
            capture_output=True, text=True, cwd=PROJECT_ROOT, env=env,
        )
        assert r.returncode == 1
        assert "not qa" in (r.stdout + r.stderr).lower()

        # production
        Path(role_path).write_text("production\n")
        r = subprocess.run(
            [sys.executable, str(sepac), "load", "shopapi"],
            capture_output=True, text=True, cwd=PROJECT_ROOT, env=env,
        )
        assert r.returncode == 1
        assert "not qa" in (r.stdout + r.stderr).lower()

        # qa is allowed (but will fail because semodule doesn't exist on mac;
        # the guardrail itself must pass)
        Path(role_path).write_text("qa\n")
        r = subprocess.run(
            [sys.executable, str(sepac), "load", "shopapi"],
            capture_output=True, text=True, cwd=PROJECT_ROOT, env=env,
        )
        # Exit may be non-zero because semodule is absent, but it must NOT be 1 from the guardrail
        assert "not qa" not in (r.stdout + r.stderr).lower()


def test_sepac_blocked_hint() -> None:
    """A needs_review block names the permission and the exact command to run after review."""
    sys.path.insert(0, str(PROJECT_ROOT / "cli"))
    import sepac as sepac_mod

    with tempfile.TemporaryDirectory() as td:
        fj = Path(td) / "findings.json"
        fj.write_text(json.dumps({
            "generation_blocked": True,
            "findings": [
                {"verdict": "needs_review", "perms": ["execmem"]},
                # exec_bin is unlocked only by the manifest, never by --approve
                {"verdict": "needs_review", "perms": ["execute"], "review_key": "exec_bin"},
                {"verdict": "forbidden", "perms": ["read"]},
            ],
        }), encoding="utf-8")
        hint = sepac_mod.blocked_hint("shopapi", fj)
        assert hint == (
            "Blocked for review: execmem. "
            "After review: sepac generate shopapi --approve execmem --apply"
        ), hint
        fj.write_text(json.dumps({"generation_blocked": False, "findings": []}), encoding="utf-8")
        assert sepac_mod.blocked_hint("shopapi", fj) is None
        assert sepac_mod.blocked_hint("shopapi", Path(td) / "missing.json") is None


def test_sepac_global_flags_help_and_capture() -> None:
    """--dry-run before the command is honoured; help hides internals; capture
    sorts denials into expected (soak.ignore) and new; check skips compile
    honestly without selinux-policy-devel; load never steals a port."""
    sepac_py = PROJECT_ROOT / "cli" / "sepac.py"

    def run(*args: str, env: dict[str, str] | None = None) -> subprocess.CompletedProcess[str]:
        return subprocess.run([sys.executable, str(sepac_py), *args], capture_output=True,
                              text=True, cwd=PROJECT_ROOT, env=env)

    # A global --dry-run must never run the generator for real.
    with tempfile.TemporaryDirectory() as td:
        trap = Path(td) / "bash"
        trap.write_text("#!/bin/sh\necho RAN >> " + str(Path(td) / "ran") + "\n", encoding="utf-8")
        trap.chmod(0o755)
        env = dict(os.environ)
        env["PATH"] = f"{td}:{env.get('PATH', '')}"
        for argv in (("--dry-run", "generate", "shopapi", "--apply"),
                     ("generate", "shopapi", "--apply", "--dry-run"),
                     ("--dry-run", "load", "shopapi", "--enforcing")):
            r = run(*argv, env=env)
            assert r.returncode == 0, r.stderr
            assert "dev_generate_policy.sh" in r.stdout or "semodule -i" in r.stdout, r.stdout
        assert not (Path(td) / "ran").exists(), "a --dry-run command executed bash"

    out = run("--help").stdout
    assert "SUPPRESS" not in out and "_complete" not in out and "_man" not in out, out
    assert "capture" in out
    out = run("--dry-run", "load", "shopapi", "--enforcing").stdout
    assert "semanage permissive -d shopapi_t" in out
    assert "semanage port -m" not in out
    out = run("--dry-run", "capture", "shopapi", "--url", "/feature-spool", "--full-audit").stdout
    for want in ("semodule -DB", "systemctl restart shopapi.service", "GET http://127.0.0.1:8091/health",
                 "GET http://127.0.0.1:8091/feature-spool", "semodule_restore_dontaudit.sh --app shopapi"):
        assert want in out, (want, out)
    assert run("capture", "shopapi", "--url", "feature-spool;rm", "--dry-run").returncode == 2

    sys.path.insert(0, str(PROJECT_ROOT / "cli"))
    import sepac as sepac_mod

    manifest = sepac_mod.load_manifest(PROJECT_ROOT / "config" / "shopapi.manifest.yml")
    line = ('type=AVC msg=audit({e}.1:1): avc:  denied  {{ {p} }} for pid=1 path="{path}" '
            'scontext=system_u:system_r:{s}:s0 tcontext=system_u:object_r:{t}:s0 tclass={c} permissive={m}')
    lines = [
        line.format(e=50, p="open", path="/old", s="shopapi_t", t="etc_t", c="file", m=0),
        line.format(e=200, p="open read", path="/etc/passwd", s="shopapi_t", t="passwd_file_t", c="file", m=0),
        line.format(e=200, p="open", path="/var/spool/shopapi/feature.log", s="shopapi_t", t="var_spool_t", c="file", m=0),
        line.format(e=200, p="read", path="/x", s="tomcat_t", t="etc_t", c="file", m=1),
    ]
    summary = "\n".join(sepac_mod.capture_summary("shopapi", manifest, lines, 100))
    assert "shopapi_t: 2 denials (enforcing: blocked)" in summary, summary
    assert "passwd_file_t file" in summary  # expected: listed in soak.ignore
    assert "{ open } on var_spool_t file  /var/spool/shopapi/feature.log" in summary, summary
    assert "etc_t" not in summary and "tomcat" not in summary, summary
    assert sepac_mod.capture_summary("shopapi", manifest, lines, 300) == ["shopapi_t: no denials"]

    # check without selinux-policy-devel: manifest and forbidden patterns run,
    # compile and semantics are reported as skipped, never as passed.
    if not Path("/usr/share/selinux/devel/Makefile").is_file():
        r = run("check", "shopapi")
        assert r.returncode == 0, r.stdout + r.stderr
        assert "Forbidden-pattern checks passed for shopapi" in r.stdout + r.stderr
        assert "SKIP compile and semantics" in r.stdout

    # load: a port another application type owns is refused, never modified.
    listing = "SELinux Port Type Proto Port Number\nother_port_t tcp 8091\n"
    try:
        sepac_mod.classify_port_assignment(listing, 8091, "tcp", "shopapi_port_t")
    except ValueError as exc:
        assert "Refusing to run semanage port -m" in str(exc)
    else:
        raise AssertionError("a port owned by another type must be refused")


def test_sepac_allow_needs_review_perm_passthrough() -> None:
    """dev_generate_policy.sh passes --allow-needs-review-perm through."""
    gen = (PROJECT_ROOT / "scripts" / "dev_generate_policy.sh").read_text(encoding="utf-8")
    assert "--allow-needs-review-perm" in gen
    pol = (PROJECT_ROOT / "scripts" / "lib" / "policy_generation.sh").read_text(encoding="utf-8")
    assert "--allow-needs-review-perm" in pol


def test_stale_canary_marker_and_force_enforce_report() -> None:
    """An abandoned marker is reported, and force_enforce is written into the deploy report."""
    facts = PROJECT_ROOT / "scripts" / "collect_soak_facts.sh"
    report_script = PROJECT_ROOT / "scripts" / "post_deploy_report.sh"
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        old = root / "shopapi"
        fresh = root / "payments"
        old.mkdir()
        fresh.mkdir()
        old_marker = old / "selinux_canary_deployed_at"
        fresh_marker = fresh / "selinux_canary_deployed_at"
        now = int(time.time())
        old_marker.write_text(str(now - 31 * 86400), encoding="utf-8")
        fresh_marker.write_text(str(now), encoding="utf-8")
        stub = root / "monitor.sh"
        stub.write_text("#!/bin/bash\necho '{\"count\":0,\"net_new_count\":0}'\n", encoding="utf-8")
        stub.chmod(0o755)
        env = os.environ.copy()
        env["MONITOR_AVC_BIN"] = str(stub)
        result = subprocess.run(
            [
                BASH,
                str(facts),
                "--app",
                "shopapi",
                "--marker-file",
                str(old_marker),
                "--report-file",
                str(root / "missing.json"),
            ],
            cwd=PROJECT_ROOT,
            capture_output=True,
            text=True,
            env=env,
        )
        assert result.returncode == 0, result.stderr
        payload = json.loads(result.stdout)
        assert payload["stale_canary_markers"] == [str(old_marker)]
        status = (PROJECT_ROOT / "ansible/roles/selinux_pac/tasks/soak_status.yml").read_text(
            encoding="utf-8"
        )
        assert "stale_canary_markers" in status
        assert "older than 30 days" in status

        out = root / "report.json"
        forced = subprocess.run(
            [
                BASH,
                str(report_script),
                "--phase",
                "enforce",
                "--manifest",
                str(root / "no-manifest.yml"),
                "--report-file",
                str(out),
                "--marker-file",
                str(root / "absent-marker"),
                "--var-dir",
                str(root),
                "--policy-version",
                "1.2.3",
                "--force-enforce",
            ],
            cwd=PROJECT_ROOT,
            capture_output=True,
            text=True,
        )
        assert out.is_file(), forced.stderr
        body = json.loads(out.read_text(encoding="utf-8"))
        assert body["force_enforce"] is True
        assert body["daily_history_bypassed"] is True
        plain = root / "plain.json"
        subprocess.run(
            [
                BASH,
                str(report_script),
                "--phase",
                "enforce",
                "--manifest",
                str(root / "no-manifest.yml"),
                "--report-file",
                str(plain),
                "--marker-file",
                str(root / "absent-marker"),
                "--var-dir",
                str(root),
                "--policy-version",
                "1.2.3",
            ],
            cwd=PROJECT_ROOT,
            capture_output=True,
            text=True,
        )
        assert plain.is_file()
        plain_body = json.loads(plain.read_text(encoding="utf-8"))
        assert plain_body["force_enforce"] is False
        assert plain_body["daily_history_bypassed"] is False


def test_soak_gate_negative_net_new() -> None:
    script = PROJECT_ROOT / "scripts" / "check_soak_gate.sh"
    negative = subprocess.run(
        [BASH, str(script), "--fail-closed", "false", "--net-new", "-1"],
        cwd=PROJECT_ROOT,
        capture_output=True,
        text=True,
    )
    assert negative.returncode == 1, negative.stdout
    closed = subprocess.run(
        [BASH, str(script), "--fail-closed", "true", "--net-new", "0"],
        cwd=PROJECT_ROOT,
        capture_output=True,
        text=True,
    )
    assert closed.returncode == 1
    ok = subprocess.run(
        [BASH, str(script), "--fail-closed", "false", "--net-new", "0"],
        cwd=PROJECT_ROOT,
        capture_output=True,
        text=True,
    )
    assert ok.returncode == 0, ok.stderr


def test_new_canary_ignores_older_soak_files() -> None:
    """A new canary marker drops daily files and fail files from the previous marker."""
    prod = (PROJECT_ROOT / "lab" / "demo_e2e_rhel_prod.sh").read_text(encoding="utf-8")
    mac = (PROJECT_ROOT / "lab" / "demo_e2e_mac.sh").read_text(encoding="utf-8")
    ops = "/var/lib/selinux-policy-ops/shopapi/selinux_soak_last_fail.avc"
    assert ops in prod and ops in mac
    assert "/var/lib/shopapi/selinux_soak_last_fail" not in prod
    assert "rm -f ${SOAK_FAIL_JSON}" not in prod
    check = PROJECT_ROOT / "scripts" / "check_soak_days.sh"
    monitor = PROJECT_ROOT / "scripts" / "monitor_avc.sh"
    with tempfile.TemporaryDirectory() as tmp:
        state = Path(tmp) / "shopapi"
        daily = state / "daily"
        daily.mkdir(parents=True)
        (state / "selinux_canary_deployed_at").write_text("9000\n", encoding="utf-8")
        old_fail = {
            "status": "fail",
            "avc_fail_closed": False,
            "net_new_count": 3,
            "count": 3,
            "since": "1000",
        }
        new_pass = {
            "status": "pass",
            "avc_fail_closed": False,
            "net_new_count": 0,
            "count": 0,
            "since": "9000",
        }
        (daily / "2026-10-06.json").write_text(json.dumps(old_fail), encoding="utf-8")
        (daily / "2026-10-07.json").write_text(json.dumps(new_pass), encoding="utf-8")
        one_day = subprocess.run(
            [
                BASH,
                str(check),
                "--state-dir",
                str(state),
                "--min-days",
                "1",
                "--today",
                "2026-10-07",
            ],
            cwd=PROJECT_ROOT,
            capture_output=True,
            text=True,
        )
        assert one_day.returncode == 0, one_day.stderr
        short = subprocess.run(
            [
                BASH,
                str(check),
                "--state-dir",
                str(state),
                "--min-days",
                "2",
                "--today",
                "2026-10-07",
            ],
            cwd=PROJECT_ROOT,
            capture_output=True,
            text=True,
        )
        assert short.returncode == 1
        assert "missing 2026-10-06" in short.stderr
        assert "did not pass" not in short.stderr
        for day in range(1, 8):
            (daily / f"2026-10-{day:02d}.json").write_text(
                json.dumps(
                    {
                        "status": "pass",
                        "avc_fail_closed": False,
                        "net_new_count": 0,
                        "since": "1000",
                    }
                ),
                encoding="utf-8",
            )
        inherited = subprocess.run(
            [
                BASH,
                str(check),
                "--state-dir",
                str(state),
                "--min-days",
                "7",
                "--today",
                "2026-10-07",
            ],
            cwd=PROJECT_ROOT,
            capture_output=True,
            text=True,
        )
        assert inherited.returncode == 1
        assert "no daily results" in inherited.stderr

        token = "OLD_CANARY_DENIAL"
        (state / "selinux_soak_last_fail.json").write_text(
            json.dumps({"since": "1000", "count": 9, "status": "fail"}),
            encoding="utf-8",
        )
        (state / "selinux_soak_last_fail.avc").write_text(token + "\n", encoding="utf-8")
        (daily / "2026-10-01.json").write_text(
            json.dumps({"since": "1000", "status": "fail", "count": 9}),
            encoding="utf-8",
        )
        bindir = Path(tmp) / "bin"
        bindir.mkdir()
        ausearch = bindir / "ausearch"
        ausearch.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
        ausearch.chmod(0o755)
        _install_healthy_audit(bindir)
        env = os.environ.copy()
        env["PATH"] = f"{bindir}{os.pathsep}{env.get('PATH', '')}"
        env.pop("APP_MANIFEST", None)
        env.pop("AUDIT_LOG", None)
        ran = subprocess.run(
            [
                BASH,
                str(monitor),
                "--domain",
                "shopapi_t",
                "--paths",
                "/opt/shopapi",
                "--manifest",
                str(Path(tmp) / "missing.yml"),
                "--marker-file",
                str(state / "selinux_canary_deployed_at"),
                "--fail-dir",
                str(state),
                "--format",
                "json",
                "--max-avc",
                "0",
                "--skip-if-unavailable",
            ],
            cwd=PROJECT_ROOT,
            capture_output=True,
            text=True,
            env=env,
        )
        assert ran.returncode == 0, ran.stdout + ran.stderr
        assert token not in (ran.stdout + ran.stderr)
        payload = json.loads(ran.stdout)
        assert payload["count"] == 0
        assert payload["status"] == "pass"
        assert "2026-10-01.json" in payload["ignored_stale_daily"]
        assert "selinux_soak_last_fail.json" in payload["ignored_stale_fail"]
        assert "selinux_soak_last_fail.avc" in payload["ignored_stale_fail"]
        assert token in (state / "selinux_soak_last_fail.avc").read_text(encoding="utf-8")


def test_soak_daily_history_and_other_app_guard() -> None:
    record = PROJECT_ROOT / "scripts" / "record_soak_day.sh"
    check = PROJECT_ROOT / "scripts" / "check_soak_days.sh"
    restore = PROJECT_ROOT / "scripts" / "semodule_restore_dontaudit.sh"
    with tempfile.TemporaryDirectory() as tmp:
        state = Path(tmp) / "shopapi"
        junk = subprocess.run(
            [BASH, str(record), "--state-dir", str(state), "--day", "2026-10-07"],
            cwd=PROJECT_ROOT,
            input="not-json",
            capture_output=True,
            text=True,
        )
        assert junk.returncode == 0, junk.stderr
        stored = json.loads((state / "daily" / "2026-10-07.json").read_text(encoding="utf-8"))
        assert stored["avc_fail_closed"] is True
        assert stored["net_new_count"] == -1

        passing = json.dumps(
            {"status": "pass", "avc_fail_closed": False, "net_new_count": 0, "count": 0}
        )
        for day in range(1, 8):
            wrote = subprocess.run(
                [
                    BASH,
                    str(record),
                    "--state-dir",
                    str(state),
                    "--day",
                    f"2026-10-{day:02d}",
                ],
                cwd=PROJECT_ROOT,
                input=passing,
                capture_output=True,
                text=True,
            )
            assert wrote.returncode == 0, wrote.stderr
        ok = subprocess.run(
            [
                BASH,
                str(check),
                "--state-dir",
                str(state),
                "--min-days",
                "7",
                "--today",
                "2026-10-07",
            ],
            cwd=PROJECT_ROOT,
            capture_output=True,
            text=True,
        )
        assert ok.returncode == 0, ok.stderr

        missing = state / "daily" / "2026-10-04.json"
        missing.unlink()
        gap = subprocess.run(
            [
                BASH,
                str(check),
                "--state-dir",
                str(state),
                "--min-days",
                "7",
                "--today",
                "2026-10-07",
            ],
            cwd=PROJECT_ROOT,
            capture_output=True,
            text=True,
        )
        assert gap.returncode == 1
        assert "2026-10-04" in gap.stderr
        restored = subprocess.run(
            [BASH, str(record), "--state-dir", str(state), "--day", "2026-10-04"],
            cwd=PROJECT_ROOT,
            input=passing,
            capture_output=True,
            text=True,
        )
        assert restored.returncode == 0, restored.stderr

        failed = json.dumps(
            {"status": "fail", "avc_fail_closed": False, "net_new_count": 2, "count": 2}
        )
        subprocess.run(
            [BASH, str(record), "--state-dir", str(state), "--day", "2026-10-05"],
            cwd=PROJECT_ROOT,
            input=failed,
            capture_output=True,
            text=True,
            check=True,
        )
        blocked = subprocess.run(
            [
                BASH,
                str(check),
                "--state-dir",
                str(state),
                "--min-days",
                "7",
                "--today",
                "2026-10-07",
            ],
            cwd=PROJECT_ROOT,
            capture_output=True,
            text=True,
        )
        assert blocked.returncode == 1
        assert "2026-10-05" in blocked.stderr

        lab = subprocess.run(
            [BASH, str(check), "--state-dir", str(Path(tmp) / "empty"), "--min-days", "0"],
            cwd=PROJECT_ROOT,
            capture_output=True,
            text=True,
        )
        assert lab.returncode == 0, lab.stderr

        root = Path(tmp) / "state"
        (root / "payments").mkdir(parents=True)
        (root / "payments" / "selinux_canary_deployed_at").write_text("1", encoding="utf-8")
        (root / "shopapi").mkdir()
        (root / "shopapi" / "selinux_canary_deployed_at").write_text("1", encoding="utf-8")
        skipped = subprocess.run(
            [BASH, str(restore), "--app", "shopapi", "--state-root", str(root)],
            cwd=PROJECT_ROOT,
            capture_output=True,
            text=True,
        )
        assert skipped.returncode == 0, skipped.stderr
        assert "skip semodule -B" in skipped.stderr

        alone = Path(tmp) / "alone"
        (alone / "shopapi").mkdir(parents=True)
        (alone / "shopapi" / "selinux_canary_deployed_at").write_text("1", encoding="utf-8")
        bindir = Path(tmp) / "bin"
        bindir.mkdir()
        ran = Path(tmp) / "ran"
        fake = bindir / "semodule"
        fake.write_text(
            "#!/bin/bash\nprintf '%s\\n' ran > \"${SEMODULE_RAN}\"\n",
            encoding="utf-8",
        )
        fake.chmod(0o755)
        env = os.environ.copy()
        env["PATH"] = f"{bindir}:{env.get('PATH', '')}"
        env["SEMODULE_RAN"] = str(ran)
        called = subprocess.run(
            [BASH, str(restore), "--app", "shopapi", "--state-root", str(alone)],
            cwd=PROJECT_ROOT,
            capture_output=True,
            text=True,
            env=env,
        )
        assert called.returncode == 0, called.stderr
        assert ran.read_text(encoding="utf-8").strip() == "ran"

        archived = subprocess.run(
            [BASH, str(restore), "--app", "shopapi", "--state-root", str(root), "--archive"],
            cwd=PROJECT_ROOT,
            capture_output=True,
            text=True,
        )
        assert archived.returncode == 0, archived.stderr
        assert not (root / "shopapi" / "selinux_canary_deployed_at").exists()
        assert (root / "shopapi" / "selinux_canary_deployed_at.enforced").is_file()
        ran.write_text("", encoding="utf-8")
        after = subprocess.run(
            [BASH, str(restore), "--app", "payments", "--state-root", str(root)],
            cwd=PROJECT_ROOT,
            capture_output=True,
            text=True,
            env=env,
        )
        assert after.returncode == 0, after.stderr
        assert "skip semodule -B" not in after.stderr
        assert ran.read_text(encoding="utf-8").strip() == "ran"
        enforce = (PROJECT_ROOT / "ansible/roles/selinux_pac/tasks/enforce.yml").read_text(
            encoding="utf-8"
        )
        assert "--archive" in enforce
        assert "--force-enforce" in enforce


def test_sepac_completion_coverage() -> None:
    """sepac completion bash lists every subcommand and flag."""
    r = subprocess.run(
        [sys.executable, str(PROJECT_ROOT / "cli" / "sepac.py"), "completion", "bash"],
        cwd=PROJECT_ROOT,
        capture_output=True,
        text=True,
    )
    assert r.returncode == 0, r.stderr
    script = r.stdout
    for cmd in ("doctor", "triage", "tune", "denials", "generate", "check",
                "load", "status", "canary", "soak", "enforce", "rollback",
                "build", "publish", "completion"):
        assert cmd in script, f"completion missing subcommand: {cmd}"
    for flag in ("--dry-run", "--verbose", "--version", "--tree", "--env",
                 "--approve", "--manifest", "--ticket"):
        assert flag in script, f"completion missing flag: {flag}"


def test_sepac_complete_from_temp_tree() -> None:
    """_complete apps and envs work from a temporary policy tree."""
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        (root / "config").mkdir()
        (root / "selinux").mkdir()
        (root / "config" / "billing.manifest.yml").write_text("app_name: billing\n")
        (root / "config" / "web.manifest.yml").write_text("app_name: web\n")
        (root / "ansible").mkdir()
        (root / "ansible" / "inventory.staging.yml").write_text("---\n")
        (root / "ansible" / "inventory.prod.yml").write_text("---\n")

        apps_r = subprocess.run(
            [sys.executable, str(PROJECT_ROOT / "cli" / "sepac.py"),
             "--tree", str(root), "_complete", "apps"],
            cwd=PROJECT_ROOT,
            capture_output=True,
            text=True,
        )
        assert apps_r.returncode == 0, apps_r.stderr
        apps = apps_r.stdout.strip().split("\n")
        assert "billing" in apps
        assert "web" in apps

        envs_r = subprocess.run(
            [sys.executable, str(PROJECT_ROOT / "cli" / "sepac.py"),
             "--tree", str(root), "_complete", "envs"],
            cwd=PROJECT_ROOT,
            capture_output=True,
            text=True,
        )
        assert envs_r.returncode == 0, envs_r.stderr
        envs = envs_r.stdout.strip().split("\n")
        assert "staging" in envs
        assert "prod" in envs


def test_sepac_manifest_lookup_order() -> None:
    """Manifest lookup: --manifest > policy tree > /etc/selinux-pac/apps/."""
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        (root / "config").mkdir()
        (root / "selinux").mkdir()
        # Create a manifest in the policy tree
        mpath = root / "config" / "testapp.manifest.yml"
        mpath.write_text(
            "app_name: testapp\n"
            "domain: testapp_t\n"
            "services:\n  primary:\n    unit: testapp.service\n"
            "paths:\n  install_root: /opt/testapp\n  var_dir: /var/lib/testapp\n"
            "  log_dir: /var/log/testapp\n  runtime_dir: /run/testapp\n"
        )

        # Using --tree should find the manifest
        r = subprocess.run(
            [sys.executable, str(PROJECT_ROOT / "cli" / "sepac.py"),
             "--tree", str(root), "triage", "testapp", "--dry-run"],
            cwd=PROJECT_ROOT,
            capture_output=True,
            text=True,
        )
        assert r.returncode == 0, r.stderr

        # --manifest flag takes precedence
        alt = root / "alt.manifest.yml"
        alt.write_text(
            "app_name: testapp\n"
            "domain: testapp_t\n"
            "services:\n  primary:\n    unit: testapp.service\n"
            "paths:\n  install_root: /opt/testapp\n  var_dir: /var/lib/testapp\n"
            "  log_dir: /var/log/testapp\n  runtime_dir: /run/testapp\n"
        )
        r2 = subprocess.run(
            [sys.executable, str(PROJECT_ROOT / "cli" / "sepac.py"),
             "--tree", str(root), "triage", "testapp",
             "--manifest", str(alt), "--dry-run"],
            cwd=PROJECT_ROOT,
            capture_output=True,
            text=True,
        )
        assert r2.returncode == 0, r2.stderr


def test_sepac_man_completeness() -> None:
    """Man page lists every subcommand and groff -ww produces no warnings."""
    r = subprocess.run(
        [sys.executable, str(PROJECT_ROOT / "cli" / "sepac.py"), "_man"],
        cwd=PROJECT_ROOT,
        capture_output=True,
        text=True,
    )
    assert r.returncode == 0, r.stderr
    manpage = r.stdout
    for cmd in ("doctor", "triage", "tune", "denials", "generate", "check",
                "load", "status", "canary", "soak", "enforce", "rollback",
                "build", "publish"):
        assert cmd in manpage, f"man page missing subcommand: {cmd}"
    assert "SEE ALSO" in manpage
    assert "EXAMPLES" in manpage
    assert "FILES" in manpage

    if shutil.which("groff"):
        groff_r = subprocess.run(
            ["groff", "-ww", "-man", "-z"],
            input=manpage,
            capture_output=True,
            text=True,
        )
        warnings = [l for l in (groff_r.stderr or "").splitlines()
                     if "warning" in l.lower()]
        assert not warnings, f"groff warnings: {warnings}"
    else:
        print("SKIP groff warning check: groff not installed")


def test_sepac_version() -> None:
    """sepac --version prints something."""
    r = subprocess.run(
        [sys.executable, str(PROJECT_ROOT / "cli" / "sepac.py"), "--version"],
        cwd=PROJECT_ROOT,
        capture_output=True,
        text=True,
    )
    assert r.returncode == 0
    assert "sepac" in r.stdout


def test_rpm_sepac_parity() -> None:
    """selinux-pac RPM parity check passes."""
    script = PROJECT_ROOT / "scripts" / "validate_rpm_sepac_parity.sh"
    result = subprocess.run(
        ["bash", str(script)],
        cwd=PROJECT_ROOT,
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0, result.stderr or result.stdout


def test_sepac_production_guard() -> None:
    """generate, check, and load refuse when role is production."""
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        role_file = root / "role"
        role_file.write_text("production\n")
        for cmd in ("generate", "check", "load"):
            r = subprocess.run(
                [sys.executable, str(PROJECT_ROOT / "cli" / "sepac.py"), cmd, "shopapi"],
                cwd=PROJECT_ROOT,
                capture_output=True,
                text=True,
                env={**os.environ, "SEPAC_ROLE_FILE": str(role_file)},
            )
            assert r.returncode != 0, f"{cmd} should fail on production"
            assert "production" in r.stderr.lower(), f"{cmd} stderr: {r.stderr}"


def test_ansible_role_writes_role_and_manifest() -> None:
    """The Ansible role tasks write /etc/selinux-pac/role and apps/ copy."""
    install_tasks = (
        PROJECT_ROOT / "ansible" / "roles" / "selinux_pac" / "tasks" / "install_packages.yml"
    ).read_text(encoding="utf-8")
    assert "/etc/selinux-pac/role" in install_tasks
    assert "/etc/selinux-pac/apps/" in install_tasks
    assert "selinux_pac_host_role" in install_tasks
    assert "selinux-pac" in install_tasks

    defaults = (
        PROJECT_ROOT / "ansible" / "roles" / "selinux_pac" / "defaults" / "main.yml"
    ).read_text(encoding="utf-8")
    assert "selinux_pac_host_role" in defaults


def test_prod_dry_run_has_sepac_commands() -> None:
    """Prod talk track uses sepac status and sepac denials."""
    prod = (PROJECT_ROOT / "lab" / "demo_e2e_rhel_prod.sh").read_text(encoding="utf-8")
    assert "sepac status shopapi" in prod
    assert "sepac denials shopapi" in prod


def test_inventory_examples_have_host_role() -> None:
    """All example inventories set selinux_pac_host_role."""
    for name in ("dev.example", "staging.example", "production.example"):
        inv = (PROJECT_ROOT / "ansible" / f"inventory.{name}.yml").read_text(encoding="utf-8")
        assert "selinux_pac_host_role" in inv, f"inventory.{name}.yml missing selinux_pac_host_role"


def test_markdown_links_resolve() -> None:
    """Every relative link in a tracked Markdown file points at a file that exists."""
    import posixpath

    tracked = subprocess.run(["git", "ls-files", "*.md"], capture_output=True, text=True,
                             cwd=str(PROJECT_ROOT)).stdout.split()
    broken = []
    for rel in tracked:
        path = PROJECT_ROOT / rel
        if not path.is_file():
            continue
        text = re.sub(r"```.*?```", "", path.read_text(encoding="utf-8"), flags=re.S)
        for match in re.finditer(r"\]\(([^)\s]+)\)", text):
            target = match.group(1)
            if re.match(r"^[a-z]+:", target) or target.startswith("#"):
                continue
            link = target.split("#", 1)[0]
            if link and not (PROJECT_ROOT / posixpath.normpath(posixpath.join(posixpath.dirname(rel), link))).exists():
                broken.append(f"{rel} -> {target}")
    assert not broken, broken


def test_docs_focus_on_sepac() -> None:
    """The front page and the three main docs lead with sepac, not engine scripts."""
    readme = (PROJECT_ROOT / "README.md").read_text(encoding="utf-8")
    assert readme.splitlines()[0].startswith("# sepac")
    for rel in ("README.md", "docs/sepac.md", "docs/shipping.md", "docs/demo.md"):
        text = (PROJECT_ROOT / rel).read_text(encoding="utf-8")
        blocks = re.findall(r"```bash\n(.*?)```", text, flags=re.S)
        lines = [ln.strip() for b in blocks for ln in b.splitlines() if ln.strip() and not ln.strip().startswith("#")]
        engine = [ln for ln in lines if re.search(r"\b(ansible-playbook|scripts/|dev_generate_policy|compile_and_validate)\b", ln)]
        assert not engine, (rel, engine)
    tracked = subprocess.run(["git", "ls-files", "docs"], capture_output=True, text=True,
                            cwd=str(PROJECT_ROOT)).stdout.split()
    docs = sorted({rel.split("/")[1] for rel in tracked})
    assert docs == ["demo.md", "guides", "sepac.md", "shipping.md"], docs


def test_no_stale_old_paths() -> None:
    """After repo reorg, no tracked file should reference old pre-reorg paths.

    Allowed exceptions:
      - .gitignore (keeps scripts/lab.env for backwards compat)
      - lab/lib/lab_env.sh (intentional fallback to scripts/lab.env)
      - tests/smoke_test.py (this very test, plus docstrings)
    """
    import subprocess

    stale_patterns = [
        r"scripts/demo_",
        r"scripts/reset_demo_vms",
        r"scripts/setup_rhel_hosts",
        r"scripts/run_",
        r"scripts/test_",
        r"scripts/smoke_test\.py",
        r"scripts/refresh_offline",
        r"scripts/sync_rhel_dev",
        r"scripts/build_rpms_on_dev",
        r"scripts/vm_check",
        r"scripts/serve_lab_repo",
        r"scripts/lab_signing_setup",
        r"scripts/lib/training_lab_runner",
        r"scripts/lib/e2e_demo",
        r"scripts/lib/lab_env",
        r"scripts/lib/demo_estate",
        r"scripts/lib/ansible_collections",
        r"selinux/myapp\.te",
        r"selinux/myapp\.fc",
        r"selinux/policy_version\.txt",
        # docs reorganised around sepac; demo apps moved under lab/apps
        r"docs/training/",
        r"docs/tool/",
        r"docs/admin/",
        r"docs/demo/",
        r"docs/examples",
        r"docs/LIVE_CHECKS",
        r"config/README\.md",
        r"(^|[^-/])demo/shopapi",
        r"(^|[^-/])demo/tomcat",
        r"e2e-demo/demo/",
        r"lab/lib/training_lab_runner",
        r"lab/lib/e2e_demo",
        r"lab/lib/present\.sh",
        r"demo_e2e_rhel_dev",
    ]
    allowed_files = {
        ".gitignore",
        "lab/lib/lab_env.sh",
        "tests/smoke_test.py",
    }
    combined = "|".join(stale_patterns)
    result = subprocess.run(
        ["git", "grep", "-lE", combined, "--", ":(exclude).git"],
        capture_output=True, text=True, cwd=str(PROJECT_ROOT),
    )
    hits = [
        f for f in result.stdout.strip().splitlines()
        if f and f not in allowed_files
    ]
    assert not hits, f"Old pre-reorg paths found in: {hits}"


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


def _fixture_book(book_dir: Path, body: str, title: str = "One") -> None:
    """Write a two-page book whose one chapter holds `body`."""
    (book_dir / "assets").mkdir(exist_ok=True)
    (book_dir / "assets" / "book.css").write_text("")
    (book_dir / "book.toml").write_text(
        'title = "Test Book"\n[[front]]\nfile = "index.md"\ntitle = "Cover"\n'
        '[[part]]\ntitle = "Part I. Test"\n'
        f'chapters = [ {{ file = "01-one.md", title = "{title}" }} ]\n'
    )
    (book_dir / "index.md").write_text("# Test Book\n")
    (book_dir / "01-one.md").write_text(body)


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


def test_book_builder_never_renders_silently_wrong() -> None:
    """Syntax the subset does not have is an error, never literal text in the page."""
    module = _load_book_builder()
    with tempfile.TemporaryDirectory() as tmp:
        book_dir = Path(tmp)

        # a link title is supported, and the target still validates
        _fixture_book(book_dir, '# One\n\nSee [the docs](https://x.test/a "The docs").\n')
        out = book_dir / "out"
        module.build(module.load_book(book_dir), book_dir, out)
        page = (out / "01-one.html").read_text()
        assert 'title="The docs"' in page, page
        assert "[the docs]" not in page, page

        # an image becomes an <img>, not a broken link with a stray bang
        (book_dir / "assets" / "diagram.svg").write_text("<svg></svg>")
        _fixture_book(book_dir, '# One\n\n![Flow](asset:diagram.svg)\n')
        module.build(module.load_book(book_dir), book_dir, out)
        page = (out / "01-one.html").read_text()
        assert '<img src="assets/diagram.svg" alt="Flow"' in page, page
        assert "!<a" not in page, page

        # an ampersand is escaped once, in a target and in alt text
        _fixture_book(
            book_dir,
            '# One\n\nSee [q](https://x.test/?a=1&b=2) and ![A & B](asset:diagram.svg).\n',
        )
        module.build(module.load_book(book_dir), book_dir, out)
        page = (out / "01-one.html").read_text()
        assert "&amp;amp;" not in page, page
        assert 'href="https://x.test/?a=1&amp;b=2"' in page, page
        assert 'alt="A &amp; B"' in page, page

        # a missing asset is still an error
        _fixture_book(book_dir, '# One\n\n![Flow](asset:nope.svg)\n')
        problems, _ = module.check(module.load_book(book_dir), book_dir)
        assert any("asset:" in p for p in problems), problems

        # footnotes are out of the subset, in either form
        for body in ("# One\n\nText[^1]\n", "# One\n\nText\n\n[^1]: note\n"):
            _fixture_book(book_dir, body)
            problems, _ = module.check(module.load_book(book_dir), book_dir)
            assert any("footnote" in p for p in problems), (body, problems)

        # a fourth heading level never reaches the contents or the search index
        _fixture_book(book_dir, "# One\n\n#### Deep\n\ntext\n")
        problems, _ = module.check(module.load_book(book_dir), book_dir)
        assert any("level-4 heading" in p for p in problems), problems

        # an unclosed tag in a raw block cannot swallow the rest of the page
        _fixture_book(book_dir, '# One\n\n<div class="x">\n\npara one\n')
        problems, _ = module.check(module.load_book(book_dir), book_dir)
        assert any("raw HTML" in p for p in problems), problems

        # unclosed inline markup is named, not printed
        _fixture_book(book_dir, "# One\n\nSome **bold here\n")
        problems, _ = module.check(module.load_book(book_dir), book_dir)
        assert any("unclosed emphasis" in p for p in problems), problems
        _fixture_book(book_dir, "# One\n\nRun `scripts/dev_generate_policy.sh now.\n")
        problems, _ = module.check(module.load_book(book_dir), book_dir)
        assert any("unclosed code span" in p for p in problems), problems


def test_book_builder_claims() -> None:
    """A path in prose is a claim. A path in a listing is evidence."""
    module = _load_book_builder()
    with tempfile.TemporaryDirectory() as tmp:
        book_dir = Path(tmp)

        # a quoted transcript may name a file the repository does not carry
        _fixture_book(
            book_dir, "# One\n\n```text\nwrote `selinux/no_such_file.te` there\n```\n"
        )
        problems, _ = module.check(module.load_book(book_dir), book_dir)
        assert not any("repository path" in p for p in problems), problems

        # prose that names a missing file fails
        _fixture_book(book_dir, "# One\n\nRun `scripts/no_such_script.sh`.\n")
        problems, _ = module.check(module.load_book(book_dir), book_dir)
        assert any("repository path" in p for p in problems), problems

        # a chapter may write a book path relative to the book
        _fixture_book(book_dir, "# One\n\nCompare `part1/01-the-default-answer.md` with `lab.md`.\n")
        problems, _ = module.check(module.load_book(book_dir), book_dir)
        assert not any("repository path" in p for p in problems), problems


def test_book_builder_enforces_the_chapter_shape() -> None:
    """book/AUTHORING.md states a shape, so the check enforces it for a chapter."""
    module = _load_book_builder()
    with tempfile.TemporaryDirectory() as tmp:
        book_dir = Path(tmp)

        _fixture_book(book_dir, "# One\n\n> A dek.\n\nBody.\n")
        problems, _ = module.check(module.load_book(book_dir), book_dir)
        assert any("::: why" in p for p in problems), problems
        assert any("::: try" in p for p in problems), problems
        assert any("What you can do now" in p for p in problems), problems

        _fixture_book(
            book_dir,
            "# One\n\n> A dek.\n\n::: why Reason\nBecause.\n:::\n\n"
            "::: try Try it\nOn the laptop.\n:::\n\n## What you can do now\n\n- Do it.\n",
        )
        problems, _ = module.check(module.load_book(book_dir), book_dir)
        assert not any(
            (":::" in p or "dek" in p or "What you can do now" in p) for p in problems
        ), problems

        # a callout inside a listing is listing text, not the chapter's shape
        _fixture_book(
            book_dir,
            "# One\n\n> A dek.\n\n```text\n::: why fake\n:::\n::: try fake\n:::\n"
            "## What you can do now\n```\n\nBody.\n",
        )
        problems, _ = module.check(module.load_book(book_dir), book_dir)
        assert any("::: why" in p for p in problems), problems


def test_book_prose_lint_reports_and_stays_clean() -> None:
    """The lint names its rule, and the shipped book passes it."""
    module = _load_book_builder()
    with tempfile.TemporaryDirectory() as tmp:
        book_dir = Path(tmp)
        _fixture_book(
            book_dir,
            "# One\n\n> A dek.\n\nYou should just make it robust -- then it has finished.\n",
        )
        findings = module.lint_prose(module.load_book(book_dir), book_dir)
        named = " ".join(findings)
        for rule in ("weak modal", "just", "word that carries no fact", "em-dash", "present perfect"):
            assert rule in named, findings
        assert "01-one.md:5" in named, findings

    book = module.load_book(PROJECT_ROOT / "book")
    assert module.lint_prose(book, PROJECT_ROOT / "book") == []


def test_book_nav_lists_each_page_once() -> None:
    """An appendix page is not front matter, and must not appear in both lists."""
    module = _load_book_builder()
    book = module.load_book(PROJECT_ROOT / "book")
    appendices = [entry for entry in book.entries if entry.appendix]
    assert appendices, "the book has appendices to test"
    with tempfile.TemporaryDirectory() as tmp:
        out = Path(tmp)
        module.build(book, PROJECT_ROOT / "book", out)
        page = (out / f"{appendices[0].slug}.html").read_text()
        nav = re.search(r'<div class="sidebar-inner">.*?</div>', page, re.S).group(0)
        front = re.search(r'Front matter</p>\s*<ul class="nav-list">(.*?)</ul>', nav, re.S)
        assert front, nav[:200]
        for entry in appendices:
            assert f'href="{entry.slug}.html"' not in front.group(1), nav[:400]
        cover = (out / "index.html").read_text()
        for entry in appendices:
            assert cover.count(f'href="{entry.slug}.html"') >= 1
        assert nav.count(f'href="{appendices[0].slug}.html"') == 1


def main() -> int:
    tests = [
        ("existing_execmem_rules_stay_baseline", test_existing_execmem_rules_stay_baseline),
        ("rpm_signing_tree_and_shopapi_ports", test_rpm_signing_tree_and_shopapi_ports),
        ("signed_repo_published_on_qa", test_signed_repo_published_on_qa),
        ("selinux_ports_and_canary_refuses_modify", test_selinux_ports_and_canary_refuses_modify),
        ("codeowners_covers_policy_surface", test_codeowners_covers_policy_surface),
        ("ci_runs_full_suite_with_stable_names", test_ci_runs_full_suite_with_stable_names),
        ("make_deps_uses_venv", test_make_deps_uses_venv),
        ("tracked_tree_has_no_model_client", test_tracked_tree_has_no_model_client),
        ("avc_parsing", test_avc_parsing),
        ("perm_merge", test_perm_merge),
        ("type_extraction_dedup", test_type_extraction_dedup),
        ("subtract_existing", test_subtract_existing),
        ("net_new_detection", test_net_new_detection),
        ("preprocess_stats", test_preprocess_stats),
        ("structured_summary_sections", test_structured_summary_sections),
        ("pr_summary_headings", test_pr_summary_headings),
        ("version_bump", test_version_bump),
        ("assemble_pr_body_policy_diff_section", test_assemble_pr_body_policy_diff_section),
        ("assemble_pr_body", test_assemble_pr_body),
        ("verify_file_contexts_skip", test_verify_file_contexts_skip),
        ("check_soak_ready_gate", test_check_soak_ready_gate),
        ("avc_epoch_window", test_avc_epoch_window),
        ("monitor_avc_skip", test_monitor_avc_skip),
        ("vendor_policy_check", test_vendor_policy_check),
        ("demo_present_dry_run", test_demo_present_dry_run),
        ("demo_present_waits_for_enter", test_demo_present_waits_for_enter),
        ("sepac_global_flags_help_and_capture", test_sepac_global_flags_help_and_capture),
        ("markdown_links_resolve", test_markdown_links_resolve),
        ("docs_focus_on_sepac", test_docs_focus_on_sepac),
        ("narration_live_checks_and_enforce_paths", test_narration_live_checks_and_enforce_paths),
        ("demo_e2e_scripts_dry_run", test_demo_e2e_scripts_dry_run),
        ("prod_soak_gate_and_lab_signing", test_prod_soak_gate_and_lab_signing),
        ("demo_outage_before_fix_dry_run", test_demo_outage_before_fix_dry_run),
        ("rehearsal_and_review_pr_paths", test_rehearsal_and_review_pr_paths),
        ("lab_env_required", test_lab_env_required),
        ("e2e_quiet_ssh_wrap_skips_when_ssh_missing", test_e2e_quiet_ssh_wrap_skips_when_ssh_missing),
        ("demo_present_preflight_names_bootstrap", test_demo_present_preflight_names_bootstrap),
        ("soak_net_new_empty_manifest", test_soak_net_new_empty_manifest),
        ("app_manifest", test_app_manifest),
        ("selinux_booleans_and_app_ci", test_selinux_booleans_and_app_ci),
        ("rpm_ops_parity", test_rpm_ops_parity),
        ("ops_rpm_soak_cli_imports_alone", test_ops_rpm_soak_cli_imports_alone),
        ("monitor_records_soak_stderr", test_monitor_records_soak_stderr),
        ("version_consistency", test_version_consistency),
        ("version_consistency_fails_on_drift", test_version_consistency_fails_on_drift),
        ("version_consistency_fails_on_payments_drift", test_version_consistency_fails_on_payments_drift),
        ("scaffold_billing_no_myapp_leak", test_scaffold_billing_no_myapp_leak),
        ("deterministic_payments_manifest_check", test_deterministic_payments_manifest_check),
        ("promote_policy_version_from_te", test_promote_policy_version_from_te),
        ("classify_fail_closed_json", test_classify_fail_closed_json),
        ("check_soak_auto_tier_fail_closed", test_check_soak_auto_tier_fail_closed),
        ("offline_fixture_sync", test_offline_fixture_sync),
        ("docs_match_the_store", test_docs_match_the_store),
        ("baseline_fixture_rerun_does_not_append", test_baseline_fixture_rerun_does_not_append),
        ("deterministic_verdict_fixture_coverage", test_deterministic_verdict_fixture_coverage),
        ("needs_review_hits", test_needs_review_hits),
        ("deterministic_fixture_classify", test_deterministic_fixture_classify),
        ("payments_onboarding_module", test_payments_onboarding_module),
        ("export_app_avcs_requires_paths", test_export_app_avcs_requires_paths),
        ("init_uses_daemon_domain", test_init_uses_daemon_domain),
        ("vm_check_reports_each_result", test_vm_check_reports_each_result),
        ("audit_health_fails_closed", test_audit_health_fails_closed),
        ("runner_var_selects_rhel_host", test_runner_var_selects_rhel_host),
        ("runner_container_expression_both_cases", test_runner_container_expression_both_cases),
        ("avc_filter_keeps_domain_denials", test_avc_filter_keeps_domain_denials),
        ("soak_counts_every_domain_denial", test_soak_counts_every_domain_denial),
        ("soak_ignore_is_explicit", test_soak_ignore_is_explicit),
        ("boolean_policy_render", test_boolean_policy_render),
        ("boolean_triage_two_matches", test_boolean_triage_two_matches),
        ("boolean_curated_when_policy_unavailable", test_boolean_curated_when_policy_unavailable),
        ("boolean_hint_yaml_still_documents_patterns", test_boolean_hint_yaml_still_documents_patterns),
        ("fc_labeling_drift_detection", test_fc_labeling_drift_detection),
        ("system_jvm_exec_bin_exception", test_system_jvm_exec_bin_exception),
        ("forbidden_exec_bin_needs_manifest_reason", test_forbidden_exec_bin_needs_manifest_reason),
        ("boolean_triage_loads_policy_once", test_boolean_triage_loads_policy_once),
        ("rhel_runtime_file_contexts", test_rhel_runtime_file_contexts),
        ("tune_report", test_tune_report),
        ("tune_report_skip_no_selinux", test_tune_report_skip_no_selinux),
        ("force_reason_recorded", test_force_reason_recorded),
        ("policy_rules_are_the_single_source", test_policy_rules_are_the_single_source),
        ("compiled_policy_rejects_foreign_entrypoint", test_compiled_policy_rejects_foreign_entrypoint),
        ("policy_audit_rejects_review_bypasses", test_policy_audit_rejects_review_bypasses),
        ("compiled_bypass_fixtures_fail_closed", test_compiled_bypass_fixtures_fail_closed),
        ("collect_soak_facts_monitor_crash", test_collect_soak_facts_monitor_crash),
        ("soak_gate_negative_net_new", test_soak_gate_negative_net_new),
        ("soak_daily_history_and_other_app_guard", test_soak_daily_history_and_other_app_guard),
        ("new_canary_ignores_older_soak_files", test_new_canary_ignores_older_soak_files),
        ("skip_soak_days_and_break_glass_reason", test_skip_soak_days_and_break_glass_reason),
        ("sepac_help_lists_all_commands", test_sepac_help_lists_all_commands),
        ("sepac_dry_run_golden", test_sepac_dry_run_golden),
        ("sepac_validation", test_sepac_validation),
        ("sepac_load_guardrail", test_sepac_load_guardrail),
        ("sepac_blocked_hint", test_sepac_blocked_hint),
        ("sepac_allow_needs_review_perm_passthrough", test_sepac_allow_needs_review_perm_passthrough),
        ("stale_canary_marker_and_force_enforce_report", test_stale_canary_marker_and_force_enforce_report),
        ("sepac_completion_coverage", test_sepac_completion_coverage),
        ("sepac_complete_from_temp_tree", test_sepac_complete_from_temp_tree),
        ("sepac_manifest_lookup_order", test_sepac_manifest_lookup_order),
        ("sepac_man_completeness", test_sepac_man_completeness),
        ("sepac_version", test_sepac_version),
        ("rpm_sepac_parity", test_rpm_sepac_parity),
        ("sepac_production_guard", test_sepac_production_guard),
        ("ansible_role_writes_role_and_manifest", test_ansible_role_writes_role_and_manifest),
        ("prod_dry_run_has_sepac_commands", test_prod_dry_run_has_sepac_commands),
        ("inventory_examples_have_host_role", test_inventory_examples_have_host_role),
        ("no_stale_old_paths", test_no_stale_old_paths),
        ("book_builder_contract", test_book_builder_contract),
        ("book_builder_fails_loudly", test_book_builder_fails_loudly),
        ("book_builder_never_renders_silently_wrong", test_book_builder_never_renders_silently_wrong),
        ("book_builder_claims", test_book_builder_claims),
        ("book_builder_enforces_the_chapter_shape", test_book_builder_enforces_the_chapter_shape),
        ("book_prose_lint_reports_and_stays_clean", test_book_prose_lint_reports_and_stays_clean),
        ("book_nav_lists_each_page_once", test_book_nav_lists_each_page_once),
    ]
    for name, fn in tests:
        fn()
        print(f"PASS {name}")
    print(f"\n{len(tests)}/{len(tests)} smoke tests passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
