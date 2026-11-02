# Guides

The main docs are [sepac.md](../sepac.md), [shipping.md](../shipping.md) and [demo.md](../demo.md). These pages go deeper: SELinux itself, the two-host lab, how the repo is tested, and the scripts behind sepac.

## Learn SELinux (no sepac needed)

| Guide | What it covers |
|-------|----------------|
| [100 — RHEL host commands](100-RHEL-HOST-COMMANDS.md) | Everything around SELinux the lab needs: SSH, packages, services, the audit daemon, ports, signed RPMs |
| [101 — Concepts](101-CONCEPTS.md) | Labels, domains, types, enforcing and permissive, unconfined |
| [102 — Commands](102-COMMANDS.md) | `getenforce`, `ausearch`, `audit2why`, `semanage`, `restorecon`, `sesearch`, `semodule` |
| [103 — Config files](103-CONFIG-FILES.md) | Where RHEL keeps the policy, file contexts and the module store |
| [104 — A module built by hand](104-HAND-BUILT-MODULE.md) | shopapi confined with nothing but the commands from 102: what sepac automates |

## Labs

| Guide | What it covers |
|-------|----------------|
| [302 — Two-host lab](302-TECHNICAL.md) | Mac + rhel-qa + rhel-prod: generate, pull request, signed RPM, canary, a refused soak, break-glass, outage, rollback, the fix, enforce |
| [202 — Engine lab](202-TOOL-LAB.md) | The 104 outcome with the engine scripts instead of sepac |
| [LIVE_CHECKS](LIVE_CHECKS.md) | Commands and output captured on rhel-qa, behind the claims in 102 and 103 |

## For developers of this repo

| Guide | What it covers |
|-------|----------------|
| [201 — Engine reference](201-TOOL-COMMANDS.md) | Each script and playbook sepac runs: inputs, outputs, what a pull request must not contain |
| [303 — Testing](303-TESTING.md) | `make test`, the fixtures in `tests/fixtures/`, CI, and the production gates |
| [304 — CI and test gates](304-CI-AND-TEST-GATES.md) | Shareable detail on the **4 CI jobs**, **106 smoke tests**, **15 bypass attempts**, and **10 generator verdicts** |
| [pr_body.example.md](pr_body.example.md), [pr_summary.example.md](pr_summary.example.md) | What a generated pull-request description looks like |
