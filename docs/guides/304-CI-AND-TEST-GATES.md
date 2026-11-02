# 304 — CI and test gates (team review)

Shareable detail behind the **“A working tool”** metrics: **113 / 15 / 10 / 4**.  
Same story as Stage 2 in the pitch: **CI checks the compiled policy, not just the text.**

Related: [303 — Testing](303-TESTING.md), [sepac.md](../sepac.md) (`check` / `generate`), [shipping.md](../shipping.md).

---

## Snapshot (matches the deck)

| # | Slide title | One-line meaning | Source |
|--:|-------------|------------------|--------|
| **113** | Smoke tests on every pull request | `make test`, offline — no SELinux host needed | [`tests/smoke_test.py`](../../tests/smoke_test.py) |
| **15** | Bypass attempts rejected in CI | CI **compiles** each hostile module and rejects it | [`tests/fixtures/compiled-bypasses/`](../../tests/fixtures/compiled-bypasses/) |
| **10** | Generator verdicts | Pinned by **16** golden fixtures: logs in, verdicts out | [`tests/fixtures/deterministic/`](../../tests/fixtures/deterministic/) |
| **4** | CI checks to require | Stable job names for branch protection | [`.github/workflows/selinux-policy-ci.yml`](../../.github/workflows/selinux-policy-ci.yml) |

**Slide examples — what each number stands for in practice**

### 113 — smoke tests (`make test`, offline)

From the deck / covered in the suite:

- `sepac load` refuses on a host whose role is **production**
- A **crashed soak monitor** blocks enforce — never reads as zero
- **Break-glass** enforce needs a written, recorded reason

Run: `make test-smoke` or `python3 tests/smoke_test.py`

### 15 — bypass attempts rejected in CI

From the deck (grep is not enough — each is compiled then rejected):

- A forbidden rule **split across two lines** to slip past grep (`split-line`)
- The domain quietly joins **`unconfined_domain_type`** (`unconfined-domain-type`)
- **`dontaudit` on `shadow_t`**, so the denial goes silent (`dontaudit-forbidden`)

Stage 2 also calls out (same suite):

- Interface macros that grant shadow access (`interface-macro`)
- Attribute grants such as **`can_setenforce`** (`can-setenforce`)
- A **permissive** declaration inside the module (`permissive-declaration`)
- A file context that relabels **`/etc/shadow`** (`fc-relabel-shadow`)
- An **entrypoint** on a type the module doesn’t own (`foreign-entrypoint`)
- Execute on **`bin_t`** through the `java_exec_t` alias (`exec-bin-alias`)

### 10 — generator verdicts (16 golden fixtures)

From the deck:

- A mislabeled file → **`restorecon`**, never an allow (`fc_drift`)
- A port bind → a **port label** in the app manifest (`private_port`)
- **`execmem`** → blocked until a reviewer approves it (`needs_review`)

### 4 — CI checks to require (branch protection)

From the deck:

| Job | What the slide says |
|-----|---------------------|
| **`forbidden-patterns`** | Fast text checks: wildcards, `shadow_t`, `bin_t` execute, paths outside the app |
| **`compiled-policy`** | Builds the module on CentOS Stream 9 and queries it with `sesearch` / `seinfo` |
| **`version-consistency`** | The module version matches `policy_version.txt` |
| **`offline-tests`** | Golden fixtures for every generator verdict, plus the **113** smoke tests |

**Also on the Stage 2 slide:** a **code owner** must approve changes to policy, playbooks, packaging, and the house rules ([`.github/CODEOWNERS`](../../.github/CODEOWNERS)).

---

## How to re-count locally

Numbers can grow; these are the current contract:

```bash
# 113 smoke tests
python3 -c "import re; print(len(re.findall(r'^def test_', open('tests/smoke_test.py').read(), re.M)))"

# 15 bypass fixtures (clean is the control, not a bypass)
ls tests/fixtures/compiled-bypasses | grep -v '^clean$' | wc -l

# 10 generator verdicts
python3 -c "import sys; sys.path.insert(0,'tests'); import smoke_test as s; print(len(s.DETERMINISTIC_CLASSIFICATION_VERDICTS), sorted(s.DETERMINISTIC_CLASSIFICATION_VERDICTS))"

# 16 golden fixtures (more than one fixture per some verdicts)
ls -d tests/fixtures/deterministic/*/ | wc -l

# 4 CI jobs
grep -E 'name: (offline-tests|forbidden-patterns|compiled-policy|version-consistency)' .github/workflows/selinux-policy-ci.yml
```

---

## 1. The four CI checks (every PR)

Workflow: [`.github/workflows/selinux-policy-ci.yml`](../../.github/workflows/selinux-policy-ci.yml)

These four job **names** are stable so branch protection can require them. They are the admin gate after `sepac generate` / a policy PR — not a “fail on purpose” demo step.

| Job | Runner | What it proves | Pass means |
|-----|--------|----------------|------------|
| **`offline-tests`** | `ubuntu-latest` | `make test` — fixtures + **113 smoke tests** + static validators | Generator logic, CLI glue, PR assembly, soak helpers, demos dry-run, etc. did not regress |
| **`forbidden-patterns`** | `ubuntu-latest` | `validate_forbidden_patterns.sh` on `myapp`, `shopapi`, `payments` + `cli/policy_audit.py` | Source `.te` / audit: no wildcards, no forbidden targets, no raw `bin_t` execute without a reviewed manifest exception; dontaudit / path audit clean |
| **`compiled-policy`** | CentOS Stream 9 (or `rhel9-utm`) | Compile real modules + **semantic** gate + **15 bypass** reject suite + AVC epoch window | Compiled policy matches house rules; each bypass is rejected with the expected message; a **clean** module is accepted |
| **`version-consistency`** | `ubuntu-latest` | `validate_version_consistency.sh` | `policy_version.txt` matches `policy_module()` |

### Stage 2 — how this maps to `sepac check`

On QA, `sepac check shopapi` is the same idea, one command:

1. Manifest valid  
2. Forbidden patterns (job **`forbidden-patterns`**)  
3. Compile (needs `selinux-policy-devel`)  
4. Semantic checks in a throwaway policy store (job **`compiled-policy`** — setenforce / shadow / unconfined / etc.)

Without `selinux-policy-devel` on a laptop, sepac **skips** compile/semantics and never claims they passed. CI’s Stream 9 job is what actually compiles.

### Extra workflow (proof the gate is live)

[`.github/workflows/selinux-policy-app-proof.yml`](../../.github/workflows/selinux-policy-app-proof.yml) includes **`bypass-rejected`**: feeds a `can-setenforce` module and asserts non-zero exit. Separate from the four required PR jobs; proves the compiled gate is not a no-op.

---

## 2. The 113 smoke tests (detail)

**File:** [`tests/smoke_test.py`](../../tests/smoke_test.py)

Offline unit/integration tests for the toolchain. Categories (full names in the file / [303 §2](303-TESTING.md)):

| Area | Examples |
|------|----------|
| AVC / generate plumbing | Parse/dedup AVCs, permission merge, net-new vs already covered |
| PR / shipping artifacts | `pr_summary` headings, `assemble_pr_body.sh`, version bump |
| Soak / monitor | Marker age, net-new counting, fail-closed when `sesearch` missing; crashed monitor ≠ zero |
| Vendor / tune / load role | Vendor refuse; `--force` reason recorded; **production role refuses `load`** |
| Break-glass / enforce | Written reason required for break-glass paths exercised in tests |
| Manifest / RPM | App manifest schema, ops RPM parity |
| Demo scripts | `demo_present.sh` / e2e `--dry-run` |
| **Generator contract** | Every one of the **10 verdicts** has ≥1 golden; `needs_review` / exec_bin |
| **Bypass contract** | Compiled-bypass fixtures exist and fail closed |
| Gates / QA | `vm_check` PASS/FAIL; loaded `bypass_*` fails host-unchanged |

**113** = count of `def test_*` today. It will grow when tests are added.

---

## 3. The 15 bypass attempts (full list)

**Driver:** [`scripts/reject_compiled_bypasses.sh`](../../scripts/reject_compiled_bypasses.sh)  
**Gate:** [`scripts/validate_policy_semantics.sh`](../../scripts/validate_policy_semantics.sh)

Each bypass is a real `policy_module(bypass, …)` that **compiles**, then must be **rejected** with a message matching `expected.txt`.  
**`clean`** (types-only) must still be **accepted**. A fixture that fails to compile does not prove the gate.

| # | Fixture | Attack / mistake | Gate must catch |
|---|---------|------------------|-----------------|
| 1 | `can-setenforce` | Attribute allowing setenforce | Attribute grant: setenforce |
| 2 | `can-load-policy` | Attribute allowing load_policy | Attribute grant: load_policy |
| 3 | `can-read-shadow-passwords` | Attribute for reading shadow | Attribute grant: can_read_shadow_passwords |
| 4 | `can-write-shadow-passwords` | Attribute for writing shadow | Attribute grant: can_write_shadow_passwords |
| 5 | `load-policy-setenforce` | Raw setenforce / load_policy style access | setenforce (and related) |
| 6 | `sys-module-sys-admin` | `capability { sys_admin sys_module }` | Dangerous capabilities |
| 7 | `unconfined-domain-type` | `typeattribute … unconfined_domain_type` | Domain marked unconfined |
| 8 | `permissive-declaration` | `permissive bypass_t;` | Domain permissive in the module |
| 9 | `file-type-star` | Broad `file_type:file *` allow | Wildcard / attribute star |
| 10 | `foreign-entrypoint` | `bin_t:file entrypoint` | Entrypoint on a foreign type |
| 11 | `fc-relabel-shadow` | `.fc` maps `/etc/shadow` | Relabel of shadow |
| 12 | `dontaudit-forbidden` | `dontaudit` toward `shadow_t` | Hiding forbidden access |
| 13 | `split-line` | Shadow allow split across lines | Still finds `shadow_t` after compile |
| 14 | `interface-macro` | Shadow via interface packaging | Still finds forbidden shadow access |
| 15 | `exec-bin-alias` | Execute on `bin_t` / java alias without exception | `bin_t` execute beyond control |

```bash
sudo bash scripts/reject_compiled_bypasses.sh
```

`make vm-check` on QA runs this among other checks and asserts `semodule -l` never lists `bypass_*` or `pac_control` afterward.

---

## 4. The 10 generator verdicts (detail)

Smoke test `deterministic_verdict_fixture_coverage` requires every verdict in `DETERMINISTIC_CLASSIFICATION_VERDICTS` to appear in ≥1 golden under [`tests/fixtures/deterministic/`](../../tests/fixtures/deterministic/). **16** fixture directories pin those **10** outcomes (some verdicts have more than one case).

| Verdict | Meaning | Typical outcome |
|---------|---------|-----------------|
| **`interface`** | Red Hat refpolicy interface match | Write the interface call, not raw allows |
| **`direct`** | Module-private type / no interface match | Narrow allow on the app’s own type |
| **`boolean`** | Fix is a SELinux boolean | Record boolean / host `setsebool` |
| **`fc_fix`** | Path missing from `.fc` | Add file-context for the app’s type |
| **`fc_drift`** | Path covered but wrong label (or stale entrypoint) | **`restorecon`** — never a wider allow |
| **`private_port`** | Bind on a generic port type | App port type + manifest `selinux_ports` |
| **`baseline`** | Already covered or deliberately omitted | Write nothing |
| **`forbidden`** | Never grant (shadow, passwd, security_t, …) | Fail closed; `--approve` does not unlock |
| **`needs_review`** | e.g. `execmem`, or `bin_t` execute without exception | Stop until `--approve` / manifest exception |
| **`toolchain_required`** | Needs sepolgen; toolchain missing | Exit 1 unless degraded mode allowed |

### Fixture → verdict

| Fixture | Verdict |
|---------|---------|
| `01-mislabeled-var-lib`, `14-stale-entrypoint` | `fc_drift` |
| `02-port-bind` | `private_port` |
| `03-shadow-read` | `forbidden` |
| `04-boolean-network-connect`, `10-boolean-hint` | `boolean` |
| `05-baseline-covered`, `13-cgroup-omit` | `baseline` |
| `06-fc-missing-line` | `fc_fix` |
| `07-toolchain-required` | `toolchain_required` |
| `08-interface-match`, `16-system-jvm-reviewed` | `interface` |
| `09-direct-no-interface`, `11-private-getopt` | `direct` |
| `12-execmem-review`, `15-system-jvm-exec-bin` | `needs_review` |

```bash
make test-fixtures
```

**Demo mapping:** Part 3 `sepac generate` stopping on **`execmem`** = `needs_review`. `/etc/passwd` refused = `forbidden`.

---

## 5. How the layers fit

```text
Developer laptop / PR
  ├─ 113 smoke tests + 16 golden fixtures     → offline-tests
  ├─ Source forbidden patterns               → forbidden-patterns
  ├─ Compile + semantics + 15 bypass rejects → compiled-policy
  └─ Version SSOT                            → version-consistency
       + CODEOWNERS on policy / playbooks / packaging / house rules

QA host (demo: sepac check / load)
  └─ Same forbidden + compile + semantics ideas, live on shopapi

Production (shipping.md)
  └─ Canary → soak → enforce — not a substitute for the 4 CI jobs
```

---

## 6. Commands for reviewers

```bash
make test                          # full offline suite
make test-smoke                    # 113 only
make test-fixtures                 # generator goldens
bash scripts/validate_forbidden_patterns.sh selinux/shopapi --app shopapi
sudo bash scripts/reject_compiled_bypasses.sh   # needs SELinux devel
make vm-check                      # QA: same compile list + host-unchanged
```

---

## 7. Talking points (Q&A)

1. **“What does CI check?”** — Four named jobs: offline suite, source patterns, compiled semantics (+ 15 bypass prove-outs), version consistency.  
2. **“Is it only grepping the `.te`?”** — No. Stage 2: **compiled** policy on Stream 9, queried with `sesearch` / `seinfo`. Text checks are the fast first pass.  
3. **“How do you know generate isn’t rubber-stamping?”** — Ten verdicts, sixteen goldens; `forbidden` and `needs_review` fail closed.  
4. **“Could someone sneak setenforce in?”** — Fifteen compiled bypass fixtures including setenforce / shadow / unconfined / split-line / dontaudit.  
5. **“What about `sepac check` in the demo?”** — Same gates applied to the generated shopapi module on QA before load.  
6. **“Who can change the house rules?”** — Code owners must approve policy, playbooks, packaging, and the rules themselves.

---

*Source of truth: `tests/smoke_test.py` (`test_*`, `DETERMINISTIC_CLASSIFICATION_VERDICTS`), `scripts/reject_compiled_bypasses.sh` (15 + `clean`), `.github/workflows/selinux-policy-ci.yml` (4 jobs), `.github/CODEOWNERS`. Update this page when those change.*
