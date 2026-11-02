# 202 — Tool lab

> Admins use `sepac`: see [sepac.md](../sepac.md). This page documents the engine scripts and playbooks sepac runs.

The same shopapi outcome as [104](104-HAND-BUILT-MODULE.md), using the scripts in [201](201-TOOL-COMMANDS.md). Each step names the 104 numbers it replaces. Do not also type those 104 commands for the same install.

---

## Stand the host up

Replaces 104 steps P1–P10.

```bash
cd ~/selinux-pac
sudo bash lab/demo_bootstrap.sh --shopapi-only
```

The service listens on port 8091. The process type is `shopapi_t`. `getenforce` stays `Enforcing`. Only that domain is log-only. The unit has no `SELinuxContext=` line.

Already generated on this box? Put the seed back, then run the same command again:

```bash
git checkout -- selinux/shopapi/
sudo bash lab/demo_bootstrap.sh --shopapi-only
```

Labs 0, 1, and 2 are still typed by hand. They are how you read a label and one AVC. The script does not replace 104 steps 0.1–2.3.

---

## First generate

Replaces 104 step 3.1. The compile and load inside `--enforce-check` replace 3.2–3.4. Without that flag, run the compile yourself. That is still 104 steps 3.2–3.4, and it is the QA host. Production does not `semodule -i`.

Curl `/log` first (104 step 2.1). Then:

```bash
sudo bash scripts/dev_generate_policy.sh --apply --app-name shopapi --app-root "$(pwd)"
```

The first run stops. Java asked for `execmem`. The tool records it and does not write it. `shopapi.te` is still the seed.

```text
*** GENERATION BLOCKED — domain-weakening permission requires --allow-needs-review ***
```

Run it again with the flag, because the log showed the denial:

```bash
sudo bash scripts/dev_generate_policy.sh --apply --allow-needs-review --app-name shopapi --app-root "$(pwd)"
```

`allow shopapi_t shopapi_log_t:file open` is the `/log` denial. `allow shopapi_t self:process execmem` is the review permission. The JVM execute on `bin_t` becomes `corecmd_exec_bin(shopapi_t)`, because `config/shopapi.manifest.yml` records the reviewed `selinux_exceptions.exec_bin`. Without that reason the generator stops with NEEDS REVIEW, and `--allow-needs-review` does not unlock it. It is not an entrypoint. Then load it (104 steps 3.2–3.4):

```bash
sudo bash scripts/compile_and_validate.sh selinux/shopapi --app shopapi
sudo semodule -i selinux/shopapi/shopapi.pp
sudo restorecon -Rv /opt/shopapi /var/lib/shopapi /var/log/shopapi
```

---

## Same URL, no new line

Replaces the second generate after 104 steps 4.1–4.2. `execmem` is already in the `.te`. The verdict is `baseline`.

```bash
cp selinux/shopapi/shopapi.te /tmp/shopapi.te.before
sudo bash scripts/dev_generate_policy.sh --apply --allow-needs-review --app-name shopapi --app-root "$(pwd)"
diff -u /tmp/shopapi.te.before selinux/shopapi/shopapi.te
```

`diff` prints nothing.

---

## The spool URL

104 steps 5.1–5.4 stay typed by hand: `semanage permissive -d`, then `/feature-spool` fails with `permissive=0`.

The second generate replaces 104 step 6.1. Allows already in the file stay baseline. The new lines are the spool path.

```bash
sudo bash scripts/dev_generate_policy.sh --apply --allow-needs-review --app-name shopapi --app-root "$(pwd)"
sudo bash scripts/compile_and_validate.sh selinux/shopapi --app shopapi
sudo semodule -i selinux/shopapi/shopapi.pp
sudo restorecon -Rv /var/spool/shopapi
curl -sf http://127.0.0.1:8091/feature-spool
```

The compile, `semodule -i`, and `restorecon` are 104 steps 6.2–6.3. The curl is 6.4. `/feature-spool` returns 200. `shopapi_t` is still not permissive. `getenforce` is `Enforcing`.

---

## Laptop, no SELinux

This does not replace labs 2–6. It is how `make check` classifies a saved denial. From the repo root:

```bash
python3 cli/deterministic_gen.py --explain \
  --avc-log tests/fixtures/deterministic/01-mislabeled-var-lib/avc.log \
  --manifest config/myapp.manifest.yml \
  --existing-te selinux/myapp/myapp.te \
  --existing-fc selinux/myapp/myapp.fc
```

| Fixture | Verdict | 104 analog |
|---------|---------|------------|
| `01-mislabeled-var-lib` | `fc_drift` | Prep P8, relabel, no new allow |
| `05-baseline-covered` | `baseline` | Lab 4 |
| `06-fc-missing-line` | `fc_fix` | Lab 6's new file-context line |

`selinux/myapp/myapp.te` is the offline golden, not a live app. The full set is `make test-fixtures`.
