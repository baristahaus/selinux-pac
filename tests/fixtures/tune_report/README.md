# Tune-report fixtures

Offline `--tune-report` cases. The generator classifies vendor-domain denials and prints host commands. It does **not** write a `.te` / `.fc` module.

**Where to run:** repo root on any OS (`make test-fixtures` or `python3 tests/smoke_test.py --no-require-backend`).

| Case | What it covers |
|------|----------------|
| `tomcat/` | `tomcat_t` denials: label (`user_home_t` on `/opt/appdata`), boolean (`http_port_t` connect), port (`name_bind` 8090), plus an unfixable `ssh_home_t` read |

```bash
VENDOR_CHECK_MOCK=1 VENDOR_CHECK_SEMODULE_L=tomcat \
  bash scripts/dev_generate_policy.sh --tune-report --skip-export \
  --app-name tomcat \
  --avc-log tests/fixtures/tune_report/tomcat/avc.log \
  --out-dir /tmp/tune_out
```
