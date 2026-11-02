# Offline fixtures

Used by `scripts/lib/stage_offline_fixture.sh` when a host has no audit log. Prefer the default **deterministic** engine ([`201 — Generate a module`](../../../docs/guides/201-TOOL-COMMANDS.md#generate-a-module)).

| Path | Role |
|------|------|
| `baseline/` | Older module snapshot (**1.1.0**) — shown as “before” in Act 3 diff |
| `generated/` | Expected module — must match `selinux/myapp.{te,fc}` for deploy/enforce |
| `avc.log` | Recorded audit lines fed to Act 4 PR assembly |

Refresh `generated/` after bumping `selinux/`:

```bash
bash tests/refresh_offline_fixture.sh
```
