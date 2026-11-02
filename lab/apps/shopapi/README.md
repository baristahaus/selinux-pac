# shopapi — Spring Boot demo reference

This is the **demo** JVM. Offline `make check` uses deterministic goldens (`selinux/myapp/myapp.te`), not a live app.

Policy starts as a **types-only** seed in `selinux/shopapi/`. The allow list is generated on rhel-qa from **observed** AVCs (`dev_generate_policy.sh --app-name shopapi`). Do not paste a JVM permission list; if `execmem` does not appear in the AVC log, do not add it.

systemd starts `/opt/shopapi/bin/shopapi` (labeled `shopapi_exec_t`). That wrapper execs the system `/usr/bin/java` (`java_exec_t`). There is no `SELinuxContext=` line. `init_daemon_domain(shopapi_t, shopapi_exec_t)` is the transition. `ps -o label,args -C java` shows `shopapi_t`. Live commands are in [docs/guides/LIVE_CHECKS.md](../../../docs/guides/LIVE_CHECKS.md).

Paths and port: `config/shopapi.manifest.yml` → `/etc/shopapi.env` (bootstrap writes that file).
