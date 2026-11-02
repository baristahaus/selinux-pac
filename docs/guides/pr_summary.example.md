### Network Bindings
- TCP **8888** bound via dedicated `myapp_port_t` (not blanket `unreserved_port_t`)
- Outbound client connect to **127.0.0.1:8889** via `myapp_backend_port_t` (`/probe-backend` integration test)

### File System Access
- State under **`/var/lib/myapp`** labeled `myapp_var_lib_t` (create, write, rename for app data)
- Logs under **`/var/log/myapp`** via `myapp_log_t` with `logging_log_filetrans` (append, rotate, create)
- Runtime socket path **`/run/myapp/notify.sock`** on `myapp_var_run_t` (`/notify-socket` probe)
- Path traversal allows on log directory parents (read/search on `var_log_t`, `usr_t`, `root_t` as needed)

### Next action
- None for this sample (ports already in `selinux_ports`; no net-new bind). After soak fail, generator fills this with `add_manifest_port` / `update_fc_and_restorecon` / `setsebool_host`. See [401-OPERATIONS.md#a-denial-after-ship](../shipping.md#a-denial-after-ship).

### Process Execution
- `init_daemon_domain(myapp_t, myapp_exec_t)` — systemd entrypoint transition
- `myapp_script_exec_t` for **`/opt/myapp/bin/backup.sh`** (`execute_no_trans`; script uses bash builtins only)
- Backend service domain `myapp_backend_t` with `init_daemon_domain` and Unix `connectto` from primary app

### Explicit Denials Maintained
- No wildcard allows; no `shadow_t`, `unconfined_t`, or `sysadm_t`
- No `bin_t:file execute` (forbidden by CI — backup script stays self-contained)
- No broad `var_t:file write`; data confined to `myapp_var_lib_t` / `myapp_log_t`
