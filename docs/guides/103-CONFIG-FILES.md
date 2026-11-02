# 103 — SELinux config files

The commands that read and write these files are in [102](102-COMMANDS.md). None of this is a repo script. Paths are the RHEL 9 layout. A directory listing that has not been captured on rhel-qa is in [LIVE_CHECKS.md](LIVE_CHECKS.md).

`restorecon` and `matchpathcon` read `/etc/selinux/targeted/contexts/files/`. That directory is not the kernel policy.

---

## /etc/selinux/config

**What it holds.** The mode to use at boot (`SELINUX=enforcing`) and the policy name (`SELINUXTYPE=targeted`).

**Which command writes it.** An editor. `setenforce` does not. `getenforce` and `sestatus` read the running mode, which can differ until reboot.

**Look safely.** `cat /etc/selinux/config`. Do not change `SELINUX=disabled`.

---

## The module store

**What it holds.** `/var/lib/selinux/targeted/active/` is the policy the kernel is using after the last rebuild. Under it:

| Path | What |
|------|------|
| `modules/100` | Every module from `selinux-policy-targeted`, at priority 100 |
| `modules/200` | Modules from an RPM, at priority 200 |
| `modules/400` | A module from `semodule -i`, and the one module `semanage permissive` adds: `permissive_<type>`, at priority 400 |
| `ports.local` | Ports added on this host with `semanage port` |
| `file_contexts.local` | File-context lines added on this host with `semanage fcontext` |
| `booleans.local` | Booleans changed on this host with `semanage boolean` or `setsebool -P` |
| `policy.kern` | The rebuilt binary beside the modules. `policy.33` is the file the kernel loads |

Local `semanage` changes for ports, file contexts, and booleans are those three files in the store. They are not modules. Only `semanage permissive` adds a module.

**Which command writes it.** `semodule -i` writes priority 400. `semanage permissive -a` writes `permissive_<type>` at priority 400. `semanage port`, `semanage fcontext`, and `semanage boolean` write `ports.local`, `file_contexts.local`, and `booleans.local`. An RPM's `%post` installs its `.pp` at priority 200. Every `semodule` or `semanage` rebuild rewrites `policy.33`.

**Look safely.** `sudo semodule --list-modules=full`. `sudo ls /var/lib/selinux/targeted/active/modules`. Do not delete a directory under `modules/`.

**Priority gotcha.** A hand-run `semodule -i` stores the module at 400. If an RPM already installed the same module name at 200, the 400 copy wins and the RPM's copy is ignored. A later `dnf update` refreshes priority 200 and leaves the 400 module in place. `semodule -l` does not show this. `semodule --list-modules=full` does. Remove the override with `semodule -X 400 -r name` only when you mean to fall back to the RPM. Production day 0 installs the RPM. It does not `semodule -i` the shopapi package onto the server.

---

## policy.33

**What it holds.** `/etc/selinux/targeted/policy/policy.33`. The number is the policy version. Every `semodule` or `semanage` rebuild rewrites this file. It is what the kernel loads.

**Which command writes it.** `semodule` and `semanage`, on every rebuild. The `selinux-policy-targeted` RPM ships the first copy. Do not edit the file by hand.

**Look safely.** `ls -l /etc/selinux/targeted/policy/policy.33`. Confirm the filename on the host with the command in [LIVE_CHECKS.md](LIVE_CHECKS.md). `sha256sum` of this file and `policy.kern` is in that same list.

---

## file_contexts and file_contexts.local

**What they hold.** `semanage fcontext` writes `file_contexts.local` in the store (`/var/lib/selinux/targeted/active/file_contexts.local`). The rebuild copies the combined map to `/etc/selinux/targeted/contexts/files/`. `restorecon` and `matchpathcon` read that directory, not the store path.

| File | What |
|------|------|
| `/etc/selinux/targeted/contexts/files/file_contexts` | The combined map from the loaded modules: path pattern to label |
| `/etc/selinux/targeted/contexts/files/file_contexts.local` | Lines `semanage fcontext -a` added on this host |

`file_contexts.homedirs` sits in the same directory. The kernel does not store this map as a list of paths.

**Which command writes them.** A module install rebuilds `file_contexts` from every module's `.fc`. `semanage fcontext -a` and `-d` write `file_contexts.local` in the store, and the rebuild updates `/etc/selinux/targeted/contexts/files/`. `semanage export` prints those local lines.

**Look safely.**

```bash
sudo semanage fcontext -l -C
sudo semanage export
```

`semanage export` only reads. Do not edit `file_contexts` with a text editor. The next rebuild replaces it.

---

## /sys/fs/selinux

**What it holds.** The kernel's selinuxfs. `policy` is the binary the kernel is enforcing. `enforce` is the mode `getenforce` reads. Booleans appear as files under `booleans/`.

**Which command writes it.** The kernel, when a policy is loaded. `setenforce` writes `enforce`. This project does not.

**Look safely.** `ls /sys/fs/selinux`. `cat /sys/fs/selinux/enforce` prints `1` when the machine is Enforcing. Do not write that file. There is no selinuxfs inside a container that is not running with SELinux, which is why the soak tool fails closed instead of pretending the policy was read.

---

## The audit log

**What it holds.** `/var/log/audit/audit.log` is the file `auditd` writes. AVC lines are one kind of record. Rotated files are `audit.log.1` and friends. `ausearch` reads the set.

**Which command writes it.** `auditd`, not `ausearch`. `ausearch` only reads.

**Look safely.** `sudo ausearch -m avc -ts recent --subject shopapi_t`. Do not `rm` the log to "reset" a soak. The reset marker is an epoch. Records older than that epoch are ignored.

---

## /etc/audit/auditd.conf

**What it holds.** How `auditd` rotates the log and what it does when the disk fills.

| Setting | Role |
|---------|------|
| `max_log_file` | Size in megabytes before rotation |
| `num_logs` | How many rotated files to keep |
| `max_log_file_action` | Usually `ROTATE` |
| `space_left_action` | What to do when free space crosses the first warning |
| `admin_space_left_action` | What to do when free space is lower still. The stock action is `SUSPEND` |
| `disk_full_action` | What to do when the disk is full. The stock action is `SUSPEND` |
| `disk_error_action` | What to do when a write fails |

**Which command writes it.** An editor, then a restart of `auditd`. No lab command writes it.

**Why it matters for soak.** Soak decides from AVC lines. If rotation deletes the file that held a denial, `ausearch` cannot see it. If `auditd` suspends because the disk is full, new denials are not written, and a monitor that only counts lines can look clean. Fail-closed applies when `ausearch` itself errors. It does not invent lines that `auditd` never wrote. Look at this file before a long soak.

**Look safely.** `cat /etc/audit/auditd.conf`. Confirm the stock actions on the host with the command in [LIVE_CHECKS.md](LIVE_CHECKS.md).

---

## /usr/share/selinux/devel

**What it holds.** `Makefile` compiles a module. `include/` is the header tree (`make` reads it for interfaces such as `init_daemon_domain`). The package is `selinux-policy-devel`.

**Which command writes it.** The RPM. You run `make -f /usr/share/selinux/devel/Makefile name.pp` in a directory that contains `name.te` and `name.fc`.

**Look safely.** `ls /usr/share/selinux/devel/Makefile /usr/share/selinux/devel/include`.

---

## /usr/share/selinux/packages

**What it holds.** The `.pp` files from the policy RPMs, before they are copied into the module store at priority 200. A shopapi RPM installs its module from the package payload. It does not leave a second copy you then `semodule -i` by hand.

**Which command writes it.** The RPM.

**Look safely.** `ls /usr/share/selinux/packages`. The exact filenames are a live check.

---

## semanage export

**What it holds.** A transcript of local customizations: file contexts, ports, booleans, permissive domains. It is not a file until you redirect it.

**Which command writes it.** `semanage export` prints. `semanage import` would apply a transcript. The labs do not import.

**Look safely.** `sudo semanage export`. Read it. Do not pipe it back into `semanage import` on a host you have not backed up.

Next: [104 — a module built by hand](104-HAND-BUILT-MODULE.md).
