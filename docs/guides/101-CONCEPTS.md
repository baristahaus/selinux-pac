# 101 — SELinux concepts

Read this before the SELinux command catalog, the config files, or a lab. The RHEL host commands (SSH, packages, services, the audit daemon) are in [100](100-RHEL-HOST-COMMANDS.md) and need no SELinux. Two names show up over and over:

| Name | What it is |
|------|------------|
| **shopapi** | The small Java app on the practice machine (**rhel-qa**). Its process type is `shopapi_t`. |
| **myapp** | A sample policy in this git repo so `make check` can run on a laptop. No service named myapp runs on rhel-qa. When a snippet says `myapp_t`, read it as the same kind of label as `shopapi_t`. |

The only commands in this guide are `getenforce`, `ls -Z`, and `ps -eZ`. Every other command is in [102](102-COMMANDS.md).

---

## What SELinux is

Linux already checks file permissions. Those answer: "Is this Unix user allowed to read or write this file?" The owner can change that answer.

**SELinux** (Security-Enhanced Linux) adds a second check inside the **kernel**. It answers: "Is this *program* allowed to do this action to this *object*?" The program cannot turn that check off by changing the file's owner.

| | Unix permissions | SELinux |
|--|------------------|---------|
| Question | Can this Unix user read this file? | Can a process labeled `shopapi_t` write a file labeled `shopapi_log_t`? |
| Who changes the answer | The file owner | An administrator, by shipping rules |
| Name | Discretionary access control (DAC) | Mandatory access control (MAC) |

Both checks run. A file can be writable by its Unix owner and still be denied by SELinux.

If an attacker takes over the app, they still only get what that app's label is allowed to touch.

On Red Hat Enterprise Linux, Fedora, and CentOS Stream, SELinux is already turned on. `getenforce` prints one word for the whole machine. The practice host stays **Enforcing**.

| Word | Meaning |
|------|---------|
| **Policy** | The full set of SELinux rules loaded in the kernel. |
| **Module** | One app's piece of that policy. Shopapi has its own module. `sshd` and `systemd` already have modules Red Hat shipped. |
| **Label** | The tag on a process or a file. |

---

## Labels

Every running program and every file wears a label. When the program tries to open a file, connect to a port, or start another program, the kernel compares the two labels against the policy.

| In a building | In SELinux | Shopapi |
|---------------|------------|---------|
| Badge on a person | Label on a running process. On a process, the type is called a **domain**. | `shopapi_t` |
| Sign on a door | Label on a file or directory | `shopapi_log_t` on a log file |
| Rule at the desk | An **allow rule** | A process badged `shopapi_t` may write a file signed `shopapi_log_t` |

- `ps -eZ` shows the label on a process. `-e` is every process. `-Z` adds the label. Lowercase `-z` is a different flag.
- `ls -Z` shows the label on each file it lists. `ls -Z` on a directory lists the files inside that directory, each with its own label. It does not print the directory's own label. The command that prints the directory itself is in [102](102-COMMANDS.md).
- The kernel's question is always: does policy allow this **source type** to do this **action** to this **target type**?
- If no rule allows it, and the machine is **Enforcing**, the action is blocked and a line is written to the audit log. If that one domain is **permissive**, the action still happens and the line is still written. The line is an **AVC**.

| Term | Plain English | Shopapi |
|------|---------------|---------|
| **Label / context** | The full tag. Four fields, separated by colons. | `system_u:system_r:shopapi_t:s0` |
| **Type** | The third field. The category the rules name. | `shopapi_t`, `shopapi_log_t` |
| **Domain** | A type worn by a running process. | `shopapi_t` while Java is running |
| **Object class** | What kind of thing is touched: a file, a directory, a socket. | `file`, `dir`, `tcp_socket` |
| **Allow rule** | One line that permits one action. | `allow shopapi_t shopapi_log_t:file write;` |
| **AVC** | The log line when an action is blocked, or would have been blocked. | A line in the audit log |
| **Confined** | Held to an allow list. | `shopapi_t` after the module is enforcing |
| **Unconfined** | Not held to an allow list. | Your SSH shell. Distro `tomcat_t` on this RHEL. |

A domain is a type on a process. `shopapi_log_t` is a type on a file, so it is not a domain.

---

## The four fields

```text
user     : role     : type      : level
system_u : system_r : shopapi_t : s0
```

| Field | Shopapi's process | What you use it for |
|-------|-------------------|---------------------|
| user | `system_u` | "This belongs to the system." You rarely write rules about it. |
| role | `system_r` | A process (`system_r`) or a file (`object_r`). |
| **type** | **`shopapi_t`** | **The field allow rules use.** |
| level | `s0` | A clearance stamp. This project leaves it at the default. |

The first field is an SELinux user. It is a different namespace from Unix users (`ansible`, `root`). Changing the Unix owner of a file does not change this field.

**`system_u`** is the SELinux user on operating-system objects: the shopapi service, its logs, and every label this project writes.

**`unconfined_u`** is the SELinux user on a normal administrator login. It describes you. It does not appear in `selinux/shopapi/shopapi.te`.

**`system_r`** is the role on a process the system started. **`object_r`** is the role on a file, a directory, or a port. **`unconfined_r`** is the role on your SSH shell. When you are reading shopapi, skip a label whose role is `unconfined_r`.

The type is the category. `shopapi_t` and `sshd_t` can both be system processes and still be different programs.

**`shopapi_t`** is the domain of the running shopapi process. The unit does not set `SELinuxContext=`. `init_daemon_domain(shopapi_t, shopapi_exec_t)` is the transition from `init_t` when systemd executes the wrapper. The JVM file is shared by every Java program on the host, so the module does not relabel it. On RHEL 9 it is `bin_t`: `java_exec_t` is an alias of `bin_t` ([`corecommands.te` on c9s](https://github.com/fedora-selinux/selinux-policy/blob/c9s/policy/modules/kernel/corecommands.te)).

**`shopapi_exec_t`** is the type on the wrapper `/opt/shopapi/bin/shopapi`. The jar and config under `/opt/shopapi` are `shopapi_lib_t`. The wrapper type and the process type are a pair.

**`shopapi_log_t`** is the type log files should have under `/var/log/shopapi`. An allow rule names this type. It does not name the path. If the file on disk still has a generic type, the allow for `shopapi_log_t` does not cover it.

**`shopapi_var_lib_t`** is state under `/var/lib/shopapi`. **`shopapi_var_run_t`** is a pid file and short-lived sockets under `/run/shopapi`. **`shopapi_port_t`** is TCP port 8091 once that port has a label. An early denial may name `unreserved_port_t`, the generic type for a high port nobody has labeled yet.

Generic types from the base policy, before this app's own types are on the files:

| Generic type | Typical path |
|--------------|----------------|
| `var_log_t` | Anything under `/var/log` that does not have a more specific type yet |
| `var_lib_t` | The same situation under `/var/lib` |
| `var_spool_t` | The same situation under `/var/spool` |
| `usr_t` | A generic type under `/usr`, and sometimes under `/opt` before the shopapi file-context line is applied |

The file on disk can still wear the generic type after the module names the shopapi type. The denial shows the type that is actually on the object. The allow you write names the shopapi type. Both facts are true until the file is relabeled. Relabeling is a later command.

**`unconfined_t`** is your SSH shell. Commands you type by hand run as `unconfined_t`. Java started from that shell runs as **`unconfined_java_t`**. **`unconfined_service_t`** is a service systemd started with no domain of its own. Either label means the wrapper is not `shopapi_exec_t`, so the transition did not run.

**`tomcat_t`** is Tomcat from the RHEL package. [`tomcat_domain_template(tomcat)`](https://github.com/fedora-selinux/selinux-policy/blob/c9s/policy/modules/contrib/tomcat.te) declares a single `tomcat_t`. The same module contains `unconfined_domain(tomcat_t)`, so on this practice RHEL the process is not held to a tight allow list. A second instance does not get a second domain.

**`jws6_tomcat_t`** is Red Hat JBoss Web Server Tomcat, when that product is what the machine is running. This one is confined. You adjust the host. You do not author a second module for it.

**`myapp_t`** and the other `myapp_*` types live in `selinux/myapp/myapp.te`. They are not the process on rhel-qa.

The last field is a sensitivity level from MLS/MCS. This project does not turn that feature on. **`s0`** is the default. Stop at the type. A range such as `s0-s0:c0.c1023` is an unconfined login, not a shopapi file.

---

## What a label looks like

`ls -Z` on a file prints that file's label. The third field of the wrapper, from [`selinux/shopapi/shopapi.fc`](../../selinux/shopapi/shopapi.fc), is `shopapi_exec_t`:

```bash
ls -Z /opt/shopapi/bin/shopapi
```

`ls -Z /opt/shopapi` lists the names inside that directory. It does not answer "what type is the directory itself?"

`ps -eZ` prints every process with its label. The shopapi Java process type is `shopapi_t`. The file type stays `shopapi_exec_t`. Starting the program does not turn the file's type into the process type.

```bash
ps -eZ
getenforce
```

`getenforce` prints `Enforcing`, `Permissive`, or `Disabled`. The lab keeps `Enforcing`.

A captured transcript of these three commands on rhel-qa is in [LIVE_CHECKS.md](LIVE_CHECKS.md).

---

## Enforcing and permissive

| Mode | What a denial does |
|------|--------------------|
| **Enforcing** | The action is blocked, and a line is written to the audit log. This is the mode the lab keeps. |
| **Permissive** | The action is allowed, and a line is still written. The whole machine is in this mode. |
| **Disabled** | SELinux is off. The lab does not use this. |

Switching the whole machine to Permissive would make SSH, cron, and every service only log denials. This project does not do that. `getenforce` stays `Enforcing`.

One domain can be on a log-only list while the machine stays Enforcing. Actions by that domain are allowed and logged. Actions by every other domain are still blocked. The commands that edit that list are in [102](102-COMMANDS.md).

| Phase | What is installed | Why that domain is log-only |
|-------|-------------------|-----------------------------|
| **Discovery** | A seed: type names, almost no allows | So the app can run and the audit log fills with the lines you will turn into allows |
| **Soak** | The finished module, installed from the signed RPM | So work that does not happen during a demo can still reveal a missing allow before the domain leaves the list |

Both phases leave `getenforce` printing `Enforcing`.

In an AVC line, `permissive=1` means this domain was log-only, so the action succeeded. `permissive=0` means the action was blocked.

**Canary** means install the new module and watch it, with the app domain still log-only. **Soak** means leave it that way for days. On production, day 0 of that wait installs the RPM. It does not type an install of the `.pp` on the server. The jobs are in [401](../shipping.md).

**Net-new** means a permission the installed module does not already allow. The same denial printed again tomorrow is not net-new if the module already has that allow.

Cron, log rotation, and certificate renewal do not run as `shopapi_t`. On the c9s policy they have their own domains (`system_cronjob_t`, `logrotate_t`, `certmonger_t`). Soak compares the log to the shopapi module, so it only counts `shopapi_t`.

---

## An AVC line

When the kernel blocks an action, or would have blocked it, it writes an AVC line. AVC stands for Access Vector Cache. Treat the letters as "the denial line."

```text
avc: denied { write } for pid=1234 comm="java"
  scontext=system_u:system_r:shopapi_t:s0
  tcontext=system_u:object_r:var_log_t:s0
  tclass=file permissive=1
```

| Field | On this line | Meaning |
|-------|--------------|---------|
| `denied { write }` | `write` | The action that was not allowed |
| `comm="java"` | `java` | The program name |
| `scontext` | `shopapi_t` | Who did it. Read the type. |
| `tcontext` | `var_log_t` | What they touched. Read the type. |
| `tclass=file` | `file` | The object class |
| `permissive=1` | `1` | The domain was log-only, so the write still happened |

Read it as a sentence: shopapi_t tried to write a file labeled var_log_t, and no allow covers that pair.

The audit log is the file `auditd` writes. Searching it is a later command. A permissive domain logs each distinct denial once. The kernel keeps that decision until a policy reload. A second identical attempt is not written again until that cache is flushed.

"The log has AVC lines" and "the rule book needs a new allow" are different statements. A line the module already allows is **baseline**. It is not written again.

---

## How a process gets its type

A process does not pick its own label. The kernel assigns one from how the process was started.

systemd executes `/opt/shopapi/bin/shopapi` (`shopapi_exec_t`). [`init_daemon_domain`](https://github.com/fedora-selinux/selinux-policy/blob/c9s/policy/modules/system/init.if) transitions `initrc_domain` on that type to `shopapi_t`, and `init_t` is an `initrc_domain`. The unit does not set `SELinuxContext=`. The wrapper then executes `/usr/bin/java`, a `bin_t` file. That execute is not an entrypoint, so the process stays `shopapi_t`. `ps -eZ` shows `shopapi_t` on the Java process. The JVM file stays `bin_t`.

The sample app uses the same idea: `init_daemon_domain(myapp_t, myapp_exec_t)` means systemd starting a file of type `myapp_exec_t` creates a process of type `myapp_t`. That is a **type transition**.

If you start Java by hand from your SSH shell, the new process keeps your shell's type, `unconfined_t`. The denials then describe your login, not the service.

---

## Types you will see

| Suffix | Means |
|--------|--------|
| `_t` | A type. Every SELinux type ends in `_t`. |
| `_exec_t` | A program file. Executing it can start a domain. |
| `_log_t` | Log files |
| `_var_lib_t` | State that should survive a reboot |
| `_var_run_t` | Runtime files under `/run` that disappear on reboot |
| `_port_t` | A network port |

Declared in [`selinux/shopapi/shopapi.te`](../../selinux/shopapi/shopapi.te). The path map is [`shopapi.fc`](../../selinux/shopapi/shopapi.fc).

| Type | Used for |
|------|----------|
| `shopapi_t` | The running shopapi process |
| `shopapi_exec_t` | The wrapper `/opt/shopapi/bin/shopapi` |
| `shopapi_lib_t` | The jar and config under `/opt/shopapi` |
| `shopapi_log_t` | Logs under `/var/log/shopapi` |
| `shopapi_var_lib_t` | State under `/var/lib/shopapi` |
| `shopapi_var_run_t` | Pid file and sockets under `/run/shopapi` |
| `shopapi_port_t` | TCP port 8091 |

`myapp_*` in [`selinux/myapp/myapp.te`](../../selinux/myapp/myapp.te) is the laptop sample. `make check` uses these types. They do not run on rhel-qa.

| Type | Used for |
|------|----------|
| `myapp_t` | The sample process domain |
| `myapp_exec_t` | The sample program file under `/opt/myapp` |
| `myapp_lib_t` | Libraries inside the sample virtualenv |
| `myapp_var_lib_t` | State under `/var/lib/myapp` |
| `myapp_log_t` | Logs under `/var/log/myapp` |
| `myapp_var_run_t` | Runtime files under `/run/myapp` |
| `myapp_port_t` | TCP port 8888 in the sample |
| `myapp_script_exec_t` | A shell script the sample runs |
| `myapp_backend_t` | A second sample process |
| `myapp_backend_exec_t` | The program file for that second process |
| `myapp_backend_port_t` | TCP port 8889 |

A **vendor domain** is a type Red Hat ships for a product. Tune the host. Do not write a parallel module. A **seed** is a starter module that declares types and has almost no allows.

---

## Glossary

| Term | Meaning |
|------|---------|
| **Kernel** | The core of the operating system. SELinux checks run here. |
| **Unix permissions** | Owner, group, and mode bits. Checked as well as SELinux. |
| **MAC** | Mandatory access control. The system enforces SELinux rules. |
| **DAC** | Discretionary access control. Unix permissions. |
| **Policy** | The full set of SELinux rules loaded in the kernel. |
| **Module** | One app's piece of policy. |
| **Label / context** | The four-field tag `user:role:type:level`. |
| **Type** | The third field. |
| **Domain** | A type on a running process. |
| **Object class** | The kind of object: `file`, `dir`, `tcp_socket`. |
| **Allow rule** | One permitted action. |
| **`.te`** | The rule book (type enforcement). Text you edit. |
| **`.fc`** | File contexts: which type a path should wear. A file on disk, read by later tools. Not part of the kernel. |
| **`.pp`** | The compiled module package the kernel loads. |
| **Enforcing** | Denials block the action. |
| **Permissive** | Denials are logged and the action still happens. The whole machine, or one domain. |
| **AVC** | The denial line in the audit log. |
| **auditd** | The service that writes the audit log. |
| **Confined** | Held to an allow list. |
| **Unconfined** | Not held to an allow list. |
| **Vendor domain** | A type shipped by Red Hat. Tune the host. |
| **Seed** | A starter module with almost no allows. |
| **Baseline** | An access the current rule book already allows. |
| **Canary** | Install a new module and watch it, domain still log-only. |
| **Soak** | Leave the canary in place for days, watching for net-new denials. |
| **Net-new** | A permission the installed module does not already allow. |
| **dontaudit** | A policy feature that hides a denial the author decided not to show. |
| **MLS/MCS** | Clearance and category labels. This project leaves them at `s0`. |
| **Type transition** | The parent process plus the file type decide the child process type. |

Next: [102 — commands](102-COMMANDS.md).
