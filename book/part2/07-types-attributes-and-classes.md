# Types, Attributes and Classes

> Every policy module is a list of types. The review of that list — *why each type exists,
> what happens if a rule names a generic type instead, and how the attribute shortcuts collapse
> ten rules into one* — is the single most valuable thing you can learn about the module language.

## Declaring types

A type is a name the policy kernel learns. You give it a name with one line:

```text
type myapp_t;
```

That is the only syntax in `.te` that creates a type. From that moment, the type may appear in
allow rules, in file-context lines, and in `sesearch` queries. The type is the thing all three
tools talk about.

In the example module (`selinux/myapp.te`), every line of type declarations is a purpose
statement — each type is tied to a path, a port, or a role. There are eleven types declared
for a single application, each one *owned* by its purpose:

```text
type myapp_t;              # process domain — the running app
type myapp_exec_t;         # entrypoint binary
type myapp_lib_t;          # application code (read-only)
type myapp_var_lib_t;      # FHS data under /var/lib/myapp
type myapp_var_run_t;      # FHS runtime socket under /run/myapp
type myapp_log_t;          # FHS log under /var/log/myapp
type myapp_script_exec_t;  # helper scripts under /opt/myapp/bin
type myapp_backend_t;      # backend stub domain
type myapp_backend_exec_t; # backend entrypoint binary
type myapp_port_t;         # port 8888 (HTTP)
type myapp_backend_port_t; # port 8889 (backend)
```

The naming convention is plain: `myapp_<purpose>_t`. The `myapp_` prefix scopes the type to the
module; the middle word names its purpose; the `_t` suffix is the kernel-level reminder that every
label field ends in `t`. The convention is not decorative — it is the reason `sesearch` returns a
clean result.

### Dedicated versus generic

The single most common mistake in the first module is reusing a generic type for an
application-owned path.

| Dedicated type | Generic type | Why dedicated wins |
|---|---|---|
| `myapp_var_lib_t` | `var_lib_t` | *writes only reach `/var/lib/myapp`, not every directory under `/var/lib`* |
| `myapp_log_t` | `var_log_t` | *logrotate and log access scoped to `/var/log/myapp`* |
| `myapp_port_t` | `unreserved_port_t` | *binds only port 8888, not every high port on the host* |
| `myapp_var_run_t` | `var_run_t` | *runtime socket is reachable only from `/run/myapp`* |

A generic type carries the policy of every consumer. `var_t` already has rules for `rsyslog_t`,
`cron_job_t`, `logrotate_t`, `root`, and a dozen other domains. Adding your own `allow
myapp_t var_t:file write;` grants your process a passport that covers every directory the generic
type applies to. The kernel sees: *every file in `/var` may be written* — not just your application's.

The same logic applies to ports. `allow myapp_t unreserved_port_t:tcp_socket name_bind;` does not
say *port 8888* — it says **every unreserved port**. That is why the CI gate in
`validate_forbidden_patterns.sh` refuses this pattern outright:

```bash
if grep -qE 'allow[[:space:]]+[^[:space:]]+[[:space:]]+var_t:file[[:space:]]+\{[^}]*write' "${te}"; then
    check_fail "Forbidden broad var_t:file write — use dedicated application types"
fi
```

Every broad grant against a generic type is a category of files. Every broad grant against a
generic port type is a category of ports. Chapter 2 shows the same distinction in the denial
tuple.

::: why The type name is the security boundary
A rule against a generic type does not grant a file — it grants a *category*. The type name
names a category. If that category already belongs to another domain, your process shares the
keys with that domain. If that category is writable by `root`, your process shares the keys with
root. A dedicated type names only your files. The review reads the type name and asks: *does this
name match the directory, the port, or the process I am trying to reach?* If yes, the rule is
narrow; if no, the rule is a category.
:::

## Attributes

A type can be *tagged* with an attribute without rewriting rules. An attribute is a label on a
type that lets a single allow rule address a whole family.

```text
typeattribute myapp_var_lib_t file_type;
```

That line says: *every rule written against `file_type` now covers this type.* The kernel does not
gain new semantics — the `file` object class was always `file` — but the policy author gains a
shorthand. Every interface that takes an *attribute* targets every tagged type at once:

```text
files_type(myapp_lib_t)        # tag myapp_lib_t as a generic file
files_type(myapp_var_lib_t)    # tag myapp_var_lib_t as a generic file
files_pid_file(myapp_var_run_t) # tag myapp_var_run_t as a PID file
files_type(myapp_script_exec_t)
files_type(myapp_backend_exec_t)

corenet_port(myapp_port_t)         # tag myapp_port_t as a generic network port
corenet_port(myapp_backend_port_t) # tag myapp_backend_port_t as a generic network port

logging_log_file(myapp_log_t)      # tag myapp_log_t as a generic log file
```

`myapp_log_t` appears once, tagged by `logging_log_file()` — the module does not also declare it with `files_type()`, because `logging_log_file()` calls `files_type()` itself.

Each of these lines declares the type, attaches an attribute, and triggers an interface that writes
the allow rules for the entire family in one call. The result is twelve allow rules that a
reviewer can read in a second: every file-tagged type inherits `read` and `open` from
`read_files_pattern`; every PID-tagged type inherits search from `files_search_pids`; every
network-port-tagged type inherits `name_bind` from `corenet_tcp_bind_generic_node`; every
log-tagged type inherits `logging_log_filetrans` and file-management from `manage_files_pattern`.

The attribute is how an interface writes rules for *all* types of its class, not just one. The
author writes one `typeattribute` line, the interface writes all the allows. This is the
difference between "ten rules per type" and "one rule per class."

### How the interface macros read

The macros in the example module are not custom — they are refpolicy interfaces, each of which
pairs an attribute with a predictable set of allows. The ones you will see most often:

| Macro | What it attaches | What follows from it |
|---|---|---|
| `files_type(TYPE)` | the file family: `file_type`, `non_security_file_type`, `non_auth_file_type` | rules written against those attributes now cover `TYPE` |
| `logging_log_file(TYPE)` | `logfile`, and it calls `files_type()` plus the tmpfs associations itself | log-file rules and `logging_log_filetrans` cover `TYPE`; you do not also call `files_type()` |
| `files_pid_file(TYPE)` | the base policy's pid-file attribute | the pid-file rules (`files_search_pids`, pid-file management) cover `TYPE` |
| `corenet_port(TYPE)` | the port-type attribute | `TYPE` can be used as a port label; binding it is a separate allow the module writes (`corenet_tcp_bind_generic_node(myapp_t)`) |
| `init_daemon_domain(DOMAIN, EXEC)` | `daemon`, then `domain_type()` and `domain_entry_file()` | a `domtrans_pattern(initrc_t, EXEC, DOMAIN)` transition, and under the systemd build `init_domain()` as well |
| `init_daemon_run_dir(TYPE, NAME)` | the run-directory association for the service | the init domain may create the runtime path for `NAME`; the domain's own access to it is written separately |

These are not invented by the module author — they come from the refpolicy library, and the
interface body is the authority: read it at
`/usr/share/selinux/devel/include/kernel/files.if` (and `system/logging.if`,
`system/init.if`) on any host with `selinux-policy-devel` installed. The names appear in `allow`
rules written by the build; the author writes the declarations, and `seinfo -a` lists the
attributes that actually exist in the policy you are running.

## Object classes and permissions

The *class* decides what kinds of operations are even meaningful; the *permission* names one of
them. A rule is the triple: *allow source target:CLASS { permission, … }*.

The kernel already names the class in every AVC line — the `tclass` field — so the list below is
what a service author will meet in practice, taken from the base policy object-class definitions:

| Object class | What it covers | Permissions you will read most often |
|---|---|---|
| `file` | regular files | `read`, `write`, `open`, `getattr`, `setattr`, `create`, `execute`, `append`, `map`, `entrypoint` |
| `dir` | directories | `search`, `open`, `read`, `write`, `add_name`, `remove_name`, `getattr` |
| `lnk_file` | symlinks | `read`, `getattr` |
| `tcp_socket` | TCP sockets | `bind`, `name_bind`, `listen`, `accept`, `connect`, `name_connect`, `read`, `write`, `shutdown` |
| `udp_socket` | UDP sockets | `bind`, `create`, `read`, `write` |
| `unix_stream_socket` | Unix domain sockets | `connectto`, `create`, `bind`, `listen`, `accept`, `read`, `write`, `setattr` |
| `process` | running processes | `fork`, `transition`, `dyntransition`, `sigchld`, `siginh`, `rlimitinh`, `execmem` |
| `capability` | kernel capabilities | `net_bind_service`, `dac_override`, `chown`, `fowner`, `sys_resource` |
| `system` | policy-level objects | `module_load`, `syslog_read`, `syslog_mod`, `syslog_console` |
| `unix_dgram_socket` | Unix datagram sockets | `send`, `recv`, `read`, `write` |

The most important column is the third — permissions that appear in *every* denial. A process
needs `file` permissions to read data; it needs `dir` permissions to create new data; it needs
`tcp_socket` permissions to talk to a port; it needs `process` permissions to spawn a child.
Writing `allow myapp_t myapp_var_lib_t:file write;` is only correct if the process is writing
text into an existing file, not creating a new one — in which case `dir:write` (or the
`manage_files_pattern` macro) is the real allow.

### Querying the installed policy

Every line of the module language is answerable with the tooling shipped with the base policy.
You do not have to trust `audit.log` alone; you can look up the rule yourself.

```bash
# What does the base policy already cover for this domain?
$ sesearch -A -s myapp_t -c file
# every (source, target, class, permission) row that the installed policy allows myapp_t on file

$ sesearch --allow -t myapp_var_lib_t
# every allow rule that addresses the target type myapp_var_lib_t

$ seinfo -t | head
# list of all types in the installed policy — this is the universe of types, not just yours

$ seinfo -a | head
# list of all attributes — this is the universe of attribute tags, not just yours
```

The first query is the most useful: it answers "what does the OS already let me do?" If the row
already exists, you do not need to add it. If it does not, you either need to add the type (so a
row can be written against it) or accept that your application does not reach that resource.

```bash
# on rhel-qa, against the compiled module:
$ sesearch --allow -s myapp_t -t myapp_var_lib_t -c file
allow myapp_t myapp_var_lib_t:file { create write ... };
# already declared in the module — there is a rule for every operation the macro expanded
```

`seinfo -t` and `seinfo -a` are for exploration. They show the *installed* policy — the union of
base policy plus all loaded modules — and they are the most honest source of truth when an
interface asks, "does my target type exist yet?" They are not a test; they are the catalog.

### Generic versus specific targets — the review verdict

The review of a target type is the same question every chapter from Part III returns to: *does
the type name match the path, or does it match a category?* The constants in
`cli/policy_rules.py` codify the answer.

```text
FORBIDDEN_TARGET_TYPES = frozenset(
    {
        "shadow_t",
        "unconfined_t",
        "sysadm_t",
        "security_t",
        "selinux_config_t",
        "passwd_file_t",
    }
)

GENERIC_FILE_TYPES = frozenset(
    {
        "var_t", "var_lib_t", "var_log_t", "var_run_t",
        "usr_t", "etc_t", "tmp_t", "default_t",
        "unlabeled_t", "home_root_t",
        "user_home_t", "user_home_dir_t",
    }
)

GENERIC_PORT_TYPES = frozenset(
    {
        "unreserved_port_t",
        "port_t",
        "reserved_port_t",
        "ephemeral_port_t",
    }
)
```

Each constant has a role: `FORBIDDEN_TARGET_TYPES` names types the module is forbidden to talk to;
`GENERIC_FILE_TYPES` names file types that every other service already reaches; `GENERIC_PORT_TYPES`
names ports that every networked service already reaches. The verdict per constant:

| Constant | Verdict | Meaning |
|---|---|---|
| `FORBIDDEN_TARGET_TYPES` | refuse outright | high-privilege types — `shadow_t`, `passwd_file_t`, `security_t` |
| `GENERIC_FILE_TYPES` | refuse unless it is the right path | every file in `/var`, `/tmp`, `/usr`, `/home` |
| `GENERIC_PORT_TYPES` | refuse unless the port is declared | every unreserved, reserved, or ephemeral port |

The CI script that enforces these verdicts is the grep block in `scripts/validate_forbidden_patterns.sh`. The pattern against a broad file grant is written as:

```bash
if grep -qE 'allow[[:space:]]+[^[:space:]]+[[:space:]]+var_t:file[[:space:]]+\{[^}]*write' "${te}"; then
    check_fail "Forbidden broad var_t:file write — use dedicated application types"
fi
```

The pattern against a broad port grant is not named in that script — the classification lives in
`cli/deterministic_gen.py`, with the constant sets in `cli/policy_rules.py`: an allow whose target
is one of the generic port types (`unreserved_port_t`, `port_t`, `reserved_port_t`,
`ephemeral_port_t`) and whose permission set includes `name_bind` is classified as
`private_port`, with `next_action: add_manifest_port` — the port type is the fix, not the allow.
`direct` is a different verdict, for the allows that name the module's own private types.

The `validate_policy_semantics.sh` script goes further: it asserts on the compiled module that no
`allow` reaches `shadow_t` or `unlabeled_t`, and that every `entrypoint` allow names only a type
under the module's own prefix:

```bash
if sesearch --direct --allow -s "${DOMAIN}" -t shadow_t -p read "${kern}" 2>/dev/null | grep -q .; then
    log_error "unexpected allow ${DOMAIN} -> shadow_t:read"
fi
if sesearch --direct --allow -s "${DOMAIN}" -t unlabeled_t "${kern}" 2>/dev/null | grep -q .; then
    log_error "unexpected allow ${DOMAIN} -> unlabeled_t"
fi
```

These assertions are the proof that the type system does the work the author forgets: they refuse
a grant against a privileged type or an unlabeled object *before* it reaches review.

::: try Read the type catalogue on rhel-qa
Nothing modifies policy; the output is your own host's answer.

```bash
$ seinfo -t | head -n 20
$ seinfo -a | head -n 20
$ sesearch -A -s myapp_t -c file
```

The first query shows the universe of types on your host — base policy plus all modules. The
second shows the attributes every type can be tagged with. The third shows your own module's
allow rows. Read the rows against generic types first: they are the ones the review asks about.
:::

## What you can do now

| Action | Command | What you learn |
|---|---|---|
| list every type on the host | `seinfo -t` | the universe your policies can target |
| list every attribute | `seinfo -a` | the shortcuts each type can take |
| list my own allows on a class | `sesearch -A -s myapp_t -c file` | the rules already written — nothing to add |
| list allows against a target type | `sesearch --allow -t myapp_var_lib_t` | the scope of your type's allow rows |
| check a deny before adding a rule | `sesearch -A -s myapp_t -c file` | the row may already exist |
| declare a dedicated type | `type myapp_spool_t;` | the smallest possible name for a path |
| tag an attribute | `typeattribute myapp_spool_t file_type;` | one interface call instead of ten rules |

The chapter's takeaway is not new syntax — it is a reading habit. When you read an allow rule,
read the target type name first: *does this name match the path, or does it match a category?*
If it matches a category, the rule is a category grant — it is still correct but it is the kind
of grant you review second. If it matches a privileged type, the rule is forbidden — you do not
review it, you rewrite it.
