# Anatomy of a Module

> A SELinux policy module is the only artifact a distribution trusts at boot. It is also
> the only artifact a distribution ships. It is built from four kinds of files, guarded
> by one file, compiled on a RHEL host, and installed with one command that reaches the
> running kernel. This chapter opens Part II. Every line here, and every rule in
> Chapter 8, is about those four files and the decision they make together.

A *module* is not a running program. It is a policy object. The running
application is a process, and the module is the policy that lets it do what it
must. Part IV explains how that policy leaves Git as an RPM.
## The four files that make a module

Each module ships as a small collection of files. A different piece of tooling
reads each kind, and each kind has one job.

| File | Purpose | Who reads it |
|------|---------|--------------|
| `module.te` | Type enforcement: types, attributes, `allow` rules, `type_transition` | `checkmodule` during build, the policy editor, and reviewers. Chapter 8 reads every rule |
| `module.fc` | File contexts: the label each path on disk carries | `restorecon` / `matchpathcon` at install time, and Chapter 9 follows every line |
| `module.if` | Interfaces: `policy_module`-level contracts that other modules call | the author (uses `gen_require`), and Chapter 8 describes how to call them and when `optional_policy` is the safe choice |
| `module.pp` | Compiled module package: the `.mod` plus the `.fc`. `semodule -i` links them into the loaded binary policy | `semodule -i` at runtime, and Chapter 19 describes how it arrives in production |

`module.pp` is never authored by hand. `checkmodule` turns `.te` into `.mod`,
and `semodule_package` wraps `.mod` + `.fc` into `.pp`. The file
`selinux/myapp.pp` in this repository is also a build artifact. It is the file
the RPM ships, but it does not live in Git. That is why Chapter 16 guards the
compile step on a RHEL host rather than running it on your laptop.

Every other file in a policy pull request supports one or two of these four
files: the `.cil`, the `policy_version.txt`, and the manifest under `config/`.
Each file has one job and no more.

:::: why Four files, not one
In theory, one text file can hold a whole policy module. But each kind serves a
different consumer. A policy language compiler reads `.te`. A labeler that walks
the filesystem reads `.fc`. A dependent author who wants to borrow a contract
reads `.if`. The kernel's policy store reads `.pp` at boot. Splitting them lets
each consumer work alone. You can check `.fc` on an air-gapped host even if you
do not have `checkmodule` installed.
::::

## `policy_module(name, version)` and the single source of truth

The first line of every `module.te` is:

```text
policy_module(myapp, 1.1.3)
```

This line names the module and pins a SemVer. It is the only human-visible
version in the module, and by convention the only copy. Every repository with a
policy module also carries a sibling called `policy_version.txt`. The rule is
*one source of truth, never two copies.*

Each module owns its own `policy_version.txt`:

```text
selinux/policy_version.txt              → contains 1.1.3 (for myapp)
selinux/shopapi/policy_version.txt      → contains 1.0.0 (for shopapi)
selinux/payments/policy_version.txt     → contains 1.0.0 (for payments)
```

Each file is a single line: the version string. That string must match the
second token of the `policy_module(...)` line. The two places can drift in two
directions at once, so the repository trusts neither.
`validate_version_consistency.sh` fails the CI if they disagree.

```text
validate_version_consistency: payments OK (1.0.0)
validate_version_consistency: myapp OK (1.1.3)
validate_version_consistency: shopapi OK (1.0.0)
validate_version_consistency: all modules OK
```

The order comes from `find … | sort` over the `policy_version.txt` files. What
matters is that the output lists every module and the last line is the summary.

The same script also checks that `packaging/<module>-selinux.spec` reads
`Version: %{modver}` rather than a hard-coded number. `rpmbuild` injects the
version from `policy_version.txt` at build time, so a literal
`Version: 1.1.3` in the spec silently mismatches the compiled package.
The build script that produces all three RPMs (`packaging/build_rpms.sh`)
reads `policy_version.txt` and passes it to `rpmbuild` as `--define "modver
1.1.3"`. If you edit the version, you edit one file. Then you rerun the
consistency check before opening the PR.

::::: note Why one source of truth
The RPM build (each `packaging/<module>-selinux.spec`) injects the version from
`policy_version.txt` at build time. If you edit the version, you edit one file
and rerun the consistency check.
:::::

`selinux/myapp.te` is the reference module for the Order Processor demo
application, a Flask server plus a small Python backend stub. It ships two
domains, `myapp_t` and `myapp_backend_t`, and they share a file tree under
`/opt/myapp`, `/var/lib/myapp`, `/var/log/myapp`, and `/run/myapp`. Read it as
a story told in sections.

### The preamble: `policy_module` and the type declarations

```text
policy_module(myapp, 1.1.3)
# Declarations
type myapp_t;
type myapp_exec_t;
type myapp_lib_t;
type myapp_var_lib_t;
type myapp_var_run_t;
type myapp_log_t;
type myapp_script_exec_t;
type myapp_backend_t;
type myapp_backend_exec_t;
type myapp_port_t;
type myapp_backend_port_t;
```

Every module starts with `policy_module(...)`. It names the module, and it
matches the `policy_version.txt` you already checked. Then the types. Each
`type` declares *one thing* the module will own in the policy: a process domain,
a binary, a directory tree, a log type, or a TCP port. Nothing here states a
permission. You cannot permit on a type that does not exist, which is why
`allow` rules appear later.

The `files_type(...)` and `corenet_port(...)` calls above each type are
refpolicy *macros* that register a type with the standard file or network
namespace. So `restorecon` and `semanage port` can recognize them without
re-reading custom tooling. The same pattern appears in Chapter 9.

### The require block

```text
require {
    type init_t;
    class process { transition dyntransition siginh rlimitinh };
    class file entrypoint;
}
```

`require` borrows *from* the base policy. It tells `checkmodule`: *I need these
types and classes, even though my module does not own them.* `init_t` is the
systemd process, the kernel's "first" process. The permissions in the list
(`transition`, `dyntransition`, `siginh`, `rlimitinh`, `entrypoint`) are the
ones systemd needs to start a unit as a domain. Every daemon-style module
requires this block. Order matters, because the kernel's policy compiler reads
the require block before it reads the rules that use it.

### The `type_transition` that starts the service in its own domain

```text
allow init_t myapp_exec_t:file { execute ... entrypoint };
allow init_t myapp_t:process { transition dyntransition siginh rlimitinh };
allow myapp_t myapp_exec_t:file entrypoint;
type_transition init_t myapp_exec_t:process myapp_t;
```

This is the most important section of the module. It is how systemd starts the
application *as `myapp_t`*, and not as `bin_t` (the generic type that labels
every executable on the system). Without it, systemd starts the Java, Python,
PHP, or other binary with whatever `bin_t` label the file carries. Then every
`allow ... bin_t:file read;` rule is a blast radius.

- `type_transition init_t myapp_exec_t:process myapp_t;`: when `init_t`
  executes anything labeled `myapp_exec_t`, the resulting process is `myapp_t`.
- `allow init_t myapp_t:process { transition ... };`: systemd can perform the
  transition. This is the permission that makes `type_transition` work.
- `allow init_t myapp_exec_t:file { ... entrypoint };`: systemd can read and
  open the entrypoint binary with all the syscalls it actually needs to launch
  it (`execute`, `read`, `open`, `getattr`, `map`, `ioctl`,
  `execute_no_trans`, `entrypoint`).
- `allow myapp_t myapp_exec_t:file entrypoint;`: the launched domain can also
  re-exec itself through the same entrypoint (used when the binary execs back
  into its own code).

The same block for `myapp_backend_t` mirrors this at `/opt/myapp/backend_stub.py`
and `/var/opt/myapp/backend_stub.py`. Every submodule gets its own
`type_transition`. The domains do not share one.

### The daemon baseline

```text
files_read_etc_files(myapp_t)
sysnet_read_config(myapp_t)
kernel_read_system_state(myapp_t)
dev_read_urand(myapp_t)
```

These four macros give the domain the minimum that every long-running process needs under enforcing. The minimum is: read /etc/, read system configuration, poll the kernel, and consume randomness. `myapp_backend_t` gets the mirrored set on the next lines, because the baseline applies per domain. The comment above the section is not decoration. Review the section once, as a unit. Do not widen one AVC at a time through generated PRs. Chapter 15 codifies that rule.

### The remaining sections

After the baseline, the module adds:

- path-traversal `files_search_*` macros for each domain (they search
  `/var/lib`, `/run`, and `/usr`. Each type reaches only its own label. The
  search runs on a generic base type, so every search is a walk past unrelated
  files)
- the Flask surface: `myapp_t` reads its own library and its own executables.
  It manages its own `/var/lib/myapp` and `/var/log/myapp`, binds a TCP port,
  and connects to `myapp_backend_port_t`. It writes pid files under
  `/run/myapp`, sends syslog, execs shells, and reads certificates
- the backend stub: `myapp_backend_t` does the same subset. It reads its own
  lib and reads the Flask binaries, so it can call them. It binds its own port,
  manages its own pid files, and talks to the Flask domain over Unix sockets
- a final `allow myapp_t myapp_t:unix_stream_socket connectto;` rule: a
  self-socket needed by a small internal component. This is the only line in
  the file that a generator wrote in. The comment above it names the generator
  hash and the refpolicy version it reproduced from.

## The build: `checkmodule`, `semodule_package`, and the `make -f` path

The text and label files become a binary module through `checkmodule` and
`semodule_package`, the refpolicy toolchain. The repository wraps that toolchain
behind a single script.

```bash
POLICY_MODULE=myapp SELINUX_DOMAIN=myapp_t \
  bash scripts/compile_and_validate.sh selinux
```

That script first runs `validate_forbidden_patterns.sh selinux`, which rejects
`shadow_t`, a blanket `bin_t` execute, and wildcards. The script then compiles.
The underlying call lives inside `scripts/lib/compile_policy.sh` and is:

```text
make -C <temp dir with myapp.te, myapp.fc, myapp.if> \
     -f /usr/share/selinux/devel/Makefile myapp.pp
```

That is `make` with the *refpolicy* `Makefile` shipped with the package
`selinux-policy-devel`. It produces `myapp.pp` from the text. The script copies
that file to `selinux/myapp.pp`, the same artifact the RPM will carry, and then
deletes the temp dir.

The host that runs it must be a RHEL host with `selinux-policy-devel`
installed. `make -C ... -f /usr/share/selinux/devel/Makefile ...` resolves only
on a host that has that path. That path exists only on RHEL, or on a vendor
container image with the same package. That is why `make check` runs offline on
the developer laptop and `compile_and_validate.sh` runs on `rhel-qa`.

A compile failure looks like one of two things:

1. **A syntax error** from `checkmodule`: a wrong type, a bad token, or a rule
   that references a type the module does not own and did not `require`.
   The script exits 1. You fix the `.te` and rerun.
2. **A `neverallow` refusal** from `policy.kern`. This is rare in a module
   build. It fires when a compiled `.mod` references a class that the base
   policy forbids for your domain. The result is the same: exit 1, fix, rerun.
   But the fix is a *review* decision, not a syntax fix. Ask whether the rule
   is too broad.

Neither of these is a CI gate. They are the build step. The CI gates
(`validate_forbidden_patterns.sh`, `validate_version_consistency.sh`) run before
and after the build. One is the PR gate. The other is the
*version-consistency* gate that keeps your `policy_module()` line matching the
`policy_version.txt` line.

## Install and lifecycle

A compiled `module.pp` arrives at a SELinux host and loads into the running
policy store. These are the four commands every operator must know.

| Command | Purpose |
|---------|---------|
| `semodule -i selinux/myapp.pp` | install or replace a module in the running policy store |
| `semodule -l` | list the enabled modules by name. `-lfull` adds the priority, the language extension, and a `disabled` marker |
| `semodule -r myapp` | remove the module from the store |
| `semodule -D` / `semodule -B` | rebuild the store with `dontaudit` rules removed (`-D`) or restored (`-B`) |

`semodule -i` is the *install* path. After it, `restorecon -Rv` is the
*labels* path, and every line in `module.fc` becomes a label on the matching
path. Both must happen. Without `semodule -i`, the policy has no rule for the
new type. Without `restorecon`, the new type has no label on disk. (`-n` is the
dry run: it prints what will change and writes nothing.)

The modules live in the libsemanage store, `/var/lib/selinux/<store>/active/`,
with one directory per module under `active/modules/`, typically
`/var/lib/selinux/targeted/active/`. `semodule -i` writes the compiled kernel
policy beside them as `active/policy.kern`, and that is the path the
repository's generated header records. `semodule -l` reads the store's module
index. `semodule -DB` is not an export: it rebuilds the policy with `dontaudit`
rules removed. The canary stage runs it, so a denial that the policy
deliberately silenced cannot hide during soak. To read a module's compiled form,
extract it: `semodule --extract=myapp --cil` writes CIL.

On a lab host, semodule -i is the action that proves a policy works against an
application. Run the app, show that the AVC log is empty for the expected paths,
and move on. On production, the same action ships as an RPM. Chapter 18
describes how selinux/myapp.pp leaves Git as <app>-selinux and arrives
through the canary. This is why the file never lives in Git: it is built on
RHEL, signed by the RPM pipeline, and promoted from QA to prod. It does not
arrive through git pull.
:::: try Install and inspect on rhel-qa
Nothing here changes state. It only shows what a fresh `myapp` module looks
like on a RHEL host that has the tooling for the next chapter.

```bash



# Verify the tooling exists; if this fails, selinux-policy-devel is missing
$ rpm -q selinux-policy-devel
selinux-policy-devel-38.1.75-2.el9_8.noarch

# Compile the module with the same command compile_and_validate.sh runs
$ cd selinux-pac
$ POLICY_MODULE=myapp SELINUX_DOMAIN=myapp_t \
    bash scripts/compile_and_validate.sh selinux
[INFO] Checking forbidden patterns in selinux/myapp.te
[INFO] Forbidden-pattern checks passed for myapp
[INFO] Static checks on selinux/myapp.te
[INFO] Compiling myapp in selinux via refpolicy Makefile
make -C /tmp/... -f /usr/share/selinux/devel/Makefile myapp.pp
[INFO] Built selinux/myapp.pp
[INFO] Validation passed for myapp (domain myapp_t)

# Install it on this host (or stop — you just saw it compile)
$ sudo semodule -i selinux/myapp.pp

# List what is installed; this is what your playbook reads before deploy
$ semodule -l | grep myapp
myapp
# -lfull prints four columns: priority, name, language extension,
# and the word "disabled" for modules that are present but off
$ semodule -lfull | grep myapp
100 myapp pp

# Clean it up (you are done — it was a lab action)
$ sudo semodule -r myapp
```

On the lab, the build step is the proof. On production, the same `.pp` is the
RPM, and the RPM arrives in production through a signed canary.
:::::

## What you can do now

You know what a policy module is built out of, where each part lives, and how
the module leaves the Git repository. It leaves as `module.pp`, built on RHEL
with `checkmodule`/`semodule_package`, signed with `rpmsign` in
`packaging/publish_internal.sh`, and shipped through AAP.
Chapter 7 covers the types, attributes, and classes that the kernel reads at
every decision. Chapter 8 lets you read every `allow` rule you met in
`myapp.te` out loud.
