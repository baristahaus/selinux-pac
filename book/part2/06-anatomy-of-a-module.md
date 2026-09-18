# Anatomy of a Module

> A SELinux policy module is the only artifact a distribution trusts at boot and a
> distribution ship. It is built from four kinds of files, guarded by one file,
> compiled on a RHEL host, and installed with a single command that reaches the
> running kernel. This chapter opens Part II: every line that follows in this
> chapter, and every rule in Chapter 8, is about those four files and the
> decision they make together.

A *module* is not a running program — it is a policy object. The running
application is a process; the policy that lets it do what it must is
the module. Part IV explains how that policy leaves Git as an RPM.
## The four files that make a module

Each module ships as a small collection of files. Each kind is read by a
different piece of tooling, and each kind has a single responsibility.

| File | Purpose | Who reads it |
|------|---------|--------------|
| `module.te` | Type enforcement — types, attributes, `allow` rules, `type_transition` | `checkmodule` during build; the policy editor and reviewers; Chapter 8 reads every rule |
| `module.fc` | File contexts — what label each path on disk carries | `restorecon` / `matchpathcon` at install time; Chapter 9 follows every line |
| `module.if` | Interfaces — `policy_module`-level contracts for other modules to call | the author (uses `gen_require`); Chapter 8 describes how to call them and when `optional_policy` is the safe choice |
| `module.pp` | Compiled binary package — the CIL the kernel loads | `semodule -i` at runtime; Chapter 19 describes how it arrives in production |

`module.pp` is never authored by hand. It is produced by
`checkmodule` (which turns `.te` into `.mod`) and
`semodule_package` (which wraps `.mod` + `.fc` into `.pp`). The
repository's `selinux/myapp.pp` is also a build artifact — the file the RPM
ships — but it does not live in Git. That is why Chapter 16 guards the
compile step on a RHEL host rather than running it on your laptop.

Every other file in a policy pull request — the `.cil`, the `policy_version.txt`,
the manifest under `config/` — supports one or two of these four files. Each
file has a job and no more.

:::: why Four files, not one
A policy module could, in theory, be all text in a single document. But each
kind is consumed by a different consumer. `.te` is read by a policy language
compiler; `.fc` is consumed by a labeler that walks the filesystem; `.if` is
consumed by a dependent author who wants to borrow a contract; `.pp` is
consumed by the kernel's policy store at boot. Splitting them lets each
consumer work without the other — you can audit `.fc` on an air-gapped host
even if you don't have `checkmodule` installed.
::::

## `policy_module(name, version)` and the single source of truth

The first line of every `module.te` is:

```text
policy_module(myapp, 1.1.3)
```

This line names the module and pins a SemVer. It is the only human-visible
version in the module itself — and, by convention, the only copy. Every
repository with a policy module also carries a sibling called
`policy_version.txt`, and the rule is *one source of truth, never two copies.*

Each module owns its own `policy_version.txt`:

```text
selinux/policy_version.txt              → contains 1.1.3 (for myapp)
selinux/shopapi/policy_version.txt      → contains 1.0.0 (for shopapi)
selinux/payments/policy_version.txt     → contains 1.0.0 (for payments)
```

Each file is a single line: the version string. That string must match the
second token of the `policy_module(...)` line. Two places can drift in two
directions at once; the repository trusts neither: `validate_version_consistency.sh`
fails the CI if they disagree.

```text
validate_version_consistency: myapp OK (1.1.3)
validate_version_consistency: shopapi OK (1.0.0)
validate_version_consistency: payments OK (1.0.0)
validate_version_consistency: all modules OK
```

The same script also checks that `packaging/<module>-selinux.spec` reads
`Version: %{modver}` rather than hard-coding a number — because `rpmbuild`
injects the version from `policy_version.txt` at build time, and a literal
`Version: 1.1.3` in the spec would silently mismatch the compiled package.
The build script that produces all three RPMs (`packaging/build_rpms.sh`)
reads `policy_version.txt` and passes it to `rpmbuild` as `--define "modver
1.1.3"`. If you edit the version, you edit one file — and you rerun the
consistency check before opening the PR.

::::: note Why one source of truth
The RPM build (each `packaging/<module>-selinux.spec`) injects the version from
`policy_version.txt` at build time. If you edit the version, you edit one file
and rerun the consistency check.
:::::

`selinux/myapp.te` is the reference module for the **Order Processor** demo
application — a Flask server plus a small Python backend stub. It ships two
domains (`myapp_t` and `myapp_backend_t`) that share a file tree under
`/opt/myapp` and `/var/lib/myapp`, `/var/log/myapp`, `/run/myapp`. Read it as a
story told in sections.

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

Every module starts with `policy_module(...)` — naming, and matching the
`policy_version.txt` you already checked. Then the types: each `type` declares
*one thing* the module will own in the policy — a process domain, a binary, a
directory tree, a log type, a TCP port. Nothing about permissions yet; you
cannot permit on a type that does not exist, which is why `allow` rules appear
later.

The `files_type(...)` and `corenet_port(...)` calls above each type are
refpolicy *macros* that register a type with the standard file or network
namespace — they let `restorecon` and `semanage port` recognise them without
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
systemd process (the kernel's "first" process). The permissions listed —
`transition`, `dyntransition`, `siginh`, `rlimitinh`, `entrypoint` — are the
ones systemd needs to start a unit as a domain. Every daemon-style module
requires this block; the order matters: the kernel's policy compiler reads the
require before it reads the rules that use it.

### The `type_transition` that starts the service in its own domain

```text
allow init_t myapp_exec_t:file { execute ... entrypoint };
allow init_t myapp_t:process { transition dyntransition siginh rlimitinh };
allow myapp_t myapp_exec_t:file entrypoint;
type_transition init_t myapp_exec_t:process myapp_t;
```

This is the most important section of the module: it is how systemd starts the
application *as `myapp_t`*, rather than as `bin_t` (the generic type that
labels every executable on the system). Without it, systemd would start the
Java/Python/PHP/whatever binary as whatever `bin_t` it carries, and every
`allow ... bin_t:file read;` would be a blast radius.

- `type_transition init_t myapp_exec_t:process myapp_t;` — when `init_t`
  executes anything labeled `myapp_exec_t`, the resulting process is `myapp_t`.
- `allow init_t myapp_t:process { transition ... };` — systemd may perform the
  transition; this is the permission that makes `type_transition` work.
- `allow init_t myapp_exec_t:file { ... entrypoint };` — systemd may read and
  open the entrypoint binary with all the syscalls it actually needs to launch
  it (`execute`, `read`, `open`, `getattr`, `map`, `ioctl`,
  `execute_no_trans`, `entrypoint`).
- `allow myapp_t myapp_exec_t:file entrypoint;` — the launched domain also may
  re-exec itself through the same entrypoint (used when the binary execs back
  into its own code).

The same block for `myapp_backend_t` mirrors this at `/opt/myapp/backend_stub.py`
and `/var/opt/myapp/backend_stub.py`. Every submodule gets its own
`type_transition` — the domains do not share.

### The daemon baseline

```text
files_read_etc_files(myapp_t)
The same block for myapp_backend_t mirrors this at /opt/myapp/backend_stub.py
and /var/opt/myapp/backend_stub.py.
```

These four macros give the domain the minimum each long-running process needs under enforcing: read /etc/, read system configs, poll the kernel, and consume randomness. They apply to each domain separately. The comment above the section is not decoration: review once as a unit; do not widen one AVC at a time via generated PRs — Chapter 15 codifies that rule.

### The remaining sections

After the baseline, the module adds:

- path-traversal `files_search_*` macros for each domain (searching `/var/lib`,
  `/run`, `/usr` — each type only reaches its own label, the search is on a
  generic base type, so every search is a walk past unrelated files)
- the Flask surface: `myapp_t` reads its own library, its own executables,
  manages its own `/var/lib/myapp` and `/var/log/myapp`, binds a TCP port,
  connects to `myapp_backend_port_t`, writes pid files under `/run/myapp`,
  sends syslog, execs shells, reads certificates
- the backend stub: `myapp_backend_t` does the same subset — reads its own
  lib, reads the Flask binaries (so it can call them), binds its own port,
  manages its own pid files, talks over Unix sockets to the Flask domain
- a final `allow myapp_t myapp_t:unix_stream_socket connectto;` — a
  self-socket needed by a small internal component; this is the only line in
  the file that a generator wrote in (the comment above it names the
  generator hash and the refpolicy version it reproduced from).

## The build: `checkmodule`, `semodule_package`, and the `make -f` path

The text and label files become a binary module through `checkmodule` and
`semodule_package` — the refpolicy toolchain — and the repository wraps that
behind a single script.

```bash
POLICY_MODULE=myapp SELINUX_DOMAIN=myapp_t \
  bash scripts/compile_and_validate.sh selinux
```

That script first runs `validate_forbidden_patterns.sh selinux` (no
`shadow_t`, no blanket `bin_t` execute, no wildcards) and then compiles. The
underlying call — inside `scripts/lib/compile_policy.sh` — is:

```text
make -C <temp dir with myapp.te, myapp.fc, myapp.if> \
     -f /usr/share/selinux/devel/Makefile myapp.pp
```

That is `make` with the *refpolicy* `Makefile` shipped with the package
`selinux-policy-devel`. It produces `myapp.pp` from the text. The file is then
shipped into `selinux/myapp.pp` (the same artifact the RPM will carry) and the
temp dir is thrown away.

The host that runs it must be a RHEL box with `selinux-policy-devel`
installed — `make -C ... -f /usr/share/selinux/devel/Makefile ...` resolves
only on a box that has that path, which only exists on RHEL (or a vendor
container image with the same package). That is why `make check` runs offline
on the developer laptop but `compile_and_validate.sh` runs on `rhel-qa`.

A compile failure looks like one of two things:

1. **A syntax error** from `checkmodule` — wrong type, bad token, or a rule
   that references a type the module does not own and did not `require`.
   The script exits 1; you fix the `.te` and rerun.
2. **A `neverallow` refusal** from `policy.kern`. This is rare in a module
   build — it fires when a compiled `.mod` references a class the base policy
   forbids for your domain. The result is the same: exit 1, fix, rerun — but
   the fix is a *review* decision (is the rule too broad?) rather than a
   syntax fix.

Neither of these is a CI gate. They are the build step. The CI gates
(`validate_forbidden_patterns.sh`, `validate_version_consistency.sh`) run
before and after the build — one is the PR gate, the other is the
*version-consistency* gate that keeps your `policy_module()` line matching the
`policy_version.txt` line.

## Install and lifecycle

A compiled `module.pp` arrives at a SELinux host and loads into the running
policy store. There are four commands every operator should know.

| Command | Purpose |
|---------|---------|
`semodule -i` is the *install* path. After it, `restorecon -Rv -n` is the
*labels* path — every line in `module.fc` becomes a label on the matching path.
Both must happen; without `semodule -i` the policy has no rule for the new
type, and without `restorecon` the new type has no label on disk.

Where the modules live: `/var/lib/selinux/<profile>/packages/` — typically
/var/lib/selinux/targeted/packages/. semodule -l reads from the same directory
and shows each installed module's name and enabled status; semodule -DB prints
each module's CIL into that same path for an operator who needs to read the
compiled policy without tools on the box. Each module lives there until it
is removed.

On a lab host, semodule -i is the action that proves a policy works against
an application — run the app, show the AVC log is empty for the expected
paths, move on. On production, the same action ships as an RPM. Chapter 18
describes how selinux/myapp.pp leaves Git as <app>-selinux and arrives
through the canary. This is why the file never lives in Git: built on RHEL,
signed by the RPM pipeline, promoted from QA to prod — not through git pull.
:::: try Install and inspect on rhel-qa
Nothing here changes state — it only shows what a fresh `myapp` module looks
like on a RHEL host that has the tooling for the next chapter.

```bash



# Verify the tooling exists; if this fails, selinux-policy-devel is missing
$ rpm -q selinux-policy-devel
selinux-policy-devel-38.1.75-2.el9_8.noarch

# Compile the module with the same command compile_and_validate.sh runs
$ cd selinux-pac
$ POLICY_MODULE=myapp SELINUX_DOMAIN=myapp_t \
    bash scripts/compile_and_validate.sh selinux
[INFO] Static checks on selinux/myapp.te
[INFO] Compiling myapp in selinux via refpolicy Makefile
make -C /tmp/... -f /usr/share/selinux/devel/Makefile myapp.pp
[INFO] Built selinux/myapp.pp
[INFO] Validation passed for myapp (domain myapp_t)

# Install it on this host (or stop — you just saw it compile)
$ sudo semodule -i selinux/myapp.pp

# List what is installed; this is what your playbook reads before deploy
$ semodule -l | grep myapp
myapp                     Active     397 7748

# Clean it up (you are done — it was a lab action)
$ sudo semodule -r myapp
```

On the lab, the build step is the proof. On production, the same `.pp` is the
RPM, and the RPM arrives in production through a signed canary.
:::::

## What you can do now

You now know what a policy module is built out of, where each part lives, and
how the module leaves the Git repository: as `module.pp`, built on RHEL with
`checkmodule`/`semodule_package`, signed by `rpmbuild`, shipped through AAP.
In Chapter 7 you meet the types, attributes and classes that the kernel reads
at every decision — and Chapter 8 lets you read every `allow` rule you just
met in `myapp.te` out loud.
