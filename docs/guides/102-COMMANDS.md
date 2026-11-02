# 102 — SELinux commands

Each entry answers one question. The words are in [101](101-CONCEPTS.md). The files these commands read and write are in [103](103-CONFIG-FILES.md). None of these commands is a repo script. The RHEL host commands around them (`dnf`, `rpm`, `systemctl`, `journalctl`, `auditctl`, `ss`, `firewall-cmd`, Ansible) are in [100](100-RHEL-HOST-COMMANDS.md).

A line of output that has not been captured on rhel-qa is listed in [LIVE_CHECKS.md](LIVE_CHECKS.md) with the command to run. Types named below are the ones [`selinux/shopapi/shopapi.fc`](../../selinux/shopapi/shopapi.fc) and the c9s policy assign, not a pasted terminal transcript.

`ls -Z` on a directory lists the files inside it. `ls -dZ` prints the directory's own label.

---

## Mode

### getenforce

**Answers.** Is the whole machine Enforcing, Permissive, or Disabled?

**Reads or writes.** Reads the active mode. Does not write a file.

**Example.** The lab requires the one word `Enforcing`. Capture: [LIVE_CHECKS.md](LIVE_CHECKS.md).

**Used in.** [104](104-HAND-BUILT-MODULE.md) lab 0. Customer talk Act 0. `ansible/enforce_production.yml` checks the host is still Enforcing after the domain leaves the log-only list.

**Common mistake.** Reading this as the mode of one domain. A log-only domain does not change this word.

### sestatus

**Answers.** The same mode, plus the loaded policy name and whether the policy is targeted.

**Reads or writes.** Reads `/etc/selinux/config` for the configured mode and the active kernel state. Does not write.

**Example.** Capture: [LIVE_CHECKS.md](LIVE_CHECKS.md). The policy name on this project is `targeted`.

**Used in.** The cheat sheet that used to sit at the bottom of the old lab. Not a playbook step.

**Common mistake.** Treating a difference between "Current mode" and "Mode from config file" as a domain setting. That difference means the running mode was changed for this boot only.

### setenforce

**Answers.** How someone would switch the whole machine for this boot. This project never runs it.

**Reads or writes.** Writes the kernel mode until reboot. It does not edit `/etc/selinux/config`.

**Example.** There is no example output, because the command is not used. `setenforce 0` would make every domain log-only. `setenforce 1` would turn the whole machine back to Enforcing.

**Used in.** Nowhere in the labs, the demos, or the playbooks.

**Common mistake.** Running `setenforce 0` to let one app start. Put that one domain on the permissive list instead.

---

## Labels

### ls -Z and ls -dZ

**Answers.** What label is stored on a file (`ls -Z file`) or on a directory itself (`ls -dZ directory`)?

**Reads or writes.** Reads the security context on the inode. Does not write.

**Example.** `ls -Z /opt/shopapi/bin/shopapi` is the wrapper. The third field in `shopapi.fc` is `shopapi_exec_t`. `ls -Z /opt/shopapi` lists the children. `ls -dZ /opt/shopapi` is the directory. Capture: [LIVE_CHECKS.md](LIVE_CHECKS.md).

**Used in.** [104](104-HAND-BUILT-MODULE.md) prep and lab 0. `scripts/verify_file_contexts.sh` compares the same fact to the file-context files.

**Common mistake.** Using `ls -Z` on a directory and reading the first line as that directory's label. That line is a child. Lowercase `-z` is a different flag.

### ps -eZ

**Answers.** What domain is each process in?

**Reads or writes.** Reads process labels from the kernel. Does not write a file.

**Example.** The shopapi Java process type is `shopapi_t`. Capture, including `ps -o label,args -C java`: [LIVE_CHECKS.md](LIVE_CHECKS.md).

**Used in.** [104](104-HAND-BUILT-MODULE.md) lab 0. Canary expects the service process to be the app domain, not `init_t`.

**Common mistake.** Starting Java from the SSH shell and reading `unconfined_t` as the service domain.

### id -Z

**Answers.** What label is on this login?

**Reads or writes.** Reads the shell's context. Does not write.

**Example.** An administrator SSH session starts with `unconfined_u` and `unconfined_r`. Capture: [LIVE_CHECKS.md](LIVE_CHECKS.md).

**Used in.** Not a lab step. It tells you which lines of `ps -eZ` are you.

**Common mistake.** Looking for `shopapi_t` here. This command prints your shell, not the service.

### matchpathcon

**Answers.** What label should this path wear, according to the file-context files on disk?

**Reads or writes.** Reads the file-context files. It does not open the file, and it does not write a label. It answers for a path that is not on disk. `matchpathcon /run/shopapi/no-such-file` is the form to use. Do not delete `/run/shopapi` to ask the question.

**Example.** After the shopapi module is loaded, the type for `/opt/shopapi/bin/shopapi` is `shopapi_exec_t`, for the jar `shopapi_lib_t`, for `/var/lib/shopapi` `shopapi_var_lib_t`, for `/var/log/shopapi` `shopapi_log_t`, for `/run/shopapi/no-such-file` `shopapi_var_run_t`. Those types are the lines in `shopapi.fc`. Capture: [LIVE_CHECKS.md](LIVE_CHECKS.md).

**Used in.** [104](104-HAND-BUILT-MODULE.md) prep, next to `ls -dZ`, before `restorecon`.

**Common mistake.** Treating its answer as the label stored on the inode. That is `ls -Z` or `ls -dZ`. A gap between the two is why `restorecon` exists.

### restorecon -Rvn

**Answers.** Repaint file labels from the file-context files (`-R` walks directories, `-v` prints changes, `-n` prints without writing).

**Reads or writes.** Reads the file-context files. Without `-n`, writes the label on each inode that differs. File contexts are files on disk. They are not part of the kernel policy image.

**Example.** A `Relabeled` line names the old type and the new type. Capture: [LIVE_CHECKS.md](LIVE_CHECKS.md). Look first with `-n`.

**Used in.** [104](104-HAND-BUILT-MODULE.md) prep and lab 6 (`/var/spool/shopapi`). Canary and enforce run `restorecon -Rv` on the manifest paths. Customer talk Act 3 and Act 6.

**Common mistake.** Skipping it after a module install. The allow names `shopapi_log_t` while the file is still `var_log_t`. Also, `restorecon` cannot label a directory that does not exist yet.

### chcon

**Answers.** How to stick a label on one inode by hand.

**Reads or writes.** Writes that inode only. The next `restorecon` replaces it from the file-context files.

**Example.** Do not use it for shopapi. The live copy-versus-move check uses it once on a scratch file, then `cp` and `mv`, in [LIVE_CHECKS.md](LIVE_CHECKS.md).

**Used in.** That live check only. No playbook. A policy pull request must not add `chcon`.

**Common mistake.** Using `chcon` as the permanent fix. The label dies at the next relabel. Add a file-context line, then `restorecon`.

### semanage fcontext

**Answers.** Add (`-a`), delete (`-d`), or list (`-l`) a local file-context line. `-C` lists only local customizations. `-l -C` is the local list.

**Reads or writes.** Writes `file_contexts.local` under the active policy store. Does not relabel existing files. `restorecon` does that.

**Example.** App B:

```bash
sudo semanage fcontext -a -t tomcat_var_lib_t '/opt/appdata(/.*)?'
sudo semanage fcontext -l -C
sudo restorecon -Rvn /opt/appdata
```

`(/.*)?` is the directory and everything under it. Capture of `-l -C`: [LIVE_CHECKS.md](LIVE_CHECKS.md).

**Used in.** Customer talk Act 2. `lab/reset_demo_vms.sh` deletes that local line between rehearsals (`-d`).

**Common mistake.** Adding the line and not running `restorecon`. The file on disk keeps the old type.

---

## Ports

### semanage port

**Answers.** List (`-l`), add (`-a`), modify (`-m`), or delete (`-d`) the type on a port.

**Reads or writes.** Writes the port records in the active policy store. `-l` only reads.

**Example.** Shopapi, after the type `shopapi_port_t` exists:

```bash
sudo semanage port -l | grep 8091
sudo semanage port -a -t shopapi_port_t -p tcp 8091
```

If `-a` says the port is defined, `-m` changes the type. App B uses `-a -t http_port_t -p tcp 8090`. Capture: [LIVE_CHECKS.md](LIVE_CHECKS.md).

**Used in.** [104](104-HAND-BUILT-MODULE.md) prep. Canary runs `semanage port -l`, then `-a` when the port is absent. Customer talk Act 2 (8090) and Act 3 (8091).

**Common mistake.** Loading the module and assuming 8091 is already `shopapi_port_t`. The `.pp` creates the type. It does not attach the type to the number.

---

## Booleans

### getsebool -a

**Answers.** Which on/off switches exist, and whether each is on.

**Reads or writes.** Reads the active booleans. Does not write. Without `-a`, one name.

**Example.** Capture: [LIVE_CHECKS.md](LIVE_CHECKS.md). RHEL's `tomcat` module has no `tomcat_can_network_connect` ([`tomcat.te` on c9s](https://github.com/fedora-selinux/selinux-policy/blob/c9s/policy/modules/contrib/tomcat.te)).

**Used in.** Customer talk Act 2, before any `setsebool`. The generator's boolean hint for `httpd_t` is `httpd_can_network_connect`. Never set that boolean for Tomcat.

**Common mistake.** Setting a boolean `audit2why` invented and `getsebool` does not list.

### semanage boolean -l

**Answers.** The same switches, plus the persistent value.

**Reads or writes.** Reads the boolean records. Does not write. `semanage boolean -m` would write. This project lists. It does not modify booleans with `semanage`.

**Example.** Capture: [LIVE_CHECKS.md](LIVE_CHECKS.md).

**Used in.** Reading the persistent value when `getsebool` and the on-disk value might differ.

**Common mistake.** Using this list as permission to turn a boolean on for a domain the boolean does not name.

### setsebool -P

**Answers.** Turn a boolean on or off and keep it across reboot. `-P` is persistent.

**Reads or writes.** Writes the boolean in the active store.

**Example.** Only when `audit2why` names a boolean and `getsebool` lists it:

```bash
sudo setsebool -P httpd_can_network_connect on
```

That boolean is for `httpd_t`. Shopapi's missing allows are new lines in `shopapi.te`, because no vendor module ships `shopapi_t`.

**Used in.** Customer talk Act 2 when a boolean is real. `ansible.posix.seboolean` in the canary role is this command.

**Common mistake.** A permanent allow in the `.te` that duplicates a boolean the vendor module already has. Or `setsebool` without `-P`, which dies at reboot.

---

## Permissive domains

### semanage permissive

**Answers.** Add (`-a`), list (`-l`), or delete (`-d`) one domain on the log-only list. The machine stays Enforcing.

**Reads or writes.** Writes a small permissive module in the policy store. `-a` and `-d` print nothing on success. An empty `-l` means no domain is on the list.

**Example.** Together with `getenforce`:

```bash
getenforce
sudo semanage permissive -a shopapi_t
sudo semanage permissive -l
sudo semanage permissive -d shopapi_t
```

**Used in.** [104](104-HAND-BUILT-MODULE.md) prep (`-a`), lab 5 (`-d` then `-l`). Canary uses `community.general.selinux_permissive` state `present`. Enforce and rollback use `absent` or `present`. `lab/reset_demo_vms.sh` clears the demo domain.

**Common mistake.** `setenforce 0` instead of `-a` on one type. Or reading `-l` output `shopapi_t` as "`getenforce` is Permissive."

---

## Modules

### semodule -l

**Answers.** Which module names are loaded? Needs root.

**Reads or writes.** Reads the module store. Does not write.

**Example.** A line containing `shopapi`, and `permissive_shopapi_t` while that domain is log-only. Capture: [LIVE_CHECKS.md](LIVE_CHECKS.md).

**Used in.** [104](104-HAND-BUILT-MODULE.md) after install. Vendor check before generate (`semodule -l` looking for `apache`).

**Common mistake.** A missing name meaning the types were never declared. The seed can be loaded and still have almost no allows.

### semodule --list-modules=full

**Answers.** The same modules, with priority and language.

**Reads or writes.** Reads the module store.

**Example.** Priorities you should see on a stock host: 100 for every module from `selinux-policy-targeted`, 200 for an RPM module, 400 for a module installed with `semodule -i` and for `permissive_<type>`. Capture: [LIVE_CHECKS.md](LIVE_CHECKS.md).

**Used in.** Confirming a hand install did not silently sit on top of an RPM module of the same name. See [103](103-CONFIG-FILES.md).

**Common mistake.** `semodule -l` alone, which hides the priority.

### semodule -i

**Answers.** Install or replace a `.pp` at priority 400 unless `-X` says otherwise.

**Reads or writes.** Writes the module store and rebuilds the active policy. Prints nothing on success. Does not relabel files and does not label a port.

**Example.** On the practice host, after `make` produces `shopapi.pp`:

```bash
sudo semodule -i shopapi.pp
```

**Used in.** [104](104-HAND-BUILT-MODULE.md) prep, lab 3, and lab 6. The canary installs the RPM when `selinux_ops_from_package` is true. It runs `semodule -i` only when it was given a loose `.pp` instead. Production day 0 is the RPM.

**Common mistake.** Treating this as the production install. A hand `-i` at 400 overrides an RPM module of the same name at 200, and the next RPM update does not remove the 400 copy.

### semodule -r

**Answers.** Remove a module.

**Reads or writes.** Writes the module store.

**Example.** `sudo semodule -r shopapi` removes the shopapi module. Capture of the following `-l`: [LIVE_CHECKS.md](LIVE_CHECKS.md).

**Used in.** Demo reset unloads leftover shopapi modules.

**Common mistake.** Removing the module and expecting file labels to revert. Labels on disk stay until something else changes them.

### semodule -X

**Answers.** Choose the priority for the install or the removal.

**Reads or writes.** Selects which priority in the store the rest of the `semodule` command uses.

**Example.** `sudo semodule -X 200 -r shopapi` would target the RPM priority. This project does not use `-X` in the labs. The default install priority is 400.

**Used in.** The priority gotcha in [103](103-CONFIG-FILES.md). Not a demo step.

**Common mistake.** Installing at 400 and then removing only priority 200. The 400 module remains and still wins.

### semodule -DB

**Answers.** Rebuild the policy with dontaudit rules disabled, so hidden denials show up in the log.

**Reads or writes.** Rewrites the active policy. The change is host-wide.

**Used in.** Canary, once, when the soak starts. Not in the 104 labs.

**Example.** No output on success. After it, denials that were dontaudit'd become AVC lines. Capture is the later `ausearch`, in [LIVE_CHECKS.md](LIVE_CHECKS.md).

**Common mistake.** Leaving `-DB` on after enforce. Enforce and rollback put dontaudit back with `-B`, unless another app still has a soak marker.

### semodule -B

**Answers.** Rebuild the policy with dontaudit rules restored.

**Reads or writes.** Rewrites the active policy.

**Example.** No output on success.

**Used in.** `scripts/semodule_restore_dontaudit.sh`, called from enforce and rollback. `ansible/reset_host_state.yml`.

**Common mistake.** Running `-B` while another app is still soaking. That app's hidden denials disappear too. The script skips `-B` when another marker is present.

### semodule -R

**Answers.** Reload the policy. Flushes the AVC cache.

**Reads or writes.** Reloads. Does not install a new module.

**Example.** After a reload, one more request can log a denial the cache had swallowed. The curl pair is in [LIVE_CHECKS.md](LIVE_CHECKS.md).

**Used in.** That live check. A second identical curl does not create a second AVC until a reload.

**Common mistake.** Counting AVC lines as if every request wrote one.

### make -f /usr/share/selinux/devel/Makefile

**Answers.** Compile a `.te` and a `.fc` in the current directory into a `.pp`.

**Reads or writes.** Reads those two files and the headers under `/usr/share/selinux/devel/include`. Writes `name.pp` in the current directory. The package `selinux-policy-devel` supplies the Makefile. A Mac does not have it.

**Example.** From a directory that contains only the module you are building:

```bash
make -f /usr/share/selinux/devel/Makefile shopapi.pp
```

A good run prints `Compiling targeted shopapi module` and `Creating targeted shopapi.pp policy package`.

**Used in.** [104](104-HAND-BUILT-MODULE.md). `scripts/lib/compile_policy.sh` runs the same Makefile inside a work directory. `scripts/compile_and_validate.sh` runs the forbidden-pattern check first, then that compile.

**Common mistake.** Running `make` with no `-f`. The repo Makefile is not the policy compiler.

### sepolicy generate

**Answers.** Write a starter module from a Red Hat template. The command on disk is `sepolicy-generate`, from `policycoreutils-devel`.

**Reads or writes.** Writes `.te`, `.fc`, and `.if` in the current directory. The template `-t unconfined_t` is unconfined. It is not the shopapi seed.

**Example.**

```bash
sepolicy-generate -a payments_t -t unconfined_t
```

**Used in.** `scripts/scaffold_sepolicy_module.sh` for a new module name. It will not replace a `.te` that already exists. Shopapi's seed is already in git. Do not delete it to force a new one.

**Common mistake.** Treating the generated file as the finished shopapi policy. Allows still come from AVC lines.

---

## Querying policy

### seinfo -t -x

**Answers.** Is this type declared, and which attributes does it have?

**Reads or writes.** Reads the active policy (`-x` expands attributes). The binary is `setools-console`.

**Example.** `seinfo -t shopapi_t -x` after the module is loaded. Capture: [LIVE_CHECKS.md](LIVE_CHECKS.md). `tomcat_t` carries `unconfined_domain` on c9s. `seinfo -t bin_t -x` lists `java_exec_t` among the aliases of `bin_t`. That is why the JVM under `/usr/lib/jvm` is `bin_t` on RHEL 9, and why `java_exec()` compiles to execute on `bin_t`.

**Used in.** `scripts/validate_policy_semantics.sh` diffs attributes against a control domain.

**Common mistake.** `seinfo` without a policy loaded in this shell's store, and reading an empty answer as "the type is not in the `.te`."

### seinfo --permissive

**Answers.** Which domains are permissive in the binary policy?

**Reads or writes.** Reads the active policy.

**Example.** Capture: [LIVE_CHECKS.md](LIVE_CHECKS.md). A domain added with `semanage permissive -a` shows up here.

**Used in.** The compiled-policy gate also reads the module CIL, because `seinfo --permissive` can stay empty when the permissive bit lives only in the module package.

**Common mistake.** An empty list meaning the domain is enforcing, when the permissive module failed to load.

### sesearch -A -s -t -c -p

**Answers.** Which allow rules exist for this source, target, class, and permission? `-A` is `--allow`.

**Reads or writes.** Reads the active policy. Does not write.

**Example.**

```bash
sesearch -A -s shopapi_t -t shopapi_log_t -c file -p write
```

**Used in.** `cli/soak_net_new.py` runs `sesearch --allow -s DOMAIN` against the policy file. The soak gate fails closed when `sesearch` is missing or the policy file cannot be read. It does not report a clean window.

**Common mistake.** `--direct` on setools 4.4.4. That flag is not in this version. Dropping it without a control domain flags base rules every domain has. The gate compares to a types-only control domain.

### sesearch --dontaudit

**Answers.** Which dontaudit rules hide a denial?

**Reads or writes.** Reads the active policy.

**Example.** `sesearch --dontaudit -s shopapi_t`. Capture: [LIVE_CHECKS.md](LIVE_CHECKS.md).

**Used in.** The compiled-policy gate, with `-ds` so inherited `dontaudit domain` rules are not treated as a bug in the app module.

**Common mistake.** A clean `ausearch` after `-DB` was never run, and calling the soak clean. `-DB` is what makes those hidden lines visible.

---

## Audit

### ausearch -m avc

**Answers.** Which AVC lines are in the audit log since a start time?

**Reads or writes.** Reads `/var/log/audit/audit.log` and rotated logs. Needs root. Does not write the log.

**Time.** `-ts recent` is the last ten minutes. `-ts today` and `-ts boot` are keywords. A clock time is two arguments, the date and the time, for example `-ts 10/08/2026 09:00:00`. One argument that contains a space is rejected with `Invalid start time`. The date order follows the locale. Do not pass an epoch to `-ts`. The monitor keeps a record when `msg=audit(EPOCH.` is at or after the marker epoch.

**Other flags.** `--subject shopapi_t` keeps that source type. `--format raw` is the line the generator reads. `--input-logs` is required when stdin is not a terminal, because `ausearch` reads stdin in that case instead of the audit log. `--checkpoint file` prints only events that were not printed by the previous search that used the same file. [104](104-HAND-BUILT-MODULE.md) uses it in labs 2, 4, and 5.

**Example.**

```bash
sudo ausearch -m avc -ts recent --subject shopapi_t
```

Capture: [LIVE_CHECKS.md](LIVE_CHECKS.md).

**Used in.** [104](104-HAND-BUILT-MODULE.md) labs 2, 4, and 5. `scripts/lib/avc_query.sh` and `scripts/monitor_avc.sh`. Customer talk Act 6. Prod soak exports the spool denial.

**Common mistake.** `2>/dev/null` around a bad `-ts`. The search fails, the count stays 0, and the soak looks clean. Any ausearch error other than `<no matches>` fails closed.

### audit2why

**Answers.** A shorter hint for the same lines: which allow or boolean would have permitted them.

**Reads or writes.** Reads the AVC text on stdin and the active policy. Does not install a rule.

**Example.**

```bash
sudo ausearch -m avc -ts recent --subject shopapi_t | audit2why
```

**Used in.** [104](104-HAND-BUILT-MODULE.md) lab 2. Customer talk Act 2, to see whether a boolean is named.

**Common mistake.** Leaving out `--subject` or `grep`. `tail` then keeps someone else's denial, often a leftover `myapp` line with `unlabeled_t`.

### audit2allow -a

**Answers.** A raw allow for every denial still in the log. `-a` reads the log. This project runs it only to look. It does not pipe the output into `semodule`.

**Reads or writes.** Reads the audit log. Writes nothing unless you redirect the output yourself.

**Example.** `sudo audit2allow -a` prints allow lines. Do not install them. They include startup noise and the wrong class.

**Used in.** Nowhere in the labs, the demos, or the playbooks. The generator classifies the same log and refuses wildcards.

**Common mistake.** `audit2allow -a -M name` followed by `semodule -i`. That is how a soak denial becomes a permanent allow on the production host.

### aureport -a

**Answers.** `aureport -a` lists AVC events. `aureport -a --summary` counts them.

**Reads or writes.** Reads the audit log. Does not write.

**Example.** `sudo aureport -a` lists the events. `sudo aureport -a --summary` prints the count. Capture: [LIVE_CHECKS.md](LIVE_CHECKS.md).

**Used in.** A quick look before `ausearch`. Not a gate. The soak gate counts records by epoch, not this summary.

**Common mistake.** A zero from `aureport` while `ausearch` was pointed at the wrong start time. Read the lines.

### sealert

**Answers.** A plain-language suggestion for an AVC: a boolean, a relabel, or a local policy module.

**Reads or writes.** Reads the audit log. `sealert -l "*"` lists stored alerts. `sealert -a` reads a log file you name. It does not install a module unless you run the `semodule -i` line it prints.

**Example.**

```bash
sudo sealert -l "*"
sudo sealert -a /var/log/audit/audit.log
```

The package is `setroubleshoot-server`.

**Used in.** Not by this tool. The deck's "old way" slide.

**Common mistake.** Running its `audit2allow -M` suggestion, then `semodule -i`, on a production host. That is the step this tool replaces.

---

Further reading on the practice host: `man selinux`, `man semodule`, `man restorecon`, `man ausearch`. The RHEL 9 book is [Using SELinux](https://access.redhat.com/documentation/en-us/red_hat_enterprise_linux/9/html/using_selinux/index).

Next: [103 — config files](103-CONFIG-FILES.md).
