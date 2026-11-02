# 100 — RHEL host commands for the lab

The SELinux commands are in [102](102-COMMANDS.md). This guide is everything else you type to run the lab: reaching the VMs, installing packages, running services, keeping the audit log trustworthy, checking ports, checking signed RPMs, and driving Ansible from the Mac.

If you run RHEL servers every day, skim the [command map](#command-map) at the end and go to [101](101-CONCEPTS.md). Nothing here is an SELinux concept, so you can read it before or after 101.

Every step names the machine. Look at the prompt before you type.

| Machine | What it is | What you type there |
|---------|------------|---------------------|
| **Mac** | The Ansible controller. UTM runs the two VMs. No SELinux. | `ssh`, `rsync`, `scp`, `ansible`, `ansible-playbook`, `git` |
| **rhel-qa** | RHEL 9 VM. The practice and developer host: shopapi, Tomcat, the generator, RPM builds. | Almost everything in this guide |
| **rhel-prod** | RHEL 9 VM. No git clone. Policy arrives only as signed RPMs. | `dnf`, `rpm`, `systemctl`, `auditctl`, `curl` |

Two rules from the rest of the docs apply here too. Never run `setenforce`. Never edit `/etc/selinux/config` to get past a problem.

---

## Part 1 — Reach the VMs

### Find the VM's address

**Where.** The VM console window in UTM, logged in as your lab user.

```bash
ip -br addr
hostname
```

**Good sign.** One interface other than `lo` is `UP` with an IPv4 address. That address is `QA_HOST` or `PROD_HOST` in `lab/lab.env`.

**Used in.** `lab/lab.env` (copied from `lab/lab.env.example`). Every script that talks to a VM reads it.

### Name the VM

**Where.** Each VM.

```bash
sudo hostnamectl set-hostname rhel-qa      # rhel-prod on the other VM
hostname
```

**Why.** The talk tracks and the prompts in [302](302-TECHNICAL.md) say `rhel-qa` and `rhel-prod`. The conductor scripts run the same `hostnamectl` line.

### Log in with a key, not a password

**Where.** Mac.

```bash
ls ~/.ssh/id_ed25519.pub || ssh-keygen -t ed25519
ssh-copy-id "$SSH_USER@$QA_HOST"
ssh-copy-id "$SSH_USER@$PROD_HOST"
ssh -o BatchMode=yes "$SSH_USER@$QA_HOST" true && echo key-ok
```

**Why.** `sync_rhel_dev.sh`, `build_rpms_on_dev.sh`, and the 302 conductor run `ssh -o BatchMode=yes`. Batch mode never asks for a password. If the key is not installed, the script fails at its first SSH line.

**Good sign.** `key-ok`, with no password prompt.

### Sudo over SSH, without a terminal

**Where.** Mac, testing each VM.

```bash
ssh "$SSH_USER@$QA_HOST" 'sudo -n true && echo sudo-ok'
```

**Why.** The scripts run `ssh host 'sudo …'` with no terminal attached, and Ansible runs with `become`. Sudo cannot ask for a password in either case. On the two lab VMs, the lab user needs sudo without a password.

If the check prints `sudo: a password is required`, run this on that VM, at its console:

```bash
echo "$USER ALL=(ALL) NOPASSWD: ALL" | sudo tee /etc/sudoers.d/90-selinux-pac-lab
sudo chmod 0440 /etc/sudoers.d/90-selinux-pac-lab
sudo visudo -cf /etc/sudoers.d/90-selinux-pac-lab
```

**Good sign.** `visudo` prints `parsed OK`, and the SSH check prints `sudo-ok`.

**Common mistake.** Doing this on a production server. It is for the two lab VMs only. A real host gets a scoped sudo rule from its owner, or AAP's own privilege escalation.

### Copy files between the Mac and a VM

**Where.** Mac.

```bash
bash lab/sync_rhel_dev.sh                                # rsync this checkout to ~/selinux-pac on rhel-qa
scp "$SSH_USER@$QA_HOST:selinux-pac/selinux/shopapi/shopapi.te" selinux/shopapi/
```

**Why.** `sync_rhel_dev.sh` is `rsync` over SSH. It installs `rsync` on rhel-qa with `dnf` if it is missing. `scp` copies one generated file back for a pull request. `setup_rhel_hosts.sh bootstrap` prints the full `scp` line.

**Common mistake.** Editing on rhel-qa and then running `sync_rhel_dev.sh`. The sync goes from the Mac to the VM and overwrites the VM's copy.

---

## Part 2 — Know the host

### Release and architecture

**Where.** Each VM.

```bash
cat /etc/redhat-release
uname -m
```

**Good sign.** `Red Hat Enterprise Linux release 9.x`. On an Apple Silicon Mac, `uname -m` prints `aarch64`. Package names are the same on `aarch64` and `x86_64`.

### The clock

**Where.** Each VM. Do this whenever the Mac has slept.

```bash
timedatectl status
sudo timedatectl set-ntp true
sudo chronyc tracking
sudo chronyc makestep
```

**Why.** UTM VMs drift when the Mac sleeps. `ausearch -ts recent` means "the last ten minutes by this VM's clock." With a skewed clock it reads the wrong window and prints `<no matches>` while the denial sits in the log. The 302 conductor runs these same lines before it collects denials.

**Good sign.** `System clock synchronized: yes` and `NTP service: active`. `chronyc tracking` shows `Leap status : Normal`.

**Reading an audit timestamp.** An audit line starts `msg=audit(1760000000.123:456)`. The first number is seconds since 1970.

```bash
date -d @1760000000
```

That prints the local time of that record. Compare it with `date` to see whether the clock was the problem.

---

## Part 3 — Packages

### Repositories

**Where.** Each VM.

```bash
sudo dnf repolist
```

**Good sign.** BaseOS and AppStream repositories are listed. If the list is empty, the VM is not registered: `sudo subscription-manager status`, then register it the way your organization does.

**Note.** The JBoss Web Server packages (`jws6-tomcat`, `jws6-tomcat-selinux`) need a JWS entitlement. Without that repository, `demo_bootstrap.sh` falls back to the RHEL `tomcat` package. The customer talk ([301](../demo.md)) covers both.

### Install what the lab needs

**rhel-qa** (the practice host, and the RPM build host for 302):

```bash
sudo dnf install -y git rsync java-17-openjdk-headless maven python3 python3-pyyaml \
  policycoreutils policycoreutils-python-utils setools-console audit selinux-policy-devel
sudo dnf install -y rpm-build rpm-sign createrepo_c      # 302 and 401 only: build, sign, publish
```

**rhel-prod** (no git, no compiler):

```bash
sudo dnf install -y java-17-openjdk-headless python3 python3-pyyaml \
  policycoreutils policycoreutils-python-utils setools-console audit
```

**Why the second rhel-qa line.** `packaging/publish_internal.sh` refuses to publish without `rpmsign`, which comes from `rpm-sign`. Without `createrepo_c` it copies the RPMs but writes no repository metadata, so `dnf` on rhel-prod finds nothing.

**Common mistake.** Installing `policycoreutils` and expecting `semanage`. `semanage` is in `policycoreutils-python-utils`.

### Which package gives which command

| Command | Package |
|---------|---------|
| `getenforce`, `getsebool`, `matchpathcon` | `libselinux-utils` (installed by default) |
| `semodule`, `restorecon`, `setsebool`, `sestatus` | `policycoreutils` |
| `semanage`, `audit2why`, `audit2allow` | `policycoreutils-python-utils` |
| `sesearch`, `seinfo` | `setools-console` |
| `ausearch`, `aureport`, `auditctl` | `audit` |
| `sealert` | `setroubleshoot-server` |
| `/usr/share/selinux/devel/Makefile` | `selinux-policy-devel` |
| `sepolicy-generate`, `sepolgen-ifgen` | `policycoreutils-devel` |
| `rpmbuild` / `rpmsign` / `createrepo_c` | `rpm-build` / `rpm-sign` / `createrepo_c` |

Ask the host instead of trusting a table:

```bash
rpm -qf "$(command -v semanage)"      # which installed package owns this file
dnf provides '*/sesearch'             # which package would supply it
```

### Ask what is installed

**Where.** Either VM.

```bash
rpm -q setools-console selinux-policy-devel           # one line per package, or "is not installed"
rpm -qa 'selinux-policy*'                             # every installed package matching a pattern
rpm -qi shopapi-selinux                               # version, build date, signature
rpm -ql shopapi-selinux                               # the files it installed
rpm -q --scripts shopapi-selinux                      # what it runs on install and removal
```

**Why.** `rpm -q --scripts shopapi-selinux` shows that the package's install step loads `shopapi.pp` with the SELinux RPM macros. That is why the module shows priority 200 in `semodule --list-modules=full` ([102](102-COMMANDS.md#modules)).

### The generator's interface data

**Where.** rhel-qa.

```bash
command -v sepolgen-ifgen || sudo dnf install -y policycoreutils-devel
ls -l /var/lib/sepolgen/interface_info || sudo sepolgen-ifgen
```

**Why.** The generator matches a denial to a Red Hat policy interface using that file. Without it, the generator refuses a raw allow on a Red Hat type and reports `toolchain_required` ([201](201-TOOL-COMMANDS.md)).

**Good sign.** The file exists and is not empty.

---

## Part 4 — Services

shopapi runs as `shopapi.service`. App A and App B share one Tomcat service: `tomcat.service` for the RHEL package, or `jws6-tomcat.service` for JBoss Web Server.

### Read the unit

**Where.** rhel-qa.

```bash
systemctl cat shopapi.service
systemctl list-unit-files 'tomcat*' 'jws*'
```

**Good sign.** The first line of `systemctl cat` is the unit's path. `ExecStart=` is the wrapper `/opt/shopapi/bin/shopapi`. `User=shopapi`. There is no `SELinuxContext=` line. The domain comes from the wrapper's label, as [104](104-HAND-BUILT-MODULE.md) explains.

### State, start, restart

```bash
systemctl status shopapi.service --no-pager
systemctl is-active shopapi.service
sudo systemctl daemon-reload                  # after you edit a unit file
sudo systemctl enable --now shopapi.service   # start now and at boot
sudo systemctl restart shopapi.service
sudo systemctl reset-failed shopapi.service   # clear a "start request repeated too quickly" lockout
```

**Good sign.** `Active: active (running)`. `is-active` prints `active`.

**Why restart matters for SELinux.** A process gets its domain when its program starts. Loading a module that adds the `shopapi_t` transition does nothing to a JVM that is already running. Neither does relabeling the wrapper. Restart the service after either one. Adding or removing the domain on the permissive list ([102](102-COMMANDS.md#permissive-domains)) takes effect at once, with no restart.

### Which domain did systemd start?

```bash
pid=$(systemctl show -p MainPID --value shopapi.service)
ps -o label=,comm= -p "$pid"
```

**Good sign.** A label ending in `shopapi_t:s0`. `unconfined_service_t` means the transition did not happen: the module is not loaded, the wrapper is mislabeled, or the service was not restarted. The vendor check runs this same pair of commands on the Tomcat service.

### Service logs

```bash
journalctl -u shopapi.service -n 20 --no-pager
journalctl -u shopapi.service -f              # follow; Ctrl-C to stop
journalctl -u shopapi.service --since "10 min ago"
```

**Why.** A Java stack trace, a port already in use, or a missing file shows here. `wait_for_endpoints.sh` prints the last 20 lines when a health check fails.

**Common mistake.** Looking for the SELinux denial here. Denials are in the audit log ([Part 5](#part-5--the-audit-log), and `ausearch` in [102](102-COMMANDS.md#audit)).

---

## Part 5 — The audit log

Every SELinux decision in this lab is read from the audit log. A gap in the log looks exactly like a clean soak. These commands tell the two apart.

### Is auditd running and recording?

**Where.** Either VM.

```bash
systemctl is-active auditd
sudo auditctl -s
```

**Good sign.** `active`. In `auditctl -s`, `enabled 1` (or `2`, which means the rules are locked) and `lost 0`.

**Why.** `scripts/check_audit_health.sh` reads these same two fields. The soak fails closed when auditd is not active, `enabled` is `0`, or `lost` has grown since the canary marker. A lost record could have been a denial.

### Restarting auditd

```bash
sudo service auditd restart
```

**Why `service`.** The auditd unit refuses a manual stop, so `systemctl restart auditd` fails. `service auditd restart` is the supported way on RHEL. You rarely need it. `reset_demo_vms.sh` does not stop auditd, and it does not delete or rewrite `/var/log/audit/audit.log`. Neither should you.

### The raw lines

```bash
sudo ls -lZ /var/log/audit/
sudo grep 'avc:  denied' /var/log/audit/audit.log | tail -5
sudo tail -f /var/log/audit/audit.log | grep --line-buffered 'avc:'
```

**Why.** `ausearch` is the right tool ([102](102-COMMANDS.md#audit)). `grep` on the file is the fallback when the clock is skewed, because it ignores time. The 302 conductor does exactly that. There are two spaces after `avc:`.

**Common mistake.** `grep 'avc: denied'` with one space. It matches nothing.

---

## Part 6 — Users, files, and Unix permissions

### The service account

**Where.** rhel-qa (and rhel-prod for 302).

```bash
getent passwd shopapi
id shopapi
```

**Good sign.** One line from `getent` with home `/opt/shopapi` and shell `/sbin/nologin`. [104](104-HAND-BUILT-MODULE.md) prep step P2 creates it with `groupadd --system` and `useradd --system`. `demo_bootstrap.sh` does the same.

**Common mistake.** Mixing up three names. `shopapi` the Unix user, `system_u` the SELinux user, and `shopapi_t` the type are different things.

### Unix permissions come first

```bash
ls -l /var/spool/shopapi
ls -ld /var/spool/shopapi
sudo chown -R shopapi:shopapi /var/spool/shopapi
```

**Why.** The kernel checks Unix permissions before it asks SELinux. A `Permission denied` with no AVC line usually means the Unix check said no, and SELinux was never asked. Fix ownership with `chown` and modes with `chmod`. Labels are the separate column `ls -Z` shows ([102](102-COMMANDS.md#labels)). The customer demo makes App A's out-of-scope file world-readable for this reason: Unix permissions cannot hide the SELinux result.

**Common mistake.** Running `chmod 777` to "fix" an SELinux denial. It changes nothing SELinux checks, and it weakens the Unix check.

---

## Part 7 — Ports and HTTP

| App | Port | URLs |
|-----|------|------|
| App A (Tomcat) | 8080 | `/standard/` |
| App B (Tomcat) | 8090 | `/inherited/data.jsp`, `/inherited/gateway.jsp` |
| shopapi | 8091 | `/health`, `/state`, `/log`, `/feature-spool` (only when a lab step names it) |

### Who is listening?

**Where.** rhel-qa.

```bash
sudo ss -ltnp | grep -E ':(8080|8090|8091)\b'
sudo lsof -iTCP:8091 -sTCP:LISTEN
```

**Good sign.** One `LISTEN` line per port, with `java` as the process. `ss` without `sudo` hides the process name. The customer demo's preflight uses `ss -ltn`, or `lsof` when `ss` is missing.

**Common mistake.** A port with nothing listening. That is a service that failed to start. Read `journalctl` before you look for an SELinux denial.

### Call the apps

```bash
curl -sS http://127.0.0.1:8091/health
curl -s -o /dev/null -w '%{http_code}\n' http://127.0.0.1:8091/state
```

**Good sign.** The health body, then `200`. A `500` from `/feature-spool` while the domain is enforcing is the lab 5 and Act 6 result, not a broken app.

Every lab `curl` goes to `127.0.0.1` on the same VM. The host firewall does not affect these calls.

### Between the VMs: the RPM repository

In 302, rhel-qa builds and signs the RPMs, then the Mac rsyncs `dist/lab-repo` and serves it locally. UTM shared networking keeps the two VMs apart: the bridge members are `PRIVATE`, and macOS `ifconfig` cannot clear that flag. Both VMs can reach the Mac's bridge address (`REPO_HOST`, typically `192.168.64.1`).

**Where.** rhel-prod (to verify).

```bash
# rhel-prod — check that the default route reaches the Mac
ip route show default
curl -sI "http://$REPO_HOST:8765/RPM-GPG-KEY" | head -1
```

**Good sign.** The default route is via `192.168.64.1` (or whatever `ifconfig bridge100` reports on the Mac), and `HTTP/1.0 200 OK` from rhel-prod.

**Note.** Run by hand, `serve_lab_repo.sh` stays in the foreground until Ctrl-C, so start it in its own terminal. The 302 conductor (`demo_e2e_mac.sh`) starts it in the background with its log in `/tmp/selinux-pac-repo.log` and runs the `curl` check from rhel-prod for you.

---

## Part 8 — Signed RPMs

Production never gets a git clone. It gets two RPMs, `selinux-policy-ops` and `<app>-selinux`, from a repository with `gpgcheck=1`. [302](302-TECHNICAL.md) part 6 and [401](../shipping.md) run these steps through scripts and Ansible. The commands below let you check each one by hand.

### Check a package file before you serve it

**Where.** rhel-qa, after `packaging/publish_internal.sh`.

```bash
cd ~/selinux-pac
sudo rpm --import dist/lab-repo/RPM-GPG-KEY
rpm -K dist/lab-repo/*.rpm
rpm -qip dist/lab-repo/shopapi-selinux-*.rpm
rpm -qp --requires dist/lab-repo/shopapi-selinux-*.rpm
```

**Good sign.** `rpm -K` prints `digests signatures OK` for each file. `rpm -qip` shows a `Signature` line. `--requires` lists `selinux-policy-ops`.

**Common mistake.** Reading a `rpm -K` failure as a corrupt file. Usually the public key is not imported on that host yet, or `publish_internal.sh` ran with `SELINUX_ALLOW_UNSIGNED=1`.

### The repository and key on rhel-prod

**Where.** rhel-prod, after the canary playbook added the repository.

```bash
sudo dnf repolist
cat /etc/yum.repos.d/selinux-pac.repo
rpm -q gpg-pubkey --qf '%{NAME}-%{VERSION}-%{RELEASE}  %{SUMMARY}\n'
dnf info shopapi-selinux
```

**Good sign.** `selinux-pac` is listed. The repo file has `gpgcheck=1`. One `gpg-pubkey` line names `selinux-pac-lab`. `dnf info` shows the version from `selinux/shopapi/policy_version.txt`.

**Why.** The canary role imports the key (`rpm_key`), writes the repo file (`yum_repository`), and installs with `dnf`. These four commands show that each step happened. There is no `rpm -Uvh` of a copied file.

### Versions and rollback

```bash
dnf list --showduplicates shopapi-selinux
rpm -q shopapi-selinux
```

**Why.** `emergency_rollback.yml` can run `dnf downgrade -y shopapi-selinux-<version>` when `rollback_dnf_version` is set. The first command shows which versions the repository still has. Rollback always puts the domain back on the permissive list first ([401](../shipping.md)).

---

## Part 9 — Ansible from the Mac

**Where.** Mac, repo root.

```bash
ansible --version                                          # pip install ansible if missing
ansible-galaxy collection install -r ansible/requirements.yml
bash lab/setup_rhel_hosts.sh ping                      # ansible -m ping to both VMs
ansible -i ansible/inventory.dev.yml all -b -m shell -a 'getenforce'
ansible-playbook -i ansible/inventory.production.yml ansible/deploy_canary.yml --list-tasks
```

**Good sign.** `SUCCESS` and `"ping": "pong"` for each VM. `Enforcing` from the ad hoc `getenforce`. `--list-tasks` prints the task names and changes nothing.

**Why.** `requirements.yml` pins `community.general` and `ansible.posix`. The roles use `selinux_permissive` and `seboolean` from them. `-b` is become (sudo), which is why [Part 1](#sudo-over-ssh-without-a-terminal) matters. `--limit canary` and `-e change_ticket=…` are the options the 302 and 401 commands add.

**Common mistake.** Running a playbook against `inventory.production.yml` when you meant `inventory.dev.yml`. Production keeps `soak_min_days: 7`. Read the `-i` argument before you press Enter.

---

## Command map

Every command you type in the labs and talks, and where it is explained.

| Command | Machine | Explained in | Used by |
|---------|---------|--------------|---------|
| `ip -br addr`, `hostnamectl`, `hostname` | VMs | [100 Part 1](#part-1--reach-the-vms) | `lab.env`, 302 conductor |
| `ssh-keygen`, `ssh-copy-id`, `ssh`, `scp`, `rsync` | Mac | [100 Part 1](#part-1--reach-the-vms) | `sync_rhel_dev.sh`, `build_rpms_on_dev.sh`, 302 |
| `sudo -n`, `visudo -cf` | VMs | [100 Part 1](#sudo-over-ssh-without-a-terminal) | Every SSH `sudo`, Ansible `become` |
| `cat /etc/redhat-release`, `uname -m` | VMs | [100 Part 2](#part-2--know-the-host) | `demo_bootstrap.sh` checks for Linux |
| `timedatectl`, `chronyc`, `date -d @` | VMs | [100 Part 2](#the-clock) | 302 conductor, any `ausearch -ts` |
| `dnf repolist`, `dnf install`, `dnf provides`, `dnf info`, `dnf list --showduplicates`, `dnf downgrade` | VMs | [100 Part 3](#part-3--packages), [Part 8](#part-8--signed-rpms) | `demo_bootstrap.sh`, canary, rollback |
| `rpm -q`, `-qa`, `-qi`, `-ql`, `-qf`, `--scripts`, `-qip`, `-qp --requires`, `-K`, `--import` | VMs | [100 Part 3](#ask-what-is-installed), [Part 8](#part-8--signed-rpms) | Vendor check, `doctor`, 302 part 6 |
| `sepolgen-ifgen` | rhel-qa | [100 Part 3](#the-generators-interface-data) | Generator interface matching |
| `systemctl cat`, `status`, `is-active`, `show -p MainPID`, `daemon-reload`, `enable --now`, `restart`, `reset-failed` | VMs | [100 Part 4](#part-4--services) | `demo_bootstrap.sh`, canary, enforce, vendor check |
| `journalctl -u` | VMs | [100 Part 4](#service-logs) | `wait_for_endpoints.sh` |
| `auditctl -s`, `service auditd restart`, `grep 'avc:  denied'` | VMs | [100 Part 5](#part-5--the-audit-log) | `check_audit_health.sh`, soak gate, 302 |
| `getent`, `id`, `useradd`, `groupadd`, `chown`, `ls -l` | VMs | [100 Part 6](#part-6--users-files-and-unix-permissions) | [104](104-HAND-BUILT-MODULE.md) prep, `demo_bootstrap.sh` |
| `ss -ltnp`, `lsof -iTCP`, `curl` | VMs | [100 Part 7](#part-7--ports-and-http) | 301 preflight, `wait_for_endpoints.sh`, every lab |
| `ip route`, `curl` (cross-VM) | rhel-prod | [100 Part 7](#between-the-vms-the-rpm-repository) | 302 part 6 repository (Mac serves the repo) |
| `rpmbuild`, `rpmsign`, `createrepo_c` | rhel-qa | [100 Part 3](#install-what-the-lab-needs) | `packaging/build_rpms.sh`, `publish_internal.sh` |
| `ansible`, `ansible-galaxy`, `ansible-playbook` | Mac | [100 Part 9](#part-9--ansible-from-the-mac) | `setup_rhel_hosts.sh`, 302, 401 |
| `getenforce`, `sestatus` | VMs | [102 Mode](102-COMMANDS.md#mode) | Every lab and talk |
| `ls -Z`, `ps -eZ`, `id -Z`, `matchpathcon`, `restorecon`, `chcon`, `semanage fcontext` | VMs | [102 Labels](102-COMMANDS.md#labels) | 104, 301 Acts 2, 3, 6, canary |
| `semanage port` | VMs | [102 Ports](102-COMMANDS.md#ports) | 104, 301 Acts 2 and 3, canary |
| `getsebool`, `semanage boolean -l`, `setsebool -P` | VMs | [102 Booleans](102-COMMANDS.md#booleans) | 301 Act 2, canary |
| `semanage permissive` | VMs | [102 Permissive domains](102-COMMANDS.md#permissive-domains) | 104, canary, enforce, rollback |
| `semodule`, `make -f /usr/share/selinux/devel/Makefile`, `sepolicy-generate` | VMs | [102 Modules](102-COMMANDS.md#modules) | 104, compile scripts, RPM install |
| `seinfo`, `sesearch` | VMs | [102 Querying policy](102-COMMANDS.md#querying-policy) | Vendor check, CI gate, soak |
| `ausearch`, `audit2why`, `audit2allow`, `aureport`, `sealert` | VMs | [102 Audit](102-COMMANDS.md#audit) | 104, generator, soak monitor |

Next: [101 — SELinux concepts](101-CONCEPTS.md).
