# 104 — A module built by hand

One app, shopapi, on rhel-qa. Every step is a command from [102](102-COMMANDS.md). No repo script. The script that does the same work is [202](202-TOOL-LAB.md), and each of those steps names the numbers it replaces.

Production day 0 installs a signed RPM. The `semodule -i` in this lab is how you see a module take effect on the practice host. Do not copy that habit onto prod. Do not run `setenforce`. Do not pipe `audit2allow` into `semodule`.

Before the first allow, curl only the URL the lab names. `/feature-spool` is lab 5.

---

## Concepts

Read [101](101-CONCEPTS.md) before this prep. The lab uses four of those ideas:

- `getenforce` stays `Enforcing`. Shopapi can be log-only by itself.
- The wrapper file is `shopapi_exec_t`. The running process is `shopapi_t`. `ls -Z` on a directory lists children. `ls -dZ` is the directory.
- An AVC line names the source type, the target type, the class, and the permission. `permissive=1` means the action still happened.
- The seed in `selinux/shopapi/shopapi.te` declares types and `init_daemon_domain(shopapi_t, shopapi_exec_t)`. It has almost no `allow` lines. The file-context lines are in `shopapi.fc`, which is a file on disk, not part of the kernel.

`/usr/bin/java` is a symlink. The JVM it points to under `/usr/lib/jvm` is `bin_t`. On RHEL 9 `java_exec_t` is another name for `bin_t`, an alias in the base `corecommands` module ([`corecommands.te` on c9s](https://github.com/fedora-selinux/selinux-policy/blob/c9s/policy/modules/kernel/corecommands.te)), so there is no narrower type for the JVM. Do not copy a JDK under `/opt/shopapi`. The unit has no `SELinuxContext=` line.

---

## Prep

SSH to rhel-qa. Repo root is the directory with `Makefile` and `scripts/`.

```bash
cd ~/selinux-pac
```

**P1.** Install the compiler, Java, and Maven.

```bash
sudo dnf install -y maven java-17-openjdk-devel python3 python3-pyyaml selinux-policy-devel policycoreutils-python-utils setools-console
```

`selinux-policy-devel` supplies `/usr/share/selinux/devel/Makefile`.

**P2.** Create the Unix account. This is not the SELinux user `system_u` and not the type `shopapi_t`.

```bash
sudo groupadd --system shopapi
sudo useradd --system --gid shopapi --home-dir /opt/shopapi --shell /sbin/nologin shopapi
```

"Already exists" is fine.

**P3.** Create the directories.

```bash
sudo mkdir -p /opt/shopapi /var/lib/shopapi /var/log/shopapi /run/shopapi /var/spool/shopapi
```

| Path | What it holds |
|------|----------------|
| `/opt/shopapi` | The program |
| `/var/lib/shopapi` | State kept across reboots |
| `/var/log/shopapi` | Logs |
| `/run/shopapi` | Pid file. Gone after reboot |
| `/var/spool/shopapi` | Lab 5. Left out of the first file-context list on purpose |

**P4.** Build the jar.

```bash
cd ~/selinux-pac/lab/apps/shopapi
mvn -q -DskipTests package
sudo cp -f target/shopapi.jar /opt/shopapi/shopapi.jar
sudo chown -R shopapi:shopapi /opt/shopapi /var/lib/shopapi /var/log/shopapi /var/spool/shopapi
cd ~/selinux-pac
```

**P5.** Install the wrapper systemd will execute.

```bash
sudo mkdir -p /opt/shopapi/bin
sudo install -m 0755 lab/apps/shopapi/bin/shopapi /opt/shopapi/bin/shopapi
sudo chown shopapi:shopapi /opt/shopapi/bin/shopapi
```

**P6.** Write the environment file and the unit. `WantedBy=multi-user.target` is what `systemctl enable` reads.

```bash
sudo tee /etc/shopapi.env >/dev/null <<'EOF'
SHOPAPI_PORT=8091
SHOPAPI_STATE_DIR=/var/lib/shopapi
SHOPAPI_LOG_DIR=/var/log/shopapi
SHOPAPI_SPOOL_DIR=/var/spool/shopapi
EOF

sudo tee /etc/systemd/system/shopapi.service >/dev/null <<'EOF'
[Unit]
Description=shopapi Spring Boot (SELinux PaC demo)
After=network.target auditd.service
Wants=auditd.service

[Service]
Type=simple
User=shopapi
Group=shopapi
EnvironmentFile=-/etc/shopapi.env
WorkingDirectory=/opt/shopapi
ExecStart=/opt/shopapi/bin/shopapi -jar /opt/shopapi/shopapi.jar
Restart=on-failure
RestartSec=5
StateDirectory=shopapi
LogsDirectory=shopapi
RuntimeDirectory=shopapi

[Install]
WantedBy=multi-user.target
EOF
```

**P7.** Compile the seed and load it. Copy the two source files into an empty directory so `make` does not see the repo Makefile.

```bash
mkdir -p /tmp/shopapi-build
cp selinux/shopapi/shopapi.te selinux/shopapi/shopapi.fc /tmp/shopapi-build/
make -C /tmp/shopapi-build -f /usr/share/selinux/devel/Makefile shopapi.pp
sudo semodule -i /tmp/shopapi-build/shopapi.pp
sudo semodule -l | grep shopapi
```

`semodule -i` prints nothing on success. It does not relabel files and it does not assign port 8091. This install is priority 400. See [103](103-CONFIG-FILES.md).

**P8.** Compare the label on disk with the file-context answer, then relabel. `ls -dZ` is the directory. `ls -Z` on a directory would list its children.

```bash
ls -dZ /opt/shopapi /var/lib/shopapi /var/log/shopapi
ls -Z /opt/shopapi/bin/shopapi /opt/shopapi/shopapi.jar
matchpathcon /opt/shopapi/bin/shopapi /opt/shopapi/shopapi.jar
matchpathcon /var/lib/shopapi /var/log/shopapi
matchpathcon /run/shopapi/no-such-file
sudo restorecon -Rvn /opt/shopapi /var/lib/shopapi /var/log/shopapi /run/shopapi
sudo restorecon -Rv /opt/shopapi /var/lib/shopapi /var/log/shopapi /run/shopapi
```

The wrapper should land on `shopapi_exec_t`. The jar should land on `shopapi_lib_t`. `/run/shopapi` may not exist until the service starts. `matchpathcon` still answers. `restorecon` does not touch `/var/spool/shopapi`. That path is lab 6.

**P9.** Label the port and put only `shopapi_t` on the log-only list.

```bash
sudo semanage port -l | grep 8091
sudo semanage port -a -t shopapi_port_t -p tcp 8091
sudo semanage permissive -a shopapi_t
getenforce
```

If the port is already defined, use `-m` instead of `-a`. `getenforce` still prints `Enforcing`.

**P10.** Start the service.

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now shopapi.service
curl -sf http://127.0.0.1:8091/health; echo
```

Already added allows on this box? Put the seed back before lab 2:

```bash
git checkout -- selinux/shopapi/
```

Then repeat P7 through P10.

---

## Lab 0 — Read a label

**0.1**

```bash
getenforce
```

**0.2**

```bash
ls -Z /opt/shopapi/bin/shopapi
ls -Z /opt/shopapi/shopapi.jar
```

**0.3**

```bash
ps -eZ | grep shopapi
```

The file type and the process type differ. `shopapi_exec_t` on the wrapper, `shopapi_lib_t` on the jar, `shopapi_t` on the process. `getenforce` is still `Enforcing`.

---

## Lab 1 — The seed is not a permission list

**1.1**

```bash
systemctl status shopapi --no-pager
```

**1.2**

```bash
ps -eZ | grep java
```

**1.3**

```bash
sed -n '1,40p' selinux/shopapi/shopapi.te
```

The unit is active. The process type is `shopapi_t`. The `.te` declares the types and `init_daemon_domain`. It does not yet allow the `/log` write or `/var/spool`. The app answers HTTP because the domain is log-only: denials are written, and the kernel does not block that domain.

A new module name, not shopapi, starts from `sepolicy-generate`. The shopapi file is already in git. Do not delete it.

---

## Lab 2 — One AVC

Curl `/log` only. `ausearch --checkpoint` separates this denial from older ones. Labs 4 and 5 reuse the same checkpoint file, so each search prints only what arrived since the previous one.

**2.1**

```bash
sudo ausearch -m avc --checkpoint /var/tmp/shopapi-lab.checkpoint --subject shopapi_t >/dev/null || true
curl -sf http://127.0.0.1:8091/log
echo
```

**2.2**

```bash
sudo ausearch -m avc --checkpoint /var/tmp/shopapi-lab.checkpoint --subject shopapi_t | tee /tmp/lab2.avc
```

**2.3**

```bash
audit2why < /tmp/lab2.avc
```

Read one line. `scontext` is `shopapi_t`. `tcontext` may still be `var_log_t` if the file was not relabeled. `tclass=file`. `permissive=1`. `{ write }` or `{ open }` is the permission. `permissive=0` waits until lab 5.

If the search prints nothing, curl `/log` again and search with the same checkpoint. Do not generate a rule from a line whose source is not `shopapi_t`.

---

## Lab 3 — Write the allow and load it

The line you add is the one you just read. An access the `.te` already allows is not written again.

**3.1.** Add an allow for the shopapi log type, not for the generic type in the denial. The denial showed `var_log_t` because the file was unlabeled. The address book already says `/var/log/shopapi` is `shopapi_log_t`. The allow names that type:

```text
allow shopapi_t shopapi_log_t:dir { search write add_name };
allow shopapi_t shopapi_log_t:file { create write append open getattr };
```

The directory line is what lets the process look up `/var/log/shopapi` and create a file in it. The file line is the write.

If the AVC included `execmem`, that permission is domain-weakening. Add `allow shopapi_t self:process execmem;` only because the log showed it. Do not add it from memory.

The startup lines also show `execute`, `execute_no_trans`, and `map` on `bin_t`. That is the wrapper starting the JVM. Never write a raw allow on `bin_t`. Add the interface Red Hat's own tomcat policy uses ([`tomcat.te` on c9s](https://github.com/fedora-selinux/selinux-policy/blob/c9s/policy/modules/contrib/tomcat.te)):

```text
corecmd_exec_bin(shopapi_t)
```

The scripts and CI accept it only because `config/shopapi.manifest.yml` records the reviewed reason under `selinux_exceptions.exec_bin`. Without it, the next restart under enforcing cannot start Java. It is not an entrypoint. The wrapper is.

**3.2.**

```bash
mkdir -p /tmp/shopapi-build
cp selinux/shopapi/shopapi.te selinux/shopapi/shopapi.fc /tmp/shopapi-build/
make -C /tmp/shopapi-build -f /usr/share/selinux/devel/Makefile shopapi.pp
```

**3.3.**

```bash
sudo semodule -i /tmp/shopapi-build/shopapi.pp
sudo semodule -l | grep shopapi
```

**3.4.**

```bash
sudo restorecon -Rv /opt/shopapi /var/lib/shopapi /var/log/shopapi
ls -dZ /var/log/shopapi
```

`semodule -l` lists `shopapi` and `permissive_shopapi_t`. The new allows came from the AVC you read, not from a JVM cookbook.

---

## Lab 4 — The same URL adds no rule

**4.1**

```bash
curl -sf http://127.0.0.1:8091/log
echo
```

**4.2**

```bash
sudo ausearch -m avc --checkpoint /var/tmp/shopapi-lab.checkpoint --subject shopapi_t
```

The curl prints the log line. `ausearch` does not print a new `shopapi_t` write denial for `/log`. The checkpoint file is the one lab 2 wrote, so older denials stay out of this search. An allow is not a denial. A permissive domain also does not log an access the module already allows. A second copy of the same denial waits for a policy reload. The `/log` allow is in the module.

---

## Lab 5 — A new URL fails

The host stays Enforcing. `/var/spool/shopapi/feature.log` was never in the first module.

**5.1**

```bash
sudo semanage permissive -d shopapi_t
```

**5.2**

```bash
sudo semanage permissive -l | grep shopapi || echo "(shopapi_t not on the permissive list — good)"
getenforce
```

**5.3**

```bash
curl -sf http://127.0.0.1:8091/log; echo "log exit=$?"
curl -sf http://127.0.0.1:8091/feature-spool; echo "spool exit=$?"
```

**5.4**

```bash
sudo ausearch -m avc --checkpoint /var/tmp/shopapi-lab.checkpoint --subject shopapi_t
```

`/log` still works. `/feature-spool` fails. The checkpoint shows the new denial and not the ones from labs 2 and 4. The new AVC has `permissive=0`. `getenforce` is still `Enforcing`.

---

## Lab 6 — Only the new surface

**6.1.** Add a file-context line and an allow for the spool path. Do not add a second `execmem` or a second `/log` allow.

In `shopapi.fc`:

```text
/var/spool/shopapi(/.*)?    gen_context(system_u:object_r:shopapi_var_lib_t,s0)
```

Use a type you declare. The seed has no spool type. `shopapi_var_lib_t` is already declared, so the module still compiles. The generator in the tool lab picks the type from the manifest instead of this shortcut. If you add `type shopapi_spool_t` and `files_type(shopapi_spool_t)`, name that type in both files. One type, one allow:

```text
allow shopapi_t shopapi_var_lib_t:dir { search write add_name };
allow shopapi_t shopapi_var_lib_t:file { create write append open getattr };
```

The directory line is required when the spool directory is `shopapi_var_lib_t`. Search, write, and add_name are how the process creates `feature.log` in that directory.

Skip that allow if lab 3 already granted `shopapi_var_lib_t` and you reused that type. The new fact is the file-context line plus `restorecon`.

**6.2.**

```bash
mkdir -p /tmp/shopapi-build
cp selinux/shopapi/shopapi.te selinux/shopapi/shopapi.fc /tmp/shopapi-build/
make -C /tmp/shopapi-build -f /usr/share/selinux/devel/Makefile shopapi.pp
sudo semodule -i /tmp/shopapi-build/shopapi.pp
```

**6.3.**

```bash
sudo restorecon -Rv /var/spool/shopapi
ls -dZ /var/spool/shopapi
```

**6.4.**

```bash
curl -sf http://127.0.0.1:8091/feature-spool
echo
getenforce
sudo semanage permissive -l | grep shopapi || echo "(shopapi_t is not permissive)"
```

`/feature-spool` returns 200. `shopapi_t` is still not on the permissive list. `getenforce` is `Enforcing`.

"There were AVCs" and "the `.te` does not already allow this" are different. Lab 4 was the first. Lab 6 is the second.

To use the box for discovery again:

```bash
sudo semanage permissive -a shopapi_t
```

---

## Lab 7 — What the talk will show

| Talk | What they show | What you typed |
|------|----------------|----------------|
| Act 0 | Covered, unconfined, or generate | Lab 1: shopapi has a seed and almost no allows |
| Act 1 | Distro Tomcat, no new module | A vendor type you do not turn into a `.te` |
| Act 2 | Path, port, boolean. No `.te` | Appendix A |
| Act 3 | First URLs, then a module | Labs 2–4 |
| Act 6 | `/feature-spool` fails, then the spool rule | Labs 5–6 |

The customer talk is [301](../demo.md). The two-host path is [302](302-TECHNICAL.md). Prod does not `semodule -i`.

---

## Appendix A — Three host commands that are not a .te

Act 2 types these against vendor Tomcat. They never write `selinux/shopapi/`.

**A1.** Files under `/opt/appdata` have the wrong type.

```bash
sudo semanage fcontext -a -t tomcat_var_lib_t '/opt/appdata(/.*)?'
sudo restorecon -Rv /opt/appdata
```

**A2.** Bind on port 8090.

```bash
sudo semanage port -a -t http_port_t -p tcp 8090
```

**A3.** A boolean, only when `audit2why` names one and `getsebool` lists it.

```bash
getsebool -a | grep httpd_can_network_connect
```

RHEL's `tomcat` module has no `tomcat_can_network_connect`. Never set `httpd_can_network_connect` for Tomcat. If `getsebool` has no match, say so and skip. `setsebool -P` is the command when the name is real.

You do not need App A or App B installed to finish labs 0–6.
