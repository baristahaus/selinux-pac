# Live checks

These commands need rhel-qa. They are not part of the on-screen demo. [102](102-COMMANDS.md) names each one.

Captured 2026-10-09 on rhel-qa after `demo_bootstrap.sh` (`getenforce` was Enforcing, `shopapi.service` was active, `shopapi_t` was permissive). The VM clock was behind the laptop: `date` on the host printed `Wed Oct  7 11:36:12 PM EDT 2026`. That is why `aureport` dates say 10/07/2026.

Customer talk the same day, after the one-query boolean change. Each time below is `cli/deterministic_gen.py` only, run with sudo because `policy.kern` is root-only. A separate `sudo` explain of `policy_out/avc.log` took 5.036 seconds.

| Generate | Result | Seconds |
|----------|--------|---------|
| Act 3, no `--allow-needs-review` | stopped on `execmem` only | 5.6 |
| Act 3, `--allow-needs-review` | wrote `corecmd_exec_bin(shopapi_t)`; passwd refused and absent from the `.te` | 5.4 |
| Act 6 | spool rule only; passwd refused again | 0.1 |

`compile_and_validate.sh` printed `bin_t execute accepted: reviewed exception`. Act 6: `getenforce` was Enforcing, `/feature-spool` was denied `permissive=0` on `/var/spool/shopapi/feature.log`, then the spool allow made the curl print `SPOOL /var/spool/shopapi/feature.log`. `shopapi_t` was not permissive at the end.

302 the same day, from a reset, finished 2026-10-09. rhel-qa built and signed the repo (`gpgcheck=1`). The Mac rsynced `dist/lab-repo` and printed `public key, signed RPMs, repodata; no private key`. From rhel-prod, `curl -sfI http://192.168.64.1:8765/RPM-GPG-KEY` printed `HTTP/1.0 200 OK`. Canary installed `selinux-policy-ops-1.1.0-2` and `shopapi-selinux-1.0.1-1` from that repo. Soak failed `raw=1 net_new=1`. Enforce without `force_enforce` refused (`0 day(s) elapsed; need 7`). Break-glass then denied `/var/spool/shopapi/feature.log` with `permissive=0`. After rollback, the spool fix shipped as `shopapi-selinux-1.0.2-1`. The clean soak was `Raw AVCs since marker: 0` and `Net-new access needs: 0`. Final enforce recap was `failed=0`. On rhel-prod afterwards: `getenforce=Enforcing`, `semanage permissive -l` had no `shopapi_t`, and `/etc/yum.repos.d/selinux-pac.repo` had `gpgcheck = 1`.

## Command catalog

```bash
getenforce
sestatus
ls -Z /opt/shopapi/bin/shopapi
ls -dZ /opt/shopapi /var/log/shopapi /var/lib/shopapi
ps -eZ | grep shopapi
id -Z
matchpathcon /opt/shopapi/bin/shopapi /opt/shopapi/shopapi.jar /var/lib/shopapi /var/log/shopapi
matchpathcon /run/shopapi/no-such-file
sudo restorecon -Rvn /opt/shopapi /var/lib/shopapi /var/log/shopapi /run/shopapi
sudo semanage fcontext -l -C
sudo semanage port -l | grep -E '8091|8090'
sudo getsebool -a | head
sudo semanage boolean -l | head
sudo semanage permissive -l
sudo semodule -l | grep shopapi
sudo semodule --list-modules=full | head
seinfo -t shopapi_t -x
seinfo -t bin_t -x | head -3
sudo semodule -l | grep -x java || echo 'no java module'
seinfo -t unconfined_java_t
matchpathcon "$(readlink -f /usr/bin/java)"
seinfo --permissive
sesearch -A -s shopapi_t -t shopapi_log_t -c file -p write
sesearch --dontaudit -s shopapi_t | head
sudo ausearch -m avc -ts recent --subject shopapi_t
sudo aureport -a
sudo aureport -a --summary
```

`ls -Z /opt/shopapi/bin/shopapi` prints `shopapi_exec_t`. `ls -dZ /opt/shopapi` prints `shopapi_lib_t`. `matchpathcon` agrees: the wrapper is `shopapi_exec_t` and the jar is `shopapi_lib_t`.

`sesearch -A -s shopapi_t -t shopapi_log_t -c file -p write` printed no lines. An `open` allow exists; a `write` allow does not.

`ausearch -m avc -ts recent --subject shopapi_t` printed `<no matches>`.

`seinfo -t unconfined_java_t` on rhel-qa (2026-10-09) printed `Types: 0`. `sudo semodule -l | grep -x java` printed nothing, so the page records `no java module`. The type is not in this policy.

`sudo aureport -a` printed 17377 AVC lines, all `init_t` `file` `execute` on `unlabeled_t`. First and last records:

```text
AVC Report
===============================================================
# date time comm subj syscall class permission obj result event
===============================================================
1. 10/07/2026 12:09:56 (_stub.py) system_u:system_r:init_t:s0 48 file execute system_u:object_r:unlabeled_t:s0 denied 179964
2. 10/07/2026 12:09:56 (python) system_u:system_r:init_t:s0 48 file execute system_u:object_r:unlabeled_t:s0 denied 179966
17377. 10/07/2026 23:35:27 (python) system_u:system_r:init_t:s0 48 file execute system_u:object_r:unlabeled_t:s0 denied 268828
```

The rest of the catalog:

```text
$ getenforce
Enforcing

$ sestatus
SELinux status:                 enabled
SELinuxfs mount:                /sys/fs/selinux
SELinux root directory:         /etc/selinux
Loaded policy name:             targeted
Current mode:                   enforcing
Mode from config file:          enforcing
Policy MLS status:              enabled
Policy deny_unknown status:     allowed
Memory protection checking:     actual (secure)
Max kernel policy version:      33

$ ls -Z /opt/shopapi/bin/shopapi
system_u:object_r:shopapi_exec_t:s0 /opt/shopapi/bin/shopapi

$ ls -dZ /opt/shopapi /var/log/shopapi /var/lib/shopapi
    system_u:object_r:shopapi_lib_t:s0 /opt/shopapi
system_u:object_r:shopapi_var_lib_t:s0 /var/lib/shopapi
    system_u:object_r:shopapi_log_t:s0 /var/log/shopapi

$ ps -eZ | grep shopapi
system_u:system_r:shopapi_t:s0  /usr/bin/java -jar /opt/shopapi/shopapi.jar

$ id -Z
unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023

$ matchpathcon /opt/shopapi/bin/shopapi /opt/shopapi/shopapi.jar /var/lib/shopapi /var/log/shopapi
/opt/shopapi/bin/shopapi	system_u:object_r:shopapi_exec_t:s0
/opt/shopapi/shopapi.jar	system_u:object_r:shopapi_lib_t:s0
/var/lib/shopapi	system_u:object_r:shopapi_var_lib_t:s0
/var/log/shopapi	system_u:object_r:shopapi_log_t:s0

$ matchpathcon /run/shopapi/no-such-file
/run/shopapi/no-such-file	system_u:object_r:var_run_t:s0

$ sudo restorecon -Rvn /opt/shopapi /var/lib/shopapi /var/log/shopapi /run/shopapi

$ sudo semanage fcontext -l -C

$ sudo semanage port -l | grep -E '8091|8090'
shopapi_port_t                 tcp      8091

$ sudo getsebool -a | head
abrt_anon_write --> off
abrt_handle_event --> off
abrt_upload_watch_anon_write --> on
antivirus_can_scan_system --> off
antivirus_use_jit --> off
auditadm_exec_content --> on
authlogin_nsswitch_use_ldap --> off
authlogin_radius --> off
authlogin_yubikey --> off
awstats_purge_apache_log_files --> off

$ sudo semanage boolean -l | head
SELinux boolean                State  Default Description

abrt_anon_write                (off  ,  off)  Allow ABRT to modify public files used for public file transfer services.
abrt_handle_event              (off  ,  off)  Determine whether ABRT can run in the abrt_handle_event_t domain to handle ABRT event scripts.
abrt_upload_watch_anon_write   (on   ,   on)  Determine whether abrt-handle-upload can modify public files used for public file transfer services in /var/spool/abrt-upload/.
antivirus_can_scan_system      (off  ,  off)  Allow antivirus programs to read non security files on a system
antivirus_use_jit              (off  ,  off)  Determine whether antivirus programs can use JIT compiler.
auditadm_exec_content          (on   ,   on)  Allow auditadm to exec content
authlogin_nsswitch_use_ldap    (off  ,  off)  Allow users to resolve user passwd entries directly from ldap rather then using a sssd server
authlogin_radius               (off  ,  off)  Allow users to login using a radius server

$ sudo semanage permissive -l
Builtin Permissive Types
dhcpc_hook_t
qgs_t
coreos_installer_t
rhc_worker_playbook_t
tuned_ppd_t
rhc_playbook_verifier_t
bootupd_t

Customized Permissive Types
rhcd_t
shopapi_t

$ sudo semodule -l | grep shopapi
permissive_shopapi_t
shopapi

$ sudo semodule --list-modules=full | head
400 permissive_rhcd_t cil
400 shopapi           pp
200 flatpak           pp
200 insights_core     pp
100 abrt              pp
100 accountsd         pp
100 acct              pp
100 afs               pp
100 afterburn         pp
100 aiccu             pp

$ seinfo -t shopapi_t -x
Types: 1
   type shopapi_t, corenet_unlabeled_type, domain, kernel_system_state_reader, daemon, pcmcia_typeattr_1;

$ seinfo --permissive
Permissive Types: 8
   bootupd_t
   coreos_installer_t
   dhcpc_hook_t
   qgs_t
   rhc_playbook_verifier_t
   rhc_worker_playbook_t
   rhcd_t
   tuned_ppd_t

$ sesearch --dontaudit -s shopapi_t | head
dontaudit daemon admin_home_t:dir { getattr ioctl lock open read search };
dontaudit daemon admin_home_t:lnk_file { getattr read };
dontaudit daemon console_device_t:chr_file { append getattr ioctl lock read write };
dontaudit daemon devpts_t:chr_file { getattr ioctl read write }; [ daemons_use_tty ]:False
dontaudit daemon firstboot_t:fifo_file { append getattr ioctl lock read write };
dontaudit daemon init_t:dir { getattr open search };
dontaudit daemon init_t:fd use;
dontaudit daemon init_t:file { getattr ioctl lock open read };
dontaudit daemon initrc_devpts_t:chr_file { append getattr ioctl lock open read write };
dontaudit daemon initrc_t:fd use;

$ sudo aureport -a --summary
Avc Object Summary Report
=================================
total  obj
=================================
17364  system_u:object_r:unlabeled_t:s0
```

`ausearch -ts` with one argument `MM/DD/YYYY HH:MM:SS` prints `Invalid start time`. The date and the time are two arguments. Do not pass an epoch to `-ts`.

## Config files

```bash
cat /etc/selinux/config
ls -l /etc/selinux/targeted/policy/policy.33
ls /var/lib/selinux/targeted/active/
ls -l /etc/selinux/targeted/contexts/files/
sha256sum /etc/selinux/targeted/policy/policy.33 /var/lib/selinux/targeted/active/policy.kern
sudo ls /var/lib/selinux/targeted/active/modules
sudo ls /var/lib/selinux/targeted/active/file_contexts /var/lib/selinux/targeted/active/file_contexts.local
cat /sys/fs/selinux/enforce
grep -E 'max_log_file|num_logs|space_left_action|admin_space_left_action|disk_full_action|disk_error_action' /etc/audit/auditd.conf
ls /usr/share/selinux/devel/Makefile /usr/share/selinux/packages
sudo semanage export
```

`policy.33` and `policy.kern` have the same sha256. `file_contexts.local` is in `/etc/selinux/targeted/contexts/files/` and is empty. It is not in the active store, so the second `ls` fails on that path. `semanage export` shows the local port and the `rhcd_t` permissive module.

```text
$ cat /etc/selinux/config

# This file controls the state of SELinux on the system.
# SELINUX= can take one of these three values:
#     enforcing - SELinux security policy is enforced.
#     permissive - SELinux prints warnings instead of enforcing.
#     disabled - No SELinux policy is loaded.
# See also:
# https://access.redhat.com/documentation/en-us/red_hat_enterprise_linux/9/html/using_selinux/changing-selinux-states-and-modes_using-selinux#changing-selinux-modes-at-boot-time_changing-selinux-states-and-modes
#
# NOTE: Up to RHEL 8 release included, SELINUX=disabled would also
# fully disable SELinux during boot. If you need a system with SELinux
# fully disabled instead of SELinux running with no policy loaded, you
# need to pass selinux=0 to the kernel command line. You can use grubby
# to persistently set the bootloader to boot with selinux=0:
#
#    grubby --update-kernel ALL --args selinux=0
#
# To revert back to SELinux enabled:
#
#    grubby --update-kernel ALL --remove-args selinux
#
SELINUX=enforcing
# SELINUXTYPE= can take one of these three values:
#     targeted - Targeted processes are protected,
#     mls - Multi Level Security protection.
SELINUXTYPE=targeted

$ ls -l /etc/selinux/targeted/policy/policy.33
-rw-r--r--. 1 root root 3492460 Oct  6 21:54 /etc/selinux/targeted/policy/policy.33

$ ls /var/lib/selinux/targeted/active/
booleans.local
commit_num
file_contexts
file_contexts.homedirs
homedir_template
modules
modules_checksum
policy.kern
policy.linked
ports.local
seusers
seusers.linked
users_extra
users_extra.linked

$ ls -l /etc/selinux/targeted/contexts/files/
total 1032
-rw-r--r--. 1 root root 418140 Oct  6 21:54 file_contexts
-rw-r--r--. 1 root root 588696 Oct  6 21:54 file_contexts.bin
-rw-r--r--. 1 root root  14623 Oct  6 21:54 file_contexts.homedirs
-rw-r--r--. 1 root root  20118 Oct  6 21:54 file_contexts.homedirs.bin
-rw-r--r--. 1 root root      0 Sep 23 10:30 file_contexts.local
-rw-r--r--. 1 root root      0 Sep 23 10:30 file_contexts.subs
-rw-r--r--. 1 root root    734 Sep 23 10:30 file_contexts.subs_dist
-rw-r--r--. 1 root root    139 Sep 23 10:30 media

$ sha256sum /etc/selinux/targeted/policy/policy.33 /var/lib/selinux/targeted/active/policy.kern
9777083665793affc8ef7378d6792fdd314d2639f81dd35538ea8e98c3d185df  /etc/selinux/targeted/policy/policy.33
9777083665793affc8ef7378d6792fdd314d2639f81dd35538ea8e98c3d185df  /var/lib/selinux/targeted/active/policy.kern

$ sudo ls /var/lib/selinux/targeted/active/modules
100
200
400
disabled

$ sudo ls /var/lib/selinux/targeted/active/file_contexts /var/lib/selinux/targeted/active/file_contexts.local
ls: cannot access '/var/lib/selinux/targeted/active/file_contexts.local': No such file or directory
/var/lib/selinux/targeted/active/file_contexts

$ cat /sys/fs/selinux/enforce
1

$ grep -E 'max_log_file|num_logs|space_left_action|admin_space_left_action|disk_full_action|disk_error_action' /etc/audit/auditd.conf
max_log_file = 8
num_logs = 5
max_log_file_action = ROTATE
space_left_action = SYSLOG
admin_space_left_action = SUSPEND
disk_full_action = SUSPEND
disk_error_action = SUSPEND

$ ls /usr/share/selinux/devel/Makefile /usr/share/selinux/packages
/usr/share/selinux/devel/Makefile
/usr/share/selinux/packages:
flatpak.pp.bz2
targeted

$ sudo semanage export
boolean -D
login -D
interface -D
user -D
port -D
node -D
fcontext -D
module -D
ibendport -D
ibpkey -D
permissive -D
boolean -m -0 httpd_can_network_connect
port -a -t shopapi_port_t -r 's0' -p tcp 8091
permissive -a rhcd_t
```

## Process label

The unit has no `SELinuxContext=` line. A comment in the unit says so, and that is the line `grep SELinuxContext` prints. The shopapi java process is `shopapi_t`. Tomcat's java process is `tomcat_t`.

```bash
systemctl cat shopapi.service | grep SELinuxContext || echo 'no SELinuxContext'
ps -o label,args -C java
```

```text
$ systemctl cat shopapi.service | grep SELinuxContext || echo 'no SELinuxContext'
# init_daemon_domain transitions from init_t. No SELinuxContext=.

$ ps -o label,args -C java
LABEL                           COMMAND
system_u:system_r:tomcat_t:s0   /usr/lib/jvm/jre/bin/java -classpath /usr/share/tomcat/bin/bootstrap.jar:... org.apache.catalina.startup.Bootstrap start
system_u:system_r:shopapi_t:s0  /usr/bin/java -jar /opt/shopapi/shopapi.jar
```

`matchpathcon /opt/shopapi/bin/shopapi` prints `shopapi_exec_t`. `matchpathcon /opt/shopapi/shopapi.jar` prints `shopapi_lib_t`.

## Runtime path that is not on disk

`/etc/selinux/targeted/contexts/files/file_contexts` contains `/run/shopapi(/.*)?` as `shopapi_var_run_t`. `matchpathcon` still prints `var_run_t`. The directory `/run/shopapi` is on disk and is also `var_run_t`. `restorecon -Rvn` printed nothing for it.

```bash
matchpathcon /run/shopapi/no-such-file
```

```text
/run/shopapi/no-such-file	system_u:object_r:var_run_t:s0
```

## Copy keeps the new label, move keeps the old one

`from-cp` wears the type of `/var/log/shopapi`. `from-mv` is still `etc_t`.

```bash
echo x > /tmp/label-src
sudo chcon -t etc_t /tmp/label-src
sudo cp /tmp/label-src /var/log/shopapi/from-cp
sudo mv /tmp/label-src /var/log/shopapi/from-mv
ls -Z /var/log/shopapi/from-cp /var/log/shopapi/from-mv
```

```text
system_u:object_r:shopapi_log_t:s0 /var/log/shopapi/from-cp
    unconfined_u:object_r:etc_t:s0 /var/log/shopapi/from-mv
```

`matchpathcon /var/lib/shopapi` prints `shopapi_var_lib_t`. `matchpathcon /var/log/shopapi` prints `shopapi_log_t`.

## One AVC until the cache is flushed

`shopapi_t` was already permissive. Both curls of `/log` returned 200. `ausearch -ts recent` does not print one line: it printed the denials from service start as well as the request. The two searches together were 150 `type=AVC` lines. One of the request lines is `shopapi_t` `open` on `/var/log/shopapi/shopapi.log` with `permissive=1`. `semodule -R` then the third curl logged that denial again. `-ts recent` is a 10-minute window, so it is not a count of the two curls.

```bash
curl -sf http://127.0.0.1:8091/log
curl -sf http://127.0.0.1:8091/log
sudo ausearch -m avc -ts recent --subject shopapi_t
sudo semodule -R
curl -sf http://127.0.0.1:8091/log
sudo ausearch -m avc -ts recent --subject shopapi_t
```

```text
curl1 200
curl2 200
ausearch -m avc -ts recent --subject shopapi_t   (exit 0, 150 type=AVC lines across both searches)
semodule -R
curl3 200
type=AVC msg=audit(1791431227.766:271160): avc:  denied  { open } for  pid=243647 comm="http-nio-0.0.0." path="/var/log/shopapi/shopapi.log" dev="dm-0" ino=17610905 scontext=system_u:system_r:shopapi_t:s0 tcontext=system_u:object_r:shopapi_log_t:s0 tclass=file permissive=1
```
