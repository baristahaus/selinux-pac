# 2026 Zero-Day CVEs vs SELinux: Impact Report

Ten zero-day vulnerabilities exploited against Linux servers in 2026, analysed
for SELinux containment on RHEL 9 with the targeted policy in enforcing mode.

> **Key finding:** SELinux contains or reduces the impact of **9 out of 10**
> zero-days exploited in 2026. Only one vulnerability (ipv6_frag_escape)
> directly defeats SELinux by patching `avc_denied()` in kernel memory.

---

## Summary table

| CVE | Name | CVSS | KEV date | SELinux verdict |
|-----|------|-----:|----------|:---------------:|
| CVE-2026-31431 | Copy Fail | 7.8 | 2026-05-01 | **Contained** |
| CVE-2026-43284 / 43500 | Dirty Frag | 8.8 | — | Reduced |
| CVE-2026-53266 | ebtables SNAT OOB | 8.8 | 2026-09-18 | Reduced |
| CVE-2026-53362 | ipv6_frag_escape | 7.8 | 2026-08-27 | Not mitigated |
| CVE-2026-64564 | SCTPhantom | 9.8 | — | Reduced |
| CVE-2026-34197 | ActiveMQ Jolokia RCE | 8.8 | 2026-04-16 | **Contained** |
| CVE-2026-42945 | Nginx Rift | 8.1 | 2026-05-13 | **Contained** |
| CVE-2026-41855 | Spring JMS Deser | 9.8 | — | **Contained** |
| CVE-2026-23479 | Redis UAF | 8.8 | — | **Contained** |
| CVE-2022-0492 | cgroups v1 escape | 7.8 | 2026-06-02 | **Contained** |

**Totals:** 6 Contained · 3 Reduced · 1 Not mitigated

---

## Rating system

| Rating | Meaning |
|--------|---------|
| **Contained** | SELinux blocks the primary exploitation path. The attacker either cannot trigger the vulnerability or, after exploitation, is confined to a domain that prevents meaningful impact. |
| **Reduced** | SELinux narrows the attack surface or blocks escalation in containerised workloads, but does not prevent exploitation from unconfined or privileged domains on bare-metal hosts. |
| **Not mitigated** | The vulnerability operates at a level that bypasses or disables SELinux enforcement. |

---

## Per-CVE analysis

### 1. CVE-2026-31431 — Copy Fail

| Field | Value |
|-------|-------|
| Component | Linux kernel AF_ALG (`crypto: algif_aead`) |
| CVSS 3.1 | 7.8 High — `AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H` |
| CISA KEV | 2026-05-01 (due 2026-05-15) |
| Red Hat | [RHSA-2026:14301](https://access.redhat.com/errata/RHSA-2026:14301), [RHSA-2026:14137](https://access.redhat.com/errata/RHSA-2026:14137), [RHSB-2026-002](https://access.redhat.com/security/vulnerabilities/RHSB-2026-002) |
| Verdict | **Contained** |

**What it does:** The AF_ALG interface exposes the kernel crypto API to
userspace via sockets. A resource-transfer flaw in `algif_aead` allows an
unprivileged local user to escalate to root. Ransomware operators adopted the
exploit within days of disclosure.

**SELinux analysis:** The targeted policy does not grant `alg_socket` access to
confined domains. Docker v29.4.3 shipped a CIL deny module:

```
(deny container_domain self (alg_socket (create)))
```

Containers running under `container_t` are fully blocked from reaching AF_ALG.
Host processes in confined domains (`httpd_t`, `redis_t`, etc.) are similarly
denied.

---

### 2. CVE-2026-43284 / CVE-2026-43500 — Dirty Frag

| Field | Value |
|-------|-------|
| Component | Linux kernel ESP/XFRM, RxRPC |
| CVSS 3.1 | 8.8 High (CVE-2026-43284), 7.8 High (CVE-2026-43500) |
| CISA KEV | Not listed (Microsoft observed ITW) |
| Red Hat | [RHSA-2026:16195](https://access.redhat.com/errata/RHSA-2026:16195), [RHSB-2026-003](https://access.redhat.com/security/vulnerabilities/RHSB-2026-003) |
| Verdict | **Reduced** |

**What it does:** Three related vulnerabilities (ESP/XFRM, RxRPC,
ESP-in-TCP "Fragnesia") allow a low-privileged local user to corrupt
page-cache contents of readable system files and gain root. The RxRPC
variant (CVE-2026-43500) does not affect Red Hat products.

**SELinux analysis:** SELinux `container_t` domain denies writes to
`/proc/self/uid_map`, blocking user namespace creation needed for the XFRM
path. In Red Hat's OpenShift testing, even with privileged SCC, root, and
unconfined seccomp, SELinux still blocked the escalation chain. However, on
bare-metal hosts running `unconfined_t`, SELinux does not prevent exploitation.

---

### 3. CVE-2026-53266 — ebtables SNAT OOB Write

| Field | Value |
|-------|-------|
| Component | Linux kernel netfilter ebtables SNAT target |
| CVSS 3.1 | 8.8 High — `AV:L/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H` |
| CISA KEV | 2026-09-18 (due 2026-09-21) |
| Red Hat | [RHSA-2026:36645](https://access.redhat.com/errata/RHSA-2026:36645), [RHSA-2026:71325](https://access.redhat.com/errata/RHSA-2026:71325), [RHSA-2026:72059](https://access.redhat.com/errata/RHSA-2026:72059) |
| Verdict | **Reduced** |

**What it does:** The ebtables SNAT target rewrites ARP sender hardware
addresses directly into a nonlinear socket-buffer fragment backed by a
splice-imported file page. This OOB write allows privilege escalation from a
user who can configure ebtables rules (`CAP_NET_ADMIN` in a network namespace).

**SELinux analysis:** The targeted policy confines container domains and
prevents them from loading netfilter rules. `CAP_NET_ADMIN` required for
ebtables configuration is denied to `container_t`. Host processes in confined
domains also lack netfilter management permissions. Unconfined processes with
`CAP_NET_ADMIN` remain vulnerable.

---

### 4. CVE-2026-53362 — ipv6_frag_escape

| Field | Value |
|-------|-------|
| Component | Linux kernel IPv6 fragmentation (`__ip6_append_data`) |
| CVSS 3.1 | 7.8 High — `AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H` |
| CISA KEV | 2026-08-27 (due 2026-08-30) |
| Red Hat | [RHSA-2026:43826](https://access.redhat.com/errata/RHSA-2026:43826), [RHSB-2026-009](https://access.redhat.com/security/vulnerabilities/RHSB-2026-009) |
| Verdict | **Not mitigated** |

**What it does:** An incorrect parameter length calculation in
`__ip6_append_data()` causes an OOB write into `skb_shared_info`. The exploit
chains this into a dirty-pagetable attack providing arbitrary kernel
read/write, overwrites process credentials, patches `avc_denied()` to bypass
SELinux, and escapes via `/proc/sys/kernel/core_pattern`.

**SELinux analysis:** The exploit explicitly patches `avc_denied()` in kernel
memory to neutralize SELinux enforcement. Red Hat confirms:

> "SELinux enforcement alone does not prevent the escape. The sysctl mitigation
> is required regardless of SELinux policy."

The mandatory mitigation is restricting user namespaces
(`sysctl user.max_user_namespaces=0`) and patching the kernel. This is the
only 2026 zero-day where SELinux is directly defeated.

---

### 5. CVE-2026-64564 — SCTPhantom

| Field | Value |
|-------|-------|
| Component | Linux kernel SCTP ASCONF transport UAF |
| CVSS 3.1 | 9.8 Critical — `AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H` |
| CISA KEV | Not listed |
| Red Hat | [RHSA-2026:69089](https://access.redhat.com/errata/RHSA-2026:69089), [RHSA-2026:69837](https://access.redhat.com/errata/RHSA-2026:69837) |
| Verdict | **Reduced** |

**What it does:** A use-after-free in SCTP ASCONF DEL-IP processing allows an
attacker to send a crafted sequence of ASCONF chunks to trigger memory
corruption. Exploitable for local privilege escalation and container escape.
Highest CVSS in this report at 9.8 (network vector, no auth required).

**SELinux analysis:** Confined domains typically lack `sctp_socket` permissions.
`container_t` cannot create SCTP sockets by default. Applications explicitly
granted SCTP access or running in `unconfined_t` remain vulnerable. The network
attack vector (`AV:N`) is partially mitigated because SELinux + firewalld can
restrict which processes bind SCTP ports.

---

### 6. CVE-2026-34197 — ActiveMQ Jolokia RCE

| Field | Value |
|-------|-------|
| Component | Apache ActiveMQ Jolokia JMX-HTTP bridge |
| CVSS 3.1 | 8.8 High — `AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H` |
| CISA KEV | 2026-04-16 |
| Red Hat | Not applicable (Red Hat does not ship ActiveMQ) |
| Verdict | **Contained** |

**What it does:** An authenticated attacker invokes
`BrokerService.addNetworkConnector()` with a crafted URI that loads a remote
Spring XML application context. Because `ResourceXmlApplicationContext`
instantiates all singleton beans before validation, arbitrary code executes via
`Runtime.exec()`.

**SELinux analysis:** When ActiveMQ runs in a confined domain (custom
`activemq_t` or `tomcat_t`), SELinux type enforcement limits post-exploitation
actions: file access restricted to labeled types, network connections confined
to allowed ports, execution of arbitrary binaries blocked. The attacker has JVM
code execution but cannot pivot to `/etc/shadow`, write to system directories,
or bind new ports.

---

### 7. CVE-2026-42945 — Nginx Rift

| Field | Value |
|-------|-------|
| Component | NGINX `ngx_http_rewrite_module` heap buffer overflow |
| CVSS 3.1 | 8.1 High — `AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H` |
| CISA KEV | 2026-05-13 |
| Red Hat | [RHSA-2026:17751](https://access.redhat.com/errata/RHSA-2026:17751) |
| Verdict | **Contained** |

**What it does:** NGINX Plus and Open Source have a heap buffer overflow in the
`ngx_http_rewrite_module` when unnamed PCRE captures and a question mark are
used in the replacement string. Crafted HTTP requests can trigger RCE (ASLR
disabled) or DoS (ASLR enabled). Requires specific non-default rewrite
configurations.

**SELinux analysis:** NGINX runs as `httpd_t` on RHEL. Even with arbitrary code
execution in the worker process, SELinux prevents writing outside web content
directories, restricts network access to labeled ports (`http_port_t`), and
blocks execution of arbitrary binaries. The attacker is trapped in the
`httpd_t` sandbox. Red Hat rated it Critical via RHSA-2026:17751.

---

### 8. CVE-2026-41855 — Spring JMS Deserialization

| Field | Value |
|-------|-------|
| Component | Spring Framework `MappingJackson2MessageConverter` |
| CVSS 3.1 | 9.8 Critical (NVD) / 8.1 High (VMware CNA) |
| CISA KEV | Not listed |
| Red Hat | Not applicable (does not affect Red Hat products) |
| Verdict | **Contained** |

**What it does:** In an untrusted JMS environment,
`MappingJackson2MessageConverter` and `JacksonJsonMessageConverter` allow
arbitrary class instantiation through gadget class deserialization. Spring
7.0.8+, 6.2.19+, 6.1.28+, 5.3.49+ are fixed.

**SELinux analysis:** When the JVM is confined (`tomcat_t` or a custom
application domain), SELinux type enforcement limits post-exploitation: no
access to system files, no execution of arbitrary binaries, network connections
restricted to labeled ports. The deserialization RCE gives code execution within
the JVM sandbox but MAC prevents lateral movement to the host.

---

### 9. CVE-2026-23479 — Redis UAF

| Field | Value |
|-------|-------|
| Component | Redis server unblock client flow |
| CVSS 3.1 | 8.8 High — `AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H` |
| CISA KEV | Not listed |
| Red Hat | [RHSA-2026:25216](https://access.redhat.com/errata/RHSA-2026:25216), [RHSA-2026:25925](https://access.redhat.com/errata/RHSA-2026:25925), [RHSA-2026:26306](https://access.redhat.com/errata/RHSA-2026:26306) |
| Verdict | **Contained** |

**What it does:** In redis-server 7.2.0 through 8.6.2, the unblock client
flow does not handle an error return from `processCommandAndResetClient`. If
a blocked client is evicted during this flow, an authenticated attacker
triggers a use-after-free leading to remote code execution. Fixed in 8.6.3.

**SELinux analysis:** Redis runs as `redis_t` on RHEL with confined
permissions. Even with code execution via the UAF, the process can only access
Redis data directories and configured ports. System files, other services'
data, and execution of arbitrary binaries are all blocked by type enforcement.
The attacker controls redis-server but cannot pivot to the host.

---

### 10. CVE-2022-0492 — cgroups v1 Container Escape

| Field | Value |
|-------|-------|
| Component | Linux kernel cgroups v1 `release_agent` |
| CVSS 3.1 | 7.8 High (NVD) / 7.0 High (Red Hat) |
| CISA KEV | 2026-06-02 (resurfaced — originally 2022) |
| Red Hat | [RHSA-2022:0823](https://access.redhat.com/errata/RHSA-2022:0823), [RHSA-2022:0825](https://access.redhat.com/errata/RHSA-2022:0825), [RHSA-2022:4642](https://access.redhat.com/errata/RHSA-2022:4642) |
| Verdict | **Contained** |

**What it does:** A missing authorization check in the cgroups v1
`release_agent` feature allows privilege escalation and namespace isolation
bypass. Originally disclosed in 2022, CISA re-added it to KEV on June 2, 2026,
indicating active exploitation of still-unpatched systems in 2026.

**SELinux analysis:** Red Hat explicitly states:

> "In OpenShift Container Platform, the container escape and privilege
> escalation caused by CVE-2022-0492 are blocked by the SELinux policy enabled
> by default on OCP cluster nodes."

SELinux prevents the container process from writing to the cgroup
`release_agent` file. Red Hat Virtualization requires SELinux enforcing mode,
which also blocks this vulnerability.

---

## Takeaways for customer conversations

1. **SELinux is not optional.** Six of ten zero-days are fully contained by
   SELinux type enforcement. Turning it off removes your last line of defence.

2. **Confined domains matter more than you think.** Application-level
   vulnerabilities (ActiveMQ, NGINX, Spring, Redis) all become contained when
   the process runs in a confined SELinux domain instead of `unconfined_t`.

3. **Containers + SELinux is the winning combination.** The `container_t`
   domain blocks AF_ALG sockets, user namespace creation, netfilter
   manipulation, and cgroup escape paths.

4. **Kernel memory corruption is the limit.** The ipv6_frag_escape exploit
   patches `avc_denied()` in kernel memory — the one case where SELinux cannot
   help. This reinforces the need for timely kernel patching alongside MAC.

5. **sepac makes it manageable.** Use `sepac triage` to check if your
   application domains are confined, `sepac denials` to catch policy gaps, and
   `sepac load --enforcing` to move from permissive to enforcing with
   confidence.

---

*Sources: NVD, CISA KEV catalog, Red Hat Security Bulletins (RHSB-2026-002,
RHSB-2026-003, RHSB-2026-009), Docker/Moby v29.4.3 release notes,
CIQ/Rocky Linux CVE-2026-53362 advisory. Updated October 2026.*
