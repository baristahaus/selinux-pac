# Containers, Namespaces and MCS

> Every container you run lands inside a policy domain: `container_t`. Each one walks out of that domain with its own categories. Namespaces isolate memory, but SELinux isolates identity. This chapter is about the label that makes a second container a stranger to the first.

## Why a container changes the policy picture

A container is a set of Linux namespaces: PID, mount, network, UTS, IPC, user, and cgroup. Each namespace isolates one dimension of the process. Namespaces do not touch the SELinux labels that the kernel assigns to every process and file. Two containers on the same host still share the same domain by default. They both run inside the generic container domain, `container_t`, so by the policy of the host they are the same thing. On those rules one container can read every file the other touches, because `container_t` is the same type on every side of every access check.

The fix is categories. Each container gets a unique MCS category pair: `s0:c123,c456` for the first, `s0:c234,c345` for the second, and so on. The level field of the label is still `s0`. The category list is what separates two processes that share a domain. The names in this chapter do not need a classified sensitivity field at all. What the categories do is give every container a unique key that the policy reads per tuple.

This is how RHEL ships the container domain by default. Every process that Podman or CRI-O starts carries the type field `container_t` and a level that is unique to that run of the container. systemd-nspawn is the odd one out. It applies an SELinux context only when you hand it one (`-Z`, or `SELinuxContext=` in a unit). Its own documentation supplies a hand-written `svirt_lxc_net_t:s0:c0,c1` instead of assigning `container_t` per run. The reference that names it is the RHEL Using SELinux chapter on container policy ([Using SELinux, Chapter 9](https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/8/html/using_selinux/creating-selinux-policies-for-containers_using-selinux)). That chapter says the `container_t` type is the default domain for every container on the host. It also says `udica` can generate a custom policy for a container. The container then runs under its own type, instead of sharing `container_t` with every other container on the box.

## Reading those labels

The whole picture is legible from the host's CLI. Two commands give you every field.

```bash title="Process labels on the host"
# ps -eZ | head -n 5
LABEL                                                 PID TTY      TIME CMD
system_u:system_r:init_t:s0                             1 ?     00:00:01 systemd
system_u:system_r:container_runtime_t:s0             8812 ?    00:00:00 conmon
system_u:system_r:container_t:s0:c123,c456           9001 pts/0  00:00:00 python3
unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023 8834 pts/1  00:00:00 bash
```

The third field is still the type. That is the enforcement decision. Note which process holds which label. The own helpers of the runtime (`podman`, `conmon`, `crun`) run as `container_runtime_t`. The payload of the container, which is the command you asked for, is what carries `container_t` with the per-run category pair. Only those payload lines end in an `s0:c…` tail. That tail is the per-container key, and it is how the host tells two containers apart.

The matching check for files is this, and Chapter 3 covers it in full:

```bash title="File labels on the host"
# ls -ldZ /var/lib/containers/storage
drwx------. 17 root root system_u:object_r:container_var_lib_t:s0 /var/lib/containers/storage
```

The top of that tree carries `container_var_lib_t`. Content that the container itself writes carries `container_file_t`, with the category list of that container. A bind mount with `:Z` and a volume are two examples. The example above shows `s0:c123,c456`. Every file inside a container gets the same category list as the process of the container. That is why the categories are the isolation. A file owned by container A and a process owned by container B lock each other out at the kernel decision. They do that even when both hold the same type field.

## Volume relabeling: `:z` versus `:Z`

Bind mounts reach the host file system. By default the SELinux label on the host path walks straight into the container alongside the bytes. That label is what the process inside the container has to ask about. If the host path is `unconfined_u:object_r:home_root_t:s0` and the process inside is `system_u:system_r:container_t:s0:c123,c456`, the policy compares their types and their levels, and answers no.

Podman's `:z` and `:Z` options change that answer by rewriting the label on the host path.
The two flags do not mean the same thing, and they share a single documented purpose:
*to relabel the file objects on the mounted volume*
([podman-run, `--volume`](https://docs.podman.io/en/v5.0.1/markdown/podman-run.1.html)).

| Suffix | What it does | When it is wrong |
|---|---|---|
| **`:z`** | labels the content with a shared content label. Every container that mounts the path read-write can use it. | a path that a host service also uses. The service fails once its label is a container label. |
| **`:Z`** | labels the content with a private, unshared label. Only this container can use it. | a path that a second container must also read, because that container is locked out, or a path that a host service uses |

The first row, `:z`, is the one for shared storage: any container that mounts the same path keeps working. That is why it is wrong for a path that a host service also reads. The second row, `:Z`, is the private answer. Only the current container can use the content, so a second container and a host service both lose access. The `podman-run` reference states both plainly, first for the shared flag: *the `z` option tells Podman that two or more containers share the volume content …* It states the private rule in the same list: *the `Z` option tells Podman to label the content with a private unshared label. Only the current container can use it*. It also warns against relabeling system files and directories, because *relabeling system content might cause other confined services on the machine to fail*.

When a host service already uses a path, the correct alternative is to stop relabeling it. Give the path its own type. Run `semanage fcontext -a -t <app>_var_lib_t '/srv/shared(/.*)?'`, then `restorecon -Rv /srv/shared`. Then let policy grant the container access to that type. That is a `container_t` allow that you review, or a type that `udica` produced. The label stays yours, and the host service keeps the context it had.

## Options that widen the boundary

Podman offers three options that widen the boundary. Each one is a decision worth writing down.

| Option | What it is for | Why it is a decision |
|---|---|---|
| `--security-opt label=type:<type_t>` | run the container under a custom process type, for example the module that `udica` produced | the container domain of the host no longer applies. An audit reads the new type and must decide whether the rules of that type still hold. |
| `--security-opt label=disable` | turn off label separation for the container, both from other containers and from the host | the container is no longer confined against host content at all: a leaked `/run`, a bind-mounted home directory, or any host file that the container can reach is fair game. For sharing between two containers, the narrower options are `--security-opt label=level:s0:c100,c200` (both containers join one level) or `:z` on the shared mount |
| `--privileged` | full root-equivalent capabilities inside the container | the container also stops transitioning into the `container_t` domain. Every check in this chapter goes away. |

Each option is the deliberate answer to a real question: a sidecar needs to reach a file, or an operator needs to mount `/dev`. Each one is also the answer to a second question: which check goes away? They are not mistakes. They are the kind of decision that a review must record.

The Podman reference for each is the same `--security-opt` page:
`label=type:TYPE` sets the process type, `label=level:LEVEL` sets the level,
and `label=disable` turns off label separation
([podman-run `--security-opt`](https://docs.podman.io/en/v4.6.0/markdown/options/security-opt.html)).

:::: warn Turn-off decisions stay in the log
`label=disable` and `--privileged` turn off the confinement this chapter is about.
Record the reason in the change ticket, the runbook and the inventory. An audit reading
the ticket later must be able to point at the row that says *why the key was removed*.
::::

## Kubernetes and CRI-O

Kubernetes reaches the container runtime with a `securityContext` block on each Pod. The field that carries SELinux is `seLinuxOptions`, and it has four fields: `user`, `role`, `type`, and `level`. This chapter is about the last two: the type and the level. The first two are the ones that the Restricted standard forbids outright, so an audit looks for them too. The runtime receives those values and passes them to the kernel when it starts each container. That is CRI-O on RHEL-based distributions, and containerd on the rest.

| Field | What it controls | Where it lives |
|---|---|---|
| `spec.securityContext.seLinuxOptions.type` | the process type for every container in the Pod | `securityContext` on the Pod |
| `spec.securityContext.seLinuxOptions.level` | the category list for every container in the Pod | `securityContext` on the Pod |

The Kubernetes documentation notes that the SELinux type is a restricted field under the Restricted Pod Security Standard. It can be undefined, or one of the allowed container types: `container_t`, `container_init_t`, `container_kvm_t`, or `container_engine_t`. A custom SELinux user or role is forbidden outright. The level is not restricted, so users can still supply it. In practice the type is the `container_t` of the platform, and the level is the per-Pod category ([Pod Security Standards, SELinux row](https://kubernetes.io/docs/concepts/security/pod-security-standards/)).

The default of the runtime is usually the right answer. The Kubernetes scheduler only decides which node a Pod lands on. The container runtime (CRI-O or containerd) composes the SELinux label on the node. It allocates a random MCS category pair when the Pod does not supply a `level`. The isolation is therefore node-scoped. Two Pods on the same node get different categories, and two Pods on different nodes can get the same ones. They are not a cluster-wide namespace, and they are not a substitute for the network policy between nodes.

## The consequence for policy authoring

A service in a container is not covered by the host application module. The host module names types like `shopapi_t` and paths like `shopapi_var_lib_t`. Those types apply only to the `shopapi_t` process that runs under systemd on the host. A `container_t` process does not inherit that allow chain. Every request it makes against a host file is answered by the generic container policy.

That is the shape of "policy as code" for containers. One half is policy for the runtime: the `container_t` allow chain. It ships with the host in the `container-selinux` package, it loads on the host, and no image carries it. The other half is a custom type of its own, where a container needs something specific. `udica` writes that custom type. It inspects the JSON of a running container (`podman inspect` into `udica -j container.json`). It emits the allowed capabilities, mounts, and ports as rules. The own type of the container is named `<name>.process`. The container then runs under that type (`--security-opt label=type:<name>.process`) instead of `container_t`. The operator owns its review, just as they own the review of the host application. Note the spelling of the type: `container_t` is a `_t` type, and the output of `udica` is a `.process` type. Pass the one you actually generated.

Chapter 1 showed the mechanism: *because the container hides it, staging is permissive*. Here is the same trap on the container path, with the build host added. A container on the build host masks a denial on the build host. On that host the container runs as `container_t`, and the generic container policy covers every request it makes against host paths. So the path change that breaks the systemd unit on production is still a path change against a directory that the generic policy covers. The confinement that really applies is the one on the host where the production service runs as `shopapi_t`. The policy for that domain never saw the new path. The point is plain: *a container masks a denial only when you read that denial as the production denial*. The production host is still Enforcing, and the domain of the production host is still the one that decides.

## A table of mechanisms

| Mechanism | What it isolates | What it costs | When to use it |
|---|---|---|---|
| `container_t` | the default domain of the runtime for every container on the host | every container shares the same type. Only categories separate them. | default. Accept it as long as the per-container level is unique |
| MCS categories (`s0:c123,c456`) | the files and processes of each container, as a stranger to every other container on the host | each container takes a per-run category list that the policy has to know about | every container on every host, automatically |
| `:z` on a bind mount | the path carries a shared content label. Every container that mounts it can read and write. | the label of the host path is rewritten for all containers, and a host service that also uses the path inherits the new label | a directory used by several containers and no host service |
| `:Z` on a bind mount | the path carries a private, unshared label. Only this one container can use it. | the host path is locked to that container. A second container, and any host service, is denied. | a directory used by exactly one container |
| `--security-opt label=type:<type>` | a custom process type that bypasses the generic `container_t` policy | you now own the allow chain for that type, and every access the type makes is your audit | a container that needs to reach a specific type, usually via `udica`, whose generated types end in `.process` |
| `--security-opt label=disable` | no label separation at all: not between containers, and not between the container and the host | the files of the container and the files of the host are one pool as far as SELinux is concerned | almost never. Prefer `label=level:` or `:z` when the goal is sharing between containers |
| `--privileged` | full root-equivalent capabilities inside the container, and no transition into `container_t` | every check the chapter is about goes away | an operator need that no less-powerful option satisfies |
| `seLinuxOptions.type` | the process type for each Pod on the cluster, usually `container_t` | the platform picks the type, and only the operator can supply one for a workload | every Pod, by default. Supply one only when you own the allow chain |
| `seLinuxOptions.level` | the category list for the Pod, which the container runtime composes on the node it lands on | the level of each Pod is unique on that node, so its files are a stranger to the other Pods there | every Pod. Accept the default unless you need a share across Pods |

## What you can do now

- **Read** a running container's label on any RHEL host with `ps -eZ | grep container` and
  recognize the `s0:c…` level as the per-run key.
- **Decide** whether `:z` or `:Z` wins for a bind mount, by checking whether a host service
  also uses the path. `:Z` is wrong for shared storage.
- **Record** each use of `--security-opt label=disable`, `--security-opt label=type:...`
  and `--privileged` as a row in the inventory with the reason, not a footnote.
- **Audit** the `seLinuxOptions` of a Kubernetes Pod. Check that `user` and `role` are unset, and
  that `type`, if set at all, is one of the allowed container types. Then look at the node.
  Two Pods on the same node must not share a category pair (`ps -eZ | grep container_t`).
  That per-node uniqueness is the isolation that the platform gives you by default.
- **Review** the container policy you are shipping against: it is the host module, plus a
  custom type for the container image, plus a decision about `container_t` or not.

:::: try On a RHEL host with Podman
Nothing changes state. You only set the vocabulary.

```bash title="Inspect a running container's label"
# ps -eZ | grep -E 'container_t|container_runtime_t'
system_u:system_r:container_t:s0:c230,c456           1 root   /usr/bin/python3 -m http.server
system_u:system_r:container_runtime_t:s0          8812 root   /usr/bin/conmon --api-version 1 ...
```

```bash title="Compare :z versus :Z on a bind mount"
# ls -Z /tmp/shared          # before mount: your host's label
# podman run --volume /tmp/shared:/data:Z fedora:41 ls -Z /data
# ls -Z /tmp/shared          # after :Z mount: you see the new label
```

(Use a Fedora or UBI image for that second line. BusyBox `ls`, the one in `alpine`, is built
without SELinux support and refuses `-Z`, so the container-side listing fails on the option
instead of showing you a label.)

The `:Z` line shows the label of the file rewritten for this container only.
The same sequence with `:z` shows it rewritten for every container that shares the level.
::::

1. **Run** the `ps -eZ` command above on your lab host. It is one of the five verify steps
   in `lab.md`, and the label you see there is the same picture this chapter is about.
2. **Pick** one bind mount in your current project that uses `:z`, and check that no host
   service also uses the path. If one does, that mount is the row that earns a review.
3. **Tell** the person adding a `--privileged` line to the run command what is going away,
   so the next read can tell you why it stayed.
