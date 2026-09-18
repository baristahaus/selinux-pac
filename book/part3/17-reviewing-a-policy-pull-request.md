# Reviewing a Policy Pull Request

> A pull request is the cheapest place to catch a dangerous rule. After it ships, it lives on a host, and the only controls left are canary, soak and rollback.

Every rule in `myapp.te` is one answer to one tuple of four values. When that rule arrives in a pull request, the reviewer's job is to decide whether it is justified by evidence and narrow enough to defend. A generator already wrote the rule from an AVC log; CI already ran the forbidden-patterns gate; the admin already asked for a policy summary in plain English. But the summary and the diff both sit in the same file, and the reviewer is the only human reading both.

This chapter is that review.

## Two questions about one `allow`

Each allow is a decision. Each rule that shows up in the diff is a decision the kernel will now answer *yes* to. The review does not decide whether the rule compiles, does not decide whether it passes `forbidden-patterns`, does not decide whether it survives soak — each of those is automated, and each is a single check. The review is what those checks cannot do.

| Question | Automated gate | The reviewer |
|---|---|---|
| Is the rule syntactically correct? | `checkmodule` / refpolicy Makefile | `compile_and_validate.sh` on rhel-qa |
| Is the rule forbidden by our own rules? | `validate_forbidden_patterns.sh` (GHA `forbidden-patterns`) | — |
| Does the SemVer in `.te` match `policy_version.txt`? | `validate_version_consistency.sh` (GHA `version-consistency`) | — |
| Does every new allow trace back to an AVC line? | `sesearch` merge-base diff | — |
| Is the target type narrow enough to defend? | no gate | you |

The last row is why the review exists. An automated gate can catch a `shadow_t` rule; it cannot catch a rule that is *technically* correct but wider than the denial that motivated it.

::: why The cheapest place to catch a dangerous rule
After a rule ships, it has moved from the review surface to the host. After that it is a canary failure, then a soak failure, then a rollback. Pull-request review is the only human check that sits before the module is loaded. It is the cheapest place to catch a rule that would later break you.
:::

## A reading order for the diff

A policy pull request in this repository carries five surfaces. Read them in this order — each is the layer that catches the next.

| Layer | What it is | What it catches |
|---|---|---|
| **The manifest** | `manifest/` — ports, file contexts, booleans, domains | the policy scope — what the module owns |
| **The `.te`** | Type Enforcement — every `allow` rule in the module | the decisions themselves |
| **The `.fc`** | File Contexts — every label on a path | what objects the policy names |
| **The access delta** | `docs/examples/fixtures/policy_diff/sample_delta.md` — `sesearch` allow diff vs merge-base | what *changed* between the last release and this one |
| **The version file** | `selinux/policy_version.txt` — SemVer | whether the bump is a symptom (policy change) or routine (build refresh) |
| **The refused shape** | every rule that touches `shadow_t`, `self:*`, `bin_t`, `unreserved_port_t`, `sysadm_t` | the forbidden catalogue |

Each layer answers a different question. The manifest tells you what the module is supposed to own. The `.te` tells you what decisions the module will make. The `.fc` tells you what objects the policy names. The access delta tells you what changed. The version tells you whether the bump is routine or urgent. The refused shape tells you what is forbidden.

## The questions to ask

Each question catches one failure mode. Each failure mode shows up in a different layer.

| Question | Catches | Layer |
|---|---|---|
| Is every new `allow` traced to an AVC line? | a rule added without evidence | access delta + AVC excerpt |
| Are the target types specific, or a broad category? | a rule wider than the denial | `.te` + `.fc` |
| Are ports declared in the manifest, or smuggled into the policy body? | `semanage port` as the control plane | manifest + §2 of the best practices |
| Is a refpolicy interface used where one exists? | raw `allow` that an interface already covers | `.te` + §1 of the best practices |
| Is vendor policy duplicated instead of inherited? | a custom module for JWS / EAP / httpd | manifest + §1 of the best practices |
| Is there any rule the app does not actually need? | a rule added by `audit2allow` | access delta + AVC excerpt |
| What breaks if the app is not started at all? | a rule that depends on live state | `.fc` + manifest + soak plan |
| How is this rolled back? | a rule the admin cannot undo | admin checklist + `303-DENIAL_RESPONSE.md` |

The checklist in the pull request template is the record of these questions. The gates answer the mechanical ones — compile, forbidden patterns, version consistency, the access delta — and the table above is what remains: the questions only a human can answer before a module reaches a host.

## What you can do now

- **Read the diff in layer order.** Manifest, `.te`, `.fc`, access delta, version, refused shapes. Each one catches what the previous cannot.
- **Ask the one question that has no gate:** is the target type narrow enough to defend? If the rule names a category where the denial named a path, the rule is wider than its evidence.
- **Refuse the shapes.** A rule that reaches `shadow_t`, a bare `self:*` grant, a `bin_t` execute, or a generic port type is refused by the template's checklist — recognise it before the checklist does.
- **Send the reviewer's own answer back into the tooling.** A rule that passes review but adds no evidence-backed access is a generator bug, and the fixture that pins that verdict is where it gets fixed.
