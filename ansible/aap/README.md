# AAP job templates and workflows

**Ansible Automation Platform (AAP)** / Automation Controller is the production control plane. These files are the click-create spec. They are **not** playbooks. Do not add `ansible.controller` to host `requirements.yml`.

When a file or port is denied after ship: [401-OPERATIONS.md#a-denial-after-ship](../../docs/shipping.md#a-denial-after-ship). Soak-monitor failure is investigate-without-mutate — attach a Controller **notification template** to **SELinux – Soak monitor** (job failed). Do not auto-install policy.

## Create in Automation Controller

1. **Project** → this git repo. Playbook path: `ansible/`.
2. **Inventory** → production hosts (`canary` + `production` groups).
3. **Job templates** from [`job_templates.yml`](job_templates.yml). Playbooks are next to this directory (`deploy_canary.yml`, …).
4. Attach [`survey_enforce.json`](survey_enforce.json) to **SELinux – Enforce**.
5. **Schedule** **SELinux – Soak monitor** daily on `canary`.
6. **Workflows** from [`workflows.yml`](workflows.yml):
   - **SELinux – Release canary** — Canary only, after RPM publish.
   - **SELinux – Promote to enforce** — Soak status → approval → Enforce.
7. **SELinux – Rollback** stays a standalone template. Never add it to the promote graph.

To create those objects from a controller that has `infra.aap_configuration`, load [`aap_configuration.yml`](aap_configuration.yml). It defines `controller_templates`, `controller_workflows` (Release canary, Promote to enforce), the enforce survey, and a daily schedule on **SELinux – Soak monitor**. The project and the production inventory must already exist. `aap_hostname` and the token stay in vault.

Laptop equivalent (same YAML): `ansible-playbook -i ansible/inventory.production.yml ansible/<playbook>.yml`. Extra-vars: [401-OPERATIONS.md](../../docs/shipping.md).
