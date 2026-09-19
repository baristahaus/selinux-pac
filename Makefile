# Root Makefile — single entry point for local verification (see `make help`).
.DEFAULT_GOAL := help

PYTHON ?= python3
PIP ?= $(PYTHON) -m pip

.PHONY: help deps test check lint fixtures test-smoke test-static test-manifest \
	test-rpm test-forbidden test-version test-fixtures test-blast-radius \
	lint-shell lint-yaml lint-ansible integration-compile integration-semantics \
	training-lab demo-bootstrap book book-check book-serve

help: ## List targets (default)
	@echo "SELinux demo — common targets:"
	@echo ""
	@grep -E '^[a-zA-Z0-9_.-]+:.*##' $(MAKEFILE_LIST) | sort | \
		awk 'BEGIN {FS = ":.*## "}; {printf "  %-22s %s\n", $$1, $$2}'
	@echo ""
	@echo "Quick start:  make deps && make check"

deps: ## Install Python deps for offline tests (no network after first run)
	@if $(PIP) --version >/dev/null 2>&1; then \
		$(PIP) install -q -r cli/requirements.txt; \
	else \
		echo "make: $(PIP) unavailable \u2014 skipping dependency install; install cli/requirements.txt yourself"; \
	fi

test: deps test-fixtures test-static test-smoke ## Offline health check (no SELinux host required)
	@echo "make test OK"

check: test lint book-check ## Full repo health: offline tests + linters + book links

fixtures: test-fixtures ## Deterministic + payments + blast-radius fixture suites only

test-fixtures: ## Golden deterministic, payments + blast-radius + tune-report fixtures
	bash scripts/run_deterministic_fixtures.sh
	bash scripts/run_deterministic_payments_check.sh
	bash scripts/run_blast_radius_fixtures.sh
	bash scripts/run_tune_report_fixtures.sh

test-static: test-forbidden test-version test-rpm test-manifest ## Shell validators (offline)

test-forbidden: ## Forbidden-pattern grep on selinux/
	bash scripts/validate_forbidden_patterns.sh selinux
	POLICY_MODULE=shopapi SELINUX_DOMAIN=shopapi_t bash scripts/validate_forbidden_patterns.sh selinux/shopapi

test-manifest: deps ## App manifest YAML validation
	bash scripts/validate_app_manifest.sh config/myapp.manifest.yml
	bash scripts/validate_app_manifest.sh config/payments.manifest.example.yml
	bash scripts/validate_app_manifest.sh config/shopapi.manifest.yml

test-version: ## policy_version.txt vs policy_module() consistency
	bash scripts/validate_version_consistency.sh

test-rpm: ## Ops RPM packaging allowlist
	bash scripts/validate_rpm_ops_parity.sh

test-smoke: deps ## Python smoke_test.py (offline; no SELinux host)
	$(PYTHON) scripts/smoke_test.py

test-blast-radius: ## Blast-radius fixtures only (skips live sesearch locally)
	bash scripts/run_blast_radius_fixtures.sh

lint: lint-shell lint-yaml lint-ansible ## Run linters (SKIP if tool not installed)

lint-shell: ## shellcheck on scripts/
	@command -v shellcheck >/dev/null 2>&1 || { echo "SKIP lint-shell: shellcheck not installed"; exit 0; }; \
	shellcheck scripts/*.sh scripts/lib/*.sh scripts/ci/*.sh scripts/validate_version_consistency.sh

lint-yaml: ## yamllint on ansible/ and workflows/
	@command -v yamllint >/dev/null 2>&1 || { echo "SKIP lint-yaml: yamllint not installed (pip install yamllint)"; exit 0; }; \
	yamllint -d relaxed ansible/ .github/workflows/

lint-ansible: ## ansible-lint on playbooks
	@command -v ansible-lint >/dev/null 2>&1 || { echo "SKIP lint-ansible: ansible-lint not installed (pip install ansible-lint)"; exit 0; }; \
	ansible-galaxy collection install -r ansible/requirements.yml && \
	ansible-lint ansible/*.yml

lint-ansible-syntax: ## ansible-playbook --syntax-check (needs ansible)
	@command -v ansible-playbook >/dev/null 2>&1 || { echo "SKIP lint-ansible-syntax: ansible not installed"; exit 0; }; \
	bash scripts/ci/ansible_syntax_check.sh

integration-compile: ## Compile selinux/ modules (needs selinux-policy-devel)
	@if [ ! -f /usr/share/selinux/devel/Makefile ]; then \
		echo "SKIP integration-compile: install selinux-policy-devel (run on rhel-dev)"; exit 0; \
	fi
	bash scripts/compile_and_validate.sh selinux
	POLICY_MODULE=payments SELINUX_DOMAIN=payments_t bash scripts/compile_and_validate.sh selinux/payments
	POLICY_MODULE=shopapi SELINUX_DOMAIN=shopapi_t bash scripts/compile_and_validate.sh selinux/shopapi

integration-semantics: ## sesearch semantic assertions (needs selinux-policy-devel)
	@if [ ! -f /usr/share/selinux/devel/Makefile ]; then \
		echo "SKIP integration-semantics: install selinux-policy-devel (run on rhel-dev)"; exit 0; \
	fi
	bash scripts/validate_policy_semantics.sh selinux

integration-blast-radius: ## Blast-radius with live sesearch (CI / rhel-dev)
	@if [ ! -f /usr/share/selinux/devel/Makefile ]; then \
		echo "SKIP integration-blast-radius: install selinux-policy-devel (run on rhel-dev)"; exit 0; \
	fi
	BLAST_RADIUS_REQUIRE_INTEGRATION=1 bash scripts/run_blast_radius_fixtures.sh

training-lab: ## Dry-run the customer talk (no SELinux required)
	bash scripts/demo_present.sh --dry-run --profile customer --no-type --auto

book: ## Build the HTML manual into site/ (tools/book/build.py)
	$(PYTHON) tools/book/build.py

book-check: ## Validate the manual: internal links, anchors, repo: references
	$(PYTHON) tools/book/build.py --check

book-serve: ## Build the manual and serve it at http://127.0.0.1:8000
	$(PYTHON) tools/book/build.py --serve 8000

demo-bootstrap: ## Stand up App A/B + shopapi on RHEL (idempotent; not for macOS)
	bash scripts/demo_bootstrap.sh
