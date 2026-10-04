# switch-mgmt - run `make` for the list of commands.
#
# Common variables:
#   SITE=hq           limit to one site group (or any Ansible pattern: SITE=hq-acc-07)
#   CHECK=1           dry run for deploy / monitoring
#   INVENTORY=...     inventory directory inside ansible/ (default: inventory;
#                     inventory-lab for the simulated switches)
#   ARGS=...          extra ansible-playbook options, e.g. ARGS=--ask-vault-pass

SHELL := /bin/sh
COMPOSE ?= docker compose
INVENTORY ?= inventory
SITE ?=
CHECK ?=
LIMIT := $(if $(SITE),--limit '$(SITE)',)
CHECKFLAG := $(if $(filter 1 yes true,$(CHECK)),--check,)
# DC_RUN_FLAGS=-T disables the TTY (CI, cron).
RUN := $(COMPOSE) run --rm $(DC_RUN_FLAGS) ansible
PLAYBOOK := $(RUN) ansible-playbook -i $(INVENTORY) $(ARGS)

.DEFAULT_GOAL := help
.PHONY: help init build up down restart ps logs pull librenms-admin librenms-token \
        discover credentials-import forget-host sync sync-oxidized sync-librenms audit plan apply \
        report show deploy monitoring backup lab-up lab-down lab-audit lab-plan lab-apply lab-reset \
        shell test

help: ## Show this help
	@echo "switch-mgmt - LibreNMS + Oxidized + Ansible for Cisco switches"
	@echo
	@awk 'BEGIN {FS = ":.*## "} /^## / {printf "\n%s\n", substr($$0, 4)} /^[a-z-]+:.*## / {printf "  %-16s %s\n", $$1, $$2}' $(MAKEFILE_LIST)
	@echo

## Setup
init: ## First run: create .env (random DB password) and the data directories
	@if [ ! -f .env ]; then \
	  sed -e "s/^PUID=.*/PUID=$$(id -u)/" -e "s/^PGID=.*/PGID=$$(id -g)/" \
	      -e "s/^LIBRENMS_DB_PASSWORD=.*/LIBRENMS_DB_PASSWORD=$$(od -An -N16 -tx1 /dev/urandom | tr -d ' \n')/" \
	      .env.example > .env && chmod 600 .env && echo "Created .env - edit it (switch login, SNMP, MONITORING_HOST)"; \
	else echo ".env already exists"; fi
	@mkdir -p data/librenms data/db data/oxidized reports backups oxidized
	@mkdir -p -m 700 data/ssh && touch data/ssh/known_hosts && chmod 600 data/ssh/known_hosts
	@[ -f oxidized/router.json ] || echo '[]' > oxidized/router.json
	@chmod 600 ansible/inventory-lab/credentials.yml
	@[ ! -f ansible/inventory/credentials.yml ] || chmod 600 ansible/inventory/credentials.yml
	@chmod +x scripts/*.sh docker/oxidized/start.sh

build: ## Build the Ansible/netaudit toolbox image
	$(COMPOSE) build ansible

up: init ## Start LibreNMS + Oxidized (http://<host>:8000)
	$(COMPOSE) up -d

down: ## Stop everything (data stays in ./data)
	$(COMPOSE) --profile lab --profile tools down

restart: ## Restart the stack (e.g. after editing .env)
	$(COMPOSE) up -d --force-recreate

ps: ## Container status
	$(COMPOSE) ps

logs: ## Follow logs (SERVICE=oxidized to pick one)
	$(COMPOSE) logs -f --tail=100 $(SERVICE)

pull: ## Pull newer images (then: make up)
	$(COMPOSE) pull

librenms-admin: ## Create the LibreNMS admin user (asks for a password if none in .env)
	@pw=$$(scripts/env-get.sh LIBRENMS_ADMIN_PASSWORD); user=$$(scripts/env-get.sh LIBRENMS_ADMIN_USER admin); \
	if [ -n "$$pw" ]; then $(COMPOSE) exec librenms lnms user:add --role=admin --password="$$pw" "$$user"; \
	else $(COMPOSE) exec librenms lnms user:add --role=admin "$$user"; fi

librenms-token: ## Create a LibreNMS API token and store it in .env
	@COMPOSE="$(COMPOSE)" scripts/librenms-token.sh

## Inventory and integration
discover: ## Build ansible/inventory/sites/SITE.yml from CDP: make discover SITE=hq SEED=10.0.0.1
	@[ -n "$(SITE)" ] && [ -n "$(SEED)" ] || { echo "usage: make discover SITE=hq SEED=10.0.0.1 [SEED2=...]"; exit 2; }
	$(RUN) netaudit discover --site $(SITE) --seed $(SEED) $(if $(SEED2),--seed $(SEED2),) \
	  --credentials inventory/credentials.yml --out inventory/sites/$(SITE).yml

credentials-import: ## Add per-switch logins from a spreadsheet: make credentials-import CSV=passwords.csv
	@[ -n "$(CSV)" ] && [ -f "$(CSV)" ] || { echo "usage: make credentials-import CSV=passwords.csv (a file in this directory)"; exit 2; }
	$(COMPOSE) run --rm $(DC_RUN_FLAGS) -w /work ansible netaudit credentials-import $(CSV) --file ansible/inventory/credentials.yml

forget-host: ## Accept a replaced switch's new SSH key: make forget-host HOST=10.10.0.7 [PORT=22]
	@[ -n "$(HOST)" ] || { echo "usage: make forget-host HOST=<address the switch is reached at> [PORT=22]"; exit 2; }
	$(RUN) ssh-keygen -f /home/netops/.ssh/known_hosts -R '$(if $(filter-out 22,$(or $(PORT),22)),[$(HOST)]:$(PORT),$(HOST))'
	@echo "The next connection records the switch's current key (run make sync to do it now)."

sync: sync-oxidized sync-librenms ## Push the inventory to Oxidized and LibreNMS

sync-oxidized: ## Write oxidized/router.json from the inventory and reload Oxidized
	$(PLAYBOOK) playbooks/oxidized_sync.yml

sync-librenms: ## Add inventory switches to LibreNMS, site groups, STP alert rules
	$(PLAYBOOK) playbooks/librenms_sync.yml $(LIMIT)

## Spanning tree
audit: ## Read-only STP audit -> reports/latest/report.html
	$(PLAYBOOK) playbooks/stp_audit.yml $(LIMIT)

plan: ## Dry run of the fixes: fresh audit + the exact commands per switch
	$(PLAYBOOK) playbooks/stp_remediate.yml --check $(LIMIT)

apply: ## Apply the fixes: canary, root bridges, then batches of 5, with checks
	$(PLAYBOOK) playbooks/stp_remediate.yml $(LIMIT)

report: ## Print where the latest report is
	@ls -l reports/latest 2>/dev/null && echo "open reports/latest/report.html" || echo "no report yet - run make audit"

## Any switch work
show: ## Run a show command everywhere: make show CMD="show spanning-tree root" SITE=hq
	@[ -n "$(CMD)" ] || { echo 'usage: make show CMD="show ..." [SITE=hq]'; exit 2; }
	$(COMPOSE) run --rm $(DC_RUN_FLAGS) -e SHOW_CMD="$(CMD)" ansible ansible-playbook -i $(INVENTORY) playbooks/show.yml $(LIMIT)

deploy: ## Push a config snippet: make deploy SNIPPET=snippets/x.cfg.j2 SITE=hq [CHECK=1]
	@[ -n "$(SNIPPET)" ] || { echo "usage: make deploy SNIPPET=snippets/<file> [SITE=hq] [CHECK=1]"; exit 2; }
	$(PLAYBOOK) playbooks/deploy_snippet.yml -e snippet=$(SNIPPET) $(CHECKFLAG) $(LIMIT)

monitoring: ## Configure SNMP, syslog, traps towards LibreNMS [CHECK=1]
	$(PLAYBOOK) playbooks/monitoring_baseline.yml $(CHECKFLAG) $(LIMIT)

backup: ## Save every running-config to backups/<site>/ now
	$(PLAYBOOK) playbooks/backup.yml $(LIMIT)

## Lab (simulated switches, safe to break)
lab-up: build ## Start 6 simulated switches with typical STP problems
	$(COMPOSE) --profile lab up -d --wait lab

lab-down: ## Stop the simulated switches
	$(COMPOSE) --profile lab stop lab

lab-reset: ## Restart the lab with its original (broken) configuration
	$(COMPOSE) --profile lab up -d --wait --force-recreate lab

lab-audit: ## make audit against the lab
	$(MAKE) audit INVENTORY=inventory-lab

lab-plan: ## make plan against the lab
	$(MAKE) plan INVENTORY=inventory-lab

lab-apply: ## make apply against the lab
	$(MAKE) apply INVENTORY=inventory-lab

## Development
shell: ## Shell in the toolbox container
	$(RUN) bash

test: ## Run the unit tests (netaudit + Ansible plugin) against the checked-out code, in the toolbox
	$(COMPOSE) run --rm $(DC_RUN_FLAGS) -w /work -e PYTHONPATH=/work/netaudit/src ansible \
	  pytest -q -p no:cacheprovider netaudit/tests ansible/tests
