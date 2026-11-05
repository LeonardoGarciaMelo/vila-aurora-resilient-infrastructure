.PHONY: evidence bootstrap build up down reset status demo security chaos incident mail phishing llm a11y resources

COMPOSE := docker compose
ALL := --profile legacy --profile tools --profile llm --profile mail --profile phishing
EXAMINER ?= Lab team

bootstrap: ## Generate secrets, certificates and keys (idempotent)
	scripts/bootstrap.sh

build: bootstrap
	$(COMPOSE) --profile legacy --profile tools --profile llm --profile mail build

up: bootstrap ## Start the hardened lab
	$(COMPOSE) up -d

down: ## Stop everything, keep data
	$(COMPOSE) $(ALL) down --remove-orphans

reset: ## Stop everything and delete lab volumes (the downloaded LLM model is kept)
	$(COMPOSE) $(ALL) down --remove-orphans
	docker volume ls -q --filter name=vaurora_ | grep -v ollama_models | xargs -r docker volume rm

status:
	$(COMPOSE) ps -a --format 'table {{.Service}}\t{{.Status}}'

demo: ## Publish panel, Mailpit and Gophish on localhost only
	$(COMPOSE) -f docker-compose.yml -f docker-compose.demo.yml up -d waf

security: ## E3 security test suite (about 10 minutes)
	python3 tests/security/run_security_tests.py

chaos: ## RT-23 WAN outage, at least 30 minutes
	systemd-inhibit --what=sleep:handle-lid-switch --who=vaurora --why="chaos test" python3 tests/resilience/chaos_test.py --minutes 35

resources: ## RT-22 per-container edge resources and bandwidth
	python3 tests/resilience/measure_edge.py --minutes 10

incident: ## Reproduce INC-VA-0712 and collect forensic evidence
	scripts/run_incident.sh "$(EXAMINER)"

mail: ## RT-10 SPF, DKIM, DMARC
	scripts/run_mail_auth_test.sh

phishing: ## RT-11 pipeline validation with scripted personas
	scripts/run_phishing_lab.sh --personas

llm: ## RT-16/17 LLM metrics and prompt injection (downloads the model once)
	scripts/pull_model.sh
	$(COMPOSE) --profile llm up -d ollama llm-triage
	$(COMPOSE) --profile llm exec -T llm-triage python -u evaluate.py

a11y: ## RT-21 axe-core in a real browser, plus screenshots
	docker build -q -t vaurora/a11y:1.0 tests/accessibility
	docker run --rm --network vaurora_cloud -v "$$PWD/secrets/lab/demo_users.json:/lab/demo_users.json:ro" -v "$$PWD/docs/results:/results" vaurora/a11y:1.0

evidence: ## Full run of every suite on the current code, about 90 minutes, then rebuilds evidence/
	scripts/run_all_evidence.sh "$(EXAMINER)"
