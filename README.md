# Vila Aurora Resilient Community Infrastructure

Working prototype (deliverable **E2**) for FIAP Global Solution 2026.2, Cybersecurity.

The Vila Aurora Community Network connects a community center, a school, a health clinic (UBS), a
solidarity kitchen and an emergency shelter. In incident INC-VA-0712, a phished password and a VPN with
no MFA led to SQL Injection on the supervision panel. The attacker drained a school water tank, while a fiber outage
silenced the vaccine fridge alarm.

This repository rebuilds that infrastructure as a lab where the attack can be reproduced, then shows it
failing against the hardened design. Everything runs in Docker on isolated networks, using synthetic data.

## Architecture

```
SUPERVISION   Operators (TOTP + RBAC)      Coordination (approves high-impact actions)     Auditor
                     |  only after MFA at the ZTNA portal, through the tunnel
CLOUD         WAF -> Panel v2 -> PostgreSQL (least privilege)     Ingest     Wazuh -> SOAR     AI
              10.60.0.0/24, default deny, reachable only through the hub
                     |  WireGuard: 51820/udp is the hub's only open port
EDGE          One autonomous node per space: Mosquitto mTLS, local rules, SQLite buffer, log shipper
                     |  MQTT over mTLS, one X.509 certificate per device
FIELD         Simulated sensors and actuators (10.10.N.0/24)
```

| Network | Subnet | Members |
| --- | --- | --- |
| IoT, one per space | `10.10.N.0/24` | Field devices, edge node |
| Edge tunnels | `10.50.0.0/24` | WireGuard addresses of the edges |
| Administrative | `10.60.0.0/24` | Hub `.1`, database `.10`, WAF `.20`, panel `.21`, broker `.30`, ingest `.31`, Wazuh `.40`, SOAR `.50` |
| Operators | `10.70.0.0/24` | WireGuard addresses of operators |
| WAN fiber / WAN 4G | `172.30.0.0/24`, `172.31.0.0/24` | Simulated internet paths |
| Legacy | `172.28.0.0/24`, `172.29.0.0/24` | Vulnerable stack used to reproduce the incident |

All networks are `internal: true`, so no container has a route to the internet and the base compose file
publishes no port on the host.

## Requirements

- Linux with Docker Engine and Compose v2. The kernel needs the WireGuard module (mainline since 5.6).
- `make`, `openssl`, `python3`.
- About 6 GB of free RAM, or 10 GB with the LLM. About 15 GB of disk.

Internet access is needed only to build images and download the model.

## Quick start

```bash
make build       # generates secrets on the first run and builds the images
make up          # starts the hardened lab
make status
```

`make build` creates `.env` and `secrets/` with random values. Neither is versioned.

To see the panel in a browser:

```bash
make demo        # publishes on 127.0.0.1 only
```

Open <https://localhost:8443>. The certificate comes from the project CA, so the browser warns about it.
Test accounts and their TOTP seeds are in `secrets/lab/demo_users.json`. To get a current code:

```bash
python3 -c "import pyotp,sys;print(pyotp.TOTP(sys.argv[1]).now())" <totp_secret>
```

The panel text is in Brazilian Portuguese because requirement RT-21 demands it.

## Reproducing the results

Each command stores its output in `docs/results/`.

| Command | What it does | Requirements | Time |
| --- | --- | --- | --- |
| `make security` | mTLS, revocation, VPN, segmentation, SQL Injection, RBAC, detection and response | RT-04 to RT-09, RT-13, RT-15 | 15 min |
| `make chaos` | Cuts the WAN at two edges, injects a fridge fault, measures reconciliation and loss | RT-02, RT-22, RT-23 | 40 min |
| `make resources` | CPU, memory, bandwidth, availability per edge | RT-22 | 10 min |
| `make incident EXAMINER="Your Name"` | Runs the attack on the legacy stack, collects hashed evidence, builds the timeline | RT-14 | 6 min |
| `make mail` | Publishes SPF, DKIM and DMARC in a lab DNS, tests a legitimate and a forged message | RT-10 | 1 min |
| `make phishing` | Runs a Gophish campaign against fictitious accounts with scripted personas | RT-11 | 2 min |
| `make llm` | Measures e-mail triage and attacks it with prompt injection | RT-16, RT-17 | 15 min |
| `make a11y` | Runs axe-core and keyboard checks in a real browser | RT-21 | 1 min |
| `make evidence` | Runs all of the above in sequence, then rebuilds `evidence/`, with system sleep blocked | All | 90 min |

The anomaly detector evaluates itself at startup and writes `docs/results/ai_anomaly_metrics.json`.

The phishing data in `docs/results/phishing_results.json` comes from one team member acting on the test accounts, so it does not measure training. `make phishing` overwrites this file with scripted persona results.

`docs/RESULTS.md` summarizes the measured results and states what was not measured.

## Repository layout

```
attack/             Attack chain for the incident (legacy stack only)
db/                 Schemas and least-privilege roles
docs/               Measured results and machine-readable test output
evidence/           Curated evidence, indexed by requirement
figures/            Images used by the report
forensics/          Evidence collection, chain of custody, timeline
phishing/           Gophish campaign automation
pki/                Project CA: issue, revoke, CRL
scripts/            Bootstrap and run helpers
services/
  edge/             Autonomous edge node
  field-sim/        Simulated devices
  hub/              WireGuard hub, nftables policy, ZTNA portal
  ingest/           Idempotent cloud ingestion
  panel-v2/         Hardened supervision panel
  legacy/           Intentionally vulnerable panel v1, legacy VPN, legacy controller
  siem/             Wazuh rules and decoders
  soar/             Low-risk automated playbooks
  ai/               IsolationForest detector
  llm-triage/       Local LLM e-mail triage with guardrails
  mail-auth/        Lab DNS and receiving MTA
tests/              Security, resilience and accessibility suites
```

## Operations

Revoke a compromised device. The script asks a person to confirm, then each edge applies the new CRL by
itself:

```bash
scripts/revoke_device.sh ubs-coldchamber-01
```

Simulate events:

```bash
docker compose exec edge-escola wan down          # cut every WAN path
docker compose exec edge-escola wan up
docker compose exec edge-ubs wan fiber-down       # cut fiber only, 4G takes over
docker compose exec field-ubs touch /tmp/faults/cold    # fridge starts warming
docker compose exec field-abrigo touch /tmp/faults/flood
```

Stop or erase the lab:

```bash
make down
make reset    # also deletes all volumes
```

## Ethics and scope

- Offensive tools run only against this lab's isolated Docker networks (Law 12.737/2012).
- Phishing simulations target only fictitious accounts created by the team. The landing page stores nothing.
- All personal data is synthetic, generated with Faker. Domains use the reserved `.example` TLD.
- `services/legacy` is vulnerable on purpose. Never expose it.

Known limits of the prototype are listed in `docs/RESULTS.md`.
