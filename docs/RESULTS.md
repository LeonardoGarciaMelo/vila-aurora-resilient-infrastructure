# Measured Results

Figures from the final run of the code in this repository. Raw outputs are indexed in
[evidence/README.md](../evidence/README.md). Regenerate everything with `make evidence`.

Environment: Docker containers on one developer workstation. All data is synthetic.

## Security suite

56 checks passed, 0 failed (`make security`).

| Scenario | Rule | MTTD (s) | MTTR (s) |
| --- | --- | --- | --- |
| stolen vpn key from unknown ip | 100101 | 3.91 | 0.97 |
| sql injection through tunnel | 100110 | 0.47 | 0.97 |
| rogue device without certificate | 100120 | 2.85 | 1.1 |
| pump command at 0240 | 100130 | 1.28 | 1.1 |
| **Mean** | | **2.13** | **1.04** |

The lab has little traffic and a local log path, so expect slower times in production.

## Resilience

| Indicator | Result |
| --- | --- |
| WAN outage, Escola and UBS | 35.47 min, no host pause (largest gap 30.9 s) |
| Readings generated / received | 2538 / 2538 |
| Loss | 0.0% |
| Duplicates | 0 |
| Reconciliation | Escola 14.3 s, UBS 11.0 s |
| Cold alarm after injected fault | 312.7 s, with no internet (the rule waits 300 s) |
| Availability of brokers and panel | 100.0% over 37.0 min only |
| Edge CPU, UBS, mean | 0.25% of one core |
| Edge memory, UBS, mean | 30.5 MB |

## AI

| Metric | IsolationForest | LLM triage |
| --- | --- | --- |
| Precision | 0.6335 | 1.0 |
| Recall | 0.9889 | 0.9 |
| F1 | 0.7722 | 0.9474 |
| False positive rate | 0.0511 | 0.0 |
| Test set | 2196 windows, 180 anomalies | 40 e-mails |

The anomaly model's false positive rate is high for volunteers, so it only alerts a person. Prompt injection:
9 of 9 attacks stayed within their criterion. In PI-07 no personal data leaked, but the
message was wrongly classified as legitimate.

## Accessibility

axe-core found 0 WCAG 2.1 A/AA violations across 7 pages. Automated tools cover only part of WCAG.

## Forensics

Tank went from 80.0% to 0.0%, and 40 synthetic records were extracted. All 8 evidence hashes verified.

## Not measured or not done

- **Energy of the edge:** needs hardware and a power meter. The report gives an estimate.
- **Training effect:** one team member acted on all test accounts, knowing the simulation. Round 1: 75.0% opened, 55.0% clicked, 20.0% submitted, 15.0% reported. Round 2, with a report link added to the e-mail: 100.0% opened, 0.0% clicked, 0.0% submitted, 85.0% reported. These figures do not measure training.
- **Full RAM forensics (Volatility 3):** only one process's memory was captured, to avoid imaging the host.
- **plaso and garak:** not run. A project script builds the timeline, and the prompt injection attacks were written by hand.
- **Synthetic voice sample:** needs a team member's written consent.
- **Long-term availability:** the figure covers minutes, not days.
- **Designed but not implemented:** WebAuthn, immutable log storage and automatic backup, automatic retention, automatic certificate renewal and expiry alerts, e-mail alerts, signed OTA, Wazuh Dashboard, MQTT rate limits.
