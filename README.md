# SOC Detections

Windows detection rules written in **Sigma**, converted to **KQL**, mapped to **MITRE ATT&CK** and paired with a **triage playbook** for the analyst who receives the alert.

> Personal learning project. All testing is done with public datasets of simulated attacks; this repository contains no data or information from any real environment.

## Why this project

A detection rule doesn't end when the alert fires. Someone has to receive it, understand what it means, rule out false positives and decide whether to escalate. This repository covers that full path for every detection.

## What each detection includes

- **Sigma rule**: detection logic in a standard, SIEM-agnostic format.
- **MITRE ATT&CK mapping**: the tactic and technique the rule covers.
- **Testing with real data**: the query is validated against public logs of simulated attacks.
- **Triage playbook**: what to check first, common false positives and criteria to close or escalate.

## Detection-as-Code

Rules are managed as code instead of being created by hand in a SIEM console:

- **History**: every change is recorded with author, date and reason.
- **Review**: changes go through a pull request before reaching the main branch.
- **Automated validation**: a GitHub Action checks rule format on every change.

## Coverage

| Rule | Tactic | Technique | Level | Playbook | Tested |
|---|---|---|---|---|---|
| _Work in progress_ | | | | | |

## Structure

| Folder | Contents |
|---|---|
| `rules/` | Sigma rules, organized by platform and log type |
| `playbooks/` | One triage playbook per rule |
| `templates/` | Templates for new rules and playbooks |
| `tests/` | Datasets used and test log |
| `scripts/` | Validation scripts |

## Author

Ferran Mullor Estrach, SOC Analyst.