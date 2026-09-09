# Architecture

## Objective

This project models a defensive cloud secrets-management posture review using synthetic inventory only. It does not connect to live AWS, Azure, GCP, CI/CD, vault, or production environments.

## Components

1. `src/models.py` — provider-neutral immutable data models and strict validation.
2. `src/assessment.py` — deterministic control evaluation and posture scoring.
3. `src/reporting.py` — fleet-level metrics and evidence-preserving Markdown reporting.
4. `data/synthetic_inventory.json` — realistic but non-operational test inventory.
5. `tests/test_assessment.py` — behavioral tests for controls, validation, deduplication, and score bounds.
6. `.github/workflows/security-quality.yml` — least-privilege CI for compilation and unit tests.

## Data Flow

`Synthetic inventory -> validation -> canonical SecretRecord objects -> control evaluation -> Finding objects -> posture metrics -> Markdown report`

## Design Principles

- Fail closed on malformed schemas and duplicate secret identifiers.
- Keep exploitability context separate from evidence of compromise.
- Preserve the exact control, affected object, severity, evidence, remediation, and ATT&CK context for each finding.
- Prefer short-lived/federated workload identity over long-lived static credentials where technically supported.
- Treat ownership, logging, rotation, encryption, and access policy as independent governance dimensions.
- Avoid provider-specific API dependencies so assessment logic remains easy to test and extend.

## Security Boundaries

The lab intentionally excludes secret values, cloud credentials, live policy enumeration, vault access, key extraction, production targeting, credential reuse, brute force, exfiltration, or exploit code. Only metadata sufficient to demonstrate defensive posture analysis is represented.
