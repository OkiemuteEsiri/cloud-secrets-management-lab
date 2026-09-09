# Cloud Secrets Management Security Lab

Defensive cloud security engineering project for assessing the governance and exposure posture of managed secrets and long-lived credentials across synthetic AWS-, Azure-, GCP-, and provider-neutral inventories.

The project is intentionally metadata-only: it never stores secret values, authenticates to cloud providers, extracts credentials, or targets production systems. Its purpose is to demonstrate how a security engineer can turn secrets-management metadata into explainable findings, prioritized remediation, measurable posture, and evidence-based revalidation.

## Problem Statement

Secrets programs frequently fail because organizations treat credential storage as a binary question—"is it in a vault?"—instead of evaluating the full lifecycle. Material risk can remain when a stored secret is publicly accessible, over-permissioned, overdue for rotation, weakly governed, poorly logged, unowned, or still used as a long-lived static credential even though federated workload identity is available.

This lab models those risks as independent controls and produces deterministic findings without relying on confidential infrastructure or unsupported assumptions.

## Security Engineering Objectives

- Normalize provider-neutral metadata into validated immutable models.
- Detect high-impact access, encryption, lifecycle, logging, and ownership weaknesses.
- Prefer workload identity and short-lived credentials where technically supported.
- Separate configuration exposure from evidence of compromise.
- Preserve control-level evidence and remediation guidance.
- Produce a bounded posture score suitable for trend analysis, not compliance certification.
- Require revalidation before a finding is considered remediated.

## Implemented Controls

| ID | Control | Primary Risk |
|---|---|---|
| CSM-001 | Public or anonymous secret access | Direct unauthorized retrieval path |
| CSM-002 | Broad principal access | Excessive privilege and credential exposure |
| CSM-003 | Encryption disabled | Secret material insufficiently protected at rest |
| CSM-004 | Production secret without customer-managed key | Reduced key-governance separation where stronger control is justified |
| CSM-005 | Rotation overdue | Extended credential exposure window |
| CSM-006 | Access logging disabled | Reduced investigation, accountability, and detection capability |
| CSM-007 | Versioning disabled | Weaker controlled rotation and rollback |
| CSM-008 | Static credential despite workload identity support | Avoidable long-lived credential risk |
| CSM-009 | Missing accountable owner | Weak lifecycle and remediation governance |

## Architecture

```text
Synthetic JSON inventory
        |
        v
Strict schema + timestamp validation
        |
        v
Immutable SecretRecord objects
        |
        v
Deterministic control engine
        |
        +--> Finding objects
        |      - control ID
        |      - severity
        |      - evidence
        |      - remediation
        |      - ATT&CK context
        |
        v
Fleet metrics + bounded posture score
        |
        v
Markdown reporting / remediation workflow
```

### Repository Structure

```text
.
├── .github/workflows/security-quality.yml
├── data/synthetic_inventory.json
├── docs/
│   ├── architecture.md
│   ├── methodology.md
│   └── remediation-validation.md
├── reports/example-assessment.md
├── src/
│   ├── __init__.py
│   ├── assessment.py
│   ├── models.py
│   └── reporting.py
└── tests/test_assessment.py
```

## Risk Model

Severity is explainable and contextual rather than randomly weighted. Examples:

- Public/anonymous access: **Critical**
- Broad principal access in production: **Critical**
- Encryption disabled: **Critical**
- Overdue static production credential: **High**
- Missing production access logging: **High**
- Static credential where workload identity is available: **High** in production
- Governance weaknesses such as missing versioning or ownership: **Medium**

The posture score is a 0–100 engineering indicator derived from weighted findings per assessed object. It is designed for comparative posture tracking and prioritization. It is not a compliance certification, exploit probability, or claim of compromise.

## MITRE ATT&CK Context

Mappings are used only to explain defensive relevance:

- **T1552.001 — Unsecured Credentials: Credentials In Files**: contextualizes risks associated with unmanaged or long-lived credential material.
- **T1078 / T1078.004 — Valid Accounts / Cloud Accounts**: relevant where exposed credentials could enable authenticated cloud access.
- **T1098 — Account Manipulation**: relevant to excessive or broadly delegated identity permissions.
- **T1562.008 — Impair Defenses: Disable or Modify Cloud Logs**: relevant where secret-access telemetry is unavailable.

A mapped technique does **not** mean the technique occurred.

## Synthetic Dataset

`data/synthetic_inventory.json` contains deliberately fictional records representing several posture conditions:

- a production workload using a static credential despite workload-identity support;
- a production credential with broad access, overdue rotation, weak logging, and weak version governance;
- a lower-risk staging credential;
- a legacy development integration illustrating multiple severe governance failures.

No real credential values, cloud account identifiers, client data, employer data, or production metadata are included.

## Running the Tests

The implementation has no third-party Python dependencies.

```bash
python -m compileall -q src
python -m unittest discover -s tests -v
python -m json.tool data/synthetic_inventory.json > /dev/null
```

The unit tests cover:

- secure baseline behavior;
- public-access severity;
- production broad-access severity;
- overdue rotation logic;
- workload-identity migration detection;
- ownership governance;
- duplicate-ID fail-closed behavior;
- posture-score bounds.

## Remediation and Validation

The workflow intentionally distinguishes **change made** from **risk removed**.

Typical remediation sequence:

1. Confirm the effective configuration and affected consumers.
2. Remove public or anonymous access first when present.
3. Replace wildcard/broad principals with named least-privilege identities.
4. Rotate stale credentials through a staged deployment.
5. Migrate long-lived credentials to workload identity or another short-lived mechanism where supported.
6. Enable logging, encryption, versioning, and accountable ownership.
7. Validate approved workload access still succeeds.
8. Validate unauthorized access is denied.
9. Confirm audit telemetry is generated.
10. Re-run the assessment and ensure the original control no longer reproduces.

Detailed closure evidence and exception governance are documented in `docs/remediation-validation.md`.

## CI/CD Security Checks

GitHub Actions uses read-only repository permissions and currently verifies:

- Python source compilation;
- unit-test execution;
- synthetic JSON inventory validity.

The workflow deliberately avoids cloud credentials and live integrations.

## Design Decisions

### Provider-neutral assessment model

Provider-specific APIs are intentionally separated from control logic. This makes the assessment engine deterministic, testable, and extensible to different secret stores without binding the project to one vendor.

### Metadata-only processing

A posture engine rarely needs secret values. Keeping values out of scope minimizes exposure and demonstrates data-minimization principles.

### Fail-closed input handling

Malformed timestamps, unsupported providers/environments, missing required fields, invalid rotation intervals, and duplicate secret identifiers raise explicit errors rather than silently degrading assessment quality.

### Evidence before closure

A ticket status is not treated as proof that risk was removed. The project defines revalidation evidence for access policy, credential rotation, workload health, revocation, logging, ownership, and repeat assessment.

## Skills Demonstrated

- Cloud security engineering
- Secrets-management governance
- Identity and least-privilege analysis
- Credential lifecycle risk management
- Defensive security automation
- Python data modeling and validation
- Explainable risk scoring
- Security reporting
- Remediation engineering
- Control revalidation
- MITRE ATT&CK contextual mapping
- Unit testing and CI/CD security hygiene

## Limitations

This is a synthetic engineering lab, not a cloud scanner or production CSPM platform. It does not:

- enumerate live secret stores;
- retrieve or inspect secret values;
- authenticate to AWS, Azure, GCP, CI/CD systems, or vault products;
- prove that an exposed credential was exploited;
- replace provider-native IAM analysis or enterprise secrets-management tooling;
- calculate financial impact or formal regulatory compliance.

Those boundaries are intentional and keep the project safe, reproducible, and portfolio-appropriate.

## Roadmap

Planned safe extensions include:

- provider adapters that consume sanitized exported metadata rather than live credentials;
- policy-as-code mappings for organizational rotation and ownership standards;
- trend analysis for posture-score change over time;
- exception-expiry tracking;
- richer control evidence schemas;
- machine-readable JSON output alongside Markdown;
- integration tests for sanitized provider-export formats.

## Safety Statement

This repository is for defensive security engineering and authorized learning. It contains only synthetic data and does not include credentials, secret material, exploit payloads, production targeting, employer/client information, or fabricated compromise claims.
