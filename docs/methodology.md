# Assessment Methodology

## Scope

The assessment evaluates metadata about managed secrets and static credentials. It is designed for defensive engineering, governance, exposure reduction, and recruiter-facing demonstration using synthetic records only.

## Control Catalogue

| Control | Risk | Default Severity |
|---|---|---|
| CSM-001 Public/anonymous access | Unauthorized retrieval path | Critical |
| CSM-002 Broad principal access | Excess privilege / lateral exposure | High–Critical |
| CSM-003 Encryption disabled | Secret material exposed at rest | Critical |
| CSM-004 No customer-managed key in production | Reduced key governance where stronger separation may be required | Medium |
| CSM-005 Rotation overdue | Extended credential exposure window | Medium–High |
| CSM-006 Access logging disabled | Reduced investigation and accountability | Medium–High |
| CSM-007 Versioning disabled | Weaker controlled rotation/rollback capability | Medium |
| CSM-008 Static credential despite workload identity support | Avoidable long-lived credential risk | Medium–High |
| CSM-009 Missing owner | Weak accountability and lifecycle governance | Medium |

## Prioritization

Severity is deterministic and contextual. Production environment, broad principal access, static credentials, and direct exposure raise priority. The posture score is a bounded 0–100 engineering indicator based on weighted findings per assessed secret. It is not a compliance certification and does not estimate probability of compromise.

## MITRE ATT&CK Context

Mappings describe defensive relevance only:

- `T1552.001` — Unsecured Credentials: Credentials In Files. Used as context for unmanaged or long-lived secret exposure risk.
- `T1078` / `T1078.004` — Valid Accounts / Cloud Accounts. Relevant when exposed or over-privileged credentials could enable authenticated access.
- `T1098` — Account Manipulation. Relevant to broad or excessive identity permissions.
- `T1562.008` — Impair Defenses: Disable or Modify Cloud Logs. Relevant when secret-access logging is missing or impaired.

A finding does not mean the mapped technique occurred.

## Validation Expectations

A remediation is not considered complete because a ticket is closed or a configuration change was requested. Closure requires evidence that the effective state now satisfies the control, dependent workloads still function, superseded credentials are revoked where appropriate, and audit telemetry confirms the intended access path.
