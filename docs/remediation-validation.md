# Remediation and Revalidation Workflow

## 1. Triage

Confirm the affected secret metadata, environment, owner, consumers, access policy, rotation history, and logging state. Validate that the finding is reproducible from the current effective configuration before assigning remediation.

## 2. Containment / Risk Reduction

For critical exposure, remove public or anonymous access first and restrict the secret to named identities. For broad access, replace wildcard principals with workload-specific or operator-specific permissions. Avoid destructive changes that could interrupt dependent services without a tested rollback path.

## 3. Corrective Action

- Enable encryption and governed key management where required.
- Rotate overdue credentials and update dependent workloads using staged deployment.
- Prefer workload identity, federation, or short-lived credentials where supported.
- Enable access logging and protect the log destination from unauthorized modification.
- Enable controlled version management.
- Assign accountable ownership and lifecycle metadata.

## 4. Revalidation

A remediation is accepted only after all applicable checks pass:

1. Effective access policy no longer grants unauthorized/broad access.
2. Required identities can still retrieve the secret through approved paths.
3. Unauthorized identities receive access denial.
4. Current secret version is encrypted as required.
5. New credential version works in dependent workloads.
6. Superseded static credential is revoked after successful migration.
7. Audit logs record successful and denied access events.
8. Ownership and next-rotation date are documented.
9. The assessment is rerun and the original control no longer produces a finding.

## 5. Closure Evidence

Recommended evidence includes configuration snapshots containing no secret values, sanitized policy diffs, rotation timestamps, workload health checks, audit-event identifiers, change/ticket references, and the re-run assessment result.

## Exception Governance

Where remediation is temporarily infeasible, document business justification, accountable owner, compensating controls, risk acceptance authority, review date, and expiry date. Exceptions must not be treated as permanent closure.
