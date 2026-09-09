from __future__ import annotations

from datetime import datetime, timezone
from typing import Iterable

from .models import Finding, SecretRecord

SEVERITY_WEIGHT = {"low": 1, "medium": 3, "high": 7, "critical": 10}


def assess_secret(secret: SecretRecord, now: datetime | None = None) -> list[Finding]:
    now = now or datetime.now(timezone.utc)
    findings: list[Finding] = []

    if secret.public_or_anonymous_access:
        findings.append(Finding(
            "CSM-001", secret.secret_id, "critical",
            "Public or anonymous secret access is enabled",
            "The inventory marks this secret as accessible through a public or anonymous path.",
            "Remove anonymous/public access, restrict access to named workload or operator identities, and revalidate effective policy.",
            ("T1552.001", "T1078.004"),
        ))

    if secret.broad_principal_access:
        severity = "critical" if secret.environment == "prod" else "high"
        findings.append(Finding(
            "CSM-002", secret.secret_id, severity,
            "Secret is accessible by an overly broad principal set",
            "The access model permits wildcard or broadly scoped principals rather than least-privilege identities.",
            "Replace broad access with workload-specific principals, document justified break-glass access, and test denied access for non-authorized identities.",
            ("T1078.004", "T1098"),
        ))

    if not secret.encrypted:
        findings.append(Finding(
            "CSM-003", secret.secret_id, "critical",
            "Secret is not encrypted at rest",
            "Encryption-at-rest control is disabled in the synthetic inventory.",
            "Enable provider-native encryption, preferably using governed key management, then verify the active secret version is encrypted.",
            ("T1552.001",),
        ))
    elif secret.environment == "prod" and not secret.customer_managed_key:
        findings.append(Finding(
            "CSM-004", secret.secret_id, "medium",
            "Production secret does not use a customer-managed key",
            "The secret is encrypted, but the inventory does not indicate a customer-managed key for production.",
            "Evaluate customer-managed encryption keys where compliance, separation-of-duties, or revocation requirements justify them.",
        ))

    reference = secret.rotated_at or secret.created_at
    age_days = (now - reference).days
    if age_days > secret.rotation_interval_days:
        overdue = age_days - secret.rotation_interval_days
        severity = "high" if secret.static_credential or secret.environment == "prod" else "medium"
        findings.append(Finding(
            "CSM-005", secret.secret_id, severity,
            "Secret rotation is overdue",
            f"Credential age is {age_days} days, exceeding the {secret.rotation_interval_days}-day policy by {overdue} days.",
            "Rotate the credential, update dependent workloads safely, revoke the previous version after validation, and confirm the next rotation deadline.",
            ("T1078", "T1552.001"),
        ))

    if not secret.access_logging_enabled:
        findings.append(Finding(
            "CSM-006", secret.secret_id, "high" if secret.environment == "prod" else "medium",
            "Secret access logging is disabled",
            "The inventory indicates secret access events are not captured for investigation and governance.",
            "Enable provider-native audit logging, route events to a protected log destination, and validate successful and denied access events are observable.",
            ("T1562.008",),
        ))

    if not secret.versioning_enabled:
        findings.append(Finding(
            "CSM-007", secret.secret_id, "medium",
            "Secret versioning is disabled",
            "Version history is unavailable, reducing controlled rotation and rollback capability.",
            "Enable version management and define a bounded retention process that avoids retaining obsolete credentials longer than necessary.",
        ))

    if secret.static_credential and secret.workload_identity_supported:
        findings.append(Finding(
            "CSM-008", secret.secret_id, "high" if secret.environment == "prod" else "medium",
            "Static credential used where workload identity is supported",
            "The workload can use federated or short-lived identity, but a long-lived static secret remains in use.",
            "Migrate to workload identity or another short-lived credential mechanism, validate workload access, then revoke the static secret.",
            ("T1552.001", "T1078.004"),
        ))

    if not secret.owner:
        findings.append(Finding(
            "CSM-009", secret.secret_id, "medium",
            "Secret has no accountable owner",
            "Ownership metadata is empty, weakening rotation, review, and incident-response accountability.",
            "Assign a service or team owner and integrate ownership validation into provisioning and periodic review.",
        ))

    return findings


def assess_inventory(secrets: Iterable[SecretRecord], now: datetime | None = None) -> list[Finding]:
    findings: list[Finding] = []
    seen: set[str] = set()
    for secret in secrets:
        if secret.secret_id in seen:
            raise ValueError(f"duplicate secret_id: {secret.secret_id}")
        seen.add(secret.secret_id)
        findings.extend(assess_secret(secret, now=now))
    return findings


def posture_score(findings: Iterable[Finding], secret_count: int) -> int:
    if secret_count <= 0:
        return 100
    penalty = sum(SEVERITY_WEIGHT[item.severity] for item in findings)
    normalized_penalty = min(100, round((penalty / (secret_count * 20)) * 100))
    return max(0, 100 - normalized_penalty)
