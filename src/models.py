from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any

VALID_PROVIDERS = {"aws", "azure", "gcp", "generic"}
VALID_ENVIRONMENTS = {"dev", "test", "staging", "prod"}
VALID_SEVERITIES = {"low", "medium", "high", "critical"}


def parse_timestamp(value: str) -> datetime:
    if not isinstance(value, str) or not value.strip():
        raise ValueError("timestamp must be a non-empty ISO-8601 string")
    normalized = value.replace("Z", "+00:00")
    parsed = datetime.fromisoformat(normalized)
    if parsed.tzinfo is None:
        raise ValueError("timestamp must include timezone information")
    return parsed.astimezone(timezone.utc)


@dataclass(frozen=True)
class SecretRecord:
    secret_id: str
    provider: str
    environment: str
    owner: str
    created_at: datetime
    rotated_at: datetime | None
    rotation_interval_days: int
    encrypted: bool
    customer_managed_key: bool
    versioning_enabled: bool
    access_logging_enabled: bool
    public_or_anonymous_access: bool
    broad_principal_access: bool
    workload_identity_supported: bool
    static_credential: bool
    tags: tuple[str, ...]

    @classmethod
    def from_dict(cls, raw: dict[str, Any]) -> "SecretRecord":
        required = {
            "secret_id", "provider", "environment", "owner", "created_at",
            "rotation_interval_days", "encrypted", "customer_managed_key",
            "versioning_enabled", "access_logging_enabled",
            "public_or_anonymous_access", "broad_principal_access",
            "workload_identity_supported", "static_credential", "tags",
        }
        missing = sorted(required - raw.keys())
        if missing:
            raise ValueError(f"missing required fields: {', '.join(missing)}")

        secret_id = str(raw["secret_id"]).strip()
        provider = str(raw["provider"]).strip().lower()
        environment = str(raw["environment"]).strip().lower()
        owner = str(raw["owner"]).strip()
        rotation_interval_days = int(raw["rotation_interval_days"])

        if not secret_id:
            raise ValueError("secret_id must not be empty")
        if provider not in VALID_PROVIDERS:
            raise ValueError(f"unsupported provider: {provider}")
        if environment not in VALID_ENVIRONMENTS:
            raise ValueError(f"unsupported environment: {environment}")
        if rotation_interval_days <= 0:
            raise ValueError("rotation_interval_days must be greater than zero")
        if not isinstance(raw["tags"], list):
            raise ValueError("tags must be a list")

        rotated_at = raw.get("rotated_at")
        return cls(
            secret_id=secret_id,
            provider=provider,
            environment=environment,
            owner=owner,
            created_at=parse_timestamp(raw["created_at"]),
            rotated_at=parse_timestamp(rotated_at) if rotated_at else None,
            rotation_interval_days=rotation_interval_days,
            encrypted=bool(raw["encrypted"]),
            customer_managed_key=bool(raw["customer_managed_key"]),
            versioning_enabled=bool(raw["versioning_enabled"]),
            access_logging_enabled=bool(raw["access_logging_enabled"]),
            public_or_anonymous_access=bool(raw["public_or_anonymous_access"]),
            broad_principal_access=bool(raw["broad_principal_access"]),
            workload_identity_supported=bool(raw["workload_identity_supported"]),
            static_credential=bool(raw["static_credential"]),
            tags=tuple(str(tag).strip() for tag in raw["tags"] if str(tag).strip()),
        )


@dataclass(frozen=True)
class Finding:
    control_id: str
    secret_id: str
    severity: str
    title: str
    evidence: str
    remediation: str
    attack_techniques: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if self.severity not in VALID_SEVERITIES:
            raise ValueError(f"unsupported severity: {self.severity}")
