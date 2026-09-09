from datetime import datetime, timezone
import unittest

from src.assessment import assess_inventory, assess_secret, posture_score
from src.models import SecretRecord


NOW = datetime(2026, 9, 10, tzinfo=timezone.utc)


def make_secret(**overrides):
    base = {
        "secret_id": "synthetic-secret-1",
        "provider": "aws",
        "environment": "prod",
        "owner": "platform-team",
        "created_at": "2026-08-01T00:00:00Z",
        "rotated_at": "2026-08-15T00:00:00Z",
        "rotation_interval_days": 90,
        "encrypted": True,
        "customer_managed_key": True,
        "versioning_enabled": True,
        "access_logging_enabled": True,
        "public_or_anonymous_access": False,
        "broad_principal_access": False,
        "workload_identity_supported": False,
        "static_credential": False,
        "tags": ["synthetic"],
    }
    base.update(overrides)
    return SecretRecord.from_dict(base)


class SecretsAssessmentTests(unittest.TestCase):
    def test_secure_record_has_no_findings(self):
        self.assertEqual(assess_secret(make_secret(), now=NOW), [])

    def test_public_access_is_critical(self):
        findings = assess_secret(make_secret(public_or_anonymous_access=True), now=NOW)
        item = next(f for f in findings if f.control_id == "CSM-001")
        self.assertEqual(item.severity, "critical")

    def test_broad_prod_access_is_critical(self):
        findings = assess_secret(make_secret(broad_principal_access=True), now=NOW)
        item = next(f for f in findings if f.control_id == "CSM-002")
        self.assertEqual(item.severity, "critical")

    def test_overdue_static_prod_secret_is_high(self):
        secret = make_secret(
            rotated_at="2026-01-01T00:00:00Z",
            rotation_interval_days=30,
            static_credential=True,
        )
        findings = assess_secret(secret, now=NOW)
        item = next(f for f in findings if f.control_id == "CSM-005")
        self.assertEqual(item.severity, "high")
        self.assertIn("exceeding", item.evidence)

    def test_static_secret_flags_when_workload_identity_supported(self):
        findings = assess_secret(
            make_secret(static_credential=True, workload_identity_supported=True),
            now=NOW,
        )
        self.assertTrue(any(f.control_id == "CSM-008" for f in findings))

    def test_missing_owner_is_reported(self):
        findings = assess_secret(make_secret(owner=""), now=NOW)
        self.assertTrue(any(f.control_id == "CSM-009" for f in findings))

    def test_duplicate_ids_fail_closed(self):
        secret = make_secret()
        with self.assertRaisesRegex(ValueError, "duplicate secret_id"):
            assess_inventory([secret, secret], now=NOW)

    def test_posture_score_is_bounded(self):
        findings = assess_secret(
            make_secret(
                public_or_anonymous_access=True,
                broad_principal_access=True,
                encrypted=False,
                versioning_enabled=False,
                access_logging_enabled=False,
                static_credential=True,
                workload_identity_supported=True,
                owner="",
            ),
            now=NOW,
        )
        score = posture_score(findings, 1)
        self.assertGreaterEqual(score, 0)
        self.assertLessEqual(score, 100)


if __name__ == "__main__":
    unittest.main()
