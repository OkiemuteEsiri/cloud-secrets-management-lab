from __future__ import annotations

from collections import Counter
from typing import Iterable

from .assessment import posture_score
from .models import Finding


def summarize(findings: Iterable[Finding], secret_count: int) -> dict[str, object]:
    items = list(findings)
    by_severity = Counter(item.severity for item in items)
    by_control = Counter(item.control_id for item in items)
    affected = len({item.secret_id for item in items})
    return {
        "secret_count": secret_count,
        "finding_count": len(items),
        "affected_secret_count": affected,
        "affected_secret_percent": round((affected / secret_count * 100), 1) if secret_count else 0.0,
        "posture_score": posture_score(items, secret_count),
        "severity_counts": dict(sorted(by_severity.items())),
        "control_counts": dict(sorted(by_control.items())),
    }


def render_markdown(findings: Iterable[Finding], secret_count: int) -> str:
    items = sorted(list(findings), key=lambda x: ({"critical": 0, "high": 1, "medium": 2, "low": 3}[x.severity], x.secret_id, x.control_id))
    metrics = summarize(items, secret_count)
    lines = [
        "# Cloud Secrets Posture Assessment",
        "",
        "> Synthetic defensive assessment. Findings do not indicate compromise.",
        "",
        "## Executive Summary",
        "",
        f"- Secrets assessed: **{metrics['secret_count']}**",
        f"- Findings: **{metrics['finding_count']}**",
        f"- Affected secrets: **{metrics['affected_secret_count']} ({metrics['affected_secret_percent']}%)**",
        f"- Posture score: **{metrics['posture_score']}/100**",
        "",
        "## Findings",
        "",
        "| Severity | Control | Secret | Finding |",
        "|---|---|---|---|",
    ]
    for item in items:
        lines.append(f"| {item.severity.upper()} | {item.control_id} | `{item.secret_id}` | {item.title} |")

    lines.extend(["", "## Detailed Evidence", ""])
    for item in items:
        techniques = ", ".join(item.attack_techniques) if item.attack_techniques else "N/A"
        lines.extend([
            f"### {item.control_id} — {item.title}",
            f"- **Secret:** `{item.secret_id}`",
            f"- **Severity:** {item.severity.upper()}",
            f"- **Evidence:** {item.evidence}",
            f"- **MITRE ATT&CK context:** {techniques}",
            f"- **Remediation:** {item.remediation}",
            "",
        ])
    return "\n".join(lines).rstrip() + "\n"
