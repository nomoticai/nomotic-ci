"""Generate compliance evidence bundles for governance configuration changes.

Creates a structured evidence package documenting what governance rules changed,
what validation was performed, what adversarial tests were run, and what the
results were. This is the 'governed adaptation' concept — governance changes
are themselves governed and evidenced.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

from nomotic_ci.config_loader import GovernanceConfig
from nomotic_ci.config_validator import ValidationReport
from nomotic_ci.adversarial_runner import AdversarialReport
from nomotic_ci.drift_checker import DriftReport
from nomotic_ci.compound_authority import CompoundAuthorityReport


@dataclass
class EvidenceBundle:
    """A compliance evidence bundle."""

    bundle_id: str
    timestamp: str
    config_source: str
    config_version: str
    compliance_frameworks: list[str]
    validation_summary: dict
    adversarial_summary: dict | None
    drift_summary: dict | None
    compound_authority_summary: dict | None
    bundle_hash: str = ""
    bundle_path: str = ""


# Patterns for sensitive data sanitization — specific patterns first, generic last
SENSITIVE_PATTERNS = [
    (re.compile(r"ghp_[a-zA-Z0-9]{36}"), "[GITHUB_TOKEN_REDACTED]"),
    (re.compile(r"sk-[a-zA-Z0-9]{32,}"), "[API_KEY_REDACTED]"),
    (re.compile(r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}"), "[EMAIL_REDACTED]"),
    (re.compile(r"(?i)(password|secret|token|key)\s*[:=]\s*(?!\[)(\S+)"), r"\1: [REDACTED]"),
]


def generate_bundle(
    config: GovernanceConfig,
    validation_report: ValidationReport,
    adversarial_report: AdversarialReport | None = None,
    drift_report: DriftReport | None = None,
    compound_report: CompoundAuthorityReport | None = None,
    compliance_frameworks: list[str] | None = None,
    bundle_dir: str = ".nomotic/bundles",
    sanitize: bool = True,
) -> EvidenceBundle:
    """Generate a compliance evidence bundle.

    Args:
        config: The governance configuration being validated.
        validation_report: Results from config validation.
        adversarial_report: Results from adversarial testing (optional).
        drift_report: Results from drift detection (optional).
        compound_report: Results from compound authority analysis (optional).
        compliance_frameworks: Frameworks to tag the bundle with.
        bundle_dir: Directory to write the bundle to.
        sanitize: Whether to sanitize sensitive data.

    Returns:
        An EvidenceBundle with the path to the written bundle.
    """
    now = datetime.now(timezone.utc)
    bundle_id = f"nci-{now.strftime('%Y%m%d-%H%M%S')}-{os.getpid()}"

    frameworks = compliance_frameworks or config.compliance_frameworks

    # Build validation summary
    validation_summary = {
        "status": validation_report.status,
        "checks_run": validation_report.checks_run,
        "issues_found": validation_report.issues_found,
        "critical_count": validation_report.critical_count,
        "warning_count": validation_report.warning_count,
        "info_count": validation_report.info_count,
        "issues": [
            {
                "severity": issue.severity,
                "check_name": issue.check_name,
                "message": issue.message,
                "location": issue.location,
                "remediation": issue.remediation,
            }
            for issue in validation_report.issues
        ],
    }

    # Build adversarial summary
    adversarial_summary = None
    if adversarial_report is not None:
        adversarial_summary = {
            "scenarios_run": adversarial_report.scenarios_run,
            "scenarios_passed": adversarial_report.scenarios_passed,
            "scenarios_failed": adversarial_report.scenarios_failed,
            "pass_rate": adversarial_report.pass_rate,
            "unexpected_allows": adversarial_report.unexpected_allows,
            "scenario_results": [
                {
                    "name": r.scenario_name,
                    "passed": r.passed,
                    "actions_tested": r.actions_tested,
                    "actions_passed": r.actions_passed,
                }
                for r in adversarial_report.results
            ],
        }

    # Build drift summary
    drift_summary = None
    if drift_report is not None:
        drift_summary = {
            "drift_detected": drift_report.drift_detected,
            "critical_count": drift_report.critical_count,
            "warning_count": drift_report.warning_count,
            "info_count": drift_report.info_count,
            "findings": [
                {
                    "category": f.category,
                    "severity": f.severity,
                    "path": f.path,
                    "description": f.description,
                }
                for f in drift_report.findings
            ],
        }

    # Build compound authority summary
    compound_summary = None
    if compound_report is not None:
        compound_summary = {
            "critical_count": compound_report.critical_count,
            "warning_count": compound_report.warning_count,
            "findings_count": len(compound_report.findings),
            "findings": [
                {
                    "severity": f.severity,
                    "agents_involved": f.agents_involved,
                    "resulting_capability": f.resulting_capability,
                    "description": f.description,
                }
                for f in compound_report.findings
            ],
        }

    bundle = EvidenceBundle(
        bundle_id=bundle_id,
        timestamp=now.isoformat(),
        config_source=config.source_path,
        config_version=config.version,
        compliance_frameworks=frameworks,
        validation_summary=validation_summary,
        adversarial_summary=adversarial_summary,
        drift_summary=drift_summary,
        compound_authority_summary=compound_summary,
    )

    # Serialize to JSON
    bundle_data = {
        "bundle_id": bundle.bundle_id,
        "timestamp": bundle.timestamp,
        "config_source": bundle.config_source,
        "config_version": bundle.config_version,
        "compliance_frameworks": bundle.compliance_frameworks,
        "validation": bundle.validation_summary,
        "adversarial_testing": bundle.adversarial_summary,
        "drift_detection": bundle.drift_summary,
        "compound_authority": bundle.compound_authority_summary,
    }

    bundle_json = json.dumps(bundle_data, indent=2, default=str)

    if sanitize:
        bundle_json = _sanitize(bundle_json)

    # Compute hash
    bundle.bundle_hash = hashlib.sha256(bundle_json.encode()).hexdigest()
    bundle_data["bundle_hash"] = bundle.bundle_hash
    bundle_json = json.dumps(bundle_data, indent=2, default=str)

    if sanitize:
        bundle_json = _sanitize(bundle_json)

    # Write to disk
    bundle_path = Path(bundle_dir)
    bundle_path.mkdir(parents=True, exist_ok=True)
    file_path = bundle_path / f"{bundle_id}.json"
    file_path.write_text(bundle_json)
    bundle.bundle_path = str(file_path)

    return bundle


def _sanitize(text: str) -> str:
    """Sanitize sensitive data from the bundle text."""
    for pattern, replacement in SENSITIVE_PATTERNS:
        text = pattern.sub(replacement, text)
    return text
