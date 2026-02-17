"""Tests for reporter module."""

from __future__ import annotations

import yaml

from nomotic_ci.config_loader import load_config_from_string, VALID_DIMENSIONS
from nomotic_ci.config_validator import validate
from nomotic_ci.adversarial_runner import run_adversarial_tests
from nomotic_ci.drift_checker import DriftReport, DriftFinding
from nomotic_ci.compound_authority import CompoundAuthorityReport, CompoundAuthorityFinding
from nomotic_ci.reporter import format_pr_comment, format_console_output


def _basic_config_dict() -> dict:
    return {
        "version": "1.0",
        "agents": {
            "agent-a": {
                "scope": {
                    "actions": ["read", "query"],
                    "targets": ["db_a"],
                    "boundaries": ["db_a"],
                },
                "trust": {"initial": 0.5, "minimum_for_action": 0.3},
                "owner": "a@test.com",
                "reason": "test",
            },
        },
        "dimensions": {
            "weights": {dim: 1.0 for dim in VALID_DIMENSIONS},
            "vetoes": ["scope_compliance", "authority_verification"],
        },
        "thresholds": {"allow": 0.7, "deny": 0.3},
        "trust": {
            "success_increment": 0.01,
            "violation_decrement": 0.05,
            "interrupt_cost": 0.03,
            "decay_rate": 0.001,
            "floor": 0.05,
            "ceiling": 0.95,
        },
    }


def _load(data: dict):
    return load_config_from_string(yaml.dump(data))


class TestPRComment:
    """Test PR comment formatting."""

    def test_contains_header(self):
        config = _load(_basic_config_dict())
        report = validate(config)
        comment = format_pr_comment(report, overall_status="pass")
        assert "Nomotic Governance Validation" in comment

    def test_contains_status(self):
        config = _load(_basic_config_dict())
        report = validate(config)
        comment = format_pr_comment(report, overall_status="pass")
        assert "Pass" in comment

    def test_contains_footer(self):
        config = _load(_basic_config_dict())
        report = validate(config)
        comment = format_pr_comment(report, overall_status="pass")
        assert "Nomotic CI" in comment

    def test_fail_status(self):
        config = _load(_basic_config_dict())
        report = validate(config)
        comment = format_pr_comment(report, overall_status="fail")
        assert "Fail" in comment

    def test_with_adversarial(self):
        config = _load(_basic_config_dict())
        validation = validate(config)
        adversarial = run_adversarial_tests(config)
        comment = format_pr_comment(
            validation, adversarial_report=adversarial, overall_status="pass"
        )
        assert "Adversarial Testing" in comment
        assert "Pass rate" in comment

    def test_with_drift(self):
        drift = DriftReport(
            drift_detected=True,
            findings=[
                DriftFinding(
                    category="scope_expansion",
                    severity="warning",
                    path="agents.agent-a.scope.actions",
                    baseline_value="['read']",
                    current_value="['read', 'write']",
                    description="Added 'write' action",
                    risk_assessment="Scope expanded",
                ),
            ],
            critical_count=0,
            warning_count=1,
            info_count=0,
            summary_text="1 change detected",
        )
        config = _load(_basic_config_dict())
        validation = validate(config)
        comment = format_pr_comment(validation, drift_report=drift, overall_status="warn")
        assert "Configuration Drift" in comment
        assert "scope_expansion" in comment or "scope.actions" in comment

    def test_with_compound(self):
        compound = CompoundAuthorityReport(
            findings=[
                CompoundAuthorityFinding(
                    severity="warning",
                    agents_involved=["agent-a", "agent-b"],
                    capabilities_combined=["read", "write"],
                    resulting_capability="effective_update",
                    description="Combined read+write on shared target",
                    mitigation="Restrict shared targets",
                ),
            ],
            critical_count=0,
            warning_count=1,
            cross_agent_risks=[],
            workflow_risks=[],
            summary_text="1 finding",
        )
        config = _load(_basic_config_dict())
        validation = validate(config)
        comment = format_pr_comment(
            validation, compound_report=compound, overall_status="warn"
        )
        assert "Compound Authority" in comment

    def test_no_compound_findings(self):
        compound = CompoundAuthorityReport(summary_text="No findings")
        config = _load(_basic_config_dict())
        validation = validate(config)
        comment = format_pr_comment(
            validation, compound_report=compound, overall_status="pass"
        )
        assert "No compound authority vulnerabilities detected" in comment


class TestConsoleOutput:
    """Test console output formatting."""

    def test_contains_header(self):
        config = _load(_basic_config_dict())
        report = validate(config)
        output = format_console_output(report, overall_status="pass")
        assert "Nomotic Governance Validation" in output

    def test_contains_status(self):
        config = _load(_basic_config_dict())
        report = validate(config)
        output = format_console_output(report, overall_status="fail")
        assert "FAIL" in output

    def test_contains_check_counts(self):
        config = _load(_basic_config_dict())
        report = validate(config)
        output = format_console_output(report, overall_status="pass")
        assert "Checks run" in output
        assert "Issues" in output

    def test_with_adversarial(self):
        config = _load(_basic_config_dict())
        validation = validate(config)
        adversarial = run_adversarial_tests(config)
        output = format_console_output(
            validation, adversarial_report=adversarial, overall_status="pass"
        )
        assert "Adversarial Testing" in output
