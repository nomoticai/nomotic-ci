"""Integration tests for the full nomotic-ci pipeline."""

from __future__ import annotations

from unittest.mock import patch

import yaml

from nomotic_ci.config_loader import load_config_from_string, VALID_DIMENSIONS
from nomotic_ci.config_validator import validate
from nomotic_ci.adversarial_runner import run_adversarial_tests
from nomotic_ci.drift_checker import check_drift
from nomotic_ci.compound_authority import analyze_compound_authority
from nomotic_ci.reporter import format_pr_comment, format_console_output


def _valid_config_dict() -> dict:
    """A valid, well-configured governance config."""
    return {
        "version": "1.0",
        "agents": {
            "reader-agent": {
                "scope": {
                    "actions": ["read", "query"],
                    "targets": ["public_db"],
                    "boundaries": ["public_db"],
                },
                "trust": {"initial": 0.5, "minimum_for_action": 0.3},
                "owner": "reader@test.com",
                "reason": "Read-only analytics",
            },
            "writer-agent": {
                "scope": {
                    "actions": ["read", "write"],
                    "targets": ["app_db"],
                    "boundaries": ["app_db"],
                },
                "trust": {"initial": 0.5, "minimum_for_action": 0.4},
                "owner": "writer@test.com",
                "reason": "Application writes",
            },
        },
        "dimensions": {
            "weights": {
                "scope_compliance": 2.0,
                "authority_verification": 2.0,
                "resource_boundaries": 1.2,
                "behavioral_consistency": 1.0,
                "cascading_impact": 1.3,
                "stakeholder_impact": 1.2,
                "incident_detection": 1.5,
                "isolation_integrity": 1.8,
                "temporal_compliance": 0.8,
                "precedent_alignment": 0.7,
                "transparency": 0.6,
                "human_override": 2.0,
                "ethical_alignment": 2.0,
            },
            "vetoes": [
                "scope_compliance",
                "authority_verification",
                "resource_boundaries",
                "incident_detection",
                "isolation_integrity",
                "temporal_compliance",
                "human_override",
                "ethical_alignment",
            ],
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


class TestEndToEndValidConfig:
    """End-to-end test with a valid configuration."""

    def test_full_pipeline(self):
        """Load -> validate -> adversarial -> compound -> report."""
        config = _load(_valid_config_dict())

        # Validate
        validation = validate(config)
        assert validation.critical_count == 0

        # Adversarial
        adversarial = run_adversarial_tests(config)
        assert adversarial.scenarios_run > 0

        # Compound authority
        compound = analyze_compound_authority(config)
        assert isinstance(compound.findings, list)

        # Report
        overall = "pass" if validation.critical_count == 0 else "fail"
        comment = format_pr_comment(
            validation, adversarial, compound_report=compound,
            overall_status=overall,
        )
        assert "Nomotic Governance Validation" in comment
        assert "Pass" in comment

        console = format_console_output(
            validation, adversarial, compound_report=compound,
            overall_status=overall,
        )
        assert "PASS" in console


class TestEndToEndThresholdInversion:
    """End-to-end test with threshold inversion producing fail."""

    def test_threshold_inversion_fails(self):
        data = _valid_config_dict()
        data["thresholds"]["allow"] = 0.2
        data["thresholds"]["deny"] = 0.8

        config = _load(data)
        validation = validate(config)

        assert validation.critical_count >= 1
        assert validation.status == "fail"

        comment = format_pr_comment(validation, overall_status="fail")
        assert "Fail" in comment


class TestEndToEndVetoRemoval:
    """End-to-end test with veto removal producing fail on drift."""

    def test_veto_removal_drift_critical(self):
        baseline_data = _valid_config_dict()
        current_data = _valid_config_dict()
        # Remove a veto
        current_data["dimensions"]["vetoes"] = ["scope_compliance"]

        current = _load(current_data)

        with patch("nomotic_ci.drift_checker._load_baseline") as mock_load:
            mock_load.return_value = _load(baseline_data)
            drift = check_drift(current, "origin/main", "nomotic.yaml")

        assert drift.drift_detected
        assert drift.critical_count >= 1

        # With fail_on_critical=True, this should produce fail status
        validation = validate(current)
        overall = "fail" if drift.critical_count > 0 else "pass"

        console = format_console_output(
            validation, drift_report=drift, overall_status=overall,
        )
        assert "FAIL" in console


class TestEndToEndAdversarialFailures:
    """End-to-end test with adversarial failures."""

    def test_permissive_config_adversarial(self):
        data = _valid_config_dict()
        # Make config very permissive
        for dim in data["dimensions"]["weights"]:
            data["dimensions"]["weights"][dim] = 0.1
        data["dimensions"]["vetoes"] = []
        data["thresholds"]["allow"] = 0.1
        data["thresholds"]["deny"] = 0.05

        config = _load(data)
        validation = validate(config)
        adversarial = run_adversarial_tests(config)

        # With permissive config, some scenarios may fail
        overall = "fail" if adversarial.scenarios_failed > 0 else "pass"

        console = format_console_output(
            validation, adversarial, overall_status=overall,
        )
        assert "Adversarial Testing" in console


class TestEndToEndDriftWithNoBaseline:
    """End-to-end test with no baseline (first config)."""

    def test_no_baseline_passes(self):
        config = _load(_valid_config_dict())

        with patch("nomotic_ci.drift_checker._load_baseline") as mock_load:
            mock_load.return_value = None
            drift = check_drift(config, "origin/main", "nomotic.yaml")

        assert not drift.drift_detected
        assert "first governance configuration" in drift.summary_text

        validation = validate(config)
        console = format_console_output(
            validation, drift_report=drift, overall_status="pass",
        )
        assert "PASS" in console
