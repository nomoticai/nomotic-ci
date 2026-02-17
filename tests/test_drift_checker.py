"""Tests for drift_checker module."""

from __future__ import annotations

from unittest.mock import patch

import yaml

from nomotic_ci.config_loader import load_config_from_string, VALID_DIMENSIONS
from nomotic_ci.drift_checker import check_drift, DriftReport


def _base_config_dict() -> dict:
    """Return a baseline config dict."""
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
            "vetoes": [
                "scope_compliance", "authority_verification",
                "resource_boundaries", "isolation_integrity",
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


def _check_with_baseline(current_data: dict, baseline_data: dict) -> DriftReport:
    """Run drift check with a mocked baseline."""
    current = _load(current_data)

    with patch("nomotic_ci.drift_checker._load_baseline") as mock_load:
        mock_load.return_value = _load(baseline_data)
        return check_drift(current, "origin/main", "nomotic.yaml")


class TestScopeExpansion:
    """Test scope expansion detection."""

    def test_new_action_added(self):
        baseline = _base_config_dict()
        current = _base_config_dict()
        current["agents"]["agent-a"]["scope"]["actions"] = ["read", "query", "write"]

        report = _check_with_baseline(current, baseline)
        assert report.drift_detected
        scope_findings = [f for f in report.findings if f.category == "scope_expansion"]
        assert len(scope_findings) >= 1
        assert any("write" in f.description for f in scope_findings)

    def test_dangerous_action_is_critical(self):
        baseline = _base_config_dict()
        current = _base_config_dict()
        current["agents"]["agent-a"]["scope"]["actions"] = ["read", "query", "delete"]

        report = _check_with_baseline(current, baseline)
        scope_findings = [f for f in report.findings if f.category == "scope_expansion"]
        assert any(f.severity == "critical" for f in scope_findings)

    def test_new_target_added(self):
        baseline = _base_config_dict()
        current = _base_config_dict()
        current["agents"]["agent-a"]["scope"]["targets"] = ["db_a", "db_b"]

        report = _check_with_baseline(current, baseline)
        target_findings = [f for f in report.findings
                          if f.category == "scope_expansion" and "target" in f.path]
        assert len(target_findings) >= 1


class TestThresholdRelaxation:
    """Test threshold relaxation detection."""

    def test_allow_threshold_decreased(self):
        baseline = _base_config_dict()
        current = _base_config_dict()
        current["thresholds"]["allow"] = 0.5  # Decreased from 0.7

        report = _check_with_baseline(current, baseline)
        thresh_findings = [f for f in report.findings if f.category == "threshold_relaxation"]
        assert len(thresh_findings) >= 1
        assert thresh_findings[0].severity == "warning"

    def test_deny_threshold_decreased(self):
        baseline = _base_config_dict()
        current = _base_config_dict()
        current["thresholds"]["deny"] = 0.1  # Decreased from 0.3

        report = _check_with_baseline(current, baseline)
        thresh_findings = [f for f in report.findings if f.category == "threshold_relaxation"]
        assert len(thresh_findings) >= 1


class TestVetoRemoval:
    """Test veto removal detection (always CRITICAL)."""

    def test_veto_removed(self):
        baseline = _base_config_dict()
        current = _base_config_dict()
        current["dimensions"]["vetoes"] = ["scope_compliance"]  # Removed several

        report = _check_with_baseline(current, baseline)
        veto_findings = [f for f in report.findings if f.category == "veto_removal"]
        assert len(veto_findings) >= 1
        assert all(f.severity == "critical" for f in veto_findings)
        assert report.critical_count >= 1


class TestWeightReduction:
    """Test weight reduction detection."""

    def test_security_weight_reduced(self):
        baseline = _base_config_dict()
        current = _base_config_dict()
        current["dimensions"]["weights"]["scope_compliance"] = 0.5  # Reduced from 1.0

        report = _check_with_baseline(current, baseline)
        weight_findings = [f for f in report.findings if f.category == "weight_reduction"]
        assert len(weight_findings) >= 1
        # scope_compliance is security-critical
        assert weight_findings[0].severity == "warning"


class TestAgentChanges:
    """Test agent addition and removal detection."""

    def test_new_agent(self):
        baseline = _base_config_dict()
        current = _base_config_dict()
        current["agents"]["agent-b"] = {
            "scope": {
                "actions": ["read"],
                "targets": ["db_b"],
                "boundaries": ["db_b"],
            },
            "trust": {"initial": 0.5, "minimum_for_action": 0.3},
            "owner": "b@test.com",
            "reason": "test",
        }

        report = _check_with_baseline(current, baseline)
        agent_findings = [f for f in report.findings if f.category == "agent_added"]
        assert len(agent_findings) >= 1
        assert agent_findings[0].severity == "info"

    def test_agent_removed(self):
        baseline = _base_config_dict()
        current = _base_config_dict()
        del current["agents"]["agent-a"]
        # Need at least one agent
        current["agents"]["agent-b"] = {
            "scope": {
                "actions": ["read"],
                "targets": ["db_b"],
                "boundaries": ["db_b"],
            },
            "trust": {"initial": 0.5, "minimum_for_action": 0.3},
            "owner": "b@test.com",
            "reason": "test",
        }

        report = _check_with_baseline(current, baseline)
        removed = [f for f in report.findings if f.category == "agent_removed"]
        assert len(removed) >= 1
        assert removed[0].severity == "info"


class TestTrustRelaxation:
    """Test trust parameter relaxation detection."""

    def test_violation_decrement_decreased(self):
        baseline = _base_config_dict()
        current = _base_config_dict()
        current["trust"]["violation_decrement"] = 0.01  # Decreased from 0.05

        report = _check_with_baseline(current, baseline)
        trust_findings = [f for f in report.findings if f.category == "trust_relaxation"]
        assert len(trust_findings) >= 1
        assert trust_findings[0].severity == "warning"

    def test_success_increment_increased(self):
        baseline = _base_config_dict()
        current = _base_config_dict()
        current["trust"]["success_increment"] = 0.1  # Increased from 0.01

        report = _check_with_baseline(current, baseline)
        trust_findings = [f for f in report.findings if f.category == "trust_relaxation"]
        assert len(trust_findings) >= 1

    def test_ceiling_increased(self):
        baseline = _base_config_dict()
        current = _base_config_dict()
        baseline["trust"]["ceiling"] = 0.90
        current["trust"]["ceiling"] = 0.99

        report = _check_with_baseline(current, baseline)
        trust_findings = [f for f in report.findings if f.category == "trust_relaxation"]
        assert len(trust_findings) >= 1

    def test_floor_decreased(self):
        baseline = _base_config_dict()
        current = _base_config_dict()
        baseline["trust"]["floor"] = 0.10
        current["trust"]["floor"] = 0.01

        report = _check_with_baseline(current, baseline)
        trust_findings = [f for f in report.findings if f.category == "trust_relaxation"]
        assert len(trust_findings) >= 1


class TestNoDrift:
    """Test that identical configs produce no drift."""

    def test_identical(self):
        data = _base_config_dict()
        report = _check_with_baseline(data, data)
        assert not report.drift_detected
        assert len(report.findings) == 0


class TestMissingBaseline:
    """Test handling of missing baseline."""

    def test_missing_baseline(self):
        current = _load(_base_config_dict())
        with patch("nomotic_ci.drift_checker._load_baseline") as mock_load:
            mock_load.return_value = None
            report = check_drift(current, "origin/main", "nomotic.yaml")
        assert not report.drift_detected
        assert "first governance configuration" in report.summary_text


class TestStricterChanges:
    """Test that stricter changes are flagged as INFO not WARNING."""

    def test_allow_threshold_increased(self):
        baseline = _base_config_dict()
        current = _base_config_dict()
        current["thresholds"]["allow"] = 0.9  # Increased (stricter)

        report = _check_with_baseline(current, baseline)
        strict_findings = [f for f in report.findings if f.category == "threshold_strictening"]
        assert len(strict_findings) >= 1
        assert strict_findings[0].severity == "info"
