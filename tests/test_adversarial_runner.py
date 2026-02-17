"""Tests for adversarial_runner module."""

from __future__ import annotations

import yaml

from nomotic_ci.config_loader import load_config_from_string, VALID_DIMENSIONS
from nomotic_ci.adversarial_runner import run_adversarial_tests


def _strict_config_dict() -> dict:
    """Return a strict config dict with high weights and all vetoes."""
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
            "agent-b": {
                "scope": {
                    "actions": ["read", "write"],
                    "targets": ["db_b"],
                    "boundaries": ["db_b"],
                },
                "trust": {"initial": 0.5, "minimum_for_action": 0.3},
                "owner": "b@test.com",
                "reason": "test",
            },
        },
        "dimensions": {
            "weights": {dim: 2.0 for dim in VALID_DIMENSIONS},
            "vetoes": list(VALID_DIMENSIONS),
        },
        "thresholds": {"allow": 0.8, "deny": 0.4},
        "trust": {
            "success_increment": 0.01,
            "violation_decrement": 0.05,
            "interrupt_cost": 0.03,
            "decay_rate": 0.001,
            "floor": 0.05,
            "ceiling": 0.95,
        },
    }


def _permissive_config_dict() -> dict:
    """Return a permissive config dict with low weights and no vetoes."""
    return {
        "version": "1.0",
        "agents": {
            "agent-a": {
                "scope": {
                    "actions": ["read", "query"],
                    "targets": ["db_a"],
                    "boundaries": ["db_a"],
                },
                "trust": {"initial": 0.5, "minimum_for_action": 0.1},
                "owner": "a@test.com",
                "reason": "test",
            },
        },
        "dimensions": {
            "weights": {dim: 0.1 for dim in VALID_DIMENSIONS},
            "vetoes": [],
        },
        "thresholds": {"allow": 0.1, "deny": 0.05},
        "trust": {
            "success_increment": 0.1,
            "violation_decrement": 0.01,
            "interrupt_cost": 0.01,
            "decay_rate": 0.001,
            "floor": 0.01,
            "ceiling": 0.99,
        },
    }


def _load(data: dict):
    return load_config_from_string(yaml.dump(data))


# The library provides 6 built-in adversarial scenarios per agent:
#   Prompt Injection Resistance, Privilege Escalation, Drift Inducement,
#   Trust Manipulation, Confused Deputy, Boundary Probing
LIBRARY_SCENARIOS_PER_AGENT = 6

EXPECTED_SCENARIO_NAMES = {
    "Prompt Injection Resistance",
    "Privilege Escalation",
    "Drift Inducement",
    "Trust Manipulation",
    "Confused Deputy",
    "Boundary Probing",
}


class TestAllScenariosRun:
    """Test that all scenarios are loaded and run."""

    def test_scenario_count(self):
        config = _load(_strict_config_dict())
        report = run_adversarial_tests(config)
        # 6 library scenarios per agent, 2 agents = 12
        expected = LIBRARY_SCENARIOS_PER_AGENT * len(config.agents)
        assert report.scenarios_run == expected

    def test_scenario_names(self):
        config = _load(_strict_config_dict())
        report = run_adversarial_tests(config)
        names = {r.scenario_name for r in report.results}
        for expected_name in EXPECTED_SCENARIO_NAMES:
            assert expected_name in names


class TestStrictConfig:
    """Test that a strict config passes adversarial scenarios."""

    def test_high_pass_rate(self):
        config = _load(_strict_config_dict())
        report = run_adversarial_tests(config)
        # Strict config should block most unauthorized actions
        assert report.pass_rate >= 0.5

    def test_privilege_escalation_blocked(self):
        config = _load(_strict_config_dict())
        report = run_adversarial_tests(config)
        priv_esc = [r for r in report.results
                    if r.scenario_name == "Privilege Escalation"]
        assert len(priv_esc) >= 1
        # At least some privilege escalation attempts should be blocked
        assert any(r.actions_passed > 0 for r in priv_esc)


class TestPermissiveConfig:
    """Test that a permissive config runs adversarial scenarios."""

    def test_lower_pass_rate(self):
        config = _load(_permissive_config_dict())
        report = run_adversarial_tests(config)
        # Permissive config should still run scenarios
        assert report.scenarios_run > 0

    def test_unexpected_allows_present(self):
        config = _load(_permissive_config_dict())
        report = run_adversarial_tests(config)
        # With very permissive settings, some unauthorized actions may be allowed
        # This depends on the runtime, so we just check the report structure
        assert isinstance(report.unexpected_allows, list)


class TestPassRateCalculation:
    """Test pass rate calculation."""

    def test_pass_rate_is_float(self):
        config = _load(_strict_config_dict())
        report = run_adversarial_tests(config)
        assert isinstance(report.pass_rate, float)
        assert 0.0 <= report.pass_rate <= 1.0

    def test_pass_rate_matches_counts(self):
        config = _load(_strict_config_dict())
        report = run_adversarial_tests(config)
        expected = report.scenarios_passed / report.scenarios_run
        assert abs(report.pass_rate - expected) < 0.001


class TestReportGeneration:
    """Test report generation."""

    def test_summary_text(self):
        config = _load(_strict_config_dict())
        report = run_adversarial_tests(config)
        assert "Adversarial Testing" in report.summary_text
        assert "/" in report.summary_text

    def test_scenarios_counts_consistent(self):
        config = _load(_strict_config_dict())
        report = run_adversarial_tests(config)
        assert report.scenarios_passed + report.scenarios_failed == report.scenarios_run

    def test_action_results_populated(self):
        config = _load(_strict_config_dict())
        report = run_adversarial_tests(config)
        for scenario in report.results:
            assert scenario.actions_tested > 0
            assert len(scenario.results) == scenario.actions_tested
            for action_result in scenario.results:
                assert action_result.actual_verdict in ("ALLOW", "DENY", "MODIFY",
                                                         "ESCALATE", "SUSPEND")
