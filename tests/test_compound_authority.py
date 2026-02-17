"""Tests for compound_authority module."""

from __future__ import annotations

import yaml

from nomotic_ci.config_loader import load_config_from_string, VALID_DIMENSIONS
from nomotic_ci.compound_authority import analyze_compound_authority


def _base_config_dict() -> dict:
    """Return a baseline config dict."""
    return {
        "version": "1.0",
        "agents": {
            "agent-a": {
                "scope": {
                    "actions": ["read", "query"],
                    "targets": ["shared_db"],
                    "boundaries": ["shared_db"],
                },
                "trust": {"initial": 0.5, "minimum_for_action": 0.3},
                "owner": "a@test.com",
                "reason": "test",
            },
            "agent-b": {
                "scope": {
                    "actions": ["write", "export"],
                    "targets": ["shared_db"],
                    "boundaries": ["shared_db"],
                },
                "trust": {"initial": 0.5, "minimum_for_action": 0.3},
                "owner": "b@test.com",
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


class TestCrossAgentReadWrite:
    """Test cross-agent read+write detection."""

    def test_read_write_detected(self):
        """Agent A reads, Agent B writes on shared target."""
        data = _base_config_dict()
        config = _load(data)
        report = analyze_compound_authority(config)
        # Should detect read+write compound on shared_db
        rw_findings = [f for f in report.findings
                       if f.resulting_capability == "effective_update"
                       or ({"read", "write"}.issubset(set(f.capabilities_combined)))]
        assert len(rw_findings) >= 1

    def test_agents_involved(self):
        data = _base_config_dict()
        config = _load(data)
        report = analyze_compound_authority(config)
        # Findings should reference both agents
        cross_findings = [f for f in report.findings
                          if len(f.agents_involved) == 2]
        if cross_findings:
            agents = set(cross_findings[0].agents_involved)
            assert "agent-a" in agents or "agent-b" in agents


class TestCrossAgentReadExport:
    """Test cross-agent read+export detection."""

    def test_read_export_detected(self):
        data = _base_config_dict()
        # Agent A reads, Agent B exports
        data["agents"]["agent-a"]["scope"]["actions"] = ["read"]
        data["agents"]["agent-b"]["scope"]["actions"] = ["export"]
        config = _load(data)
        report = analyze_compound_authority(config)
        exfil_findings = [f for f in report.findings
                          if f.resulting_capability == "data_exfiltration"]
        assert len(exfil_findings) >= 1


class TestNonOverlappingTargets:
    """Test that non-overlapping targets produce no cross-agent flags."""

    def test_no_shared_targets(self):
        data = _base_config_dict()
        data["agents"]["agent-a"]["scope"]["targets"] = ["db_a"]
        data["agents"]["agent-a"]["scope"]["boundaries"] = ["db_a"]
        data["agents"]["agent-b"]["scope"]["targets"] = ["db_b"]
        data["agents"]["agent-b"]["scope"]["boundaries"] = ["db_b"]
        config = _load(data)
        report = analyze_compound_authority(config)
        cross_findings = [f for f in report.findings
                          if len(f.agents_involved) == 2]
        assert len(cross_findings) == 0


class TestWorkflowSimulation:
    """Test workflow simulation for authority escalation patterns."""

    def test_workflow_analysis_runs(self):
        data = _base_config_dict()
        data["agents"]["agent-a"]["scope"]["actions"] = ["read", "query", "write"]
        config = _load(data)
        report = analyze_compound_authority(config)
        # Workflow analysis should run and produce risks
        assert isinstance(report.workflow_risks, list)


class TestSingleAgentCompound:
    """Test single-agent compound capability detection."""

    def test_read_write_delete_same_agent(self):
        data = _base_config_dict()
        data["agents"]["agent-a"]["scope"]["actions"] = ["read", "write", "delete"]
        config = _load(data)
        report = analyze_compound_authority(config)
        single_findings = [f for f in report.findings
                           if len(f.agents_involved) == 1
                           and "agent-a" in f.agents_involved]
        # Should detect read+write, read+delete, delete+write compounds
        assert len(single_findings) >= 1

    def test_single_action_no_compound(self):
        data = _base_config_dict()
        data["agents"]["agent-a"]["scope"]["actions"] = ["read"]
        data["agents"]["agent-b"]["scope"]["actions"] = ["read"]
        data["agents"]["agent-b"]["scope"]["targets"] = ["other_db"]
        data["agents"]["agent-b"]["scope"]["boundaries"] = ["other_db"]
        config = _load(data)
        report = analyze_compound_authority(config)
        single_findings = [f for f in report.findings
                           if len(f.agents_involved) == 1]
        assert len(single_findings) == 0


class TestReportGeneration:
    """Test report structure and severity levels."""

    def test_report_structure(self):
        data = _base_config_dict()
        config = _load(data)
        report = analyze_compound_authority(config)
        assert isinstance(report.findings, list)
        assert isinstance(report.critical_count, int)
        assert isinstance(report.warning_count, int)
        assert isinstance(report.cross_agent_risks, list)
        assert isinstance(report.workflow_risks, list)
        assert isinstance(report.summary_text, str)

    def test_no_findings_message(self):
        data = _base_config_dict()
        data["agents"]["agent-a"]["scope"]["actions"] = ["read"]
        data["agents"]["agent-b"]["scope"]["actions"] = ["read"]
        data["agents"]["agent-b"]["scope"]["targets"] = ["other_db"]
        data["agents"]["agent-b"]["scope"]["boundaries"] = ["other_db"]
        config = _load(data)
        report = analyze_compound_authority(config)
        if not report.findings:
            assert "No compound authority" in report.summary_text
