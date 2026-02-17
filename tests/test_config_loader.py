"""Tests for config_loader module."""

from __future__ import annotations

import os
import tempfile

import pytest
import yaml

from nomotic_ci.config_loader import (
    ConfigError,
    load_config,
    load_config_from_string,
    VALID_DIMENSIONS,
)


EXAMPLES_DIR = os.path.join(os.path.dirname(__file__), "..", "examples")


def _basic_config_dict() -> dict:
    """Return a minimal valid config dict."""
    return {
        "version": "1.0",
        "agents": {
            "test-agent": {
                "scope": {
                    "actions": ["read", "write"],
                    "targets": ["db"],
                    "boundaries": ["db"],
                },
                "trust": {"initial": 0.5, "minimum_for_action": 0.3},
                "owner": "test@example.com",
                "reason": "test",
            }
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


def _write_yaml(tmpdir: str, data: dict, filename: str = "nomotic.yaml") -> str:
    """Write a YAML config to a temp directory and return the file path."""
    path = os.path.join(tmpdir, filename)
    with open(path, "w") as f:
        yaml.dump(data, f)
    return path


class TestLoadValidConfigs:
    """Test loading known-good example configs."""

    def test_load_basic(self):
        config = load_config(os.path.join(EXAMPLES_DIR, "basic"))
        assert config.version == "1.0"
        assert len(config.agents) == 2
        agent_ids = {a.agent_id for a in config.agents}
        assert "customer-service-agent" in agent_ids
        assert "reporting-agent" in agent_ids

    def test_load_fintech(self):
        config = load_config(os.path.join(EXAMPLES_DIR, "fintech"))
        assert config.version == "1.0"
        assert len(config.agents) == 2
        assert config.allow_threshold == 0.8
        assert config.deny_threshold == 0.4
        assert "SOC2" in config.compliance_frameworks
        assert "PCI-DSS" in config.compliance_frameworks

    def test_load_healthcare(self):
        config = load_config(os.path.join(EXAMPLES_DIR, "healthcare"))
        assert config.version == "1.0"
        assert len(config.agents) == 2
        assert "HIPAA" in config.compliance_frameworks
        assert "SOC2" in config.compliance_frameworks


class TestLoadFromDirectory:
    """Test finding and loading config from a directory."""

    def test_find_in_directory(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            data = _basic_config_dict()
            _write_yaml(tmpdir, data)
            config = load_config(tmpdir)
            assert config.version == "1.0"

    def test_find_in_subdirectory(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            subdir = os.path.join(tmpdir, "sub")
            os.makedirs(subdir)
            data = _basic_config_dict()
            _write_yaml(subdir, data)
            config = load_config(tmpdir)
            assert config.version == "1.0"

    def test_load_from_file_path(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            data = _basic_config_dict()
            path = _write_yaml(tmpdir, data, "custom.yaml")
            config = load_config(path)
            assert config.version == "1.0"


class TestMissingRequiredFields:
    """Test that missing required fields raise ConfigError."""

    def test_missing_version(self):
        data = _basic_config_dict()
        del data["version"]
        with pytest.raises(ConfigError) as exc_info:
            load_config_from_string(yaml.dump(data))
        assert any("version" in e for e in exc_info.value.errors)

    def test_missing_agents(self):
        data = _basic_config_dict()
        del data["agents"]
        with pytest.raises(ConfigError) as exc_info:
            load_config_from_string(yaml.dump(data))
        assert any("agents" in e for e in exc_info.value.errors)

    def test_missing_dimensions(self):
        data = _basic_config_dict()
        del data["dimensions"]
        with pytest.raises(ConfigError) as exc_info:
            load_config_from_string(yaml.dump(data))
        assert any("dimensions" in e for e in exc_info.value.errors)

    def test_missing_thresholds(self):
        data = _basic_config_dict()
        del data["thresholds"]
        with pytest.raises(ConfigError) as exc_info:
            load_config_from_string(yaml.dump(data))
        assert any("thresholds" in e for e in exc_info.value.errors)

    def test_missing_trust(self):
        data = _basic_config_dict()
        del data["trust"]
        with pytest.raises(ConfigError) as exc_info:
            load_config_from_string(yaml.dump(data))
        assert any("trust" in e for e in exc_info.value.errors)

    def test_empty_agents(self):
        data = _basic_config_dict()
        data["agents"] = {}
        with pytest.raises(ConfigError) as exc_info:
            load_config_from_string(yaml.dump(data))
        assert any("at least one" in e for e in exc_info.value.errors)


class TestInvalidValues:
    """Test validation of invalid field values."""

    def test_invalid_dimension_name(self):
        data = _basic_config_dict()
        data["dimensions"]["weights"]["scope_compiance"] = 1.0  # typo
        with pytest.raises(ConfigError) as exc_info:
            load_config_from_string(yaml.dump(data))
        assert any("scope_compiance" in e for e in exc_info.value.errors)

    def test_negative_threshold(self):
        data = _basic_config_dict()
        data["thresholds"]["allow"] = -0.1
        with pytest.raises(ConfigError) as exc_info:
            load_config_from_string(yaml.dump(data))
        assert any("0.0 and 1.0" in e for e in exc_info.value.errors)

    def test_threshold_above_one(self):
        data = _basic_config_dict()
        data["thresholds"]["deny"] = 1.5
        with pytest.raises(ConfigError) as exc_info:
            load_config_from_string(yaml.dump(data))
        assert any("0.0 and 1.0" in e for e in exc_info.value.errors)

    def test_empty_agent_scope(self):
        data = _basic_config_dict()
        data["agents"]["test-agent"]["scope"]["actions"] = []
        with pytest.raises(ConfigError) as exc_info:
            load_config_from_string(yaml.dump(data))
        assert any("non-empty" in e for e in exc_info.value.errors)

    def test_negative_weight(self):
        data = _basic_config_dict()
        data["dimensions"]["weights"]["scope_compliance"] = -1.0
        with pytest.raises(ConfigError) as exc_info:
            load_config_from_string(yaml.dump(data))
        assert any("non-negative" in e for e in exc_info.value.errors)


class TestConfigNotFound:
    """Test file-not-found handling."""

    def test_file_not_found(self):
        with pytest.raises(FileNotFoundError):
            load_config("/nonexistent/path")

    def test_empty_directory(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            with pytest.raises(FileNotFoundError):
                load_config(tmpdir)


class TestLoadFromString:
    """Test loading configs from YAML strings."""

    def test_valid_string(self):
        data = _basic_config_dict()
        config = load_config_from_string(yaml.dump(data))
        assert config.version == "1.0"

    def test_empty_string(self):
        with pytest.raises(ConfigError):
            load_config_from_string("")

    def test_non_mapping(self):
        with pytest.raises(ConfigError):
            load_config_from_string("- item1\n- item2\n")


class TestAgentParsing:
    """Test agent definition parsing."""

    def test_agent_scope_is_set(self):
        data = _basic_config_dict()
        config = load_config_from_string(yaml.dump(data))
        agent = config.agents[0]
        assert isinstance(agent.scope, set)
        assert "read" in agent.scope
        assert "write" in agent.scope

    def test_agent_trust_defaults(self):
        data = _basic_config_dict()
        config = load_config_from_string(yaml.dump(data))
        agent = config.agents[0]
        assert agent.initial_trust == 0.5
        assert agent.min_trust == 0.3

    def test_raw_preserved(self):
        data = _basic_config_dict()
        config = load_config_from_string(yaml.dump(data))
        assert config.raw is not None
        assert "agents" in config.raw
