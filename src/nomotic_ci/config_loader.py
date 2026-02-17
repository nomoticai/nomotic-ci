"""Load and parse nomotic.yaml governance configuration files.

Validates schema structure and converts to a GovernanceConfig dataclass
consumed by other nomotic-ci modules.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path

import yaml


VALID_DIMENSIONS = frozenset([
    "scope_compliance",
    "authority_verification",
    "resource_boundaries",
    "behavioral_consistency",
    "cascading_impact",
    "stakeholder_impact",
    "incident_detection",
    "isolation_integrity",
    "temporal_compliance",
    "precedent_alignment",
    "transparency",
    "human_override",
    "ethical_alignment",
])


@dataclass
class AgentConfig:
    """Configuration for a single governed agent."""

    agent_id: str
    scope: set[str]
    targets: list[str]
    boundaries: list[str]
    initial_trust: float
    min_trust: float
    owner: str
    reason: str


@dataclass
class GovernanceConfig:
    """Parsed and validated governance configuration."""

    version: str
    agents: list[AgentConfig]
    dimension_weights: dict[str, float]
    veto_dimensions: list[str]
    allow_threshold: float
    deny_threshold: float
    trust_settings: dict[str, float]
    compliance_frameworks: list[str]
    raw: dict  # Original parsed YAML
    source_path: str  # File path this was loaded from


class ConfigError(Exception):
    """Raised when a governance config has validation errors."""

    def __init__(self, errors: list[str]) -> None:
        self.errors = errors
        super().__init__(f"Config validation failed with {len(errors)} error(s): {'; '.join(errors)}")


def find_config_file(config_path: str, config_file: str = "nomotic.yaml") -> str:
    """Find the governance config file at the given path.

    If config_path is a file, return it directly.
    If config_path is a directory, search for config_file within it (recursively).
    """
    path = Path(config_path)

    if path.is_file():
        return str(path)

    if path.is_dir():
        # Check the directory itself first
        direct = path / config_file
        if direct.is_file():
            return str(direct)

        # Search recursively
        for found in sorted(path.rglob(config_file)):
            return str(found)

    raise FileNotFoundError(
        f"Governance config '{config_file}' not found at '{config_path}'"
    )


def load_config(config_path: str, config_file: str = "nomotic.yaml") -> GovernanceConfig:
    """Load and validate a governance configuration file.

    Args:
        config_path: Path to directory or file containing the governance config.
        config_file: Name of the config file to look for when config_path is a directory.

    Returns:
        A validated GovernanceConfig.

    Raises:
        FileNotFoundError: If the config file is not found.
        ConfigError: If the config has validation errors.
    """
    file_path = find_config_file(config_path, config_file)

    with open(file_path) as f:
        raw = yaml.safe_load(f)

    if not isinstance(raw, dict):
        raise ConfigError(["Config file is empty or not a valid YAML mapping"])

    return parse_config(raw, file_path)


def load_config_from_string(content: str, source: str = "<string>") -> GovernanceConfig:
    """Load a governance config from a YAML string.

    Useful for loading baseline configs from git show output.
    """
    raw = yaml.safe_load(content)
    if not isinstance(raw, dict):
        raise ConfigError(["Config content is empty or not a valid YAML mapping"])
    return parse_config(raw, source)


def parse_config(raw: dict, source_path: str) -> GovernanceConfig:
    """Parse and validate a raw YAML dict into a GovernanceConfig."""
    errors: list[str] = []

    # Version
    version = raw.get("version")
    if version is None:
        errors.append("Missing required field: 'version'")
    elif str(version) != "1.0":
        errors.append(f"Unsupported version '{version}', expected '1.0'")

    # Agents
    agents_raw = raw.get("agents")
    agents: list[AgentConfig] = []
    if agents_raw is None:
        errors.append("Missing required field: 'agents'")
    elif not isinstance(agents_raw, dict):
        errors.append("'agents' must be a mapping of agent definitions")
    elif len(agents_raw) == 0:
        errors.append("'agents' must contain at least one agent definition")
    else:
        for agent_id, agent_def in agents_raw.items():
            agent, agent_errors = _parse_agent(agent_id, agent_def)
            errors.extend(agent_errors)
            if agent is not None:
                agents.append(agent)

    # Dimensions
    dimensions_raw = raw.get("dimensions")
    dimension_weights: dict[str, float] = {}
    veto_dimensions: list[str] = []
    if dimensions_raw is None:
        errors.append("Missing required field: 'dimensions'")
    elif not isinstance(dimensions_raw, dict):
        errors.append("'dimensions' must be a mapping")
    else:
        # Weights
        weights_raw = dimensions_raw.get("weights")
        if weights_raw is None:
            errors.append("Missing required field: 'dimensions.weights'")
        elif not isinstance(weights_raw, dict):
            errors.append("'dimensions.weights' must be a mapping")
        else:
            for dim_name, weight in weights_raw.items():
                if dim_name not in VALID_DIMENSIONS:
                    errors.append(
                        f"Invalid dimension name '{dim_name}' in dimensions.weights. "
                        f"Valid dimensions: {', '.join(sorted(VALID_DIMENSIONS))}"
                    )
                elif not isinstance(weight, (int, float)):
                    errors.append(f"Weight for '{dim_name}' must be a number, got {type(weight).__name__}")
                elif weight < 0:
                    errors.append(f"Weight for '{dim_name}' must be non-negative, got {weight}")
                else:
                    dimension_weights[dim_name] = float(weight)

        # Vetoes
        vetoes_raw = dimensions_raw.get("vetoes")
        if vetoes_raw is not None:
            if not isinstance(vetoes_raw, list):
                errors.append("'dimensions.vetoes' must be a list")
            else:
                for veto in vetoes_raw:
                    if veto not in VALID_DIMENSIONS:
                        errors.append(
                            f"Invalid dimension name '{veto}' in dimensions.vetoes. "
                            f"Valid dimensions: {', '.join(sorted(VALID_DIMENSIONS))}"
                        )
                    else:
                        veto_dimensions.append(veto)

    # Thresholds
    thresholds_raw = raw.get("thresholds")
    allow_threshold = 0.7
    deny_threshold = 0.3
    if thresholds_raw is None:
        errors.append("Missing required field: 'thresholds'")
    elif not isinstance(thresholds_raw, dict):
        errors.append("'thresholds' must be a mapping")
    else:
        allow_val = thresholds_raw.get("allow")
        deny_val = thresholds_raw.get("deny")

        if allow_val is None:
            errors.append("Missing required field: 'thresholds.allow'")
        elif not isinstance(allow_val, (int, float)):
            errors.append(f"'thresholds.allow' must be a number, got {type(allow_val).__name__}")
        elif not (0.0 <= allow_val <= 1.0):
            errors.append(f"'thresholds.allow' must be between 0.0 and 1.0, got {allow_val}")
        else:
            allow_threshold = float(allow_val)

        if deny_val is None:
            errors.append("Missing required field: 'thresholds.deny'")
        elif not isinstance(deny_val, (int, float)):
            errors.append(f"'thresholds.deny' must be a number, got {type(deny_val).__name__}")
        elif not (0.0 <= deny_val <= 1.0):
            errors.append(f"'thresholds.deny' must be between 0.0 and 1.0, got {deny_val}")
        else:
            deny_threshold = float(deny_val)

    # Trust settings
    trust_raw = raw.get("trust")
    trust_settings: dict[str, float] = {}
    required_trust_keys = [
        "success_increment", "violation_decrement", "interrupt_cost",
        "decay_rate", "floor", "ceiling",
    ]
    if trust_raw is None:
        errors.append("Missing required field: 'trust'")
    elif not isinstance(trust_raw, dict):
        errors.append("'trust' must be a mapping")
    else:
        for key in required_trust_keys:
            val = trust_raw.get(key)
            if val is None:
                errors.append(f"Missing required trust setting: 'trust.{key}'")
            elif not isinstance(val, (int, float)):
                errors.append(f"'trust.{key}' must be a number, got {type(val).__name__}")
            elif val < 0:
                errors.append(f"'trust.{key}' must be non-negative, got {val}")
            else:
                trust_settings[key] = float(val)

        # Validate floor/ceiling ranges
        if "floor" in trust_settings and trust_settings["floor"] > 1.0:
            errors.append(f"'trust.floor' must be between 0.0 and 1.0, got {trust_settings['floor']}")
        if "ceiling" in trust_settings and trust_settings["ceiling"] > 1.0:
            errors.append(f"'trust.ceiling' must be between 0.0 and 1.0, got {trust_settings['ceiling']}")

    # Compliance frameworks (optional)
    compliance_frameworks: list[str] = []
    compliance_raw = raw.get("compliance")
    if compliance_raw is not None and isinstance(compliance_raw, dict):
        frameworks = compliance_raw.get("frameworks", [])
        if isinstance(frameworks, list):
            compliance_frameworks = [str(f) for f in frameworks]

    if errors:
        raise ConfigError(errors)

    return GovernanceConfig(
        version=str(version),
        agents=agents,
        dimension_weights=dimension_weights,
        veto_dimensions=veto_dimensions,
        allow_threshold=allow_threshold,
        deny_threshold=deny_threshold,
        trust_settings=trust_settings,
        compliance_frameworks=compliance_frameworks,
        raw=raw,
        source_path=source_path,
    )


def _parse_agent(agent_id: str, agent_def: object) -> tuple[AgentConfig | None, list[str]]:
    """Parse a single agent definition."""
    errors: list[str] = []

    if not isinstance(agent_def, dict):
        return None, [f"Agent '{agent_id}' definition must be a mapping"]

    # Scope
    scope_raw = agent_def.get("scope")
    actions: set[str] = set()
    targets: list[str] = []
    boundaries: list[str] = []

    if scope_raw is None:
        errors.append(f"Agent '{agent_id}': missing required field 'scope'")
    elif not isinstance(scope_raw, dict):
        errors.append(f"Agent '{agent_id}': 'scope' must be a mapping")
    else:
        actions_raw = scope_raw.get("actions")
        if not isinstance(actions_raw, list) or len(actions_raw) == 0:
            errors.append(f"Agent '{agent_id}': 'scope.actions' must be a non-empty list")
        else:
            actions = set(str(a) for a in actions_raw)

        targets_raw = scope_raw.get("targets")
        if isinstance(targets_raw, list):
            targets = [str(t) for t in targets_raw]

        boundaries_raw = scope_raw.get("boundaries")
        if isinstance(boundaries_raw, list):
            boundaries = [str(b) for b in boundaries_raw]

    # Trust
    trust_raw = agent_def.get("trust")
    initial_trust = 0.5
    min_trust = 0.3

    if trust_raw is None:
        errors.append(f"Agent '{agent_id}': missing required field 'trust'")
    elif not isinstance(trust_raw, dict):
        errors.append(f"Agent '{agent_id}': 'trust' must be a mapping")
    else:
        init_val = trust_raw.get("initial")
        if init_val is not None and isinstance(init_val, (int, float)):
            initial_trust = float(init_val)
        min_val = trust_raw.get("minimum_for_action")
        if min_val is not None and isinstance(min_val, (int, float)):
            min_trust = float(min_val)

    owner = str(agent_def.get("owner", ""))
    reason = str(agent_def.get("reason", ""))

    if errors:
        return None, errors

    return AgentConfig(
        agent_id=agent_id,
        scope=actions,
        targets=targets,
        boundaries=boundaries,
        initial_trust=initial_trust,
        min_trust=min_trust,
        owner=owner,
        reason=reason,
    ), errors
