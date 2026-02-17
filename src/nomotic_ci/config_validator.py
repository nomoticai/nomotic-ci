"""Deep validation of governance configurations.

Goes beyond schema validation to check logical consistency, security
properties, and runtime behavior using Nomotic's GovernanceRuntime.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from nomotic import (
    Action,
    AgentContext,
    GovernanceRuntime,
    TrustProfile,
    Verdict,
)
from nomotic.runtime import RuntimeConfig

from nomotic_ci.config_loader import GovernanceConfig


CRITICAL_DIMENSIONS = frozenset(["scope_compliance", "authority_verification"])

SECURITY_DIMENSIONS = frozenset([
    "scope_compliance",
    "authority_verification",
    "incident_detection",
    "isolation_integrity",
])

# Compliance framework dimension requirements — dimensions that should have
# elevated weights for a given framework.
COMPLIANCE_DIMENSION_HINTS: dict[str, dict[str, float]] = {
    "HIPAA": {
        "isolation_integrity": 1.5,
        "stakeholder_impact": 1.5,
        "transparency": 1.0,
    },
    "SOC2": {
        "scope_compliance": 1.5,
        "incident_detection": 1.5,
        "transparency": 1.0,
    },
    "PCI-DSS": {
        "resource_boundaries": 1.5,
        "isolation_integrity": 1.5,
        "scope_compliance": 1.5,
    },
    "ISO27001": {
        "scope_compliance": 1.5,
        "authority_verification": 1.5,
        "incident_detection": 1.5,
    },
}


@dataclass
class ValidationIssue:
    """A single validation finding."""

    severity: str  # "critical", "warning", "info"
    check_name: str
    message: str
    details: str
    location: str  # e.g., "agents.trading-agent.scope" or "thresholds"
    remediation: str


@dataclass
class ValidationReport:
    """Aggregated validation results."""

    issues: list[ValidationIssue] = field(default_factory=list)
    status: str = "pass"  # "pass", "warn", "fail"
    critical_count: int = 0
    warning_count: int = 0
    info_count: int = 0
    checks_run: int = 0

    @property
    def issues_found(self) -> int:
        return len(self.issues)


def validate(config: GovernanceConfig) -> ValidationReport:
    """Run all validation checks against a governance configuration.

    Returns a ValidationReport with all issues found.
    """
    report = ValidationReport()
    checks = [
        _check_threshold_inversion,
        _check_veto_weight_contradiction,
        _check_missing_critical_vetoes,
        _check_overlapping_scopes,
        _check_overprivileged_agents,
        _check_trust_floor_above_minimum,
        _check_compliance_dimensions,
        _check_simulation,
    ]

    for check in checks:
        report.checks_run += 1
        try:
            issues = check(config)
            for issue in issues:
                report.issues.append(issue)
                if issue.severity == "critical":
                    report.critical_count += 1
                elif issue.severity == "warning":
                    report.warning_count += 1
                else:
                    report.info_count += 1
        except Exception as exc:
            report.issues.append(ValidationIssue(
                severity="warning",
                check_name="internal_error",
                message=f"Check failed with error: {exc}",
                details=str(exc),
                location="internal",
                remediation="This may indicate an issue with the nomotic library version.",
            ))
            report.warning_count += 1

    # Determine overall status
    if report.critical_count > 0:
        report.status = "fail"
    elif report.warning_count > 0:
        report.status = "warn"
    else:
        report.status = "pass"

    return report


def _check_threshold_inversion(config: GovernanceConfig) -> list[ValidationIssue]:
    """Check if allow_threshold <= deny_threshold (paradox)."""
    if config.allow_threshold <= config.deny_threshold:
        return [ValidationIssue(
            severity="critical",
            check_name="threshold_inversion",
            message="Threshold inversion: allow_threshold <= deny_threshold",
            details=(
                f"allow_threshold ({config.allow_threshold}) must be greater than "
                f"deny_threshold ({config.deny_threshold}). This creates a paradox "
                f"where actions can be simultaneously allowed and denied."
            ),
            location="thresholds",
            remediation=(
                "Set allow_threshold > deny_threshold. "
                "Example: allow: 0.7, deny: 0.3"
            ),
        )]
    return []


def _check_veto_weight_contradiction(config: GovernanceConfig) -> list[ValidationIssue]:
    """Check for dimensions with veto authority but zero weight."""
    issues: list[ValidationIssue] = []
    for dim in config.veto_dimensions:
        weight = config.dimension_weights.get(dim, 0.0)
        if weight == 0.0:
            issues.append(ValidationIssue(
                severity="warning",
                check_name="veto_weight_contradiction",
                message=f"Dimension '{dim}' has veto authority but weight 0.0",
                details=(
                    f"'{dim}' can halt actions via veto but contributes nothing to the "
                    f"UCS score. Vetoed actions will have no UCS signal explaining the block."
                ),
                location=f"dimensions.weights.{dim}",
                remediation=f"Set a non-zero weight for '{dim}' or remove it from the veto list.",
            ))
    return issues


def _check_missing_critical_vetoes(config: GovernanceConfig) -> list[ValidationIssue]:
    """Check for high-weight dimensions missing from the veto list."""
    issues: list[ValidationIssue] = []
    for dim, weight in config.dimension_weights.items():
        if weight > 1.5 and dim not in config.veto_dimensions:
            severity = "warning" if dim in CRITICAL_DIMENSIONS else "info"
            issues.append(ValidationIssue(
                severity=severity,
                check_name="missing_critical_veto",
                message=f"High-weight dimension '{dim}' (weight={weight}) is not in the veto list",
                details=(
                    f"'{dim}' has weight {weight} but no veto authority. An agent could score "
                    f"low on {dim} but still pass via high scores in other dimensions."
                ),
                location="dimensions.vetoes",
                remediation=f"Consider adding '{dim}' to dimensions.vetoes.",
            ))
    return issues


def _check_overlapping_scopes(config: GovernanceConfig) -> list[ValidationIssue]:
    """Check for agents with write access to the same targets."""
    issues: list[ValidationIssue] = []
    write_actions = {"write", "update", "delete", "transfer", "execute", "approve"}

    for i, agent_a in enumerate(config.agents):
        for agent_b in config.agents[i + 1:]:
            a_writes = agent_a.scope & write_actions
            b_writes = agent_b.scope & write_actions

            if not a_writes or not b_writes:
                continue

            shared_targets = set(agent_a.targets) & set(agent_b.targets)
            if shared_targets:
                issues.append(ValidationIssue(
                    severity="info",
                    check_name="overlapping_scopes",
                    message=(
                        f"Agents '{agent_a.agent_id}' and '{agent_b.agent_id}' "
                        f"have write access to shared targets"
                    ),
                    details=(
                        f"Shared targets: {', '.join(sorted(shared_targets))}. "
                        f"'{agent_a.agent_id}' actions: {', '.join(sorted(a_writes))}. "
                        f"'{agent_b.agent_id}' actions: {', '.join(sorted(b_writes))}."
                    ),
                    location=f"agents.{agent_a.agent_id}.scope / agents.{agent_b.agent_id}.scope",
                    remediation="Consider narrowing scopes to avoid conflicting writes.",
                ))
    return issues


def _check_overprivileged_agents(config: GovernanceConfig) -> list[ValidationIssue]:
    """Check for agents with unusually broad scopes."""
    issues: list[ValidationIssue] = []
    for agent in config.agents:
        action_count = len(agent.scope)
        target_count = len(agent.targets)

        if action_count > 5:
            issues.append(ValidationIssue(
                severity="warning",
                check_name="overprivileged_agent",
                message=f"Agent '{agent.agent_id}' has a broad action scope ({action_count} action types)",
                details=f"Actions: {', '.join(sorted(agent.scope))}",
                location=f"agents.{agent.agent_id}.scope.actions",
                remediation="Consider splitting into multiple agents with narrower scopes.",
            ))

        if target_count > 10:
            issues.append(ValidationIssue(
                severity="warning",
                check_name="overprivileged_agent",
                message=f"Agent '{agent.agent_id}' has access to many targets ({target_count})",
                details=f"Targets: {', '.join(agent.targets)}",
                location=f"agents.{agent.agent_id}.scope.targets",
                remediation="Consider restricting the target set for this agent.",
            ))
    return issues


def _check_trust_floor_above_minimum(config: GovernanceConfig) -> list[ValidationIssue]:
    """Check if trust floor > any agent's minimum_for_action."""
    issues: list[ValidationIssue] = []
    floor = config.trust_settings.get("floor", 0.05)

    for agent in config.agents:
        if floor > agent.min_trust:
            issues.append(ValidationIssue(
                severity="warning",
                check_name="trust_floor_above_minimum",
                message=(
                    f"Trust floor ({floor}) is above agent '{agent.agent_id}' "
                    f"minimum_for_action ({agent.min_trust})"
                ),
                details=(
                    f"Agent '{agent.agent_id}' requires trust >= {agent.min_trust} to act, "
                    f"but the trust floor is {floor}. Trust can never drop below {floor}, "
                    f"so trust degradation has no practical effect for this agent."
                ),
                location=f"trust.floor / agents.{agent.agent_id}.trust.minimum_for_action",
                remediation=(
                    f"Either lower trust.floor below {agent.min_trust} or raise "
                    f"the agent's minimum_for_action above {floor}."
                ),
            ))
    return issues


def _check_compliance_dimensions(config: GovernanceConfig) -> list[ValidationIssue]:
    """Check compliance framework dimension alignment."""
    issues: list[ValidationIssue] = []
    for framework in config.compliance_frameworks:
        hints = COMPLIANCE_DIMENSION_HINTS.get(framework)
        if hints is None:
            continue
        for dim, min_weight in hints.items():
            actual_weight = config.dimension_weights.get(dim, 0.0)
            if actual_weight < min_weight:
                issues.append(ValidationIssue(
                    severity="info",
                    check_name="compliance_dimension_alignment",
                    message=(
                        f"{framework} compliance: '{dim}' weight ({actual_weight}) "
                        f"is below recommended minimum ({min_weight})"
                    ),
                    details=(
                        f"For {framework} compliance, '{dim}' should typically have "
                        f"a weight of at least {min_weight}."
                    ),
                    location=f"dimensions.weights.{dim}",
                    remediation=f"Consider increasing '{dim}' weight to at least {min_weight}.",
                ))
    return issues


def _check_simulation(config: GovernanceConfig) -> list[ValidationIssue]:
    """Simulate governance decisions to verify the config produces expected verdicts.

    Instantiates a GovernanceRuntime with the config, sets up agent scopes,
    and tests that out-of-scope actions are denied.
    """
    issues: list[ValidationIssue] = []

    if not config.agents:
        return issues

    runtime_config = RuntimeConfig(
        allow_threshold=config.allow_threshold,
        deny_threshold=config.deny_threshold,
    )
    runtime = GovernanceRuntime(config=runtime_config)

    # Configure dimensions
    _configure_runtime(runtime, config)

    agent = config.agents[0]
    context = AgentContext(
        agent_id=agent.agent_id,
        trust_profile=TrustProfile(
            agent_id=agent.agent_id,
            overall_trust=agent.initial_trust,
        ),
    )

    # Test in-scope action
    if agent.targets and agent.scope:
        in_scope_action = Action(
            agent_id=agent.agent_id,
            action_type=next(iter(agent.scope)),
            target=agent.targets[0],
        )
        verdict = runtime.evaluate(in_scope_action, context)
        if verdict.verdict == Verdict.DENY:
            issues.append(ValidationIssue(
                severity="warning",
                check_name="simulation_in_scope_denied",
                message=f"In-scope action for '{agent.agent_id}' was denied (UCS={verdict.ucs:.3f})",
                details=(
                    f"Action type='{in_scope_action.action_type}', "
                    f"target='{in_scope_action.target}' was expected to be allowed "
                    f"but received verdict={verdict.verdict.name}."
                ),
                location=f"agents.{agent.agent_id}",
                remediation="Review dimension weights and thresholds — the config may be too strict.",
            ))

    # Test out-of-scope action (should be denied)
    out_of_scope_action = Action(
        agent_id=agent.agent_id,
        action_type="delete",
        target="unauthorized_system",
    )
    verdict = runtime.evaluate(out_of_scope_action, context)
    if verdict.verdict == Verdict.ALLOW:
        issues.append(ValidationIssue(
            severity="critical",
            check_name="simulation_unauthorized_allowed",
            message=f"Out-of-scope action was ALLOWED for '{agent.agent_id}'",
            details=(
                f"Action type='delete', target='unauthorized_system' should have been denied "
                f"but received verdict=ALLOW (UCS={verdict.ucs:.3f}). "
                f"The config allows unauthorized actions."
            ),
            location=f"agents.{agent.agent_id}.scope",
            remediation=(
                "Ensure scope_compliance and isolation_integrity dimensions have "
                "veto authority and non-zero weights."
            ),
        ))

    return issues


def _configure_runtime(runtime: GovernanceRuntime, config: GovernanceConfig) -> None:
    """Configure a GovernanceRuntime from a GovernanceConfig.

    Sets dimension weights, veto flags, agent scopes, and boundaries.
    """
    for dim in runtime.registry.dimensions:
        # Set weights
        if dim.name in config.dimension_weights:
            dim.weight = config.dimension_weights[dim.name]

        # Set veto flags
        dim.can_veto = dim.name in config.veto_dimensions

    # Configure agent scopes and boundaries
    scope_dim = runtime.registry.get("scope_compliance")
    isolation_dim = runtime.registry.get("isolation_integrity")

    for agent in config.agents:
        if scope_dim is not None and hasattr(scope_dim, "configure_agent_scope"):
            scope_dim.configure_agent_scope(agent.agent_id, agent.scope)

        if isolation_dim is not None and hasattr(isolation_dim, "set_boundaries"):
            isolation_dim.set_boundaries(agent.agent_id, agent.boundaries)
