"""Configuration drift detection between baseline and current governance configs.

Compares a PR's governance config against the baseline (from the target branch)
and classifies changes by category and severity.
"""

from __future__ import annotations

import subprocess
from dataclasses import dataclass, field

from nomotic_ci.config_loader import GovernanceConfig, load_config_from_string


DANGEROUS_ACTIONS = frozenset(["delete", "transfer", "execute", "approve"])

SECURITY_CRITICAL_DIMENSIONS = frozenset([
    "scope_compliance",
    "authority_verification",
    "incident_detection",
    "isolation_integrity",
])


@dataclass
class DriftFinding:
    """A single drift finding between baseline and current configs."""

    category: str  # scope_expansion, threshold_relaxation, veto_removal, etc.
    severity: str  # critical, warning, info
    path: str  # Config path, e.g., "agents.trading-agent.scope.actions"
    baseline_value: str
    current_value: str
    description: str
    risk_assessment: str


@dataclass
class DriftReport:
    """Aggregated drift detection results."""

    drift_detected: bool
    findings: list[DriftFinding] = field(default_factory=list)
    critical_count: int = 0
    warning_count: int = 0
    info_count: int = 0
    summary_text: str = ""


def check_drift(
    current_config: GovernanceConfig,
    baseline_ref: str,
    config_path: str,
) -> DriftReport:
    """Compare current config against the baseline and detect drift.

    Args:
        current_config: The PR's governance config.
        baseline_ref: Git ref for the baseline (e.g., 'origin/main').
        config_path: Path to the config file relative to the repo root.

    Returns:
        A DriftReport with all findings.
    """
    baseline_config = _load_baseline(baseline_ref, config_path)

    if baseline_config is None:
        return DriftReport(
            drift_detected=False,
            summary_text="No baseline found — first governance configuration.",
        )

    findings: list[DriftFinding] = []

    findings.extend(_check_scope_changes(baseline_config, current_config))
    findings.extend(_check_threshold_changes(baseline_config, current_config))
    findings.extend(_check_veto_changes(baseline_config, current_config))
    findings.extend(_check_weight_changes(baseline_config, current_config))
    findings.extend(_check_agent_additions_removals(baseline_config, current_config))
    findings.extend(_check_trust_changes(baseline_config, current_config))

    critical = sum(1 for f in findings if f.severity == "critical")
    warning = sum(1 for f in findings if f.severity == "warning")
    info = sum(1 for f in findings if f.severity == "info")

    if findings:
        summary_lines = [f"Configuration drift detected: {len(findings)} change(s)"]
        summary_lines.append(f"  Critical: {critical}, Warning: {warning}, Info: {info}")
        for f in findings:
            summary_lines.append(f"  [{f.severity.upper()}] {f.category}: {f.description}")
        summary_text = "\n".join(summary_lines)
    else:
        summary_text = "No configuration drift detected."

    return DriftReport(
        drift_detected=len(findings) > 0,
        findings=findings,
        critical_count=critical,
        warning_count=warning,
        info_count=info,
        summary_text=summary_text,
    )


def _load_baseline(baseline_ref: str, config_path: str) -> GovernanceConfig | None:
    """Load the baseline governance config from a git ref.

    Uses `git show {ref}:{path}` to read the file at the baseline ref.
    Returns None if the file doesn't exist at that ref.
    """
    try:
        result = subprocess.run(
            ["git", "show", f"{baseline_ref}:{config_path}"],
            capture_output=True,
            text=True,
            timeout=30,
        )
        if result.returncode != 0:
            return None
        return load_config_from_string(result.stdout, source=f"{baseline_ref}:{config_path}")
    except (subprocess.TimeoutExpired, FileNotFoundError, Exception):
        return None


def _check_scope_changes(
    baseline: GovernanceConfig, current: GovernanceConfig
) -> list[DriftFinding]:
    """Detect scope expansions in agent definitions."""
    findings: list[DriftFinding] = []
    baseline_agents = {a.agent_id: a for a in baseline.agents}

    for agent in current.agents:
        base_agent = baseline_agents.get(agent.agent_id)
        if base_agent is None:
            continue  # New agent — handled separately

        # Check action expansion
        new_actions = agent.scope - base_agent.scope
        if new_actions:
            has_dangerous = bool(new_actions & DANGEROUS_ACTIONS)
            severity = "critical" if has_dangerous else "warning"
            findings.append(DriftFinding(
                category="scope_expansion",
                severity=severity,
                path=f"agents.{agent.agent_id}.scope.actions",
                baseline_value=str(sorted(base_agent.scope)),
                current_value=str(sorted(agent.scope)),
                description=(
                    f"Agent '{agent.agent_id}' gained new actions: "
                    f"{', '.join(sorted(new_actions))}"
                ),
                risk_assessment=(
                    "CRITICAL: Expansion includes dangerous actions "
                    f"({', '.join(sorted(new_actions & DANGEROUS_ACTIONS))})"
                    if has_dangerous else
                    "Scope expanded with non-dangerous actions"
                ),
            ))

        # Check target expansion
        new_targets = set(agent.targets) - set(base_agent.targets)
        if new_targets:
            findings.append(DriftFinding(
                category="scope_expansion",
                severity="warning",
                path=f"agents.{agent.agent_id}.scope.targets",
                baseline_value=str(sorted(base_agent.targets)),
                current_value=str(sorted(agent.targets)),
                description=(
                    f"Agent '{agent.agent_id}' gained new targets: "
                    f"{', '.join(sorted(new_targets))}"
                ),
                risk_assessment="Agent now has access to additional resources",
            ))

        # Check boundary expansion
        new_boundaries = set(agent.boundaries) - set(base_agent.boundaries)
        if new_boundaries:
            findings.append(DriftFinding(
                category="scope_expansion",
                severity="warning",
                path=f"agents.{agent.agent_id}.scope.boundaries",
                baseline_value=str(sorted(base_agent.boundaries)),
                current_value=str(sorted(agent.boundaries)),
                description=(
                    f"Agent '{agent.agent_id}' gained new boundaries: "
                    f"{', '.join(sorted(new_boundaries))}"
                ),
                risk_assessment="Agent boundary set expanded",
            ))

    return findings


def _check_threshold_changes(
    baseline: GovernanceConfig, current: GovernanceConfig
) -> list[DriftFinding]:
    """Detect threshold relaxation."""
    findings: list[DriftFinding] = []

    if current.allow_threshold < baseline.allow_threshold:
        findings.append(DriftFinding(
            category="threshold_relaxation",
            severity="warning",
            path="thresholds.allow",
            baseline_value=str(baseline.allow_threshold),
            current_value=str(current.allow_threshold),
            description=(
                f"Allow threshold decreased from {baseline.allow_threshold} "
                f"to {current.allow_threshold} (easier to approve actions)"
            ),
            risk_assessment="Lower allow threshold means actions need less confidence to proceed",
        ))
    elif current.allow_threshold > baseline.allow_threshold:
        findings.append(DriftFinding(
            category="threshold_strictening",
            severity="info",
            path="thresholds.allow",
            baseline_value=str(baseline.allow_threshold),
            current_value=str(current.allow_threshold),
            description=(
                f"Allow threshold increased from {baseline.allow_threshold} "
                f"to {current.allow_threshold} (stricter)"
            ),
            risk_assessment="Stricter threshold — governance is being tightened",
        ))

    if current.deny_threshold < baseline.deny_threshold:
        findings.append(DriftFinding(
            category="threshold_relaxation",
            severity="warning",
            path="thresholds.deny",
            baseline_value=str(baseline.deny_threshold),
            current_value=str(current.deny_threshold),
            description=(
                f"Deny threshold decreased from {baseline.deny_threshold} "
                f"to {current.deny_threshold} (harder to deny actions)"
            ),
            risk_assessment="Lower deny threshold means more actions fall into the ambiguous zone",
        ))

    return findings


def _check_veto_changes(
    baseline: GovernanceConfig, current: GovernanceConfig
) -> list[DriftFinding]:
    """Detect veto list changes. Removals are always CRITICAL."""
    findings: list[DriftFinding] = []
    baseline_vetoes = set(baseline.veto_dimensions)
    current_vetoes = set(current.veto_dimensions)

    removed = baseline_vetoes - current_vetoes
    for dim in sorted(removed):
        findings.append(DriftFinding(
            category="veto_removal",
            severity="critical",
            path="dimensions.vetoes",
            baseline_value=str(sorted(baseline_vetoes)),
            current_value=str(sorted(current_vetoes)),
            description=f"Veto dimension '{dim}' was removed",
            risk_assessment=(
                f"Removing veto authority from '{dim}' removes a hard safety boundary. "
                f"Actions that would have been blocked by '{dim}' can now pass."
            ),
        ))

    added = current_vetoes - baseline_vetoes
    for dim in sorted(added):
        findings.append(DriftFinding(
            category="veto_addition",
            severity="info",
            path="dimensions.vetoes",
            baseline_value=str(sorted(baseline_vetoes)),
            current_value=str(sorted(current_vetoes)),
            description=f"Veto dimension '{dim}' was added",
            risk_assessment="New veto dimension adds a hard safety boundary",
        ))

    return findings


def _check_weight_changes(
    baseline: GovernanceConfig, current: GovernanceConfig
) -> list[DriftFinding]:
    """Detect dimension weight reductions."""
    findings: list[DriftFinding] = []

    for dim in baseline.dimension_weights:
        base_weight = baseline.dimension_weights[dim]
        curr_weight = current.dimension_weights.get(dim, 0.0)

        if curr_weight < base_weight:
            is_security = dim in SECURITY_CRITICAL_DIMENSIONS
            findings.append(DriftFinding(
                category="weight_reduction",
                severity="warning" if is_security else "info",
                path=f"dimensions.weights.{dim}",
                baseline_value=str(base_weight),
                current_value=str(curr_weight),
                description=(
                    f"Dimension '{dim}' weight decreased from "
                    f"{base_weight} to {curr_weight}"
                ),
                risk_assessment=(
                    f"Security-critical dimension '{dim}' was de-emphasized"
                    if is_security else
                    f"Dimension '{dim}' de-emphasized in governance scoring"
                ),
            ))

    return findings


def _check_agent_additions_removals(
    baseline: GovernanceConfig, current: GovernanceConfig
) -> list[DriftFinding]:
    """Detect new and removed agents."""
    findings: list[DriftFinding] = []
    baseline_ids = {a.agent_id for a in baseline.agents}
    current_ids = {a.agent_id for a in current.agents}

    for agent_id in sorted(current_ids - baseline_ids):
        agent = next(a for a in current.agents if a.agent_id == agent_id)
        findings.append(DriftFinding(
            category="agent_added",
            severity="info",
            path=f"agents.{agent_id}",
            baseline_value="(not present)",
            current_value=f"actions={sorted(agent.scope)}, targets={agent.targets}",
            description=f"New agent '{agent_id}' added",
            risk_assessment=f"New agent with scope: {sorted(agent.scope)}, targets: {agent.targets}",
        ))

    for agent_id in sorted(baseline_ids - current_ids):
        findings.append(DriftFinding(
            category="agent_removed",
            severity="info",
            path=f"agents.{agent_id}",
            baseline_value="(present)",
            current_value="(removed)",
            description=f"Agent '{agent_id}' was removed",
            risk_assessment="Agent definition removed from governance config",
        ))

    return findings


def _check_trust_changes(
    baseline: GovernanceConfig, current: GovernanceConfig
) -> list[DriftFinding]:
    """Detect trust parameter relaxation."""
    findings: list[DriftFinding] = []

    base_trust = baseline.trust_settings
    curr_trust = current.trust_settings

    # violation_decrement decreased (violations cost less trust)
    base_vd = base_trust.get("violation_decrement", 0.05)
    curr_vd = curr_trust.get("violation_decrement", 0.05)
    if curr_vd < base_vd:
        findings.append(DriftFinding(
            category="trust_relaxation",
            severity="warning",
            path="trust.violation_decrement",
            baseline_value=str(base_vd),
            current_value=str(curr_vd),
            description=(
                f"violation_decrement decreased from {base_vd} to {curr_vd} "
                f"(violations cost less trust)"
            ),
            risk_assessment="Trust penalties for violations have been reduced",
        ))

    # success_increment increased (trust builds faster)
    base_si = base_trust.get("success_increment", 0.01)
    curr_si = curr_trust.get("success_increment", 0.01)
    if curr_si > base_si:
        findings.append(DriftFinding(
            category="trust_relaxation",
            severity="warning",
            path="trust.success_increment",
            baseline_value=str(base_si),
            current_value=str(curr_si),
            description=(
                f"success_increment increased from {base_si} to {curr_si} "
                f"(trust builds faster)"
            ),
            risk_assessment="Trust accumulates more quickly after successful actions",
        ))

    # ceiling increased
    base_ceil = base_trust.get("ceiling", 0.95)
    curr_ceil = curr_trust.get("ceiling", 0.95)
    if curr_ceil > base_ceil:
        findings.append(DriftFinding(
            category="trust_relaxation",
            severity="warning",
            path="trust.ceiling",
            baseline_value=str(base_ceil),
            current_value=str(curr_ceil),
            description=f"Trust ceiling increased from {base_ceil} to {curr_ceil}",
            risk_assessment="Maximum achievable trust has been raised",
        ))

    # floor decreased
    base_floor = base_trust.get("floor", 0.05)
    curr_floor = curr_trust.get("floor", 0.05)
    if curr_floor < base_floor:
        findings.append(DriftFinding(
            category="trust_relaxation",
            severity="warning",
            path="trust.floor",
            baseline_value=str(base_floor),
            current_value=str(curr_floor),
            description=f"Trust floor decreased from {base_floor} to {curr_floor}",
            risk_assessment="Minimum trust level has been lowered",
        ))

    return findings
