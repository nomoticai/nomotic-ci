"""Compound authority analysis for governance configurations.

Detects situations where individually-safe agent scopes combine to create
unsafe compound capabilities, either across agents or within a single agent's
multi-step workflows.

Cross-agent analysis uses pair-wise scope comparison against known dangerous
capability combinations.  Workflow analysis delegates to the library's
WorkflowGovernor which detects cumulative risk, ordering concerns, compound
authority chains, and behavioral drift across steps.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from itertools import combinations
from typing import Any

from nomotic import Action, AgentContext, TrustProfile
from nomotic.context_profile import (
    CompletedStep,
    ContextProfile,
    WorkflowContext,
)
from nomotic.sandbox import (
    AgentConfig as SandboxAgentConfig,
    build_sandbox_runtime,
)
from nomotic.workflow_governor import WorkflowGovernor, WorkflowGovernorConfig

from nomotic_ci.config_loader import GovernanceConfig


# Known dangerous capability combinations
DANGEROUS_COMBINATIONS: list[tuple[set[str], str, str]] = [
    (
        {"read", "write"},
        "effective_update",
        "Combined read+write on the same target enables data modification",
    ),
    (
        {"read", "export"},
        "data_exfiltration",
        "Combined read+export enables data exfiltration to external systems",
    ),
    (
        {"delete", "write"},
        "data_replacement",
        "Combined delete+write enables complete data replacement",
    ),
    (
        {"read", "transfer"},
        "data_movement",
        "Combined read+transfer enables data aggregation and movement",
    ),
    (
        {"authenticate", "authorize", "execute"},
        "full_privilege_chain",
        "Combined authenticate+authorize+execute creates a full privilege chain",
    ),
    (
        {"read", "delete"},
        "targeted_deletion",
        "Combined read+delete enables targeted data removal",
    ),
    (
        {"query", "write"},
        "query_driven_modification",
        "Combined query+write enables data modification based on query results",
    ),
]


@dataclass
class CompoundAuthorityFinding:
    """A single compound authority finding."""

    severity: str  # "critical", "warning", "info"
    agents_involved: list[str]
    capabilities_combined: list[str]
    resulting_capability: str
    description: str
    mitigation: str


@dataclass
class CompoundAuthorityReport:
    """Aggregated compound authority analysis results."""

    findings: list[CompoundAuthorityFinding] = field(default_factory=list)
    critical_count: int = 0
    warning_count: int = 0
    cross_agent_risks: list[dict[str, Any]] = field(default_factory=list)
    workflow_risks: list[dict[str, Any]] = field(default_factory=list)
    summary_text: str = ""


def analyze_compound_authority(config: GovernanceConfig) -> CompoundAuthorityReport:
    """Analyze a governance config for compound authority vulnerabilities.

    Checks cross-agent scope assembly and per-agent workflow risks.
    """
    findings: list[CompoundAuthorityFinding] = []
    cross_agent_risks: list[dict[str, Any]] = []
    workflow_risks: list[dict[str, Any]] = []

    # Cross-agent analysis
    cross_findings, cross_risks = _analyze_cross_agent(config)
    findings.extend(cross_findings)
    cross_agent_risks.extend(cross_risks)

    # Per-agent workflow analysis using library WorkflowGovernor
    wf_findings, wf_risks = _analyze_workflows(config)
    findings.extend(wf_findings)
    workflow_risks.extend(wf_risks)

    # Single-agent compound detection
    single_findings = _analyze_single_agent_compounds(config)
    findings.extend(single_findings)

    critical = sum(1 for f in findings if f.severity == "critical")
    warning = sum(1 for f in findings if f.severity == "warning")

    if findings:
        summary_lines = [f"Compound authority analysis: {len(findings)} finding(s)"]
        summary_lines.append(f"  Critical: {critical}, Warning: {warning}")
        for f in findings:
            summary_lines.append(
                f"  [{f.severity.upper()}] {f.resulting_capability}: {f.description}"
            )
        summary_text = "\n".join(summary_lines)
    else:
        summary_text = "No compound authority vulnerabilities detected."

    return CompoundAuthorityReport(
        findings=findings,
        critical_count=critical,
        warning_count=warning,
        cross_agent_risks=cross_agent_risks,
        workflow_risks=workflow_risks,
        summary_text=summary_text,
    )


def _analyze_cross_agent(
    config: GovernanceConfig,
) -> tuple[list[CompoundAuthorityFinding], list[dict[str, Any]]]:
    """Analyze every pair of agents for combined capability risks."""
    findings: list[CompoundAuthorityFinding] = []
    risks: list[dict[str, Any]] = []

    for agent_a, agent_b in combinations(config.agents, 2):
        shared_targets = set(agent_a.targets) & set(agent_b.targets)
        if not shared_targets:
            continue

        combined_actions = agent_a.scope | agent_b.scope

        for required_actions, capability, description in DANGEROUS_COMBINATIONS:
            # Check if the combination requires both agents (not achievable by one alone)
            if not required_actions.issubset(combined_actions):
                continue
            if required_actions.issubset(agent_a.scope) or required_actions.issubset(agent_b.scope):
                continue  # Single agent can already do this — not a cross-agent issue

            a_contribution = required_actions & agent_a.scope
            b_contribution = required_actions & agent_b.scope

            severity = "critical" if capability in (
                "full_privilege_chain", "data_exfiltration", "data_replacement"
            ) else "warning"

            finding = CompoundAuthorityFinding(
                severity=severity,
                agents_involved=[agent_a.agent_id, agent_b.agent_id],
                capabilities_combined=sorted(required_actions),
                resulting_capability=capability,
                description=(
                    f"'{agent_a.agent_id}' ({', '.join(sorted(a_contribution))}) + "
                    f"'{agent_b.agent_id}' ({', '.join(sorted(b_contribution))}) "
                    f"on shared targets ({', '.join(sorted(shared_targets))}): {description}"
                ),
                mitigation=(
                    f"Consider removing shared targets between these agents, or "
                    f"restricting one agent's actions to prevent the "
                    f"'{capability}' combination."
                ),
            )
            findings.append(finding)
            risks.append({
                "agents": [agent_a.agent_id, agent_b.agent_id],
                "shared_targets": sorted(shared_targets),
                "capability": capability,
                "severity": severity,
            })

    return findings, risks


def _analyze_workflows(
    config: GovernanceConfig,
) -> tuple[list[CompoundAuthorityFinding], list[dict[str, Any]]]:
    """Analyze per-agent workflow risks using the library WorkflowGovernor.

    Simulates multi-step workflows for each agent and checks for
    compound authority flags, ordering concerns, and risk escalation.
    """
    findings: list[CompoundAuthorityFinding] = []
    risks: list[dict[str, Any]] = []

    governor = WorkflowGovernor(WorkflowGovernorConfig(
        compound_authority_detection=True,
        ordering_analysis=True,
        consequence_projection=False,  # not needed for static analysis
        drift_across_steps_detection=True,
    ))

    for agent in config.agents:
        if len(agent.scope) < 2:
            continue

        actions_list = sorted(agent.scope)

        # Build a sandbox runtime for this agent
        sandbox_config = SandboxAgentConfig(
            agent_id=agent.agent_id,
            actions=actions_list,
            boundaries=agent.boundaries,
        )
        runtime = build_sandbox_runtime(agent_config=sandbox_config, agent_id=agent.agent_id)

        # Build completed steps by simulating each action through the runtime
        completed_steps: list[CompletedStep] = []
        context = AgentContext(
            agent_id=agent.agent_id,
            trust_profile=TrustProfile(
                agent_id=agent.agent_id,
                overall_trust=agent.initial_trust,
            ),
        )

        now = datetime.now(timezone.utc).isoformat()

        for i, action_type in enumerate(actions_list):
            target = agent.targets[i % len(agent.targets)] if agent.targets else "default"
            action = Action(
                agent_id=agent.agent_id,
                action_type=action_type,
                target=target,
            )
            verdict = runtime.evaluate(action, context)
            completed_steps.append(CompletedStep(
                step_id=f"step-{i + 1}",
                step_number=i + 1,
                method=action_type,
                target=target,
                verdict=verdict.verdict.name,
                ucs=verdict.ucs,
                timestamp=now,
            ))

        # Build workflow context and context profile for the governor
        workflow = WorkflowContext(
            workflow_id=f"wf-{agent.agent_id}",
            workflow_type="compound_authority_analysis",
            current_step=len(completed_steps),
            total_steps=len(completed_steps),
            steps_completed=completed_steps,
            steps_remaining=[],
        )
        profile = ContextProfile(
            profile_id=f"profile-{agent.agent_id}",
            agent_id=agent.agent_id,
            profile_type="workflow_analysis",
            workflow=workflow,
        )

        # Assess workflow
        assessment = governor.assess_workflow(f"wf-{agent.agent_id}", profile)

        # Convert compound authority flags to findings
        for flag in assessment.compound_authority_flags:
            findings.append(CompoundAuthorityFinding(
                severity=flag.severity if flag.severity in ("critical", "warning") else "info",
                agents_involved=[agent.agent_id],
                capabilities_combined=flag.methods_chained,
                resulting_capability=flag.resulting_capability,
                description=(
                    f"Agent '{agent.agent_id}' workflow: {flag.description}"
                ),
                mitigation=(
                    "Review the action sequence and consider whether "
                    "sequential execution should be governed as a compound operation."
                ),
            ))

        # Convert risk factors to workflow risks
        if assessment.risk_factors or assessment.compound_authority_flags:
            risk_entry: dict[str, Any] = {
                "agent": agent.agent_id,
                "cumulative_risk": assessment.cumulative_risk_score,
                "risk_trajectory": assessment.risk_trajectory,
                "recommendation": assessment.recommendation,
                "risk_factors": [f.to_dict() for f in assessment.risk_factors],
                "compound_flags": [f.to_dict() for f in assessment.compound_authority_flags],
            }
            risks.append(risk_entry)

        # Check for escalation pattern via UCS values
        ucs_values = [s.ucs for s in completed_steps]
        if len(ucs_values) >= 3:
            increasing = all(
                ucs_values[i] <= ucs_values[i + 1]
                for i in range(len(ucs_values) - 1)
            )
            if increasing and ucs_values[-1] > ucs_values[0] + 0.1:
                findings.append(CompoundAuthorityFinding(
                    severity="info",
                    agents_involved=[agent.agent_id],
                    capabilities_combined=actions_list,
                    resulting_capability="authority_escalation",
                    description=(
                        f"Agent '{agent.agent_id}' shows increasing UCS across "
                        f"sequential actions ({ucs_values[0]:.3f} -> {ucs_values[-1]:.3f}), "
                        f"which may indicate an authority escalation pattern"
                    ),
                    mitigation=(
                        "Review the action ordering and consider whether sequential "
                        "action execution should affect UCS scoring."
                    ),
                ))

    return findings, risks


def _analyze_single_agent_compounds(
    config: GovernanceConfig,
) -> list[CompoundAuthorityFinding]:
    """Check single agents for dangerous compound capabilities."""
    findings: list[CompoundAuthorityFinding] = []

    for agent in config.agents:
        for required_actions, capability, description in DANGEROUS_COMBINATIONS:
            if required_actions.issubset(agent.scope):
                severity = "warning" if capability in (
                    "full_privilege_chain", "data_exfiltration", "data_replacement"
                ) else "info"

                findings.append(CompoundAuthorityFinding(
                    severity=severity,
                    agents_involved=[agent.agent_id],
                    capabilities_combined=sorted(required_actions),
                    resulting_capability=capability,
                    description=(
                        f"Agent '{agent.agent_id}' has combined capabilities "
                        f"{sorted(required_actions)}: {description}"
                    ),
                    mitigation=(
                        f"Consider splitting '{agent.agent_id}' into separate agents "
                        f"to avoid the '{capability}' compound capability."
                    ),
                ))

    return findings
