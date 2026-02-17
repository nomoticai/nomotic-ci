"""Run adversarial test scenarios against governance configurations.

Simulates adversarial attack patterns (privilege escalation, scope assembly,
boundary probing, etc.) using Nomotic's GovernanceRuntime to verify that the
governance config correctly blocks malicious or unauthorized actions.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any

from nomotic import (
    Action,
    AgentContext,
    GovernanceRuntime,
    TrustProfile,
)
from nomotic.runtime import RuntimeConfig

from nomotic_ci.config_loader import GovernanceConfig
from nomotic_ci.config_validator import _configure_runtime


@dataclass
class ActionTestResult:
    """Result of a single adversarial action test."""

    action_type: str
    target: str
    agent_id: str
    expected_verdict: str  # "DENY" or "ALLOW"
    actual_verdict: str
    ucs: float
    passed: bool
    description: str


@dataclass
class ScenarioTestResult:
    """Result of an adversarial scenario (a group of related action tests)."""

    scenario_name: str
    description: str
    actions_tested: int
    actions_passed: int
    passed: bool
    results: list[ActionTestResult] = field(default_factory=list)


@dataclass
class AdversarialReport:
    """Aggregated adversarial testing results."""

    scenarios_run: int
    scenarios_passed: int
    scenarios_failed: int
    pass_rate: float
    results: list[ScenarioTestResult]
    unexpected_allows: list[dict[str, Any]]
    summary_text: str


def run_adversarial_tests(config: GovernanceConfig) -> AdversarialReport:
    """Run all adversarial scenarios against the governance configuration.

    Creates a GovernanceRuntime configured per the governance config, then
    runs each adversarial scenario and collects results.
    """
    runtime = _build_runtime(config)
    scenarios = _get_all_scenarios(config)

    results: list[ScenarioTestResult] = []
    unexpected_allows: list[dict[str, Any]] = []

    for scenario_fn in scenarios:
        result = scenario_fn(runtime, config)
        results.append(result)

        # Collect unexpected allows
        for action_result in result.results:
            if not action_result.passed and action_result.actual_verdict == "ALLOW":
                unexpected_allows.append({
                    "scenario": result.scenario_name,
                    "action_type": action_result.action_type,
                    "target": action_result.target,
                    "agent_id": action_result.agent_id,
                    "ucs": action_result.ucs,
                    "description": action_result.description,
                })

    scenarios_passed = sum(1 for r in results if r.passed)
    scenarios_failed = len(results) - scenarios_passed
    pass_rate = scenarios_passed / len(results) if results else 1.0

    summary_lines = [f"Adversarial Testing: {scenarios_passed}/{len(results)} scenarios passed"]
    for r in results:
        status = "PASS" if r.passed else "FAIL"
        summary_lines.append(f"  [{status}] {r.scenario_name}: {r.actions_passed}/{r.actions_tested}")
    if unexpected_allows:
        summary_lines.append(f"\n  {len(unexpected_allows)} unexpected ALLOW verdict(s) detected!")

    return AdversarialReport(
        scenarios_run=len(results),
        scenarios_passed=scenarios_passed,
        scenarios_failed=scenarios_failed,
        pass_rate=pass_rate,
        results=results,
        unexpected_allows=unexpected_allows,
        summary_text="\n".join(summary_lines),
    )


def _build_runtime(config: GovernanceConfig) -> GovernanceRuntime:
    """Build a GovernanceRuntime configured from the governance config."""
    runtime_config = RuntimeConfig(
        allow_threshold=config.allow_threshold,
        deny_threshold=config.deny_threshold,
    )
    runtime = GovernanceRuntime(config=runtime_config)
    _configure_runtime(runtime, config)
    return runtime


def _evaluate_action(
    runtime: GovernanceRuntime,
    agent_id: str,
    action_type: str,
    target: str,
    trust: float,
    expected: str,
    description: str,
) -> ActionTestResult:
    """Evaluate a single action and compare to expected verdict."""
    action = Action(agent_id=agent_id, action_type=action_type, target=target)
    context = AgentContext(
        agent_id=agent_id,
        trust_profile=TrustProfile(agent_id=agent_id, overall_trust=trust),
    )
    verdict = runtime.evaluate(action, context)
    actual = verdict.verdict.name
    passed = actual == expected
    return ActionTestResult(
        action_type=action_type,
        target=target,
        agent_id=agent_id,
        expected_verdict=expected,
        actual_verdict=actual,
        ucs=verdict.ucs,
        passed=passed,
        description=description,
    )


def _get_all_scenarios(
    config: GovernanceConfig,
) -> list[Callable[[GovernanceRuntime, GovernanceConfig], ScenarioTestResult]]:
    """Return all adversarial scenario test functions."""
    return [
        _scenario_privilege_escalation,
        _scenario_scope_assembly,
        _scenario_boundary_probing,
        _scenario_trust_manipulation,
        _scenario_action_type_abuse,
        _scenario_cross_agent_impersonation,
    ]


# --- Adversarial Scenarios ---


def _scenario_privilege_escalation(
    runtime: GovernanceRuntime, config: GovernanceConfig
) -> ScenarioTestResult:
    """Test privilege escalation attempts.

    Agents attempt actions outside their configured scope — actions they are
    not authorized for. All should be DENIED.
    """
    results: list[ActionTestResult] = []

    for agent in config.agents:
        # Attempt a delete action (usually not in scope)
        if "delete" not in agent.scope:
            results.append(_evaluate_action(
                runtime, agent.agent_id, "delete",
                agent.targets[0] if agent.targets else "some_target",
                agent.initial_trust, "DENY",
                f"Agent '{agent.agent_id}' attempts unauthorized 'delete'",
            ))

        # Attempt an execute action
        if "execute" not in agent.scope:
            results.append(_evaluate_action(
                runtime, agent.agent_id, "execute",
                "system_command", agent.initial_trust, "DENY",
                f"Agent '{agent.agent_id}' attempts unauthorized 'execute'",
            ))

        # Attempt an approve action
        if "approve" not in agent.scope:
            results.append(_evaluate_action(
                runtime, agent.agent_id, "approve",
                "admin_panel", agent.initial_trust, "DENY",
                f"Agent '{agent.agent_id}' attempts unauthorized 'approve'",
            ))

        # Attempt an admin action
        if "admin" not in agent.scope:
            results.append(_evaluate_action(
                runtime, agent.agent_id, "admin",
                "system_config", agent.initial_trust, "DENY",
                f"Agent '{agent.agent_id}' attempts unauthorized 'admin'",
            ))

    passed = sum(1 for r in results if r.passed)
    return ScenarioTestResult(
        scenario_name="Privilege Escalation",
        description="Agents attempt actions outside their configured scope",
        actions_tested=len(results),
        actions_passed=passed,
        passed=passed == len(results),
        results=results,
    )


def _scenario_scope_assembly(
    runtime: GovernanceRuntime, config: GovernanceConfig
) -> ScenarioTestResult:
    """Test cross-agent scope assembly.

    An adversary might try to use one agent's read access with another agent's
    write access. Each agent attempting the other's privileged actions should
    be denied.
    """
    results: list[ActionTestResult] = []

    for i, agent_a in enumerate(config.agents):
        for agent_b in config.agents[i + 1:]:
            # Agent A tries agent B's unique actions on B's targets
            b_only_actions = agent_b.scope - agent_a.scope
            for action_type in b_only_actions:
                for target in agent_b.targets:
                    if target not in agent_a.targets:
                        results.append(_evaluate_action(
                            runtime, agent_a.agent_id, action_type,
                            target, agent_a.initial_trust, "DENY",
                            (f"Agent '{agent_a.agent_id}' attempts '{action_type}' "
                             f"on '{target}' (belongs to '{agent_b.agent_id}')"),
                        ))
                        break  # One test per action type is sufficient

            # Agent B tries agent A's unique actions on A's targets
            a_only_actions = agent_a.scope - agent_b.scope
            for action_type in a_only_actions:
                for target in agent_a.targets:
                    if target not in agent_b.targets:
                        results.append(_evaluate_action(
                            runtime, agent_b.agent_id, action_type,
                            target, agent_b.initial_trust, "DENY",
                            (f"Agent '{agent_b.agent_id}' attempts '{action_type}' "
                             f"on '{target}' (belongs to '{agent_a.agent_id}')"),
                        ))
                        break

    if not results:
        # Add a baseline test if no cross-agent pairs exist
        agent = config.agents[0]
        results.append(_evaluate_action(
            runtime, agent.agent_id, "unauthorized_action",
            "unauthorized_target", agent.initial_trust, "DENY",
            f"Agent '{agent.agent_id}' attempts unauthorized action on unauthorized target",
        ))

    passed = sum(1 for r in results if r.passed)
    return ScenarioTestResult(
        scenario_name="Scope Assembly",
        description="Agents attempt to use other agents' privileges",
        actions_tested=len(results),
        actions_passed=passed,
        passed=passed == len(results),
        results=results,
    )


def _scenario_boundary_probing(
    runtime: GovernanceRuntime, config: GovernanceConfig
) -> ScenarioTestResult:
    """Test boundary probing.

    Agents attempt in-scope action types but on targets outside their boundaries.
    These should be denied by isolation_integrity.
    """
    results: list[ActionTestResult] = []
    unauthorized_targets = [
        "internal_secrets",
        "admin_database",
        "payment_processor",
        "credential_store",
    ]

    for agent in config.agents:
        for target in unauthorized_targets:
            if target not in agent.boundaries:
                action_type = next(iter(agent.scope)) if agent.scope else "read"
                results.append(_evaluate_action(
                    runtime, agent.agent_id, action_type,
                    target, agent.initial_trust, "DENY",
                    f"Agent '{agent.agent_id}' probes boundary with '{action_type}' on '{target}'",
                ))

    passed = sum(1 for r in results if r.passed)
    return ScenarioTestResult(
        scenario_name="Boundary Probing",
        description="Agents attempt actions on targets outside their boundaries",
        actions_tested=len(results),
        actions_passed=passed,
        passed=passed == len(results),
        results=results,
    )


def _scenario_trust_manipulation(
    runtime: GovernanceRuntime, config: GovernanceConfig
) -> ScenarioTestResult:
    """Test trust manipulation.

    Agents with very low trust attempt actions. Even in-scope actions should
    be more scrutinized at low trust levels.
    """
    results: list[ActionTestResult] = []

    for agent in config.agents:
        # Agent at near-zero trust attempts out-of-scope action
        results.append(_evaluate_action(
            runtime, agent.agent_id, "delete",
            "unauthorized_system",
            0.01,  # Very low trust
            "DENY",
            f"Agent '{agent.agent_id}' at trust=0.01 attempts unauthorized 'delete'",
        ))

        # Agent at near-zero trust attempts out-of-scope on sensitive target
        results.append(_evaluate_action(
            runtime, agent.agent_id, "execute",
            "credential_store",
            0.01,
            "DENY",
            f"Agent '{agent.agent_id}' at trust=0.01 attempts 'execute' on credentials",
        ))

    passed = sum(1 for r in results if r.passed)
    return ScenarioTestResult(
        scenario_name="Trust Manipulation",
        description="Low-trust agents attempt unauthorized actions",
        actions_tested=len(results),
        actions_passed=passed,
        passed=passed == len(results),
        results=results,
    )


def _scenario_action_type_abuse(
    runtime: GovernanceRuntime, config: GovernanceConfig
) -> ScenarioTestResult:
    """Test action type abuse.

    Agents attempt dangerous action types (delete, transfer, execute) on their
    own targets. If these action types aren't in scope, they should be denied.
    """
    results: list[ActionTestResult] = []
    dangerous_actions = ["delete", "transfer", "execute", "approve", "admin"]

    for agent in config.agents:
        for action_type in dangerous_actions:
            if action_type not in agent.scope:
                target = agent.targets[0] if agent.targets else "some_target"
                results.append(_evaluate_action(
                    runtime, agent.agent_id, action_type,
                    target, agent.initial_trust, "DENY",
                    (f"Agent '{agent.agent_id}' attempts dangerous "
                     f"'{action_type}' on own target '{target}'"),
                ))

    passed = sum(1 for r in results if r.passed)
    return ScenarioTestResult(
        scenario_name="Action Type Abuse",
        description="Agents attempt dangerous action types not in their scope",
        actions_tested=len(results),
        actions_passed=passed,
        passed=passed == len(results),
        results=results,
    )


def _scenario_cross_agent_impersonation(
    runtime: GovernanceRuntime, config: GovernanceConfig
) -> ScenarioTestResult:
    """Test cross-agent impersonation.

    A fake agent ID (not in the config) attempts actions on real targets.
    Without configured scope, all actions should be denied.
    """
    results: list[ActionTestResult] = []
    fake_agent_id = "malicious-agent-00"

    all_targets = set()
    for agent in config.agents:
        all_targets.update(agent.targets)

    for target in list(all_targets)[:4]:  # Test up to 4 targets
        results.append(_evaluate_action(
            runtime, fake_agent_id, "read",
            target, 0.5, "DENY",
            f"Fake agent '{fake_agent_id}' attempts 'read' on '{target}'",
        ))
        results.append(_evaluate_action(
            runtime, fake_agent_id, "write",
            target, 0.5, "DENY",
            f"Fake agent '{fake_agent_id}' attempts 'write' on '{target}'",
        ))

    if not results:
        results.append(_evaluate_action(
            runtime, fake_agent_id, "read",
            "some_target", 0.5, "DENY",
            f"Fake agent '{fake_agent_id}' attempts 'read' on unregistered target",
        ))

    passed = sum(1 for r in results if r.passed)
    return ScenarioTestResult(
        scenario_name="Cross-Agent Impersonation",
        description="Unregistered agents attempt actions on real targets",
        actions_tested=len(results),
        actions_passed=passed,
        passed=passed == len(results),
        results=results,
    )
