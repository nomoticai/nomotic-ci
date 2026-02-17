"""Run adversarial test scenarios against governance configurations.

Uses the nomotic library's built-in adversarial scenario library and runner
to red-team each agent's governance envelope. The library provides structured
multi-phase attack scenarios (injection resistance, privilege escalation,
drift inducement, trust manipulation, confused deputy, boundary probing)
and a runner that evaluates governance verdicts against expected outcomes.

The CI layer converts GovernanceConfig agents into sandbox AgentConfigs,
runs the library scenarios, and maps the results into a CI-friendly
AdversarialReport.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from tempfile import mkdtemp
from typing import Any

from nomotic.adversarial import (
    AdversarialRunner as LibraryRunner,
    ScenarioTestResult as LibScenarioResult,
    get_all_scenarios,
)

from nomotic_ci.config_loader import GovernanceConfig


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

    For each agent in the config, creates a library AdversarialRunner with
    the agent's scope and boundaries, then runs all built-in adversarial
    scenarios.  Results are aggregated into a single AdversarialReport.
    """
    scenarios = get_all_scenarios()
    all_results: list[ScenarioTestResult] = []
    unexpected_allows: list[dict[str, Any]] = []

    for agent in config.agents:
        base_dir = Path(mkdtemp(prefix="nomotic-ci-"))
        runner = LibraryRunner(base_dir=base_dir, agent_id=agent.agent_id)

        for scenario in scenarios:
            lib_result = runner.run_scenario(scenario)
            mapped = _map_scenario_result(lib_result, agent.agent_id)
            all_results.append(mapped)

            # Collect unexpected allows
            for action_result in mapped.results:
                if not action_result.passed and action_result.actual_verdict == "ALLOW":
                    unexpected_allows.append({
                        "scenario": mapped.scenario_name,
                        "action_type": action_result.action_type,
                        "target": action_result.target,
                        "agent_id": action_result.agent_id,
                        "ucs": action_result.ucs,
                        "description": action_result.description,
                    })

    scenarios_passed = sum(1 for r in all_results if r.passed)
    scenarios_failed = len(all_results) - scenarios_passed
    pass_rate = scenarios_passed / len(all_results) if all_results else 1.0

    summary_lines = [
        f"Adversarial Testing: {scenarios_passed}/{len(all_results)} scenarios passed"
    ]
    for r in all_results:
        status = "PASS" if r.passed else "FAIL"
        summary_lines.append(
            f"  [{status}] {r.scenario_name}: {r.actions_passed}/{r.actions_tested}"
        )
    if unexpected_allows:
        summary_lines.append(
            f"\n  {len(unexpected_allows)} unexpected ALLOW verdict(s) detected!"
        )

    return AdversarialReport(
        scenarios_run=len(all_results),
        scenarios_passed=scenarios_passed,
        scenarios_failed=scenarios_failed,
        pass_rate=pass_rate,
        results=all_results,
        unexpected_allows=unexpected_allows,
        summary_text="\n".join(summary_lines),
    )


def _map_scenario_result(
    lib_result: LibScenarioResult, agent_id: str,
) -> ScenarioTestResult:
    """Map a library ScenarioTestResult to our CI ScenarioTestResult."""
    mapped_actions: list[ActionTestResult] = []
    for ar in lib_result.action_results:
        mapped_actions.append(ActionTestResult(
            action_type=ar.attack_technique or "unknown",
            target="",
            agent_id=agent_id,
            expected_verdict=ar.expected_verdict,
            actual_verdict=ar.actual_verdict,
            ucs=ar.ucs,
            passed=ar.passed,
            description=ar.action_description,
        ))

    return ScenarioTestResult(
        scenario_name=lib_result.scenario_name.replace("_", " ").title(),
        description=lib_result.category,
        actions_tested=lib_result.total_actions,
        actions_passed=lib_result.correct_verdicts,
        passed=lib_result.passed,
        results=mapped_actions,
    )
