"""Format validation results for PR comments and console output.

Generates Markdown-formatted reports for GitHub PR comments and plain-text
output for the console/action log.
"""

from __future__ import annotations

from nomotic_ci import __version__
from nomotic_ci.config_validator import ValidationReport
from nomotic_ci.adversarial_runner import AdversarialReport
from nomotic_ci.drift_checker import DriftReport
from nomotic_ci.compound_authority import CompoundAuthorityReport


SEVERITY_ICONS = {
    "critical": "\u274c",   # red X
    "warning": "\u26a0\ufe0f",  # warning sign
    "info": "\u2139\ufe0f",     # info
}

STATUS_ICONS = {
    "pass": "\u2705",    # green check
    "warn": "\u26a0\ufe0f",  # warning sign
    "fail": "\u274c",    # red X
}


def format_pr_comment(
    validation_report: ValidationReport,
    adversarial_report: AdversarialReport | None = None,
    drift_report: DriftReport | None = None,
    compound_report: CompoundAuthorityReport | None = None,
    overall_status: str = "pass",
) -> str:
    """Format all results into a Markdown PR comment.

    Args:
        validation_report: Config validation results.
        adversarial_report: Adversarial testing results (optional).
        drift_report: Drift detection results (optional).
        compound_report: Compound authority results (optional).
        overall_status: One of "pass", "warn", "fail".

    Returns:
        A Markdown-formatted string suitable for a PR comment.
    """
    status_icon = STATUS_ICONS.get(overall_status, "\u2753")
    status_label = {"pass": "Pass", "warn": "Warning", "fail": "Fail"}.get(
        overall_status, "Unknown"
    )

    sections = []
    sections.append("## \U0001f6e1\ufe0f Nomotic Governance Validation\n")
    sections.append(f"**Status**: {status_icon} {status_label}\n")

    # Validation section
    sections.append(_format_validation_section(validation_report))

    # Adversarial section
    if adversarial_report is not None:
        sections.append(_format_adversarial_section(adversarial_report))

    # Drift section
    if drift_report is not None:
        sections.append(_format_drift_section(drift_report))

    # Compound authority section
    if compound_report is not None:
        sections.append(_format_compound_section(compound_report))

    sections.append(
        f"\n---\n*Validated by "
        f"[Nomotic CI](https://github.com/NomoticAI/nomotic-ci) v{__version__}*"
    )

    return "\n".join(sections)


def format_console_output(
    validation_report: ValidationReport,
    adversarial_report: AdversarialReport | None = None,
    drift_report: DriftReport | None = None,
    compound_report: CompoundAuthorityReport | None = None,
    overall_status: str = "pass",
) -> str:
    """Format results as plain text for console output."""
    lines = []
    lines.append("=" * 60)
    lines.append("  Nomotic Governance Validation")
    lines.append("=" * 60)
    lines.append(f"  Status: {overall_status.upper()}")
    lines.append("")

    # Validation
    lines.append("--- Configuration Validation ---")
    lines.append(f"  Checks run: {validation_report.checks_run}")
    lines.append(f"  Issues: {validation_report.issues_found} "
                 f"(critical={validation_report.critical_count}, "
                 f"warning={validation_report.warning_count}, "
                 f"info={validation_report.info_count})")
    for issue in validation_report.issues:
        lines.append(f"  [{issue.severity.upper()}] {issue.check_name}: {issue.message}")

    # Adversarial
    if adversarial_report is not None:
        lines.append("")
        lines.append("--- Adversarial Testing ---")
        lines.append(adversarial_report.summary_text)

    # Drift
    if drift_report is not None:
        lines.append("")
        lines.append("--- Configuration Drift ---")
        lines.append(drift_report.summary_text)

    # Compound authority
    if compound_report is not None:
        lines.append("")
        lines.append("--- Compound Authority ---")
        lines.append(compound_report.summary_text)

    lines.append("")
    lines.append("=" * 60)
    return "\n".join(lines)


def _format_validation_section(report: ValidationReport) -> str:
    """Format the validation section of the PR comment."""
    lines = []
    lines.append("### Configuration Validation")

    if not report.issues:
        lines.append("\n\u2705 All checks passed.\n")
        return "\n".join(lines)

    lines.append("")
    lines.append("| Check | Status | Details |")
    lines.append("|-------|--------|---------|")

    # Group issues by check_name for a cleaner table
    seen_checks: set[str] = set()
    for issue in report.issues:
        if issue.check_name in seen_checks:
            continue
        seen_checks.add(issue.check_name)
        icon = SEVERITY_ICONS.get(issue.severity, "\u2753")
        lines.append(f"| {issue.check_name} | {icon} | {issue.message} |")

    lines.append("")
    return "\n".join(lines)


def _format_adversarial_section(report: AdversarialReport) -> str:
    """Format the adversarial testing section of the PR comment."""
    lines = []
    lines.append("### Adversarial Testing")

    total_actions = sum(r.actions_tested for r in report.results)
    total_passed = sum(r.actions_passed for r in report.results)
    lines.append(f"**Pass rate: {total_passed}/{total_actions} "
                 f"({report.pass_rate:.0%})**\n")

    lines.append("| Scenario | Result | Details |")
    lines.append("|----------|--------|---------|")

    for result in report.results:
        icon = "\u2705" if result.passed else "\u274c"
        lines.append(
            f"| {result.scenario_name} | {icon} {result.actions_passed}/{result.actions_tested} "
            f"| {result.description} |"
        )

    if report.unexpected_allows:
        lines.append(f"\n\u26a0\ufe0f **{len(report.unexpected_allows)} unexpected ALLOW "
                     f"verdict(s)** — actions that should have been denied were allowed.\n")

    lines.append("")
    return "\n".join(lines)


def _format_drift_section(report: DriftReport) -> str:
    """Format the drift detection section of the PR comment."""
    lines = []
    lines.append("### Configuration Drift")

    if not report.drift_detected:
        lines.append(f"\n{report.summary_text}\n")
        return "\n".join(lines)

    lines.append("")
    lines.append("| Change | Severity | Details |")
    lines.append("|--------|----------|---------|")

    for finding in report.findings:
        icon = SEVERITY_ICONS.get(finding.severity, "\u2753")
        lines.append(
            f"| `{finding.path}` | {icon} {finding.severity.capitalize()} "
            f"| {finding.description} |"
        )

    lines.append("")
    return "\n".join(lines)


def _format_compound_section(report: CompoundAuthorityReport) -> str:
    """Format the compound authority section of the PR comment."""
    lines = []
    lines.append("### Compound Authority")

    if not report.findings:
        lines.append("\nNo compound authority vulnerabilities detected.\n")
        return "\n".join(lines)

    lines.append("")
    lines.append("| Risk | Severity | Agents | Details |")
    lines.append("|------|----------|--------|---------|")

    for finding in report.findings:
        icon = SEVERITY_ICONS.get(finding.severity, "\u2753")
        agents = ", ".join(finding.agents_involved)
        lines.append(
            f"| {finding.resulting_capability} | {icon} {finding.severity.capitalize()} "
            f"| {agents} | {finding.description} |"
        )

    lines.append("")
    return "\n".join(lines)
