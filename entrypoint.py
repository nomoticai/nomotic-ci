"""Main entry point for the Nomotic CI GitHub Action.

Reads inputs, runs all governance validation checks, formats output,
posts PR comments, sets action outputs, and exits with the appropriate code.
"""

from __future__ import annotations

import json
import os
import sys
import time
import urllib.request
import urllib.error

from nomotic_ci.config_loader import load_config, ConfigError
from nomotic_ci.config_validator import validate
from nomotic_ci.adversarial_runner import run_adversarial_tests
from nomotic_ci.drift_checker import check_drift
from nomotic_ci.compound_authority import analyze_compound_authority
from nomotic_ci.bundle_generator import generate_bundle
from nomotic_ci.reporter import format_pr_comment, format_console_output
from nomotic_ci.outputs import set_output


def get_input(name: str, default: str = "") -> str:
    """Read a GitHub Action input from environment variables."""
    return os.environ.get(f"INPUT_{name.upper()}", default)


def get_bool_input(name: str, default: bool = False) -> bool:
    """Read a boolean GitHub Action input."""
    val = get_input(name, str(default).lower())
    return val.lower() in ("true", "1", "yes")


def get_pr_number() -> int | None:
    """Extract the PR number from the GitHub event payload."""
    event_path = os.environ.get("GITHUB_EVENT_PATH", "")
    if not event_path or not os.path.exists(event_path):
        return None
    try:
        with open(event_path) as f:
            event = json.load(f)
        pr = event.get("pull_request") or event.get("issue")
        if pr and "number" in pr:
            return int(pr["number"])
    except (json.JSONDecodeError, KeyError, TypeError, ValueError):
        pass
    return None


def post_pr_comment(comment: str, token: str) -> bool:
    """Post a comment to the PR using the GitHub REST API."""
    repo = os.environ.get("GITHUB_REPOSITORY", "")
    pr_number = get_pr_number()

    if not repo or not pr_number or not token:
        print("  Skipping PR comment: missing repository, PR number, or token.")
        return False

    url = f"https://api.github.com/repos/{repo}/issues/{pr_number}/comments"
    data = json.dumps({"body": comment}).encode()
    req = urllib.request.Request(
        url,
        data=data,
        headers={
            "Authorization": f"token {token}",
            "Accept": "application/vnd.github.v3+json",
            "Content-Type": "application/json",
        },
        method="POST",
    )

    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            if resp.status in (200, 201):
                print(f"  PR comment posted successfully.")
                return True
            print(f"  PR comment failed with status {resp.status}.")
    except urllib.error.HTTPError as e:
        print(f"  PR comment failed: {e.code} {e.reason}")
    except urllib.error.URLError as e:
        print(f"  PR comment failed: {e.reason}")

    return False


def main() -> int:
    """Run the Nomotic CI governance validation pipeline."""
    start_time = time.time()

    # Read inputs
    config_path = get_input("config_path", ".")
    config_file = get_input("config_file", "nomotic.yaml")
    baseline_ref = get_input("baseline_ref", "origin/main")
    run_adversarial = get_bool_input("adversarial_tests", True)
    run_compound = get_bool_input("compound_authority_check", True)
    run_drift = get_bool_input("drift_detection", True)
    run_bundle = get_bool_input("evidence_bundle", False)
    compliance_frameworks_str = get_input("compliance_frameworks", "")
    fail_on_critical = get_bool_input("fail_on_critical", True)
    fail_on_adversarial = get_bool_input("fail_on_adversarial", True)
    do_post_comment = get_bool_input("post_comment", True)
    github_token = get_input("github_token", "")
    sanitize = get_bool_input("sanitize_output", True)
    bundle_dir = get_input("bundle_dir", ".nomotic/bundles")

    compliance_frameworks = [
        f.strip() for f in compliance_frameworks_str.split(",") if f.strip()
    ]

    print("=" * 60)
    print("  Nomotic CI — Governance Validation")
    print("=" * 60)

    # Step 1: Load config
    print("\n[1/6] Loading governance configuration...")
    step_start = time.time()
    try:
        config = load_config(config_path, config_file)
        print(f"  Loaded: {config.source_path}")
        print(f"  Agents: {len(config.agents)}")
        print(f"  Version: {config.version}")
        print(f"  ({time.time() - step_start:.2f}s)")
    except FileNotFoundError as e:
        print(f"  ERROR: {e}")
        set_output("validation_status", "fail")
        set_output("issues_found", "1")
        set_output("critical_issues", "1")
        return 1
    except ConfigError as e:
        print(f"  ERROR: Config validation failed:")
        for err in e.errors:
            print(f"    - {err}")
        set_output("validation_status", "fail")
        set_output("issues_found", str(len(e.errors)))
        set_output("critical_issues", str(len(e.errors)))
        return 1

    # Step 2: Validate config
    print("\n[2/6] Validating governance configuration...")
    step_start = time.time()
    validation_report = validate(config)
    print(f"  Status: {validation_report.status}")
    print(f"  Issues: {validation_report.issues_found} "
          f"(critical={validation_report.critical_count}, "
          f"warning={validation_report.warning_count}, "
          f"info={validation_report.info_count})")
    print(f"  ({time.time() - step_start:.2f}s)")

    # Step 3: Adversarial tests
    adversarial_report = None
    if run_adversarial:
        print("\n[3/6] Running adversarial test suite...")
        step_start = time.time()
        adversarial_report = run_adversarial_tests(config)
        print(f"  Scenarios: {adversarial_report.scenarios_passed}/{adversarial_report.scenarios_run} passed")
        print(f"  Pass rate: {adversarial_report.pass_rate:.0%}")
        if adversarial_report.unexpected_allows:
            print(f"  Unexpected ALLOWs: {len(adversarial_report.unexpected_allows)}")
        print(f"  ({time.time() - step_start:.2f}s)")
    else:
        print("\n[3/6] Adversarial tests: skipped")

    # Step 4: Drift detection
    drift_report = None
    if run_drift:
        print("\n[4/6] Checking configuration drift...")
        step_start = time.time()
        # Determine the config file path relative to repo root
        config_rel_path = os.path.relpath(config.source_path)
        drift_report = check_drift(config, baseline_ref, config_rel_path)
        print(f"  Drift detected: {drift_report.drift_detected}")
        if drift_report.drift_detected:
            print(f"  Changes: {len(drift_report.findings)} "
                  f"(critical={drift_report.critical_count}, "
                  f"warning={drift_report.warning_count}, "
                  f"info={drift_report.info_count})")
        print(f"  ({time.time() - step_start:.2f}s)")
    else:
        print("\n[4/6] Drift detection: skipped")

    # Step 5: Compound authority analysis
    compound_report = None
    if run_compound:
        print("\n[5/6] Analyzing compound authority...")
        step_start = time.time()
        compound_report = analyze_compound_authority(config)
        total_findings = len(compound_report.findings)
        print(f"  Findings: {total_findings} "
              f"(critical={compound_report.critical_count}, "
              f"warning={compound_report.warning_count})")
        print(f"  ({time.time() - step_start:.2f}s)")
    else:
        print("\n[5/6] Compound authority analysis: skipped")

    # Step 6: Evidence bundle
    bundle_path = ""
    if run_bundle:
        print("\n[6/6] Generating evidence bundle...")
        step_start = time.time()
        bundle = generate_bundle(
            config=config,
            validation_report=validation_report,
            adversarial_report=adversarial_report,
            drift_report=drift_report,
            compound_report=compound_report,
            compliance_frameworks=compliance_frameworks or None,
            bundle_dir=bundle_dir,
            sanitize=sanitize,
        )
        bundle_path = bundle.bundle_path
        print(f"  Bundle: {bundle.bundle_path}")
        print(f"  Hash: {bundle.bundle_hash[:16]}...")
        print(f"  ({time.time() - step_start:.2f}s)")
    else:
        print("\n[6/6] Evidence bundle: skipped")

    # Determine overall status
    overall_status = _determine_overall_status(
        validation_report=validation_report,
        adversarial_report=adversarial_report,
        drift_report=drift_report,
        fail_on_critical=fail_on_critical,
        fail_on_adversarial=fail_on_adversarial,
    )

    # Console output
    console = format_console_output(
        validation_report=validation_report,
        adversarial_report=adversarial_report,
        drift_report=drift_report,
        compound_report=compound_report,
        overall_status=overall_status,
    )
    print(f"\n{console}")

    # PR comment
    if do_post_comment:
        print("Posting PR comment...")
        comment = format_pr_comment(
            validation_report=validation_report,
            adversarial_report=adversarial_report,
            drift_report=drift_report,
            compound_report=compound_report,
            overall_status=overall_status,
        )
        post_pr_comment(comment, github_token)

    # Set outputs
    set_output("validation_status", overall_status)
    set_output("issues_found", str(validation_report.issues_found))
    set_output("critical_issues", str(validation_report.critical_count))
    set_output("adversarial_pass_rate", str(adversarial_report.pass_rate) if adversarial_report else "")
    set_output("drift_detected", str(drift_report.drift_detected).lower() if drift_report else "false")
    set_output("compound_authority_flags", str(len(compound_report.findings)) if compound_report else "0")
    set_output("bundle_path", bundle_path)

    elapsed = time.time() - start_time
    print(f"\nCompleted in {elapsed:.2f}s — status: {overall_status.upper()}")

    return 1 if overall_status == "fail" else 0


def _determine_overall_status(
    validation_report: ValidationReport,
    adversarial_report: AdversarialReport | None,
    drift_report: DriftReport | None,
    fail_on_critical: bool,
    fail_on_adversarial: bool,
) -> str:
    """Determine the overall pass/warn/fail status."""
    # Critical validation issues
    if fail_on_critical and validation_report.critical_count > 0:
        return "fail"

    # Critical drift issues
    if fail_on_critical and drift_report and drift_report.critical_count > 0:
        return "fail"

    # Adversarial failures
    if fail_on_adversarial and adversarial_report and adversarial_report.scenarios_failed > 0:
        return "fail"

    # Warnings
    if validation_report.warning_count > 0:
        return "warn"

    if drift_report and drift_report.warning_count > 0:
        return "warn"

    return "pass"


if __name__ == "__main__":
    sys.exit(main())
