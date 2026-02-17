# Nomotic CI — Governance Validation for CI/CD

[![CI](https://github.com/NomoticAI/nomotic-ci/actions/workflows/ci.yml/badge.svg)](https://github.com/NomoticAI/nomotic-ci/actions/workflows/ci.yml)

**nomotic-ci validates your AI governance rules before they reach production.**

For runtime agent governance, see [Nomotic](https://github.com/NomoticAI/Nomotic).

## What It Does

Nomotic CI is a GitHub Action that validates AI governance configurations (`nomotic.yaml`) in your CI/CD pipeline. On every PR that modifies governance rules, it:

- **Validates** configuration structure and logical consistency
- **Runs adversarial tests** against the config to verify it blocks unauthorized actions
- **Detects drift** from the baseline configuration on the target branch
- **Analyzes compound authority** risks across agents
- **Generates compliance evidence bundles** for auditable governance changes

## Quick Start

Add this workflow to your repository:

```yaml
# .github/workflows/governance.yml
name: Governance Validation

on:
  pull_request:
    paths:
      - 'nomotic.yaml'
      - '**/nomotic.yaml'

jobs:
  validate:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0  # Full history needed for drift detection against baseline

      - uses: NomoticAI/nomotic-ci@v1
        with:
          config_path: '.'
          adversarial_tests: 'true'
          drift_detection: 'true'
          compound_authority_check: 'true'
```

## Governance Configuration

Create a `nomotic.yaml` in your repository to define your AI agent governance rules:

```yaml
version: "1.0"

agents:
  customer-service-agent:
    scope:
      actions: [read, write, query]
      targets: [customer_records, order_history, faq_database]
      boundaries: [customer_records, order_history, faq_database]
    trust:
      initial: 0.5
      minimum_for_action: 0.3
    owner: "email@xxxxx.xxx"
    reason: "Customer service automation"

dimensions:
  weights:
    scope_compliance: 1.5
    authority_verification: 1.5
    resource_boundaries: 1.2
    behavioral_consistency: 1.0
    cascading_impact: 1.3
    stakeholder_impact: 1.2
    incident_detection: 1.5
    isolation_integrity: 1.4
    temporal_compliance: 0.8
    precedent_alignment: 0.7
    transparency: 0.6
    human_override: 2.0
    ethical_alignment: 2.0

  vetoes:
    - scope_compliance
    - authority_verification
    - resource_boundaries
    - incident_detection
    - isolation_integrity
    - temporal_compliance
    - human_override
    - ethical_alignment

thresholds:
  allow: 0.7
  deny: 0.3

trust:
  success_increment: 0.01
  violation_decrement: 0.05
  interrupt_cost: 0.03
  decay_rate: 0.001
  floor: 0.05
  ceiling: 0.95
```

See the `examples/` directory for fintech and healthcare configurations.

## What It Checks

### Configuration Validation

- Schema validation (required fields, valid dimension names)
- Threshold inversion (allow <= deny creates a paradox)
- Veto-weight contradictions (veto authority with zero weight)
- Missing vetoes on critical dimensions
- Overlapping agent scopes with shared targets
- Overprivileged agents (broad scopes)
- Trust floor above agent minimums
- Runtime simulation (verifies out-of-scope actions are denied)

### Adversarial Testing

Runs six attack scenarios per agent against the config using Nomotic's governance runtime:

| Scenario | What It Tests |
|----------|---------------|
| Prompt Injection Resistance | Injected instructions attempting to bypass governance |
| Privilege Escalation | Agents attempt actions outside their scope |
| Drift Inducement | Gradual behavioral shifts to erode governance boundaries |
| Trust Manipulation | Low-trust agents attempt unauthorized actions |
| Confused Deputy | Cross-agent privilege confusion and delegation abuse |
| Boundary Probing | In-scope actions on out-of-boundary targets |

### Drift Detection

Compares the PR's config against the target branch baseline:

| Category | Severity | Example |
|----------|----------|---------|
| Scope expansion | Warning/Critical | New actions added (critical if delete/transfer/execute) |
| Threshold relaxation | Warning | allow_threshold decreased |
| Veto removal | Critical | Dimension removed from veto list |
| Weight reduction | Warning | Security dimension weight decreased |
| Agent added/removed | Info | New agent definition |
| Trust relaxation | Warning | violation_decrement decreased |

### Compound Authority Analysis

Detects when individually-safe agent scopes combine to create unsafe capabilities:

- **Cross-agent**: Agent A reads + Agent B writes on shared target = effective update
- **Single-agent**: Agent has read + write + delete = full data lifecycle control
- **Workflow**: Sequential action patterns that escalate authority

## Example PR Comment

When a PR modifies governance rules, Nomotic CI posts a comment like this:

```markdown
## 🛡️ Nomotic Governance Validation

**Status**: ✅ Pass

### Configuration Validation
| Check | Status | Details |
|-------|--------|---------|
| Schema validation | ✅ | Valid nomotic.yaml |
| Threshold consistency | ✅ | allow (0.7) > deny (0.3) |
| Scope security | ⚠️ | Agent `trading-agent` has broad scope (4 action types) |
| Simulation check | ✅ | Out-of-scope actions correctly denied |

### Adversarial Testing
**Pass rate: 12/12 (100%)**

| Scenario | Result | Details |
|----------|--------|---------|
| Prompt Injection Resistance | ✅ | All injection attempts blocked |
| Privilege Escalation | ✅ | All escalation attempts blocked |
| Drift Inducement | ✅ | Drift correctly flagged |
| Trust Manipulation | ✅ | Trust manipulation blocked |
| Confused Deputy | ✅ | Deputy attacks handled |
| Boundary Probing | ✅ | All boundary probes handled |

### Configuration Drift
| Change | Severity | Details |
|--------|----------|---------|
| `agents.trading-agent.scope.actions` | ⚠️ Warning | Added `reconcile` action |
| `thresholds.allow` | ℹ️ Info | Changed 0.75 → 0.80 (stricter) |

### Compound Authority
No compound authority vulnerabilities detected.

---
*Validated by Nomotic CI v0.1.0*
```

## Inputs

| Input | Default | Description |
|-------|---------|-------------|
| `config_path` | `.` | Path to governance config directory or file |
| `config_file` | `nomotic.yaml` | Config file name to search for |
| `baseline_ref` | `origin/main` | Git ref for drift detection baseline |
| `adversarial_tests` | `true` | Run adversarial test suite |
| `compound_authority_check` | `true` | Analyze compound authority risks |
| `drift_detection` | `true` | Detect configuration drift |
| `evidence_bundle` | `false` | Generate compliance evidence bundle |
| `compliance_frameworks` | ` ` | Comma-separated frameworks (SOC2, HIPAA, PCI-DSS, ISO27001) |
| `fail_on_critical` | `true` | Fail if critical issues found |
| `fail_on_adversarial` | `true` | Fail if adversarial tests fail |
| `post_comment` | `true` | Post results as PR comment |
| `github_token` | `${{ github.token }}` | Token for PR comments |
| `sanitize_output` | `true` | Sanitize sensitive data in outputs |
| `bundle_dir` | `.nomotic/bundles` | Directory for evidence bundles |

## Outputs

| Output | Description |
|--------|-------------|
| `validation_status` | Overall result: `pass`, `warn`, or `fail` |
| `issues_found` | Total issues found |
| `critical_issues` | Critical issues count |
| `adversarial_pass_rate` | Test pass rate (0.0–1.0) |
| `drift_detected` | Whether drift was detected (`true`/`false`) |
| `compound_authority_flags` | Number of compound authority findings |
| `bundle_path` | Path to evidence bundle (if generated) |

## Evidence Bundles

When `evidence_bundle: 'true'`, Nomotic CI generates a JSON evidence package documenting:

- What governance rules were validated
- What checks were performed and their results
- What adversarial tests were run
- What drift was detected
- Compliance framework mappings (SOC2, HIPAA, PCI-DSS, ISO27001)

Archive bundles as build artifacts for compliance retention:

```yaml
      - uses: NomoticAI/nomotic-ci@v1
        with:
          evidence_bundle: 'true'
          compliance_frameworks: 'SOC2,HIPAA'

      - uses: actions/upload-artifact@v4
        if: always()
        with:
          name: governance-evidence
          path: .nomotic/bundles/
          retention-days: 2555  # 7 years for compliance
```

## Requirements

- Requires `nomotic>=0.2.0` ([PyPI](https://pypi.org/project/nomotic/))
- Python 3.11+
- Docker-based GitHub Action — no local installation needed

## License

Apache-2.0 — see [LICENSE](LICENSE).
