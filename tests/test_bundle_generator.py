"""Tests for bundle_generator module."""

from __future__ import annotations

import json
import os
import tempfile

import yaml

from nomotic_ci.config_loader import load_config_from_string, VALID_DIMENSIONS
from nomotic_ci.config_validator import validate
from nomotic_ci.adversarial_runner import run_adversarial_tests
from nomotic_ci.bundle_generator import generate_bundle, _sanitize


def _basic_config_dict() -> dict:
    return {
        "version": "1.0",
        "agents": {
            "agent-a": {
                "scope": {
                    "actions": ["read", "query"],
                    "targets": ["db_a"],
                    "boundaries": ["db_a"],
                },
                "trust": {"initial": 0.5, "minimum_for_action": 0.3},
                "owner": "a@test.com",
                "reason": "test",
            },
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
        "compliance": {"frameworks": ["SOC2"]},
    }


def _load(data: dict):
    return load_config_from_string(yaml.dump(data))


class TestBundleGeneration:
    """Test evidence bundle generation."""

    def test_bundle_created(self):
        config = _load(_basic_config_dict())
        report = validate(config)
        with tempfile.TemporaryDirectory() as tmpdir:
            bundle = generate_bundle(
                config=config,
                validation_report=report,
                bundle_dir=tmpdir,
            )
            assert os.path.exists(bundle.bundle_path)
            assert bundle.bundle_id.startswith("nci-")

    def test_bundle_with_frameworks(self):
        config = _load(_basic_config_dict())
        report = validate(config)
        with tempfile.TemporaryDirectory() as tmpdir:
            bundle = generate_bundle(
                config=config,
                validation_report=report,
                compliance_frameworks=["SOC2", "HIPAA"],
                bundle_dir=tmpdir,
            )
            assert "SOC2" in bundle.compliance_frameworks
            assert "HIPAA" in bundle.compliance_frameworks

    def test_bundle_uses_config_frameworks(self):
        config = _load(_basic_config_dict())
        report = validate(config)
        with tempfile.TemporaryDirectory() as tmpdir:
            bundle = generate_bundle(
                config=config,
                validation_report=report,
                bundle_dir=tmpdir,
            )
            assert "SOC2" in bundle.compliance_frameworks


class TestBundleHash:
    """Test bundle hash generation."""

    def test_hash_present(self):
        config = _load(_basic_config_dict())
        report = validate(config)
        with tempfile.TemporaryDirectory() as tmpdir:
            bundle = generate_bundle(
                config=config,
                validation_report=report,
                bundle_dir=tmpdir,
            )
            assert len(bundle.bundle_hash) == 64  # SHA-256 hex digest

    def test_hash_matches_content(self):
        config = _load(_basic_config_dict())
        report = validate(config)
        with tempfile.TemporaryDirectory() as tmpdir:
            bundle = generate_bundle(
                config=config,
                validation_report=report,
                bundle_dir=tmpdir,
            )
            with open(bundle.bundle_path) as f:
                data = json.load(f)
            assert "bundle_hash" in data


class TestSanitization:
    """Test sensitive data sanitization."""

    def test_email_sanitized(self):
        text = "owner is user@example.com for this agent"
        sanitized = _sanitize(text)
        assert "user@example.com" not in sanitized
        assert "[EMAIL_REDACTED]" in sanitized

    def test_github_token_sanitized(self):
        text = "token: ghp_abcdefghijklmnopqrstuvwxyz1234567890"
        sanitized = _sanitize(text)
        assert "ghp_" not in sanitized
        assert "[GITHUB_TOKEN_REDACTED]" in sanitized

    def test_api_key_sanitized(self):
        text = "api key: sk-12345678901234567890123456789012"
        sanitized = _sanitize(text)
        assert "sk-" not in sanitized

    def test_sanitization_applied_to_bundle(self):
        data = _basic_config_dict()
        data["agents"]["agent-a"]["owner"] = "secret@company.com"
        config = _load(data)
        report = validate(config)
        with tempfile.TemporaryDirectory() as tmpdir:
            bundle = generate_bundle(
                config=config,
                validation_report=report,
                bundle_dir=tmpdir,
                sanitize=True,
            )
            with open(bundle.bundle_path) as f:
                content = f.read()
            assert "secret@company.com" not in content


class TestBundleDirectory:
    """Test bundle directory handling."""

    def test_creates_directory(self):
        config = _load(_basic_config_dict())
        report = validate(config)
        with tempfile.TemporaryDirectory() as tmpdir:
            bundle_dir = os.path.join(tmpdir, "nested", "bundles")
            bundle = generate_bundle(
                config=config,
                validation_report=report,
                bundle_dir=bundle_dir,
            )
            assert os.path.isdir(bundle_dir)
            assert os.path.exists(bundle.bundle_path)

    def test_bundle_path_in_correct_dir(self):
        config = _load(_basic_config_dict())
        report = validate(config)
        with tempfile.TemporaryDirectory() as tmpdir:
            bundle = generate_bundle(
                config=config,
                validation_report=report,
                bundle_dir=tmpdir,
            )
            assert bundle.bundle_path.startswith(tmpdir)


class TestBundleContents:
    """Test bundle JSON content."""

    def test_contains_validation(self):
        config = _load(_basic_config_dict())
        report = validate(config)
        with tempfile.TemporaryDirectory() as tmpdir:
            bundle = generate_bundle(
                config=config,
                validation_report=report,
                bundle_dir=tmpdir,
            )
            with open(bundle.bundle_path) as f:
                data = json.load(f)
            assert "validation" in data
            assert data["validation"]["status"] in ("pass", "warn", "fail")

    def test_contains_adversarial(self):
        config = _load(_basic_config_dict())
        validation = validate(config)
        adversarial = run_adversarial_tests(config)
        with tempfile.TemporaryDirectory() as tmpdir:
            bundle = generate_bundle(
                config=config,
                validation_report=validation,
                adversarial_report=adversarial,
                bundle_dir=tmpdir,
            )
            with open(bundle.bundle_path) as f:
                data = json.load(f)
            assert data["adversarial_testing"] is not None
            assert "scenarios_run" in data["adversarial_testing"]

    def test_contains_metadata(self):
        config = _load(_basic_config_dict())
        report = validate(config)
        with tempfile.TemporaryDirectory() as tmpdir:
            bundle = generate_bundle(
                config=config,
                validation_report=report,
                bundle_dir=tmpdir,
            )
            with open(bundle.bundle_path) as f:
                data = json.load(f)
            assert "bundle_id" in data
            assert "timestamp" in data
            assert "config_version" in data
