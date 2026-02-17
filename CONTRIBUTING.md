# Contributing to Nomotic CI

Thank you for your interest in contributing to Nomotic CI.

## Development Setup

1. Clone the repository:
   ```bash
   git clone https://github.com/NomoticAI/nomotic-ci.git
   cd nomotic-ci
   ```

2. Install in development mode:
   ```bash
   pip install -e ".[dev]"
   ```

3. Run tests:
   ```bash
   pytest tests/ -v
   ```

4. Run linter:
   ```bash
   ruff check src/ tests/
   ```

5. Run type checker:
   ```bash
   mypy src/nomotic_ci/
   ```

## Project Structure

- `src/nomotic_ci/` — Core library modules
- `tests/` — Test suite
- `examples/` — Example governance configurations
- `entrypoint.py` — GitHub Action entry point
- `action.yml` — GitHub Action definition

## Adding a New Validation Check

1. Add the check function to `src/nomotic_ci/config_validator.py`
2. Register it in the `validate()` function's check list
3. Add tests to `tests/test_config_validator.py`
4. Update `src/nomotic_ci/reporter.py` if the check needs special formatting

## Adding a New Adversarial Scenario

1. Add the scenario function to `src/nomotic_ci/adversarial_runner.py`
2. Register it in `_get_all_scenarios()`
3. Add tests to `tests/test_adversarial_runner.py`

## Submitting Changes

1. Fork the repository
2. Create a feature branch
3. Make your changes with tests
4. Ensure all tests pass and linting is clean
5. Submit a pull request

## Code Style

- Python 3.11+ with type annotations
- Line length: 100 characters
- Linted with ruff
- Type-checked with mypy (strict mode)
