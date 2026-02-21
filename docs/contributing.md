---
title: Contributing
description: Contribute to GuardianShield — help make AI security accessible to everyone.
---

# Contributing to GuardianShield

GuardianShield is open source and contributions are welcome. Whether you are fixing a typo, adding a detection pattern, improving documentation, or building a new feature — every contribution helps make AI security more accessible.

!!! tip "First time contributing to open source?"
    GuardianShield is a great project to start with. The codebase is pure Python with zero external dependencies, the test suite is straightforward, and the maintainers are happy to guide you through the process.

---

## Development Setup

Fork and clone the repository, then install in development mode:

```bash
git clone https://github.com/sparkvibe-io/GuardianShield.git
cd GuardianShield
pip install -e ".[dev]"
make test
```

This installs GuardianShield in editable mode with all development dependencies — testing, linting, type checking, and documentation tools.

!!! note "Python version"
    GuardianShield requires **Python 3.9 or higher**. We recommend using the latest stable Python release for development.

---

## Running Tests

Run the full test suite with:

```bash
make test
```

Or call pytest directly for more control:

```bash
pytest tests/ -v
```

Run a specific test file or test function:

```bash
pytest tests/test_code_scanner.py -v
pytest tests/test_code_scanner.py::test_sql_injection_detection -v
```

!!! tip "Write tests for every change"
    All new features and bug fixes should include corresponding tests. If you are adding a new detection pattern, include test cases for both true positives (should detect) and true negatives (should not flag).

---

## Code Style

GuardianShield uses [Ruff](https://docs.astral.sh/ruff/) for linting and formatting, and [mypy](https://mypy-lang.org/) for static type checking.

### Linting

```bash
make lint
```

This runs `ruff check` against the codebase. Fix any issues before submitting a pull request.

### Formatting

```bash
make format
```

This runs `ruff format` to apply consistent code formatting. The CI pipeline will reject PRs with formatting violations.

### Type Checking

```bash
make typecheck
```

This runs `mypy` with strict mode. All public functions and methods should have type annotations.

!!! note
    Run all three checks before committing. The CI pipeline runs `make lint`, `make format --check`, and `make typecheck` on every pull request.

---

## Adding Detection Patterns

One of the most impactful ways to contribute is adding new regex detection patterns to GuardianShield's scanners. Each scanner module maintains a list of compiled patterns that are matched against input text.

### Steps

1. **Identify the scanner** — Determine which scanner module your pattern belongs to:

    - `code_scanner` — Vulnerability patterns (SQLi, XSS, command injection, etc.)
    - `secret_scanner` — Credential and secret patterns (API keys, tokens, passwords)
    - `injection_scanner` — Prompt injection heuristics
    - `pii_scanner` — Personally identifiable information patterns
    - `content_scanner` — Content moderation patterns

2. **Add the pattern** — Add your compiled regex to the appropriate pattern list in the scanner module under `src/guardianshield/scanners/`.

3. **Set severity and metadata** — Each pattern should include a severity level (`CRITICAL`, `HIGH`, `MEDIUM`, or `LOW`), a finding type, and a descriptive message.

4. **Write tests** — Add test cases in `tests/` that cover:

    - True positives — inputs that should trigger the pattern
    - True negatives — similar but benign inputs that should not trigger
    - Edge cases — boundary conditions, encoding variations, partial matches

5. **Test across sensitivity levels** — Verify that your pattern behaves correctly at `low`, `medium`, and `high` sensitivity settings.

!!! tip "Pattern quality matters"
    A good detection pattern is specific enough to avoid false positives on common code, but broad enough to catch real threats. When in doubt, favor precision over recall — fewer false positives makes GuardianShield more useful for developers.

---

## Adding a New Profile

Safety profiles are YAML files that define a complete security policy. To add a new profile:

1. **Create the profile file** — Add a new YAML file in `src/guardianshield/profiles/`:

    ```yaml title="src/guardianshield/profiles/my_profile.yaml"
    name: my_profile
    description: A custom safety profile for specific use case
    sensitivity: medium
    scanners:
      code_scanner:
        enabled: true
      secret_scanner:
        enabled: true
      injection_scanner:
        enabled: true
      pii_scanner:
        enabled: true
      content_scanner:
        enabled: true
    blocked_categories:
      - violence
      - self_harm
    ```

2. **Register the profile** — Add an entry for your profile in the `BUILTIN_PROFILES` dictionary so GuardianShield discovers it at startup.

3. **Write tests** — Add test cases that verify your profile loads correctly and applies the expected scanner configuration and sensitivity settings.

4. **Document the profile** — Include a description of the target use case and how it differs from existing profiles.

---

## Pull Request Process

1. **Fork** the repository on GitHub.

2. **Create a feature branch** from `main`:

    ```bash
    git checkout -b feature/my-improvement
    ```

3. **Make your changes** — Write code, add tests, update documentation as needed.

4. **Run the full check suite** before committing:

    ```bash
    make lint
    make format
    make typecheck
    make test
    ```

5. **Commit with a clear message** that describes what changed and why:

    ```bash
    git commit -m "Add detection pattern for Heroku API keys"
    ```

6. **Push to your fork** and open a pull request against `main`.

7. **Respond to review feedback** — Maintainers will review your PR and may request changes. All PRs require at least one approval before merging.

!!! note "Keep PRs focused"
    Each pull request should address a single concern — one bug fix, one feature, or one set of related patterns. Smaller PRs are easier to review and faster to merge.

---

## Code of Conduct

GuardianShield is committed to providing a welcoming and inclusive environment for everyone. All contributors are expected to:

- **Be respectful** — Treat every contributor with dignity and professionalism, regardless of experience level, background, or identity.
- **Be inclusive** — Welcome newcomers, explain context when asked, and make space for diverse perspectives.
- **Be constructive** — Offer actionable feedback in code reviews. Critique ideas, not people.
- **Be collaborative** — Work toward shared goals. Disagreements are welcome; hostility is not.

Unacceptable behavior includes harassment, personal attacks, trolling, and deliberate intimidation. Maintainers reserve the right to remove any content or contributor that violates these standards.

If you experience or witness unacceptable behavior, please open a private issue or contact the maintainers directly.

---

## License

All contributions to GuardianShield are made under the **Apache-2.0** license. By submitting a pull request, you agree that your contribution will be licensed under the same terms.

This ensures that GuardianShield remains free, open-source, and legally safe for everyone to use — including the patent grant that protects adopters from IP claims.

---

## Getting Help

If you have questions about contributing, need guidance on an approach, or want to discuss a feature idea before writing code:

- **Open a GitHub issue** — [github.com/sparkvibe-io/GuardianShield/issues](https://github.com/sparkvibe-io/GuardianShield/issues)
- **Start a discussion** — Use GitHub Discussions for open-ended questions and ideas.
- **Read the docs** — The [Configuration](configuration.md) and [Getting Started](getting-started.md) guides cover most common topics.

[Open an Issue :material-arrow-right:](https://github.com/sparkvibe-io/GuardianShield/issues){ .md-button .md-button--primary }
[Read the Docs](getting-started.md){ .md-button }
