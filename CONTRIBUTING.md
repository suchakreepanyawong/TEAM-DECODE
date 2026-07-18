# Contributing to Auto Multibase Decode

Thanks for your interest in contributing! This document describes how to get the code, run tests, and submit changes.

## Code of conduct
Please follow the repository `CODE_OF_CONDUCT.md`. Be respectful and constructive.

## Quick start
1. Fork the repository and create a feature branch:

```bash
git checkout -b feature/my-change
```

2. Install dependencies (recommended in a venv):

```bash
python -m venv .venv
.venv\Scripts\activate    # Windows
source .venv/bin/activate  # Unix
python -m pip install -r requirements.txt
```

3. Run tests:

```bash
pytest -q
```

## Style and tests
- Follow existing code style (PEP8). Keep changes minimal and focused.
- Add unit tests for new features and bug fixes.
- Ensure tests pass locally before submitting a PR.

## Commit messages and PRs
- Use clear commit messages describing the intent.
- Open a PR against `main` with a descriptive title and summary.
- If your change affects behavior, include examples and test cases.

## Security issues
If you find a security vulnerability, please follow `SECURITY.md` to report it privately.

Thank you for helping improve this project!