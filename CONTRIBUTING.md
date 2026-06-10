# Contributing to DRIFT

First: thank you. DRIFT is open because scrutiny makes it stronger.

---

## The iron rule

**Never implement cryptographic primitives from scratch.**

Use `PyNaCl` or the `cryptography` library for all curve math, AEAD,
and hashing. You are _composing_ well-understood building blocks —
not reimplementing them. PRs that hand-roll Curve25519, AES, or any
other primitive will be closed, no matter how elegant they look.

This rule exists because subtle implementation bugs in crypto code
can silently break security in ways that look perfectly fine in tests.
Vetted libraries have been reviewed by people who spend their careers
on this. We have not.

---

## Getting started

```bash
git clone https://github.com/YOUR_USERNAME/drift.git
cd drift
pip install -e ".[dev]"
pytest          # all tests should pass
ruff check .    # linter
mypy drift/     # type checker
```

---

## What to work on

Check the [issues](https://github.com/YOUR_USERNAME/drift/issues) tab.
The phase labels tell you where each issue fits:

| Label | Meaning |
|-------|---------|
| `phase-0` | Basic E2E — unblocked, good first issues |
| `phase-1` | Stealth addresses |
| `phase-2` | Double Ratchet |
| `phase-3` | Tor transport |
| `phase-4` | Federation + cover traffic |
| `phase-5` | Extras (panic key, FMD, etc.) |

**Phase 0 is the best starting point.** The chat UI (`drift/ui/`) and
the WebSocket client (`drift/transport/`) are both wide open.

---

## Pull request checklist

- [ ] All existing tests pass (`pytest`)
- [ ] New code has tests
- [ ] Linter passes (`ruff check .`)
- [ ] Type checker passes (`mypy drift/`)
- [ ] PR description explains *what* and *why*, not just *what*
- [ ] Crypto changes include a clear explanation of the security reasoning

---

## Security issues

Please **do not** open a public GitHub issue for security vulnerabilities.
Email the maintainers directly (address in SECURITY.md). We aim to
respond within 72 hours.

---

## Code style

- Python 3.11+, type-annotated, `ruff` formatted (line length 100)
- Docstrings on every public function — explain *why*, not just *what*
- No magic numbers in crypto code — name every constant and explain it
