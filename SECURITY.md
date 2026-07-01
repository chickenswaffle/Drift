# Security policy

## Supported versions

DRIFT is pre-alpha. No version is considered production-safe yet.
Do not use DRIFT for anything where your safety depends on it until
a formal independent audit has been completed and published here.

## Reporting a vulnerability

**Do not open a public GitHub issue for security vulnerabilities.**

Please report security issues by creating a [GitHub Security Advisory](https://github.com/YOUR_USERNAME/drift/security/advisories/new)
(private, only visible to maintainers and GitHub staff).

Include:
- A description of the vulnerability
- Steps to reproduce or a proof of concept
- The potential impact in your assessment

We aim to respond within **72 hours** and to issue a fix or mitigation
within **14 days** for critical issues.

## Audit status

- [ ] No independent audit has been performed yet.
- [ ] Audit planned for post-Phase 2 (once the core protocol is stable).

Results will be published in full in this repository.

## Desktop app signing

- macOS `.dmg` builds are **unsigned and un-notarized** — Gatekeeper will warn
  on first open. Verify the download's SHA-256 against the release page before
  opening. In-app updates are minisign-verified regardless.

## Scope

We consider the following in scope:
- Cryptographic protocol flaws
- Key material leakage
- Authentication bypasses
- Metadata leakage beyond documented threat model

Out of scope:
- Physical access attacks (beyond documented limits)
- Endpoint compromise (beyond documented limits)
- Social engineering
