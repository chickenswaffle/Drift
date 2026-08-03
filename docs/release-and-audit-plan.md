# DRIFT release and audit plan

**Status:** Proposed — deliberately prioritised before new protocol features.

DRIFT's strongest asset is a serious privacy model built from concrete technical
choices, rather than an instruction to trust a server. The next work should make
that work easier to operate, verify, and trust. This plan deliberately favours
evidence and release discipline over adding another headline capability.

## Outcome

Ship a coherent, reproducible desktop/reference release whose public claims,
source tree, CI results, and security documentation agree — then enter an
external audit with a small, well-defined scope and clear remediation process.

## Milestone 1 — establish a reliable release baseline

1. Triage every currently failing workflow, beginning with the desktop-app and
   Pi node image release runs. Record the cause, fix or explicitly defer it,
   and make the expected result visible in the workflow/release notes.
2. Ensure protected/default-branch CI runs the complete intended quality gate:
   unit and integration tests, linting, type checks, the Gauntlet, and desktop
   packaging checks where applicable.
3. Make release artifacts reproducible and attributable: document the build
   inputs, supported platforms, signing/verification steps, and provenance for
   each artifact.

**Exit criterion:** the current release branch is green end-to-end and a
maintainer can reproduce or verify every published artifact from documented
steps.

## Milestone 2 — align the public project story

1. Reconcile the README, `AGENTS.md`, changelog, badges, release tags, and
   active branches so they describe the same current release and phase status.
2. Publish one concise support matrix: reference CLI, relay, desktop app, Pi
   image, and planned mobile work — each marked as shipped, experimental, or
   planned.
3. Keep threat-model boundaries adjacent to the relevant claims. In particular,
   state what cover traffic, WITNESS, Tor transport, and Lockdown Mode do and
   do not protect against without implying a guarantee beyond the design.

**Exit criterion:** a new user can answer “what can I safely try today?” and
“what remains experimental?” from the repository front page without chasing
branches or release history.

## Milestone 3 — prepare and run an external security review

1. Freeze a review target: exact commit/tag, supported deployment modes,
   threat model, protocol documents, and all cryptographically sensitive code
   paths.
2. Produce an audit packet: architecture map, build instructions, test vectors,
   Gauntlet results, known limitations, and a reviewed inventory of third-party
   dependencies and licenses.
3. Commission an independent audit appropriate to the target scope. Do not
   treat self-review, CI, or the Gauntlet as a substitute for independent
   review.
4. Publish a remediation tracker with severity, scope, owner, target release,
   and verification evidence. Update the security notice only when the stated
   scope has actually been reviewed and findings have been addressed.

**Exit criterion:** the public audit report and remediation record are linked
from the README, with their exact reviewed scope and remaining limitations.

## Milestone 4 — hold the feature line until trust work is complete

- Prefer bugs, test coverage, reproducibility, documentation, and audit
  findings over expanding protocol surface area.
- Treat changes to crypto, transport metadata, vault/duress behavior, FMD, and
  cover traffic as review-gated security work, not routine feature work.
- Keep desktop/mobile scope separate from the audit target unless its parity and
  threat-model deltas are explicitly included in the review.

## Deferred decisions

These should be decided only after the baseline and audit scope are stable:

- Whether the Pi image is a supported public release artifact or an experimental
  build.
- Which desktop releases and platforms are in the first audit scope.
- Whether audit remediation needs a compatibility or vault-format migration for
  the documented L2/L4 backlog.
- The next protocol or product feature after the audit cycle.

## Principles

1. **Claims follow evidence.** DRIFT should say no more than the reviewed,
   tested implementation supports.
2. **Honesty is a feature.** Clear limitations are more valuable than broad,
   ambiguous privacy language.
3. **A smaller verified surface beats a larger speculative one.**
