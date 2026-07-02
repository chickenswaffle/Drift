# DRIFT open-core — what stays free, what we sell, and why

*Working memo for the maintainers. Not legal advice; trademark and licensing
decisions below need a lawyer before they are executed.*

## The one-paragraph strategy

The protocol, the client, and the reference relay stay **MIT, forever** —
for a security tool, open source isn't marketing, it *is* the product's
credibility (nobody should trust an encrypted messenger they can't read).
Revenue comes from the layer above the protocol: **operated infrastructure
and enterprise tooling** that are genuinely ours to sell because they are
services and private code, not the commons. The moat is not the code — MIT
code is already free forever and we cannot (and should not) claw it back —
the moat is the **name, the spec stewardship, and the operated network**.

## What is already irrevocably open

Everything shipped to date under MIT: `drift/` (client + crypto composition),
`relay/` (reference relay + WITNESS), the desktop app, `PROTOCOL.md`
(DRIFT-P/1). Anyone may fork, rebrand, and resell it. That is fine — Signal's
code is open too; people pay Signal-shaped companies for operation, trust,
and support, not for tarballs.

## The open core (stays MIT, maintained publicly)

- The Drift Protocol spec (`PROTOCOL.md`) and its reference implementation
- The terminal client and desktop app
- The reference relay, federation, and the WITNESS proof layer
- The Gauntlet adversarial test suite

Keeping WITNESS open is strategic, not charitable: verifiable blindness only
means something if the verifier is public code.

## The proprietary / paid layer (candidates, in rough order of viability)

1. **DRIFT Relay Network (operated).** A fleet of geographically distributed,
   WITNESS-publishing relays with uptime SLAs, onion endpoints, and abuse
   handling. Free tier for individuals; paid tiers for orgs. This is the
   Signal model: people pay for *operation*, not code.
2. **WITNESS Monitor (SaaS).** Continuous third-party verification of any
   relay's blindness chain — alerting (mail/webhook/pager) the moment a chain
   breaks, plus signed monthly attestation reports. Compliance teams buy
   reports; the in-app canary stays free.
3. **Enterprise federation dashboard.** Private code: fleet management for
   orgs running their own relay mesh — provisioning, chain health, cover-
   traffic budgeting, beacon TTL policy, audit exports.
4. **Mobile push gateway** (when Phase 13 mobile lands). Privacy-preserving
   wake-up relay (no APNs/FCM metadata leak) is genuinely hard and genuinely
   operable — a natural paid service.
5. **Priority support / integration engineering.** Boring, reliable.

Rule of thumb for every future feature: *protocol guarantees → open core;
operation, monitoring, and org tooling → paid layer.* A feature that weakens
the open client to upsell the paid layer is rejected on sight — that trade
kills the credibility that makes the paid layer sellable.

## The moat: trademark + stewardship

- Register **"DRIFT"** and **"Drift Protocol"** as trademarks (lawyer
  required; classes for software + SaaS). MIT licenses the code, not the
  name: forks may take everything except calling themselves DRIFT.
- Publish a **"Drift Protocol Compatible"** certification mark + a public
  conformance checklist (the Gauntlet is its seed). Compatibility branding
  becomes something we grant.
- We steward DRIFT-P versioning. Forks can diverge, but *the* protocol
  number lives here.

## Licensing mechanics going forward

- New code in this repo: stays MIT (default).
- Paid-layer code: separate private repos from day one — never mixed into
  this tree, so there is never a relicensing knot to untangle.
- Adopt a lightweight **CLA or DCO** for external contributions *now*, before
  there are many contributors — it preserves future flexibility (e.g. dual
  licensing a specific component) and costs nothing today.
- Alternatives considered and rejected: AGPL relicensing (chills the adoption
  a messenger needs; past MIT versions remain forkable anyway) and
  closed-sourcing new features (kills trust — see rule of thumb above).

## Sequencing (proposed)

1. Ship DRIFT-P/1 spec publicly (done — `PROTOCOL.md`).
2. DCO/CLA for contributions; trademark filings started in parallel.
3. Stand up 2–3 operated relays with WITNESS public dashboards (free beta) —
   this is both the first product and the best marketing.
4. WITNESS Monitor as the first paid SKU (smallest build, clearest buyer).
5. Enterprise dashboard when ≥1 org runs its own mesh.
