"""
DRIFT — terminal-first E2E encrypted messenger with rotating stealth addresses.

Status: pre-alpha. Phases 0–8 complete (transport, stealth addresses, Double
Ratchet, Tor + sealed sender, panic/decoy + FMD privacy dial, beacons, group
messaging), Phase 10 — WITNESS (the verifiable proof of relay blindness),
Phase 11 — sovereign rooms (cryptographic chatrooms with no server-side room),
and X3DH asynchronous key agreement (the prekey handshake that closes the H3
forward-secrecy residual and retires the deterministic ratchet bootstrap).
"""

__version__ = "0.14.0"
__author__ = "DRIFT contributors"
