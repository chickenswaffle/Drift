#!/usr/bin/env python3
"""
scripts/gauntlet.py — DRIFT adversarial probe harness

A standalone, in-process red-team run against the DRIFT stack. It spins up the
reference relay with FastAPI's TestClient (no ports, no asyncio server), mints
two real identities (Alice and Bob) plus a third eavesdropper (Eve) in their own
temp dirs, and fires ten adversarial probes at the protocol's core privacy and
crypto invariants. Each probe prints a live PASS/FAIL line; the process exits 0
iff every probe holds.

    python scripts/gauntlet.py

Nothing here touches the network or a real server: the relay runs in-process via
TestClient, and every identity / vault lives under a throwaway tempfile dir.
"""

from __future__ import annotations

import argparse
import base64
import json
import logging
import os
import sys
import tempfile
import time
import warnings
from collections.abc import Callable

# Keep the live report clean: the relay + httpx chatter at INFO, and TestClient
# emits a one-shot deprecation warning. None of it is the probe output.
warnings.filterwarnings("ignore", message="Using `httpx` with `starlette.testclient`")

# The relay mints/loads its long-term identity and peer file at *import* time, so
# point them at a throwaway temp dir before importing relay.server — the run
# never reads or writes the repo's own relay_identity.json / peers.json. Each
# identity (Alice/Bob/Eve) also gets its own DRIFT_CONFIG sandbox.
_TMP = tempfile.mkdtemp(prefix="drift-gauntlet-")
os.environ["DRIFT_RELAY_IDENTITY"] = os.path.join(_TMP, "relay_identity.json")
os.environ["DRIFT_PEERS_FILE"] = os.path.join(_TMP, "peers.json")
os.environ.setdefault("DRIFT_CONFIG", os.path.join(_TMP, "config"))

import httpx  # noqa: E402
from cryptography.exceptions import InvalidTag  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402
from rich.console import Console  # noqa: E402

from drift.crypto import (  # noqa: E402
    Identity,
    Keypair,
    b58decode,
    b58encode,
    decrypt,
)
from drift.crypto.burn import generate_burn_token  # noqa: E402
from drift.crypto.fmd import FMDKeypair, derive_fmd_key, fmd_flag, fmd_test  # noqa: E402
from drift.crypto.panic import KDFParams, create_vault, try_unlock  # noqa: E402
from drift.crypto.ratchet import Header, _kdf_ck, init_sender, ratchet_encrypt  # noqa: E402
from drift.crypto.sealed import parse as parse_sealed  # noqa: E402
from drift.crypto.stealth import scan_for_message  # noqa: E402
from drift.crypto.x3dh import (  # noqa: E402
    PreKeyBundle,
    X3DHError,
    X3DHHeader,
    generate_prekey_bundle,
    x3dh_receive,
    x3dh_send,
)
from drift.transport.client import Envelope  # noqa: E402
from drift.transport.session import (  # noqa: E402
    STEALTH_CHANNEL,
    PairwiseRatchet,
    _keypair_from_private,
    _scan_and_unseal,
)
from relay import server  # noqa: E402

# relay.server calls logging.basicConfig(INFO) at import; silence the per-request
# httpx/relay lines so only the PASS/FAIL report reaches the terminal.
for _noisy in ("httpx", "drift.relay"):
    logging.getLogger(_noisy).setLevel(logging.WARNING)

console = Console(highlight=False)

ProbeFn = Callable[[], tuple[bool, str]]


# --------------------------------------------------------------------------- #
# Identity-material scanning helpers (used by the blindness / opacity probes)
# --------------------------------------------------------------------------- #

def _identity_raw_tokens(idn: Identity) -> list[bytes]:
    """Every raw key blob that would betray ``idn`` if it leaked onto the wire."""
    return [
        idn.scan_keypair.public_bytes(),
        idn.spend_keypair.public_bytes(),
        idn.scan_keypair.private_bytes(),
        idn.spend_keypair.private_bytes(),
    ]


def _identity_str_tokens(idn: Identity) -> list[str]:
    """The same key material in every string encoding the stack uses (b58/b64)."""
    out: list[str] = [idn.contact_code()]
    for raw in _identity_raw_tokens(idn):
        out.append(b58encode(raw))
        out.append(base64.b64encode(raw).decode())
    return out


def _scan_for_identity(
    idn: Identity, *, text: str, raw: bytes
) -> list[str]:
    """Return the labels of any of ``idn``'s tokens that appear in text/bytes."""
    found: list[str] = []
    for s_token in _identity_str_tokens(idn):
        if s_token and s_token in text:
            found.append(f"str:{s_token[:12]}…")
    for b_token in _identity_raw_tokens(idn):
        if b_token and b_token in raw:
            found.append(f"raw:{b_token[:4].hex()}…")
    return found


class Gauntlet:
    """Holds the in-process relay + cast and runs each adversarial probe."""

    def __init__(self) -> None:
        self.client = TestClient(server.app)
        # Three real identities in their own config sandboxes.
        self.alice = self._mint("alice")
        self.bob = self._mint("bob")
        self.eve = self._mint("eve")
        # Bob's receive-side keys, used to scan/unseal the firehose for him.
        self.bob_scan_priv = self.bob.scan_keypair.private_bytes()
        self.bob_spend_pub = self.bob.spend_keypair.public_bytes()
        self.bob_spend_priv = self.bob.spend_keypair.private_bytes()

    @staticmethod
    def _mint(name: str) -> Identity:
        """A fresh identity rooted in its own temp DRIFT_CONFIG dir."""
        cfg = os.path.join(_TMP, name)
        os.makedirs(cfg, exist_ok=True)
        return Identity.generate()

    # -- shared plumbing ----------------------------------------------------

    def _post(self, addr: bytes, blob: bytes) -> httpx.Response:
        """POST a sealed envelope to the relay exactly as the transport would."""
        payload = {
            "to": STEALTH_CHANNEL,
            "ct": base64.b64encode(blob).decode(),
            "ts": int(time.time()),
            "addr": base64.b64encode(addr).decode(),
        }
        resp: httpx.Response = self.client.post("/send", json=payload)
        return resp

    def _alice_envelope(self, text: bytes) -> tuple[bytes, bytes]:
        """A genuine sealed, stealth-addressed envelope Alice→Bob."""
        channel = PairwiseRatchet(self.alice, self.bob.contact_code())
        addr, blob, _flag = channel.encrypt(text)
        return addr, blob

    def _bob_parse(
        self, addr: bytes, blob: bytes
    ) -> tuple[X3DHHeader | None, bytes | None, Header, bytes] | None:
        """Run Bob's identity-level scan+unseal over one envelope."""
        env = Envelope(to=STEALTH_CHANNEL, ciphertext=blob, one_time_addr=addr)
        return _scan_and_unseal(
            env, self.bob_scan_priv, self.bob_spend_pub, self.bob_spend_priv
        )

    # ===================================================================== #
    # Probe 1 — relay blindness
    # ===================================================================== #
    def probe_relay_blindness(self) -> tuple[bool, str]:
        addr, blob = self._alice_envelope(b"the relay must learn nothing")
        resp = self._post(addr, blob)
        assert resp.status_code == 200

        texts: list[str] = []
        raws: list[bytes] = []
        for ep in ("/health", "/", "/witness/current", "/federation/peers"):
            r = self.client.get(ep)
            texts.append(r.text)
            raws.append(r.content)
        combined_text = "\n".join(texts)
        combined_raw = b"".join(raws)

        leaks: list[str] = []
        for idn, label in ((self.alice, "alice"), (self.bob, "bob")):
            for hit in _scan_for_identity(idn, text=combined_text, raw=combined_raw):
                leaks.append(f"{label}:{hit}")
        if leaks:
            return False, f"identity material leaked: {leaks}"
        return True, "4 relay endpoints expose zero identity material"

    # ===================================================================== #
    # Probe 2 — stealth address unlinkability
    # ===================================================================== #
    def probe_stealth_unlinkability(self) -> tuple[bool, str]:
        channel = PairwiseRatchet(self.alice, self.bob.contact_code())
        addrs: list[bytes] = []
        ephemerals: list[bytes] = []
        for _ in range(10):
            addr, blob, _flag = channel.encrypt(b"unlinkable")
            addrs.append(addr)
            ephemerals.append(parse_sealed(blob)[0])

        if len({bytes(a) for a in addrs}) != 10:
            return False, "addresses repeated — linkable"
        for i, a in enumerate(addrs):
            for j, b in enumerate(addrs):
                if i != j and (b.startswith(a) or b.endswith(a)):
                    return False, "one address is a prefix/suffix of another"

        # No address may equal either party's static scan/spend key (any encoding).
        forbidden: set[bytes] = set()
        for idn in (self.alice, self.bob):
            forbidden.add(idn.scan_keypair.public_bytes())
            forbidden.add(idn.spend_keypair.public_bytes())
        if any(a in forbidden for a in addrs):
            return False, "an address equals a static public key"

        # Without the recipient's scan key, a third party cannot detect — let
        # alone derive — any of the ten addresses. Bob (the true scan key) can.
        eve_scan = self.eve.scan_keypair.private_bytes()
        for addr, eph in zip(addrs, ephemerals, strict=True):
            if scan_for_message(eph, addr, eve_scan, self.bob_spend_pub) is not None:
                return False, "Eve detected an address without the scan key"
            if scan_for_message(eph, addr, self.bob_scan_priv, self.bob_spend_pub) is None:
                return False, "Bob failed to detect his own address"
        return True, "10/10 addresses distinct, non-derivable without scan key"

    # ===================================================================== #
    # Probe 3 — forward secrecy
    # ===================================================================== #
    def probe_forward_secrecy(self) -> tuple[bool, str]:
        recipient = Keypair.generate()
        state = init_sender(os.urandom(32), recipient.public_bytes())
        header0, ct0 = ratchet_encrypt(state, b"the past must stay sealed")
        # Advance (and discard) 3 further message keys — simulating deletion.
        for _ in range(3):
            ratchet_encrypt(state, b"newer traffic")
        chain_now = state.sending_chain_key
        assert chain_now is not None
        # Only the advanced chain key survives; it is one-way, so no derivation
        # from it can reproduce msg #0's key.
        _next, candidate = _kdf_ck(chain_now)
        try:
            decrypt(candidate, ct0, associated_data=header0.to_bytes())
        except InvalidTag:
            return True, "deleted key unrecoverable from advanced chain (InvalidTag)"
        return False, "advanced chain key reconstructed a past message key"

    # ===================================================================== #
    # Probe 4 — burn token replay
    # ===================================================================== #
    def probe_burn_replay(self) -> tuple[bool, str]:
        server._burn_nonces_seen.clear()
        token = generate_burn_token(os.urandom(32), "conversation")
        body = {"token": token, "scope": "conversation", "channel": STEALTH_CHANNEL}
        first = self.client.post("/burn", json=body)
        if first.status_code != 200:
            return False, f"first burn rejected ({first.status_code})"
        replay = self.client.post("/burn", json=body)
        if replay.status_code != 409:
            return False, f"replay not rejected ({replay.status_code})"
        return True, "first burn 200, identical replay 409"

    # ===================================================================== #
    # Probe 5 — sealed sender opacity
    # ===================================================================== #
    def probe_sealed_sender(self) -> tuple[bool, str]:
        server._recent.clear()
        addr, blob = self._alice_envelope(b"who sent this?")
        resp = self._post(addr, blob)
        assert resp.status_code == 200

        buffered = server._recent.get(STEALTH_CHANNEL, [])
        if not buffered:
            return False, "relay stored no envelope to inspect"
        stored = buffered[-1]

        # Flatten every stored field into text + raw bytes for scanning. The "ct"
        # field is base64 — decode it so a sender key hidden inside the sealed
        # blob would still be caught.
        text = json.dumps(stored, default=str)
        raw = bytearray()
        for value in stored.values():
            if isinstance(value, str):
                raw += value.encode()
                try:
                    raw += base64.b64decode(value, validate=True)
                except (ValueError, TypeError):
                    pass
        leaks = _scan_for_identity(self.alice, text=text, raw=bytes(raw))
        if leaks:
            return False, f"sender identity in stored blob: {leaks}"
        return True, f"stored fields {sorted(stored)} carry no sender identity"

    # ===================================================================== #
    # Probe 6 — WITNESS chain integrity
    # ===================================================================== #
    def probe_witness_chain(self) -> tuple[bool, str]:
        # Seal a few extra certificates so the chain has real hash-links to check
        # (the periodic heartbeat is too slow for a single run).
        for _ in range(3):
            server.witness_chain.generate()

        from relay.witness import WitnessCertificate, verify_chain

        chain_data = self.client.get("/witness/chain").json()
        certs = [WitnessCertificate.from_dict(c) for c in chain_data["certificates"]]
        if len(certs) < 2:
            return False, "chain too short to verify links"

        pub = self.client.get("/witness/pubkey").json()
        relay_id = b58decode(pub["pubkey_b58"])
        if certs[-1].relay_id != relay_id:
            return False, "chain not signed by the advertised relay key"

        for i, cert in enumerate(certs):
            if not cert.verify_signature():
                return False, f"bad signature on certificate {i}"
        for i in range(1, len(certs)):
            if certs[i].previous_cert_hash != certs[i - 1].cert_hash():
                return False, f"broken hash link before certificate {i}"

        # Tamper: flip one bit of one signature → the whole chain must fail.
        tampered = list(certs)
        bad = bytearray(tampered[-1].relay_signature)
        bad[0] ^= 0xFF
        tampered[-1].relay_signature = bytes(bad)
        if verify_chain(tampered):
            return False, "tampered chain still verified"
        return True, f"{len(certs)} certs verify clean; tamper rejected"

    # ===================================================================== #
    # Probe 7 — forged message rejection
    # ===================================================================== #
    def probe_forged_message(self) -> tuple[bool, str]:
        alice_ch = PairwiseRatchet(self.alice, self.bob.contact_code())
        bob_ch = PairwiseRatchet(self.bob, self.alice.contact_code())

        addr_a, blob_a = self._first_envelope(alice_ch, b"first")
        parsed = self._bob_parse(addr_a, blob_a)
        if parsed is None:
            return False, "Bob could not scan his own message"
        _x3dh, fs_pub, header, ratchet_ct = parsed
        root_mix = (
            _keypair_from_private(self.bob_spend_priv).ecdh(fs_pub)
            if fs_pub is not None
            else None
        )

        # Forge: flip bit 7 of byte 0 of the AEAD body, decrypt → must InvalidTag.
        forged = bytearray(ratchet_ct)
        forged[0] ^= 0x80
        try:
            bob_ch.decrypt_ratchet(header, bytes(forged), root_mix)
            return False, "forged ciphertext authenticated"
        except InvalidTag:
            pass

        # The genuine message still decrypts — the forgery left state untouched.
        first = bob_ch.decrypt_ratchet(header, ratchet_ct, root_mix)
        if first != b"first":
            return False, "genuine message failed after forgery attempt"

        # And a fresh, legitimate follow-up decrypts too.
        addr_b, blob_b = alice_ch.encrypt(b"second")[0:2]
        parsed2 = self._bob_parse(addr_b, blob_b)
        if parsed2 is None:
            return False, "Bob could not scan the follow-up"
        _x2, fs_pub2, header2, ct2 = parsed2
        mix2 = (
            _keypair_from_private(self.bob_spend_priv).ecdh(fs_pub2)
            if fs_pub2 is not None
            else None
        )
        second = bob_ch.decrypt_ratchet(header2, ct2, mix2)
        if second != b"second":
            return False, "ratchet state corrupted by forged message"
        return True, "InvalidTag on tamper; ratchet survived, both msgs decrypt"

    @staticmethod
    def _first_envelope(channel: PairwiseRatchet, text: bytes) -> tuple[bytes, bytes]:
        addr, blob, _flag = channel.encrypt(text)
        return addr, blob

    # ===================================================================== #
    # Probe 8 — panic key isolation
    # ===================================================================== #
    def probe_panic_isolation(self) -> tuple[bool, str]:
        real_phrase = "river-amber-north-42"
        duress_phrase = "frost-harbor-ridge-7"
        params = KDFParams(time_cost=1, memory_cost=64, parallelism=1)

        real_dict = self.alice.to_dict()
        real_payload = json.dumps({"identity": real_dict}).encode()
        decoy = Identity.generate()
        duress_payload = json.dumps({"identity": decoy.to_dict()}).encode()

        vault = create_vault(
            real_phrase,
            real_payload,
            duress_passphrase=duress_phrase,
            duress_payload=duress_payload,
            params=params,
        )

        opened = try_unlock(vault, duress_phrase)
        if opened is None:
            return False, "duress passphrase opened nothing"
        duress_id = json.loads(opened)["identity"]
        if duress_id["scan_priv"] == real_dict["scan_priv"]:
            return False, "duress unlock returned the real identity"

        # The real private keys must not appear anywhere in the duress payload.
        leaked = [
            field
            for field in ("scan_priv", "spend_priv")
            if real_dict[field].encode() in opened
        ]
        if leaked:
            return False, f"real private key reachable via duress: {leaked}"

        # Sanity: the real passphrase still recovers the real identity.
        real_opened = try_unlock(vault, real_phrase)
        if real_opened is None or json.loads(real_opened)["identity"]["scan_priv"] != (
            real_dict["scan_priv"]
        ):
            return False, "real passphrase failed to recover the real identity"
        return True, "duress unlock yields decoy; real keys unreachable"

    # ===================================================================== #
    # Probe 9 — X3DH one-time prekey consumption
    # ===================================================================== #
    def probe_otpk_consumption(self) -> tuple[bool, str]:
        _bundle, privates = generate_prekey_bundle(self.bob)
        addr = self.bob.scan_keypair.public_b58()
        pub = self.client.post(f"/prekeys/{addr}", json=privates.publish_payload(self.bob))
        if pub.status_code != 200:
            return False, f"publish failed ({pub.status_code})"
        published_ids = set(privates.one_time.keys())

        # Alice fetches a bundle — the relay hands out and deletes one OTPK.
        fetched = self.client.get(f"/prekeys/{addr}").json()
        consumed_id = fetched["one_time_prekey_id"]
        if consumed_id not in published_ids:
            return False, "relay served an unknown OTPK id"
        bundle = PreKeyBundle.from_dict(fetched)
        _result, header = x3dh_send(self.alice, bundle)
        assert header.one_time_prekey_id == consumed_id

        # Drain the rest of the relay's pool — the consumed id must never reappear.
        remaining: set[int] = set()
        for _ in range(len(published_ids) + 2):
            data = self.client.get(f"/prekeys/{addr}").json()
            otpk_id = data["one_time_prekey_id"]
            if otpk_id is None:
                break
            remaining.add(otpk_id)
        if consumed_id in remaining:
            return False, "consumed OTPK was served a second time"

        # Responder side: completing the handshake burns Bob's OTPK private; a
        # replay of the same header can no longer be honoured.
        x3dh_receive(self.bob, privates, header)
        try:
            x3dh_receive(self.bob, privates, header)
            return False, "consumed OTPK accepted on replay"
        except X3DHError:
            pass
        return True, f"OTPK {consumed_id} consumed once, replay rejected"

    # ===================================================================== #
    # Probe 10 — FMD false-positive rate
    # ===================================================================== #
    def probe_fmd_rate(self) -> tuple[bool, str]:
        trials = 500
        # Bob's full detection key, plus a *different* random sender key the 500
        # decoy envelopes are flagged for. The relay's dial is the number of
        # Bob sub-keys tested: native false-positive rate is 2**-k.
        bob_full = derive_fmd_key(os.urandom(32), 24)
        other = derive_fmd_key(os.urandom(32), 24)

        flags: list[tuple[bytes, bytes]] = []
        for _ in range(trials):
            decoy_addr = os.urandom(32)
            flags.append((fmd_flag(decoy_addr, other.public_keys), decoy_addr))

        def passes(filter_key: FMDKeypair | None) -> int:
            """Mirror relay._passes_fmd: no key → classic (forward all)."""
            if filter_key is None:
                return trials
            return sum(1 for flag, msg in flags if fmd_test(flag, filter_key, msg))

        # rate≈0.0 — finest key (k=24, 2**-24); rate≈0.1 — k=3 (2**-3); rate=1.0
        # — classic mode, no filter.
        fine = bob_full
        coarse = bob_full.downgrade(0.1)
        n_zero = passes(fine)
        n_dial = passes(coarse)
        n_all = passes(None)

        if n_zero != 0:
            return False, f"rate≈0 leaked {n_zero}/{trials}"
        if n_all != trials:
            return False, f"rate=1.0 dropped {trials - n_all}/{trials}"
        if not (20 <= n_dial <= 80):
            return False, f"rate≈0.1 out of band: {n_dial}/{trials}"
        return True, f"rates 0/0.1/1.0 → {n_zero}/{n_dial}/{n_all} of {trials}"


# --------------------------------------------------------------------------- #
# Runner
# --------------------------------------------------------------------------- #

def _header() -> None:
    style = "bold cyan"
    console.print()
    console.print("  ╔══════════════════════════════════════╗", style=style)
    console.print("  ║   DRIFT GAUNTLET — adversarial probe ║", style=style)
    console.print("  ║   v0.15.0 · 10 attacks · 0 mercy    ║", style=style)
    console.print("  ╚══════════════════════════════════════╝", style=style)
    console.print()


def _summary(passed: int, total: int) -> None:
    failed = total - passed
    ok = failed == 0
    line = f"  {passed}/{total} PASSED  ·  {failed} FAILED".ljust(37)
    verdict = ("  DRIFT held." if ok else f"  {failed} probes failed.").ljust(37)
    style = "bold green" if ok else "bold red"
    console.print()
    console.print("  ┌─────────────────────────────────────┐", style=style)
    console.print(f"  │{line}│", style=style)
    console.print(f"  │{verdict}│", style=style)
    console.print("  └─────────────────────────────────────┘", style=style)
    console.print()


# Canonical probe registry. Each entry is (stable kebab id, human display name,
# bound method name). The kebab id is the machine-readable handle used by --json
# and --probe; the display name is the one-line attack shown in the live report.
_PROBE_SPECS: list[tuple[str, str, str]] = [
    ("relay-blindness", "relay cannot enumerate contacts", "probe_relay_blindness"),
    ("stealth-unlinkability", "10 messages produce 10 unlinkable addresses", "probe_stealth_unlinkability"),
    ("forward-secrecy", "deleted message keys cannot decrypt past ciphertext", "probe_forward_secrecy"),
    ("burn-replay", "burn token cannot be replayed", "probe_burn_replay"),
    ("sealed-sender-opacity", "relay stored blobs contain no sender identity", "probe_sealed_sender"),
    ("witness-chain-integrity", "WITNESS chain is signed and hash-linked", "probe_witness_chain"),
    ("forged-message-rejection", "tampered ciphertext raises InvalidTag, ratchet state survives", "probe_forged_message"),
    ("panic-isolation", "duress passphrase produces unreachable real identity", "probe_panic_isolation"),
    ("otpk-consumption", "consumed OTPK is deleted and non-reusable", "probe_otpk_consumption"),
    ("fmd-rate", "FMD rate dial controls relay-side detection probability", "probe_fmd_rate"),
]

# Result statuses. The probes here only ever pass, fail, or error; "skip" is part
# of the contract for invariants that cannot be tested honestly in isolation.
STATUS_PASS = "pass"
STATUS_FAIL = "fail"
STATUS_SKIP = "skip"
STATUS_ERROR = "error"


def run_probe(g: Gauntlet, probe_id: str, fn: ProbeFn) -> dict[str, object]:
    """Run one probe, time it, and normalise the outcome into a result dict.

    A returned ``(True, detail)`` is a pass and ``(False, detail)`` a fail; any
    uncaught exception is an error with the exception text as the detail."""
    started = time.perf_counter()
    try:
        ok, detail = fn()
        status = STATUS_PASS if ok else STATUS_FAIL
    except Exception as exc:  # noqa: BLE001 — a probe crash is an honest error
        status, detail = STATUS_ERROR, f"{type(exc).__name__}: {exc}"
    duration_ms = int(round((time.perf_counter() - started) * 1000.0))
    return {"probe": probe_id, "status": status, "detail": detail, "duration_ms": duration_ms}


def _print_live(probe_id: str, display: str, result: dict[str, object]) -> None:
    """Stream one probe result in the live, coloured report."""
    status = result["status"]
    detail = result["detail"]
    ms = result["duration_ms"]
    if status == STATUS_PASS:
        console.print(f"[bold green]✓  PASS[/bold green]  {display}  [dim]{detail} · {ms}ms[/dim]")
    elif status == STATUS_SKIP:
        console.print(f"[bold yellow]•  SKIP[/bold yellow]  {display}  [dim]{detail} · {ms}ms[/dim]")
    else:
        badge = "✗  FAIL" if status == STATUS_FAIL else "!  ERR "
        console.print(f"[bold red]{badge}[/bold red]  {display}  [dim]{detail} · {ms}ms[/dim]")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="gauntlet.py",
        description="Fire 10 adversarial probes at DRIFT's core privacy and crypto invariants.",
    )
    parser.add_argument("--json", action="store_true", help="emit results as a JSON array to stdout")
    parser.add_argument("--probe", metavar="NAME", help="run a single probe by its id")
    args = parser.parse_args(argv)

    specs = _PROBE_SPECS
    if args.probe is not None:
        specs = [s for s in _PROBE_SPECS if s[0] == args.probe]
        if not specs:
            available = ", ".join(pid for pid, _, _ in _PROBE_SPECS)
            print(f"unknown probe '{args.probe}'. available: {available}", file=sys.stderr)
            return 2

    if not args.json:
        _header()

    g = Gauntlet()
    results: list[dict[str, object]] = []
    for probe_id, display, method in specs:
        fn: ProbeFn = getattr(g, method)
        if not args.json:
            console.print(f"⟳  [dim]{display}...[/dim]")
        result = run_probe(g, probe_id, fn)
        results.append(result)
        if not args.json:
            _print_live(probe_id, display, result)

    if args.json:
        print(json.dumps(results, indent=2))
    else:
        passed = sum(1 for r in results if r["status"] == STATUS_PASS)
        _summary(passed, len(results))

    broken = any(r["status"] in (STATUS_FAIL, STATUS_ERROR) for r in results)
    return 1 if broken else 0


if __name__ == "__main__":
    sys.exit(main())
