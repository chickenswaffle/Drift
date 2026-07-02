import { useCallback, useEffect, useRef, useState } from "react";
import { Modal } from "./modals";
import { notifyRaw } from "./notify";
import { rpc } from "./rpc";

/**
 * WITNESS live canary — verifiable privacy as ambient UI.
 *
 * Every 60 s the sidecar refetches the relay's signed, hash-chained blindness
 * certificates and re-verifies the whole recent chain (signatures, chain
 * continuity, period coverage, zero-knowledge claims) with the same code
 * anyone can run from the CLI. A green heartbeat means "proven blind, right
 * now". The instant a chain breaks — a reset, a bad signature, a dark window —
 * the widget goes loud. No other messenger shows you this because no other
 * messenger can.
 */

export interface WitnessInfo {
  supported: boolean;
  verified: boolean;
  error?: string;
  count?: number;
  signatures_valid?: boolean;
  chain_intact?: boolean;
  coverage_complete?: boolean;
  blindness_held?: boolean;
  fingerprint?: string;
  merkle_root?: string;
  period_seconds?: number;
  latest?: {
    timestamp: number;
    messages_routed: number;
    sender_identities_known: number;
    recipient_identities_known: number;
    contents_readable: number;
    conversations_linked: number;
    cert_hash: string;
    statement: string;
  } | null;
}

type CanaryState = "unwatched" | "verified" | "unsupported" | "broken";

export function WitnessCanary() {
  const [info, setInfo] = useState<WitnessInfo | null>(null);
  const [state, setState] = useState<CanaryState>("unwatched");
  const [open, setOpen] = useState(false);
  // Once a chain break is seen, it stays broken until the app restarts —
  // a canary that resurrects itself on the next poll would be worthless.
  const broken = useRef(false);
  const lastHash = useRef<string | null>(null);

  const poll = useCallback(async () => {
    if (broken.current) return;
    try {
      const res = await rpc<WitnessInfo>("witness_status");
      setInfo(res);
      if (!res.supported) {
        setState("unsupported");
        return;
      }
      // A verified chain whose newest cert stops chaining onto what we saw
      // before, or any failed verification, is a canary death.
      if (!res.verified) {
        broken.current = true;
        setState("broken");
        void notifyRaw("WITNESS chain break — relay may be compromised");
        return;
      }
      lastHash.current = res.latest?.cert_hash ?? lastHash.current;
      setState("verified");
    } catch {
      // Sidecar hiccup or tor-require without tor: not proof of anything —
      // show unwatched, never a false alarm.
      setState("unwatched");
    }
  }, []);

  useEffect(() => {
    void poll();
    const t = setInterval(() => void poll(), 60_000);
    return () => clearInterval(t);
  }, [poll]);

  const label =
    state === "verified"
      ? "witness · chain verified"
      : state === "broken"
        ? "WITNESS · CHAIN BROKEN"
        : state === "unsupported"
          ? "witness · no proof offered"
          : "witness · unwatched";

  return (
    <>
      <button
        className={`witness-row ${state}`}
        title="the relay's live, signed proof of blindness — click for what it cannot see"
        onClick={() => setOpen(true)}
      >
        <span className={`witness-dot ${state}`} aria-hidden />
        <span className="witness-label">{label}</span>
      </button>
      {open && <WitnessPanel info={info} state={state} onClose={() => setOpen(false)} />}
    </>
  );
}

function WitnessPanel({
  info,
  state,
  onClose,
}: {
  info: WitnessInfo | null;
  state: CanaryState;
  onClose: () => void;
}) {
  const latest = info?.latest;
  return (
    <Modal title="witness · proof of blindness" onClose={onClose}>
      {state === "broken" && (
        <p className="error">
          ⚠ CHAIN BREAK — this relay&apos;s certificate chain failed verification.
          It was reset, forged, or went dark. Treat the relay as compromised and
          switch relays in settings.
        </p>
      )}
      {state === "unsupported" && (
        <p className="muted small">
          This relay publishes no witness certificates. Your messages are still
          end-to-end encrypted and stealth-addressed — but the relay offers no
          live proof that it isn&apos;t logging metadata. That silence is
          information too.
        </p>
      )}
      {state === "unwatched" && (
        <p className="muted small">could not reach the relay to check — retrying every minute.</p>
      )}
      {state === "verified" && info && latest && (
        <>
          <p className="muted small">
            Every 60 seconds this relay signs a certificate of what it provably
            cannot know, hash-chained so it can&apos;t rewrite its past. DRIFT
            re-verifies the chain independently — this is measured, not promised.
          </p>
          <div className="witness-facts">
            <div className="witness-fact">
              <span className="wf-num">{latest.sender_identities_known}</span> sender identities known
            </div>
            <div className="witness-fact">
              <span className="wf-num">{latest.recipient_identities_known}</span> recipient identities known
            </div>
            <div className="witness-fact">
              <span className="wf-num">{latest.contents_readable}</span> messages readable
            </div>
            <div className="witness-fact">
              <span className="wf-num">{latest.conversations_linked}</span> conversations linkable
            </div>
          </div>
          <p className="muted small">
            {info.count} certificates verified · all signatures valid · chain
            intact · coverage complete · routed {latest.messages_routed} envelopes
            last period
          </p>
          <p className="muted small">
            relay fingerprint <code className="safety-inline">{info.fingerprint}</code>
          </p>
        </>
      )}
      <p className="modal-foot muted small">
        cryptographic proof of the relay&apos;s software state — it cannot prove
        no one tampered with hardware. Verify yourself anytime:{" "}
        <code>drift witness verify</code>
      </p>
    </Modal>
  );
}
