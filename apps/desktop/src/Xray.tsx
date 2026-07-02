import { Modal } from "./modals";
import type { ChatMessage } from "./types";

/**
 * Cipher X-ray — the actual envelope from the wire, not a re-creation.
 *
 * Two columns: what the relay saw (a one-time address and an opaque blob —
 * nothing else), and what this client recovered from it. Every byte shown on
 * the left was already public the moment it crossed the wire; the address was
 * used exactly once and is cryptographically unlinkable to any other.
 */

function hexRows(hex: string): string[] {
  // 16 bytes (32 hex chars) per row, spaced in pairs, like a hex editor.
  const rows: string[] = [];
  for (let i = 0; i < hex.length; i += 32) {
    const row = hex.slice(i, i + 32);
    rows.push(row.replace(/(..)/g, "$1 ").trimEnd());
  }
  return rows;
}

const LAYERS = [
  ["stealth address", "one-time, unlinkable — routed without knowing you"],
  ["sealed sender", "opened — sender identity was hidden from the relay"],
  ["ratchet header", "advanced — this message key now no longer exists"],
  ["XChaCha20-Poly1305", "authenticated — tampering would have been fatal"],
  ["plaintext", "yours alone"],
] as const;

export function XrayModal({ message, onClose }: { message: ChatMessage; onClose: () => void }) {
  const env = message.envelope;
  if (!env) return null;
  const sent = env.dir === "out";
  return (
    <Modal title="cipher x-ray" onClose={onClose}>
      <div className="xray-cols">
        <div className="xray-col">
          <div className="label">what the relay saw</div>
          <div className="xray-field">
            <span className="xray-key">one-time address</span>
            <code className="xray-addr">{env.addr_b58}</code>
          </div>
          <div className="xray-field">
            <span className="xray-key">opaque blob · {env.wire_bytes} bytes {sent ? "sent" : "received"}</span>
            <pre className="xray-hex" aria-label="ciphertext preview">
              {hexRows(env.sealed_preview).join("\n")}
              {"\n… " + Math.max(0, env.wire_bytes - env.sealed_preview.length / 2) + " more bytes"}
            </pre>
          </div>
          <div className="xray-field">
            <span className="xray-key">fmd flag</span>
            <span className="small">{env.fmd ? "present (decoy-matched noise)" : "none"}</span>
          </div>
          <p className="muted small">
            no sender. no recipient identity. no conversation id. no timestamps
            it can link. this address never appears again.
          </p>
        </div>
        <div className="xray-col">
          <div className="label">what you see</div>
          <div className="xray-ladder">
            {LAYERS.map(([name, note], i) => (
              <div key={name} className="xray-layer" style={{ animationDelay: `${i * 0.12}s` }}>
                <span className="xray-layer-name">{name}</span>
                <span className="xray-layer-note muted">{note}</span>
              </div>
            ))}
          </div>
          <div className="xray-plain">
            <span className="pfx">{sent ? "›" : "‹"}</span> {message.text}
          </div>
        </div>
      </div>
      <p className="modal-foot muted small">
        this is the actual envelope from the wire, not a re-creation. The
        address and blob were public the moment they crossed the network — the
        plaintext never was.
      </p>
    </Modal>
  );
}
