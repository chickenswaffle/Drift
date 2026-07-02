import { useEffect, useState } from "react";
import { Modal } from "./modals";
import { randomart } from "./randomart";
import { rpc } from "./rpc";
import { secScore, type Fix, type SecItem } from "./seccheck";
import type { Contacts } from "./types";

/**
 * SEC badge + expandable checklist panel.
 *
 * The badge is the honest number (passed/total); the panel is the why and the
 * fix. Red rows carry a one-line threat statement and, where a safe default
 * exists, a one-click fix; anything needing judgment jumps to Settings.
 */

export function SecBadge({ items, onOpen }: { items: SecItem[]; onOpen: () => void }) {
  const { passed, total, tone } = secScore(items);
  return (
    <button
      className={`sec-badge ${tone}`}
      title="security posture — click for the checklist"
      onClick={onOpen}
    >
      SEC {passed}/{total}
    </button>
  );
}

export function SecPanel({
  items,
  onFix,
  onClose,
}: {
  items: SecItem[];
  onFix: (fix: Fix) => void;
  onClose: () => void;
}) {
  const { passed, total } = secScore(items);
  return (
    <Modal title={`security check · ${passed}/${total}`} onClose={onClose}>
      <div className="sec-list">
        {items.map((item) => (
          <div key={item.id} className={`sec-row ${item.pass ? "ok" : "bad"}`}>
            <span className="sec-glyph">{item.pass ? "✓" : "✗"}</span>
            <div className="sec-body">
              <div className="sec-label">{item.label}</div>
              {!item.pass && <div className="sec-threat">{item.threat}</div>}
              {item.note && <div className="sec-note">{item.note}</div>}
            </div>
            {!item.pass && item.fix && (
              <button className="sec-fix" onClick={() => onFix(item.fix!)}>
                › {item.fix.label}
              </button>
            )}
          </div>
        ))}
      </div>
      <p className="modal-foot muted small">
        a posture check, not a guarantee — a green board does not make a
        compromised endpoint safe.
      </p>
    </Modal>
  );
}

/**
 * Out-of-band verification: the safety number plus its randomart, and the
 * attestation button. Same picture on both screens = same keys; a middleman
 * shows a different picture on one side.
 */
export function VerifyModal({
  name,
  verified,
  onVerified,
  onClose,
}: {
  name: string;
  verified: boolean;
  onVerified: (contacts: Contacts) => void;
  onClose: () => void;
}) {
  const [number, setNumber] = useState<string | null>(null);
  const [err, setErr] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  useEffect(() => {
    void (async () => {
      try {
        const res = await rpc<{ safety_number: string }>("safety_number", { name });
        setNumber(res.safety_number);
      } catch (e) {
        setErr(String(e));
      }
    })();
  }, [name]);

  async function mark(v: boolean) {
    setBusy(true);
    setErr(null);
    try {
      const res = await rpc<{ contacts: Contacts }>("contact_verify", { name, verified: v });
      onVerified(res.contacts);
      if (v) onClose();
    } catch (e) {
      setErr(String(e));
    } finally {
      setBusy(false);
    }
  }

  return (
    <Modal title={`verify · ${name}`} onClose={onClose}>
      <p className="muted small">
        Compare with {name} over a call or in person. Same picture on both
        screens = same keys. Different picture = someone is in the middle.
      </p>
      {number ? (
        <>
          <pre className="randomart" aria-label="key randomart">{randomart(number)}</pre>
          <div className="codebox safety">
            <code>{number}</code>
          </div>
          <p />
          {verified ? (
            <>
              <p className="small" style={{ color: "var(--green)" }}>✓ marked verified</p>
              <button className="ghost" onClick={() => void mark(false)} disabled={busy}>
                › unmark
              </button>
            </>
          ) : (
            <button className="primary" onClick={() => void mark(true)} disabled={busy}>
              › it matches — mark verified
            </button>
          )}
        </>
      ) : (
        !err && <p className="muted small">computing…</p>
      )}
      {err && <p className="error small">{err}</p>}
    </Modal>
  );
}
