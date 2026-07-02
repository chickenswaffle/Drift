import { useCallback, useEffect, useState } from "react";
import { rpc } from "./rpc";
import { Updater } from "./Updater";
import { copyText } from "./util";
import type { Contacts, Status } from "./types";

// Native notifications are opt-*out* — on unless the user turns them off. The
// Messenger reads this before firing anything, and the body is always generic
// (never message content), consistent with the app-plan's push stance.
const NOTIFY_KEY = "drift.notify";
export function notificationsEnabled(): boolean {
  return localStorage.getItem(NOTIFY_KEY) !== "0";
}

// FMD privacy dial. The rate is a false-positive probability `p`: a larger `p`
// means the relay flags a bigger decoy set alongside your real messages, so it
// cannot tell which fetches are yours (larger anonymity set) — at the cost of
// more traffic to scan. `0` = exact match: fastest, but the relay filters
// precisely to you. Achievable rates are powers of two (see crypto/fmd.py).
const FMD_STOPS = [
  { key: "off", label: "off", rate: 0, note: "exact match — fastest, but the relay filters precisely to you" },
  { key: "low", label: "low", rate: 2 ** -14, note: "a modest decoy set hides your fetches among others'" },
  { key: "high", label: "high", rate: 2 ** -6, note: "a large decoy set — most private, more traffic to scan" },
] as const;

function nearestStopKey(rate: number): string {
  if (rate <= 0) return "off";
  // compare in log space so power-of-two stops match cleanly
  let best: (typeof FMD_STOPS)[number] = FMD_STOPS[0];
  let bestD = Infinity;
  for (const s of FMD_STOPS) {
    if (s.rate <= 0) continue;
    const d = Math.abs(Math.log2(s.rate) - Math.log2(rate));
    if (d < bestD) {
      bestD = d;
      best = s;
    }
  }
  return best.key;
}

export function Settings({
  status,
  contacts,
  version,
  onClose,
  onChanged,
}: {
  status: Status;
  contacts: Contacts;
  version: string;
  onClose: () => void;
  onChanged?: () => void;
}) {
  // close on Escape
  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if (e.key === "Escape") onClose();
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [onClose]);

  return (
    <div className="modal-backdrop" onClick={onClose}>
      <div
        className="modal card"
        role="dialog"
        aria-modal="true"
        aria-label="settings"
        onClick={(e) => e.stopPropagation()}
      >
        <header className="modal-head">
          <span className="modal-title">settings</span>
          <button className="modal-x" onClick={onClose} aria-label="close settings">
            ✗
          </button>
        </header>

        <VaultSection vaultExists={status.vault_exists} onChanged={onChanged} />
        <VerifySection contacts={contacts} />
        <FmdSection currentRate={status.fmd_rate} />
        <CoverSection />
        <NotifySection />
        <ClipboardSection />

        <section className="setting">
          <div className="label">updates</div>
          <Updater current={version} />
        </section>

        <div className="modal-foot muted small">relay · {status.relay_url}</div>
      </div>
    </div>
  );
}

function VaultSection({
  vaultExists,
  onChanged,
}: {
  vaultExists: boolean;
  onChanged?: () => void;
}) {
  const [pass, setPass] = useState("");
  const [duress, setDuress] = useState("");
  const [mode, setMode] = useState<"wipe" | "decoy">("wipe");
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<string | null>(null);
  const [done, setDone] = useState(false);

  async function create() {
    if (!pass || busy) return;
    setBusy(true);
    setErr(null);
    try {
      await rpc("vault_create", {
        passphrase: pass,
        duress_passphrase: duress || undefined,
        duress_mode: mode,
      });
      setPass("");
      setDuress("");
      setDone(true);
      onChanged?.();
    } catch (e) {
      setErr(String(e));
    } finally {
      setBusy(false);
    }
  }

  return (
    <section className="setting">
      <div className="label">vault</div>
      {vaultExists || done ? (
        <>
          <p className="muted small">
            A passphrase-sealed vault is set. Lock DRIFT from the sidebar or tray;
            unlock with your passphrase. Your identity is encrypted at rest.
          </p>
          <p className="muted small">
            Panic lock (tray, or Ctrl/Cmd+Shift+L anywhere) seals instantly with
            no passphrase — anything changed this session (new contacts, rooms)
            is discarded. Normal lock preserves changes.
          </p>
        </>
      ) : (
        <>
          <p className="muted small">
            Set a passphrase to seal your identity at rest and enable lock. An
            optional duress passphrase opens a decoy or triggers a wipe —
            indistinguishable to an onlooker from a normal unlock.
          </p>
          <input
            className="lock-input"
            type="password"
            placeholder="passphrase"
            value={pass}
            onChange={(e) => setPass(e.target.value)}
          />
          <input
            className="lock-input"
            type="password"
            placeholder="duress passphrase (optional)"
            value={duress}
            onChange={(e) => setDuress(e.target.value)}
          />
          {duress && (
            <div className="dial">
              <button
                className={`dial-stop ${mode === "wipe" ? "on" : ""}`}
                onClick={() => setMode("wipe")}
              >
                wipe
              </button>
              <button
                className={`dial-stop ${mode === "decoy" ? "on" : ""}`}
                onClick={() => setMode("decoy")}
              >
                decoy
              </button>
            </div>
          )}
          <button className="primary" onClick={() => void create()} disabled={busy || !pass}>
            {busy ? "sealing…" : "› set passphrase"}
          </button>
          {err && <p className="error small">{err}</p>}
        </>
      )}
    </section>
  );
}

function VerifySection({ contacts }: { contacts: Contacts }) {
  const names = Object.keys(contacts);
  const [name, setName] = useState<string>(names[0] ?? "");
  const [number, setNumber] = useState<string | null>(null);
  const [err, setErr] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  const show = useCallback(async () => {
    if (!name) return;
    setBusy(true);
    setErr(null);
    setNumber(null);
    try {
      const res = await rpc<{ safety_number: string }>("safety_number", { name });
      setNumber(res.safety_number);
    } catch (e) {
      setErr(String(e));
    } finally {
      setBusy(false);
    }
  }, [name]);

  return (
    <section className="setting">
      <div className="label">verify a contact</div>
      {names.length === 0 ? (
        <p className="muted small">no contacts yet — add one first.</p>
      ) : (
        <>
          <p className="muted small">
            Read this safety number aloud together (or compare over a call). If it
            matches on both sides, no one is sitting in the middle.
          </p>
          <div className="verify-row">
            <select
              className="select"
              value={name}
              onChange={(e) => {
                setName(e.target.value);
                setNumber(null);
                setErr(null);
              }}
            >
              {names.map((n) => (
                <option key={n} value={n}>
                  {n}
                </option>
              ))}
            </select>
            <button className="ghost" onClick={() => void show()} disabled={busy || !name}>
              {busy ? "…" : "› show"}
            </button>
          </div>
          {number && <SafetyNumber value={number} />}
          {err && <p className="error small">{err}</p>}
        </>
      )}
    </section>
  );
}

function SafetyNumber({ value }: { value: string }) {
  const [copied, setCopied] = useState(false);
  return (
    <div
      className="codebox safety"
      title="click to copy"
      onClick={() => {
        void copyText(value);
        setCopied(true);
        setTimeout(() => setCopied(false), 1200);
      }}
    >
      <code>{value}</code>
      <span className="copy">{copied ? "copied ✓" : "copy"}</span>
    </div>
  );
}

function FmdSection({ currentRate }: { currentRate: number }) {
  const [active, setActive] = useState<string>(() => nearestStopKey(currentRate));
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<string | null>(null);

  async function pick(stop: (typeof FMD_STOPS)[number]) {
    if (busy) return;
    setBusy(true);
    setErr(null);
    const prev = active;
    setActive(stop.key);
    try {
      await rpc<{ fmd_rate: number }>("fmd_set", { rate: stop.rate });
    } catch (e) {
      setActive(prev);
      setErr(String(e));
    } finally {
      setBusy(false);
    }
  }

  const note = FMD_STOPS.find((s) => s.key === active)?.note ?? "";

  return (
    <section className="setting">
      <div className="label">metadata privacy (FMD)</div>
      <div className="dial">
        {FMD_STOPS.map((s) => (
          <button
            key={s.key}
            className={`dial-stop ${active === s.key ? "on" : ""}`}
            onClick={() => void pick(s)}
            disabled={busy}
          >
            {s.label}
          </button>
        ))}
      </div>
      <p className="muted small">{note}</p>
      {err && <p className="error small">{err}</p>}
    </section>
  );
}

// Cover traffic: Poisson-scheduled dummy envelopes + uniform message size on
// open 1:1 channels, so a wire-watcher can't tell when you're really talking.
const COVER_STOPS = [
  { key: "off", note: "no decoys — cheapest, but send timing is visible on the wire" },
  { key: "low", note: "occasional decoys blur your activity pattern at modest bandwidth" },
  { key: "high", note: "steady decoys — strongest timing cover, costs the most bandwidth" },
] as const;

function CoverSection() {
  const [active, setActive] = useState<string>("off");
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<string | null>(null);

  useEffect(() => {
    void rpc<{ cover_level: string }>("cover_get")
      .then((r) => setActive(r.cover_level))
      .catch(() => undefined);
  }, []);

  async function pick(key: string) {
    if (busy) return;
    setBusy(true);
    setErr(null);
    const prev = active;
    setActive(key);
    try {
      await rpc<{ cover_level: string }>("cover_set", { level: key });
    } catch (e) {
      setActive(prev);
      setErr(String(e));
    } finally {
      setBusy(false);
    }
  }

  const note = COVER_STOPS.find((s) => s.key === active)?.note ?? "";

  return (
    <section className="setting">
      <div className="label">cover traffic</div>
      <div className="dial">
        {COVER_STOPS.map((s) => (
          <button
            key={s.key}
            className={`dial-stop ${active === s.key ? "on" : ""}`}
            onClick={() => void pick(s.key)}
            disabled={busy}
          >
            {s.key}
          </button>
        ))}
      </div>
      <p className="muted small">
        {note} Constant-shape decoy traffic on open 1:1 channels — hides when
        you&apos;re really talking. Applies to newly opened chats.
      </p>
      {err && <p className="error small">{err}</p>}
    </section>
  );
}

// Clipboard clearing is opt-*in*: silently blanking the clipboard surprises
// people, but codes and safety numbers sitting in an OS clipboard forever is
// its own leak. The actual timer lives in util.copyText.
const CLIPBOARD_CLEAR_KEY = "drift.clipboard_clear";

function ClipboardSection() {
  const [on, setOn] = useState<boolean>(
    () => localStorage.getItem(CLIPBOARD_CLEAR_KEY) === "1",
  );
  return (
    <section className="setting">
      <div className="label">clipboard</div>
      <label className="toggle">
        <input
          type="checkbox"
          checked={on}
          onChange={() => {
            const next = !on;
            setOn(next);
            localStorage.setItem(CLIPBOARD_CLEAR_KEY, next ? "1" : "0");
          }}
        />
        clear copied codes from the clipboard after 30 seconds
      </label>
      <p className="muted small">
        Best-effort: only clears if the clipboard still holds what DRIFT copied,
        and some OS clipboard managers keep history DRIFT can&apos;t reach.
      </p>
    </section>
  );
}

function NotifySection() {
  const [on, setOn] = useState<boolean>(() => notificationsEnabled());
  return (
    <section className="setting">
      <div className="label">notifications</div>
      <label className="toggle">
        <input
          type="checkbox"
          checked={on}
          onChange={() => {
            const next = !on;
            setOn(next);
            localStorage.setItem(NOTIFY_KEY, next ? "1" : "0");
          }}
        />
        notify me on new messages when DRIFT isn&apos;t focused
      </label>
      <p className="muted small">
        The alert names the contact only — never the message. Nothing about who
        contacts you leaves this machine.
      </p>
    </section>
  );
}
