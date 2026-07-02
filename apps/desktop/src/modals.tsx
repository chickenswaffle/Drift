import { useEffect, useState } from "react";
import { rpc } from "./rpc";
import { CodeBox } from "./CodeBox";
import type { Conversation, GroupInfo } from "./types";

/** Shared modal shell: backdrop, card, title, Escape-to-close. */
export function Modal({
  title,
  onClose,
  children,
}: {
  title: string;
  onClose: () => void;
  children: React.ReactNode;
}) {
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
        aria-label={title}
        onClick={(e) => e.stopPropagation()}
      >
        <header className="modal-head">
          <span className="modal-title">{title}</span>
          <button className="modal-x" onClick={onClose} aria-label="close">
            ✗
          </button>
        </header>
        {children}
      </div>
    </div>
  );
}

function Tabs({
  tabs,
  tab,
  setTab,
}: {
  tabs: string[];
  tab: string;
  setTab: (t: string) => void;
}) {
  return (
    <div className="dial modal-tabs">
      {tabs.map((t) => (
        <button key={t} className={`dial-stop ${tab === t ? "on" : ""}`} onClick={() => setTab(t)}>
          {t}
        </button>
      ))}
    </div>
  );
}

// ------------------------------------------------- disappearing contact code

const INVITE_TTLS = [
  { key: "10m", seconds: 600 },
  { key: "1h", seconds: 3600 },
  { key: "24h", seconds: 24 * 3600 },
] as const;

function fmtRemaining(total: number): string {
  const s = Math.max(0, total);
  const h = Math.floor(s / 3600);
  const m = Math.floor((s % 3600) / 60);
  const sec = s % 60;
  return h > 0
    ? `${h}:${String(m).padStart(2, "0")}:${String(sec).padStart(2, "0")}`
    : `${m}:${String(sec).padStart(2, "0")}`;
}

export function InviteModal({ onClose }: { onClose: () => void }) {
  const [ttl, setTtl] = useState<(typeof INVITE_TTLS)[number]>(INVITE_TTLS[1]);
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<string | null>(null);
  const [invite, setInvite] = useState<{ code: string; expires_at: number } | null>(null);
  const [remaining, setRemaining] = useState(0);
  const [gone, setGone] = useState<"expired" | "extinguished" | null>(null);

  // Live countdown off the relay's expires_at — the truth, not our request.
  useEffect(() => {
    if (!invite || gone) return;
    const tick = () => {
      const left = invite.expires_at - Math.floor(Date.now() / 1000);
      setRemaining(left);
      if (left <= 0) setGone("expired");
    };
    tick();
    const t = setInterval(tick, 1000);
    return () => clearInterval(t);
  }, [invite, gone]);

  async function mint() {
    if (busy) return;
    setBusy(true);
    setErr(null);
    try {
      const res = await rpc<{ code: string; expires_at: number }>("invite_create", {
        ttl_seconds: ttl.seconds,
      });
      setInvite(res);
      setGone(null);
    } catch (e) {
      setErr(String(e));
    } finally {
      setBusy(false);
    }
  }

  async function extinguish() {
    if (!invite || busy) return;
    setBusy(true);
    try {
      await rpc("invite_extinguish", { code: invite.code });
      setGone("extinguished");
    } catch (e) {
      setErr(String(e));
    } finally {
      setBusy(false);
    }
  }

  return (
    <Modal title="disappearing code" onClose={onClose}>
      {invite ? (
        <>
          {gone ? (
            <p className="muted small">
              {gone === "expired" ? "This code has expired." : "Code extinguished."} It no
              longer resolves to anything. Mint another whenever you like.
            </p>
          ) : (
            <>
              <p className="muted small">
                This code resolves to your permanent contact code exactly once, then
                burns. It dies on its own at the timer. Best-effort: a relay that
                ignores deletes, or a federation peer holding a replica, keeps the
                sealed blob until expiry — but the blob is useless without this exact
                code.
              </p>
              <CodeBox code={invite.code} dashed />
              <div className="invite-countdown">
                expires in <strong>{fmtRemaining(remaining)}</strong>
              </div>
              <button className="ghost danger" onClick={() => void extinguish()} disabled={busy}>
                › extinguish now
              </button>
            </>
          )}
          {gone && (
            <button className="primary" onClick={() => { setInvite(null); setGone(null); }}>
              › mint another
            </button>
          )}
        </>
      ) : (
        <>
          <p className="muted small">
            Share a one-time code instead of your permanent one. Whoever redeems it
            first gets your contact code; then it burns. Your permanent code stays
            off the wire.
          </p>
          <div className="label">lifetime</div>
          <div className="dial">
            {INVITE_TTLS.map((t) => (
              <button
                key={t.key}
                className={`dial-stop ${ttl.key === t.key ? "on" : ""}`}
                onClick={() => setTtl(t)}
              >
                {t.key}
              </button>
            ))}
          </div>
          <button className="primary" onClick={() => void mint()} disabled={busy}>
            {busy ? "lighting…" : "› mint disappearing code"}
          </button>
          {err && <p className="error small">{err}</p>}
        </>
      )}
    </Modal>
  );
}

// ---------------------------------------------------------------- channels

export function NewChannelModal({
  onClose,
  onDone,
}: {
  onClose: () => void;
  onDone: () => void;
}) {
  const [tab, setTab] = useState("create");
  const [name, setName] = useState("");
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<string | null>(null);
  const [code, setCode] = useState<string | null>(null);

  async function go() {
    if (!name.trim() || busy) return;
    setBusy(true);
    setErr(null);
    try {
      if (tab === "create") {
        const res = await rpc<{ share_code: string }>("channel_create", { name: name.trim() });
        setCode(res.share_code);
      } else {
        await rpc("channel_join", { name: name.trim() });
        onDone();
        onClose();
      }
    } catch (e) {
      setErr(String(e));
    } finally {
      setBusy(false);
    }
  }

  return (
    <Modal title="channel" onClose={onClose}>
      <Tabs tabs={["create", "subscribe"]} tab={tab} setTab={(t) => { setTab(t); setCode(null); setErr(null); }} />
      {code ? (
        <>
          <p className="muted small">
            Channel created. You are the only poster. Share this name — anyone who
            has it can read. To revoke, roll the code from the channel's manage
            sheet.
          </p>
          <CodeBox code={code} dashed />
          <button className="primary" onClick={() => { onDone(); onClose(); }}>
            › done
          </button>
        </>
      ) : (
        <>
          <p className="muted small">
            {tab === "create"
              ? "A broadcast channel you own — you post, anyone with the name reads. Treat the name as a password."
              : "Subscribe to a channel by name (read-only)."}
          </p>
          <input
            className="lock-input"
            placeholder="channel name"
            value={name}
            autoFocus
            onChange={(e) => setName(e.target.value)}
            onKeyDown={(e) => { if (e.key === "Enter") void go(); }}
          />
          <button className="primary" onClick={() => void go()} disabled={busy || !name.trim()}>
            {busy ? "…" : tab === "create" ? "› create" : "› subscribe"}
          </button>
          {err && <p className="error small">{err}</p>}
        </>
      )}
    </Modal>
  );
}

// ---------------------------------------------------------------- rooms

export function JoinRoomModal({ onClose, onDone }: { onClose: () => void; onDone: () => void }) {
  const [tab, setTab] = useState("create");
  const [tier, setTier] = useState<"open" | "invite" | "dark">("open");
  const [name, setName] = useState("");
  const [token, setToken] = useState("");
  const [descriptor, setDescriptor] = useState("");
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<string | null>(null);
  const [result, setResult] = useState<{ share_code: string; token?: string } | null>(null);

  async function go() {
    if (busy) return;
    setBusy(true);
    setErr(null);
    try {
      if (tab === "create") {
        if (tier !== "dark" && !name.trim()) throw new Error("name required");
        const res = await rpc<{ share_code: string; token?: string }>("room_create", {
          tier,
          name: tier === "dark" ? undefined : name.trim(),
        });
        setResult(res);
      } else {
        if (descriptor.trim()) {
          await rpc("room_join", { descriptor: descriptor.trim() });
        } else {
          if (!name.trim()) throw new Error("name or descriptor required");
          await rpc("room_join", {
            name: name.trim(),
            token: token.trim() || undefined,
          });
        }
        onDone();
        onClose();
      }
    } catch (e) {
      setErr(String(e));
    } finally {
      setBusy(false);
    }
  }

  return (
    <Modal title="room" onClose={onClose}>
      <Tabs tabs={["create", "join"]} tab={tab} setTab={(t) => { setTab(t); setResult(null); setErr(null); }} />
      {result ? (
        <>
          <p className="muted small">
            Room created. Rooms are encrypted but NOT forward-secret — anyone who
            ever learns the code can read all messages. Share only with people you
            trust.
          </p>
          <div className="label">share code</div>
          <CodeBox code={result.share_code} dashed />
          {result.token && (
            <>
              <div className="label">posting token (grants posting rights)</div>
              <CodeBox code={result.token} dashed />
            </>
          )}
          <button className="primary" onClick={() => { onDone(); onClose(); }}>
            › done
          </button>
        </>
      ) : tab === "create" ? (
        <>
          <div className="label">tier</div>
          <div className="dial">
            {(["open", "invite", "dark"] as const).map((t) => (
              <button key={t} className={`dial-stop ${tier === t ? "on" : ""}`} onClick={() => setTier(t)}>
                {t}
              </button>
            ))}
          </div>
          <p className="muted small">
            {tier === "open"
              ? "Anyone who knows the name can read and post."
              : tier === "invite"
                ? "Anyone with the name reads; posting needs the invite token you'll get."
                : "No name — a random secret shared only via its descriptor/QR."}
          </p>
          {tier !== "dark" && (
            <input
              className="lock-input"
              placeholder="room name (treat as a password)"
              value={name}
              autoFocus
              onChange={(e) => setName(e.target.value)}
            />
          )}
          <button className="primary" onClick={() => void go()} disabled={busy}>
            {busy ? "…" : "› create"}
          </button>
          {err && <p className="error small">{err}</p>}
        </>
      ) : (
        <>
          <p className="muted small">Join by name (+ token for invite rooms), or paste a driftroom: code.</p>
          <input
            className="lock-input"
            placeholder="room name"
            value={name}
            onChange={(e) => setName(e.target.value)}
          />
          <input
            className="lock-input"
            placeholder="invite token (optional)"
            value={token}
            onChange={(e) => setToken(e.target.value)}
          />
          <input
            className="lock-input"
            placeholder="…or paste a driftroom: code"
            value={descriptor}
            onChange={(e) => setDescriptor(e.target.value)}
          />
          <button className="primary" onClick={() => void go()} disabled={busy}>
            {busy ? "…" : "› join"}
          </button>
          {err && <p className="error small">{err}</p>}
        </>
      )}
    </Modal>
  );
}

// ---------------------------------------------------------------- groups

export function NewGroupModal({
  contacts,
  onClose,
  onDone,
}: {
  contacts: string[];
  onClose: () => void;
  onDone: () => void;
}) {
  const [name, setName] = useState("");
  const [picked, setPicked] = useState<Set<string>>(new Set());
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<string | null>(null);

  function toggle(n: string) {
    setPicked((s) => {
      const next = new Set(s);
      if (next.has(n)) next.delete(n);
      else next.add(n);
      return next;
    });
  }

  async function go() {
    if (!name.trim() || busy) return;
    setBusy(true);
    setErr(null);
    try {
      await rpc("group_create", { name: name.trim(), members: [...picked] });
      onDone();
      onClose();
    } catch (e) {
      setErr(String(e));
    } finally {
      setBusy(false);
    }
  }

  return (
    <Modal title="group" onClose={onClose}>
      <p className="muted small">
        A private group (≤10). Forward-secret; you can accept/deny members here.
        Pick from your contacts.
      </p>
      <input
        className="lock-input"
        placeholder="group name"
        value={name}
        autoFocus
        onChange={(e) => setName(e.target.value)}
      />
      <div className="picker">
        {contacts.length === 0 && <p className="muted small">no contacts yet — add some first.</p>}
        {contacts.map((n) => (
          <label key={n} className="toggle">
            <input type="checkbox" checked={picked.has(n)} onChange={() => toggle(n)} />
            {n}
          </label>
        ))}
      </div>
      <button className="primary" onClick={() => void go()} disabled={busy || !name.trim()}>
        {busy ? "…" : "› create group"}
      </button>
      {err && <p className="error small">{err}</p>}
    </Modal>
  );
}

// ---------------------------------------------------------------- manage

export function ManageModal({
  conversation,
  group,
  contacts,
  onClose,
  onDone,
  onLeft,
}: {
  conversation: Conversation;
  group?: GroupInfo;
  contacts: string[];
  onClose: () => void;
  onDone: () => void;
  onLeft: () => void;
}) {
  const { kind, label, tier } = conversation;
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<string | null>(null);
  const [rolled, setRolled] = useState<{ share_code: string; token?: string } | null>(null);
  const [token, setToken] = useState<string | null>(null);
  const [addName, setAddName] = useState("");

  async function rotate() {
    if (busy) return;
    setBusy(true);
    setErr(null);
    try {
      const res = await rpc<{ share_code: string; token?: string }>("room_rotate", { label });
      setRolled(res);
      onDone();
    } catch (e) {
      setErr(String(e));
    } finally {
      setBusy(false);
    }
  }

  async function mint() {
    setBusy(true);
    setErr(null);
    try {
      const res = await rpc<{ token: string }>("room_invite", { label });
      setToken(res.token);
    } catch (e) {
      setErr(String(e));
    } finally {
      setBusy(false);
    }
  }

  async function leave() {
    setBusy(true);
    try {
      await rpc("room_leave", { label });
      onLeft();
      onClose();
    } catch (e) {
      setErr(String(e));
      setBusy(false);
    }
  }

  async function addMember() {
    if (!addName || busy) return;
    setBusy(true);
    setErr(null);
    try {
      await rpc("group_add", { group: label, member_name: addName });
      setAddName("");
      onDone();
    } catch (e) {
      setErr(String(e));
    } finally {
      setBusy(false);
    }
  }

  async function removeMember(code: string) {
    setBusy(true);
    setErr(null);
    try {
      await rpc("group_remove", { group: label, code });
      onDone();
    } catch (e) {
      setErr(String(e));
    } finally {
      setBusy(false);
    }
  }

  const isRoom = kind === "room" || kind === "channel";
  const memberCodes = new Set((group?.members ?? []).map((m) => m.name));
  const addable = contacts.filter((c) => !memberCodes.has(c));

  return (
    <Modal title={`manage · ${label}`} onClose={onClose}>
      {isRoom && (
        <>
          <section className="setting">
            <div className="label">rolling invite code</div>
            <p className="muted small">
              A blind relay can't deny an individual reader, so revoking means
              rolling the code: everyone is locked out until you reshare the new
              one. This is the honest revoke.
            </p>
            {rolled ? (
              <>
                <div className="label">new share code</div>
                <CodeBox code={rolled.share_code} dashed />
                {rolled.token && (
                  <>
                    <div className="label">new posting token</div>
                    <CodeBox code={rolled.token} dashed />
                  </>
                )}
              </>
            ) : (
              <button className="primary" onClick={() => void rotate()} disabled={busy}>
                {busy ? "…" : "› roll the code"}
              </button>
            )}
          </section>
          {tier === "invite" && kind === "room" && (
            <section className="setting">
              <div className="label">invite token</div>
              {token ? (
                <CodeBox code={token} dashed />
              ) : (
                <button className="ghost" onClick={() => void mint()} disabled={busy}>
                  show posting token
                </button>
              )}
            </section>
          )}
          <section className="setting">
            <button className="ghost danger" onClick={() => void leave()} disabled={busy}>
              leave (local only)
            </button>
          </section>
        </>
      )}

      {kind === "group" && (
        <>
          <section className="setting">
            <div className="label">members ({group?.size ?? 1})</div>
            {(group?.members ?? []).map((m) => (
              <div className="member-row" key={m.code}>
                <span className="item-label">{m.name}</span>
                <button className="link danger" onClick={() => void removeMember(m.code)} disabled={busy}>
                  remove
                </button>
              </div>
            ))}
          </section>
          <section className="setting">
            <div className="label">add member (accept)</div>
            <div className="verify-row">
              <select className="select" value={addName} onChange={(e) => setAddName(e.target.value)}>
                <option value="">— pick a contact —</option>
                {addable.map((c) => (
                  <option key={c} value={c}>
                    {c}
                  </option>
                ))}
              </select>
              <button className="ghost" onClick={() => void addMember()} disabled={busy || !addName}>
                + add
              </button>
            </div>
          </section>
        </>
      )}
      {err && <p className="error small">{err}</p>}
    </Modal>
  );
}
