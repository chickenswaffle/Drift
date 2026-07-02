import { useEffect, useRef, useState } from "react";
import type { ChatMessage, Conversation } from "./types";
import { Scramble } from "./Scramble";
import { accentFor, copyText, fmtTime, glyphFor } from "./util";

/** One conversation surface for every kind. A 1:1 chat, a room/channel (public
 *  banner, sender pseudonyms, read-only when you hold no posting token), and a
 *  group (sender names, member count) all share the composer + scroll; only the
 *  header, banner, and per-line author rendering differ. */
// Per-conversation disappearing-messages dial. Client-side display TTL only —
// the sweep lives in App; this just owns the setting + banner.
const EXPIRY_STOPS = [
  { key: "off", seconds: 0 },
  { key: "5m", seconds: 300 },
  { key: "1h", seconds: 3600 },
  { key: "1d", seconds: 86400 },
] as const;

export function ChatPane({
  conversation,
  messages,
  status,
  connected,
  onSend,
  onBurn,
  onManage,
}: {
  conversation: Conversation;
  messages: ChatMessage[];
  status?: string;
  connected: boolean;
  onSend: (text: string) => void;
  onBurn?: (scope: "message" | "conversation") => void;
  onManage?: () => void;
}) {
  const [draft, setDraft] = useState("");
  const [expiry, setExpiry] = useState<number>(() =>
    Number(localStorage.getItem(`drift.expire.${conversation.label}`) ?? 0),
  );
  const [burnArmed, setBurnArmed] = useState(false);
  const [transmit, setTransmit] = useState(false);
  const scroller = useRef<HTMLDivElement>(null);

  function pickExpiry(seconds: number) {
    setExpiry(seconds);
    if (seconds) localStorage.setItem(`drift.expire.${conversation.label}`, String(seconds));
    else localStorage.removeItem(`drift.expire.${conversation.label}`);
  }

  useEffect(() => {
    scroller.current?.scrollTo(0, scroller.current.scrollHeight);
  }, [messages]);

  const { kind, label, tier, canPost, sessionTag, size } = conversation;
  const isRoom = kind === "room" || kind === "channel";
  const readOnly = isRoom && canPost === false;
  const accent = accentFor(label);

  function submit() {
    const t = draft.trim();
    if (!t) return;
    setDraft("");
    onSend(t);
    // Brief "sealed & transmitted" pulse on the composer prompt.
    setTransmit(true);
    setTimeout(() => setTransmit(false), 420);
  }

  const prefix = (m: ChatMessage) =>
    m.dir === "out" ? "›" : m.dir === "in" ? "‹" : "·";

  // Burn targets only our most recent sent line (that's what the burn token
  // addresses — the last message this session sent).
  const lastOutIndex = (() => {
    for (let i = messages.length - 1; i >= 0; i--) {
      if (messages[i].dir === "out") return i;
    }
    return -1;
  })();

  const headStatus =
    status ??
    (isRoom
      ? `${tier ?? "room"}${readOnly ? " · read-only" : ""}`
      : kind === "group"
        ? `${size ?? "?"} members`
        : connected
          ? "secure channel open"
          : "negotiating…");

  return (
    <div className="chat">
      <header className="chat-head">
        <span className="chan-glyph" style={{ color: accent }}>
          {glyphFor(kind)}
        </span>
        <span className="who" style={{ color: accent, textShadow: `0 0 6px ${accent}66` }}>
          {label}
        </span>
        <span className="muted small">{headStatus}</span>
        <span className="head-spacer" />
        <span className="expiry-dial" title="disappearing messages (this screen only)">
          <span className="muted small">expiry</span>
          {EXPIRY_STOPS.map((s) => (
            <button
              key={s.key}
              className={`dial-stop mini ${expiry === s.seconds ? "on" : ""}`}
              onClick={() => pickExpiry(s.seconds)}
            >
              {s.key}
            </button>
          ))}
        </span>
        {onBurn &&
          (burnArmed ? (
            <span className="burn-confirm">
              <button className="link danger" onClick={() => { setBurnArmed(false); onBurn("conversation"); }}>
                confirm burn
              </button>
              <button className="link" onClick={() => setBurnArmed(false)}>
                cancel
              </button>
            </span>
          ) : (
            <button
              className="link danger"
              title="erase this conversation from the relay and your peer's verified client"
              onClick={() => setBurnArmed(true)}
            >
              burn conversation
            </button>
          ))}
        {onManage && kind !== "contact" && (
          <button className="link chat-manage" onClick={onManage}>
            manage
          </button>
        )}
      </header>

      {expiry > 0 && (
        <div className="room-banner disappearing" title="client-side display timer">
          DISAPPEARING · lines vanish from this screen on schedule. Your peer keeps
          their copy unless you burn — burn asks their verified client to delete
          too. Honest relays hold nothing past 30 seconds either way.
        </div>
      )}

      {isRoom && (
        <div className="room-banner" title="rooms are shared-key, not ratcheted">
          PUBLIC · encrypted, not forward-secret · sender tags are pseudonyms, not
          identities
        </div>
      )}

      <div className="scroll" ref={scroller}>
        {messages.map((m, i) => (
          <div key={i} className={`line ${m.dir}`}>
            <span className="pfx">{prefix(m)}</span>
            {m.dir === "in" && m.who && (
              <span className="who-tag" style={{ color: accentFor(m.who) }}>
                {m.who}
                {m.authorized === false ? " (unverified)" : ""}
              </span>
            )}
            {m.dir === "in" ? (
              <Scramble className="body" text={m.text} />
            ) : (
              <span className="body">{m.text}</span>
            )}
            {m.dir !== "sys" && (
              <button
                className="line-copy"
                title="copy this line to the clipboard"
                onClick={() => void copyText(m.text)}
              >
                copy
              </button>
            )}
            {onBurn && i === lastOutIndex && (
              <button
                className="line-copy danger"
                title="erase this message from the relay and your peer's verified client"
                onClick={() => onBurn("message")}
              >
                burn
              </button>
            )}
            <span className="ts muted">{fmtTime(m.ts)}</span>
          </div>
        ))}
      </div>

      <div className={`composer${transmit ? " transmit" : ""}`}>
        <span className="prompt">{sessionTag ? `${sessionTag} ›` : "›"}</span>
        <input
          placeholder={readOnly ? "read-only — you hold no posting token" : "type a message…"}
          value={draft}
          disabled={readOnly}
          onChange={(e) => setDraft(e.target.value)}
          onKeyDown={(e) => {
            if (e.key === "Enter") submit();
          }}
        />
        <button className="primary" onClick={submit} disabled={readOnly || !draft.trim()}>
          send
        </button>
      </div>
    </div>
  );
}
