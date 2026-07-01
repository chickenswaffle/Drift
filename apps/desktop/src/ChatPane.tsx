import { useEffect, useRef, useState } from "react";
import type { ChatMessage, Conversation } from "./types";
import { accentFor, fmtTime, glyphFor } from "./util";

/** One conversation surface for every kind. A 1:1 chat, a room/channel (public
 *  banner, sender pseudonyms, read-only when you hold no posting token), and a
 *  group (sender names, member count) all share the composer + scroll; only the
 *  header, banner, and per-line author rendering differ. */
export function ChatPane({
  conversation,
  messages,
  status,
  connected,
  onSend,
  onManage,
}: {
  conversation: Conversation;
  messages: ChatMessage[];
  status?: string;
  connected: boolean;
  onSend: (text: string) => void;
  onManage?: () => void;
}) {
  const [draft, setDraft] = useState("");
  const scroller = useRef<HTMLDivElement>(null);

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
  }

  const prefix = (m: ChatMessage) =>
    m.dir === "out" ? "›" : m.dir === "in" ? "‹" : "·";

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
        {onManage && kind !== "contact" && (
          <button className="link chat-manage" onClick={onManage}>
            manage
          </button>
        )}
      </header>

      {isRoom && (
        <div className="room-banner" title="rooms are shared-key, not ratcheted">
          PUBLIC · encrypted, not forward-secret · sender tags are pseudonyms, not
          identities
        </div>
      )}

      <div className="scroll" ref={scroller}>
        {messages.map((m, i) => (
          <div
            key={i}
            className={`line ${m.dir}`}
            title="click to copy"
            onClick={() => void navigator.clipboard.writeText(m.text)}
          >
            <span className="pfx">{prefix(m)}</span>
            {m.dir === "in" && m.who && (
              <span className="who-tag" style={{ color: accentFor(m.who) }}>
                {m.who}
                {m.authorized === false ? " (unverified)" : ""}
              </span>
            )}
            <span className="body">{m.text}</span>
            <span className="ts muted">{fmtTime(m.ts)}</span>
          </div>
        ))}
      </div>

      <div className="composer">
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
