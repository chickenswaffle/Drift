import { useState } from "react";
import { CodeBox } from "./CodeBox";
import { accentFor, glyphFor } from "./util";
import type { Conversation, ConvoKind, GroupInfo, RoomInfo } from "./types";

interface Item {
  kind: ConvoKind;
  label: string;
  sub?: string; // small trailing note (tier, member count, …)
}

export function Sidebar({
  version,
  myCode,
  contacts,
  channels,
  rooms,
  groups,
  active,
  openLabels,
  onOpen,
  onNew,
  onAddContact,
  onSettings,
  onLock,
  vaultExists,
  relayUrl,
}: {
  version: string;
  myCode: string;
  contacts: string[];
  channels: RoomInfo[];
  rooms: RoomInfo[];
  groups: GroupInfo[];
  active: Conversation | null;
  openLabels: Set<string>;
  onOpen: (kind: ConvoKind, label: string, meta?: Partial<Conversation>) => void;
  onNew: (kind: ConvoKind) => void;
  onAddContact: (name: string, code: string) => Promise<void>;
  onSettings: () => void;
  onLock: () => void;
  vaultExists: boolean;
  relayUrl: string;
}) {
  const channelItems: Item[] = channels.map((c) => ({
    kind: "channel",
    label: c.label,
    sub: c.is_owner ? "owner" : "sub",
  }));
  const roomItems: Item[] = rooms.map((r) => ({ kind: "room", label: r.label, sub: r.tier }));
  const groupItems: Item[] = groups.map((g) => ({
    kind: "group",
    label: g.label,
    sub: `${g.size}`,
  }));
  const contactItems: Item[] = contacts.map((n) => ({ kind: "contact", label: n }));

  const meta = (kind: ConvoKind, label: string): Partial<Conversation> => {
    if (kind === "channel") {
      const c = channels.find((x) => x.label === label);
      return { tier: c?.tier, canPost: c?.can_post, isOwner: c?.is_owner };
    }
    if (kind === "room") {
      const r = rooms.find((x) => x.label === label);
      return { tier: r?.tier, canPost: r?.can_post };
    }
    if (kind === "group") {
      const g = groups.find((x) => x.label === label);
      return { size: g?.size };
    }
    return {};
  };

  return (
    <aside className="sidebar">
      <div className="brand">
        DRIFT<span className="ver">{version}</span>
      </div>
      <div className="me">
        <div className="label">your contact code</div>
        <CodeBox code={myCode} />
      </div>

      <div className="nav">
        <Section title="channels" kind="channel" onNew={onNew} count={channelItems.length}>
          {channelItems.map((it) => (
            <NavItem
              key={it.label}
              item={it}
              active={active?.kind === "channel" && active.label === it.label}
              on={openLabels.has(it.label)}
              onClick={() => onOpen("channel", it.label, meta("channel", it.label))}
            />
          ))}
        </Section>

        <Section title="rooms" kind="room" onNew={onNew} count={roomItems.length}>
          {roomItems.map((it) => (
            <NavItem
              key={it.label}
              item={it}
              active={active?.kind === "room" && active.label === it.label}
              on={openLabels.has(it.label)}
              onClick={() => onOpen("room", it.label, meta("room", it.label))}
            />
          ))}
        </Section>

        <Section title="groups" kind="group" onNew={onNew} count={groupItems.length}>
          {groupItems.map((it) => (
            <NavItem
              key={it.label}
              item={it}
              active={active?.kind === "group" && active.label === it.label}
              on={openLabels.has(it.label)}
              onClick={() => onOpen("group", it.label, meta("group", it.label))}
            />
          ))}
        </Section>

        <Section
          title="contacts"
          kind="contact"
          onNew={onNew}
          count={contactItems.length}
          adder={<AddContact onAdd={onAddContact} />}
        >
          {contactItems.map((it) => (
            <NavItem
              key={it.label}
              item={it}
              active={active?.kind === "contact" && active.label === it.label}
              on={openLabels.has(it.label)}
              onClick={() => onOpen("contact", it.label)}
            />
          ))}
        </Section>
      </div>

      <div className="footer">
        <div className="foot-actions">
          <button className="link" onClick={onSettings}>
            settings
          </button>
          {vaultExists && (
            <button className="link" onClick={onLock}>
              lock
            </button>
          )}
        </div>
        <div className="muted small">relay · {relayUrl}</div>
      </div>
    </aside>
  );
}

function Section({
  title,
  kind,
  count,
  onNew,
  children,
  adder,
}: {
  title: string;
  kind: ConvoKind;
  count: number;
  onNew: (kind: ConvoKind) => void;
  children: React.ReactNode;
  adder?: React.ReactNode;
}) {
  const [open, setOpen] = useState(true);
  const [showAdder, setShowAdder] = useState(false);
  return (
    <div className="nav-section">
      <div className="nav-head">
        <button className="nav-toggle" onClick={() => setOpen((o) => !o)}>
          <span className="caret">{open ? "▾" : "▸"}</span> {title}
          <span className="nav-count">{count}</span>
        </button>
        <button
          className="nav-add"
          title={`new ${title.replace(/s$/, "")}`}
          onClick={() => (adder ? setShowAdder((s) => !s) : onNew(kind))}
        >
          ＋
        </button>
      </div>
      {open && (
        <div className="nav-items">
          {adder && showAdder ? adder : null}
          {children}
        </div>
      )}
    </div>
  );
}

function NavItem({
  item,
  active,
  on,
  onClick,
}: {
  item: Item;
  active: boolean;
  on: boolean;
  onClick: () => void;
}) {
  const accent = accentFor(item.label);
  return (
    <button className={`nav-item ${active ? "active" : ""}`} onClick={onClick}>
      <span className="item-glyph" style={{ color: accent }}>
        {glyphFor(item.kind)}
      </span>
      <span className="item-label">{item.label}</span>
      {item.sub && <span className="item-sub muted">{item.sub}</span>}
      <span className="dot" data-on={on} />
    </button>
  );
}

function AddContact({ onAdd }: { onAdd: (name: string, code: string) => Promise<void> }) {
  const [name, setName] = useState("");
  const [code, setCode] = useState("");
  const [err, setErr] = useState<string | null>(null);

  async function submit() {
    setErr(null);
    try {
      await onAdd(name.trim(), code.trim());
      setName("");
      setCode("");
    } catch (e) {
      setErr(String(e));
    }
  }

  return (
    <div className="add-contact">
      <input placeholder="name" value={name} onChange={(e) => setName(e.target.value)} />
      <input
        placeholder="drift:… contact code"
        value={code}
        onChange={(e) => setCode(e.target.value)}
      />
      <button className="ghost" onClick={() => void submit()} disabled={!name || !code}>
        + add contact
      </button>
      {err && <p className="error small">{err}</p>}
    </div>
  );
}
