import { useCallback, useEffect, useRef, useState } from "react";
import { rpc, onSidecar } from "./rpc";
import { Settings, notificationsEnabled } from "./Settings";
import { notify } from "./notify";
import { Sidebar } from "./Sidebar";
import { ChatPane } from "./ChatPane";
import { CommandPalette, type Command } from "./CommandPalette";
import { NewChannelModal, JoinRoomModal, NewGroupModal, ManageModal, InviteModal } from "./modals";
import { CodeBox } from "./CodeBox";
import type {
  ChatMessage,
  Contacts,
  Conversation,
  ConvoKind,
  GroupInfo,
  RoomInfo,
  Status,
} from "./types";

const VERSION = "v0.19.0";

// Block-art wordmark shown on the boot screen.
const WORDMARK = String.raw`
 ██████╗ ██████╗ ██╗███████╗████████╗
 ██╔══██╗██╔══██╗██║██╔════╝╚══██╔══╝
 ██║  ██║██████╔╝██║█████╗     ██║
 ██║  ██║██╔══██╗██║██╔══╝     ██║
 ██████╔╝██║  ██║██║██║        ██║
 ╚═════╝ ╚═╝  ╚═╝╚═╝╚═╝        ╚═╝`;

/** Blinking terminal caret. */
function Cursor() {
  return <span className="cursor" aria-hidden />;
}

export function App() {
  const [status, setStatus] = useState<Status | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [locked, setLocked] = useState(false);
  const [lockPrompt, setLockPrompt] = useState(false);

  const hasVault = useRef(false);
  hasVault.current = !!status?.vault_exists;

  const refreshStatus = useCallback(async () => {
    try {
      setStatus(await rpc<Status>("status"));
    } catch (e) {
      setError(String(e));
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    void refreshStatus();
  }, [refreshStatus]);

  // Tray "lock vault" → open the lock prompt (only when there's a vault to seal).
  useEffect(() => {
    let un: (() => void) | undefined;
    void (async () => {
      try {
        const { listen } = await import("@tauri-apps/api/event");
        un = await listen("menu:lock", () => {
          if (hasVault.current) setLockPrompt(true);
        });
      } catch {
        /* no Tauri in dev */
      }
    })();
    return () => un?.();
  }, []);

  // Panic (tray item or the global CmdOrCtrl+Shift+L): no prompt, no
  // passphrase — shred the working copy, show the lock screen, hide the
  // window. Changes since the last unlock are discarded by design.
  useEffect(() => {
    let un: (() => void) | undefined;
    void (async () => {
      try {
        const { listen } = await import("@tauri-apps/api/event");
        un = await listen("menu:panic", () => {
          if (!hasVault.current) return;
          void (async () => {
            try {
              await rpc("panic_lock");
              setLockPrompt(false);
              setLocked(true);
              const { getCurrentWindow } = await import("@tauri-apps/api/window");
              await getCurrentWindow().hide();
            } catch {
              /* no vault or sidecar hiccup — nothing to seal */
            }
          })();
        });
      } catch {
        /* no Tauri in dev */
      }
    })();
    return () => un?.();
  }, []);

  let content: JSX.Element;
  if (locked) {
    content = (
      <LockScreen
        onUnlock={() => {
          setLocked(false);
          void refreshStatus();
        }}
      />
    );
  } else if (loading) {
    content = <Boot sub="connecting to local core" />;
  } else if (error) {
    content = <Boot sub={`sidecar error: ${error}`} failed />;
  } else if (!status?.identity_exists) {
    content = <Onboarding onDone={refreshStatus} />;
  } else {
    content = (
      <Messenger
        status={status}
        onLock={() => setLockPrompt(true)}
        onRefreshStatus={refreshStatus}
      />
    );
  }

  return (
    <>
      <div className="scanbar" aria-hidden />
      {content}
      {lockPrompt && (
        <LockPrompt
          onLocked={() => {
            setLockPrompt(false);
            setLocked(true);
          }}
          onCancel={() => setLockPrompt(false)}
        />
      )}
    </>
  );
}

const BOOT_LINES = [
  "drift core " + VERSION,
  "spinning up local node",
  "loading identity keyring",
  "negotiating sealed transport",
];

function Boot({ sub, failed }: { sub: string; failed?: boolean }) {
  return (
    <div className="boot">
      <pre className="ascii">{WORDMARK}</pre>
      <div className="boot-log">
        {BOOT_LINES.map((l, i) => (
          <div key={i} className="boot-line" style={{ animationDelay: `${0.15 * i}s` }}>
            <span className="ok">›</span> {l}…
          </div>
        ))}
        <div
          className={`boot-line status ${failed ? "err" : ""}`}
          style={{ animationDelay: `${0.15 * BOOT_LINES.length}s` }}
        >
          {failed ? (
            <>
              <span className="bad">✗</span> {sub}
            </>
          ) : (
            <>
              <span className="dot-pulse" /> {sub}
              <Cursor />
            </>
          )}
        </div>
      </div>
    </div>
  );
}

function Onboarding({ onDone }: { onDone: () => void }) {
  const [busy, setBusy] = useState(false);
  const [code, setCode] = useState<string | null>(null);
  const [err, setErr] = useState<string | null>(null);
  // Optional seal-it-now step: the sidecar's init already takes vault params,
  // so onboarding can create identity + vault in one shot.
  const [sealing, setSealing] = useState(false);
  const [pass, setPass] = useState("");
  const [duress, setDuress] = useState("");
  const [mode, setMode] = useState<"wipe" | "decoy">("wipe");

  async function generate(withVault: boolean) {
    setBusy(true);
    setErr(null);
    try {
      const params = withVault
        ? {
            passphrase: pass,
            duress_passphrase: duress || undefined,
            duress_mode: duress ? mode : undefined,
          }
        : {};
      const res = await rpc<{ contact_code: string }>("init", params);
      setCode(res.contact_code);
    } catch (e) {
      setErr(String(e));
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="boot">
      <pre className="ascii">{WORDMARK}</pre>
      <div className="card">
        {code ? (
          <>
            <div className="label">identity ready — share this code</div>
            <CodeBox code={code} />
            <p />
            <button className="primary" onClick={onDone}>
              › continue
            </button>
          </>
        ) : sealing ? (
          <>
            <p className="muted small">
              Seal your identity behind a passphrase from the start. An optional
              duress passphrase opens a decoy or triggers a wipe —
              indistinguishable to an onlooker from a normal unlock.
            </p>
            <input
              className="lock-input"
              type="password"
              placeholder="passphrase"
              value={pass}
              autoFocus
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
            <button
              className="primary"
              disabled={busy || !pass}
              onClick={() => void generate(true)}
            >
              {busy ? "generating…" : "› generate sealed identity"}
            </button>
            <button className="link" onClick={() => setSealing(false)}>
              back
            </button>
            {err && <p className="error small">{err}</p>}
          </>
        ) : (
          <>
            <p className="muted">
              No accounts. No phone numbers. Your identity is a keypair generated
              locally — it never leaves this machine.
            </p>
            <button className="primary" disabled={busy} onClick={() => void generate(false)}>
              {busy ? "generating…" : "› generate my identity"}
            </button>
            <button className="link" onClick={() => setSealing(true)}>
              › generate + seal with a passphrase
            </button>
            {err && <p className="error small">{err}</p>}
          </>
        )}
      </div>
    </div>
  );
}

/** Full-screen vault gate shown after locking. */
function LockScreen({ onUnlock }: { onUnlock: () => void }) {
  const [pass, setPass] = useState("");
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<string | null>(null);

  async function unlock() {
    if (!pass || busy) return;
    setBusy(true);
    setErr(null);
    try {
      // Indistinguishable by design: real, decoy, and wipe passphrases all return
      // ok=true and take this exact same path — same text, timing, transition.
      // Only a passphrase that opens neither slot returns ok=false.
      const res = await rpc<{ ok: boolean }>("unlock", { passphrase: pass });
      if (res.ok) {
        onUnlock();
      } else {
        setPass("");
        setErr("incorrect passphrase");
      }
    } catch (e) {
      setErr(String(e));
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="boot">
      <pre className="ascii">{WORDMARK}</pre>
      <div className="card lock">
        <div className="label">vault locked</div>
        <p className="muted small">Enter your passphrase to unseal your identity.</p>
        <input
          className="lock-input"
          type="password"
          placeholder="passphrase"
          value={pass}
          autoFocus
          onChange={(e) => setPass(e.target.value)}
          onKeyDown={(e) => {
            if (e.key === "Enter") void unlock();
          }}
        />
        <button className="primary" onClick={() => void unlock()} disabled={busy || !pass}>
          {busy ? "…" : "› unlock"}
        </button>
        {err && <p className="error small">{err}</p>}
      </div>
    </div>
  );
}

/** Passphrase prompt to seal the vault. */
function LockPrompt({ onLocked, onCancel }: { onLocked: () => void; onCancel: () => void }) {
  const [pass, setPass] = useState("");
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<string | null>(null);

  async function lock() {
    if (!pass || busy) return;
    setBusy(true);
    setErr(null);
    try {
      const res = await rpc<{ locked: boolean }>("lock", { passphrase: pass });
      if (res.locked) onLocked();
      else setErr("that passphrase doesn't open the vault");
    } catch (e) {
      setErr(String(e));
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="modal-backdrop" onClick={onCancel}>
      <div
        className="modal card"
        role="dialog"
        aria-modal="true"
        aria-label="lock vault"
        onClick={(e) => e.stopPropagation()}
      >
        <header className="modal-head">
          <span className="modal-title">lock vault</span>
          <button className="modal-x" onClick={onCancel} aria-label="cancel">
            ✗
          </button>
        </header>
        <p className="muted small">
          Seal your identity and close every open channel. Unlock again with your
          passphrase.
        </p>
        <input
          className="lock-input"
          type="password"
          placeholder="passphrase"
          value={pass}
          autoFocus
          onChange={(e) => setPass(e.target.value)}
          onKeyDown={(e) => {
            if (e.key === "Enter") void lock();
          }}
        />
        <button className="primary" onClick={() => void lock()} disabled={busy || !pass}>
          {busy ? "sealing…" : "› lock now"}
        </button>
        {err && <p className="error small">{err}</p>}
      </div>
    </div>
  );
}

type Modal = "channel" | "room" | "group" | "manage" | "invite" | null;

function Messenger({
  status,
  onLock,
  onRefreshStatus,
}: {
  status: Status;
  onLock: () => void;
  onRefreshStatus: () => void;
}) {
  const relayUrl = status.relay_url;
  const [myCode, setMyCode] = useState("");
  const [contacts, setContacts] = useState<Contacts>({});
  const [channels, setChannels] = useState<RoomInfo[]>([]);
  const [rooms, setRooms] = useState<RoomInfo[]>([]);
  const [groups, setGroups] = useState<GroupInfo[]>([]);
  const [active, setActive] = useState<Conversation | null>(null);
  const [open, setOpen] = useState<Record<string, Conversation>>({});
  const [threads, setThreads] = useState<Record<string, ChatMessage[]>>({});
  const [convoStatus, setConvoStatus] = useState<Record<string, string>>({});
  const [modal, setModal] = useState<Modal>(null);
  const [settingsOpen, setSettingsOpen] = useState(false);
  const [paletteOpen, setPaletteOpen] = useState(false);

  const openRef = useRef(open);
  openRef.current = open;

  // Convos where WE just requested a burn: the relay echoes the verified
  // tombstone to every subscriber (us included), so the event — not the rpc
  // call — is the single source of truth. This flag only decides whether the
  // sys line says "you" or "peer" and which side's line disappears.
  const pendingBurns = useRef(new Set<string>());

  const append = useCallback((m: ChatMessage) => {
    setThreads((prev) => {
      const list = prev[m.convo] ? [...prev[m.convo], m] : [m];
      return { ...prev, [m.convo]: list };
    });
  }, []);

  const refreshLists = useCallback(async () => {
    try {
      const c = await rpc<{ contacts: Contacts }>("contacts_list");
      setContacts(c.contacts);
      const ch = await rpc<{ channels: RoomInfo[]; rooms: RoomInfo[] }>("channels_list");
      setChannels(ch.channels);
      setRooms(ch.rooms);
      const g = await rpc<{ groups: GroupInfo[] }>("groups_list");
      setGroups(g.groups);
    } catch {
      /* surfaced elsewhere */
    }
  }, []);

  useEffect(() => {
    void (async () => {
      try {
        const who = await rpc<{ contact_code: string }>("whoami");
        setMyCode(who.contact_code);
      } catch {
        /* surfaced elsewhere */
      }
      await refreshLists();
    })();
  }, [refreshLists]);

  // One subscription to the sidecar event stream.
  useEffect(() => {
    const un = onSidecar(({ event, data }) => {
      if (event === "message") {
        const convo = String(data.convo);
        const dir = data.dir as ChatMessage["dir"];
        const who = data.who != null ? String(data.who) : undefined;
        const authorized =
          typeof data.authorized === "boolean" ? data.authorized : undefined;
        append({ convo, dir, text: String(data.text), ts: Date.now(), who, authorized });
        if (dir === "in" && notificationsEnabled() && !document.hasFocus()) {
          void notify(who ?? convo);
        }
      } else if (event === "chat_event") {
        const convo = String(data.convo);
        const detail = `${data.kind}${data.detail ? ` ${data.detail}` : ""}`;
        setConvoStatus((s) => ({ ...s, [convo]: detail }));
        append({ convo, dir: "sys", text: detail, ts: Date.now() });
      } else if (event === "burn") {
        // Only HMAC-verified tombstones reach here (the session checks the
        // token before the sidecar emits).
        const convo = String(data.convo);
        const scope = String(data.scope);
        const mine = pendingBurns.current.delete(convo);
        setThreads((prev) => {
          const list = prev[convo] ?? [];
          if (scope === "conversation") {
            return {
              ...prev,
              [convo]: [{
                convo, dir: "sys" as const, ts: Date.now(),
                text: mine ? "conversation burned" : "conversation burned by peer",
              }],
            };
          }
          // message scope: the burner's last sent line vanishes — ours if we
          // initiated, else the peer's latest incoming.
          const gone = mine ? "out" : "in";
          const idx = [...list].reverse().findIndex((m) => m.dir === gone);
          const next = idx === -1 ? [...list] : [
            ...list.slice(0, list.length - 1 - idx),
            ...list.slice(list.length - idx),
          ];
          next.push({
            convo, dir: "sys" as const, ts: Date.now(),
            text: mine ? "your last message burned" : "peer burned their last message",
          });
          return { ...prev, [convo]: next };
        });
      }
    });
    return () => {
      void un.then((f) => f());
    };
  }, [append]);

  // Ctrl/Cmd-K toggles the command palette.
  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if ((e.ctrlKey || e.metaKey) && e.key.toLowerCase() === "k") {
        e.preventDefault();
        setPaletteOpen((p) => !p);
      }
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, []);

  const openConversation = useCallback(
    async (kind: ConvoKind, label: string, meta: Partial<Conversation> = {}) => {
      const existing = openRef.current[label];
      if (existing) {
        setActive(existing);
        return;
      }
      setActive({ kind, label, ...meta });
      try {
        const params =
          kind === "contact"
            ? { kind, contact: label, relay_url: relayUrl }
            : { kind, label, relay_url: relayUrl };
        const res = await rpc<{
          tier?: string;
          can_post?: boolean;
          session_tag?: string;
          size?: number;
        }>("chat_open", params);
        const merged: Conversation = {
          kind,
          label,
          tier: res.tier ?? meta.tier,
          canPost: res.can_post ?? meta.canPost,
          sessionTag: res.session_tag,
          size: res.size ?? meta.size,
          isOwner: meta.isOwner,
        };
        setOpen((o) => ({ ...o, [label]: merged }));
        setActive((a) => (a && a.label === label ? merged : a));
      } catch (e) {
        append({ convo: label, dir: "sys", text: `could not open: ${e}`, ts: Date.now() });
      }
    },
    [relayUrl, append],
  );

  async function send(text: string) {
    if (!active) return;
    try {
      await rpc("chat_send", { convo: active.label, text });
    } catch (e) {
      append({ convo: active.label, dir: "sys", text: `send failed: ${e}`, ts: Date.now() });
    }
  }

  async function burn(scope: "message" | "conversation") {
    if (!active) return;
    const convo = active.label;
    pendingBurns.current.add(convo);
    try {
      await rpc("chat_burn", { convo, scope });
      // The verified tombstone will arrive as a "burn" event and do the erasing.
    } catch (e) {
      pendingBurns.current.delete(convo);
      append({ convo, dir: "sys", text: `burn failed: ${e}`, ts: Date.now() });
    }
  }

  // Disappearing messages: one sweep drops lines older than each conversation's
  // expiry dial (localStorage drift.expire.<label>, seconds; absent/0 = off).
  // Client-side by design — there is no on-disk history anywhere to purge, and
  // the peer keeps their copy unless burn is used.
  useEffect(() => {
    const sweep = () => {
      const now = Date.now();
      setThreads((prev) => {
        let changed = false;
        const next: typeof prev = {};
        for (const [label, list] of Object.entries(prev)) {
          const ttl = Number(localStorage.getItem(`drift.expire.${label}`) ?? 0);
          if (!ttl) {
            next[label] = list;
            continue;
          }
          const kept = list.filter((m) => m.dir === "sys" || m.ts >= now - ttl * 1000);
          if (kept.length !== list.length) changed = true;
          next[label] = kept;
        }
        return changed ? next : prev;
      });
    };
    const t = setInterval(sweep, 30_000);
    return () => clearInterval(t);
  }, []);

  async function addContact(name: string, code: string): Promise<string | void> {
    // A driftinvite: code redeems (and burns) a disappearing invite; a drift:
    // code is a permanent contact code. Same box, both work.
    if (code.startsWith("driftinvite:")) {
      const res = await rpc<{ contacts: Contacts }>("invite_resolve", { name, code });
      setContacts(res.contacts);
      return (
        "added — unverified. An invite proves the code wasn't tampered with, " +
        "not who made it. Compare safety numbers before trusting."
      );
    }
    const res = await rpc<{ contacts: Contacts }>("contacts_add", { name, code });
    setContacts(res.contacts);
  }

  async function removeContact(name: string) {
    try {
      const res = await rpc<{ contacts: Contacts }>("contacts_remove", { name });
      setContacts(res.contacts);
      // The sidecar closed any live session; drop our side of it too.
      setOpen((o) => {
        const next = { ...o };
        delete next[name];
        return next;
      });
      setThreads((t) => {
        const next = { ...t };
        delete next[name];
        return next;
      });
      setActive((a) => (a && a.kind === "contact" && a.label === name ? null : a));
    } catch {
      /* surfaced elsewhere */
    }
  }

  async function checkCode(code: string): Promise<string> {
    const res = await rpc<{ safety_number: string }>("safety_number", { code });
    return res.safety_number;
  }

  function onNew(kind: ConvoKind) {
    if (kind === "channel") setModal("channel");
    else if (kind === "room") setModal("room");
    else if (kind === "group") setModal("group");
    // contacts add inline in the sidebar
  }

  // Palette commands: every conversation + the create/lock/settings actions.
  const commands: Command[] = [
    ...channels.map((c) => ({
      id: `ch:${c.label}`,
      label: `# ${c.label}`,
      hint: "channel",
      run: () =>
        void openConversation("channel", c.label, {
          tier: c.tier,
          canPost: c.can_post,
          isOwner: c.is_owner,
        }),
    })),
    ...rooms.map((r) => ({
      id: `rm:${r.label}`,
      label: `⬡ ${r.label}`,
      hint: `room · ${r.tier}`,
      run: () => void openConversation("room", r.label, { tier: r.tier, canPost: r.can_post }),
    })),
    ...groups.map((g) => ({
      id: `gr:${g.label}`,
      label: `※ ${g.label}`,
      hint: "group",
      run: () => void openConversation("group", g.label, { size: g.size }),
    })),
    ...Object.keys(contacts).map((n) => ({
      id: `ct:${n}`,
      label: `› ${n}`,
      hint: "contact",
      run: () => void openConversation("contact", n),
    })),
    { id: "new-channel", label: "New channel", hint: "action", run: () => setModal("channel") },
    { id: "new-room", label: "New room", hint: "action", run: () => setModal("room") },
    { id: "new-group", label: "New group", hint: "action", run: () => setModal("group") },
    { id: "invite", label: "Share disappearing code", hint: "action", run: () => setModal("invite") },
    { id: "settings", label: "Settings", hint: "action", run: () => setSettingsOpen(true) },
    ...(status.vault_exists
      ? [{ id: "lock", label: "Lock vault", hint: "action", run: onLock }]
      : []),
  ];

  const activeConvo = active ? (open[active.label] ?? active) : null;

  return (
    <div className="app">
      <Sidebar
        version={VERSION}
        myCode={myCode}
        contacts={Object.keys(contacts)}
        channels={channels}
        rooms={rooms}
        groups={groups}
        active={active}
        openLabels={new Set(Object.keys(open))}
        onOpen={(kind, label, meta) => void openConversation(kind, label, meta)}
        onNew={onNew}
        onAddContact={addContact}
        onRemoveContact={(name) => void removeContact(name)}
        onCheckCode={checkCode}
        onInvite={() => setModal("invite")}
        onSettings={() => setSettingsOpen(true)}
        onLock={onLock}
        vaultExists={status.vault_exists}
        relayUrl={relayUrl}
      />
      <main className="pane">
        {activeConvo ? (
          <ChatPane
            key={activeConvo.label}
            conversation={activeConvo}
            messages={threads[activeConvo.label] ?? []}
            status={convoStatus[activeConvo.label]}
            connected={!!open[activeConvo.label]}
            onSend={send}
            onBurn={
              activeConvo.kind === "contact" && open[activeConvo.label]
                ? (scope) => void burn(scope)
                : undefined
            }
            onManage={activeConvo.kind !== "contact" ? () => setModal("manage") : undefined}
          />
        ) : (
          <EmptyState onPalette={() => setPaletteOpen(true)} />
        )}
      </main>

      {settingsOpen && (
        <Settings
          status={status}
          contacts={contacts}
          version={VERSION}
          onChanged={onRefreshStatus}
          onClose={() => setSettingsOpen(false)}
        />
      )}
      {modal === "invite" && <InviteModal onClose={() => setModal(null)} />}
      {modal === "channel" && (
        <NewChannelModal onClose={() => setModal(null)} onDone={() => void refreshLists()} />
      )}
      {modal === "room" && (
        <JoinRoomModal onClose={() => setModal(null)} onDone={() => void refreshLists()} />
      )}
      {modal === "group" && (
        <NewGroupModal
          contacts={Object.keys(contacts)}
          onClose={() => setModal(null)}
          onDone={() => void refreshLists()}
        />
      )}
      {modal === "manage" && activeConvo && (
        <ManageModal
          conversation={activeConvo}
          group={
            activeConvo.kind === "group"
              ? groups.find((g) => g.label === activeConvo.label)
              : undefined
          }
          contacts={Object.keys(contacts)}
          onClose={() => setModal(null)}
          onDone={() => void refreshLists()}
          onLeft={() => {
            const label = activeConvo.label;
            setModal(null);
            setActive(null);
            setOpen((o) => {
              const next = { ...o };
              delete next[label];
              return next;
            });
            void refreshLists();
          }}
        />
      )}
      {paletteOpen && (
        <CommandPalette commands={commands} onClose={() => setPaletteOpen(false)} />
      )}
    </div>
  );
}

function EmptyState({ onPalette }: { onPalette: () => void }) {
  return (
    <div className="empty">
      <pre className="ascii empty-mark">{WORDMARK}</pre>
      <div className="empty-hint muted">
        <span className="blip">›</span> select a conversation, or press{" "}
        <button className="kbd" onClick={onPalette}>
          Ctrl-K
        </button>{" "}
        to jump anywhere
        <Cursor />
      </div>
    </div>
  );
}
