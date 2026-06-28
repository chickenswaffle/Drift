import { useEffect, useRef, useState, useCallback } from "react";
import { rpc, onSidecar } from "./rpc";
import type { Status, Contacts, ChatMessage } from "./types";

const VERSION = "v0.15.3";

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

  if (loading) return <Boot sub="connecting to local core" />;
  if (error) return <Boot sub={`sidecar error: ${error}`} failed />;
  if (!status?.identity_exists) return <Onboarding onDone={refreshStatus} />;
  return <Messenger status={status} />;
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

  async function generate() {
    setBusy(true);
    setErr(null);
    try {
      const res = await rpc<{ contact_code: string }>("init");
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
        {!code ? (
          <>
            <p className="muted">
              No accounts. No phone numbers. Your identity is a keypair generated
              locally — it never leaves this machine.
            </p>
            <button className="primary" disabled={busy} onClick={generate}>
              {busy ? "generating…" : "› generate my identity"}
            </button>
            {err && <p className="error small">{err}</p>}
          </>
        ) : (
          <>
            <div className="label">identity ready — share this code</div>
            <CodeBox code={code} />
            <p />
            <button className="primary" onClick={onDone}>
              › continue
            </button>
          </>
        )}
      </div>
    </div>
  );
}

function CodeBox({ code }: { code: string }) {
  const [copied, setCopied] = useState(false);
  return (
    <div
      className="codebox"
      onClick={() => {
        void navigator.clipboard.writeText(code);
        setCopied(true);
        setTimeout(() => setCopied(false), 1200);
      }}
      title="click to copy"
    >
      <code>{code}</code>
      <span className="copy">{copied ? "copied ✓" : "copy"}</span>
    </div>
  );
}

function Messenger({ status }: { status: Status }) {
  const [myCode, setMyCode] = useState("");
  const [contacts, setContacts] = useState<Contacts>({});
  const [active, setActive] = useState<string | null>(null);
  const [openConvos, setOpenConvos] = useState<Set<string>>(new Set());
  const [threads, setThreads] = useState<Record<string, ChatMessage[]>>({});

  // Append helper kept stable so the event listener never goes stale.
  const append = useCallback((m: ChatMessage) => {
    setThreads((prev) => {
      const list = prev[m.convo] ? [...prev[m.convo], m] : [m];
      return { ...prev, [m.convo]: list };
    });
  }, []);

  useEffect(() => {
    void (async () => {
      try {
        const who = await rpc<{ contact_code: string }>("whoami");
        setMyCode(who.contact_code);
        const c = await rpc<{ contacts: Contacts }>("contacts_list");
        setContacts(c.contacts);
      } catch {
        /* surfaced elsewhere */
      }
    })();
  }, []);

  // Single subscription to the sidecar event stream.
  useEffect(() => {
    const un = onSidecar(({ event, data }) => {
      if (event === "message") {
        append({
          convo: String(data.convo),
          dir: data.dir as ChatMessage["dir"],
          text: String(data.text),
          ts: Date.now(),
        });
      } else if (event === "chat_event") {
        append({
          convo: String(data.convo),
          dir: "sys",
          text: `${data.kind}${data.detail ? ` ${data.detail}` : ""}`,
          ts: Date.now(),
        });
      }
    });
    return () => {
      void un.then((f) => f());
    };
  }, [append]);

  async function openChat(name: string) {
    setActive(name);
    if (openConvos.has(name)) return;
    try {
      await rpc("chat_open", { contact: name, relay_url: status.relay_url });
      setOpenConvos((s) => new Set(s).add(name));
    } catch (e) {
      append({ convo: name, dir: "sys", text: `could not connect: ${e}`, ts: Date.now() });
    }
  }

  async function addContact(name: string, code: string) {
    const res = await rpc<{ contacts: Contacts }>("contacts_add", { name, code });
    setContacts(res.contacts);
  }

  const names = Object.keys(contacts);

  return (
    <div className="app">
      <aside className="sidebar">
        <div className="brand">
          DRIFT<span className="ver">{VERSION}</span>
        </div>
        <div className="me">
          <div className="label">your contact code</div>
          <CodeBox code={myCode} />
        </div>
        <AddContact onAdd={addContact} />
        <div className="contacts">
          <div className="label">contacts</div>
          {names.length === 0 && (
            <p className="muted small">no contacts yet — add one above.</p>
          )}
          {names.map((name, i) => (
            <button
              key={name}
              className={`contact ${active === name ? "active" : ""}`}
              style={{ animationDelay: `${0.04 * i}s` }}
              onClick={() => void openChat(name)}
            >
              <span className="dot" data-on={openConvos.has(name)} />
              {name}
            </button>
          ))}
        </div>
        <div className="footer muted">relay · {status.relay_url}</div>
      </aside>
      <main className="pane">
        {active ? (
          <Chat
            convo={active}
            messages={threads[active] ?? []}
            connected={openConvos.has(active)}
          />
        ) : (
          <div className="empty">
            <span className="blip">›</span> select a contact to open a channel
            <Cursor />
          </div>
        )}
      </main>
    </div>
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
      <div className="label">add contact</div>
      <input placeholder="name" value={name} onChange={(e) => setName(e.target.value)} />
      <input
        placeholder="drift:… contact code"
        value={code}
        onChange={(e) => setCode(e.target.value)}
      />
      <button className="ghost" onClick={() => void submit()} disabled={!name || !code}>
        + add
      </button>
      {err && <p className="error small">{err}</p>}
    </div>
  );
}

function Chat({
  convo,
  messages,
  connected,
}: {
  convo: string;
  messages: ChatMessage[];
  connected: boolean;
}) {
  const [draft, setDraft] = useState("");
  const scroller = useRef<HTMLDivElement>(null);

  useEffect(() => {
    scroller.current?.scrollTo(0, scroller.current.scrollHeight);
  }, [messages]);

  async function send() {
    const text = draft.trim();
    if (!text) return;
    setDraft("");
    try {
      await rpc("chat_send", { convo, text });
    } catch (e) {
      // re-show the draft so nothing is silently lost
      setDraft(text);
      console.error(e);
    }
  }

  const prefix = (dir: ChatMessage["dir"]) => (dir === "out" ? "›" : dir === "in" ? "‹" : "·");

  return (
    <div className="chat">
      <header className="chat-head">
        <span className="dot" data-on={connected} />
        <span className="who">{convo}</span>
        <span className="muted small">
          {connected ? "secure channel open" : "negotiating…"}
        </span>
      </header>
      <div className="scroll" ref={scroller}>
        {messages.map((m, i) => (
          <div key={i} className={`line ${m.dir}`}>
            <span className="pfx">{prefix(m.dir)}</span>
            <span className="body">{m.text}</span>
          </div>
        ))}
      </div>
      <div className="composer">
        <span className="prompt">›</span>
        <input
          placeholder="type a message…"
          value={draft}
          onChange={(e) => setDraft(e.target.value)}
          onKeyDown={(e) => {
            if (e.key === "Enter") void send();
          }}
        />
        <button className="primary" onClick={() => void send()} disabled={!draft.trim()}>
          send
        </button>
      </div>
    </div>
  );
}
