import { useEffect, useMemo, useState } from "react";

export interface Command {
  id: string;
  label: string;
  hint?: string;
  run: () => void;
}

/** Ctrl/Cmd-K launcher: fuzzy-jump to any conversation and run actions. */
export function CommandPalette({
  commands,
  onClose,
}: {
  commands: Command[];
  onClose: () => void;
}) {
  const [q, setQ] = useState("");
  const [sel, setSel] = useState(0);

  const filtered = useMemo(() => {
    const needle = q.toLowerCase().trim();
    if (!needle) return commands;
    return commands.filter(
      (c) =>
        c.label.toLowerCase().includes(needle) ||
        (c.hint ?? "").toLowerCase().includes(needle),
    );
  }, [q, commands]);

  useEffect(() => {
    setSel(0);
  }, [q]);

  function onKey(e: React.KeyboardEvent) {
    if (e.key === "ArrowDown") {
      e.preventDefault();
      setSel((s) => Math.min(s + 1, filtered.length - 1));
    } else if (e.key === "ArrowUp") {
      e.preventDefault();
      setSel((s) => Math.max(s - 1, 0));
    } else if (e.key === "Enter") {
      e.preventDefault();
      const cmd = filtered[sel];
      if (cmd) {
        onClose();
        cmd.run();
      }
    } else if (e.key === "Escape") {
      onClose();
    }
  }

  return (
    <div className="modal-backdrop palette-backdrop" onClick={onClose}>
      <div className="palette" onClick={(e) => e.stopPropagation()}>
        <input
          className="palette-input"
          placeholder="jump to… or type a command"
          value={q}
          autoFocus
          onChange={(e) => setQ(e.target.value)}
          onKeyDown={onKey}
        />
        <div className="palette-list">
          {filtered.length === 0 && <div className="palette-empty muted small">no matches</div>}
          {filtered.map((c, i) => (
            <button
              key={c.id}
              className={`palette-item ${i === sel ? "sel" : ""}`}
              onMouseEnter={() => setSel(i)}
              onClick={() => {
                onClose();
                c.run();
              }}
            >
              <span className="palette-label">{c.label}</span>
              {c.hint && <span className="palette-hint muted">{c.hint}</span>}
            </button>
          ))}
        </div>
      </div>
    </div>
  );
}
