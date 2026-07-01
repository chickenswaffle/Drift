import type { ConvoKind } from "./types";

// A deterministic accent color per name — gives every conversation and sender a
// stable visual identity without avatars or a single emoji. Drawn from a small
// CRT-flavored palette so it always sits inside the terminal aesthetic.
const ACCENTS = [
  "#00ff41", // matrix green
  "#00d4ff", // cyan
  "#ffd166", // amber
  "#c77dff", // violet
  "#ff6b6b", // red
  "#4dd6a1", // teal
  "#f4a259", // orange
  "#7aa2f7", // blue
];

export function accentFor(name: string): string {
  let h = 0;
  for (let i = 0; i < name.length; i++) h = (h * 31 + name.charCodeAt(i)) >>> 0;
  return ACCENTS[h % ACCENTS.length];
}

// Non-emoji glyphs, one per conversation kind (the CLI's 📢 is deliberately not
// used — nothing in this UI is an emoji).
export function glyphFor(kind: ConvoKind): string {
  switch (kind) {
    case "channel":
      return "#";
    case "room":
      return "⬡";
    case "group":
      return "※";
    default:
      return "›";
  }
}

// The one clipboard writer. If the user has opted into clipboard clearing
// (Settings), the copied text is blanked after 30 s — but only if the clipboard
// still holds *that* text, so we never stomp something copied since. Best
// effort by design: if the platform denies clipboard reads, we skip silently,
// and some OS clipboard managers keep history DRIFT can't reach.
const CLIPBOARD_CLEAR_MS = 30_000;

export async function copyText(text: string): Promise<void> {
  await navigator.clipboard.writeText(text);
  if (localStorage.getItem("drift.clipboard_clear") !== "1") return;
  setTimeout(() => {
    navigator.clipboard
      .readText()
      .then((current) => {
        if (current === text) return navigator.clipboard.writeText("");
      })
      .catch(() => undefined);
  }, CLIPBOARD_CLEAR_MS);
}

export function fmtTime(ts: number): string {
  const d = new Date(ts);
  return `${String(d.getHours()).padStart(2, "0")}:${String(d.getMinutes()).padStart(2, "0")}`;
}
