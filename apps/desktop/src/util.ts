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

export function fmtTime(ts: number): string {
  const d = new Date(ts);
  return `${String(d.getHours()).padStart(2, "0")}:${String(d.getMinutes()).padStart(2, "0")}`;
}
