import { useEffect, useRef, useState } from "react";
import { prefersReducedMotion } from "./util";

// The glyph pool the ciphertext "settles" out of — kept to terminal-safe
// characters so the effect reads as decryption noise, not mojibake.
const GLYPHS = "01!<>[]{}/\\=+*#%$&ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
const CHAR_MS = 14; // per-frame cadence
const SETTLE_PER_CHAR = 1.4; // frames a char stays scrambled before it locks

function pick(): string {
  // A tiny LCG seeded off the clock avoids Math.random (banned in some
  // sandboxes) while staying visually random enough for noise.
  pick._s = (pick._s * 1103515245 + 12345) & 0x7fffffff;
  return GLYPHS[pick._s % GLYPHS.length];
}
pick._s = 0x2545f4914f6cdd1d & 0x7fffffff;

/**
 * Renders `text` as if it were being decrypted: each character starts as random
 * glyph noise and locks into place left-to-right. Purely cosmetic — the real
 * text is already in hand; this just dramatizes its arrival. Falls back to a
 * plain span (no animation, no extra renders) under prefers-reduced-motion.
 */
export function Scramble({ text, className }: { text: string; className?: string }) {
  const reduced = prefersReducedMotion();
  const [shown, setShown] = useState(reduced ? text : "");
  const raf = useRef<number | null>(null);

  useEffect(() => {
    if (reduced) {
      setShown(text);
      return;
    }
    let frame = 0;
    const total = text.length * SETTLE_PER_CHAR + 6;
    let last = 0;

    const step = (t: number) => {
      if (t - last >= CHAR_MS) {
        last = t;
        frame++;
        const locked = Math.floor(frame / SETTLE_PER_CHAR);
        let out = "";
        for (let i = 0; i < text.length; i++) {
          const ch = text[i];
          if (i < locked || ch === " ") out += ch;
          else out += pick();
        }
        setShown(out);
      }
      if (frame < total) raf.current = requestAnimationFrame(step);
      else setShown(text);
    };
    raf.current = requestAnimationFrame(step);
    return () => {
      if (raf.current != null) cancelAnimationFrame(raf.current);
    };
  }, [text, reduced]);

  return <span className={className}>{shown}</span>;
}
