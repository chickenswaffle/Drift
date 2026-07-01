import { useState } from "react";
import { copyText } from "./util";

/** A click-to-copy box for a contact code, invite code, or room descriptor. */
export function CodeBox({ code, dashed }: { code: string; dashed?: boolean }) {
  const [copied, setCopied] = useState(false);
  return (
    <div
      className={`codebox${dashed ? " dashed" : ""}`}
      title="click to copy"
      onClick={() => {
        void copyText(code);
        setCopied(true);
        setTimeout(() => setCopied(false), 1200);
      }}
    >
      <code>{code}</code>
      <span className="copy">{copied ? "copied ✓" : "copy"}</span>
    </div>
  );
}
