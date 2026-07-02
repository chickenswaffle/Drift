import type { Status } from "./types";

/**
 * The security checklist — an honest posture check, not a guarantee.
 *
 * Every item maps to a real control against a real threat, reads live state,
 * and (where safe) carries a one-click fix. Items the platform cannot enforce
 * say so instead of silently passing. A green board does not make a
 * compromised endpoint safe, and the panel says that too.
 */

export type Fix =
  | { kind: "rpc"; method: string; params: Record<string, unknown>; label: string }
  | { kind: "local"; key: string; value: string; label: string }
  | { kind: "settings"; label: string } // needs input — jump to Settings
  | { kind: "verify"; label: string } // open the safety-number verify flow
  | { kind: "shield"; label: string }; // toggle the lockdown screen shield

export interface SecItem {
  id: string;
  label: string;
  pass: boolean;
  threat: string; // one line: what being red actually exposes
  fix?: Fix; // offered on red rows only
  note?: string; // honesty caveat (e.g. platform limits)
}

export function isLoopback(relayUrl: string): boolean {
  return /^wss?:\/\/(127\.0\.0\.1|localhost|\[::1\])([:/]|$)/.test(relayUrl);
}

export function onLinux(): boolean {
  const probe = `${navigator.platform ?? ""} ${navigator.userAgent ?? ""}`;
  return /linux/i.test(probe) && !/android/i.test(probe);
}

export interface SecInputs {
  status: Status;
  coverLevel: string; // from cover_get
  shieldOn: boolean; // lockdown screen shield (device-local)
  convo?: { kind: string; label: string; verified: boolean };
}

export function buildChecklist(inp: SecInputs): SecItem[] {
  const { status, coverLevel, shieldOn, convo } = inp;
  const torOn = status.tor_mode !== undefined && status.tor_mode !== "off" && !!status.tor_active;

  const items: SecItem[] = [
    {
      id: "tor",
      label: "tor routing",
      pass: torOn,
      threat: "your IP is visible to the relay, and your ISP sees you talk to it.",
      fix: { kind: "settings", label: "open settings" },
    },
    {
      id: "wss",
      label: "encrypted relay link",
      pass: status.relay_url.startsWith("wss://") || isLoopback(status.relay_url) || torOn,
      threat: "plaintext WebSocket over the open internet — the ciphertext is safe, the metadata is not.",
      fix: { kind: "settings", label: "open settings" },
    },
    {
      id: "vault",
      label: "identity vault",
      pass: status.vault_exists,
      threat: "your identity keys sit unencrypted on disk — anyone at this machine owns them.",
      fix: { kind: "settings", label: "open settings" },
    },
    {
      id: "cover",
      label: "cover traffic",
      pass: coverLevel !== "off",
      threat: "a wire observer can see exactly when and how much you really talk.",
      fix: { kind: "rpc", method: "cover_set", params: { level: "low" }, label: "set low" },
    },
    {
      id: "fmd",
      label: "metadata noise (fmd)",
      pass: status.fmd_rate > 0,
      threat: "the relay can tell precisely which envelopes are yours; noise makes it guess.",
      // 2^-14 — the Settings "low" stop (achievable FMD rates are powers of two).
      fix: { kind: "rpc", method: "fmd_set", params: { rate: 2 ** -14 }, label: "set low" },
    },
    {
      id: "clip",
      label: "clipboard guard",
      pass: localStorage.getItem("drift.clipboard_clear") === "1",
      threat: "copied codes linger in the clipboard for any app to read later.",
      fix: { kind: "local", key: "drift.clipboard_clear", value: "1", label: "enable" },
    },
    {
      id: "shield",
      label: "screen shield",
      pass: shieldOn && !onLinux(),
      threat: "any app (or OS feature) can screenshot or record this window.",
      fix: onLinux() ? undefined : { kind: "shield", label: "enable" },
      note: onLinux()
        ? "not enforceable on Linux — the compositor offers no capture block"
        : undefined,
    },
    {
      id: "conceal",
      label: "contact code concealed",
      pass: localStorage.getItem("drift.conceal") === "1",
      threat: "your permanent code is readable by anyone glancing at (or capturing) the sidebar.",
      fix: { kind: "local", key: "drift.conceal", value: "1", label: "conceal" },
    },
  ];

  if (convo && convo.kind === "contact") {
    items.push(
      {
        id: "verified",
        label: "contact verified",
        pass: convo.verified,
        threat: "you have not confirmed these keys out-of-band — a middleman would look identical.",
        fix: { kind: "verify", label: "verify now" },
      },
      {
        id: "expiry",
        label: "disappearing messages",
        pass: !!Number(localStorage.getItem(`drift.expire.${convo.label}`) ?? 0),
        threat: "this screen keeps the whole conversation for as long as the app runs.",
        fix: { kind: "local", key: `drift.expire.${convo.label}`, value: "3600", label: "set 1h" },
      },
    );
  }

  return items;
}

export function secScore(items: SecItem[]): { passed: number; total: number; tone: "ok" | "warn" | "bad" } {
  const passed = items.filter((i) => i.pass).length;
  const total = items.length;
  const tone = passed === total ? "ok" : passed >= total / 2 ? "warn" : "bad";
  return { passed, total, tone };
}
