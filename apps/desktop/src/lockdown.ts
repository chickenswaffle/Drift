/**
 * Desktop Lockdown Mode — device-local endpoint hardening.
 *
 * Four protections, individually toggleable, or all at once via the master
 * switch. All state is per-device (localStorage) by design: what THIS screen
 * defends against is a property of this machine, not of your identity.
 *
 * Honesty: the screen shield blocks capture on macOS and Windows only (Linux
 * compositors offer no such API — we say so, we don't pretend). Nothing here
 * binds your peer's device, and no software stops a camera pointed at glass.
 */

export const SHIELD_KEY = "drift.lockdown.shield";
export const BLUR_KEY = "drift.lockdown.blur";
export const NOCOPY_KEY = "drift.lockdown.nocopy";
export const CLIP_KEY = "drift.clipboard_clear"; // shared with the clipboard guard

const on = (k: string) => localStorage.getItem(k) === "1";
const set = (k: string, v: boolean) => {
  if (v) localStorage.setItem(k, "1");
  else localStorage.removeItem(k);
};

export const shieldOn = () => on(SHIELD_KEY);
export const blurOn = () => on(BLUR_KEY);
export const noCopyGlobal = () => on(NOCOPY_KEY);
export const clipGuardOn = () => on(CLIP_KEY);

/** True when every lockdown protection is on (the master switch state). */
export const lockdownAll = () => shieldOn() && blurOn() && noCopyGlobal() && clipGuardOn();

/** Per-conversation no-copy: forced by the global switch, or set per chat. */
export const noCopyFor = (label: string) =>
  noCopyGlobal() || localStorage.getItem(`drift.nocopy.${label}`) === "1";

/** Ask the OS to exclude this window from screen capture. No-op outside Tauri
 *  (dev browser) and on Linux (unsupported — surfaced in the UI, not hidden). */
export async function applyShield(enabled: boolean): Promise<void> {
  try {
    const { getCurrentWindow } = await import("@tauri-apps/api/window");
    await getCurrentWindow().setContentProtected(enabled);
  } catch {
    /* dev browser or platform without support */
  }
}

export async function setShield(enabled: boolean): Promise<void> {
  set(SHIELD_KEY, enabled);
  await applyShield(enabled);
}

export function setBlur(enabled: boolean): void {
  set(BLUR_KEY, enabled);
}

export function setNoCopyGlobal(enabled: boolean): void {
  set(NOCOPY_KEY, enabled);
}

export function setClipGuard(enabled: boolean): void {
  set(CLIP_KEY, enabled);
}

/** The master switch: everything on, or everything off. */
export async function setLockdownAll(enabled: boolean): Promise<void> {
  setBlur(enabled);
  setNoCopyGlobal(enabled);
  setClipGuard(enabled);
  await setShield(enabled);
}

/** Re-apply persisted protections on app start (the OS forgets; we don't). */
export async function applyOnStartup(): Promise<void> {
  if (shieldOn()) await applyShield(true);
}
