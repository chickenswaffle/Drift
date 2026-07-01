import { useCallback, useEffect, useRef, useState } from "react";
import type { Update } from "@tauri-apps/plugin-updater";

// Auto-update, on by default. Nothing is downloaded or installed without a
// click; the only automatic behaviour is a *quiet check* on launch. It is opt-
// *out* — the check runs unless the user unticks it — so a fresh install
// actually learns about updates instead of sitting silent forever.
// The flow: check() → (if newer) downloadAndInstall() → relaunch().

type State =
  | { k: "idle" }
  | { k: "checking" }
  | { k: "uptodate" }
  | { k: "available"; version: string; notes?: string }
  | { k: "downloading"; pct: number }
  | { k: "ready" }
  | { k: "error"; msg: string };

const AUTO_KEY = "drift.autoUpdate";

export function Updater({ current }: { current: string }) {
  const [state, setState] = useState<State>({ k: "idle" });
  // Default ON: only an explicit "0" (the user opting out) disables the launch check.
  const [auto, setAuto] = useState<boolean>(() => localStorage.getItem(AUTO_KEY) !== "0");
  const update = useRef<Update | null>(null);

  const check = useCallback(async (quiet = false) => {
    setState({ k: "checking" });
    try {
      const { check } = await import("@tauri-apps/plugin-updater");
      const found = await check();
      update.current = found;
      if (found) {
        setState({ k: "available", version: found.version, notes: found.body });
      } else {
        setState({ k: "uptodate" });
        if (quiet) setState({ k: "idle" });
      }
    } catch (e) {
      // dev/browser (no Tauri) or network error — stay quiet on auto-checks
      if (quiet) setState({ k: "idle" });
      else setState({ k: "error", msg: String(e) });
    }
  }, []);

  const install = useCallback(async () => {
    const u = update.current;
    if (!u) return;
    try {
      let total = 0;
      let got = 0;
      await u.downloadAndInstall((ev) => {
        if (ev.event === "Started") {
          total = ev.data.contentLength ?? 0;
          setState({ k: "downloading", pct: 0 });
        } else if (ev.event === "Progress") {
          got += ev.data.chunkLength;
          setState({ k: "downloading", pct: total ? Math.round((got / total) * 100) : 0 });
        } else if (ev.event === "Finished") {
          setState({ k: "ready" });
        }
      });
      const { relaunch } = await import("@tauri-apps/plugin-process");
      await relaunch();
    } catch (e) {
      setState({ k: "error", msg: String(e) });
    }
  }, []);

  // quiet check on launch — only if opted in
  useEffect(() => {
    if (auto) void check(true);
    // run once on mount
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  function toggleAuto() {
    const next = !auto;
    setAuto(next);
    localStorage.setItem(AUTO_KEY, next ? "1" : "0");
  }

  return (
    <div className="updater">
      {state.k === "available" || state.k === "downloading" || state.k === "ready" ? (
        <div className="upd-banner">
          {state.k === "available" && (
            <>
              <span className="upd-dot" />
              <span className="upd-msg">update {state.version} available</span>
              <button className="upd-go" onClick={() => void install()}>install &amp; restart</button>
            </>
          )}
          {state.k === "downloading" && (
            <span className="upd-msg">downloading… {state.pct}%</span>
          )}
          {state.k === "ready" && <span className="upd-msg">restarting…</span>}
        </div>
      ) : (
        <div className="upd-row">
          <button className="upd-check" onClick={() => void check(false)} disabled={state.k === "checking"}>
            {state.k === "checking" ? "checking…" : "check for updates"}
          </button>
          <span className="upd-status">
            {state.k === "uptodate" && `up to date · ${current}`}
            {state.k === "error" && <span className="error">update check failed</span>}
            {state.k === "idle" && current}
          </span>
        </div>
      )}
      <label className="upd-auto" title="quietly check for updates each time DRIFT starts">
        <input type="checkbox" checked={auto} onChange={toggleAuto} />
        check automatically on launch
      </label>
    </div>
  );
}
