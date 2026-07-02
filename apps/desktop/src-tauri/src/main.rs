// DRIFT desktop — Tauri shell.
//
// This process owns no cryptography. It spawns the Python sidecar
// (`python -m drift.sidecar`) as a child, speaks newline-delimited JSON-RPC to
// it over stdin/stdout, and exposes a single `rpc` command to the web UI.
// Unsolicited sidecar events (incoming messages, transport status) are
// forwarded to the UI as a Tauri `"sidecar"` event.
//
// The whole point of the Phase 13 plan: one internally reviewed crypto
// implementation. The desktop app is a *view* over the existing Python core,
// exactly like the CLI and TUI — later the sidecar is swapped for a native
// Rust `drift-core` under the same UI, with no UI rewrite.

#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use std::collections::HashMap;
use std::io::{BufRead, BufReader, Write};
use std::path::PathBuf;
use std::process::{Child, ChildStdin, Command, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use serde_json::{json, Value};
use tauri::menu::{Menu, MenuItem};
use tauri::tray::TrayIconBuilder;
use tauri::{Emitter, Manager};
use tokio::sync::oneshot;

type Pending = Arc<Mutex<HashMap<u64, oneshot::Sender<Value>>>>;

/// Bridge to the Python sidecar: a writer to its stdin, a correlation table of
/// in-flight request ids, and a handle that keeps the child alive.
struct Bridge {
    stdin: Mutex<ChildStdin>,
    pending: Pending,
    next_id: AtomicU64,
    _child: Mutex<Child>,
}

impl Bridge {
    async fn call(&self, method: String, params: Value) -> Result<Value, String> {
        let id = self.next_id.fetch_add(1, Ordering::SeqCst);
        let (tx, rx) = oneshot::channel();
        self.pending
            .lock()
            .map_err(|_| "bridge poisoned".to_string())?
            .insert(id, tx);

        let req = json!({ "id": id, "method": method, "params": params });
        {
            let mut w = self.stdin.lock().map_err(|_| "stdin poisoned".to_string())?;
            writeln!(w, "{}", req).map_err(|e| e.to_string())?;
            w.flush().map_err(|e| e.to_string())?;
        }

        let resp = rx.await.map_err(|_| "sidecar closed the connection".to_string())?;
        if resp.get("ok").and_then(Value::as_bool).unwrap_or(false) {
            Ok(resp.get("result").cloned().unwrap_or(Value::Null))
        } else {
            Err(resp
                .get("error")
                .and_then(Value::as_str)
                .unwrap_or("sidecar error")
                .to_string())
        }
    }
}

/// Every sidecar method the web UI may call. Anything else is rejected here in
/// the shell, so even a compromised webview cannot probe the sidecar surface
/// beyond what the UI legitimately uses.
const ALLOWED_METHODS: &[&str] = &[
    "ping",
    "status",
    "init",
    "whoami",
    "contacts_list",
    "contacts_add",
    "contacts_remove",
    "safety_number",
    "fmd_get",
    "fmd_set",
    "cover_get",
    "cover_set",
    "relay_get",
    "relay_set",
    "tor_get",
    "tor_set",
    "tor_status",
    "lock",
    "unlock",
    "vault_create",
    "panic_lock",
    "chat_open",
    "chat_send",
    "chat_close",
    "chat_burn",
    "channels_list",
    "channel_create",
    "channel_join",
    "room_create",
    "room_join",
    "room_invite",
    "room_rotate",
    "room_leave",
    "groups_list",
    "group_create",
    "group_add",
    "group_remove",
    "invite_create",
    "invite_resolve",
    "invite_extinguish",
];

/// The single command the web UI calls. `method` is checked against the
/// allowlist above; `params` are forwarded to the sidecar and `result` (or
/// `error`) comes straight back.
#[tauri::command]
async fn rpc(
    state: tauri::State<'_, Bridge>,
    method: String,
    params: Value,
) -> Result<Value, String> {
    if !ALLOWED_METHODS.contains(&method.as_str()) {
        return Err(format!("method not allowed: {method}"));
    }
    state.call(method, params).await
}

/// How to launch the sidecar, in priority order:
///   1. `$DRIFT_SIDECAR_BIN` — an explicit path (override / testing).
///   2. A bundled `drift-sidecar[.exe]` next to the app executable — this is
///      where Tauri's `externalBin` drops the PyInstaller-frozen binary in a
///      packaged install, so the installer needs **no** system Python.
///   3. Dev fallback — run the Python module from the repo (`python3 -m
///      drift.sidecar`); interpreter and cwd are overridable via
///      `$DRIFT_PYTHON` / `$DRIFT_REPO`.
fn sidecar_command() -> (String, Vec<String>, Option<PathBuf>) {
    if let Ok(bin) = std::env::var("DRIFT_SIDECAR_BIN") {
        return (bin, vec![], None);
    }
    if let Ok(exe) = std::env::current_exe() {
        if let Some(dir) = exe.parent() {
            let name = if cfg!(windows) { "drift-sidecar.exe" } else { "drift-sidecar" };
            let bundled = dir.join(name);
            if bundled.exists() {
                return (bundled.to_string_lossy().into_owned(), vec![], None);
            }
        }
    }
    let python = std::env::var("DRIFT_PYTHON").unwrap_or_else(|_| "python3".to_string());
    let repo = std::env::var("DRIFT_REPO").unwrap_or_else(|_| "../../..".to_string());
    (
        python,
        vec!["-m".to_string(), "drift.sidecar".to_string()],
        Some(PathBuf::from(repo)),
    )
}

fn spawn_sidecar(app: &tauri::AppHandle) -> Result<Bridge, String> {
    let (cmd, args, cwd) = sidecar_command();
    let mut command = Command::new(&cmd);
    command
        .args(&args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit()); // sidecar logs go to our stderr
    if let Some(dir) = &cwd {
        command.current_dir(dir);
    }
    // On Windows the sidecar is a console-subsystem executable; spawning it the
    // normal way pops up a stray terminal window next to the app. We only ever
    // talk to it over piped stdio, so launch it with CREATE_NO_WINDOW to keep it
    // fully headless — no console flash, no spooky black box.
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        const CREATE_NO_WINDOW: u32 = 0x0800_0000;
        command.creation_flags(CREATE_NO_WINDOW);
    }
    let mut child = command
        .spawn()
        .map_err(|e| format!("failed to spawn sidecar `{cmd}`: {e}"))?;

    let stdin = child.stdin.take().ok_or("no sidecar stdin")?;
    let stdout = child.stdout.take().ok_or("no sidecar stdout")?;
    let pending: Pending = Arc::new(Mutex::new(HashMap::new()));

    // Reader thread: route id-tagged responses to their waiters; forward
    // unsolicited events to the UI as a single "sidecar" Tauri event carrying
    // the whole {event, data} frame.
    let pending_reader = pending.clone();
    let handle = app.clone();
    std::thread::spawn(move || {
        let reader = BufReader::new(stdout);
        for line in reader.lines() {
            let Ok(line) = line else { break };
            let line = line.trim();
            if line.is_empty() {
                continue;
            }
            let Ok(frame) = serde_json::from_str::<Value>(line) else {
                continue;
            };
            if let Some(id) = frame.get("id").and_then(Value::as_u64) {
                if let Ok(mut map) = pending_reader.lock() {
                    if let Some(tx) = map.remove(&id) {
                        let _ = tx.send(frame);
                    }
                }
            } else if frame.get("event").is_some() {
                let _ = handle.emit("sidecar", &frame);
            }
        }
    });

    Ok(Bridge {
        stdin: Mutex::new(stdin),
        pending,
        next_id: AtomicU64::new(1),
        _child: Mutex::new(child),
    })
}

/// Show the main window if hidden, hide it if visible — the tray's primary
/// affordance for a single-window app.
fn toggle_main(app: &tauri::AppHandle) {
    if let Some(win) = app.get_webview_window("main") {
        if win.is_visible().unwrap_or(false) {
            let _ = win.hide();
        } else {
            let _ = win.show();
            let _ = win.set_focus();
        }
    }
}

/// System-tray icon + menu. "Lock vault" emits `menu:lock` to the UI (which owns
/// the passphrase prompt) rather than touching the sidecar from here.
fn build_tray(app: &tauri::AppHandle) -> tauri::Result<()> {
    let show = MenuItem::with_id(app, "show", "Show / Hide", true, None::<&str>)?;
    let lock = MenuItem::with_id(app, "lock", "Lock vault", true, None::<&str>)?;
    let panic = MenuItem::with_id(app, "panic", "Panic lock", true, None::<&str>)?;
    let quit = MenuItem::with_id(app, "quit", "Quit DRIFT", true, None::<&str>)?;
    let menu = Menu::with_items(app, &[&show, &lock, &panic, &quit])?;

    let mut builder = TrayIconBuilder::new()
        .menu(&menu)
        .show_menu_on_left_click(false)
        .tooltip("DRIFT")
        .on_menu_event(|app, event| match event.id.as_ref() {
            "show" => toggle_main(app),
            "lock" => {
                let _ = app.emit("menu:lock", ());
            }
            "panic" => {
                let _ = app.emit("menu:panic", ());
            }
            "quit" => app.exit(0),
            _ => {}
        });
    if let Some(icon) = app.default_window_icon() {
        builder = builder.icon(icon.clone());
    }
    builder.build(app)?;
    Ok(())
}

fn main() {
    tauri::Builder::default()
        // Single-instance MUST be registered first: a second launch is routed to
        // the running app (focus it) instead of spawning a second sidecar.
        .plugin(tauri_plugin_single_instance::init(|app, _args, _cwd| {
            if let Some(win) = app.get_webview_window("main") {
                let _ = win.show();
                let _ = win.unminimize();
                let _ = win.set_focus();
            }
        }))
        // Remember window size/position across restarts.
        .plugin(tauri_plugin_window_state::Builder::new().build())
        // Auto-update: the UI drives the check/download/install flow; these
        // plugins expose it and let us relaunch into the new version.
        .plugin(tauri_plugin_updater::Builder::new().build())
        .plugin(tauri_plugin_process::init())
        // Native notifications for incoming messages (fired from the UI).
        .plugin(tauri_plugin_notification::init())
        // Global panic shortcut: works even when the window is hidden/unfocused.
        // The UI owns the actual lock (it calls the sidecar's `panic_lock`);
        // this only emits the event, mirroring the tray's division of labor.
        .plugin(
            tauri_plugin_global_shortcut::Builder::new()
                .with_shortcuts(["CmdOrCtrl+Shift+L"])
                .expect("valid panic shortcut")
                .with_handler(|app, _shortcut, event| {
                    if event.state == tauri_plugin_global_shortcut::ShortcutState::Pressed {
                        let _ = app.emit("menu:panic", ());
                    }
                })
                .build(),
        )
        .setup(|app| {
            let bridge = spawn_sidecar(&app.handle())?;
            app.manage(bridge);
            build_tray(&app.handle())?;
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![rpc])
        .run(tauri::generate_context!())
        .expect("error while running DRIFT desktop");
}
