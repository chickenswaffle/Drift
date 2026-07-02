// Native OS notification for incoming messages. Metadata-safe by construction:
// the body names the contact only, never message content — consistent with the
// app-plan's push stance (docs/app-plan.md §4.2). Dynamically imported so the
// dev/browser build (no Tauri IPC) degrades to a silent no-op instead of throwing.
export async function notify(contact: string): Promise<void> {
  return notifyRaw(`new message from ${contact}`);
}

/** A notification with a verbatim body — used for security alerts (e.g. a
 *  WITNESS chain break), which aren't about a contact. Still metadata-safe:
 *  alert text only, never message content. */
export async function notifyRaw(body: string): Promise<void> {
  try {
    const mod = await import("@tauri-apps/plugin-notification");
    let granted = await mod.isPermissionGranted();
    if (!granted) {
      granted = (await mod.requestPermission()) === "granted";
    }
    if (granted) {
      mod.sendNotification({ title: "DRIFT", body });
    }
  } catch {
    /* no Tauri (dev/browser) or plugin unavailable — skip quietly */
  }
}
