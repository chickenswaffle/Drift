// Native OS notification for incoming messages. Metadata-safe by construction:
// the body names the contact only, never message content — consistent with the
// app-plan's push stance (docs/app-plan.md §4.2). Dynamically imported so the
// dev/browser build (no Tauri IPC) degrades to a silent no-op instead of throwing.
export async function notify(contact: string): Promise<void> {
  try {
    const mod = await import("@tauri-apps/plugin-notification");
    let granted = await mod.isPermissionGranted();
    if (!granted) {
      granted = (await mod.requestPermission()) === "granted";
    }
    if (granted) {
      mod.sendNotification({ title: "DRIFT", body: `new message from ${contact}` });
    }
  } catch {
    /* no Tauri (dev/browser) or plugin unavailable — skip quietly */
  }
}
