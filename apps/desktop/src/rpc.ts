// Thin client over the Tauri `rpc` command and the `sidecar` event stream.
// Everything the UI knows about the DRIFT protocol goes through here.
import { invoke } from "@tauri-apps/api/core";
import { listen, type UnlistenFn } from "@tauri-apps/api/event";

export async function rpc<T = unknown>(
  method: string,
  params: Record<string, unknown> = {},
): Promise<T> {
  return invoke<T>("rpc", { method, params });
}

export interface SidecarFrame {
  event: string;
  data: Record<string, unknown>;
}

/** Subscribe to all sidecar events; `cb` gets each {event, data} frame. */
export function onSidecar(cb: (frame: SidecarFrame) => void): Promise<UnlistenFn> {
  return listen<SidecarFrame>("sidecar", (e) => cb(e.payload));
}
