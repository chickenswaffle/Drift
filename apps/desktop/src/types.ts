export interface Status {
  identity_exists: boolean;
  vault_exists: boolean;
  fmd_rate: number;
  relay_url: string;
  tor_mode?: "off" | "prefer" | "require";
  tor_available?: boolean;
  tor_active?: boolean;
}

export type Contacts = Record<string, string>; // name -> contact code

export type MsgDir = "in" | "out" | "sys";

export interface ChatMessage {
  convo: string;
  dir: MsgDir;
  text: string;
  ts: number;
  who?: string; // room/group sender pseudonym or name
  authorized?: boolean; // room posts: false → unverified sender tag
}

// Everything the sidebar can open. `label` is the sidecar handle: a contact's
// local name, or a room/channel/group's local label.
export type ConvoKind = "contact" | "channel" | "room" | "group";

export interface Conversation {
  kind: ConvoKind;
  label: string;
  tier?: string; // rooms/channels: open | invite | dark
  canPost?: boolean; // rooms/channels
  sessionTag?: string; // rooms/channels: our 4-char pseudonym
  size?: number; // groups
  isOwner?: boolean; // channels
}

// A room or channel as returned by `channels_list`.
export interface RoomInfo {
  label: string;
  tier: string;
  kind: string; // "room" | "channel"
  is_owner: boolean;
  can_post: boolean;
  message_count: number;
}

export interface GroupInfo {
  label: string;
  size: number;
  members: { name: string; code: string }[];
}
