export interface Status {
  identity_exists: boolean;
  vault_exists: boolean;
  fmd_rate: number;
  relay_url: string;
}

export type Contacts = Record<string, string>; // name -> contact code

export type MsgDir = "in" | "out" | "sys";

export interface ChatMessage {
  convo: string;
  dir: MsgDir;
  text: string;
  ts: number;
}
