# Running a DRIFT relay — setup guide

A relay is a **blind bulletin board**: it routes opaque ciphertext, holds
nothing useful past ~30 seconds, and signs a proof of its own blindness every
60 seconds (WITNESS). It needs no database, no accounts, no configuration to
start — one Python process.

This guide goes from laptop test to public server.

---

## 1. Quick start (local, 2 minutes)

```bash
git clone https://github.com/chickenswaffle/Drift.git
cd Drift
python3.11 -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"

python -m relay.server
```

That's it — the relay is listening on `ws://0.0.0.0:8765`.

**Check it's alive** (from another terminal):

```bash
curl http://127.0.0.1:8765/              # hello + blindness notice
curl http://127.0.0.1:8765/capabilities  # {"protocol":"DRIFT-P/1","extensions":["drift-ext/witness/1"]}
drift witness verify ws://127.0.0.1:8765 # cryptographically verify its proof chain
```

**Point a client at it:** in the desktop app → Settings → relay →
`ws://<your-ip>:8765`, or in the CLI `drift chat --relay ws://<your-ip>:8765 …`.

## 2. Files the relay creates (in its working directory)

| File | What it is | Treat it as |
|---|---|---|
| `relay_identity.json` | The relay's long-term Ed25519 key — its WITNESS identity | **Secret. Back it up.** Losing it = the relay becomes a stranger; leaking it = someone can forge your relay's proofs |
| `witness_chain.jsonl` | Append-only log of blindness certificates | Keep it — it's the relay's tamper-evident history |
| `peers.json` | Federation peer list (optional) | Edit to join a mesh |

Note what is **not** here: no message store, no user database. Messages live
in RAM for the replay window and vanish.

## 3. Environment variables (all optional)

| Variable | Default | Purpose |
|---|---|---|
| `DRIFT_RELAY_IDENTITY` | `relay_identity.json` | where the identity key lives |
| `DRIFT_WITNESS_LOG` | `witness_chain.jsonl` | where the certificate chain lives |
| `DRIFT_PEERS_FILE` | `peers.json` | federation peers |
| `DRIFT_SELF_URL` | *(unset)* | this relay's public URL, told to peers when federating |
| `DRIFT_BEACON_MAX_TTL` | `86400` (24 h) | server-side cap on beacon/invite lifetime |
| `DRIFT_RELAY_RELOAD` | *(unset)* | dev auto-reload; never set in production |

Custom port / host: run via uvicorn directly —

```bash
uvicorn relay.server:app --host 0.0.0.0 --port 9000
```

## 4. Production setup (public server)

### 4a. Create a user + directory

```bash
sudo useradd -r -m -d /opt/drift-relay drift
sudo -u drift bash -c '
  cd /opt/drift-relay
  git clone https://github.com/chickenswaffle/Drift.git app
  cd app && python3.11 -m venv .venv && .venv/bin/pip install -e .
'
```

### 4b. systemd service — `/etc/systemd/system/drift-relay.service`

```ini
[Unit]
Description=DRIFT relay (blind ciphertext router)
After=network-online.target
Wants=network-online.target

[Service]
User=drift
WorkingDirectory=/opt/drift-relay
Environment=DRIFT_SELF_URL=wss://relay.example.com
ExecStart=/opt/drift-relay/app/.venv/bin/python -m relay.server
Restart=always
RestartSec=3
# hardening
NoNewPrivileges=true
ProtectSystem=strict
ReadWritePaths=/opt/drift-relay
PrivateTmp=true

[Install]
WantedBy=multi-user.target
```

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now drift-relay
sudo systemctl status drift-relay
```

### 4c. TLS (`wss://`) — put Caddy in front (easiest)

The relay itself speaks plain `ws://`; terminate TLS with a reverse proxy.
Caddy gets and renews the certificate automatically:

```bash
sudo apt install caddy    # or your distro's equivalent
```

`/etc/caddy/Caddyfile`:

```
relay.example.com {
    reverse_proxy 127.0.0.1:8765
}
```

```bash
sudo systemctl reload caddy
```

Clients now connect to **`wss://relay.example.com`** (port 443 — also the
firewall-friendliest). Keep 8765 closed to the outside
(`ufw allow 443; ufw deny 8765` or bind uvicorn to 127.0.0.1).

### 4d. Verify from anywhere

```bash
curl https://relay.example.com/capabilities
drift witness verify wss://relay.example.com     # full chain verification
drift witness subscribe wss://relay.example.com  # live canary in a terminal
```

Browsers can read the plain-English proof at
`https://relay.example.com/cannot-see`.

## 5. Federation (optional, multi-relay mesh)

On each relay, list the others in `peers.json`:

```json
["wss://relay-b.example.com", "wss://relay-c.example.com"]
```

…and set `DRIFT_SELF_URL` so peers know who's gossiping. Envelopes, beacons,
and burns replicate across the mesh; clients fail over automatically.

## 6. Operating honestly

- **The relay proves its own blindness** — publish your relay URL and invite
  people to run `drift witness verify` against it. A relay that breaks its
  chain (restarts with a new identity, gaps its coverage) is *visibly*
  suspect; that's the design working, not a bug to hide.
- Wiping `relay_identity.json` + `witness_chain.jsonl` starts a fresh chain —
  do it only with public notice, since watchers will (correctly) alarm.
- Upgrades: `git pull && pip install -e . && systemctl restart drift-relay`.
  Sub-60-second restarts keep period coverage intact.

## Troubleshooting

| Symptom | Fix |
|---|---|
| Client can't connect over the internet | Firewall: expose 443 (Caddy), not 8765; check `DRIFT_SELF_URL` uses `wss://` |
| `witness verify` fails right after a fresh install | The chain needs at least one 60 s period — wait a minute, retry |
| Watchers alarm after a server rebuild | Expected if the identity/chain files were lost — restore from backup or announce the new identity |
| Port already in use | Another relay instance is running: `systemctl status drift-relay` |
