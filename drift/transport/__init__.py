"""
drift.transport — network transport layer

Phase 0: plain WebSocket client
Phase 3: Tor bootstrap via arti or stem (see tor.py), routing every relay
         byte through a SOCKS5 circuit — selected per-session, transparent to
         the crypto and session layers above

The transport layer is intentionally decoupled from the crypto layer.
crypto/ knows nothing about networks; transport/ knows nothing about
message content. This separation makes both easier to audit and replace.
"""
