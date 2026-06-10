"""
drift.ui — terminal user interface

Built with Textual (https://textual.textualize.io/).

Phase 0 scope:
  - Message pane (incoming/outgoing)
  - Input field with send-on-Enter
  - Status bar (relay connection, Tor status)

To contribute the UI, see:
  https://textual.textualize.io/guide/
  drift/ui/app.py  (create this file)

The UI should know nothing about crypto or network details.
It calls functions from drift.transport and receives decrypted
plaintext strings back — separation of concerns.
"""
