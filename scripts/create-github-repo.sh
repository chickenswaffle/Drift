#!/usr/bin/env bash
# scripts/create-github-repo.sh
#
# Creates the DRIFT GitHub repository and pushes the initial commit.
# Requires the GitHub CLI (gh): https://cli.github.com
#
# Usage:
#   chmod +x scripts/create-github-repo.sh
#   ./scripts/create-github-repo.sh
#
# If you don't have gh installed:
#   brew install gh        # macOS
#   winget install gh      # Windows
#   sudo apt install gh    # Debian/Ubuntu

set -e

REPO_NAME="drift"
DESCRIPTION="Terminal-first E2E encrypted messenger with rotating stealth addresses"

echo "→ Checking for GitHub CLI..."
if ! command -v gh &>/dev/null; then
    echo "GitHub CLI (gh) not found."
    echo "Install it from https://cli.github.com then re-run this script."
    exit 1
fi

echo "→ Checking GitHub auth..."
gh auth status || gh auth login

echo "→ Initialising git repo..."
git init
git add .
git commit -m "feat: initial DRIFT scaffold

- Core crypto module: X25519 keypairs, XChaCha20-Poly1305 AEAD, HKDF
- Identity system: scan + spend keypairs, contact codes, base58
- Stealth address spec (Phase 1 placeholder with full protocol docs)
- Reference relay: FastAPI + WebSockets, in-memory mailbox
- CLI: init, whoami, add, verify, chat (Typer + Rich)
- Full test suite for crypto layer
- CI: GitHub Actions (Python 3.11 + 3.12, ruff, mypy, pytest)
- DESIGN.md: full protocol specification
- CONTRIBUTING.md, SECURITY.md, LICENSE (MIT)"

echo "→ Creating GitHub repository..."
gh repo create "$REPO_NAME" \
    --public \
    --description "$DESCRIPTION" \
    --push \
    --source .

echo ""
echo "✓ Repository created and pushed."
echo "  https://github.com/$(gh api user --jq .login)/$REPO_NAME"
echo ""
echo "Next steps:"
echo "  1. Go to the repo → Settings → About → add topics:"
echo "     encryption  e2e  messaging  privacy  cli  cryptography"
echo "  2. Pin DESIGN.md so contributors find it immediately"
echo "  3. Create these issues to start the Phase 0 board:"
echo "     - [ ] Build WebSocket client in drift/transport/"
echo "     - [ ] Build Textual chat UI in drift/ui/"
echo "     - [ ] Wire CLI drift chat to transport + crypto"
echo "     - [ ] Phase 1: implement stealth address derivation"
