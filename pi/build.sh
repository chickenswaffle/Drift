#!/usr/bin/env bash
#
# build.sh — build the DRIFT mesh-node Raspberry Pi image with pi-gen.
#
#   pi/build.sh
#
# Clones the official Raspberry Pi OS image builder (pi-gen), drops in our
# `config` and `stage-drift`, and runs the Docker-based build so the result is
# reproducible across host OSes (works on Linux and macOS with Docker). The
# finished, ready-to-flash image lands in pi/deploy/.
#
# Knobs (all optional, via environment):
#   DRIFT_REF      git ref of THIS repo to bake into the image   (default: main)
#   DRIFT_REPO_URL repo to clone inside the image                (default: upstream)
#   PI_GEN_REF     pi-gen branch to pin                          (default: bookworm)
#   PI_GEN_DIR     where to check pi-gen out                     (default: pi/.pi-gen)
#
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PI_GEN_REF="${PI_GEN_REF:-bookworm}"
WORK="${PI_GEN_DIR:-${HERE}/.pi-gen}"
export DRIFT_REF="${DRIFT_REF:-main}"
export DRIFT_REPO_URL="${DRIFT_REPO_URL:-https://github.com/chickenswaffle/Drift.git}"

echo "⬡ DRIFT pi-gen build"
echo "  pi-gen ref : ${PI_GEN_REF}"
echo "  drift ref  : ${DRIFT_REF}"
echo "  workdir    : ${WORK}"

command -v docker >/dev/null 2>&1 || {
    echo "✗ docker is required (pi-gen build runs in a container)" >&2
    exit 1
}

# 1. Fetch / refresh pi-gen, pinned to a branch.
if [ ! -d "${WORK}/.git" ]; then
    git clone --depth 1 --branch "${PI_GEN_REF}" \
        https://github.com/RPi-Distro/pi-gen.git "${WORK}"
else
    git -C "${WORK}" fetch --depth 1 origin "${PI_GEN_REF}"
    git -C "${WORK}" checkout -f "FETCH_HEAD"
fi

# 2. Inject our config + stage.
cp "${HERE}/config" "${WORK}/config"
rm -rf "${WORK}/stage-drift"
cp -r "${HERE}/stage-drift" "${WORK}/stage-drift"
chmod +x "${WORK}/stage-drift/prerun.sh" \
         "${WORK}/stage-drift/00-install-drift/01-run.sh"

# 3. Don't also export the bare Lite image — only our stage produces an artifact.
touch "${WORK}/stage2/SKIP_IMAGES"

# 4. Forward our build knobs to the in-chroot install step. pi-gen only passes a
#    whitelist of env vars into the build container, so instead of relying on
#    env passthrough we write the values into the copied stage itself, where the
#    step script reads them as a sibling file (`files/drift-build.env`).
{
    echo "DRIFT_REF=${DRIFT_REF}"
    echo "DRIFT_REPO_URL=${DRIFT_REPO_URL}"
} > "${WORK}/stage-drift/00-install-drift/files/drift-build.env"

# 5. Build. build-docker.sh auto-reads ./config and runs the whole pipeline in a
#    container (reproducible across host OSes).
cd "${WORK}"
./build-docker.sh

# 6. Surface the artifact in pi/deploy/.
mkdir -p "${HERE}/deploy"
shopt -s nullglob
artifacts=("${WORK}/deploy"/*.img.xz "${WORK}/deploy"/*.zip)
if [ ${#artifacts[@]} -eq 0 ]; then
    echo "✗ build finished but no image found in ${WORK}/deploy" >&2
    exit 1
fi
cp "${artifacts[@]}" "${HERE}/deploy/"
echo "✓ image(s) ready:"
for a in "${HERE}/deploy"/*; do echo "    $a"; done
