#!/bin/bash -e
#
# Seed this stage's rootfs from the previous stage (Lite / stage2) the first
# time it runs. Standard pi-gen stage boilerplate.

if [ ! -d "${ROOTFS_DIR}" ]; then
	copy_previous
fi
