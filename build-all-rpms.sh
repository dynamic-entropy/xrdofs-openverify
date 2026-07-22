#!/usr/bin/env bash
# Build OpenVerify + xrdmon-collector RPMs (used as Containerfile CMD).
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")"
bash build-rpm.sh
bash build-xrdmon-rpm.sh
