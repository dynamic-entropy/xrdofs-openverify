#!/usr/bin/env bash
# Install xrdmon-collector from a GitHub Release onto an AAA host
# (e.g. cms-xrd-global-test). Writes metrics next to OpenVerify:
#   /var/lib/node_exporter/textfile_collector/xrdmon.prom
#
# Usage:
#   ./install-from-release.sh [VERSION]
#   XRDMON_VERSION=0.2.6 ./install-from-release.sh
#
# Defaults to latest xrdmon-v* release for linux/amd64 (CERN EL hosts).

set -euo pipefail

REPO="${XRDMON_REPO:-dynamic-entropy/xrdofs-openverify}"
VERSION="${1:-${XRDMON_VERSION:-}}"
ARCH="$(uname -m)"
case "${ARCH}" in
  x86_64|amd64) GOARCH=amd64 ;;
  aarch64|arm64) GOARCH=arm64 ;;
  *) echo "unsupported arch: ${ARCH}" >&2; exit 1 ;;
esac

TEXTFILE_DIR="${XRDMON_TEXTFILE_DIR:-/var/lib/node_exporter/textfile_collector}"
BIN_DIR="${XRDMON_BIN_DIR:-/usr/bin}"
UNIT_SRC="$(cd "$(dirname "$0")" && pwd)/xrdmon-collector.service"

if [[ -z "${VERSION}" ]]; then
  VERSION="$(curl -fsSL "https://api.github.com/repos/${REPO}/releases" \
    | grep -oE '"tag_name": "xrdmon-v[^"]+"' \
    | head -1 \
    | sed 's/.*"xrdmon-v//;s/"$//')"
  if [[ -z "${VERSION}" ]]; then
    echo "no xrdmon-v* release found on ${REPO}" >&2
    exit 1
  fi
fi

TAG="xrdmon-v${VERSION}"
ASSET="xrdmon-collector-${VERSION}-linux-${GOARCH}.tar.gz"
URL="https://github.com/${REPO}/releases/download/${TAG}/${ASSET}"
TMP="$(mktemp -d)"
trap 'rm -rf "${TMP}"' EXIT

echo "Downloading ${URL}"
curl -fsSL -o "${TMP}/${ASSET}" "${URL}"
curl -fsSL -o "${TMP}/${ASSET}.sha256" "${URL}.sha256" || true
if [[ -f "${TMP}/${ASSET}.sha256" ]]; then
  (cd "${TMP}" && sha256sum -c "${ASSET}.sha256")
fi

tar -C "${TMP}" -xzf "${TMP}/${ASSET}"
install -m 0755 "${TMP}/xrdmon-collector-${VERSION}-linux-${GOARCH}" "${BIN_DIR}/xrdmon-collector"

mkdir -p "${TEXTFILE_DIR}"
if [[ -f "${UNIT_SRC}" ]]; then
  install -m 0644 "${UNIT_SRC}" /etc/systemd/system/xrdmon-collector.service
  systemctl daemon-reload
  systemctl enable --now xrdmon-collector.service
  systemctl --no-pager --full status xrdmon-collector.service || true
fi

echo "Installed ${BIN_DIR}/xrdmon-collector (${TAG})"
echo "Textfile: ${TEXTFILE_DIR}/xrdmon.prom"
echo "Remember to point xrootd/cmsd at 127.0.0.1:9930 (see README)."
