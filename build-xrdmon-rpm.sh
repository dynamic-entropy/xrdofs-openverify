#!/usr/bin/env bash
# Build the xrdmon-collector RPM (expects rpmdevtools + golang on PATH).
# Uses the same git-archive Source0 naming as xrdofs-openverify.spec so both
# packages can share one tarball when built back-to-back.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "${REPO_ROOT}"

OV_SPEC="xrdofs-openverify.spec"
SPEC_FILE="xrdmon-collector.spec"

if [[ ! -f "${SPEC_FILE}" ]]; then
  echo "Missing ${SPEC_FILE}" >&2
  exit 1
fi

# Version/tarball name follow the OpenVerify package so Source0 matches.
OV_VERSION="$(rpmspec -q --srpm --qf '%{VERSION}\n' "${OV_SPEC}" | head -1)"
OV_NAME="$(rpmspec -q --srpm --qf '%{NAME}\n' "${OV_SPEC}" | head -1)"
VERSION="$(rpmspec -q --srpm --qf '%{VERSION}\n' "${SPEC_FILE}" | head -1)"

if [[ "${VERSION}" != "${OV_VERSION}" ]]; then
  echo "WARNING: ${SPEC_FILE} version (${VERSION}) != ${OV_SPEC} (${OV_VERSION}); Source0 uses openverify version/tarball." >&2
fi

rpmdev-setuptree
SOURCE_TGZ="$(rpm -E '%{_sourcedir}')/${OV_NAME}-${OV_VERSION}.tar.gz"

if [[ ! -f "${SOURCE_TGZ}" ]]; then
  echo "==> Creating ${OV_NAME}-${OV_VERSION}.tar.gz from git HEAD ..."
  git archive --format=tar.gz --prefix="${OV_NAME}-${OV_VERSION}/" \
    -o "${SOURCE_TGZ}" HEAD
else
  echo "==> Reusing existing Source0 ${SOURCE_TGZ}"
fi

cp "${SPEC_FILE}" "$(rpm -E '%{_specdir}')/"
rpmbuild -ba "$(rpm -E '%{_specdir}')/${SPEC_FILE}"

echo "Built xrdmon-collector RPMs under $(rpm -E '%{_rpmdir}')"
